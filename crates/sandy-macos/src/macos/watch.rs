//! `process.end_with_parent`: a watcher process ends the program when the process that started
//! sandy ends.
//!
//! 1. sandy reads its parent's process ID as its first step (or the caller names it with
//!    `--parent-pid` and sandy checks it then). Here it checks that this process is still its
//!    parent; otherwise the parent has already ended, and sandy refuses to start the program.
//!    With `--parent-start` the caller names when its own process started, and sandy checks
//!    that instead, so the named process need not be sandy's parent. Process 1 is refused in
//!    both cases: macOS has no subreaper, so launchd is the parent of every process whose
//!    parent ended, and waiting for launchd to end says nothing.
//! 2. sandy starts the watcher as a helper process (see `helper`), so it is not a child of the
//!    program. The watcher registers `NOTE_EXIT` in a kqueue for the parent and for sandy's
//!    process ID, which the program keeps after the exec. With `children = "contained"` the ID
//!    stays the supervising sandy's, which forwards the signals and ends the program's process
//!    group. Then the watcher applies its own profile: no files, no network, no Mach services; it
//!    may only signal.
//! 3. Once the watcher is ready, sandy checks its parent again. The watcher registered while that
//!    process was still sandy's parent, so the registration names it, and not another process
//!    that got the same process ID after it ended.
//! 4. The watcher waits. When the program ends first, the watcher ends. When the parent ends, the
//!    watcher sends SIGTERM and SIGCONT (so that a stopped program gets the request) to the
//!    program, waits at most `GRACE` for it to end, then sends SIGKILL, and ends.
//!
//! macOS has no pidfd, so the watcher signals the program by its process ID. Before each signal it
//! checks that the program has not ended. The ID could name another process only if the program
//! ended right between that check and the signal and macOS gave the ID to a new process in that
//! moment, which it does only after the process IDs wrapped around.
//!
//! The policy requires `signals = "isolated"`, so the program cannot signal the watcher, and the
//! watcher is in a session of its own with every signal blocked, so no group or terminal signal
//! reaches it either.

use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use sandy_core::{ParentProcess, SandboxError};

use super::helper::{self, NO_EVENT, new_queue, register};
use super::seatbelt::Seatbelt;
use crate::profile::{Profile, watcher_profile};

/// How long the program may take to end after SIGTERM before the watcher kills it.
pub const GRACE: Duration = Duration::from_secs(5);

/// Starts the watcher for `parent`, the process that started sandy, and returns once the watcher
/// is confined and watching.
pub fn start(parent: ParentProcess, seatbelt: &Seatbelt) -> Result<(), SandboxError> {
    let id = parent.id as libc::pid_t;
    if id <= 1 {
        return Err(SandboxError::new(format!(
            "sandy will not watch process {id}: macOS has no child subreaper, so launchd \
             (process 1) is the parent of every process whose parent has ended. Either the \
             process that started sandy has already ended, or launchd started sandy itself; \
             launchd has no end to wait for"
        )));
    }
    ensure_parent(parent)?;
    // SAFETY: getpid has no requirements.
    let program = unsafe { libc::getpid() };
    let profile = watcher_profile();
    let seatbelt = *seatbelt;
    helper::start("the watcher", &[], move |ready| {
        let queue = match watch_and_confine(id, program, &profile, &seatbelt) {
            Ok(queue) => queue,
            Err(error) => ready.fail(&error.to_string()),
        };
        ready.report();
        watch(&queue, id, program);
    })?;
    // The watcher registered `NOTE_EXIT` while the parent was still the same process, so the
    // registration names that process and not a later one with the same ID.
    ensure_parent(parent)
}

/// Checks that the named process is still the one the caller means: with `--parent-start` that
/// it started when the caller said, and otherwise that it is still sandy's own parent.
fn ensure_parent(parent: ParentProcess) -> Result<(), SandboxError> {
    let ended = || {
        Err(SandboxError::new(
            "the process that started sandy has already ended",
        ))
    };
    let id = parent.id as libc::pid_t;
    let Some(token) = parent.start else {
        // SAFETY: getppid has no requirements.
        if unsafe { libc::getppid() } != id {
            return ended();
        }
        return Ok(());
    };
    let Some(started) = start_time(id) else {
        return ended();
    };
    if started != token {
        return Err(SandboxError::new(format!(
            "process {id} started at {started}, not at {token} (--parent-start); the process \
             that started sandy may have ended already"
        )));
    }
    Ok(())
}

/// When process `id` started, in microseconds since the epoch, from `PROC_PIDTBSDINFO`. macOS
/// records this once at the start of the process, so a later change of the system clock does
/// not alter it, and two processes with the same ID would have to start in the same microsecond
/// to share it. `None` when the process is gone or its information cannot be read.
///
/// `p_uniqueid` of `PROC_PIDUNIQIDENTIFIERINFO` would be a stronger token, but it is not in the
/// public SDK headers; sandy uses one private interface (Seatbelt) and does not need a second.
fn start_time(id: libc::pid_t) -> Option<u64> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer has exactly the size passed.
    let written = unsafe {
        libc::proc_pidinfo(
            id,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole structure.
    let info = unsafe { info.assume_init() };
    Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// Registers the end of the parent and of the program, then applies the watcher's profile, which
/// denies process information about others.
fn watch_and_confine(
    parent: libc::pid_t,
    program: libc::pid_t,
    profile: &Profile,
    seatbelt: &Seatbelt,
) -> io::Result<OwnedFd> {
    let queue = new_queue()?;
    register(&queue, parent as usize, libc::EVFILT_PROC, libc::NOTE_EXIT)?;
    register(&queue, program as usize, libc::EVFILT_PROC, libc::NOTE_EXIT)?;
    seatbelt.apply(profile).map_err(io::Error::other)?;
    Ok(queue)
}

/// Waits until the parent or the program ends. When the parent ends first, or waiting fails and
/// the watcher can no longer see it, ends the program.
fn watch(queue: &OwnedFd, parent: libc::pid_t, program: libc::pid_t) {
    let mut events = [NO_EVENT; 2];
    while let Ok(count) = helper::wait_events(queue, &mut events, None) {
        if exited(&events[..count], program) {
            return;
        }
        if exited(&events[..count], parent) {
            break;
        }
    }
    if !send(queue, program, libc::SIGTERM) || !send(queue, program, libc::SIGCONT) {
        return;
    }
    if !ends_within(queue, program, GRACE) {
        send(queue, program, libc::SIGKILL);
    }
}

fn exited(events: &[libc::kevent], pid: libc::pid_t) -> bool {
    events
        .iter()
        .any(|event| event.filter == libc::EVFILT_PROC && event.ident == pid as usize)
}

/// Sends `signal` to the program unless it has ended. Returns whether it sent the signal.
fn send(queue: &OwnedFd, program: libc::pid_t, signal: libc::c_int) -> bool {
    if ends_within(queue, program, Duration::ZERO) {
        return false;
    }
    // SAFETY: kill takes a process ID and a signal; see the module documentation for the ID.
    unsafe { libc::kill(program, signal) };
    true
}

/// Whether the program ends within `timeout`. The kqueue reports the end once, so a caller that
/// gets `true` must not ask again.
fn ends_within(queue: &OwnedFd, program: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut events = [NO_EVENT; 2];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match helper::wait_events(queue, &mut events, Some(left)) {
            Ok(0) | Err(_) => return false,
            Ok(count) if exited(&events[..count], program) => return true,
            Ok(_) => {}
        }
    }
}
