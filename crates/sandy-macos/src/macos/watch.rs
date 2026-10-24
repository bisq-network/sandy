//! `process.end_with_parent`: a watcher process ends the program when the process that started
//! sandy ends.
//!
//! 1. sandy reads its parent's process ID as its first step (or the caller names it with
//!    `--parent-pid` and sandy checks it then). Here it checks that this process is still its
//!    parent; otherwise the parent has already ended, and sandy refuses to start the program.
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
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use sandy_core::SandboxError;

use super::helper::{self, NO_EVENT, new_queue, register};
use super::seatbelt::Seatbelt;
use crate::profile::{Profile, watcher_profile};

/// How long the program may take to end after SIGTERM before the watcher kills it.
pub const GRACE: Duration = Duration::from_secs(5);

/// Starts the watcher for `parent`, the process that started sandy, and returns once the watcher
/// is confined and watching.
pub fn start(parent: libc::pid_t, seatbelt: &Seatbelt) -> Result<(), SandboxError> {
    ensure_parent(parent)?;
    // SAFETY: getpid has no requirements.
    let program = unsafe { libc::getpid() };
    let profile = watcher_profile();
    let seatbelt = *seatbelt;
    helper::start("the watcher", &[], move |ready| {
        let queue = match watch_and_confine(parent, program, &profile, &seatbelt) {
            Ok(queue) => queue,
            Err(error) => ready.fail(&error.to_string()),
        };
        ready.report();
        watch(&queue, parent, program);
    })?;
    ensure_parent(parent)
}

fn ensure_parent(parent: libc::pid_t) -> Result<(), SandboxError> {
    // SAFETY: getppid has no requirements.
    if unsafe { libc::getppid() } != parent {
        return Err(SandboxError::new(
            "the process that started sandy has already ended",
        ));
    }
    Ok(())
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
