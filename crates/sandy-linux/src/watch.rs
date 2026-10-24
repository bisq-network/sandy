//! `process.end_with_parent`: a watcher process ends the program when the process that started
//! sandy ends.
//!
//! 1. sandy reads its parent's process ID as its first step (or the caller names it with
//!    `--parent-pid` and sandy checks it then). Here it opens a pidfd for that process and checks
//!    that it is still sandy's parent; otherwise the parent has already ended, and sandy refuses
//!    to start the program. With `--parent-start` the caller names the start time of its own
//!    process instead, and sandy checks that (see `check_start`), so the named process need not
//!    be sandy's parent. It also opens a pidfd for its own process ID, which the program keeps
//!    after execve. With `children = "contained"` the ID stays the supervising sandy's, which
//!    forwards the signals and ends the program's process group.
//! 2. sandy starts the watcher as a helper process (see `helper`), so it is not a child of the
//!    program. The watcher keeps only the two pidfds, the readiness pipe and `/dev/null` as its
//!    standard descriptors, and confines itself:
//!    no_new_privs, Landlock without file access and without TCP, and a seccomp filter that allows
//!    only polling, the readiness report, ending, and `pidfd_send_signal` through the program's
//!    descriptor with the three signals below. It has no Landlock signal scope, because it must
//!    signal the program, which runs in another Landlock domain.
//! 3. The watcher polls both pidfds. When the program ends first, the watcher ends. When the
//!    parent ends, the watcher sends SIGTERM and SIGCONT (so that a stopped program gets the
//!    request) to the program, waits at most `GRACE` for it to end, then sends SIGKILL, and ends.
//!
//! The policy requires `signals = "isolated"`, so the program cannot signal the watcher, and the
//! watcher is in a session of its own with every signal blocked (see `helper`), so no group or
//! terminal signal reaches it either. It is also undumpable, so a program with a write grant on
//! `/proc` cannot raise its `oom_score_adj` and have the kernel end it under memory pressure.
//!
//! A parent that ends before sandy has read its process ID cannot be detected without
//! `--parent-pid` and `--parent-start`: sandy then already has another parent, the process it
//! was re-parented to, and nothing on the host records which process started sandy.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use landlock::{ABI, Scope};
use sandy_core::{ParentProcess, SandboxError};

use crate::filter;
use crate::helper::{self, Ready};

/// How long the program may take to end after SIGTERM before the watcher kills it.
pub const GRACE: Duration = Duration::from_secs(5);

/// Starts the watcher for `parent`, the process that started sandy, and returns once the watcher
/// is confined and watching.
pub fn start(parent: ParentProcess, abi: ABI) -> Result<(), SandboxError> {
    let id = parent.id as libc::pid_t;
    let parent_fd = open_parent(id)?;
    match parent.start {
        Some(token) => check_start(id, token, &parent_fd)?,
        // SAFETY: getppid has no preconditions.
        None if unsafe { libc::getppid() } != id => return Err(already_ended()),
        None => {}
    }
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    helper::start("the watcher", move |ready| {
        watcher_main(&parent_fd, &program, ready, abi)
    })?;
    Ok(())
}

fn already_ended() -> SandboxError {
    SandboxError::new("the process that started sandy has already ended")
}

/// A pidfd for the process that started sandy. `ESRCH` means that no process has that ID any
/// more, which `helper::pidfd_open` would report as a plain failure.
fn open_parent(id: libc::pid_t) -> Result<OwnedFd, SandboxError> {
    // SAFETY: pidfd_open takes a process ID and flags and returns a new close-on-exec
    // descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, id, 0u32) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::ESRCH) => already_ended(),
            _ => SandboxError::io("cannot open a pidfd for sandy's parent", error),
        });
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Checks that the process `id` started at `token`, so that the caller is told apart from a
/// process that got its ID afterwards. `pidfd` must be a pidfd of `id`.
///
/// The start time is read by process ID, which could name another process by the time it is
/// read. A pidfd becomes readable as soon as its process ends, so a pidfd that is not readable
/// after the read proves that the process held its ID throughout. That also covers a parent
/// that ended before sandy ran: either its ID is gone (`pidfd_open` fails), or the pidfd is
/// readable, or another process holds the ID now and its start time differs.
fn check_start(id: libc::pid_t, token: u64, pidfd: &OwnedFd) -> Result<(), SandboxError> {
    let Some(started) = start_time(id)? else {
        return Err(already_ended());
    };
    let mut poll = [readable(pidfd.as_raw_fd())];
    // SAFETY: polls one open descriptor and returns at once.
    if unsafe { libc::poll(poll.as_mut_ptr(), 1, 0) } != 0 {
        return Err(already_ended());
    }
    if started != token {
        return Err(SandboxError::new(format!(
            "process {id} started at {started}, not at {token} (--parent-start); the process \
             that started sandy may have ended already"
        )));
    }
    Ok(())
}

/// When process `id` started, in clock ticks since boot: field 22 of `/proc/ID/stat`. It is
/// measured from the boot of the host, so a change of the system clock does not alter it.
/// `None` when the process is gone.
fn start_time(id: libc::pid_t) -> Result<Option<u64>, SandboxError> {
    let path = format!("/proc/{id}/stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SandboxError::io(format!("cannot read {path}"), error)),
    };
    parse_start_time(&stat)
        .map(Some)
        .ok_or_else(|| SandboxError::new(format!("{path} has no start time")))
}

/// Field 22 of a `/proc/PID/stat` line. The name in field 2 can hold spaces and parentheses, so
/// the fields are counted from the last closing parenthesis; field 3 is the first after it.
fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = stat.get(stat.rfind(')')? + 1..)?;
    after_name.split_whitespace().nth(19)?.parse().ok()
}

fn watcher_main(parent: &OwnedFd, program: &OwnedFd, ready: Ready, abi: ABI) {
    let mut keep = vec![parent.as_raw_fd(), program.as_raw_fd(), ready.fd()];
    keep.extend(helper::STANDARD_DESCRIPTORS);
    let confined = helper::set_undumpable().and_then(|()| confine(&keep, program.as_raw_fd(), abi));
    if let Err(error) = confined {
        ready.fail(&error.to_string());
    }
    ready.report();
    watch(parent.as_raw_fd(), program.as_raw_fd());
}

fn confine(keep: &[RawFd], program: RawFd, abi: ABI) -> Result<(), SandboxError> {
    let filters = filter::watcher(program)
        .map_err(|error| SandboxError::new(format!("cannot build the watcher filter: {error}")))?;
    helper::confine(
        "the watcher",
        keep,
        abi,
        [],
        Scope::AbstractUnixSocket.into(),
        &filters,
    )
}

/// Waits until the parent or the program ends. When the parent ends first, or polling fails and
/// the watcher can no longer see it, ends the program.
fn watch(parent: RawFd, program: RawFd) {
    let mut polls = [readable(parent), readable(program)];
    // SAFETY: polls two open descriptors.
    while unsafe { libc::poll(polls.as_mut_ptr(), 2, -1) } < 0
        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
    {}
    if polls[1].revents != 0 {
        return;
    }
    send(program, libc::SIGTERM);
    send(program, libc::SIGCONT);
    if !ends_within(program, GRACE) {
        send(program, libc::SIGKILL);
    }
}

fn readable(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Whether the process behind `pidfd` ends within `timeout`.
fn ends_within(pidfd: RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut poll = [readable(pidfd)];
        let millis = left.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        // SAFETY: polls one open descriptor.
        match unsafe { libc::poll(poll.as_mut_ptr(), 1, millis) } {
            0 => return false,
            ready if ready > 0 => return true,
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
}

fn send(pidfd: RawFd, signal: libc::c_int) {
    // SAFETY: pidfd_send_signal with a null siginfo sends the bare signal to the pidfd's process,
    // which cannot be another process even if its ID was reused.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostCapabilities;
    use std::fs::File;
    use std::net::TcpListener;
    use std::process::{Command, Stdio};

    const OUTCOMES: [&str; 6] = [
        "ok",
        "confine failed",
        "a file could be opened",
        "a socket could be bound",
        "the program could not be signaled",
        "another process could be signaled",
    ];

    /// What a confined watcher can still do. Returns an index into `OUTCOMES`.
    fn try_escapes(program: RawFd, other: RawFd, abi: ABI) -> i32 {
        if confine(&[program, other], program, abi).is_err() {
            return 1;
        }
        if File::open("/proc/self/status").is_ok() {
            return 2;
        }
        if TcpListener::bind("127.0.0.1:0").is_ok() {
            return 3;
        }
        if send_signal(program, libc::SIGCONT) != 0 {
            return 4;
        }
        // The filter names the program's descriptor, so the second pidfd is out of reach.
        if send_signal(other, libc::SIGCONT) == 0 {
            return 5;
        }
        0
    }

    fn send_signal(pidfd: RawFd, signal: libc::c_int) -> libc::c_long {
        // SAFETY: pidfd_send_signal with a null siginfo sends the bare signal.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        }
    }

    #[test]
    fn the_start_time_is_field_22_whatever_the_name_holds() {
        let stat = "7 (a b) c) S 1 7 7 0 -1 4194560 300 0 0 0 1 2 0 0 20 0 1 0 918273 500 0";
        assert_eq!(parse_start_time(stat), Some(918_273));
        assert_eq!(parse_start_time("7 (prog) S 1"), None);
        assert_eq!(parse_start_time("nothing"), None);
    }

    /// The same value `/proc/self/stat` shows, and it does not change while the process runs.
    #[test]
    fn this_process_has_a_start_time() {
        // SAFETY: getpid has no preconditions.
        let own = unsafe { libc::getpid() };
        let first = start_time(own).unwrap().expect("this process runs");
        assert_eq!(start_time(own).unwrap(), Some(first));
        let pidfd = helper::pidfd_open(own, "this process").unwrap();
        check_start(own, first, &pidfd).unwrap();
        let error = check_start(own, first + 1, &pidfd).unwrap_err().to_string();
        assert!(error.contains("--parent-start"), "{error}");
    }

    /// The child process applies the watcher's confinement to itself. It never prints and leaves
    /// through `_exit`.
    #[test]
    fn the_confined_watcher_can_signal_the_program_and_nothing_else() {
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let mut program = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let pidfd = helper::pidfd_open(program.id() as libc::pid_t, "the program").unwrap();
        // SAFETY: getpid has no preconditions.
        let other = helper::pidfd_open(unsafe { libc::getpid() }, "this process").unwrap();
        // SAFETY: the child only runs `try_escapes` and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = try_escapes(pidfd.as_raw_fd(), other.as_raw_fd(), ABI::from(version));
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        let _ = program.kill();
        let _ = program.wait();
        assert!(libc::WIFEXITED(status), "wait status {status}");
        let outcome = libc::WEXITSTATUS(status) as usize;
        assert_eq!(outcome, 0, "{}", OUTCOMES[outcome.min(OUTCOMES.len() - 1)]);
    }
}
