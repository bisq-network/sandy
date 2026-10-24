//! `process.end_with_parent`: a watcher process ends the program when the process that started
//! sandy ends.
//!
//! 1. sandy reads its parent's process ID as its first step (or the caller names it with
//!    `--parent-pid` and sandy checks it then). Here it opens a pidfd for that process and checks
//!    that it is still sandy's parent; otherwise the parent has already ended, and sandy refuses
//!    to start the program. It also opens a pidfd for its own process ID, which the program keeps
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
//! `--parent-pid`: sandy then already has another parent, the process it was re-parented to.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use landlock::{ABI, Scope};
use sandy_core::SandboxError;

use crate::filter;
use crate::helper::{self, Ready};

/// How long the program may take to end after SIGTERM before the watcher kills it.
pub const GRACE: Duration = Duration::from_secs(5);

/// Starts the watcher for `parent`, the process that started sandy, and returns once the watcher
/// is confined and watching.
pub fn start(parent_id: libc::pid_t, abi: ABI) -> Result<(), SandboxError> {
    let parent = helper::pidfd_open(parent_id, "sandy's parent")?;
    // SAFETY: as above.
    if unsafe { libc::getppid() } != parent_id {
        return Err(SandboxError::new(
            "the process that started sandy has already ended",
        ));
    }
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    helper::start("the watcher", move |ready| {
        watcher_main(&parent, &program, ready, abi)
    })
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
