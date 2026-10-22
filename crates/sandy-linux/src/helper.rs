//! Helper processes that sandy starts before it confines itself and that must not be children of
//! the program, such as the relay of exposed and forwarded ports:
//!
//! 1. sandy verifies that it has one thread and forks twice. The intermediate process exits at
//!    once, so the helper is not a child of the program and the program's wait never reaps it.
//!    The helper starts a session of its own and blocks every signal except the fault signals.
//!    Signals that the kernel sends to a process group or to a terminal's foreground group (Ctrl+C,
//!    a hangup, SIGTTIN, the SIGHUP to an orphaned group) skip the Landlock signal scope, and the
//!    program can cause some of them; in its own session the helper is in none of these groups,
//!    and a signal from another process of the user stays pending.
//! 2. The helper confines itself (`confine`) and reports over a close-on-exec pipe that it is
//!    ready, or why it is not. sandy continues only after a ready report.
//!
//! A helper is a fork, not a new program. sandy is single-threaded when it forks (checked), so the
//! child can use the allocator and threads like any process.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, Ruleset,
    RulesetAttr, RulesetCreatedAttr, Scope,
};
use sandy_core::SandboxError;

use crate::filter::{self, Filters};
use crate::launch::{ensure_single_thread, restrict, set_no_new_privs};

const READY: &[u8] = b"ready";

/// Signals that report a fault of the process itself. They stay unblocked, so a fault ends it.
const FAULTS: [libc::c_int; 7] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
    libc::SIGSYS,
    libc::SIGABRT,
];

/// Blocks every signal except the faults. Returns the blocked set and the previous mask. Blocked
/// signals stay pending, also when their action is to ignore them.
pub(crate) fn block_signals() -> io::Result<(libc::sigset_t, libc::sigset_t)> {
    // SAFETY: sigset_t is plain data; sigfillset and sigdelset initialize and change it, and
    // sigprocmask writes the previous mask into `previous`.
    unsafe {
        let mut blocked: libc::sigset_t = mem::zeroed();
        libc::sigfillset(&mut blocked);
        for fault in FAULTS {
            libc::sigdelset(&mut blocked, fault);
        }
        let mut previous: libc::sigset_t = mem::zeroed();
        if libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((blocked, previous))
    }
}

/// The helper's end of the readiness pipe.
pub(crate) struct Ready(File);

impl Ready {
    pub(crate) fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// Reports that the helper is confined and serving. Ends the helper if sandy is gone.
    pub(crate) fn report(mut self) {
        if self.0.write_all(READY).is_err() {
            // SAFETY: ends the helper without running sandy's cleanup.
            unsafe { libc::_exit(1) };
        }
    }

    /// Reports why the helper did not start, and ends it.
    pub(crate) fn fail(mut self, message: &str) -> ! {
        let _ = self.0.write_all(message.as_bytes());
        // SAFETY: ends the helper without running sandy's cleanup.
        unsafe { libc::_exit(1) }
    }
}

/// Starts `main` in a helper process named `name` (for example "the relay") and returns once it
/// reported that it is ready. `main` runs in the helper and must call `Ready::report` after it has
/// confined itself; the helper ends when `main` returns. What `main` owns is dropped in sandy.
pub(crate) fn start(name: &str, main: impl FnOnce(Ready)) -> Result<(), SandboxError> {
    let (mut ready_read, ready_write) = pipe(&format!("{name}'s pipe"))?;
    ensure_single_thread()?;

    // SAFETY: sandy is single-threaded (checked above), so the child may run any code. Both
    // children leave only through `_exit`, never by returning into sandy's code.
    let intermediate = unsafe { libc::fork() };
    match intermediate {
        -1 => {
            return Err(SandboxError::io(
                format!("cannot fork {name}"),
                io::Error::last_os_error(),
            ));
        }
        0 => {
            drop(ready_read);
            // SAFETY: as above; the intermediate process is single-threaded too.
            match unsafe { libc::fork() } {
                0 => {
                    // SAFETY: setsid has no preconditions; a grandchild never leads a group.
                    if unsafe { libc::setsid() } < 0 {
                        Ready(ready_write).fail(&format!("{name} cannot start a session"));
                    }
                    if let Err(error) = block_signals() {
                        Ready(ready_write).fail(&format!("{name} cannot block signals: {error}"));
                    }
                    // A panic must not unwind into sandy's code in this process.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        main(Ready(ready_write))
                    }));
                    // SAFETY: ends the helper without running sandy's cleanup.
                    unsafe { libc::_exit(0) }
                }
                -1 => Ready(ready_write).fail(&format!("cannot fork {name}")),
                // SAFETY: ends the intermediate process without running sandy's cleanup.
                _ => unsafe { libc::_exit(0) },
            }
        }
        _ => {}
    }
    drop(ready_write);
    drop(main);
    let mut status = 0;
    // SAFETY: waits for the intermediate child, which exits right after its fork.
    unsafe { libc::waitpid(intermediate, &mut status, 0) };

    let mut report = Vec::new();
    ready_read
        .read_to_end(&mut report)
        .map_err(|error| SandboxError::io(format!("cannot read {name}'s report"), error))?;
    if report.is_empty() {
        return Err(SandboxError::new(format!(
            "{name} ended before it was ready"
        )));
    }
    if report != READY {
        return Err(SandboxError::new(format!(
            "{name} did not start: {}",
            String::from_utf8_lossy(&report)
        )));
    }
    Ok(())
}

/// Closes every descriptor except `keep`, then applies no_new_privs, a Landlock ruleset without
/// any file access that allows TCP connect only to `connect_ports` and no TCP bind (from ABI 4)
/// and has `scopes` (from ABI 6), and `filters`. `name` names the helper in errors.
pub(crate) fn confine(
    name: &str,
    keep: &[RawFd],
    abi: ABI,
    connect_ports: impl IntoIterator<Item = u16>,
    scopes: BitFlags<Scope>,
    filters: &Filters,
) -> Result<(), SandboxError> {
    close_descriptors_except(keep)?;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(landlock_error)?;
    if abi >= ABI::V4 {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(landlock_error)?;
    }
    if abi >= ABI::V6 && !scopes.is_empty() {
        ruleset = ruleset.scope(scopes).map_err(landlock_error)?;
    }
    let mut ruleset = ruleset.create().map_err(landlock_error)?;
    if abi >= ABI::V4 {
        for port in connect_ports {
            let connect: BitFlags<AccessNet> = AccessNet::ConnectTcp.into();
            ruleset = ruleset
                .add_rule(NetPort::new(port, connect))
                .map_err(landlock_error)?;
        }
    }
    set_no_new_privs()?;
    restrict(ruleset)?;
    filter::install(filters)
        .map_err(|error| SandboxError::new(format!("cannot install {name}'s filter: {error}")))
}

fn landlock_error(error: landlock::RulesetError) -> SandboxError {
    SandboxError::new(format!("Landlock: {error}"))
}

/// Closes every descriptor that is not in `keep`, so a helper holds nothing of sandy's.
pub(crate) fn close_descriptors_except(keep: &[RawFd]) -> Result<(), SandboxError> {
    let mut keep: Vec<u32> = keep.iter().map(|&fd| fd as u32).collect();
    keep.sort_unstable();
    let mut first = 0u32;
    for &kept in keep.iter().chain([&u32::MAX]) {
        if kept > first {
            close_range(first, kept - 1)?;
        }
        first = kept.saturating_add(1);
    }
    Ok(())
}

fn close_range(first: u32, last: u32) -> Result<(), SandboxError> {
    // SAFETY: closes descriptors this process owns; the kept ones are outside the range.
    if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) } != 0 {
        return Err(SandboxError::io(
            "cannot close the inherited descriptors",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// A pidfd for process `pid`. `name` names the process in the error.
pub(crate) fn pidfd_open(pid: libc::pid_t, name: &str) -> Result<OwnedFd, SandboxError> {
    // SAFETY: pidfd_open takes a process ID and flags and returns a new close-on-exec descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(SandboxError::io(
            format!("cannot open a pidfd for {name}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// A close-on-exec pipe: (read end, write end). `name` names it in the error.
pub(crate) fn pipe(name: &str) -> Result<(File, File), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::io(
            format!("cannot create {name}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: both descriptors were just created and nothing else owns them.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
