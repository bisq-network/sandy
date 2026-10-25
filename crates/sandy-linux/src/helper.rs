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
//! 2. It points 0, 1 and 2 at `/dev/null`, as the macOS helper does. A helper that kept sandy's
//!    standard error would hold the caller's pipe open for as long as it runs, which the caller
//!    sees as output that never ends.
//! 3. The helper confines itself (`confine`) and reports over a close-on-exec pipe that it is
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

/// What a helper writes to its readiness pipe, followed by its process ID, so that sandy can
/// watch it. A failure writes a message instead, which never starts with this.
const READY: &str = "ready ";

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
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        if write!(self.0, "{READY}{pid}").is_err() {
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
pub(crate) fn start(name: &str, main: impl FnOnce(Ready)) -> Result<libc::pid_t, SandboxError> {
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|error| SandboxError::io("cannot open /dev/null", error))?;
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
                    if let Err(error) = null_standard_descriptors(&null) {
                        Ready(ready_write)
                            .fail(&format!("{name} cannot drop the caller's stdio: {error}"));
                    }
                    drop(null);
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
    let report = String::from_utf8_lossy(&report);
    let started = report
        .strip_prefix(READY)
        .and_then(|pid| pid.parse::<libc::pid_t>().ok());
    let Some(started) = started else {
        return Err(SandboxError::new(format!("{name} did not start: {report}")));
    };
    Ok(started)
}

/// Gives this process's `/proc/<pid>` files to root, so that the program cannot change them even
/// with a write grant on `/proc`. Without this the program can set `oom_score_adj` of sandy's
/// processes to the maximum and let the kernel's out-of-memory killer end them before anything
/// else, which takes away the guarantee they stand for. A child forked afterwards starts with the
/// flag, which the kernel resets when the child executes the target, so the program itself is
/// unaffected.
pub(crate) fn set_undumpable() -> Result<(), SandboxError> {
    // SAFETY: PR_SET_DUMPABLE only sets a process flag.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(SandboxError::io(
            "cannot hide the process from the program",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Makes a forked program dumpable again, which it inherited undumpable from sandy: the watcher of
/// the diagnostic mode reads the path of the program's execve out of its memory, which the kernel
/// allows only for a dumpable process (measured on Linux 7.2: every such path was unreadable).
/// It changes only this process, not sandy or the guard.
pub(crate) fn set_dumpable() -> Result<(), SandboxError> {
    // SAFETY: PR_SET_DUMPABLE only sets a process flag.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(SandboxError::io(
            "cannot make the program readable for the diagnostic mode",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Points 0, 1 and 2 at `/dev/null`. The helper keeps the three numbers, so a connection it
/// accepts later cannot take one of them and receive what a panic writes to standard error.
fn null_standard_descriptors(null: &File) -> io::Result<()> {
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: dup2 takes an open descriptor and the number it is copied to.
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The descriptor numbers every helper keeps: `/dev/null` as 0, 1 and 2.
pub(crate) const STANDARD_DESCRIPTORS: [RawFd; 3] =
    [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];

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

/// A close-on-exec Unix socket pair of `kind` (`SOCK_STREAM` or `SOCK_SEQPACKET`). `name` names it
/// in the error.
pub(crate) fn socket_pair(
    kind: libc::c_int,
    name: &str,
) -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two new descriptors into `fds`.
    let created = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            kind | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if created != 0 {
        return Err(SandboxError::io(
            format!("cannot create {name}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: both descriptors were just created and nothing else owns them.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// The control message of one descriptor, rounded up as the kernel expects it.
const CONTROL_SIZE: usize = {
    // SAFETY: CMSG_SPACE only computes a size.
    unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as usize }
};

/// Sends a copy of `descriptor` over the Unix socket `socket` (`SCM_RIGHTS`), with one byte.
pub(crate) fn send_descriptor(socket: RawFd, descriptor: RawFd) -> io::Result<()> {
    let mut body = [0u8; 1];
    let mut buffer = [0u8; CONTROL_SIZE];
    let mut iov = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    // SAFETY: msghdr is plain data; the fields below describe the buffers above, which live
    // until the call has returned.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    message.msg_controllen = buffer.len() as _;
    // SAFETY: the control buffer is large enough for one descriptor (CONTROL_SIZE), so
    // CMSG_FIRSTHDR returns a pointer into it.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header).cast::<RawFd>().write(descriptor);
    }
    // SAFETY: sends the message above over an open socket.
    let sent = unsafe { libc::sendmsg(socket, &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receives one descriptor that `send_descriptor` sent, close-on-exec. `None` when the other end
/// closed first, or sent no descriptor.
pub(crate) fn receive_descriptor(socket: &OwnedFd) -> Option<OwnedFd> {
    let mut body = [0u8; 1];
    let mut buffer = [0u8; CONTROL_SIZE];
    let mut iov = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    // SAFETY: as in `send_descriptor`.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    message.msg_controllen = buffer.len() as _;
    loop {
        // SAFETY: receives into the buffers above.
        let received =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if received <= 0 {
            return None;
        }
        break;
    }
    // SAFETY: reads the control message the kernel wrote into the buffer.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return None;
        }
        let descriptor = libc::CMSG_DATA(header).cast::<RawFd>().read();
        Some(OwnedFd::from_raw_fd(descriptor))
    }
}
