//! The relay for `network.expose`. sandy starts it before it confines itself:
//!
//! 1. Bind every listener and open a pidfd for sandy's own process ID, which the program keeps
//!    after execve.
//! 2. Fork twice. The intermediate process exits at once, so the relay is not a child of the
//!    program and the program's wait never reaps it.
//! 3. The relay closes every descriptor except the listeners, the pidfd, standard error and the
//!    readiness pipe, then confines itself: no_new_privs, Landlock without any file access and
//!    with TCP connect only to the exposed ports, and seccomp filters for its few system calls.
//! 4. It starts serving and reports readiness. sandy continues only after that report.
//! 5. It exits when the pidfd becomes readable, that is when the program ends, also by SIGKILL.
//!
//! The relay is a fork, not a new program. sandy is single-threaded when it forks (checked), so
//! the child can use the allocator and threads like any process.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::thread;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, Ruleset,
    RulesetAttr, RulesetCreatedAttr, Scope,
};
use sandy_core::{ExposedPort, SandboxError};

use crate::filter;
use crate::launch::{ensure_single_thread, restrict, set_no_new_privs};

/// What the relay needs from the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayConfig {
    pub expose: Vec<ExposedPort>,
    pub abi: ABI,
}

const READY: &[u8] = b"ready";

/// Starts the relay and returns once it is confined and serving.
pub fn start(config: &RelayConfig) -> Result<(), SandboxError> {
    let listeners = config
        .expose
        .iter()
        .map(|expose| {
            let listener = TcpListener::bind(expose.listen).map_err(|error| {
                SandboxError::io(format!("cannot listen on {}", expose.listen), error)
            })?;
            Ok((listener, expose.target()))
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let program = pidfd_open_self()?;
    let (mut ready_read, ready_write) = pipe()?;
    ensure_single_thread()?;

    // SAFETY: sandy is single-threaded (checked above), so the child may run any code. Both
    // children leave only through `_exit`, never by returning into sandy's code.
    let intermediate = unsafe { libc::fork() };
    match intermediate {
        -1 => {
            return Err(SandboxError::io(
                "cannot fork the relay",
                io::Error::last_os_error(),
            ));
        }
        0 => {
            drop(ready_read);
            // SAFETY: as above; the intermediate process is single-threaded too.
            match unsafe { libc::fork() } {
                0 => relay_main(listeners, program, ready_write, config),
                -1 => report_and_exit(ready_write, "cannot fork the relay"),
                // SAFETY: ends the intermediate process without running sandy's cleanup.
                _ => unsafe { libc::_exit(0) },
            }
        }
        _ => {}
    }
    drop(ready_write);
    drop(listeners);
    drop(program);
    let mut status = 0;
    // SAFETY: waits for the intermediate child, which exits right after its fork.
    unsafe { libc::waitpid(intermediate, &mut status, 0) };

    let mut report = Vec::new();
    ready_read
        .read_to_end(&mut report)
        .map_err(|error| SandboxError::io("cannot read the relay's report", error))?;
    if report.is_empty() {
        return Err(SandboxError::new("the relay ended before it was ready"));
    }
    if report != READY {
        return Err(SandboxError::new(format!(
            "the relay did not start: {}",
            String::from_utf8_lossy(&report)
        )));
    }
    Ok(())
}

fn relay_main(
    listeners: Vec<(TcpListener, SocketAddr)>,
    program: OwnedFd,
    ready: File,
    config: &RelayConfig,
) -> ! {
    let mut keep: Vec<RawFd> = listeners.iter().map(|(l, _)| l.as_raw_fd()).collect();
    keep.extend([program.as_raw_fd(), ready.as_raw_fd(), libc::STDERR_FILENO]);
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        confine(&keep, config)?;
        for (listener, target) in listeners {
            thread::Builder::new()
                .spawn(move || sandy_relay::serve(listener, target))
                .map_err(|error| SandboxError::io("cannot start a relay thread", error))?;
        }
        Ok::<(), SandboxError>(())
    }));
    match started {
        Ok(Ok(())) => {
            let mut ready = ready;
            if ready.write_all(READY).is_err() {
                // SAFETY: ends the relay without running sandy's cleanup.
                unsafe { libc::_exit(1) };
            }
            drop(ready);
            wait_for_exit(&program);
            // SAFETY: as above.
            unsafe { libc::_exit(0) }
        }
        Ok(Err(error)) => report_and_exit(ready, &error.to_string()),
        Err(_) => report_and_exit(ready, "the relay panicked"),
    }
}

fn report_and_exit(mut ready: File, message: &str) -> ! {
    let _ = ready.write_all(message.as_bytes());
    // SAFETY: ends the child without running sandy's cleanup.
    unsafe { libc::_exit(1) }
}

/// Closes the other descriptors, then applies no_new_privs, Landlock and seccomp.
fn confine(keep: &[RawFd], config: &RelayConfig) -> Result<(), SandboxError> {
    close_descriptors_except(keep)?;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(config.abi))
        .map_err(landlock_error)?;
    if config.abi >= ABI::V4 {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(landlock_error)?;
    }
    if config.abi >= ABI::V6 {
        ruleset = ruleset
            .scope(Scope::Signal | Scope::AbstractUnixSocket)
            .map_err(landlock_error)?;
    }
    let mut ruleset = ruleset.create().map_err(landlock_error)?;
    if config.abi >= ABI::V4 {
        for expose in &config.expose {
            let connect: BitFlags<AccessNet> = AccessNet::ConnectTcp.into();
            ruleset = ruleset
                .add_rule(NetPort::new(expose.port, connect))
                .map_err(landlock_error)?;
        }
    }
    set_no_new_privs()?;
    restrict(ruleset)?;
    let filters = filter::relay()
        .map_err(|error| SandboxError::new(format!("cannot build the relay filter: {error}")))?;
    filter::install(&filters)
        .map_err(|error| SandboxError::new(format!("cannot install the relay filter: {error}")))
}

fn landlock_error(error: landlock::RulesetError) -> SandboxError {
    SandboxError::new(format!("Landlock: {error}"))
}

/// Closes every descriptor that is not in `keep`, so the relay holds nothing of sandy's.
fn close_descriptors_except(keep: &[RawFd]) -> Result<(), SandboxError> {
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

/// Waits until the program ends. A pidfd becomes readable when its process exits.
fn wait_for_exit(program: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: program.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: `poll` points to one valid pollfd.
        let result = unsafe { libc::poll(&mut poll, 1, -1) };
        if result > 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

fn pidfd_open_self() -> Result<OwnedFd, SandboxError> {
    // SAFETY: getpid has no preconditions; pidfd_open returns a new close-on-exec descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
    if fd < 0 {
        return Err(SandboxError::io(
            "cannot open a pidfd for the program",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn pipe() -> Result<(File, File), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::io(
            "cannot create the relay's pipe",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: both descriptors were just created and nothing else owns them.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
