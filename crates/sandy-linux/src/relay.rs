//! The relay for `network.expose` and `network.forward`. Both are pairs of a loopback address
//! the relay listens on and a loopback address it connects to: `expose` listens outside for the
//! program's port, `forward` listens on the program's port for a service outside. One relay
//! process serves all pairs. sandy starts it before it confines itself:
//!
//! 1. Bind every listener and open a pidfd for sandy's own process ID, which the program keeps
//!    after execve. With `children = "contained"` the ID stays sandy's, which ends after the
//!    program's process group.
//! 2. Fork twice. The intermediate process exits at once, so the relay is not a child of the
//!    program and the program's wait never reaps it.
//! 3. The relay closes every descriptor except the listeners, the pidfd, standard error and the
//!    readiness pipe, then confines itself: no_new_privs, Landlock without any file access and
//!    with TCP connect only to the target ports, and seccomp filters for its few system calls.
//! 4. It reports readiness; sandy continues only after that report. It then polls the pidfd and
//!    the listeners and relays each accepted connection in its own threads.
//! 5. When the pidfd becomes readable, that is when the program (with `contained`: sandy) ends,
//!    also by SIGKILL, it closes the listeners at once, gives accepted connections at most one
//!    second, and exits.
//!
//! The relay is a fork, not a new program. sandy is single-threaded when it forks (checked), so
//! the child can use the allocator and threads like any process.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, Ruleset,
    RulesetAttr, RulesetCreatedAttr, Scope,
};
use sandy_core::{ExposedPort, ForwardedPort, SandboxError};

use crate::filter;
use crate::launch::{ensure_single_thread, restrict, set_no_new_privs};

/// The relay accepts connections on `listen` and connects each one to `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPair {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

/// What the relay needs from the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayConfig {
    pub pairs: Vec<RelayPair>,
    pub abi: ABI,
}

impl RelayConfig {
    /// The relay for these ports, or `None` when there is nothing to relay.
    pub fn new(expose: &[ExposedPort], forward: &[ForwardedPort], abi: ABI) -> Option<Self> {
        let exposed = expose.iter().map(|expose| RelayPair {
            listen: expose.listen,
            target: expose.target(),
        });
        let forwarded = forward.iter().map(|forward| RelayPair {
            listen: forward.listen(),
            target: forward.to,
        });
        let pairs: Vec<RelayPair> = exposed.chain(forwarded).collect();
        (!pairs.is_empty()).then_some(RelayConfig { pairs, abi })
    }
}

const READY: &[u8] = b"ready";

/// Starts the relay and returns once it is confined and serving.
pub fn start(config: &RelayConfig) -> Result<(), SandboxError> {
    let listeners = config
        .pairs
        .iter()
        .map(|pair| {
            let listener = TcpListener::bind(pair.listen).map_err(|error| {
                SandboxError::io(format!("cannot listen on {}", pair.listen), error)
            })?;
            Ok((listener, pair.target))
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let program = pidfd_open_self()?;
    let (mut ready_read, ready_write) = pipe("the relay's pipe")?;
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
        // Every connection gets its own threads. Starting one now shows that the filter allows
        // it, so a missing system call fails the start instead of the first connection.
        thread::Builder::new()
            .spawn(|| ())
            .and_then(|thread| {
                thread
                    .join()
                    .map_err(|_| io::Error::other("the test thread panicked"))
            })
            .map_err(|error| SandboxError::io("cannot start a relay thread", error))?;
        for (listener, _) in &listeners {
            listener
                .set_nonblocking(true)
                .map_err(|error| SandboxError::io("cannot prepare a listener", error))?;
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
            serve_until_exit(listeners, &program);
            // SAFETY: as above.
            unsafe { libc::_exit(0) }
        }
        Ok(Err(error)) => report_and_exit(ready, &error.to_string()),
        Err(_) => report_and_exit(ready, "the relay panicked"),
    }
}

/// How long accepted connections may outlive the program (rule 5 of "Forwarded ports" in
/// DESIGN.md).
const DRAIN: Duration = Duration::from_secs(1);
const DRAIN_POLL: Duration = Duration::from_millis(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// Accepts and relays connections until the program ends, then closes the listeners at once and
/// gives the accepted connections at most `DRAIN` to deliver what is left. A program that
/// connects, writes and exits therefore does not lose its data, as it would not without a relay.
fn serve_until_exit(listeners: Vec<(TcpListener, SocketAddr)>, program: &OwnedFd) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut polls: Vec<libc::pollfd> = [program.as_raw_fd()]
        .into_iter()
        .chain(listeners.iter().map(|(listener, _)| listener.as_raw_fd()))
        .map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    loop {
        // SAFETY: `polls` holds `len` valid pollfd entries.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Without poll the relay cannot see the program end; it must not outlive it.
            break;
        }
        // Connections that completed together with the end of the program are still taken.
        for (poll, (listener, target)) in polls[1..].iter().zip(&listeners) {
            if poll.revents != 0 {
                accept_all(listener, *target, &active);
            }
        }
        if polls[0].revents != 0 {
            break;
        }
    }
    drop(listeners);
    let ended = Instant::now();
    while active.load(Ordering::Acquire) > 0 && ended.elapsed() < DRAIN {
        thread::sleep(DRAIN_POLL);
    }
}

/// Accepts every waiting connection on `listener` and relays each one in its own thread, up to
/// `sandy_relay::MAX_CONNECTIONS` at the same time.
fn accept_all(listener: &TcpListener, target: SocketAddr, active: &Arc<AtomicUsize>) {
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            // A connection reset before accept, or no descriptors left: try again on the next
            // readiness report, after a pause so a lasting error does not spin.
            Err(_) => {
                thread::sleep(ACCEPT_ERROR_PAUSE);
                return;
            }
        };
        if active.fetch_add(1, Ordering::AcqRel) >= sandy_relay::MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let slot = Slot(Arc::clone(active));
        // If the thread cannot start, the closure and its slot are dropped, which frees the slot.
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            let _ = sandy_relay::relay(client, target);
        });
    }
}

/// One counted connection. Dropping it frees the count, also when its thread never started.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
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
        for pair in &config.pairs {
            let connect: BitFlags<AccessNet> = AccessNet::ConnectTcp.into();
            ruleset = ruleset
                .add_rule(NetPort::new(pair.target.port(), connect))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostCapabilities;
    use std::net::TcpStream;

    const OUTCOMES: [&str; 6] = [
        "ok",
        "confine failed",
        "the target was unreachable",
        "another port was reachable",
        "a file could be opened",
        "a new socket could be bound",
    ];

    /// What a compromised relay would try after `confine`. Returns an index into `OUTCOMES`.
    fn try_escapes(config: &RelayConfig, other: SocketAddr) -> i32 {
        if confine(&[libc::STDERR_FILENO], config).is_err() {
            return 1;
        }
        if TcpStream::connect(config.pairs[0].target).is_err() {
            return 2;
        }
        // Landlock checks TCP ports from ABI 4; older kernels allow every port.
        if config.abi >= ABI::V4 && TcpStream::connect(other).is_ok() {
            return 3;
        }
        if File::open("/proc/self/status").is_ok() {
            return 4;
        }
        if TcpListener::bind("127.0.0.1:0").is_ok() {
            return 5;
        }
        0
    }

    /// The child process applies the relay's confinement to itself. It never prints and leaves
    /// through `_exit`; the allocator stays usable after fork in glibc and musl, also while other
    /// test threads run.
    #[test]
    fn the_confined_relay_reaches_only_its_targets() {
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let config = RelayConfig {
            pairs: vec![RelayPair {
                listen: "127.0.0.1:1".parse().unwrap(),
                target: target.local_addr().unwrap(),
            }],
            abi: ABI::from(version),
        };
        let other = other.local_addr().unwrap();
        // SAFETY: the child only runs `try_escapes` and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = try_escapes(&config, other);
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        let outcome = libc::WEXITSTATUS(status) as usize;
        assert_eq!(outcome, 0, "{}", OUTCOMES[outcome.min(OUTCOMES.len() - 1)]);
    }
}
