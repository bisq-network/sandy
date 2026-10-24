//! The relay for `network.expose` and `network.forward`. Both are pairs of a loopback address
//! the relay listens on and a loopback address it connects to: `expose` listens outside for the
//! program's port, `forward` listens on the program's port for a service outside. One relay
//! process serves all pairs. sandy starts it before it confines itself:
//!
//! 1. Bind every listener and open a pidfd for sandy's own process ID, which the program keeps
//!    after execve. With `children = "contained"` the ID stays sandy's, which ends after the
//!    program's process group.
//! 2. Start the relay as a helper process (see `helper`): forked twice, so it is not a child of
//!    the program and the program's wait never reaps it.
//! 3. The relay closes every descriptor except the listeners, the pidfd, standard error and the
//!    readiness pipe, then confines itself: no_new_privs, Landlock without any file access and
//!    with TCP connect only to the target ports, and seccomp filters for its few system calls.
//! 4. It reports readiness; sandy continues only after that report. It then polls the pidfd and
//!    the listeners and relays each accepted connection in its own threads.
//! 5. When the pidfd becomes readable, that is when the program (with `contained`: sandy) ends,
//!    also by SIGKILL, it closes the listeners at once, gives accepted connections at most one
//!    second, and exits. With `contained` it also polls a pipe whose write end only the guard
//!    holds: the pipe ends when the guard has ended the program's group, also while sandy is
//!    stopped and therefore does not end.
//!

use std::fs::File;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use landlock::{ABI, Scope};
use sandy_core::{ExposedPort, ForwardedPort, SandboxError};

use crate::filter;
use crate::helper::{self, Ready};

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

/// Starts the relay and returns once it is confined and serving. `ended` is the read end of the
/// guard's pipe with `children = "contained"` (see the module documentation).
pub fn start(config: &RelayConfig, ended: Option<File>) -> Result<(), SandboxError> {
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
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    helper::start("the relay", move |ready| {
        relay_main(listeners, program, ended, ready, config)
    })
}

fn relay_main(
    listeners: Vec<(TcpListener, SocketAddr)>,
    program: OwnedFd,
    ended: Option<File>,
    ready: Ready,
    config: &RelayConfig,
) {
    let mut keep: Vec<RawFd> = listeners.iter().map(|(l, _)| l.as_raw_fd()).collect();
    keep.extend([program.as_raw_fd(), ready.fd(), libc::STDERR_FILENO]);
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandy_relay::raise_descriptor_limit(listeners.len()).map_err(|error| {
            SandboxError::io("cannot raise the relay's descriptor limit", error)
        })?;
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
            ready.report();
            serve_until_exit(listeners, &program, ended.as_ref());
        }
        Ok(Err(error)) => ready.fail(&error.to_string()),
        Err(_) => ready.fail("the relay panicked"),
    }
}

/// How long accepted connections may outlive the program (rule 5 of "Forwarded ports" in
/// DESIGN.md).
const DRAIN: Duration = Duration::from_secs(1);
const DRAIN_POLL: Duration = Duration::from_millis(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// Accepts and relays connections until the program ends (or the guard's pipe `ended` ends),
/// then closes the listeners at once and gives the accepted connections at most `DRAIN` to
/// deliver what is left. A program that connects, writes and exits therefore does not lose its
/// data, as it would not without a relay.
fn serve_until_exit(
    listeners: Vec<(TcpListener, SocketAddr)>,
    program: &OwnedFd,
    ended: Option<&File>,
) {
    // One count per listener: clients of one port cannot take the connections of another.
    let active: Vec<Arc<AtomicUsize>> = listeners
        .iter()
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();
    let total = || {
        active
            .iter()
            .map(|count| count.load(Ordering::Acquire))
            .sum::<usize>()
    };
    // The end watches come first; the listeners follow.
    let ends: Vec<RawFd> = [program.as_raw_fd()]
        .into_iter()
        .chain(ended.map(AsRawFd::as_raw_fd))
        .collect();
    let mut polls: Vec<libc::pollfd> = ends
        .iter()
        .copied()
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
        let watched = polls[ends.len()..].iter().zip(&listeners).zip(&active);
        for ((poll, (listener, target)), count) in watched {
            if poll.revents != 0 {
                accept_all(listener, *target, count);
            }
        }
        if polls[..ends.len()].iter().any(|poll| poll.revents != 0) {
            break;
        }
    }
    drop(listeners);
    let ended = Instant::now();
    while total() > 0 && ended.elapsed() < DRAIN {
        thread::sleep(DRAIN_POLL);
    }
    if total() > 0 {
        // The relay ends now; the connections it still relays end with a reset, not with the
        // normal end that would look like a complete stream.
        sandy_relay::abort_all();
    }
}

/// Accepts every waiting connection on `listener` and relays each one in its own thread, up to
/// `sandy_relay::MAX_CONNECTIONS` of this listener at the same time.
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

/// Closes the other descriptors, then applies no_new_privs, Landlock (TCP connect only to the
/// targets, signal and abstract socket scopes) and seccomp.
fn confine(keep: &[RawFd], config: &RelayConfig) -> Result<(), SandboxError> {
    let filters = filter::relay()
        .map_err(|error| SandboxError::new(format!("cannot build the relay filter: {error}")))?;
    helper::confine(
        "the relay",
        keep,
        config.abi,
        config.pairs.iter().map(|pair| pair.target.port()),
        Scope::Signal | Scope::AbstractUnixSocket,
        &filters,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostCapabilities;
    use std::fs::File;
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
