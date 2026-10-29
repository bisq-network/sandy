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
//! 3. The relay closes every descriptor except the listeners, the pidfd, `/dev/null` as its
//!    standard descriptors and the readiness pipe, then confines itself: no_new_privs, Landlock
//!    without any file access and with TCP connect only to the target ports, and seccomp filters
//!    for its few system calls.
//! 4. It reports readiness; sandy continues only after that report. It then polls the pidfd and
//!    the listeners and relays each accepted connection in its own threads.
//! 5. When the pidfd becomes readable, that is when the program (with `contained`: sandy) ends,
//!    also by SIGKILL, it closes the listeners at once, gives accepted connections at most one
//!    second, and exits. With `contained` it also polls a pipe whose write end only the guard
//!    holds: the pipe ends when the guard has ended the program's group, also while sandy is
//!    stopped and therefore does not end.
//! 6. With the default `signals = "any"` the program may send SIGSTOP to the relay, which no
//!    process can block. A stopped relay sees neither the end of the program nor its own
//!    listeners, so the kernel keeps completing handshakes for them. The relay therefore has a
//!    watchdog: a timer that kills it when its poll loop has not run for `WATCHDOG` (see
//!    `Watchdog`). With `signals = "isolated"` the program cannot signal the relay, and the relay
//!    has no timer: there it could only kill a healthy relay that the host was slow to schedule.
//!
//! With `ip = "private"` the program's side of each pair is the sandbox's network namespace
//! (`namespace`), while the relay stays in the host's, so that it can listen and connect there.
//! A socket belongs to the namespace it was created in, so:
//!
//! - A forward listener is bound inside after sandy entered the namespace and handed to the
//!   relay (`handover`), which waits for it once it is confined. No other user reaches that
//!   namespace, so the relay checks no owner there (`peer`).
//! - An exposed listener is bound outside in step 1, as without the namespace. The connection to
//!   the program's port must start inside, so the relay asks the socket factory there for each
//!   socket and connects it itself (`factory`). When the factory ends, the relay ends.
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
use sandy_core::{ExposedPort, ForwardedPort, SandboxError, SignalScope};

use crate::factory::{self, Factory};
use crate::filter;
use crate::handover::{self, Handover, Inbox};
use crate::helper::{self, Ready, WATCHDOG_TICK, Watchdog};
use crate::launch::Threads;
use crate::peer::PeerCheck;

/// Why a contained program ends when its relay ends first (`contain::Helper`).
pub const ENDED_FIRST: &str = "the relay of the exposed or forwarded ports ended before the \
    program; the ports it served are gone and the program has been ended with it";

/// The relay accepts connections on `listen` and connects each one to `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPair {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

/// What the relay needs from the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayConfig {
    /// The exposed pairs first, then the forwarded ones.
    pub pairs: Vec<RelayPair>,
    /// How many of `pairs` are forwarded ports, which come last. A forwarded port serves the
    /// program alone, so only there does the relay refuse connections from other users; an
    /// exposed port is meant for other processes, which may belong to another user.
    pub forwarded: usize,
    /// Whether the relay arms its watchdog: only with `signals = "any"`, where the program can
    /// stop it (see `Watchdog`).
    pub watchdog: bool,
    pub abi: ABI,
    /// `ip = "private"`: the program's side is the sandbox's network namespace (see the module
    /// documentation).
    pub private: bool,
}

impl RelayConfig {
    /// The relay for these ports, or `None` when there is nothing to relay.
    pub fn new(
        expose: &[ExposedPort],
        forward: &[ForwardedPort],
        signals: SignalScope,
        abi: ABI,
        private: bool,
    ) -> Option<Self> {
        let exposed = expose.iter().map(|expose| RelayPair {
            listen: expose.listen,
            target: expose.target(),
        });
        let forwarded = forward.iter().map(|forward| RelayPair {
            listen: forward.listen(),
            target: forward.to,
        });
        let pairs: Vec<RelayPair> = exposed.chain(forwarded).collect();
        (!pairs.is_empty()).then_some(RelayConfig {
            pairs,
            forwarded: forward.len(),
            watchdog: signals == SignalScope::Any,
            abi,
            private,
        })
    }

    fn exposed(&self) -> &[RelayPair] {
        &self.pairs[..self.pairs.len() - self.forwarded]
    }

    fn forwarded(&self) -> &[RelayPair] {
        &self.pairs[self.pairs.len() - self.forwarded..]
    }
}

/// What the process that enters the sandbox's network namespace still does for a started relay,
/// with `RelayConfig::private`: bind the forward listeners and hand them over, and start the
/// socket factory of the exposed ports. Both after `Namespaces::enter`.
#[derive(Debug, Default)]
pub struct Inside {
    pub handover: Option<Handover>,
    pub factory: Option<factory::Pending>,
}

/// One listening socket of the relay and what it does with the connections it accepts.
struct Served {
    listener: TcpListener,
    listen: SocketAddr,
    target: SocketAddr,
    /// Whether a connection the kernel names as another user's is refused (see `peer`).
    refuse_other_users: bool,
    /// With `RelayConfig::private`, an exposed port connects through the socket factory.
    factory: Option<Arc<Factory>>,
}

impl Served {
    fn new(listener: TcpListener, pair: &RelayPair) -> Served {
        Served {
            listener,
            listen: pair.listen,
            target: pair.target,
            refuse_other_users: false,
            factory: None,
        }
    }
}

/// Starts the relay and returns its process ID once it is confined, and what is left to do
/// inside the namespace with `RelayConfig::private`. `ended` is the read end of the guard's pipe
/// with `children = "contained"` (see the module documentation).
pub fn start(
    config: &RelayConfig,
    ended: Option<File>,
) -> Result<(libc::pid_t, Inside), SandboxError> {
    let bind = |pair: &RelayPair| {
        TcpListener::bind(pair.listen)
            .map(|listener| Served::new(listener, pair))
            .map_err(|error| SandboxError::io(format!("cannot listen on {}", pair.listen), error))
    };
    let mut inside = Inside::default();
    let (factory, pending) = match config.private && !config.exposed().is_empty() {
        true => {
            let (factory, pending) = factory::pair()?;
            (Some(Arc::new(factory)), Some(pending))
        }
        false => (None, None),
    };
    inside.factory = pending;
    let mut listeners = config
        .exposed()
        .iter()
        .map(|pair| {
            let mut served = bind(pair)?;
            served.factory = factory.clone();
            Ok(served)
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let mut inbox = None;
    let mut peers = None;
    if config.private {
        if !config.forwarded().is_empty() {
            let addresses = config.forwarded().iter().map(|pair| pair.listen).collect();
            let (handover, received) = handover::pair(addresses, "the relay")?;
            inside.handover = Some(handover);
            inbox = Some(received);
        }
    } else if !config.forwarded().is_empty() {
        for pair in config.forwarded() {
            let mut served = bind(pair)?;
            served.refuse_other_users = true;
            listeners.push(served);
        }
        // The check needs a netlink socket, which the relay cannot open once it is confined, and
        // it refuses the run here when the kernel cannot answer.
        peers = Some(PeerCheck::open()?);
    }
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    let relay = Relay {
        listeners,
        inbox,
        factory,
        peers,
        program,
        ended,
    };
    let threads = Threads::open()?;
    let pid = helper::start("the relay", &threads, move |ready| {
        relay_main(relay, ready, config)
    })?;
    Ok((pid, inside))
}

/// What the relay process owns.
struct Relay {
    listeners: Vec<Served>,
    /// With `RelayConfig::private`, where the forward listeners arrive.
    inbox: Option<Inbox>,
    factory: Option<Arc<Factory>>,
    peers: Option<PeerCheck>,
    program: OwnedFd,
    ended: Option<File>,
}

fn relay_main(relay: Relay, ready: Ready, config: &RelayConfig) {
    let Relay {
        mut listeners,
        inbox,
        factory,
        peers,
        program,
        ended,
    } = relay;
    let mut keep: Vec<RawFd> = listeners
        .iter()
        .map(|served| served.listener.as_raw_fd())
        .collect();
    keep.extend([program.as_raw_fd(), ready.fd()]);
    keep.extend(helper::STANDARD_DESCRIPTORS);
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(peers.as_ref().map(PeerCheck::fd));
    keep.extend(inbox.as_ref().map(Inbox::fd));
    keep.extend(factory.as_ref().map(|factory| factory.fd()));
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandy_relay::raise_descriptor_limit(config.pairs.len()).map_err(|error| {
            SandboxError::io("cannot raise the relay's descriptor limit", error)
        })?;
        // Created before the filter is installed, so only re-arming it has to pass the filter.
        let watchdog = config
            .watchdog
            .then(|| Watchdog::create("the relay"))
            .transpose()?;
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
        for served in &listeners {
            served
                .listener
                .set_nonblocking(true)
                .map_err(|error| SandboxError::io("cannot prepare a listener", error))?;
        }
        Ok::<Option<Watchdog>, SandboxError>(watchdog)
    }));
    let watchdog = match started {
        Ok(Ok(watchdog)) => watchdog,
        Ok(Err(error)) => ready.fail(&error.to_string()),
        Err(_) => ready.fail("the relay panicked"),
    };
    ready.report();
    let mut ends = vec![program.as_raw_fd()];
    ends.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    if let Some(inbox) = inbox {
        let Some(received) = inbox.wait(&ends, watchdog.as_ref()) else {
            return;
        };
        for (listener, pair) in received.into_iter().zip(config.forwarded()) {
            if listener.set_nonblocking(true).is_err() {
                return;
            }
            listeners.push(Served::new(listener, pair));
        }
    }
    serve_until_exit(
        listeners,
        peers.as_ref(),
        &ends,
        factory.as_deref(),
        watchdog.as_ref(),
    );
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
///
/// `ends` are the program's pidfd and the guard's pipe. With a socket factory the relay also
/// ends when the factory has ended: without it, no exposed connection reaches the program.
fn serve_until_exit(
    listeners: Vec<Served>,
    peers: Option<&PeerCheck>,
    ends: &[RawFd],
    factory: Option<&Factory>,
    watchdog: Option<&Watchdog>,
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
    // The end watches come first; the listeners follow. The factory's socket carries answers
    // for the connection threads, so only its end counts here: poll reports a hangup without
    // being asked.
    let readable = |fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut polls: Vec<libc::pollfd> = ends.iter().copied().map(readable).collect();
    polls.extend(factory.map(|factory| libc::pollfd {
        fd: factory.fd(),
        events: 0,
        revents: 0,
    }));
    let watched = polls.len();
    polls.extend(
        listeners
            .iter()
            .map(|served| readable(served.listener.as_raw_fd())),
    );
    let tick = match watchdog {
        Some(_) => WATCHDOG_TICK.as_millis() as libc::c_int,
        None => -1,
    };
    loop {
        if let Some(watchdog) = watchdog {
            watchdog.rearm();
        }
        // SAFETY: `polls` holds `len` valid pollfd entries.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, tick) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Without poll the relay cannot see the program end; it must not outlive it.
            break;
        }
        let stopped = was_stopped();
        let over = polls[..watched].iter().any(|poll| poll.revents != 0);
        // Connections that completed together with the end of the program are still taken. Not
        // so after a stop: the relay did not run, so its backlog may hold connections that were
        // made after the program ended.
        if !(over && stopped) {
            let waiting = polls[watched..].iter().zip(&listeners).zip(&active);
            for ((poll, served), count) in waiting {
                if poll.revents != 0 {
                    accept_all(served, peers, count);
                }
            }
        }
        if over {
            // The kernel completes a handshake on its own, so it can have queued a connection
            // after it filled in this turn's poll result. Closing the listeners now would drop
            // it, and rule 5 of "Forwarded ports" promises the program's last connection, so
            // take what is waiting. Not after a stop, for the reason above.
            if !stopped {
                for (served, count) in listeners.iter().zip(&active) {
                    accept_all(served, peers, count);
                }
            }
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

/// Whether the relay was stopped and continued since the last turn of the poll loop. SIGSTOP
/// cannot be blocked, but SIGCONT can: the helper blocks every signal except the faults, so the
/// kernel continues the process and leaves SIGCONT pending, which a long turn on a merely busy
/// host does not.
///
/// It is not exact at the moment of resuming. The kernel wakes a stopped process before it
/// queues the signal, so a relay can run a turn before the SIGCONT is there to take, and the
/// end of the program is not always in the same poll result as the readiness of a listener.
/// A relay continued while its program has already ended can therefore take its backlog before
/// it can tell that either happened, which has been seen on this host. What bounds that window
/// is the watchdog ending a relay that was stopped for `WATCHDOG`, not this check. Without a
/// watchdog the program cannot stop the relay in the first place.
fn was_stopped() -> bool {
    // SAFETY: sigset_t is plain data, and the two calls initialize and change it.
    let cont = unsafe {
        let mut cont: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut cont);
        libc::sigaddset(&mut cont, libc::SIGCONT);
        cont
    };
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: takes a pending SIGCONT without waiting; the siginfo is not needed.
    unsafe { libc::sigtimedwait(&cont, std::ptr::null_mut(), &now) >= 0 }
}

/// Accepts every waiting connection on `served` and relays each one in its own thread, up to
/// `sandy_relay::MAX_CONNECTIONS` of this listener at the same time. A connection the kernel
/// names as another user's is closed before it takes one of those places.
fn accept_all(served: &Served, peers: Option<&PeerCheck>, active: &Arc<AtomicUsize>) {
    let target = served.target;
    loop {
        let (client, peer) = match served.listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            // A connection reset before accept, or no descriptors left: try again on the next
            // readiness report, after a pause so a lasting error does not spin.
            Err(_) => {
                thread::sleep(ACCEPT_ERROR_PAUSE);
                return;
            }
        };
        if served.refuse_other_users
            && !peers.is_some_and(|peers| peers.may_relay(peer, served.listen))
        {
            continue;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= sandy_relay::MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let slot = Slot(Arc::clone(active));
        let factory = served.factory.clone();
        // If the thread cannot start, the closure and its slot are dropped, which frees the slot.
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            let _ = match factory {
                Some(factory) => factory
                    .connect(target)
                    .and_then(|server| sandy_relay::relay_streams(client, server)),
                None => sandy_relay::relay(client, target),
            };
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
    let targets: Vec<u16> = config.pairs.iter().map(|pair| pair.target.port()).collect();
    helper::confine(
        "the relay",
        keep,
        config.abi,
        Some(&targets),
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

    const OUTCOMES: [&str; 8] = [
        "ok",
        "confine failed",
        "the target was unreachable",
        "another port was reachable",
        "a file could be opened",
        "a new socket could be bound",
        "a process could be started",
        "no thread could be started",
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
        // clone with fork's flags; the other arguments are zero on x86_64 and arm64 alike.
        // SAFETY: a child that clone creates leaves through `_exit` at once.
        let child = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
        if child == 0 {
            // SAFETY: ends the child without running anything of the parent's.
            unsafe { libc::_exit(0) };
        }
        if child > 0 {
            // SAFETY: reaps the child created above.
            unsafe { libc::waitpid(child as libc::pid_t, std::ptr::null_mut(), 0) };
            return 6;
        }
        if std::thread::spawn(|| ()).join().is_err() {
            return 7;
        }
        0
    }

    /// The child process applies the relay's confinement to itself. It never prints and leaves
    /// through `_exit`. It starts a thread, so the test runs in a process of its own (`alone`).
    #[test]
    fn the_confined_relay_reaches_only_its_targets() {
        if !crate::alone::in_own_process() {
            return;
        }
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
            forwarded: 0,
            watchdog: true,
            abi: ABI::from(version),
            private: false,
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
