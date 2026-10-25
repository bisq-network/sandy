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

use crate::filter;
use crate::helper::{self, Ready};
use crate::peer::PeerCheck;

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
}

impl RelayConfig {
    /// The relay for these ports, or `None` when there is nothing to relay.
    pub fn new(
        expose: &[ExposedPort],
        forward: &[ForwardedPort],
        signals: SignalScope,
        abi: ABI,
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
        })
    }
}

/// One listening socket of the relay and what it does with the connections it accepts.
struct Served {
    listener: TcpListener,
    listen: SocketAddr,
    target: SocketAddr,
    /// Whether a connection the kernel names as another user's is refused (see `peer`).
    refuse_other_users: bool,
}

/// Starts the relay and returns its process ID once it is confined and serving. `ended` is the
/// read end of the guard's pipe with `children = "contained"` (see the module documentation).
pub fn start(config: &RelayConfig, ended: Option<File>) -> Result<libc::pid_t, SandboxError> {
    let exposed = config.pairs.len() - config.forwarded;
    let listeners = config
        .pairs
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let listener = TcpListener::bind(pair.listen).map_err(|error| {
                SandboxError::io(format!("cannot listen on {}", pair.listen), error)
            })?;
            Ok(Served {
                listener,
                listen: pair.listen,
                target: pair.target,
                refuse_other_users: index >= exposed,
            })
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    // The check needs a netlink socket, which the relay cannot open once it is confined, and it
    // refuses the run here when the kernel cannot answer.
    let peers = (config.forwarded > 0).then(PeerCheck::open).transpose()?;
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    helper::start("the relay", move |ready| {
        relay_main(listeners, peers, program, ended, ready, config)
    })
}

fn relay_main(
    listeners: Vec<Served>,
    peers: Option<PeerCheck>,
    program: OwnedFd,
    ended: Option<File>,
    ready: Ready,
    config: &RelayConfig,
) {
    let mut keep: Vec<RawFd> = listeners
        .iter()
        .map(|served| served.listener.as_raw_fd())
        .collect();
    keep.extend([program.as_raw_fd(), ready.fd()]);
    keep.extend(helper::STANDARD_DESCRIPTORS);
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(peers.as_ref().map(PeerCheck::fd));
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandy_relay::raise_descriptor_limit(listeners.len()).map_err(|error| {
            SandboxError::io("cannot raise the relay's descriptor limit", error)
        })?;
        // Created before the filter is installed, so only re-arming it has to pass the filter.
        let watchdog = config.watchdog.then(Watchdog::create).transpose()?;
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
    match started {
        Ok(Ok(watchdog)) => {
            ready.report();
            serve_until_exit(
                listeners,
                peers.as_ref(),
                &program,
                ended.as_ref(),
                watchdog.as_ref(),
            );
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

/// How long the relay lives after its poll loop stopped running. The loop re-arms the watchdog
/// every `WATCHDOG_TICK`, so this is the bound a stopped relay dies within, and at the same time
/// the margin a relay that the host is slow to schedule has before it is killed by mistake.
const WATCHDOG: Duration = Duration::from_secs(2);
/// How long the poll loop waits for work before it wakes to re-arm the watchdog. Without a
/// watchdog it waits until there is work.
const WATCHDOG_TICK: Duration = Duration::from_millis(250);

/// A timer that kills the relay when its poll loop stops running. SIGSTOP and SIGKILL cannot be
/// blocked, and with the default `signals = "any"` the program may send either to the relay. A
/// stopped relay keeps its ports bound and relays whatever its backlog collected once someone
/// continues it, which would put it beyond the one second bound of rule 5. The timer asks the
/// kernel for SIGKILL, which arrives also while the process is stopped.
///
/// With `signals = "isolated"` the relay has none. The Landlock signal scope keeps the program
/// from signalling it, and its own session keeps terminal and group signals away, so nothing the
/// program does can stop it. The timer would only kill a relay the host did not schedule for
/// `WATCHDOG`, which with `children = "contained"` ends the program too.
struct Watchdog(libc::c_int);

impl Watchdog {
    /// Creates the timer. It must be created before the relay confines itself, so that the
    /// filter has to allow only `timer_settime`.
    fn create() -> Result<Watchdog, SandboxError> {
        // SAFETY: sigevent is plain data; zero is SIGEV_SIGNAL with an empty value.
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGKILL;
        let mut timer: libc::c_int = 0;
        // SAFETY: timer_create reads `event` and writes the timer's ID into `timer`.
        let created = unsafe {
            libc::syscall(
                libc::SYS_timer_create,
                libc::CLOCK_MONOTONIC,
                &raw const event,
                &raw mut timer,
            )
        };
        if created != 0 {
            return Err(SandboxError::io(
                "cannot create the relay's watchdog timer",
                io::Error::last_os_error(),
            ));
        }
        Ok(Watchdog(timer))
    }

    /// Gives the relay another `WATCHDOG`. A relay that cannot re-arm has lost the guarantee that
    /// it ends with the program, so it ends now.
    fn rearm(&self) {
        let next = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: WATCHDOG.as_secs() as _,
                tv_nsec: WATCHDOG.subsec_nanos() as _,
            },
        };
        // SAFETY: timer_settime reads `next` and writes nothing, because the old value is null.
        let armed = unsafe {
            libc::syscall(
                libc::SYS_timer_settime,
                self.0,
                0,
                &raw const next,
                std::ptr::null_mut::<libc::itimerspec>(),
            )
        };
        if armed != 0 {
            // SAFETY: ends the relay without running sandy's cleanup.
            unsafe { libc::_exit(1) };
        }
    }
}

/// Accepts and relays connections until the program ends (or the guard's pipe `ended` ends),
/// then closes the listeners at once and gives the accepted connections at most `DRAIN` to
/// deliver what is left. A program that connects, writes and exits therefore does not lose its
/// data, as it would not without a relay.
fn serve_until_exit(
    listeners: Vec<Served>,
    peers: Option<&PeerCheck>,
    program: &OwnedFd,
    ended: Option<&File>,
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
    // The end watches come first; the listeners follow.
    let ends: Vec<RawFd> = [program.as_raw_fd()]
        .into_iter()
        .chain(ended.map(AsRawFd::as_raw_fd))
        .collect();
    let mut polls: Vec<libc::pollfd> = ends
        .iter()
        .copied()
        .chain(listeners.iter().map(|served| served.listener.as_raw_fd()))
        .map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
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
        let over = polls[..ends.len()].iter().any(|poll| poll.revents != 0);
        // Connections that completed together with the end of the program are still taken. Not
        // so after a stop: the relay did not run, so its backlog may hold connections that were
        // made after the program ended.
        if !(over && stopped) {
            let watched = polls[ends.len()..].iter().zip(&listeners).zip(&active);
            for ((poll, served), count) in watched {
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
            forwarded: 0,
            watchdog: true,
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
