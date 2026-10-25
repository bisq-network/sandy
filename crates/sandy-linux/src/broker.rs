//! The egress broker of `network.egress` under `ip = "private"` (docs/DESIGN.md, "Egress broker";
//! docs/linux.md, "Egress broker"). The program connects to the broker's listener on 127.0.0.1
//! inside the sandbox's network namespace and names a destination in SOCKS5; the broker runs in
//! the host's namespace, checks the destination (`sandy_relay::broker`) and connects from there.
//! sandy starts it before it confines itself and before it enters the namespace:
//!
//! 1. Open the netlink socket that answers the host's part of the check (`routes`), a pidfd for
//!    sandy's own process ID, which the program keeps after execve (with `children = "contained"`
//!    the supervising sandy's), and the handover of the listener (`handover`).
//! 2. Start the broker as a helper process (`helper`): forked twice, so it is not a child of the
//!    program, in a session of its own with its signals blocked and `/dev/null` as its standard
//!    descriptors.
//! 3. The broker raises its descriptor limit, creates its watchdog under `signals = "any"`,
//!    closes every descriptor except the netlink socket, the pidfd, the guard's pipe with
//!    `contained`, the inbox and the readiness pipe, and confines itself: no_new_privs; Landlock
//!    with every file right and TCP bind handled and no rule, so it opens no file and binds no
//!    port, and TCP connect unhandled, because the check decides where it connects; the signal
//!    and abstract socket scopes; and its own seccomp filter (`filter::broker`).
//! 4. It reports that it is ready and waits for the listener, which the process that becomes the
//!    program binds inside the namespace after `Namespaces::enter`, while it watches the ends
//!    below.
//! 5. It serves the listener until the program ends (the pidfd), and with `contained` until the
//!    guard's pipe ends. Then it ends as the relay does (rule 5 of "Forwarded ports"): it takes
//!    the connections the backlog holds, closes the listener, gives the accepted connections at
//!    most one second and resets the rest. A thread watches the ends, requests the stop and keeps
//!    the watchdog armed, so a broker the program stopped dies within two seconds.
//!
//! The relay leaves its backlog alone after the program stopped it, because a connection that
//! waited there may have been made after the program ended, and it would reach whatever holds the
//! relay's target by then. The broker takes its backlog also then. Only processes inside the
//! sandbox's network namespace reach its listener: the program's own, which are confined as the
//! program is, and processes of sandy's user that entered it, which reach the network directly
//! anyway. Every connection is still checked and gets at most the drain second, so a late one
//! reaches nothing the program could not reach while it ran.

use std::fs::File;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::thread;

use landlock::{ABI, Scope};
use sandy_core::{Egress, EgressReach, SandboxError, SignalScope};
use sandy_relay::Stop;

use crate::filter;
use crate::handover::{self, Handover, Inbox};
use crate::helper::{self, Ready, Watchdog};
use crate::launch::Threads;
use crate::routes::Routes;

/// Why a contained program ends when its broker ends first (`contain::Helper`).
pub const ENDED_FIRST: &str = "the egress broker ended before the program; the program can no \
    longer connect out and has been ended with it";

/// What the broker needs from the plan.
#[derive(Debug, Clone, PartialEq)]
pub struct BrokerConfig {
    /// The listener inside the sandbox's network namespace: 127.0.0.1 at the egress port.
    pub listen: SocketAddr,
    pub reach: EgressReach,
    /// Whether the broker arms a watchdog: only with `signals = "any"`, where the program can
    /// stop it (`helper::Watchdog`).
    pub watchdog: bool,
    pub abi: ABI,
}

impl BrokerConfig {
    /// The broker of `egress`, or `None` without one.
    pub fn new(egress: Option<Egress>, signals: SignalScope, abi: ABI) -> Option<BrokerConfig> {
        egress.map(|egress| BrokerConfig {
            listen: egress.listen(),
            reach: egress.reach,
            watchdog: signals == SignalScope::Any,
            abi,
        })
    }
}

/// Starts the broker and returns its process ID once it is confined, and the handover of its
/// listener, which the process that enters the namespace sends (`launch::enter`). `ended` is the
/// read end of the guard's pipe with `children = "contained"`.
pub fn start(
    config: &BrokerConfig,
    ended: Option<File>,
) -> Result<(libc::pid_t, Handover), SandboxError> {
    // A kernel that cannot answer refuses the run here instead of every connection later.
    let routes = Routes::open()?;
    let (handover, inbox) = handover::pair(vec![config.listen], "the egress broker")?;
    // SAFETY: getpid has no preconditions.
    let program = helper::pidfd_open(unsafe { libc::getpid() }, "the program")?;
    let broker = Broker {
        routes,
        inbox,
        program,
        ended,
    };
    let pid = helper::start("the egress broker", &Threads::open()?, move |ready| {
        broker_main(broker, ready, config)
    })?;
    Ok((pid, handover))
}

/// What the broker process owns.
struct Broker {
    routes: Routes,
    inbox: Inbox,
    program: OwnedFd,
    ended: Option<File>,
}

fn broker_main(broker: Broker, ready: Ready, config: &BrokerConfig) {
    let Broker {
        mut routes,
        inbox,
        program,
        ended,
    } = broker;
    let mut keep = vec![routes.fd(), inbox.fd(), program.as_raw_fd(), ready.fd()];
    keep.extend(helper::STANDARD_DESCRIPTORS);
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandy_relay::broker::raise_descriptor_limit().map_err(|error| {
            SandboxError::io("cannot raise the egress broker's descriptor limit", error)
        })?;
        // Created before the filter is installed, so only re-arming it has to pass the filter.
        let watchdog = config
            .watchdog
            .then(|| Watchdog::create("the egress broker"))
            .transpose()?;
        confine(&keep, config.abi)?;
        // Every connection gets its own threads. Starting one now shows that the filter allows
        // it, so a missing system call fails the start instead of the first connection.
        thread::Builder::new()
            .spawn(|| ())
            .and_then(|thread| {
                thread
                    .join()
                    .map_err(|_| std::io::Error::other("the test thread panicked"))
            })
            .map_err(|error| {
                SandboxError::io("cannot start a thread of the egress broker", error)
            })?;
        Ok::<Option<Watchdog>, SandboxError>(watchdog)
    }));
    let watchdog = match started {
        Ok(Ok(watchdog)) => watchdog,
        Ok(Err(error)) => ready.fail(&error.to_string()),
        Err(_) => ready.fail("the egress broker panicked"),
    };
    ready.report();
    let mut ends = vec![program.as_raw_fd()];
    ends.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    let Some(listener) = inbox
        .wait(&ends, watchdog.as_ref())
        .and_then(|mut listeners| listeners.pop())
    else {
        return;
    };
    // The serve loop polls the listener, and a connection reset before the accept must not
    // block it there.
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    let stop = Stop::new();
    let request = stop.clone();
    let watching = thread::Builder::new().spawn(move || {
        // A failed poll leaves the broker blind to the end of the program, so it ends too.
        let _ = helper::wait_for(&ends, watchdog.as_ref());
        request.request();
        // The descriptors stay open for as long as the poll needs them.
        drop((program, ended));
    });
    if watching.is_err() {
        return;
    }
    sandy_relay::broker::serve(
        listener,
        |listener| listener.accept().map(|(client, _)| client),
        config.reach,
        routes,
        &stop,
        sandy_relay::DRAIN,
    );
}

/// Closes the other descriptors, then applies no_new_privs, Landlock (no file, no TCP bind, any
/// TCP connect, signal and abstract socket scopes) and seccomp.
fn confine(keep: &[RawFd], abi: ABI) -> Result<(), SandboxError> {
    let filters = filter::broker().map_err(|error| {
        SandboxError::new(format!("cannot build the egress broker's filter: {error}"))
    })?;
    helper::confine(
        "the egress broker",
        keep,
        abi,
        None,
        Scope::Signal | Scope::AbstractUnixSocket,
        &filters,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostCapabilities;
    use sandy_core::destination::HostNetwork;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::time::Duration;

    const OUTCOMES: [&str; 10] = [
        "ok",
        "confine failed",
        "a file could be opened",
        "a socket could be bound",
        "a UDP or netlink socket could be created",
        "a TCP connect failed",
        "the addresses of a connection could not be read",
        "the routes socket did not answer",
        "a process could be started",
        "no thread could be started",
    ];

    /// What a compromised broker would try after `confine`. Returns an index into `OUTCOMES`.
    fn try_escapes(routes: &mut Routes, abi: ABI, other: SocketAddr) -> i32 {
        if confine(&[routes.fd()], abi).is_err() {
            return 1;
        }
        if std::fs::File::open("/proc/self/status").is_ok() {
            return 2;
        }
        if TcpListener::bind("127.0.0.1:0").is_ok() {
            return 3;
        }
        // SAFETY: socket returns a new descriptor or -1, which the check below closes again.
        let other_sockets = [
            (libc::AF_INET, libc::SOCK_DGRAM, 0),
            (libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE),
        ]
        .map(|(family, kind, protocol)| unsafe { libc::socket(family, kind, protocol) });
        if other_sockets.iter().any(|&fd| fd >= 0) {
            return 4;
        }
        // Landlock leaves every port to the destination check: here a port no rule names.
        let Ok(stream) = TcpStream::connect(other) else {
            return 5;
        };
        if stream.local_addr().is_err() || stream.peer_addr().is_err() {
            return 6;
        }
        let loopback = IpAddr::from([127, 0, 0, 1]);
        if !routes.is_host(loopback).unwrap_or(false) {
            return 7;
        }
        // clone with fork's flags; the other arguments are zero on x86_64 and arm64 alike.
        // SAFETY: a child that clone creates leaves through `_exit` at once.
        let child = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
        if child == 0 {
            // SAFETY: ends the child without running anything of the parent's.
            unsafe { libc::_exit(0) };
        }
        if child > 0 {
            return 8;
        }
        if thread::spawn(|| ()).join().is_err() {
            return 9;
        }
        0
    }

    /// The child process applies the broker's confinement to itself and leaves through `_exit`.
    /// It starts a thread, so the test runs in a process of its own (`alone`).
    #[test]
    fn the_confined_broker_can_only_connect_out() {
        if !crate::alone::in_own_process() {
            return;
        }
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let mut routes = Routes::open().unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let other_address = other.local_addr().unwrap();
        // SAFETY: the child only runs `try_escapes` and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = try_escapes(&mut routes, ABI::from(version), other_address);
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

    fn free_address() -> io::Result<SocketAddr> {
        TcpListener::bind("127.0.0.1:0")?.local_addr()
    }

    fn address_in_use(error: &SandboxError) -> bool {
        std::error::Error::source(error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some_and(|source| source.kind() == io::ErrorKind::AddrInUse)
    }

    /// One SOCKS5 request through the broker at `broker`; returns the reply code.
    fn request(broker: SocketAddr, address: &[u8]) -> io::Result<u8> {
        let mut stream = TcpStream::connect(broker)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut all = vec![5, 1, 0, 5, 1, 0];
        all.extend(address);
        stream.write_all(&all)?;
        let mut answer = [0u8; 12];
        stream.read_exact(&mut answer)?;
        Ok(answer[3])
    }

    /// The broker, started as a helper by a forked child that stands in for the program, serves
    /// the listener it was handed with the kernel's answers about this host, and ends within the
    /// drain second after its program. Nothing here needs the network: every destination it asks
    /// for is refused.
    #[test]
    fn the_broker_serves_its_listener_and_ends_with_its_program() {
        if !crate::alone::in_own_process() {
            return;
        }
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let canary = TcpListener::bind("127.0.0.1:0").unwrap();
        canary.set_nonblocking(true).unwrap();
        let [a, b] = canary.local_addr().unwrap().port().to_be_bytes();
        let (mut report, mut report_write) = helper::pipe("the test's pipe").unwrap();
        // SAFETY: the child is a fork of a process with one test thread (`alone`), runs the
        // steps below and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            drop(report);
            let outcome = (|| {
                // A port that was free a moment ago can be taken by any process of the host
                // before the handover binds it again, so the child takes a few tries.
                let mut tries = 0;
                let (pid, listen) = loop {
                    let config = BrokerConfig {
                        listen: free_address().map_err(|_| 1)?,
                        reach: EgressReach::PublicAndLocal,
                        watchdog: true,
                        abi: ABI::from(version),
                    };
                    let (pid, handover) = start(&config, None).map_err(|_| 2)?;
                    match handover.send() {
                        Ok(()) => break (pid, config.listen),
                        Err(error) if address_in_use(&error) && tries < 5 => tries += 1,
                        Err(_) => return Err(3),
                    }
                };
                report_write.write_all(&pid.to_ne_bytes()).map_err(|_| 2)?;
                // This host under its loopback name, and a name.
                let host = [1, 127, 0, 0, 1, a, b];
                let name = [
                    3, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0, 80,
                ];
                let replies = [request(listen, &host), request(listen, &name)];
                match replies.map(Result::ok) {
                    [Some(2), Some(8)] => Ok(()),
                    _ => Err(4),
                }
            })();
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome.err().unwrap_or(0)) };
        }
        drop(report_write);
        let mut pid = [0u8; std::mem::size_of::<libc::pid_t>()];
        report.read_exact(&mut pid).unwrap();
        let broker = helper::pidfd_open(libc::pid_t::from_ne_bytes(pid), "the broker").unwrap();
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "step {}",
            libc::WEXITSTATUS(status)
        );
        assert!(
            canary.accept().is_err(),
            "the broker connected to this host"
        );
        let mut poll = libc::pollfd {
            fd: broker.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // The drain second, and the stop check of the serve loop.
        // SAFETY: polls one open descriptor.
        let ended = unsafe { libc::poll(&mut poll, 1, 1500) };
        assert_eq!(ended, 1, "the broker outlived its program");
    }
}
