//! The egress broker behind `network.egress` (docs/DESIGN.md, "Private network and egress" and
//! "Egress broker"). For each connection of the program:
//!
//! 1. It reads one SOCKS5 request (`socks::read_request`), within `socks::HANDSHAKE_TIMEOUT`.
//! 2. It checks the destination (`sandy_core::destination::check`): the static part, then the
//!    host's own addresses and subnets. A refusal gets reply 2, or reply 1 when the host cannot
//!    tell whether the address is its own.
//! 3. It connects to the address it checked, within 10 seconds. A failure gets the matching
//!    reply.
//! 4. It refuses a connection that reached the host anyway: one whose local address is loopback
//!    or equal to its peer's, which is what a connection to an address of the host looks like,
//!    also to one the host gained after step 2. It gets reply 2, and the connection to the host
//!    ends with a reset.
//! 5. It sends reply 0, naming `0.0.0.0:0`, and from then on copies bytes like the relay, with
//!    the same half close, resets and idle limit.
//!
//! The handshake is the only thing it parses. The backend decides where the broker runs, how it
//! is confined, which `HostNetwork` it asks, and when it stops.

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sandy_core::destination::{self, HostNetwork, Refusal, Subnet};
use sandy_core::{EXPLAIN_PREFIX, EgressReach};

use crate::report::Lines;
use crate::socks::{self, Refused, Reply};
use crate::{
    AsRawListener, CONNECT_TIMEOUT, Connections, HALF_CLOSED_IDLE, Stop, raw, relay_streams_with,
    reset_on_close, serve_connections_until,
};

/// How many connections the broker serves at the same time; it closes more at once. A program
/// that talks to many peers needs more than the relay's `MAX_CONNECTIONS` per port. Each takes two
/// threads and two descriptors, and macOS allows a process 2048 threads (`kern.num_taskthreads`,
/// measured on macOS 27), so this leaves the process some of its own.
pub const MAX_CONNECTIONS: usize = 1000;

const _: () = assert!(MAX_CONNECTIONS > crate::MAX_CONNECTIONS);

/// The stack of each broker thread. The handshake, the check and the copying keep their buffers
/// on the heap, so this is ample, and `MAX_CONNECTIONS` reserve about 500 MiB of address space
/// instead of the 4 GiB that the standard library's default of 2 MiB would.
pub(crate) const THREAD_STACK: usize = 256 * 1024;

/// Serves the broker on `listener` until `stop` is requested, then ends as `serve_until` does:
/// it still takes the connections that wait in the backlog, closes the listener, waits up to
/// `drain` for the accepted connections, and leaves those still open to end with a reset when
/// the process ends (`abort_all`). `accept` takes one connection from `listener`, which on
/// Windows may be an AF_UNIX one (`unix::Listener`).
///
/// `reach` and `host` decide the destinations (`sandy_core::destination::check`). With
/// `explain` (`run --explain`) the broker names every connection it refuses or cannot make. On
/// Unix the caller raises the descriptor limit first (`raise_descriptor_limit`).
pub fn serve<L, A, H>(
    listener: L,
    accept: A,
    reach: EgressReach,
    host: H,
    explain: Option<Explain>,
    stop: &Stop,
    drain: Duration,
) where
    L: AsRawListener,
    A: FnMut(&L) -> io::Result<TcpStream>,
    H: HostNetwork + Send + Sync + 'static,
{
    let explain = explain.map(Arc::new);
    let broker = Broker {
        reach,
        host,
        reached_host,
        explain: explain.clone(),
    };
    serve_broker(listener, accept, broker, stop, drain);
    if let Some(explain) = explain {
        explain.finish();
    }
}

/// The most lines `Explain` writes in one run. The program decides how many destinations it
/// tries, and the report keeps every line it wrote so that it writes each one once.
pub const MOST_LINES: usize = 1000;

/// The broker's part of the diagnostic mode (`run --explain`): a line on `out` for each
/// connection it refuses or cannot make, and why, each distinct line once. It decides nothing:
/// the broker answers every connection the same with it or without it. The lines go through
/// `report::Lines`, so a standard error that nobody reads holds up no connection.
pub struct Explain {
    state: Mutex<ExplainState>,
    lines: Lines,
}

impl std::fmt::Debug for Explain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Explain").finish_non_exhaustive()
    }
}

struct ExplainState {
    /// What identifies the lines given so far, each once.
    seen: HashSet<String>,
    ended: bool,
}

impl Explain {
    pub fn new(out: impl Write + Send + 'static) -> Explain {
        Explain {
            state: Mutex::new(ExplainState {
                seen: HashSet::new(),
                ended: false,
            }),
            lines: Lines::start(out, EXPLAIN_PREFIX, "egress"),
        }
    }

    /// Ends the report (`report::Lines::finish`). The broker calls it when it stops serving,
    /// because a connection thread can still hold the report then.
    pub fn finish(&self) {
        self.lines.finish();
    }

    /// Reports `line` unless it was reported before.
    pub fn report(&self, line: String) {
        self.report_as(line.clone(), || line);
    }

    /// Reports the line that `line` makes, unless one with the same `key` was reported before.
    /// `line` runs only for a new key, and outside the lock, so that what it costs is paid once.
    fn report_as(&self, key: String, line: impl FnOnce() -> String) {
        let ending = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.ended || state.seen.contains(&key) {
                return;
            }
            if state.seen.len() < MOST_LINES {
                state.seen.insert(key);
                false
            } else {
                state.ended = true;
                true
            }
        };
        let line = if ending {
            format!("{MOST_LINES} egress lines written, the most in one run; no more follow")
        } else {
            line()
        };
        self.lines.send(format!("{EXPLAIN_PREFIX}{line}\n"));
    }
}

/// Raises this process's soft limit of open descriptors so that `MAX_CONNECTIONS` fit, two
/// descriptors each, plus some for the process itself.
#[cfg(unix)]
pub fn raise_descriptor_limit() -> io::Result<()> {
    crate::raise_descriptor_limit_to(2 * MAX_CONNECTIONS + 64)
}

fn serve_broker<L, A, H, R>(
    listener: L,
    accept: A,
    broker: Broker<H, R>,
    stop: &Stop,
    drain: Duration,
) where
    L: AsRawListener,
    A: FnMut(&L) -> io::Result<TcpStream>,
    H: HostNetwork + Send + Sync + 'static,
    R: Fn(&TcpStream) -> bool + Send + Sync + 'static,
{
    let explain = broker.explain.clone();
    let mut connections = Connections::new(MAX_CONNECTIONS, Some(THREAD_STACK), move |client| {
        let _ = broker.handle(client);
    });
    if let Some(explain) = explain {
        connections = connections.reporting_full(Arc::new(move |limit| {
            explain.report(full_line(limit));
        }));
    }
    serve_connections_until(vec![(listener, connections)], accept, stop, drain);
}

/// What the broker decides with. `reached_host` is the check after the connect; only tests
/// replace it, to reach a stand-in on this host.
struct Broker<H, R> {
    reach: EgressReach,
    host: H,
    reached_host: R,
    explain: Option<Arc<Explain>>,
}

/// The line for a connection closed at once because `limit` connections are open. A relay in
/// front of the broker (Windows) writes it too.
pub fn full_line(limit: usize) -> String {
    format!("an egress connection was closed at once: {limit} are open, the most the broker serves")
}

impl<H, R> Broker<H, R>
where
    H: HostNetwork,
    R: Fn(&TcpStream) -> bool,
{
    fn handle(&self, client: TcpStream) -> io::Result<()> {
        // A listener that does not block may pass that on to the connections it accepts.
        client.set_nonblocking(false)?;
        let requested = match socks::read_request(&client) {
            Ok(requested) => requested,
            Err(error) => {
                if let Some(line) = request_line(&error) {
                    self.explain(|| line);
                }
                return Err(error);
            }
        };
        let destination = match destination::check(requested, self.reach, &self.host) {
            Ok(destination) => destination,
            Err(refusal) => {
                let reply = match refusal {
                    Refusal::HostUnknown => Reply::GeneralFailure,
                    _ => Reply::NotAllowed,
                };
                let replied = socks::reply(&client, reply);
                if let Some(explain) = &self.explain {
                    let key = format!("{requested} {refusal:?}");
                    explain.report_as(key, || self.refusal_line(requested, &refusal, reply));
                }
                return replied;
            }
        };
        let server = match TcpStream::connect_timeout(&destination, CONNECT_TIMEOUT) {
            Ok(server) => server,
            Err(error) => {
                let reply = Reply::for_connect_error(&error);
                let replied = socks::reply(&client, reply);
                self.explain(|| {
                    format!(
                        "egress to {destination} failed with reply {}: the connect failed: {error}",
                        reply as u8
                    )
                });
                return replied;
            }
        };
        if (self.reached_host)(&server) {
            reset_on_close(raw(&server));
            let replied = socks::reply(&client, Reply::NotAllowed);
            self.explain(|| {
                format!(
                    "egress to {destination} refused with reply 2: the connection reached this host"
                )
            });
            return replied;
        }
        socks::reply(&client, Reply::Succeeded)?;
        relay_streams_with(client, server, HALF_CLOSED_IDLE, Some(THREAD_STACK))
    }

    fn explain(&self, line: impl FnOnce() -> String) {
        if let Some(explain) = &self.explain {
            explain.report(line());
        }
    }

    /// The line for a destination that `check` refused with `reply`: the reason, the subnet that
    /// makes an address the local network, and whether `public-and-local` would allow it.
    fn refusal_line(&self, requested: SocketAddr, refusal: &Refusal, reply: Reply) -> String {
        let ip = requested.ip().to_canonical();
        let reason = match refusal {
            Refusal::HostSubnet => match self
                .host
                .subnets()
                .ok()
                .and_then(|subnets| Subnet::holding(&subnets, ip))
            {
                Some(subnet) => format!(
                    "on {subnet}, a network this host reaches without a router, which is the local network"
                ),
                None => refusal.to_string(),
            },
            _ => refusal.to_string(),
        };
        let mut line = format!(
            "egress to {requested} refused with reply {}: {reason}",
            reply as u8
        );
        // After a host query that failed, another one tells nothing about this refusal.
        if *refusal != Refusal::HostUnknown
            && self.reach == EgressReach::Public
            && destination::check(requested, EgressReach::PublicAndLocal, &self.host).is_ok()
        {
            line.push_str("; reach = \"public-and-local\" allows it");
        }
        line
    }
}

/// The line for a request that `read_request` refused or could not read. The end of the stream
/// before a request names nothing: a client that only checks the port does that.
fn request_line(error: &io::Error) -> Option<String> {
    Some(match Refused::of(error) {
        Some(refused) if refused.reason == socks::NAMES_NOT_RESOLVED => {
            "egress to a name refused with reply 8: the broker resolves no names, so the program \
             has to resolve the name and ask for an address"
                .to_string()
        }
        Some(Refused {
            reply: Some(reply),
            reason,
        }) => format!(
            "egress request refused with reply {}: {reason}",
            reply as u8
        ),
        Some(Refused {
            reply: None,
            reason,
        }) => format!("egress request refused: {reason}"),
        None if error.kind() == io::ErrorKind::UnexpectedEof => return None,
        None if error.kind() == io::ErrorKind::TimedOut => format!(
            "egress connection closed: no SOCKS5 request within {} seconds",
            socks::HANDSHAKE_TIMEOUT.as_secs()
        ),
        None if error.kind() == io::ErrorKind::InvalidData => {
            format!("egress connection closed: the program does not speak SOCKS5 to it: {error}")
        }
        None => format!("egress connection closed while it read the request: {error}"),
    })
}

/// Whether the connection `server` ended at this host after all: its local address is loopback,
/// or the peer's own address, as the host picks it for a connection to itself. An address that
/// cannot be read counts as the host's.
fn reached_host(server: &TcpStream) -> bool {
    match (server.local_addr(), server.peer_addr()) {
        (Ok(local), Ok(peer)) => {
            let local = local.ip().to_canonical();
            local.is_loopback() || local == peer.ip().to_canonical()
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DRAIN;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, UdpSocket};
    use std::sync::{OnceLock, mpsc};
    use std::thread;
    use std::time::Instant;

    use sandy_core::destination::Subnet;

    /// How long a server at `stand_in` may take to answer, which leaves time to answer a firewall
    /// prompt. The macOS firewall ends the connections to a test program that listens at an
    /// address other than loopback, without data, until the program is allowed in its options.
    /// It asked nobody when the program ran over SSH or in a Screen Sharing session other than
    /// the one on the screen (measured on macOS 27).
    const STAND_IN_WAIT: Duration = Duration::from_secs(30);

    /// A host check that answers from fixed lists.
    #[derive(Default)]
    struct TestHost {
        own: Vec<IpAddr>,
        subnets: Vec<Subnet>,
        fails: bool,
    }

    impl HostNetwork for TestHost {
        fn is_host(&self, destination: SocketAddr) -> io::Result<bool> {
            if self.fails {
                return Err(io::Error::other("no answer"));
            }
            Ok(self.own.contains(&destination.ip()))
        }

        fn subnets(&self) -> io::Result<Vec<Subnet>> {
            Ok(self.subnets.clone())
        }
    }

    /// An address of this host other than loopback, which the tests use as a stand-in for a
    /// server elsewhere: the source address of the route to a documentation address. Nothing is
    /// sent; `None` when the host has no such route.
    fn stand_in() -> Option<IpAddr> {
        let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
        probe.connect("192.0.2.1:9").ok()?;
        let ip = probe.local_addr().ok()?.ip();
        (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
    }

    /// Panics unless a server at `stand_in` answers a direct connection within `STAND_IN_WAIT`,
    /// so that a test whose server there has to answer fails with the cause on this host rather
    /// than as a failure of the broker. Checked once per test program.
    fn assert_stand_in_answers(stand_in: IpAddr) {
        static CHECKED: OnceLock<Result<(), String>> = OnceLock::new();
        if let Err(reason) = CHECKED.get_or_init(|| stand_in_answers(stand_in)) {
            panic!("{reason}");
        }
    }

    fn stand_in_answers(stand_in: IpAddr) -> Result<(), String> {
        let server = echo_server(stand_in);
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < STAND_IN_WAIT {
            match echo_directly(server) {
                Ok(answer) if answer == b"echo:probe" => return Ok(()),
                Ok(answer) => last = format!("it answered {:?}", String::from_utf8_lossy(&answer)),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "the test needs a server at {server}, an address of this host, but it answered no \
             direct connection within {STAND_IN_WAIT:?} (last: {last}). A firewall of this host \
             can stop such connections: the macOS firewall{} ends them without data until the \
             test program is allowed, and it may not ask. On macOS, add {} under System \
             Settings, Network, Firewall, Options, with incoming connections allowed, and run the \
             test again.",
            firewall_state(),
            std::env::current_exe().map_or_else(
                |error| format!("this test program (its path is unknown: {error})"),
                |program| program.display().to_string()
            )
        ))
    }

    fn echo_directly(server: SocketAddr) -> io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"probe")?;
        stream.shutdown(Shutdown::Write)?;
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer)?;
        Ok(answer)
    }

    /// The state of the macOS firewall, for the message of a failure.
    #[cfg(target_os = "macos")]
    fn firewall_state() -> String {
        let state = std::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .arg("--getglobalstate")
            .output();
        match state {
            Ok(output) => format!(
                " (here: {})",
                String::from_utf8_lossy(&output.stdout).trim()
            ),
            Err(error) => format!(" (its state here is unknown: {error})"),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn firewall_state() -> String {
        String::new()
    }

    /// A test host that does not know `stand_in` as its own and has it as a subnet, so that
    /// `public-and-local` allows it whatever block it is in.
    fn host_without(stand_in: IpAddr) -> TestHost {
        TestHost {
            subnets: vec![Subnet::new(stand_in, 32).unwrap()],
            ..TestHost::default()
        }
    }

    /// Starts a broker on a loopback listener. `exempt` is a peer that the check after the
    /// connect lets through, for a stand-in on this host.
    fn start(
        reach: EgressReach,
        host: TestHost,
        exempt: Option<IpAddr>,
    ) -> (SocketAddr, Stop, thread::JoinHandle<()>) {
        start_explained(reach, host, exempt, None)
    }

    /// `start` with the diagnostic report going to `explain`.
    fn start_explained(
        reach: EgressReach,
        host: TestHost,
        exempt: Option<IpAddr>,
        explain: Option<Arc<Explain>>,
    ) -> (SocketAddr, Stop, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Stop::new().unwrap();
        let request = stop.clone();
        let broker = Broker {
            reach,
            host,
            reached_host: move |server: &TcpStream| {
                let peer = server.peer_addr().map(|peer| peer.ip()).ok();
                peer.is_none() || (peer != exempt && reached_host(server))
            },
            explain,
        };
        let server = thread::spawn(move || {
            serve_broker(
                listener,
                |listener| listener.accept().map(|(client, _)| client),
                broker,
                &request,
                DRAIN,
            );
        });
        (address, stop, server)
    }

    fn request_bytes(destination: SocketAddr) -> Vec<u8> {
        let mut request = vec![5, 1, 0];
        match destination.ip() {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend(ip.octets());
            }
        }
        request.extend(destination.port().to_be_bytes());
        request
    }

    /// Connects through the broker the way a client does: greeting, answer, request, reply.
    fn connect_through(broker: SocketAddr, destination: SocketAddr) -> (TcpStream, u8) {
        let mut stream = TcpStream::connect(broker).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(&[5, 1, 0]).unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).unwrap();
        assert_eq!(answer, [5, 0]);
        stream.write_all(&request_bytes(destination)).unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(
            [reply[0], reply[2], reply[3]],
            [5, 0, 1],
            "{destination}: {reply:?}"
        );
        assert_eq!(&reply[4..], [0; 6], "the reply names an address");
        (stream, reply[1])
    }

    /// A server that answers every request with "echo:" plus the request, after the client
    /// half-closes.
    fn echo_server(ip: IpAddr) -> SocketAddr {
        let listener = TcpListener::bind((ip, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                thread::spawn(move || {
                    let mut request = Vec::new();
                    if stream.read_to_end(&mut request).is_ok() {
                        let _ = stream.write_all(b"echo:");
                        let _ = stream.write_all(&request);
                    }
                });
            }
        });
        address
    }

    fn exchange(mut stream: TcpStream, request: &[u8]) -> Vec<u8> {
        stream.write_all(request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        answer
    }

    #[test]
    fn data_flows_to_an_allowed_destination() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        assert_stand_in_answers(stand_in);
        let target = echo_server(stand_in);
        let (broker, stop, server) = start(
            EgressReach::PublicAndLocal,
            host_without(stand_in),
            Some(stand_in),
        );
        let (stream, reply) = connect_through(broker, target);
        assert_eq!(reply, 0);
        assert_eq!(exchange(stream, b"hello"), b"echo:hello");

        // A client that sends its request and its first data in one write, before any answer.
        let mut stream = TcpStream::connect(broker).unwrap();
        let mut all = vec![5, 1, 0];
        all.extend(request_bytes(target));
        all.extend(b"early");
        stream.write_all(&all).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        let reply = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(answer[..12], reply);
        assert_eq!(answer[12..], *b"echo:early");

        // An IPv4-mapped address reaches the address it maps.
        let mapped = match stand_in {
            IpAddr::V4(ip) => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), target.port()),
            IpAddr::V6(_) => target,
        };
        let (stream, reply) = connect_through(broker, mapped);
        assert_eq!(reply, 0);
        assert_eq!(exchange(stream, b"mapped"), b"echo:mapped");

        stop.request();
        server.join().unwrap();
    }

    /// Listeners where a forbidden destination would end if the broker connected to it. A
    /// test fails if any of them ever sees a connection.
    struct Canaries {
        listeners: Vec<TcpListener>,
    }

    impl Canaries {
        fn bind(addresses: &[IpAddr]) -> Canaries {
            let listeners = addresses
                .iter()
                .filter_map(|ip| TcpListener::bind((*ip, 0)).ok())
                .collect::<Vec<_>>();
            for listener in &listeners {
                listener.set_nonblocking(true).unwrap();
            }
            Canaries { listeners }
        }

        fn port(&self, ip: IpAddr) -> Option<u16> {
            self.listeners
                .iter()
                .map(|listener| listener.local_addr().unwrap())
                .find(|address| address.ip() == ip)
                .map(|address| address.port())
        }

        fn assert_untouched(&self) {
            for listener in &self.listeners {
                match listener.accept() {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    other => panic!(
                        "{} saw a connection: {other:?}",
                        listener.local_addr().unwrap()
                    ),
                }
            }
        }
    }

    /// Every form of this host and of the destinations no reach allows gets reply 2, and none
    /// of them reaches a listener.
    #[test]
    fn every_forbidden_form_is_refused_with_reply_2() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        let loopback4: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback6: IpAddr = "::1".parse().unwrap();
        let canaries = Canaries::bind(&[loopback4, loopback6, stand_in]);
        let four = canaries.port(loopback4).unwrap();
        let six = canaries.port(loopback6).unwrap_or(four);
        let own = canaries.port(stand_in).unwrap();
        let mut forms: Vec<SocketAddr> = [
            "127.0.0.1",
            "127.0.0.2",
            "0.0.0.0",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::7f00:1",
            "2002:7f00:1::1",
            "2001:0:4136:e378:8000:63bf:80ff:fffe",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ]
        .iter()
        .map(|ip| SocketAddr::new(ip.parse().unwrap(), four))
        .collect();
        forms.extend(["::1", "::"].map(|ip| SocketAddr::new(ip.parse().unwrap(), six)));
        // The stand-in is this host here, under each of its names, and port 0 is never allowed.
        forms.push(SocketAddr::new(stand_in, own));
        if let IpAddr::V4(ip) = stand_in {
            forms.push(SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), own));
        }
        forms.push(SocketAddr::new(stand_in, 0));

        let host = TestHost {
            own: vec![stand_in],
            subnets: vec![Subnet::new(stand_in, 32).unwrap()],
            ..TestHost::default()
        };
        let (public_and_local, stop, server) = start(EgressReach::PublicAndLocal, host, None);
        for destination in &forms {
            let (_stream, reply) = connect_through(public_and_local, *destination);
            assert_eq!(reply, 2, "{destination}");
        }
        stop.request();
        server.join().unwrap();

        // With `public` the stand-in is refused also when the host check misses it: it is on a
        // subnet of the host, or in a block that is not public.
        let (public, stop, server) = start(EgressReach::Public, host_without(stand_in), None);
        for destination in &forms {
            let (_stream, reply) = connect_through(public, *destination);
            assert_eq!(reply, 2, "{destination}");
        }
        stop.request();
        server.join().unwrap();
        canaries.assert_untouched();
    }

    /// The check after the connect catches what the host check missed: the connection reaches
    /// the listener, but gets reply 2, carries no data and ends with a reset.
    #[test]
    fn a_connection_that_reached_the_host_anyway_is_refused() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        let listener = TcpListener::bind((stand_in, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let (broker, stop, server) =
            start(EgressReach::PublicAndLocal, host_without(stand_in), None);
        let (mut stream, reply) = connect_through(broker, target);
        assert_eq!(reply, 2);
        let _ = stream.write_all(b"never relayed");
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        assert!(rest.is_empty(), "{rest:?}");
        // Linux keeps a connection that was reset before its accept in the backlog; another
        // system may drop it, which is as good.
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let reached = loop {
            match listener.accept() {
                Ok((reached, _)) => break Some(reached),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break None,
            }
        };
        if cfg!(target_os = "linux") {
            assert!(
                reached.is_some(),
                "the connection never reached the listener"
            );
        }
        if let Some(mut reached) = reached {
            // macOS refuses socket options on a socket that was reset (EINVAL).
            let _ = reached.set_nonblocking(false);
            let _ = reached.set_read_timeout(Some(Duration::from_secs(5)));
            let mut received = Vec::new();
            let ended = reached.read_to_end(&mut received);
            assert!(received.is_empty(), "{received:?}");
            if cfg!(target_os = "linux") {
                assert_eq!(
                    ended.map_err(|error| error.kind()),
                    Err(io::ErrorKind::ConnectionReset)
                );
            }
        }
        stop.request();
        server.join().unwrap();
    }

    #[test]
    fn the_check_after_the_connect_knows_the_host_by_its_local_address() {
        let mut targets = vec!["127.0.0.1".parse().unwrap()];
        targets.extend(stand_in());
        for ip in targets {
            let listener = TcpListener::bind((ip, 0)).unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            assert!(reached_host(&stream), "{ip}");
        }
    }

    #[test]
    fn a_closed_port_gets_reply_5() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        let unused = TcpListener::bind((stand_in, 0)).unwrap();
        let target = unused.local_addr().unwrap();
        drop(unused);
        let (broker, stop, server) = start(
            EgressReach::PublicAndLocal,
            host_without(stand_in),
            Some(stand_in),
        );
        let (_stream, reply) = connect_through(broker, target);
        assert_eq!(reply, 5);
        stop.request();
        server.join().unwrap();
    }

    #[test]
    fn a_host_that_cannot_tell_gets_reply_1() {
        let host = TestHost {
            fails: true,
            ..TestHost::default()
        };
        let (broker, stop, server) = start(EgressReach::Public, host, None);
        let (_stream, reply) = connect_through(broker, "192.31.196.1:443".parse().unwrap());
        assert_eq!(reply, 1);
        stop.request();
        server.join().unwrap();
    }

    /// On Windows the program's connections reach sandy over AF_UNIX (docs/windows.md,
    /// "Forwarded ports"), and the broker serves them like TCP ones.
    #[cfg(windows)]
    #[test]
    fn serves_connections_from_a_unix_socket() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        let target = echo_server(stand_in);
        let dir = std::env::temp_dir().join(format!("sandy-broker-unix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = crate::unix::Listener::bind(&path).unwrap();
        let stop = Stop::new().unwrap();
        let request = stop.clone();
        let broker = Broker {
            reach: EgressReach::PublicAndLocal,
            host: host_without(stand_in),
            reached_host: move |server: &TcpStream| {
                server.peer_addr().map(|peer| peer.ip()).ok() != Some(stand_in)
                    && reached_host(server)
            },
            explain: None,
        };
        let server = thread::spawn(move || {
            serve_broker(
                listener,
                |listener| listener.accept(),
                broker,
                &request,
                DRAIN,
            );
        });
        let client = crate::unix::connect_to(&path).unwrap();
        let mut all = vec![5, 1, 0];
        all.extend(request_bytes(target));
        all.extend(b"hello");
        (&client).write_all(&all).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        (&client).read_to_end(&mut answer).unwrap();
        assert_eq!(answer[..12], [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(answer[12..], *b"echo:hello");
        stop.request();
        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The broker's own handshake answers reach the client through `serve` as well.
    #[test]
    fn a_name_gets_reply_8() {
        let (broker, stop, server) = start(EgressReach::Public, TestHost::default(), None);
        let mut stream = TcpStream::connect(broker).unwrap();
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, 9];
        request.extend(b"localhost");
        request.extend([0, 80]);
        stream.write_all(&request).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, [5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
        stop.request();
        server.join().unwrap();
    }

    /// Rule 5: a connection that was made before the stop and waits in the backlog is still
    /// served; afterwards the listener is closed.
    #[test]
    fn a_stopped_broker_still_serves_connections_already_made() {
        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        assert_stand_in_answers(stand_in);
        let target = echo_server(stand_in);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let mut all = vec![5, 1, 0];
        all.extend(request_bytes(target));
        all.extend(b"late");
        client.write_all(&all).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let stop = Stop::new().unwrap();
        // Only once the backlog holds it: on macOS the connect can return before the listener
        // has the connection.
        while crate::pending(&[crate::raw_listener(&listener)], &stop, None)
            .unwrap()
            .is_empty()
        {}
        stop.request();
        let broker = Broker {
            reach: EgressReach::PublicAndLocal,
            host: host_without(stand_in),
            reached_host: |_: &TcpStream| false,
            explain: None,
        };
        // The broker ends as soon as the connection has, so a drain longer than `DRAIN` costs
        // nothing here and keeps a slow host from cutting the connection.
        serve_broker(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            broker,
            &stop,
            Duration::from_secs(10),
        );
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        assert_eq!(answer[12..], *b"echo:late");
        assert!(TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err());
    }

    #[test]
    fn a_stop_request_ends_an_idle_broker_promptly() {
        let (_, stop, server) = start(EgressReach::Public, TestHost::default(), None);
        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        stop.request();
        server.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
    }

    /// Rule 5: a stop request closes the listener at once. Here it comes while the serve loop
    /// waits again after a connection, where a loop that looked for a stop every 50 ms would
    /// keep the listener almost that long.
    #[cfg(unix)]
    #[test]
    fn a_stop_request_closes_the_listener_at_once() {
        let (address, stop, server) = start(EgressReach::Public, TestHost::default(), None);
        drop(TcpStream::connect(address).unwrap());
        thread::sleep(Duration::from_millis(5));
        let started = Instant::now();
        stop.request();
        server.join().unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(25), "{elapsed:?}");
        assert!(TcpStream::connect(address).is_err());
    }

    /// A client that was accepted and never finishes its handshake delays the end by at most the
    /// drain time.
    #[test]
    fn the_drain_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Stop::new().unwrap();
        let request = stop.clone();
        let drain = Duration::from_millis(300);
        let (accepted, was_accepted) = mpsc::channel();
        let server = thread::spawn(move || {
            serve(
                listener,
                move |listener| {
                    let client = listener.accept().map(|(client, _)| client);
                    if client.is_ok() {
                        let _ = accepted.send(());
                    }
                    client
                },
                EgressReach::Public,
                TestHost::default(),
                None,
                &request,
                drain,
            );
        });
        let _client = TcpStream::connect(address).unwrap();
        // The stop comes after the accept: on macOS the connect can return before the listener
        // has the connection, by milliseconds under loopback traffic, and a broker that is
        // already stopping does not wait for one.
        was_accepted
            .recv_timeout(Duration::from_secs(10))
            .expect("the broker accepts the client");
        let started = Instant::now();
        stop.request();
        server.join().unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= drain && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
    }

    /// Beyond its limit the broker closes a connection at once, before any handshake, and
    /// serves again once a place is free.
    #[test]
    fn connections_beyond_the_limit_are_closed() {
        let (release, released) = mpsc::channel::<()>();
        let released = std::sync::Mutex::new(released);
        let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&closed);
        let connections = Connections::new(2, Some(THREAD_STACK), move |client: TcpStream| {
            let _ = released.lock().unwrap().recv();
            let _ = (&client).write_all(b"served");
        })
        .reporting_full(Arc::new(move |limit| {
            assert_eq!(limit, 2);
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut clients = Vec::new();
        for _ in 0..3 {
            let client = TcpStream::connect(address).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            assert!(connections.start(accepted));
            clients.push(client);
        }
        let mut third = clients.pop().unwrap();
        let mut answer = Vec::new();
        third.read_to_end(&mut answer).unwrap();
        assert!(answer.is_empty());
        assert_eq!(connections.active(), 2);
        assert_eq!(closed.load(std::sync::atomic::Ordering::Relaxed), 1);
        for _ in 0..2 {
            release.send(()).unwrap();
        }
        for mut client in clients {
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            assert_eq!(answer, b"served");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while connections.active() > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(connections.active(), 0);
    }

    /// A shared buffer for the lines of `Explain`.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Lines {
        fn read(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(String::from)
                .collect()
        }
    }

    fn explained(
        reach: EgressReach,
        host: TestHost,
        exempt: Option<IpAddr>,
    ) -> (SocketAddr, Stop, thread::JoinHandle<()>, Lines) {
        let lines = Lines::default();
        let explain = Arc::new(Explain::new(lines.clone()));
        let (broker, stop, server) = start_explained(reach, host, exempt, Some(explain));
        (broker, stop, server, lines)
    }

    /// The report names the reason of each refusal once, the subnet that makes an address the
    /// local network, and whether `public-and-local` would allow it. The replies stay the same.
    #[test]
    fn explain_names_each_refusal_once_with_its_reason() {
        let host = TestHost {
            subnets: vec![
                Subnet::new("10.1.2.0".parse().unwrap(), 24).unwrap(),
                Subnet::new("1.2.3.0".parse().unwrap(), 24).unwrap(),
            ],
            ..TestHost::default()
        };
        let (broker, stop, server, lines) = explained(EgressReach::Public, host, None);
        let local: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let private: SocketAddr = "10.1.2.3:80".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:80".parse().unwrap();
        for destination in [local, local, private, loopback] {
            assert_eq!(connect_through(broker, destination).1, 2, "{destination}");
        }
        stop.request();
        server.join().unwrap();
        let lines = lines.read();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines.iter().all(|line| line.starts_with(EXPLAIN_PREFIX)),
            "{lines:?}"
        );
        let hint = "; reach = \"public-and-local\" allows it";
        assert!(
            lines[0].ends_with(&format!(
                "egress to 1.2.3.4:80 refused with reply 2: on 1.2.3.0/24, a network this host \
                 reaches without a router, which is the local network{hint}"
            )),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("egress to 10.1.2.3:80 refused with reply 2: ")
                && lines[1].ends_with(hint),
            "{lines:?}"
        );
        assert!(
            lines[2].contains("egress to 127.0.0.1:80 refused with reply 2: ")
                && !lines[2].contains("public-and-local"),
            "{lines:?}"
        );
    }

    /// A host that cannot tell, a name and a failed connect each get a line with their reply.
    #[test]
    fn explain_names_unknown_hosts_names_and_failed_connects() {
        let host = TestHost {
            fails: true,
            ..TestHost::default()
        };
        let (broker, stop, server, lines) = explained(EgressReach::Public, host, None);
        assert_eq!(connect_through(broker, "1.1.1.1:80".parse().unwrap()).1, 1);
        let mut stream = TcpStream::connect(broker).unwrap();
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, 9];
        request.extend(b"localhost");
        request.extend([0, 80]);
        stream.write_all(&request).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        // A connection that ends before its request names nothing.
        drop(TcpStream::connect(broker).unwrap());
        stop.request();
        server.join().unwrap();
        let lines = lines.read();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].ends_with(
                "egress to 1.1.1.1:80 refused with reply 1: this host could not tell whether the \
                 address is its own"
            ),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("egress to a name refused with reply 8"),
            "{lines:?}"
        );

        let Some(stand_in) = stand_in() else {
            eprintln!("skipped: this host has no address besides loopback");
            return;
        };
        let unused = TcpListener::bind((stand_in, 0)).unwrap();
        let target = unused.local_addr().unwrap();
        drop(unused);
        let (broker, stop, server, lines) = explained(
            EgressReach::PublicAndLocal,
            host_without(stand_in),
            Some(stand_in),
        );
        assert_eq!(connect_through(broker, target).1, 5);
        stop.request();
        server.join().unwrap();
        let lines = lines.read();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&format!(
                "egress to {target} failed with reply 5: the connect failed: "
            )),
            "{lines:?}"
        );
    }

    /// The report stops after `MOST_LINES` distinct lines and says so once. Lines the queue
    /// could not take are counted in the report instead.
    #[test]
    fn explain_stops_after_its_most_lines() {
        let lines = Lines::default();
        let explain = Explain::new(lines.clone());
        for n in 0..MOST_LINES + 5 {
            explain.report(format!("line {n}"));
            explain.report("line 0".to_string());
        }
        drop(explain);
        let lines = lines.read();
        let dropped: usize = lines
            .iter()
            .filter_map(|line| {
                line.strip_prefix(EXPLAIN_PREFIX)?
                    .split_once(" egress lines dropped")
            })
            .map(|(count, _)| count.parse::<usize>().unwrap())
            .sum();
        let named = lines.iter().filter(|line| line.contains(" line ")).count();
        // The line that ends the report goes through the queue too, so it is written or counted
        // among the dropped ones.
        let ended = lines
            .iter()
            .filter(|line| line.contains("no more follow"))
            .count();
        assert!(ended <= 1, "{lines:?}");
        assert_eq!(named + dropped + ended, MOST_LINES + 1, "{lines:?}");
    }

    /// A standard error that takes nothing holds up no report: the lines that do not fit the
    /// queue are dropped at once, and the end of the broker waits at most `FINAL_WRITE`.
    #[test]
    fn a_stalled_standard_error_holds_up_no_report() {
        struct Stalled(Arc<Mutex<mpsc::Receiver<()>>>);
        impl Write for Stalled {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.0.lock().unwrap().recv();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release, stalled) = mpsc::channel::<()>();
        let explain = Explain::new(Stalled(Arc::new(Mutex::new(stalled))));
        let started = Instant::now();
        for n in 0..MOST_LINES {
            explain.report(format!("line {n}"));
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert!(explain.lines.dropped() > 0);
        let ending = Instant::now();
        drop(explain);
        assert!(ending.elapsed() < crate::report::FINAL_WRITE + Duration::from_secs(1));
        drop(release);
    }
}
