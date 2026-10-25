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

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use sandy_core::EgressReach;
use sandy_core::destination::{self, HostNetwork, Refusal};

use crate::socks::{self, Reply};
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
const THREAD_STACK: usize = 256 * 1024;

/// Serves the broker on `listener` until `stop` is requested, then ends as `serve_until` does:
/// it still takes the connections that wait in the backlog, closes the listener, waits up to
/// `drain` for the accepted connections, and leaves those still open to end with a reset when
/// the process ends (`abort_all`). `accept` takes one connection from `listener`, which on
/// Windows may be an AF_UNIX one (`unix::Listener`).
///
/// `reach` and `host` decide the destinations (`sandy_core::destination::check`). On Unix the
/// caller raises the descriptor limit first (`raise_descriptor_limit`).
pub fn serve<L, A, H>(
    listener: L,
    accept: A,
    reach: EgressReach,
    host: H,
    stop: &Stop,
    drain: Duration,
) where
    L: AsRawListener,
    A: FnMut(&L) -> io::Result<TcpStream>,
    H: HostNetwork + Send + Sync + 'static,
{
    let broker = Broker {
        reach,
        host,
        reached_host,
    };
    serve_broker(listener, accept, broker, stop, drain);
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
    let connections = Connections::new(MAX_CONNECTIONS, Some(THREAD_STACK), move |client| {
        let _ = broker.handle(client);
    });
    serve_connections_until(listener, accept, &connections, stop, drain);
}

/// What the broker decides with. `reached_host` is the check after the connect; only tests
/// replace it, to reach a stand-in on this host.
struct Broker<H, R> {
    reach: EgressReach,
    host: H,
    reached_host: R,
}

impl<H, R> Broker<H, R>
where
    H: HostNetwork,
    R: Fn(&TcpStream) -> bool,
{
    fn handle(&self, client: TcpStream) -> io::Result<()> {
        // A listener that does not block may pass that on to the connections it accepts.
        client.set_nonblocking(false)?;
        let requested = socks::read_request(&client)?;
        let destination = match destination::check(requested, self.reach, &self.host) {
            Ok(destination) => destination,
            Err(Refusal::HostUnknown) => return socks::reply(&client, Reply::GeneralFailure),
            Err(_) => return socks::reply(&client, Reply::NotAllowed),
        };
        let server = match TcpStream::connect_timeout(&destination, CONNECT_TIMEOUT) {
            Ok(server) => server,
            Err(error) => return socks::reply(&client, Reply::for_connect_error(&error)),
        };
        if (self.reached_host)(&server) {
            reset_on_close(raw(&server));
            return socks::reply(&client, Reply::NotAllowed);
        }
        socks::reply(&client, Reply::Succeeded)?;
        relay_streams_with(client, server, HALF_CLOSED_IDLE, Some(THREAD_STACK))
    }
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
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use sandy_core::destination::Subnet;

    /// A host check that answers from fixed lists.
    #[derive(Default)]
    struct TestHost {
        own: Vec<IpAddr>,
        subnets: Vec<Subnet>,
        fails: bool,
    }

    impl HostNetwork for TestHost {
        fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
            if self.fails {
                return Err(io::Error::other("no answer"));
            }
            Ok(self.own.contains(&ip))
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Stop::new();
        let request = stop.clone();
        let broker = Broker {
            reach,
            host,
            reached_host: move |server: &TcpStream| {
                let peer = server.peer_addr().map(|peer| peer.ip()).ok();
                peer.is_none() || (peer != exempt && reached_host(server))
            },
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
        let stop = Stop::new();
        let request = stop.clone();
        let broker = Broker {
            reach: EgressReach::PublicAndLocal,
            host: host_without(stand_in),
            reached_host: move |server: &TcpStream| {
                server.peer_addr().map(|peer| peer.ip()).ok() != Some(stand_in)
                    && reached_host(server)
            },
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
        let target = echo_server(stand_in);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let mut all = vec![5, 1, 0];
        all.extend(request_bytes(target));
        all.extend(b"late");
        client.write_all(&all).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let stop = Stop::new();
        stop.request();
        let broker = Broker {
            reach: EgressReach::PublicAndLocal,
            host: host_without(stand_in),
            reached_host: |_: &TcpStream| false,
        };
        serve_broker(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            broker,
            &stop,
            DRAIN,
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

    /// A client that never finishes its handshake delays the end by at most the drain time.
    #[test]
    fn the_drain_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let stop = Stop::new();
        stop.request();
        let drain = Duration::from_millis(300);
        let started = Instant::now();
        serve(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            EgressReach::Public,
            TestHost::default(),
            &stop,
            drain,
        );
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
        let connections = Connections::new(2, Some(THREAD_STACK), move |client: TcpStream| {
            let _ = released.lock().unwrap().recv();
            let _ = (&client).write_all(b"served");
        });
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
}
