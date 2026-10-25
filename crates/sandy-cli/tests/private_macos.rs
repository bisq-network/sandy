//! macOS tests of `ip = "private"`. macOS has no loopback of the program's own, so the profile is
//! relay only: TCP out to the forwarded ports and in on the exposed ports. Seatbelt's `localhost`
//! matches every address of the Mac, not loopback, so the relay holds the forwarded ports at the
//! wildcard addresses (docs/macos.md, "The private network"). Tests whose name says "only",
//! "holds" or "refuses" check an invariant; the others record a route that stays open, each
//! named by a row of the exceptions table in DESIGN.md, so that a change shows up as a failing
//! test.
#![cfg(target_os = "macos")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use common::*;

const WAIT: Duration = Duration::from_secs(20);
/// mDNSResponder, the name resolver.
const DNS_RESOLVER: &str = "/private/var/run/mDNSResponder";
/// What the probe's tcp-send action writes.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A loopback service outside the sandbox that counts the connections it accepts.
fn counting_service() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (address, count)
}

/// The addresses of this Mac outside loopback, the first one of each kind: IPv4, IPv6
/// link-local and other IPv6, with port 0. `None` without an IPv4 address, which every test
/// here needs.
fn other_addresses() -> Option<Vec<SocketAddr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list, which freeifaddrs frees below.
    assert_eq!(unsafe { libc::getifaddrs(&mut list) }, 0);
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entry is an element of the list that getifaddrs returned.
        let interface = unsafe { &*entry };
        entry = interface.ifa_next;
        let up = interface.ifa_flags & libc::IFF_UP as u32 != 0;
        let loopback = interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        if interface.ifa_addr.is_null() || !up || loopback {
            continue;
        }
        // SAFETY: ifa_addr points at a socket address of the family it names.
        let address = match i32::from(unsafe { (*interface.ifa_addr).sa_family }) {
            libc::AF_INET => {
                // SAFETY: as above, an AF_INET address.
                let raw = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
                SocketAddr::from((Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr)), 0))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, an AF_INET6 address.
                let raw = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in6>() };
                let mut octets = raw.sin6_addr.s6_addr;
                let mut scope = raw.sin6_scope_id;
                // The kernel's own form of a link-local address carries the interface in the
                // third and fourth byte.
                let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
                if link_local && (octets[2], octets[3]) != (0, 0) {
                    scope = u32::from(u16::from_be_bytes([octets[2], octets[3]]));
                    (octets[2], octets[3]) = (0, 0);
                }
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), 0, 0, scope))
            }
            _ => continue,
        };
        if !found.iter().any(|known| kind(known) == kind(&address)) {
            found.push(address);
        }
    }
    // SAFETY: the list came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    found.sort_by_key(kind);
    found
        .first()
        .is_some_and(SocketAddr::is_ipv4)
        .then_some(found)
}

fn kind(address: &SocketAddr) -> u8 {
    match address {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(v6) if v6.scope_id() != 0 => 1,
        SocketAddr::V6(_) => 2,
    }
}

fn at(address: SocketAddr, port: u16) -> SocketAddr {
    let mut address = address;
    address.set_port(port);
    address
}

fn skip_without_addresses() {
    skip(
        "non-loopback-address",
        "this Mac has no IPv4 address outside loopback",
    );
}

fn private_forward(fixture: &Fixture, port: u16, to: SocketAddr) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "private".to_string(),
        "--forward".to_string(),
        format!("{port}={to}"),
    ]);
    args
}

/// The program under sandy with its standard input and output piped, so the test can let it go
/// on and read each result as it comes.
fn start(args: &[String], actions: &[(&str, &str)]) -> (Child, BufReader<ChildStdout>) {
    let mut child = Command::new(sandy_path())
        .args(run_args(args, actions))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdout)
}

fn next_line(stdout: &mut BufReader<ChildStdout>) -> ProbeLine {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    parse_line(line.trim_end())
}

/// Waits until sandy has become the probe. The relay and its holder binds are in place before
/// that.
fn wait_for_program(pid: u32) {
    let start = Instant::now();
    loop {
        let output = Command::new("/bin/ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&output.stdout)
            .trim()
            .ends_with("sandy-probe")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "sandy never became the program");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Accepts one connection on `listener` within `WAIT` and returns what it sends.
fn receive(listener: &TcpListener) -> Option<Vec<u8>> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                let mut received = Vec::new();
                let _ = stream.read_to_end(&mut received);
                return Some(received);
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    None
}

/// The program reaches its forwarded port and nothing else of IP: not the service behind it
/// directly, not a listener at another address of the Mac, no datagram, no listening socket, no
/// name resolution, no NECP. Every control succeeds outside the sandbox.
#[test]
fn a_private_network_reaches_only_its_forwarded_ports() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("private-only");
    let (service, accepted) = counting_service();
    let elsewhere = TcpListener::bind(at(others[0], 0)).unwrap();
    let port = free_port();
    let direct = service.to_string();
    let other_host_address = elsewhere.local_addr().unwrap().to_string();
    let other_port = format!("127.0.0.1:{}", free_port());
    let controls = [
        ("tcp-connect", direct.as_str()),
        ("tcp-connect", other_host_address.as_str()),
        ("udp-send", direct.as_str()),
        ("tcp-listen", other_port.as_str()),
        ("resolve", "localhost"),
        ("necp-open", ""),
        ("unix-connect", DNS_RESOLVER),
    ];
    for line in probe_outside(&controls) {
        line.assert_ok();
    }
    let forwarded = format!("127.0.0.1:{port}");
    let mut actions = vec![("tcp-connect", forwarded.as_str())];
    actions.extend(controls);
    let inside = probe_inside(&private_forward(&fixture, port, service), &actions);
    inside[0].assert_ok();
    for line in &inside[1..] {
        line.assert_blocked();
    }
    let start = Instant::now();
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(start.elapsed() < WAIT, "the forwarded service saw nothing");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Seatbelt lets the program connect to a forwarded port at every address of the Mac. The
/// relay binds the port at the wildcard addresses without listening, so while it runs no other
/// socket of this user can take them, and a connection to the port at an address where no one
/// listens goes unanswered instead of being refused. Afterwards the port is free again.
#[test]
fn the_relay_holds_the_forwarded_ports_at_the_wildcard_addresses() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("private-holder");
    let (service, _) = counting_service();
    let port = free_port();
    let targets: Vec<String> = others
        .iter()
        .chain(&[SocketAddr::from((Ipv6Addr::LOCALHOST, 0))])
        .map(|address| at(*address, port).to_string())
        .collect();
    let mut actions = vec![("read-line", "-")];
    actions.extend(
        targets
            .iter()
            .map(|target| ("tcp-connect", target.as_str())),
    );
    let (mut program, mut stdout) = start(&private_forward(&fixture, port, service), &actions);
    wait_for_program(program.id());
    for wildcard in ["0.0.0.0", "::"] {
        let taken = TcpListener::bind((wildcard, port));
        assert_eq!(
            taken.as_ref().map_err(std::io::Error::kind).err(),
            Some(std::io::ErrorKind::AddrInUse),
            "{wildcard}: {taken:?}"
        );
    }
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let results: Vec<ProbeLine> = targets.iter().map(|_| next_line(&mut stdout)).collect();
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    for line in &results {
        assert!(
            line.result == "error" && line.detail.contains("timed out"),
            "a connection to {} was answered: {line:?}",
            line.target
        );
    }
    for wildcard in ["0.0.0.0", "::"] {
        TcpListener::bind((wildcard, port)).unwrap();
    }
}

/// A listener of another socket at a wildcard address of a forwarded port would receive the
/// program's connections to the port at the other addresses of the Mac, so sandy refuses, and
/// check says so first. With `ip = "all"` the program reaches that listener anyway, so the same
/// forward runs there.
#[test]
fn a_wildcard_listener_on_a_forwarded_port_refuses_a_private_network() {
    let fixture = Fixture::new("private-refused");
    let (service, _) = counting_service();
    for wildcard in ["0.0.0.0", "::"] {
        let listener = TcpListener::bind((wildcard, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let args = private_forward(&fixture, port, service);
        let output = sandy(run_args(&args, &[("pid", "")]));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        assert!(
            stderr.contains(&format!("cannot hold port {port}")),
            "{stderr}"
        );

        let mut check = vec!["check".to_string()];
        check.extend(args.iter().cloned());
        let output = sandy(&check);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(1), "{stdout}");
        assert!(
            stdout.contains(&format!(
                "UNAVAILABLE  IP networking limited to the sandbox's own loopback: cannot hold \
                 port {port}"
            )),
            "{stdout}"
        );

        let mut all = fixture.access_args();
        all.extend(["--ip", "all", "--forward"].map(String::from));
        all.push(format!("{port}={service}"));
        probe_inside(&all, &[("pid", "")])[0].assert_ok();
    }
}

/// The exceptions row for `ip = "private"` with `forward` on macOS: the relay holds a forwarded
/// port only at the wildcard addresses, so a process of sandy's own user can listen on it at an
/// address of the Mac outside loopback, and receives the program's connection there. When this
/// fails, the route is closed and the row has to go.
#[test]
fn a_process_of_the_same_user_takes_a_forwarded_port_at_another_address() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("private-taken");
    let (service, _) = counting_service();
    let port = free_port();
    let target = at(others[0], port).to_string();
    let (mut program, mut stdout) = start(
        &private_forward(&fixture, port, service),
        &[("read-line", "-"), ("tcp-send", target.as_str())],
    );
    wait_for_program(program.id());
    let taken = TcpListener::bind(at(others[0], port)).expect(
        "a process of sandy's user can no longer bind a forwarded port next to the holder, so \
         the exception for ip = \"private\" with forward on macOS is stale",
    );
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let received = receive(&taken);
    let sent = next_line(&mut stdout);
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    sent.assert_ok();
    assert_eq!(
        received.as_deref(),
        Some(TCP_SEND_PAYLOAD),
        "the program's connection to {target} no longer reaches a listener of the same user, \
         so the exception for ip = \"private\" with forward on macOS is stale"
    );
}

/// The same row: once the relay has ended, its holder binds and its listener are gone, and the
/// program's forwarded port reaches whatever binds it next. With `signals = "any"` the program
/// could end the relay itself; here the test does. With `children = "contained"` the guard ends
/// the program with its relay instead (`review_relays.rs`).
#[test]
fn a_forwarded_port_reaches_whatever_binds_it_once_the_relay_has_ended() {
    let fixture = Fixture::new("private-relay-ended");
    let (service, _) = counting_service();
    let port = free_port();
    let forwarded = format!("127.0.0.1:{port}");
    let (mut program, mut stdout) = start(
        &private_forward(&fixture, port, service),
        &[("read-line", "-"), ("tcp-send", forwarded.as_str())],
    );
    wait_for_program(program.id());
    let relay = relay_of(port);
    // SAFETY: kill has no memory arguments.
    assert_eq!(unsafe { libc::kill(relay, libc::SIGKILL) }, 0);
    let start = Instant::now();
    // SAFETY: as above; signal 0 only asks whether the process exists.
    while unsafe { libc::kill(relay, 0) } == 0 {
        assert!(start.elapsed() < WAIT, "the relay did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    let taken = TcpListener::bind(&forwarded).unwrap();
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let received = receive(&taken);
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        received.as_deref(),
        Some(TCP_SEND_PAYLOAD),
        "the forwarded port of a program whose relay ended no longer reaches a new listener, so \
         the exception for ip = \"private\" with forward on macOS is stale"
    );
}

/// The process that listens on `port` at 127.0.0.1, found with lsof.
fn relay_of(port: u16) -> libc::pid_t {
    let output = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            &format!("-iTCP@127.0.0.1:{port}"),
            "-sTCP:LISTEN",
            "-t",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let pids: Vec<libc::pid_t> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
    assert_eq!(pids.len(), 1, "no single listener on {port}: {text:?}");
    pids[0]
}

/// Connects to `address` from this process until the program reports its next result, which
/// it does once it accepted a connection or gave up.
fn connect_until_reported(address: SocketAddr, results: &mpsc::Receiver<ProbeLine>) -> ProbeLine {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Ok(line) = results.recv_timeout(Duration::from_millis(100)) {
            return line;
        }
    }
    panic!("the program reported nothing while this process connected to {address}");
}

/// An exposed port works under a private network: a client outside reaches the program through
/// the relay. The exceptions row for `ip = "private"` with `expose` on macOS: the program can
/// also listen on its exposed port at an address of the Mac outside loopback, where this process,
/// every other local process and other hosts reach it without the relay. Other ports and
/// datagrams stay closed. When the second accept fails, the route is closed and the row has to
/// go.
#[test]
fn the_program_listens_on_its_exposed_port_at_every_address() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("private-expose");
    let (inner, outer) = (free_port(), free_port());
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "private".to_string(),
        "--expose".to_string(),
        format!("127.0.0.1:{outer}={inner}"),
    ]);
    let loopback = format!("127.0.0.1:{inner}");
    let elsewhere = at(others[0], inner);
    let elsewhere_text = elsewhere.to_string();
    let other_port = at(others[0], free_port()).to_string();
    let (program, mut stdout) = start(
        &args,
        &[
            ("tcp-accept", loopback.as_str()),
            ("tcp-accept", elsewhere_text.as_str()),
            ("tcp-listen", other_port.as_str()),
            ("udp-receive", loopback.as_str()),
        ],
    );
    let (sender, results) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for _ in 0..4 {
            if sender.send(next_line(&mut stdout)).is_err() {
                return;
            }
        }
    });
    let through_relay =
        connect_until_reported(format!("127.0.0.1:{outer}").parse().unwrap(), &results);
    let direct = connect_until_reported(elsewhere, &results);
    let rest: Vec<ProbeLine> = results.iter().collect();
    reader.join().unwrap();
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    through_relay.assert_ok();
    assert_eq!(
        direct.result, "ok",
        "the program can no longer listen on its exposed port at {elsewhere}, so the exception \
         for ip = \"private\" with expose on macOS is stale: {direct:?}"
    );
    assert_eq!(rest.len(), 2, "{rest:?}");
    for line in &rest {
        line.assert_blocked();
    }
}
