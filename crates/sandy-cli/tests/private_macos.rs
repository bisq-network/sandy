//! macOS tests of `ip = "private"` and its egress broker. macOS has no loopback of the program's
//! own, so the profile is relay only: TCP out to the forwarded and egress ports and in on the
//! exposed ports. Seatbelt's `localhost` matches every address of the Mac, not loopback, so the
//! relay and the broker hold their ports at the wildcard addresses and at every address the Mac
//! has (docs/macos.md, "The private network"). Tests whose name says "only", "holds", "refuses"
//! or "ends" check an invariant; the others record a route that stays open, each named by a row
//! of the exceptions table in DESIGN.md, so that a change shows up as a failing test. One part
//! of a row has no test: an address that the Mac gains while sandy runs, which no test can add
//! without administrator rights.
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

/// A private network with a forwarded port. A port that sandy holds needs isolated signals on
/// macOS, so that the program cannot end its relay.
fn private_forward(fixture: &Fixture, port: u16, to: SocketAddr) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "private".to_string(),
        "--signals".to_string(),
        "isolated".to_string(),
        "--forward".to_string(),
        format!("{port}={to}"),
    ]);
    args
}

/// A private network with the egress broker on `port`.
fn private_egress(fixture: &Fixture, port: u16, reach: &str) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "private".to_string(),
        "--signals".to_string(),
        "isolated".to_string(),
        "--egress".to_string(),
        format!("{port}={reach}"),
    ]);
    args
}

/// Every address of this Mac outside loopback and the other loopback family, at `port`, for
/// the holder checks.
fn held_addresses(others: &[SocketAddr], port: u16) -> Vec<SocketAddr> {
    let mut held: Vec<SocketAddr> = others.iter().map(|address| at(*address, port)).collect();
    held.extend(
        ["0.0.0.0", "[::]", "[::1]"]
            .map(|ip| format!("{ip}:{port}").parse::<SocketAddr>().unwrap()),
    );
    held
}

/// Binds every address of `held` the way another program of this user would, which the holder
/// must refuse while it runs.
fn assert_held(held: &[SocketAddr]) {
    for address in held {
        let taken = TcpListener::bind(address).map(drop).map_err(|e| e.kind());
        assert_eq!(
            taken,
            Err(std::io::ErrorKind::AddrInUse),
            "a socket of this user took {address} next to the holder"
        );
    }
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
/// directly, not a listener at another address of the Mac, no datagram, no ICMP, no listening
/// socket, no name resolver, no NECP. Every control succeeds outside the sandbox. `localhost`
/// resolves from /etc/hosts, which getaddrinfo reads itself, and a name that only DNS knows does
/// not.
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
        ("icmp-socket-echo", "127.0.0.1"),
        ("tcp-listen", other_port.as_str()),
        ("necp-open", ""),
        ("unix-connect", DNS_RESOLVER),
    ];
    for line in probe_outside(&controls) {
        line.assert_ok();
    }
    let forwarded = format!("127.0.0.1:{port}");
    let mut actions = vec![
        ("tcp-connect", forwarded.as_str()),
        ("resolve", "localhost"),
        ("resolve", "example.com"),
    ];
    actions.extend(controls);
    let inside = probe_inside(&private_forward(&fixture, port, service), &actions);
    inside[0].assert_ok();
    inside[1].assert_ok();
    for line in &inside[3..] {
        line.assert_blocked();
    }
    if probe_outside(&[("resolve", "example.com")])[0].result == "ok" {
        inside[2].assert_blocked();
    } else {
        skip("dns", "this Mac resolves no name through DNS");
    }
    let start = Instant::now();
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(start.elapsed() < WAIT, "the forwarded service saw nothing");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Seatbelt lets the program connect to a forwarded port at every address of the Mac. The
/// relay binds the port without listening at the wildcard addresses and at every address the Mac
/// has, so while it runs no other socket of this user can take any of them, and a connection to
/// the port at such an address goes unanswered instead of being refused. Afterwards the port is
/// free again.
#[test]
fn the_relay_holds_the_forwarded_ports_at_every_address() {
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
    assert_held(&held_addresses(&others, port));
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let results: Vec<ProbeLine> = targets.iter().map(|_| next_line(&mut stdout)).collect();
    let output = program.wait_with_output().unwrap();
    let ended = Instant::now();
    assert!(output.status.success(), "{output:?}");
    // The relay is a process of its own: it frees the port when it sees the program end, a
    // moment after the program's exit.
    let wildcards = ["0.0.0.0:0", "[::]:0"].map(|address| at(address.parse().unwrap(), port));
    let freed = freed_after(&wildcards, ended, "the relay kept the forwarded port");
    assert!(
        freed < FREED_AT_ONCE,
        "the relay kept the forwarded port {freed:?} after the program ended"
    );
    for line in &results {
        assert!(
            line.result == "error" && line.detail.contains("timed out"),
            "a connection to {} was answered: {line:?}",
            line.target
        );
    }
}

/// A socket that already listens on a forwarded port, at a wildcard address or at an address of
/// the Mac, would receive the program's connections there, so sandy refuses, and check says so
/// first. With `ip = "all"` the program reaches that listener anyway, so the same forward runs
/// there.
#[test]
fn a_listener_on_a_forwarded_port_refuses_a_private_network() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("private-refused");
    let (service, _) = counting_service();
    let mut addresses: Vec<SocketAddr> = ["0.0.0.0:0", "[::]:0", "[::1]:0"]
        .map(|address| address.parse().unwrap())
        .to_vec();
    addresses.push(others[0]);
    for address in addresses {
        let listener = TcpListener::bind(address).unwrap();
        let port = listener.local_addr().unwrap().port();
        let args = private_forward(&fixture, port, service);
        let output = sandy(run_args(&args, &[("pid", "")]));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        assert!(
            stderr.contains(&format!("cannot hold port {port}")),
            "{address}: {stderr}"
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

/// With `signals = "any"` the program could end its relay or broker and leave the port to
/// whatever binds it next at any address of the Mac, so sandy refuses a held port then, and says
/// what to set. A private network with only an exposed port holds nothing and runs.
#[test]
fn a_held_port_refuses_signals_any() {
    let fixture = Fixture::new("private-signals");
    let (service, _) = counting_service();
    let mut forward = fixture.access_args();
    forward.extend(["--ip", "private", "--forward"].map(String::from));
    forward.push(format!("{}={service}", free_port()));
    let mut egress = fixture.access_args();
    egress.extend(["--ip", "private", "--egress"].map(String::from));
    egress.push(free_port().to_string());
    for args in [forward, egress] {
        let output = sandy(run_args(&args, &[("pid", "")]));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        assert!(stderr.contains("set signals = \"isolated\""), "{stderr}");
    }
    let mut exposed = fixture.access_args();
    exposed.extend(["--ip", "private", "--expose"].map(String::from));
    exposed.push(format!("127.0.0.1:{}={}", free_port(), free_port()));
    probe_inside(&exposed, &[("pid", "")])[0].assert_ok();
}

/// The exceptions row for `ip = "private"` with `forward` or `egress` on macOS, without
/// `macos.relays = "ipv4"`: Seatbelt's `localhost` matches an IPv6 link-local address of this
/// Mac with any interface as its scope, so the program may connect to its forwarded port at an
/// address that is this Mac's on one link and may be another host's on another, where nothing of
/// sandy's can hold it. The test asks with loopback as the scope, where no such address exists,
/// so nothing leaves this Mac: the profile lets the connect through, and it times out on lo0.
/// Control: a link-local address that is not this Mac's is denied at the same scope. When the
/// first connect is denied, the route is closed and that part of the row has to go.
#[test]
fn a_link_local_address_of_this_mac_matches_at_every_scope() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let Some(SocketAddr::V6(own)) = others.iter().copied().find(|address| kind(address) == 1)
    else {
        return skip(
            "ipv6-link-local",
            "this Mac has no IPv6 link-local address outside loopback",
        );
    };
    // SAFETY: the name is a C string.
    let loopback = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
    assert_ne!(loopback, 0, "no lo0");
    let fixture = Fixture::new("private-scope");
    let (service, _) = counting_service();
    let port = free_port();
    let mut foreign = own.ip().segments();
    foreign[7] ^= 0xffff;
    let at_loopback = |ip: Ipv6Addr| SocketAddrV6::new(ip, port, 0, loopback).to_string();
    let (own_there, foreign_there) = (at_loopback(*own.ip()), at_loopback(foreign.into()));
    let inside = probe_inside(
        &private_forward(&fixture, port, service),
        &[
            ("tcp-connect", own_there.as_str()),
            ("tcp-connect", foreign_there.as_str()),
        ],
    );
    assert_eq!(inside[1].result, "denied", "{:?}", inside[1]);
    assert!(
        inside[0].result == "error" && inside[0].detail.contains("timed out"),
        "the profile no longer lets the program connect to {own_there}, a link-local address of \
         this Mac at another scope, so that part of the exception for ip = \"private\" on macOS \
         is stale: {:?}",
        inside[0]
    );
}

/// With `macos.relays = "ipv4"` the profile allows the forwarded and egress ports for IPv4
/// sockets only, which closes the route that
/// `a_link_local_address_of_this_mac_matches_at_every_scope` records: the connect to this Mac's
/// link-local address at the scope of lo0 is denied. So is every other IPv6 form, ::1 and
/// ::ffff:127.0.0.1 included, which is how Java and .NET connect to an IPv4 address by default,
/// while the relay and the broker still serve over IPv4. Control: with `dual-stack` the same
/// connects pass the profile, ::ffff:127.0.0.1 reaches the relay and the broker, and the others
/// find a holder or nothing and go unanswered.
#[test]
fn ipv4_relays_are_reached_only_over_ipv4() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let Some(SocketAddr::V6(own)) = others.iter().copied().find(|address| kind(address) == 1)
    else {
        return skip(
            "ipv6-link-local",
            "this Mac has no IPv6 link-local address outside loopback",
        );
    };
    // SAFETY: the name is a C string.
    let loopback = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
    assert_ne!(loopback, 0, "no lo0");
    let fixture = Fixture::new("private-ipv4");
    let (service, accepted) = counting_service();
    // Ports of their own for each run: the relay and the broker of the first run free theirs a
    // moment after its program has ended, as separate processes, so the second run could still
    // find them taken.
    let run = |relays: &str| {
        let (port, egress) = (free_port(), free_port());
        let forwarded = format!("127.0.0.1:{port}");
        let refused = through(egress, "127.0.0.1:1");
        let mapped = format!("[::ffff:127.0.0.1]:{port}");
        let mapped_broker = format!("[::ffff:127.0.0.1]:{egress}");
        let ipv6_loopback = format!("[::1]:{port}");
        let scoped = SocketAddrV6::new(*own.ip(), port, 0, loopback).to_string();
        let actions = [
            ("tcp-connect", forwarded.as_str()),
            ("socks5-connect", refused.as_str()),
            ("tcp-connect", mapped.as_str()),
            ("tcp-connect", mapped_broker.as_str()),
            ("tcp-connect", ipv6_loopback.as_str()),
            ("tcp-connect", scoped.as_str()),
        ];
        let mut args = private_forward(&fixture, port, service);
        args.extend(["--egress", &egress.to_string(), "--macos-relays", relays].map(String::from));
        probe_inside(&args, &actions)
    };

    let ipv4 = run("ipv4");
    ipv4[0].assert_ok();
    assert_eq!(reply_of(&ipv4[1]), 2, "{ipv4:?}");
    for line in &ipv4[2..] {
        assert_eq!(line.result, "denied", "{line:?}");
    }
    let start = Instant::now();
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(start.elapsed() < WAIT, "the forwarded service saw nothing");
        std::thread::sleep(Duration::from_millis(50));
    }

    let dual_stack = run("dual-stack");
    dual_stack[0].assert_ok();
    assert_eq!(reply_of(&dual_stack[1]), 2, "{dual_stack:?}");
    dual_stack[2].assert_ok();
    dual_stack[3].assert_ok();
    for line in &dual_stack[4..] {
        assert!(
            line.result == "error" && line.detail.contains("timed out"),
            "{line:?}"
        );
    }
}

/// Under `signals = "isolated"` the program cannot stop or end its relay or its broker, which is
/// what a forwarded or egress port needs on macOS (`a_held_port_refuses_signals_any`). Control:
/// outside the sandbox this user may signal both. Afterwards both still serve.
#[test]
fn the_program_cannot_signal_its_relay_or_broker() {
    let fixture = Fixture::new("private-signal-helpers");
    let (service, accepted) = counting_service();
    let (port, egress) = (free_port(), free_port());
    let mut args = private_forward(&fixture, port, service);
    args.extend(["--egress".to_string(), egress.to_string()]);
    let forwarded = format!("127.0.0.1:{port}");
    let refused = through(egress, "127.0.0.1:1");
    let (mut program, mut stdout) = start(
        &args,
        &[
            ("signal-stop", "-"),
            ("signal-stop", "-"),
            ("tcp-connect", forwarded.as_str()),
            ("socks5-connect", refused.as_str()),
        ],
    );
    wait_for_program(program.id());
    let helpers = [relay_of(port), relay_of(egress)];
    let pids = helpers.map(|pid| pid.to_string());
    for line in probe_outside(&[("signal", &pids[0]), ("signal", &pids[1])]) {
        line.assert_ok();
    }
    let mut stdin = program.stdin.take().unwrap();
    for pid in &pids {
        writeln!(stdin, "{pid}").unwrap();
    }
    drop(stdin);
    let results: Vec<ProbeLine> = (0..4).map(|_| next_line(&mut stdout)).collect();
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    for line in &results[..2] {
        assert_eq!(line.result, "denied", "{line:?}");
    }
    results[2].assert_ok();
    assert_eq!(reply_of(&results[3]), 2, "{results:?}");
    let start = Instant::now();
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(
            start.elapsed() < WAIT,
            "the relay did not serve after the signals"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The exceptions row for `ip = "private"` with `forward` on macOS: once the relay has ended,
/// here because the test ends it from outside the sandbox, its holder binds and its listener are
/// gone, and the program's forwarded port reaches whatever binds it next. With
/// `children = "contained"` the guard ends the program with its relay instead
/// (`review_relays.rs`). When this fails, the route is closed and that part of the row has to go.
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

/// The probe's `socks5-connect` target: the broker on `port`, then the destination.
fn through(port: u16, destination: &str) -> String {
    format!("127.0.0.1:{port}\u{1f}{destination}")
}

/// The reply code in the detail of a `socks5-connect` result.
fn reply_of(line: &ProbeLine) -> u8 {
    line.assert_ok();
    line.detail
        .strip_prefix("reply ")
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("{line:?}"))
}

/// The default gateway of this Mac, from `route`; `None` without one.
fn gateway() -> Option<Ipv4Addr> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("gateway: "))
        .and_then(|gateway| gateway.parse().ok())
}

/// The public destination of the tests, when this Mac reaches it.
const PUBLIC: &str = "1.1.1.1:443";

fn internet() -> bool {
    TcpStream::connect_timeout(&PUBLIC.parse().unwrap(), Duration::from_secs(5)).is_ok()
}

/// The broker refuses every form of this Mac with reply 2: loopback, `0.0.0.0` and `::`, the
/// address on the local network and its IPv4-mapped form, an IPv6 address of an interface, and
/// the gateway, which `public` counts as the local network. It refuses a name with reply 8. None
/// of them reaches the listener that waits on every address at that port.
#[test]
fn the_broker_refuses_this_mac_its_network_and_names() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("egress-refused");
    let canary = TcpListener::bind("[::]:0").unwrap();
    canary.set_nonblocking(true).unwrap();
    let port = canary.local_addr().unwrap().port();
    let lan = match others[0].ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("the first address is IPv4"),
    };
    let mut destinations: Vec<String> = [
        "127.0.0.1".to_string(),
        "[::1]".to_string(),
        "[::ffff:127.0.0.1]".to_string(),
        "0.0.0.0".to_string(),
        "[::]".to_string(),
        lan.to_string(),
        format!("[{}]", lan.to_ipv6_mapped()),
    ]
    .iter()
    .map(|ip| format!("{ip}:{port}"))
    .collect();
    destinations.extend(
        others
            .iter()
            .filter(|address| address.is_ipv6())
            .map(|address| at(*address, port).to_string()),
    );
    let gateway = gateway();
    destinations.extend(gateway.map(|gateway| format!("{gateway}:80")));
    let egress = free_port();
    let mut actions: Vec<(&str, String)> = destinations
        .iter()
        .map(|destination| ("socks5-connect", through(egress, destination)))
        .collect();
    actions.push(("socks5-connect", through(egress, "example.com:80")));
    let actions: Vec<(&str, &str)> = actions
        .iter()
        .map(|(action, target)| (*action, target.as_str()))
        .collect();
    let inside = probe_inside(&private_egress(&fixture, egress, "public"), &actions);
    let (names, addresses) = inside.split_last().unwrap();
    for line in addresses {
        assert_eq!(reply_of(line), 2, "{line:?}");
    }
    assert_eq!(reply_of(names), 8, "{names:?}");
    assert!(
        canary.accept().is_err(),
        "a refused destination reached this Mac"
    );
    if gateway.is_none() {
        skip("default-gateway", "this Mac has no default gateway");
    }
}

/// Names a host of the local network that is not this Mac, as `ADDRESS:PORT`, which takes TCP
/// connections there. Unset, the test that needs one skips, so the suite sends nothing into the
/// local network by itself.
const LOCAL_PEER: &str = "SANDY_TEST_LOCAL_PEER";

/// `public-and-local` allows the local network: the broker tries the named peer, so its reply is
/// not 2, but it still refuses this Mac's own address there.
#[test]
fn public_and_local_reaches_the_local_network_but_not_this_mac() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let Some(peer) = std::env::var(LOCAL_PEER)
        .ok()
        .filter(|peer| !peer.is_empty())
    else {
        return skip(
            "local-network-peer",
            "SANDY_TEST_LOCAL_PEER names no host of the local network",
        );
    };
    let fixture = Fixture::new("egress-local");
    let egress = free_port();
    let to_peer = through(egress, &peer);
    let to_self = through(egress, &at(others[0], 80).to_string());
    let inside = probe_inside(
        &private_egress(&fixture, egress, "public-and-local"),
        &[
            ("socks5-connect", to_peer.as_str()),
            ("socks5-connect", to_self.as_str()),
        ],
    );
    let reply = reply_of(&inside[0]);
    assert!(
        reply != 2 && reply != 1,
        "the broker did not try the peer: {inside:?}"
    );
    assert_eq!(reply_of(&inside[1]), 2, "{inside:?}");
}

/// The broker connects to a public address. Only the connection is checked; nothing is sent.
#[test]
fn the_broker_connects_to_a_public_address() {
    if !internet() {
        return skip("internet", "this Mac does not reach 1.1.1.1:443");
    }
    let fixture = Fixture::new("egress-public");
    let egress = free_port();
    let target = through(egress, PUBLIC);
    let inside = probe_inside(
        &private_egress(&fixture, egress, "public"),
        &[("socks5-connect", target.as_str()), ("tcp-connect", PUBLIC)],
    );
    assert_eq!(reply_of(&inside[0]), 0, "{inside:?}");
    // The program itself reaches only the broker.
    inside[1].assert_blocked();
}

/// The broker holds its port like the relay: no other socket of this user can bind it at the
/// wildcard or any current address while it runs, and the program's connection to the port at
/// another address of the Mac goes unanswered.
#[test]
fn the_broker_holds_its_port_at_every_address() {
    let Some(others) = other_addresses() else {
        return skip_without_addresses();
    };
    let fixture = Fixture::new("egress-holder");
    let egress = free_port();
    let elsewhere = at(others[0], egress).to_string();
    let (mut program, mut stdout) = start(
        &private_egress(&fixture, egress, "public"),
        &[("read-line", "-"), ("tcp-connect", elsewhere.as_str())],
    );
    wait_for_program(program.id());
    assert_held(&held_addresses(&others, egress));
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let connected = next_line(&mut stdout);
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        connected.result == "error" && connected.detail.contains("timed out"),
        "{connected:?}"
    );
}

/// What a SOCKS5 client outside the sandbox gets from the broker at `port` for `destination`.
fn socks_reply(port: u16, destination: SocketAddr) -> std::io::Result<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.write_all(&[5, 1, 0])?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer)?;
    let mut request = vec![5, 1, 0, 1];
    match destination {
        SocketAddr::V4(v4) => request.extend(v4.ip().octets()),
        SocketAddr::V6(_) => unreachable!("the tests ask for IPv4"),
    }
    request.extend(destination.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    Ok(reply[1])
}

/// The exceptions row for `egress` on macOS: the broker cannot tell who connects, so this test
/// process, outside the sandbox, connects out through it as sandy's user. When this fails, the
/// route is closed and the row has to go.
#[test]
fn the_broker_serves_a_process_outside_the_sandbox() {
    if !internet() {
        return skip("internet", "this Mac does not reach 1.1.1.1:443");
    }
    let fixture = Fixture::new("egress-outside");
    let egress = free_port();
    let (mut program, _stdout) = start(
        &private_egress(&fixture, egress, "public"),
        &[("read-line", "-")],
    );
    wait_for_program(program.id());
    let reply = socks_reply(egress, PUBLIC.parse().unwrap());
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        reply.ok(),
        Some(0),
        "a process outside the sandbox no longer connects out through the broker, so the \
         exception for egress on macOS is stale"
    );
}

/// The broker ends with the program: its listener and its holder binds are gone right after.
#[test]
fn the_broker_ends_with_the_program() {
    let fixture = Fixture::new("egress-end");
    let egress = free_port();
    let (mut program, mut stdout) = start(
        &private_egress(&fixture, egress, "public"),
        &[("read-line", "-")],
    );
    wait_for_program(program.id());
    let broker = relay_of(egress);
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let output = program.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let start = Instant::now();
    // SAFETY: signal 0 only asks whether the process exists.
    while unsafe { libc::kill(broker, 0) } == 0 {
        assert!(start.elapsed() < WAIT, "the broker outlived the program");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(TcpStream::connect(("127.0.0.1", egress)).is_err());
    TcpListener::bind(("0.0.0.0", egress)).unwrap();
}

/// Rule 5 of "Forwarded ports" holds for the broker as for the relay: when the program ends, its
/// listener and its holder binds go at once, also while it still drains a connection, so a run
/// that starts right after can bind the port. The drained connection is a client that never
/// sends its request.
#[test]
fn the_broker_frees_its_port_as_soon_as_the_program_ends() {
    let fixture = Fixture::new("egress-free");
    let egress = free_port();
    let (mut program, mut stdout) = start(
        &private_egress(&fixture, egress, "public"),
        &[("read-line", "-")],
    );
    wait_for_program(program.id());
    let broker = relay_of(egress);
    let held = TcpStream::connect(("127.0.0.1", egress)).unwrap();
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    next_line(&mut stdout).assert_ok();
    let output = program.wait_with_output().unwrap();
    let ended = Instant::now();
    assert!(output.status.success(), "{output:?}");
    let addresses = ["127.0.0.1", "0.0.0.0", "[::]"]
        .map(|ip| format!("{ip}:{egress}").parse::<SocketAddr>().unwrap());
    let freed = freed_after(&addresses, ended, "the broker kept its port");
    // SAFETY: signal 0 only asks whether the process exists.
    let draining = unsafe { libc::kill(broker, 0) } == 0;
    drop(held);
    assert!(
        draining,
        "the broker ended before it drained the held connection"
    );
    assert!(
        freed < FREED_AT_ONCE,
        "the broker kept its port {freed:?} after the program ended"
    );
}

/// How soon after the end of the program its relay or broker has freed its ports.
const FREED_AT_ONCE: Duration = Duration::from_millis(20);

/// Waits until every one of `addresses` can be bound, at most `WAIT`, and returns how long after
/// `ended` that was.
fn freed_after(addresses: &[SocketAddr], ended: Instant, kept: &str) -> Duration {
    while !addresses
        .iter()
        .all(|address| TcpListener::bind(address).is_ok())
    {
        assert!(ended.elapsed() < WAIT, "{kept}");
        std::thread::sleep(Duration::from_millis(1));
    }
    ended.elapsed()
}

/// With `children = "contained"` the guard watches the broker as it watches the relay: a broker
/// that dies ends the program, and sandy fails with status 125 and says why.
#[test]
fn a_dead_broker_ends_a_contained_program() {
    let fixture = Fixture::new("egress-contained");
    let egress = free_port();
    let mut args = private_egress(&fixture, egress, "public");
    args.extend(["--children", "contained"].map(String::from));
    let (mut program, mut stdout) =
        start(&args, &[("pid", "-"), ("read-line", "-"), ("exit", "7")]);
    // sandy binds the listener and forks the broker twice, so until the broker has reported that
    // it is ready, sandy or the process between the two forks holds the listener too, and a look
    // then can find that process and kill it instead. The program starts only after the report.
    next_line(&mut stdout).assert_ok();
    let broker = relay_of(egress);
    assert_ne!(broker as u32, program.id(), "the listener is still sandy's");
    // SAFETY: kill has no memory arguments.
    assert_eq!(unsafe { libc::kill(broker, libc::SIGKILL) }, 0);
    let start = Instant::now();
    while program.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < WAIT,
            "sandy kept the program running after its broker was gone"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = program.wait_with_output().unwrap();
    let reason = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(reason.contains("the egress broker ended"), "{reason}");
}
