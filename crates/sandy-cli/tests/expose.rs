//! Exposed ports: a client outside the sandbox reaches a server inside it through the relay, and
//! the relay ends with the program.

mod common;

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

const WAIT: Duration = Duration::from_secs(20);

/// Two loopback ports that were free a moment ago. The first stays bound while the second is
/// chosen, so the two are never the same port, which two separate choices can be.
fn free_ports() -> (u16, u16) {
    let port = |listener: &TcpListener| listener.local_addr().unwrap().port();
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    (port(&first), port(&second))
}

/// Starts the probe in the sandbox; it accepts one connection on `inner` while sandy relays
/// `outer` to it.
fn start_server(fixture: &Fixture, inner: u16, outer: u16) -> Child {
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--expose".to_string(),
        format!("127.0.0.1:{outer}={inner}"),
    ]);
    let inner_address = format!("127.0.0.1:{inner}");
    let args = run_args(&sandbox_args, &[("tcp-accept", &inner_address)]);
    Command::new(sandy_path())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Connects to `outer` until the sandboxed server has accepted one connection. Early attempts can
/// reach the relay before the server listens; the relay then closes them.
fn connect_until_accepted(server: &mut Child, outer: u16) {
    let deadline = Instant::now() + WAIT;
    while server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the server never accepted");
        let _ = TcpStream::connect_timeout(
            &format!("127.0.0.1:{outer}").parse().unwrap(),
            Duration::from_millis(500),
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn exposed_port_reaches_the_program() {
    let fixture = Fixture::new("expose");
    let (inner, outer) = free_ports();
    let mut server = start_server(&fixture, inner, outer);
    connect_until_accepted(&mut server, outer);
    let output = server.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    lines[0].assert_ok();
}

#[test]
fn relay_ends_with_the_program() {
    let fixture = Fixture::new("expose-end");
    let (inner, outer) = free_ports();
    let mut server = start_server(&fixture, inner, outer);
    connect_until_accepted(&mut server, outer);
    server.wait().unwrap();
    let deadline = Instant::now() + WAIT;
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    while TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok() {
        assert!(
            Instant::now() < deadline,
            "the relay still accepts after the program ended"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn expose_without_ip_is_refused() {
    let fixture = Fixture::new("expose-noip");
    let mut sandbox_args = fixture.access_args();
    let (inner, outer) = free_ports();
    sandbox_args.extend(["--expose".to_string(), format!("127.0.0.1:{outer}={inner}")]);
    let output = sandy(run_args(&sandbox_args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(reason.contains("ip = \"all\""), "{reason}");
}

/// The program has to listen for the relay's connections, which `ip = "client"` denies, so sandy
/// refuses the policy and says what to use instead.
#[test]
fn expose_with_ip_client_is_refused() {
    let fixture = Fixture::new("expose-client");
    let mut sandbox_args = fixture.access_args();
    let (inner, outer) = free_ports();
    sandbox_args.extend([
        "--ip".to_string(),
        "client".to_string(),
        "--expose".to_string(),
        format!("127.0.0.1:{outer}={inner}"),
    ]);
    let output = sandy(run_args(&sandbox_args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(
        reason.contains("ip = \"client\" denies listening; use ip = \"all\""),
        "{reason}"
    );
    let mut check = vec!["check".to_string()];
    check.extend(platform_args());
    check.extend(sandbox_args);
    let output = sandy(&check);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

/// The relay holds many connections at once: each one needs two descriptors in the relay, more
/// than the soft limit of 256 that macOS gives a process, which the relay raises.
#[test]
fn an_exposed_port_relays_many_connections_at_once() {
    const CONNECTIONS: usize = 180;
    let fixture = Fixture::new("expose-many");
    // `free_port` only reports a port that was free a moment ago, so another process on the host
    // can take it before sandy binds it. That is the test's own race, not a refusal to enforce
    // the policy, so it picks another pair instead of failing. Anything else sandy says fails.
    let (server, outer) = loop {
        let (inner, outer) = free_ports();
        let mut sandbox_args = fixture.access_args();
        sandbox_args.extend([
            "--ip".to_string(),
            "all".to_string(),
            "--expose".to_string(),
            format!("127.0.0.1:{outer}={inner}"),
        ]);
        let serve = format!("127.0.0.1:{inner}\u{1f}{CONNECTIONS}");
        let mut server = Command::new(sandy_path())
            .args(run_args(&sandbox_args, &[("tcp-serve", &serve)]))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // sandy binds the relay's port before it starts anything else, so a port another
        // process took shows up at once; a run still alive after this has the port.
        let grace = Instant::now() + Duration::from_secs(2);
        while Instant::now() < grace && server.try_wait().unwrap().is_none() {
            std::thread::sleep(Duration::from_millis(50));
        }
        if server.try_wait().unwrap().is_none() {
            break (server, outer);
        }
        let output = server.wait_with_output().unwrap();
        let message = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(message.contains("Address already in use"), "{output:?}");
    };
    let address: SocketAddr = format!("127.0.0.1:{outer}").parse().unwrap();
    let deadline = Instant::now() + WAIT * 3;
    let mut clients = Vec::with_capacity(CONNECTIONS);
    // Every connection stays open, so all of them go through the relay at the same time. The
    // program counts every connection that reaches it and stops at CONNECTIONS, so a connection
    // the test gives up on but the program counted would take a place the test never gets back.
    // A connect without a timeout therefore either hands over the connection or made none, and a
    // connection the relay accepted is waited for. Only a connection the relay closed without a
    // greeting is retried, and only before the first greeting: the relay closes one when it
    // cannot reach the program, which is before the program listens, so the program never saw
    // it.
    while clients.len() < CONNECTIONS && Instant::now() < deadline {
        // Nothing listens until sandy binds the port, and a pending connect completes then.
        let Ok(mut stream) = TcpStream::connect(address) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        // Longer than the relay's own connect timeout, so a connection that waits for the
        // program to listen is not given up on.
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut greeting = [0u8; 3];
        match stream.read_exact(&mut greeting) {
            Ok(()) => {
                assert_eq!(&greeting, b"hi\n", "the relay delivered other bytes");
                clients.push(stream);
            }
            Err(error) => {
                assert!(
                    clients.is_empty(),
                    "the relay closed connection {} of {CONNECTIONS} without a greeting: {error}",
                    clients.len() + 1
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    let greeted = clients.len();
    let output = server.wait_with_output().unwrap();
    assert_eq!(greeted, CONNECTIONS, "{output:?}");
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();
}
