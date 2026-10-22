//! Exposed ports: a client outside the sandbox reaches a server inside it through the relay, and
//! the relay ends with the program.

mod common;

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

const WAIT: Duration = Duration::from_secs(20);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let (inner, outer) = (free_port(), free_port());
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
    let (inner, outer) = (free_port(), free_port());
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
    sandbox_args.extend([
        "--expose".to_string(),
        format!("127.0.0.1:{}={}", free_port(), free_port()),
    ]);
    let output = sandy(run_args(&sandbox_args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
