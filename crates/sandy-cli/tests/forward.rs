//! Forwarded ports: the program reaches a loopback service outside the sandbox through the relay.

mod common;

use std::io::Read;
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
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

/// A loopback service outside the sandbox. The thread reports whether a connection arrived
/// before the deadline.
fn outside_service() -> (String, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let accepted = thread::spawn(move || {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if listener.accept().is_ok() {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    });
    (address, accepted)
}

#[test]
fn forwarded_port_reaches_the_outside_service() {
    let fixture = Fixture::new("forward");
    let (service, accepted) = outside_service();
    let inner = free_port();
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}={service}"),
    ]);
    let lines = probe_inside(&args, &[("tcp-connect", &format!("127.0.0.1:{inner}"))]);
    lines[0].assert_ok();
    assert!(
        accepted.join().unwrap(),
        "the outside service saw no connection"
    );
}

#[test]
fn forward_without_ip_is_refused() {
    let fixture = Fixture::new("forward-noip");
    let mut args = fixture.access_args();
    args.extend([
        "--forward".to_string(),
        format!("{}=127.0.0.1:{}", free_port(), free_port()),
    ]);
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}

/// A program that writes more than the target reads in time, and exits. When the one second of
/// rule 5 runs out, the relay ends the connection with a reset: the target gets every byte or
/// sees the cut, but never a normal end after part of the stream.
#[test]
fn a_connection_cut_when_the_relay_ends_is_reset() {
    let fixture = Fixture::new("forward-cut");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let service = listener.local_addr().unwrap().to_string();
    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Busy: it reads only after the relay has given up.
        thread::sleep(Duration::from_secs(3));
        let mut received = Vec::new();
        let complete = stream.read_to_end(&mut received).is_ok();
        (received.len(), complete)
    });
    let inner = free_port();
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}={service}"),
    ]);
    let bytes = 4_000_000;
    let send = format!("127.0.0.1:{inner}\u{1f}{bytes}");
    probe_inside(&args, &[("tcp-send-many", &send)])[0].assert_ok();
    let (received, normal_end) = target.join().unwrap();
    assert!(
        !normal_end || received == bytes,
        "the target saw a normal end after {received} of {bytes} bytes"
    );
}
