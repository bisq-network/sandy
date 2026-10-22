//! Forwarded ports: the program reaches a loopback service outside the sandbox through the relay.

mod common;

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
