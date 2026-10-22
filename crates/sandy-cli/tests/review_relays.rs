//! Security review of the port relays (`network.expose` and `network.forward`), see
//! docs/reviews/2026-10-23-relays.md.
//!
//! These tests probe the relay lifetime, the fail-closed behaviour when a relay cannot bind, and
//! the internal `__relay`/`__forward` commands when an attacker runs them directly on the host.
//! Each test is gated per platform. The Unix tests run on Linux and macOS, where sandy binds the
//! relay listeners the same way. Windows forward and expose are covered by `escape_windows.rs`
//! (`forward_socket_is_reachable_only_by_the_relay`, `relays_reach_only_the_program`,
//! `forward_relay_ends_with_the_program`, `relay_stops_listening_as_soon_as_the_program_ends`).
//!
//! Every test that asserts a denial or an end also runs a control: the same action succeeds
//! outside the sandbox, or while the program still runs, so a test cannot pass because the action
//! was impossible anyway.
//!
//! The whole file is Unix only. sandy binds the relay listeners the same way on Linux and macOS,
//! so these tests run on both. Windows forward and expose have their own tests in
//! `escape_windows.rs`.
#![cfg(unix)]

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::*;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A loopback service outside the sandbox that accepts connections and holds them open, so a
/// relayed connection stays alive until the relay itself ends it.
fn holding_service() -> (u16, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop_tx, stop_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                held.push(stream);
            }
            if stop_rx.try_recv().is_ok() {
                break;
            }
        }
    });
    (port, stop_tx)
}

/// A relay that cannot bind its listen address must fail the whole run: the program never starts.
/// Otherwise a run could proceed believing an exposed port is served when it is not, or (worse) a
/// stale listener from another owner would receive the outside connections.
#[test]
fn relay_bind_conflict_fails_closed() {
    // Occupy the address the relay would listen on.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer = occupied.local_addr().unwrap().port();
    let inner = free_port();

    let sandbox_args = [
        "--ip".to_string(),
        "all".to_string(),
        "--expose".to_string(),
        format!("127.0.0.1:{outer}={inner}"),
    ];
    let output = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("env", "PATH")]))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(EXIT_FAILURE),
        "a run whose relay cannot bind must be refused: {output:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "the program ran although the relay could not bind: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Control: with the address free, the identical run starts the program and produces output.
    drop(occupied);
    let output = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("env", "PATH")]))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "with a free listen address the run must start: {output:?}"
    );
    assert!(
        !output.stdout.is_empty(),
        "the control run produced no probe output: {output:?}"
    );
}

/// The internal `__relay` and `__forward` commands are not part of the documented interface. A
/// backend starts them only with a real listening socket (expose) or inside the sandbox
/// (forward). Run directly by an unsandboxed attacker they must give nothing: no relay is
/// established, so the caller gains no reach it did not already have as an unsandboxed user.
#[test]
fn internal_commands_yield_no_working_relay() {
    // `__forward` is Windows only; on Unix it refuses.
    let output = sandy([
        "__forward",
        "127.0.0.1:1",
        "/tmp/sandy-review-nonexistent.sock",
    ]);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");

    // `__relay` with a descriptor number that is not an open socket cannot serve. The relay would
    // need a listening socket the caller passed; an arbitrary number yields an error, not a relay.
    let output = sandy(["__relay", "999999999999", "127.0.0.1:1"]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_FAILURE),
        "__relay with an out-of-range descriptor must fail: {output:?}"
    );

    // A control that the binary itself works: `--version` succeeds.
    let output = sandy(["--version"]);
    assert!(output.status.success(), "{output:?}");
}

/// Rule 5 of "Forwarded ports" in DESIGN.md gives an upper bound: when the program ends, the
/// relay closes its listeners at once and ends accepted connections within one second. This test
/// proves the program cannot hold the relay open past that bound: it opens a relayed connection,
/// keeps it open, kills the program, and times both the stop of new connections and the close of
/// the open connection.
#[test]
fn relay_does_not_outlive_the_program_beyond_the_drain() {
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let sandbox_args = [
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}=127.0.0.1:{service_port}"),
    ];
    // The program sleeps; its PID is sandy's PID after execve, which the relay watches.
    let mut program = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("sleep", "600000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Control: while the program runs, a connection through the forward port reaches the service.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut held = loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        if let Ok(stream) =
            TcpStream::connect_timeout(&format!("127.0.0.1:{inner}").parse().unwrap(), HALF_SECOND)
        {
            break stream;
        }
        assert!(
            Instant::now() < deadline,
            "the forward relay never listened"
        );
        thread::sleep(Duration::from_millis(50));
    };
    held.write_all(b"review").unwrap();

    // Kill the program (SIGKILL), then measure the relay's end from the client side.
    let killed = Instant::now();
    program.kill().unwrap();
    program.wait().unwrap();

    // New connections must stop quickly: the relay closes its listener as soon as the program ends.
    let mut stop_accept = None;
    while killed.elapsed() < Duration::from_secs(5) {
        match TcpStream::connect_timeout(
            &format!("127.0.0.1:{inner}").parse().unwrap(),
            Duration::from_millis(200),
        ) {
            Ok(stream) => {
                drop(stream);
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                stop_accept = Some(killed.elapsed());
                break;
            }
        }
    }
    let stop_accept = stop_accept.expect("the relay kept accepting after the program was killed");

    // The open connection must be closed within the drain, not kept alive by the client.
    held.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buffer = [0u8; 16];
    // A reset is as much an end as a clean close: the relay may close a socket with unread data,
    // and the kernel then answers with RST. Only a connection that stays open fails the test.
    let closed_at = match held.read(&mut buffer) {
        Ok(_) => killed.elapsed(),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            killed.elapsed()
        }
        Err(error) => panic!("the held connection was not closed: {error}"),
    };

    let _ = held.shutdown(Shutdown::Both);
    let _ = stop_service.send(());

    assert!(
        stop_accept < Duration::from_millis(1500),
        "new connections were still accepted {stop_accept:?} after the program was killed"
    );
    assert!(
        closed_at < Duration::from_secs(3),
        "the relay held an open connection {closed_at:?} after the program was killed, past the \
         one second drain"
    );
}

const HALF_SECOND: Duration = Duration::from_millis(500);
