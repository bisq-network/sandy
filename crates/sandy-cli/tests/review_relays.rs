//! Security review of the port relays (`network.expose` and `network.forward`).
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
    // Set while the connection is surely open: macOS refuses socket options (EINVAL) once the
    // peer has reset the connection, and the relay may reset it before the read below.
    held.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

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

/// The relay must not hold sandy's standard error. A caller that reads sandy's output sees the
/// end of the program as the end of that output; a relay that kept the descriptor would hold the
/// pipe open for the whole drain, and for as long as it lives when it is stopped.
#[test]
fn the_relay_does_not_hold_standard_error() {
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let sandbox_args = [
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}=127.0.0.1:{service_port}"),
    ];
    let mut program = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("sleep", "3000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // One relayed connection that the service holds open, so the relay has something to drain
    // when the program ends.
    let held = connect_when_relayed(inner, &mut program);
    let mut stderr = program.stderr.take().unwrap();
    program.wait().unwrap();
    let ended = Instant::now();
    let mut output = Vec::new();
    stderr.read_to_end(&mut output).unwrap();
    let eof = ended.elapsed();
    drop(held);
    let _ = stop_service.send(());
    assert!(
        output.is_empty(),
        "sandy wrote to standard error: {}",
        String::from_utf8_lossy(&output)
    );
    assert!(
        eof < Duration::from_millis(500),
        "standard error reached its end only {eof:?} after the program ended, so the relay held it"
    );
}

/// A program with the default `signals = "any"` may send SIGSTOP to its relay, which no process
/// can block. The relay must still not outlive the program: while it is stopped the kernel
/// completes handshakes for its listeners, and once someone continues it, it would relay
/// connections that were made after the program ended (DESIGN.md, "Forwarded ports", rule 5).
///
/// Linux only. On macOS a stopped process cannot be woken by a timer of its own, so only
/// `signals = "isolated"` keeps the bound there (docs/macos.md).
#[cfg(target_os = "linux")]
#[test]
fn a_stopped_relay_ends_with_the_program() {
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let sandbox_args = [
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}=127.0.0.1:{service_port}"),
    ];
    // The program reads the relay's process ID from its standard input and stops it.
    let mut program = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("signal-stop", "-")]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let relay = relay_of(inner, &mut program);
    let address = format!("127.0.0.1:{inner}").parse().unwrap();
    // Control: the forward port serves while the program runs.
    assert!(
        TcpStream::connect_timeout(&address, HALF_SECOND).is_ok(),
        "the forward port did not serve before the stop"
    );

    let mut stdin = program.stdin.take().unwrap();
    writeln!(stdin, "{relay}").unwrap();
    drop(stdin);
    let mut stdout = program.stdout.take().unwrap();
    program.wait().unwrap();
    let mut report = String::new();
    stdout.read_to_string(&mut report).unwrap();
    assert!(
        report.contains("signal-stop\t-\tok"),
        "the program did not stop the relay: {report}"
    );

    // The stopped relay cannot see the end of the program, so its watchdog must end it.
    let deadline = Duration::from_secs(8);
    let gone = ends_soon(relay, deadline);
    let refused = TcpStream::connect_timeout(&address, HALF_SECOND).is_err();
    let _ = stop_service.send(());
    if !gone {
        // A relay that stays stopped would keep its port for as long as this host runs.
        kill_process(relay);
    }
    assert!(
        gone,
        "the stopped relay was still alive {deadline:?} after the program ended"
    );
    assert!(
        refused,
        "the stopped relay still held its port after it ended"
    );
}

/// With `children = "contained"` sandy stays as the supervisor, so it can watch the relay in
/// turn and end the program's group when the relay is gone. Without that, the program keeps
/// running with its ports served by nothing, and a relay that was only frozen can serve a
/// connection made after the program ended (`relay::was_stopped`). Killing the relay is the
/// mechanism, not a race: the scenario it protects against cannot be tested without one.
///
/// Linux only: sandy watches the relay in the Linux `contain` supervisor.
#[cfg(target_os = "linux")]
#[test]
fn a_dead_relay_ends_a_contained_program() {
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let sandbox_args = [
        "--ip",
        "all",
        "--children",
        "contained",
        "--signals",
        "isolated",
        "--forward",
    ]
    .map(String::from)
    .into_iter()
    .chain([format!("{inner}=127.0.0.1:{service_port}")])
    .collect::<Vec<String>>();
    let mut program = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("sleep", "600000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let relay = relay_of(inner, &mut program);
    let address = format!("127.0.0.1:{inner}").parse().unwrap();
    // Control: the port serves while the program and its relay run.
    assert!(
        TcpStream::connect_timeout(&address, HALF_SECOND).is_ok(),
        "the forward port did not serve before the relay was killed"
    );

    kill_process(relay);
    let deadline = Instant::now() + Duration::from_secs(20);
    while program.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "sandy kept the program running after its relay was gone"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let output = program.wait_with_output().unwrap();
    let _ = stop_service.send(());
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "sandy reported success although its relay was gone: {output:?}"
    );
    assert!(
        reason.contains("relay"),
        "sandy did not say that the relay ended: {reason}"
    );
    // The program went with it, and so did the port it was served on.
    assert!(
        TcpStream::connect_timeout(&address, HALF_SECOND).is_err(),
        "the forward port still answers after the run ended"
    );
}

/// The relay of the sandbox that `program` runs: the one process that listens on
/// 127.0.0.1:`port`. Waits until it is there, and fails if the program ends first.
#[cfg(target_os = "linux")]
fn relay_of(port: u16, program: &mut std::process::Child) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        if let Some(relay) = listening_process(port) {
            return relay;
        }
        assert!(Instant::now() < deadline, "no relay listened on {port}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The single process that listens on 127.0.0.1:`port`. /proc/net/tcp shows the local address in
/// hexadecimal (127.0.0.1 is 0100007F on little-endian hosts) and LISTEN as 0A; the socket's
/// inode names the descriptor that the holding process has open.
#[cfg(target_os = "linux")]
fn listening_process(port: u16) -> Option<u32> {
    let local = format!("0100007F:{port:04X}");
    let table = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let listening = fields.get(1) == Some(&local.as_str()) && fields.get(3) == Some(&"0A");
        listening.then(|| fields.get(9).map(|inode| inode.to_string()))?
    })?;
    let socket = format!("socket:[{inode}]");
    let holders: Vec<u32> = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let mut descriptors = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
            let holds = descriptors.any(|fd| {
                fd.and_then(|fd| std::fs::read_link(fd.path()))
                    .is_ok_and(|link| link.as_os_str() == socket.as_str())
            });
            holds.then_some(pid)
        })
        .collect();
    match holders[..] {
        [relay] => Some(relay),
        _ => None,
    }
}

/// Connects to the relay's port on 127.0.0.1 once it listens, and waits until the relay has
/// taken the connection. Fails if the program ends first.
fn connect_when_relayed(port: u16, program: &mut std::process::Child) -> TcpStream {
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        if let Ok(stream) = TcpStream::connect_timeout(&address, HALF_SECOND) {
            // The relay accepts in its poll loop and then connects to the other side.
            thread::sleep(Duration::from_millis(300));
            return stream;
        }
        assert!(Instant::now() < deadline, "the relay never listened");
        thread::sleep(Duration::from_millis(50));
    }
}

const HALF_SECOND: Duration = Duration::from_millis(500);
