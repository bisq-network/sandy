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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::unix::live_members;
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
    // The control frees the occupied port, and `free_port` only reports a port that was free a
    // moment ago, so another process on the host can take either before sandy binds them. That
    // is the test's own race, not a refusal to enforce the policy, so it picks another pair
    // instead of failing. Anything else sandy says fails.
    for _ in 0..10 {
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

        // Control: with the address free, the identical run starts the program and produces
        // output.
        drop(occupied);
        let output = Command::new(sandy_path())
            .args(run_args(&sandbox_args, &[("env", "PATH")]))
            .output()
            .unwrap();
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("Address already in use")
        {
            continue;
        }
        assert!(
            output.status.success(),
            "with a free listen address the run must start: {output:?}"
        );
        assert!(
            !output.stdout.is_empty(),
            "the control run produced no probe output: {output:?}"
        );
        return;
    }
    panic!("another process took the control's ports ten times in a row");
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

/// The watchdog exists only for `signals = "any"`. With `signals = "isolated"` the program
/// cannot stop its relay, so a timer could only kill a healthy relay that the host did not run
/// for two seconds, and with `children = "contained"` that ends the program with status 125. The
/// test stands in for such a host: it stops the relay from outside the sandbox for longer than
/// the watchdog's period and continues it. The relay must still serve and the program must keep
/// running. Control: the same stop under `signals = "any"` still ends the relay.
#[cfg(target_os = "linux")]
#[test]
fn only_signals_any_arms_the_relay_watchdog() {
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    service.set_nonblocking(true).unwrap();
    let to = service.local_addr().unwrap();
    let forward = |inner: u16, more: &[&str]| -> Vec<String> {
        ["--ip", "all"]
            .iter()
            .chain(more)
            .map(|arg| arg.to_string())
            .chain(["--forward".to_string(), format!("{inner}={to}")])
            .collect()
    };

    let inner = free_port();
    let isolated = forward(inner, &["--children", "contained", "--signals", "isolated"]);
    // The program runs until the test sends it a line, then exits with its own status.
    let mut program = Command::new(sandy_path())
        .args(run_args(&isolated, &[("read-line", "-"), ("exit", "7")]))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let relay = relay_of(inner, &mut program);
    assert!(
        relayed(inner, &service),
        "the forward port did not serve before the stop"
    );
    freeze(relay, WATCHDOG_PERIOD * 3 / 2);
    assert!(
        is_running(relay),
        "the relay did not survive a stop under isolated signals"
    );
    assert!(
        program.try_wait().unwrap().is_none(),
        "the contained program ended while its relay was stopped"
    );
    assert!(
        relayed(inner, &service),
        "the forward port did not serve after the relay was continued"
    );
    writeln!(program.stdin.take().unwrap(), "end").unwrap();
    let output = program.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "the program did not end on its own: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let inner = free_port();
    let mut program = Command::new(sandy_path())
        .args(run_args(&forward(inner, &[]), &[("sleep", "600000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let relay = relay_of(inner, &mut program);
    assert!(
        relayed(inner, &service),
        "the forward port did not serve before the stop"
    );
    freeze(relay, WATCHDOG_PERIOD * 3 / 2);
    let gone = ends_soon(relay, Duration::from_secs(5));
    let _ = program.kill();
    let _ = program.wait();
    if !gone {
        kill_process(relay);
    }
    assert!(
        gone,
        "the watchdog did not end a stopped relay under signals = \"any\""
    );
}

/// The Linux relay's `WATCHDOG`.
#[cfg(target_os = "linux")]
const WATCHDOG_PERIOD: Duration = Duration::from_secs(2);

/// Stops process `pid` for `period` and continues it.
#[cfg(target_os = "linux")]
fn freeze(pid: u32, period: Duration) {
    // SAFETY: kill takes a process ID and a signal.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    thread::sleep(period);
    // SAFETY: as above.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
}

/// Whether a connection to the forward port on 127.0.0.1:`port` reaches `service`, which must be
/// non-blocking.
#[cfg(target_os = "linux")]
fn relayed(port: u16, service: &TcpListener) -> bool {
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    let Ok(_client) = TcpStream::connect_timeout(&address, HALF_SECOND) else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if service.accept().is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

/// With `children = "contained"` sandy stays as the supervisor, and its guard watches the relay
/// in turn and ends the program's group when the relay is gone. Without that, the program keeps
/// running with its ports served by nothing, and any local user can bind the freed forward port
/// and receive what the program sends there. sandy reports the end as its own failure, status
/// 125. Control: a run whose program ends on its own while the relay lives exits with the
/// program's status.
#[test]
fn a_dead_relay_ends_a_contained_program() {
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let sandbox_args = contained_forward(inner, service_port);
    let address = format!("127.0.0.1:{inner}").parse().unwrap();
    // The program runs until the test sends it a line, then exits with its own status.
    let start = || {
        Command::new(sandy_path())
            .args(run_args(
                &sandbox_args,
                &[("read-line", "-"), ("exit", "7")],
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };

    // Control: the port serves while the program and its relay run, sandy keeps the program
    // while the relay lives, and the program's own end is the end of the run.
    let mut program = start();
    relay_of(inner, &mut program);
    assert!(
        TcpStream::connect_timeout(&address, HALF_SECOND).is_ok(),
        "the forward port did not serve while the relay ran"
    );
    thread::sleep(Duration::from_secs(1));
    assert!(
        program.try_wait().unwrap().is_none(),
        "sandy ended the program while its relay was alive"
    );
    writeln!(program.stdin.take().unwrap(), "end").unwrap();
    let output = program.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "the program's own end was not the end of the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut program = start();
    let relay = relay_of(inner, &mut program);
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
    assert_eq!(
        output.status.code(),
        Some(EXIT_FAILURE),
        "sandy did not fail although its relay was gone: {output:?}"
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

/// The guard ends the group when the relay ends, so the freed forward port does not wait for
/// sandy: while sandy is stopped, a dead relay still ends the program at once, and sandy reports
/// the failure when it continues. Control: stopping sandy alone ends nothing.
#[test]
fn a_dead_relay_ends_a_contained_program_while_sandy_is_stopped() {
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let (mut sandy, program) = start_contained(inner, service_port);
    let group = group_of(program);
    let relay = relay_of(inner, &mut sandy);
    send(sandy.id(), libc::SIGSTOP);
    thread::sleep(HALF_SECOND);
    let alive = !live_members(group).is_empty();
    kill_process(relay);
    let ended = within(END_TIMEOUT, || live_members(group).is_empty());
    send(sandy.id(), libc::SIGCONT);
    let output = sandy.wait_with_output().unwrap();
    let _ = stop_service.send(());
    assert!(alive, "control: stopping sandy ended the program");
    assert!(
        ended,
        "the program outlived its relay while sandy was stopped"
    );
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

/// When the guard wakes, it reports that the relay ended first only when the program has not
/// ended too. A relay that ended in the same look as the program is the normal end of a run, not
/// a failure. Stopping the guard makes that look certain: the program exits and the relay is
/// killed while the guard is stopped, and the test waits for both ends as the guard learns them,
/// so the guard finds both when its poll starts again after the stop. sandy is stopped as well,
/// so that it cannot end the run before the guard has decided.
///
/// Linux only. On macOS a stopped process still finishes the kevent call that an event woke and
/// stops only on its way back to user space (seen on macOS 26.5), so the guard takes the
/// program's end alone, and no stop from outside can give it both ends in one look.
#[cfg(target_os = "linux")]
#[test]
fn a_relay_that_ends_with_the_program_is_the_normal_end_of_a_run() {
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let (service_port, stop_service) = holding_service();
    let inner = free_port();
    let (mut sandy, program) = start_contained(inner, service_port);
    let group = group_of(program);
    let guard = common::linux::guard_of(sandy.id(), program);
    let relay = relay_of(inner, &mut sandy);
    let (program_end, relay_end) = (pidfd(program), pidfd(relay));
    send(sandy.id(), libc::SIGSTOP);
    send(guard, libc::SIGSTOP);
    let both_stopped = within(END_TIMEOUT, || stopped(sandy.id()) && stopped(guard));
    writeln!(sandy.stdin.take().unwrap(), "end").unwrap();
    let program_exited = ends_within(&program_end, END_TIMEOUT);
    kill_process(relay);
    let relay_exited = ends_within(&relay_end, END_TIMEOUT);
    send(guard, libc::SIGCONT);
    let group_ended = within(END_TIMEOUT, || live_members(group).is_empty());
    send(sandy.id(), libc::SIGCONT);
    let output = sandy.wait_with_output().unwrap();
    let _ = stop_service.send(());
    assert!(both_stopped, "sandy and the guard did not stop");
    assert!(program_exited, "the program did not exit");
    assert!(relay_exited, "the relay did not end");
    assert!(group_ended, "the guard did not end the group");
    assert_eq!(
        output.status.code(),
        Some(7),
        "a relay that ended with the program failed the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Options for a contained program with a forward port from `inner` to 127.0.0.1:`service`.
fn contained_forward(inner: u16, service: u16) -> Vec<String> {
    [
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
    .chain([format!("{inner}=127.0.0.1:{service}")])
    .collect()
}

/// Starts a contained program with a forward port from `inner` to 127.0.0.1:`service`. The
/// program reports its process ID, which this returns with sandy, and runs until the test sends
/// it a line; then it exits with status 7.
fn start_contained(inner: u16, service: u16) -> (std::process::Child, u32) {
    let actions = [("pid", "-"), ("read-line", "-"), ("exit", "7")];
    let mut sandy = Command::new(sandy_path())
        .args(run_args(&contained_forward(inner, service), &actions))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let program: u32 = parse_line(line.trim_end())
        .detail
        .parse()
        .unwrap_or_else(|_| panic!("the program did not report its process ID: {line}"));
    // In a PID namespace of its own the program reports its ID there.
    #[cfg(target_os = "linux")]
    let program = common::linux::outside_id(sandy.id(), program as libc::pid_t) as u32;
    // The program must not end on a closed pipe when it reports its next action.
    thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
    (sandy, program)
}

fn send(pid: u32, signal: libc::c_int) {
    // SAFETY: kill takes a process ID and a signal.
    unsafe { libc::kill(pid as libc::pid_t, signal) };
}

/// Whether `condition` holds within `timeout`.
fn within(timeout: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    true
}

/// The process group of process `pid`.
fn group_of(pid: u32) -> libc::pid_t {
    // SAFETY: getpgid takes a process ID.
    let group = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert!(group > 0, "process {pid} has no group");
    group
}

/// Whether process `pid` is stopped.
#[cfg(target_os = "linux")]
fn stopped(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // The state follows the name in parentheses.
    stat.rfind(')')
        .and_then(|end| stat.get(end + 2..end + 3))
        .is_some_and(|state| matches!(state, "T" | "t"))
}

/// A pidfd for process `pid`. It tells of the end of the process as it tells the guard.
#[cfg(target_os = "linux")]
fn pidfd(pid: u32) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    // SAFETY: pidfd_open takes a process ID and flags.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(fd >= 0, "cannot open a pidfd for process {pid}");
    // SAFETY: the descriptor is new and owned by nothing else.
    unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) }
}

/// Whether the process of `pidfd` ends within `timeout`.
#[cfg(target_os = "linux")]
fn ends_within(pidfd: &std::os::fd::OwnedFd, timeout: Duration) -> bool {
    use std::os::fd::AsRawFd;
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    unsafe { libc::poll(&mut poll, 1, timeout.as_millis() as libc::c_int) > 0 }
}

/// The relay of the sandbox that `program` runs: the one process that listens on
/// 127.0.0.1:`port`. Waits until it is there, and fails if the program ends first. sandy binds
/// the listener before it starts the relay, so until then sandy itself is that process.
fn relay_of(port: u16, program: &mut std::process::Child) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        if let Some(relay) = listening_process(port).filter(|&pid| pid != program.id()) {
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

/// The single process that listens on 127.0.0.1:`port`, found with lsof.
#[cfg(target_os = "macos")]
fn listening_process(port: u16) -> Option<u32> {
    let output = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            &format!("-iTCP@127.0.0.1:{port}"),
            "-sTCP:LISTEN",
            "-t",
        ])
        .output()
        .ok()?;
    let holders: Vec<u32> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
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
