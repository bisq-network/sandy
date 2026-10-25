//! Forwarded ports: the program reaches a loopback service outside the sandbox through the relay.

mod common;

use std::io::Read;
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::*;

const WAIT: Duration = Duration::from_secs(20);
#[cfg(target_os = "linux")]
const HALF_SECOND: Duration = Duration::from_millis(500);

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

/// The program connects to the relay, which `ip = "client"` allows as well as `ip = "all"`.
#[test]
fn forwarded_port_reaches_the_outside_service() {
    let fixture = Fixture::new("forward");
    for ip in ["all", "client"] {
        let (service, accepted) = outside_service();
        let inner = free_port();
        let mut args = fixture.access_args();
        args.extend([
            "--ip".to_string(),
            ip.to_string(),
            "--forward".to_string(),
            format!("{inner}={service}"),
        ]);
        // The program connects and exits without sending anything. The kernel keeps no owner
        // for the socket it closed, and the relay serves the connection anyway (rule 6 of
        // "Forwarded ports").
        let lines = probe_inside(&args, &[("tcp-connect", &format!("127.0.0.1:{inner}"))]);
        lines[0].assert_ok();
        assert!(
            accepted.join().unwrap(),
            "the outside service saw no connection with ip = {ip:?}"
        );
    }
}

#[test]
fn forward_without_ip_is_refused() {
    let fixture = Fixture::new("forward-noip");
    let mut args = fixture.access_args();
    // Two different ports: the same port twice is refused for another reason.
    let port = free_port();
    args.extend([
        "--forward".to_string(),
        format!("{port}=127.0.0.1:{}", port ^ 1),
    ]);
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(reason.contains("ip = \"client\" or \"all\""), "{reason}");
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

/// A forward listener is an ordinary loopback port, so any local user can connect to it. Only
/// the program should: the relay reaches the service outside as sandy's user, so a connection of
/// another user would pass an owner rule of a packet filter or a peer credential check in that
/// service. On Linux the relay asks the kernel who owns the other end and closes a connection
/// the kernel names as another user's. The one it cannot name is a peer that closed its socket
/// first, which it serves (docs/linux.md, "Exposed and forwarded ports"); a peer that holds its
/// connection open, which is what reading an answer takes, is always named. macOS has no such
/// check (docs/macos.md), so this test is Linux only.
#[cfg(target_os = "linux")]
#[test]
fn a_forward_port_refuses_other_users() {
    let fixture = Fixture::new("forward-other-user");
    let probe = fixture.copy_probe("bin");
    let Some(other_user) = other_user(&probe) else {
        skip(
            "other-user",
            "cannot run a program as another user (no `sudo -n -u nobody`, and no user namespace \
             with sub-user IDs)",
        );
        return;
    };
    let as_other_user = |actions: &[(&str, &str)]| {
        std::process::Command::new(&other_user[0])
            .args(&other_user[1..])
            .args(probe_args(actions))
            .output()
            .unwrap()
    };

    let (service, accepted) = counting_service();
    let inner = free_port();
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}={service}"),
    ]);
    let mut program = std::process::Command::new(sandy_path())
        .args(run_args(&args, &[("sleep", "30000")]))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let address: std::net::SocketAddr = format!("127.0.0.1:{inner}").parse().unwrap();

    // Control: a connection of sandy's own user reaches the service.
    let deadline = Instant::now() + WAIT;
    let held = loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&address, HALF_SECOND) {
            break stream;
        }
        assert!(
            Instant::now() < deadline,
            "the forward relay never listened"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert!(
        waits_for(&accepted, 1),
        "the control connection was not relayed"
    );

    // The other user's connection reaches the port, because the kernel completes the handshake,
    // but it must never reach the service. It is held open until the relay closes it: that is
    // what any use of the service needs, and the kernel names the owner of a socket that exists.
    let port = format!("127.0.0.1:{inner}");
    let output = as_other_user(&[("tcp-connect-read", &port)]);
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();
    thread::sleep(Duration::from_secs(1));
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::Acquire),
        1,
        "the service was reached by another user"
    );

    // The relay still serves sandy's own user after it refused the other one.
    let second = std::net::TcpStream::connect_timeout(&address, HALF_SECOND).unwrap();
    assert!(waits_for(&accepted, 2), "the relay stopped serving");

    drop(held);
    drop(second);
    kill_process(program.id());
    let _ = program.wait();
}

/// A program with a dual-stack IPv6 socket, which Java uses by default, reaches an IPv4 forward
/// port through the IPv4-mapped address. The kernel then names the owner of the other end in
/// IPv6 form, and the relay must still recognize the connection as the one it asked about. The
/// plain IPv4 connection first is the control.
#[cfg(target_os = "linux")]
#[test]
fn a_forward_port_serves_a_dual_stack_socket() {
    use std::io::Write;

    let fixture = Fixture::new("forward-dual-stack");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let service = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.write_all(b"hi");
        }
    });
    let inner = free_port();
    let mut args = fixture.access_args();
    args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{inner}={service}"),
    ]);
    // The program holds the connection until the service's answer has come, so the kernel
    // names its owner: a peer that closed first is served whatever the check says.
    let lines = probe_inside(
        &args,
        &[
            ("tcp-connect-read", &format!("127.0.0.1:{inner}")),
            ("tcp-connect-read", &format!("[::ffff:127.0.0.1]:{inner}")),
        ],
    );
    assert_eq!(lines[0].detail, "2 bytes", "{lines:?}");
    assert_eq!(lines[1].detail, "2 bytes", "{lines:?}");
}

/// How to run `probe` as a local user that is not sandy's: with `sudo -n -u nobody`, or else in a
/// user namespace that maps this account's sub-user IDs, where the probe's socket belongs to one
/// of them. `None` when neither works here. Returns the command and its arguments; the action and
/// its target follow.
#[cfg(target_os = "linux")]
fn other_user(probe: &str) -> Option<Vec<String>> {
    let ways = [
        vec!["sudo", "-n", "-u", "nobody", probe],
        vec![
            "unshare",
            "-U",
            "--map-root-user",
            "--map-auto",
            "--",
            "setpriv",
            "--reuid=1",
            "--regid=1",
            "--clear-groups",
            probe,
        ],
    ];
    ways.into_iter()
        .map(|way| way.into_iter().map(String::from).collect::<Vec<String>>())
        // The other user must be able to run the probe at all, or the test would pass because
        // nothing ever connected.
        .find(|way| {
            std::process::Command::new(&way[0])
                .args(&way[1..])
                .args(["env", "PATH"])
                .output()
                .is_ok_and(|output| output.status.success())
        })
}

/// A loopback service outside the sandbox that counts the connections it accepted and holds them
/// open.
#[cfg(target_os = "linux")]
fn counting_service() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::Ordering;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&accepted);
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::AcqRel);
            held.push(stream);
        }
    });
    (address, accepted)
}

/// Whether the service accepted `count` connections before the deadline.
#[cfg(target_os = "linux")]
fn waits_for(accepted: &std::sync::atomic::AtomicUsize, count: usize) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if accepted.load(std::sync::atomic::Ordering::Acquire) >= count {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}
