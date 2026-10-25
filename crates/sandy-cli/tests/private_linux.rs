//! `ip = "private"` on Linux: the program runs in a user and network namespace of its own, with
//! only `lo`, and reaches the host only through the relays (docs/linux.md, "Private network").
//! Every denial has a control: the same action with `ip = "all"`, which reaches the host.
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::*;

const WAIT: Duration = Duration::from_secs(20);

/// What `check` exits with when only `sandy setup` is missing.
const EXIT_NEEDS_SETUP: i32 = 2;
const EXIT_NOT_ENFORCEABLE: i32 = 1;

/// The plan line of the requirement.
const PRIVATE_LINE: &str = "IP networking limited to the sandbox's own loopback";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn private() -> Vec<String> {
    args(&["--ip", "private"])
}

fn all() -> Vec<String> {
    args(&["--ip", "all"])
}

/// Whether this host gives sandy the namespaces, as `check` says; records a skip when not. Ubuntu
/// 23.10 and newer refuse them to an unconfined sandy until `sandy setup` installs a profile.
fn private_network_works() -> bool {
    let output = sandy(["check", "--ip", "private"]);
    if output.status.success() {
        return true;
    }
    skip(
        "user-namespaces",
        &format!(
            "this host gives sandy no user and network namespace: {}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| line.contains(PRIVATE_LINE))
                .unwrap_or("check failed")
        ),
    );
    false
}

/// The ways a program can be started that enter the namespaces in different processes: the exec
/// model, and with `children = "contained"` a forked child, which needs signal isolation and so
/// Landlock ABI 6. Records a skip for the second where it is missing.
fn launch_modes() -> Vec<Vec<String>> {
    let mut modes = vec![Vec::new()];
    if common::linux::landlock_abi() >= 6 {
        modes.push(args(&["--children", "contained", "--signals", "isolated"]));
    } else {
        skip(
            "landlock-abi-6",
            "children = contained needs signal isolation, which needs Landlock ABI 6",
        );
    }
    modes
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The address the host would send from to reach other machines, which is one of its own
/// non-loopback addresses. A UDP connect only looks up the route and sends nothing.
fn host_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// A loopback service outside the sandbox that answers every connection with "hi", counts it
/// and closes it.
fn answering_service() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::AcqRel);
            let _ = stream.write_all(b"hi");
        }
    });
    (address, accepted)
}

fn spawn_sandy(sandbox_args: &[String], actions: &[(&str, &str)]) -> Child {
    Command::new(sandy_path())
        .args(run_args(sandbox_args, actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The program cannot reach a TCP or UDP listener on the host's loopback, IPv4 or IPv6. It has a
/// loopback of its own, so the connect is refused there instead of being denied.
#[test]
fn the_program_reaches_no_listener_on_the_hosts_loopback() {
    if !private_network_works() {
        return;
    }
    let mut listeners = vec![TcpListener::bind("127.0.0.1:0").unwrap()];
    match TcpListener::bind("[::1]:0") {
        Ok(listener) => listeners.push(listener),
        Err(error) => skip("ipv6-loopback", &format!("cannot listen on ::1: {error}")),
    }
    for listener in &listeners {
        let target = listener.local_addr().unwrap().to_string();
        let actions = [("tcp-connect", target.as_str())];
        probe_inside(&all(), &actions)[0].assert_ok();
        let line = &probe_inside(&private(), &actions)[0];
        line.assert_blocked();
        assert!(line.detail.contains("refused"), "{line:?}");
    }

    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let target = receiver.local_addr().unwrap().to_string();
    let received = |sandbox_args: &[String]| {
        // The send succeeds either way: a datagram has no answer to wait for.
        probe_inside(sandbox_args, &[("udp-send", &target)])[0].assert_ok();
        receiver.recv_from(&mut [0; 16]).is_ok()
    };
    assert!(received(&all()), "the control datagram did not arrive");
    assert!(
        !received(&private()),
        "a datagram reached the host's loopback"
    );
}

/// Nor a listener on an address of the host's own network interfaces, which `ip = "all"`
/// reaches over the host's loopback route.
#[test]
fn the_program_reaches_no_other_address_of_the_host() {
    if !private_network_works() {
        return;
    }
    let Some(address) = host_address() else {
        return skip(
            "host-address",
            "this host has no route to other machines, so no address of its own to try",
        );
    };
    let listener = TcpListener::bind(SocketAddr::new(address, 0)).unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let actions = [("tcp-connect", target.as_str())];
    probe_inside(&all(), &actions)[0].assert_ok();
    probe_inside(&private(), &actions)[0].assert_blocked();
}

/// Abstract Unix socket names belong to a network namespace, so a listener of the host is out of
/// reach also with `unix_sockets = "all"`, which lifts the Landlock scope that otherwise denies it
/// (`abstract_unix_socket_is_unreachable` in escape_linux.rs).
#[test]
fn the_program_reaches_no_abstract_socket_of_the_host() {
    if !private_network_works() {
        return;
    }
    let name = format!("sandy-private-{}", std::process::id());
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let _listener = UnixListener::bind_addr(&address).unwrap();
    let actions = [("unix-connect-abstract", name.as_str())];
    probe_inside(&args(&["--unix-sockets", "all"]), &actions)[0].assert_ok();
    let line = &probe_inside(
        &args(&["--ip", "private", "--unix-sockets", "all"]),
        &actions,
    )[0];
    line.assert_blocked();
    assert!(line.detail.contains("refused"), "{line:?}");
}

/// No datagram that the host sends to the program's port arrives: the port is on the program's
/// own loopback, which only the program's processes reach.
#[test]
fn datagrams_from_outside_do_not_reach_the_program() {
    if !private_network_works() {
        return;
    }
    inbound_udp(Some(&all())).assert_ok();
    inbound_udp(Some(&private())).assert_blocked();
}

/// The program may listen, and is reached through an exposed port, but not directly at its own
/// port, which is on its own loopback. The same with `contained`, where a forked child enters the
/// namespace, and with `--explain`.
#[test]
fn an_exposed_port_reaches_the_program_and_its_own_port_stays_inside() {
    if !private_network_works() {
        return;
    }
    let mut modes = launch_modes();
    modes.push(args(&["--explain"]));
    for mode in modes {
        let inner = free_port();
        let outer = free_port();
        let mut sandbox_args = private();
        sandbox_args.extend(mode.iter().cloned());
        sandbox_args.extend(args(&["--expose", &format!("127.0.0.1:{outer}={inner}")]));
        let inner_address = format!("127.0.0.1:{inner}");
        let mut server = spawn_sandy(&sandbox_args, &[("tcp-accept", &inner_address)]);
        let outer_address: SocketAddr = format!("127.0.0.1:{outer}").parse().unwrap();
        let inner_socket: SocketAddr = inner_address.parse().unwrap();
        let deadline = Instant::now() + WAIT;
        let mut reached_directly = false;
        while server.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "{mode:?}: the server never accepted"
            );
            reached_directly |=
                TcpStream::connect_timeout(&inner_socket, Duration::from_millis(200)).is_ok();
            let _ = TcpStream::connect_timeout(&outer_address, Duration::from_millis(500));
            thread::sleep(Duration::from_millis(100));
        }
        let output = server.wait_with_output().unwrap();
        assert!(output.status.success(), "{mode:?}: {output:?}");
        let lines = parse(&output);
        assert_eq!(lines.len(), 1, "{mode:?}: {output:?}");
        lines[0].assert_ok();
        assert!(
            !reached_directly,
            "{mode:?}: the program's own port took a connection"
        );
    }
}

/// The children of process `parent` that lead a session of their own, from `/proc/PID/stat`
/// (fields 4 and 6, counted after the name in parentheses).
fn session_leading_children(parent: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let fields: Vec<&str> = stat[stat.rfind(')')? + 2..].split(' ').collect();
            let (ppid, session): (u32, u32) =
                (fields.get(1)?.parse().ok()?, fields.get(3)?.parse().ok()?);
            (ppid == parent && session == pid).then_some(pid)
        })
        .collect()
}

/// With `children = "contained"` the child that enters the namespace starts the socket factory
/// of the exposed ports, so the guard, which sandy forked before, cannot watch it. The relay
/// watches it instead and ends when it ends, and the guard then ends the program, as for a dead
/// relay (review_relays.rs). The factory is re-parented to sandy, the child subreaper, and is
/// the one child of sandy in a session of its own. Control: while the factory lives, the program
/// runs on.
#[test]
fn a_dead_socket_factory_ends_a_contained_program() {
    if !private_network_works() {
        return;
    }
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let mut sandbox_args = private();
    sandbox_args.extend(args(&["--children", "contained", "--signals", "isolated"]));
    sandbox_args.extend(args(&[
        "--expose",
        &format!("127.0.0.1:{}=8080", free_port()),
    ]));
    let mut program = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[("read-line", "-"), ("exit", "7")],
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + WAIT;
    let factory = loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended early"
        );
        if let [factory] = session_leading_children(program.id())[..] {
            break factory;
        }
        assert!(Instant::now() < deadline, "no socket factory appeared");
        thread::sleep(Duration::from_millis(20));
    };
    thread::sleep(Duration::from_secs(1));
    assert!(
        program.try_wait().unwrap().is_none(),
        "sandy ended the program while its factory was alive"
    );
    kill_process(factory);
    let deadline = Instant::now() + WAIT;
    while program.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "sandy kept the program running after its socket factory was gone"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let output = program.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(reason.contains("relay"), "{reason}");
}

/// A forwarded port reaches the service outside, also with `contained`.
#[test]
fn a_forwarded_port_reaches_the_service() {
    if !private_network_works() {
        return;
    }
    let (service, accepted) = answering_service();
    for (index, mode) in launch_modes().into_iter().enumerate() {
        let inner = free_port();
        let mut sandbox_args = private();
        sandbox_args.extend(mode.iter().cloned());
        sandbox_args.extend(args(&["--forward", &format!("{inner}={service}")]));
        let lines = probe_inside(
            &sandbox_args,
            &[
                ("tcp-connect-read", &format!("127.0.0.1:{inner}")),
                ("tcp-connect", &service.to_string()),
            ],
        );
        assert_eq!(lines[0].detail, "2 bytes", "{mode:?}: {lines:?}");
        // The service itself is on the host's loopback, which the program does not reach.
        lines[1].assert_blocked();
        assert_eq!(accepted.load(Ordering::Acquire), index + 1, "{mode:?}");
    }
}

/// How to run `probe` as a local user that is not sandy's: with `sudo -n -u nobody`, or in a user
/// namespace that maps this account's sub-user IDs (as in forward.rs). `None` when neither works.
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
        .find(|way| {
            Command::new(&way[0])
                .args(&way[1..])
                .args(["env", "PATH"])
                .output()
                .is_ok_and(|output| output.status.success())
        })
}

/// `nsenter` into the user and network namespace of `pid`, keeping the caller's IDs, which is
/// how a process outside reaches the sandbox's loopback.
fn nsenter(pid: u32) -> Vec<String> {
    args(&[
        "nsenter",
        "--target",
        &pid.to_string(),
        "--user",
        "--net",
        "--preserve-credentials",
        "--",
    ])
}

fn run(command: &[String], actions: &[(&str, &str)]) -> Output {
    Command::new(&command[0])
        .args(&command[1..])
        .args(probe_args(actions))
        .output()
        .unwrap()
}

/// The forward listener is in the sandbox's network namespace, so another local user can neither
/// connect to the port on the host's loopback, where nothing listens, nor enter the namespace,
/// which belongs to sandy's user. With `ip = "all"` the same connect reaches the relay, which can
/// only refuse it afterwards (forward.rs). A process of sandy's own user can enter it and reach
/// the service, which is the exception that `check` names.
#[test]
fn another_user_cannot_reach_a_forward_port() {
    if !private_network_works() {
        return;
    }
    let fixture = Fixture::new("private-other-user");
    let probe = fixture.copy_probe("bin");
    let Some(other_user) = other_user(&probe) else {
        return skip(
            "other-user",
            "cannot run a program as another user (no `sudo -n -u nobody`, and no user namespace \
             with sub-user IDs)",
        );
    };
    if Command::new("nsenter").arg("--version").output().is_err() {
        return skip("nsenter", "nsenter of util-linux is not installed");
    }
    let (service, accepted) = answering_service();
    let inner = free_port();
    let mut sandbox_args = private();
    sandbox_args.extend(args(&["--forward", &format!("{inner}={service}")]));
    let mut program = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("sleep", "30000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = format!("127.0.0.1:{inner}");
    let connect = [("tcp-connect-read", port.as_str())];

    // Control: this user enters the namespace and reaches the service through the relay. The
    // program keeps sandy's process ID in the exec model.
    let own = [nsenter(program.id()), vec![probe.clone()]].concat();
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(
            program.try_wait().unwrap().is_none(),
            "the program ended before the relay was ready"
        );
        let output = run(&own, &connect);
        if output.status.success() && parse(&output)[0].detail == "2 bytes" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the forward port never answered: {output:?}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let reached = accepted.load(Ordering::Acquire);

    // The other user, on the host's loopback.
    let output = run(&other_user, &connect);
    assert!(output.status.success(), "{output:?}");
    let line = &parse(&output)[0];
    line.assert_blocked();
    assert!(line.detail.contains("refused"), "{line:?}");
    // The other user, entering the namespace: nsenter fails before the probe runs.
    let entering = [
        other_user[..other_user.len() - 1].to_vec(),
        nsenter(program.id()),
        vec![probe.clone()],
    ]
    .concat();
    let output = run(&entering, &connect);
    assert!(!output.status.success(), "{output:?}");
    assert!(parse(&output).is_empty(), "{output:?}");
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        accepted.load(Ordering::Acquire),
        reached,
        "the service was reached by another user"
    );

    kill_process(program.id());
    let _ = program.wait();
}

/// In the exec model the program keeps sandy's process ID, also in its own namespaces. It runs as
/// the user and group that ran sandy, root is not mapped, and it holds no capability, not even in
/// the bounding set.
#[test]
fn the_program_keeps_its_ids_and_holds_no_capability() {
    if !private_network_works() {
        return;
    }
    let mut sandbox_args = private();
    sandbox_args.extend(args(&["--read", "/proc"]));
    let actions = [
        ("pid", "-"),
        ("status-field", "Uid"),
        ("status-field", "Gid"),
        ("status-field", "CapEff"),
        ("status-field", "CapPrm"),
        ("status-field", "CapBnd"),
        ("status-field", "CapAmb"),
        ("read", "/proc/self/uid_map"),
    ];
    let child = spawn_sandy(&sandbox_args, &actions);
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines[0].detail, pid.to_string(), "{lines:?}");
    // SAFETY: getuid and getgid have no preconditions.
    let (user, group) = unsafe { (libc::getuid(), libc::getgid()) };
    let four = |id: u32| vec![id.to_string(); 4].join(" ");
    assert_eq!(lines[1].detail, four(user), "{lines:?}");
    assert_eq!(lines[2].detail, four(group), "{lines:?}");
    for line in &lines[3..7] {
        assert_eq!(line.detail, "0000000000000000", "{line:?}");
    }
    lines[7].assert_ok();
}

/// A socket on a standard stream belongs to the network it was created in, outside the
/// sandbox's own, so sandy refuses every IP socket there under `ip = "private"`, also a connected
/// stream socket that `ip = "all"` and `ip = "client"` take (DESIGN.md, "Private network and
/// egress", rule 3).
#[test]
fn an_inherited_ip_socket_is_refused() {
    // sandy refuses a policy it cannot enforce before it looks at the standard streams.
    if !private_network_works() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let with_stdin = |sandbox_args: &[String], stdin: Stdio| {
        Command::new(sandy_path())
            .args(run_args(sandbox_args, &[("pid", "-")]))
            .stdin(stdin)
            .output()
            .unwrap()
    };
    let connected = || TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let output = with_stdin(&all(), stdin_from(connected()));
    assert!(output.status.success(), "{output:?}");

    let datagram = UdpSocket::bind("127.0.0.1:0").unwrap();
    for stdin in [stdin_from(connected()), stdin_from(datagram)] {
        let output = with_stdin(&private(), stdin);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(
                "ip = \"private\" cannot hold for it: the socket belongs to a network outside the \
                 sandbox"
            ),
            "{stderr}"
        );
    }
}

/// On a host that gives sandy the namespaces, check names the mechanism and what stays open,
/// and no longer warns about a forwarded port, which no other user reaches here.
#[test]
fn check_reports_the_private_network_and_what_stays_open() {
    if !private_network_works() {
        return;
    }
    let to = TcpListener::bind("127.0.0.1:0").unwrap();
    let forward = format!("{}={}", free_port(), to.local_addr().unwrap());
    let output = sandy(["check", "--ip", "private", "--forward", &forward]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.lines().any(|line| line.starts_with("enforced     ")
            && line.contains(PRIVATE_LINE)
            && line.contains("network namespace")),
        "{stdout}"
    );
    assert!(stdout.contains("handed to the relay"), "{stdout}");
    let warns = |text: &str| {
        stderr
            .lines()
            .any(|line| line.starts_with("warning: ") && line.contains(text))
    };
    assert!(warns("can enter it (nsenter)"), "{stderr}");
    assert!(!warns("another local user can deliver a write"), "{stderr}");

    // Control: with ip = "all" the forwarded port takes a write of another user.
    let output = sandy(["check", "--ip", "all", "--forward", &forward]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("another local user can deliver a write"),
        "{stderr}"
    );
    assert!(!stderr.contains("can enter it (nsenter)"), "{stderr}");
}

/// Ubuntu 23.10 and newer let an unconfined process create a user namespace but give it no
/// rights there, so sandy cannot set one up until `sandy setup` installs an AppArmor profile for
/// it. check exits with status 2 for that, which a caller can act on without reading text, and
/// run refuses with the same reason. Elsewhere the check exits 0 (the test above).
#[test]
fn check_needs_setup_under_the_apparmor_restriction() {
    let read = |path: &str| {
        std::fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    };
    let restricted = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1";
    let unconfined = read("/proc/self/attr/apparmor/current") == "unconfined";
    if !(restricted && unconfined) {
        return skip(
            "apparmor-userns-restriction",
            "this host does not restrict user namespaces of unconfined processes with AppArmor",
        );
    }
    let reason = "kernel.apparmor_restrict_unprivileged_userns = 1";
    let output = sandy(["check", "--ip", "private"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(EXIT_NEEDS_SETUP), "{stdout}");
    let line = stdout
        .lines()
        .find(|line| line.contains(PRIVATE_LINE))
        .unwrap_or_default();
    assert!(line.starts_with("UNAVAILABLE  "), "{stdout}");
    assert!(line.contains(reason), "{line}");
    assert!(line.contains("`sandy setup`"), "{line}");

    let output = sandy(run_args(&private(), &[("pid", "-")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "{stderr}");
}

/// A host can allow user namespaces and still refuse them to sandy, for example inside a sandbox
/// whose seccomp filter denies `unshare`, as sandy's own does. `plan` cannot see that without a
/// trial; check makes one and reports the step that fails, and run refuses.
#[test]
fn check_tries_the_namespaces_inside_a_sandbox_that_denies_them() {
    if !private_network_works() {
        return;
    }
    let fixture = Fixture::new("private-nested");
    let inner = fixture.path("bin/sandy");
    copy_executable(sandy_path(), &inner);
    let outer = args(&[
        "run",
        "--read-exec",
        &fixture.arg("bin"),
        "--read",
        "/proc",
        "--",
    ]);
    let mut check = outer.clone();
    check.extend(args(&[inner.to_str().unwrap(), "check", "--ip", "private"]));
    let output = sandy(&check);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = stdout
        .lines()
        .find(|line| line.contains(PRIVATE_LINE))
        .unwrap_or_default();
    assert!(
        line.starts_with("UNAVAILABLE  ")
            && line.contains("a trial of the sandbox's namespaces failed")
            && line.contains("user namespace"),
        "{stdout}"
    );

    let mut run = outer;
    run.extend(args(&[
        inner.to_str().unwrap(),
        "run",
        "--ip",
        "private",
        "--read-exec",
        "/usr",
        "--",
        "/usr/bin/true",
    ]));
    let output = sandy(&run);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let mut stderr = String::new();
    output
        .stderr
        .as_slice()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("cannot create the sandbox's user namespace"),
        "{stderr}"
    );
}
