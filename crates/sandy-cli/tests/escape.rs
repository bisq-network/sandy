//! Escape tests: they run `sandy-probe` inside the sandbox and check that every action the policy
//! does not allow fails and every action it allows works.
//!
//! Each denial is checked against a control run of the same action outside the sandbox. A test
//! therefore cannot pass because the action was impossible anyway (missing file, closed port).
//!
//! These tests describe the platform-neutral contract. Platform-specific escape routes (for
//! example the D-Bus session bus on Linux) have their own tests in the backend crates or in
//! `escape_<platform>.rs`.

mod common;

use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use common::*;

#[test]
fn check_accepts_the_default_policy() {
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    let output = sandy(&args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "check failed:\n{stdout}");
    assert!(!stdout.contains("UNAVAILABLE"), "{stdout}");
}

#[test]
fn reads_only_allowed_paths() {
    let fixture = Fixture::new("read");
    let lines = controlled(
        &fixture.access_args(),
        &[
            ("read", &fixture.arg("ro/file")),
            ("list", &fixture.arg("ro")),
            ("read", &fixture.arg("rw/file")),
            ("read", &fixture.arg("secret/file")),
            ("list", &fixture.arg("secret")),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
    lines[2].assert_ok();
    lines[3].assert_blocked();
    lines[4].assert_blocked();
}

#[test]
fn writes_only_writable_paths() {
    let fixture = Fixture::new("write");
    let (rw_new, rw_dir, rw_file) = (
        fixture.arg("rw/new"),
        fixture.arg("rw/newdir"),
        fixture.arg("rw/file"),
    );
    let (ro_new, ro_file, secret_new) = (
        fixture.arg("ro/new"),
        fixture.arg("ro/file"),
        fixture.arg("secret/new"),
    );
    let actions = [
        ("write", rw_new.as_str()),
        ("mkdir", rw_dir.as_str()),
        ("delete", rw_file.as_str()),
        ("write", ro_new.as_str()),
        ("delete", ro_file.as_str()),
        ("write", secret_new.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();

    let lines = probe_inside(&fixture.access_args(), &actions);
    lines[0].assert_ok();
    lines[1].assert_ok();
    lines[2].assert_ok();
    lines[3].assert_blocked();
    lines[4].assert_blocked();
    lines[5].assert_blocked();
    assert!(fixture.path("ro/file").exists());
    assert!(!fixture.path("ro/new").exists());
    assert!(!fixture.path("secret/new").exists());
}

/// Emptying a file needs the same right as writing it: a file in a read-only path and a file
/// outside the policy keep their content, through `truncate` and, on Unix, through a read-only
/// open with `O_TRUNC`.
#[test]
fn read_only_and_outside_files_cannot_be_truncated() {
    let fixture = Fixture::new("truncate");
    let (ro, secret, rw) = (
        fixture.arg("ro/file"),
        fixture.arg("secret/file"),
        fixture.arg("rw/file"),
    );
    let mut actions = vec![("truncate", ro.as_str()), ("truncate", secret.as_str())];
    if cfg!(unix) {
        actions.push(("open-rdonly-trunc", ro.as_str()));
        actions.push(("open-rdonly-trunc", secret.as_str()));
    }
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();

    for line in probe_inside(&fixture.access_args(), &actions) {
        line.assert_blocked();
    }
    assert_eq!(fs::read(fixture.path("ro/file")).unwrap(), b"content");
    assert_eq!(fs::read(fixture.path("secret/file")).unwrap(), b"content");

    // The positive control: in a writable path the program may empty a file. Where the kernel
    // cannot check truncation, sandy denies the call for every path instead.
    let line = &probe_inside(&fixture.access_args(), &[("truncate", rw.as_str())])[0];
    if truncation_works_in_writable_paths() {
        line.assert_ok();
        assert!(fs::read(fixture.path("rw/file")).unwrap().is_empty());
    } else {
        line.assert_blocked();
        assert_eq!(fs::read(fixture.path("rw/file")).unwrap(), b"content");
    }
}

/// Whether the sandbox lets the program empty a file in a writable path. Before Landlock ABI 3
/// the kernel cannot check truncation, so sandy's filter denies `truncate` for every path, also
/// a writable one (docs/linux.md, "Truncation"). Seatbelt and Windows check truncation with the
/// right to write the file's data.
fn truncation_works_in_writable_paths() -> bool {
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 3 {
        return false;
    }
    true
}

#[test]
fn executes_only_executable_paths() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("exec");
    let allowed = fixture.copy_probe("bin");
    let secret = fixture.copy_probe("secret");
    let readable = fixture.copy_probe("ro");
    let lines = controlled(
        &fixture.access_args(),
        &[("exec", &allowed), ("exec", &secret), ("exec", &readable)],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    lines[2].assert_blocked();
}

#[test]
fn ip_networking_is_denied_by_default() {
    let fixture = Fixture::new("ipdeny");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let lines = controlled(&fixture.access_args(), &[("tcp-connect", &address)]);
    lines[0].assert_blocked();

    // Inbound: no connection from outside may reach a listener of the program, whether the
    // sandbox refuses the bind (Linux) or drops the incoming traffic (Windows).
    let (connected, line) = inbound_tcp(None);
    assert!(connected, "control: {line:?}");
    line.assert_ok();
    let (connected, line) = inbound_tcp(Some(&fixture.access_args()));
    assert!(!connected, "connected to the program: {line:?}");
    line.assert_blocked();
}

#[test]
fn ip_networking_works_when_allowed() {
    let fixture = Fixture::new("ipallow");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut args = fixture.access_args();
    args.extend(["--ip".to_string(), "all".to_string()]);
    let lines = controlled(&args, &[("tcp-connect", &address)]);
    lines[0].assert_ok();
}

/// `ip = "client"`: the program connects out, resolves names through the system and asks a DNS
/// server itself, and gets the answers to its datagrams. The control without IP networking shows
/// that the connection needs the setting.
#[test]
fn ip_client_connects_out() {
    let fixture = Fixture::new("ipclient-out");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let query = format!("{}\u{1f}example.test", dns_server());
    let client = with_ip(&fixture, "client");
    let lines = controlled(
        &client,
        &[
            ("tcp-connect", &address),
            ("resolve", "localhost"),
            ("dns-query", &query),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
    assert_eq!(lines[2].detail, "rcode 0, 0 answers", "{:?}", lines[2]);
    probe_inside(&fixture.access_args(), &[("tcp-connect", &address)])[0].assert_blocked();

    let (control, _) = udp_answer(None, false);
    control.assert_ok();
    let (line, peer) = udp_answer(Some(&client), false);
    line.assert_ok();
    assert_eq!(line.detail, format!("from {peer}"));
}

/// `ip = "client"`: no connection reaches a listener of the program. Linux and macOS refuse
/// listen itself; Windows lets the program listen and drops what arrives. The controls: the
/// connection arrives outside the sandbox, and with `ip = "all"` on Linux and macOS, while
/// Windows drops every loopback connection into an AppContainer also then (docs/windows.md,
/// "Loopback").
#[test]
fn ip_client_takes_no_connections() {
    let fixture = Fixture::new("ipclient-in");
    let client = with_ip(&fixture, "client");
    let all = with_ip(&fixture, "all");
    let listen = [("tcp-listen", "127.0.0.1:0")];
    let lines = controlled(&client, &listen);
    if cfg!(windows) {
        lines[0].assert_ok();
    } else {
        lines[0].assert_blocked();
    }
    probe_inside(&all, &listen)[0].assert_ok();

    let (connected, line) = inbound_tcp(None);
    assert!(connected, "control: {line:?}");
    let (connected, line) = inbound_tcp(Some(&client));
    assert!(!connected, "connected to the program: {line:?}");
    line.assert_blocked();
    let (connected, line) = inbound_tcp(Some(&all));
    assert_eq!(connected, !cfg!(windows), "ip = \"all\": {line:?}");
}

/// `ip = "client"` and datagrams the program did not ask for. This records the routes the
/// exceptions table of DESIGN.md names, so a platform that closes one fails here: on Linux and
/// macOS a UDP socket that is not connected receives from every sender, at the port the kernel
/// chose for it, and at a port the program binds itself unless Landlock ABI 10 refuses that bind.
/// Windows drops both over loopback, as it does with `ip = "all"`.
#[test]
fn ip_client_datagrams_from_others() {
    let fixture = Fixture::new("ipclient-udp");
    let client = with_ip(&fixture, "client");
    let all = with_ip(&fixture, "all");

    inbound_udp(None).assert_ok();
    let bound = inbound_udp(Some(&client));
    let gap = !cfg!(windows);
    #[cfg(target_os = "linux")]
    let gap = gap && common::linux::landlock_abi() < 10;
    if gap {
        bound.assert_ok();
    } else {
        bound.assert_blocked();
    }
    assert_eq!(inbound_udp(Some(&all)).result == "ok", !cfg!(windows));

    let (control, third) = udp_answer(None, true);
    assert_eq!(control.detail, format!("from {third}"));
    let (line, third) = udp_answer(Some(&client), true);
    if cfg!(windows) {
        line.assert_blocked();
    } else {
        assert_eq!(line.detail, format!("from {third}"), "{line:?}");
    }
}

/// A DNS server on loopback that answers every query with no records. Returns its address.
fn dns_server() -> String {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap().to_string();
    server
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    std::thread::spawn(move || {
        let mut query = [0; 512];
        while let Ok((length, client)) = server.recv_from(&mut query) {
            // The query itself, marked as a response.
            query[2] |= 0x80;
            let _ = server.send_to(&query[..length], client);
        }
    });
    address
}

fn with_ip(fixture: &Fixture, ip: &str) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend(["--ip".to_string(), ip.to_string()]);
    args
}

#[cfg(unix)]
#[test]
fn unix_sockets_are_denied_by_default() {
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new("unix");
    let socket = fixture.path("rw/socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    let socket = socket.to_str().unwrap().to_string();

    let mut ip_only = fixture.access_args();
    ip_only.extend(["--ip".to_string(), "all".to_string()]);
    let lines = controlled(&ip_only, &[("unix-connect", &socket)]);
    lines[0].assert_blocked();

    let mut unix_allowed = ip_only.clone();
    unix_allowed.extend(["--unix-sockets".to_string(), "all".to_string()]);
    let lines = probe_inside(&unix_allowed, &[("unix-connect", &socket)]);
    lines[0].assert_ok();
}

#[test]
fn environment_contains_only_allowed_variables() {
    let fixture = Fixture::new("env");
    let mut args = vec!["run".to_string()];
    args.extend(platform_args());
    args.extend(fixture.access_args());
    args.extend([
        "--pass-env".to_string(),
        "SANDY_PASSED".to_string(),
        "--set-env".to_string(),
        "SANDY_SET=fixed".to_string(),
        "--".to_string(),
        probe_path(),
    ]);
    args.extend(probe_args(&[
        ("env", "SANDY_PASSED"),
        ("env", "SANDY_SET"),
        ("env", "SANDY_HIDDEN"),
    ]));
    let output = Command::new(sandy_path())
        .args(&args)
        .env("SANDY_PASSED", "passed")
        .env("SANDY_SET", "overridden")
        .env("SANDY_HIDDEN", "hidden")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(
        (lines[0].result.as_str(), lines[0].detail.as_str()),
        ("ok", "passed")
    );
    assert_eq!(
        (lines[1].result.as_str(), lines[1].detail.as_str()),
        ("ok", "fixed")
    );
    lines[2].assert_blocked();
}

#[test]
fn refuses_a_path_that_is_writable_and_executable() {
    let fixture = Fixture::new("wx");
    let mut args = vec!["run".to_string()];
    args.extend(platform_args());
    args.extend([
        "--read-write".to_string(),
        fixture.arg("rw"),
        "--read-exec".to_string(),
        fixture.arg("rw"),
        "--".to_string(),
        probe_path(),
        "write".to_string(),
        fixture.arg("rw/marker"),
    ]);
    let output = sandy(&args);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(!fixture.path("rw/marker").exists());
}

#[test]
fn refuses_a_relative_program_path() {
    let output = sandy(["run", "sandy-probe"]);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

/// The program gets argv[0] as the caller wrote the program, not the resolved path: multi-call
/// programs choose their behavior by this name.
#[test]
fn the_program_gets_the_name_the_caller_gave_it() {
    let fixture = Fixture::new("arg0");
    let program = fixture.copy_probe("bin");
    // Rust removes `.` from a path with the Windows `\\?\` prefix, so spell it without one.
    let plain = program.strip_prefix(r"\\?\").unwrap_or(&program);
    let path = std::path::Path::new(plain);
    let spelled = path
        .parent()
        .unwrap()
        .join(".")
        .join(path.file_name().unwrap());
    let spelled = spelled.to_str().unwrap();
    let mut args = vec!["run".to_string()];
    args.extend(platform_args());
    args.extend(fixture.access_args());
    args.extend([
        "--".to_string(),
        spelled.to_string(),
        "arg0".to_string(),
        "-".to_string(),
    ]);
    let output = sandy(&args);
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    lines[0].assert_ok();
    assert_eq!(lines[0].detail, spelled);
}

/// The policy file is trusted: a program that could write it would choose its own policy for
/// the next start.
#[test]
fn refuses_a_policy_file_inside_a_writable_path() {
    let fixture = Fixture::new("policy-file");
    let write_policy = |dir: &str| {
        let file = fixture.path(dir).join("policy.toml");
        let text = format!(
            "version = 1\n[filesystem]\nread_write = ['{}']\n",
            fixture.arg("rw")
        );
        std::fs::write(&file, text).unwrap();
        file.to_str().unwrap().to_string()
    };
    let mut check = vec!["check".to_string()];
    check.extend(platform_args());

    // Control: the same policy from a directory the program cannot write.
    let mut args = check.clone();
    args.extend(["--policy".to_string(), write_policy("ro")]);
    let output = sandy(&args);
    assert!(output.status.success(), "{output:?}");

    let mut args = check;
    args.extend(["--policy".to_string(), write_policy("rw")]);
    let output = sandy(&args);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("inside writable path"), "{stderr}");
}

/// A writable path that reaches the policy file under a second name is as dangerous as one that
/// contains it: the program rewrites it there, and the next start reads what it wrote.
#[cfg(unix)]
#[test]
fn refuses_a_policy_file_reached_through_a_link_in_a_writable_path() {
    let fixture = Fixture::new("policy-link");
    let policy = fixture.path("ro/policy.toml");
    let text = format!(
        "version = 1\n[filesystem]\nread_write = ['{}']\n",
        fixture.arg("rw")
    );
    fs::write(&policy, text).unwrap();
    let check = |file: &str| {
        let mut args = vec!["check".to_string()];
        args.extend(platform_args());
        args.extend(["--policy".to_string(), file.to_string()]);
        sandy(&args)
    };

    // Control: the policy file where it lies, outside the writable path.
    let output = check(&fixture.arg("ro/policy.toml"));
    assert!(output.status.success(), "{output:?}");

    // Named through a symbolic link inside the writable path.
    std::os::unix::fs::symlink(&policy, fixture.path("rw/policy.toml")).unwrap();
    let output = check(&fixture.arg("rw/policy.toml"));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writable path"), "{stderr}");

    // Named where it lies, with a second name inside the writable path.
    fs::hard_link(&policy, fixture.path("rw/second.toml")).unwrap();
    let output = check(&fixture.arg("ro/policy.toml"));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writable path"), "{stderr}");
}

/// The same for sandy's own executable, which the program would replace for the next start.
/// `current_exe` resolves the name on Linux, so the name sandy was started under is checked too.
#[cfg(unix)]
#[test]
fn refuses_a_sandy_executable_a_writable_path_reaches() {
    let fixture = Fixture::new("sandy-link");
    let copy = fixture.path("bin/sandy");
    copy_executable(sandy_path(), &copy);
    let check = |program: &std::path::Path| {
        let mut args = vec!["check".to_string()];
        args.extend(platform_args());
        args.extend(["--read-write".to_string(), fixture.arg("rw")]);
        run_copied(program, &args)
    };

    // Control: sandy outside the writable path.
    let output = check(&copy);
    assert!(output.status.success(), "{output:?}");

    // Started through a symbolic link inside the writable path.
    let link = fixture.path("rw/sandy");
    std::os::unix::fs::symlink(&copy, &link).unwrap();
    let output = check(&link);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    fs::remove_file(&link).unwrap();

    // Started where it lies, with a second name inside the writable path.
    fs::hard_link(&copy, &link).unwrap();
    let output = check(&copy);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writable path"), "{stderr}");
}

/// Rule 3 by identity: a file with one name in an executable path and one in a writable path is
/// writable and executable, whichever name a call uses. The program could rewrite the code that
/// the next run, or a process outside the sandbox, executes.
#[test]
fn a_hard_link_between_writable_and_executable_paths_is_refused() {
    let fixture = Fixture::new("link-wx");
    let tool = fixture.copy_probe("bin");
    let run = || {
        sandy(run_args(
            &fixture.access_args(),
            &[("read", &fixture.arg("ro/file"))],
        ))
    };

    // Control: the same policy without the link.
    let output = run();
    assert!(output.status.success(), "{output:?}");

    fs::hard_link(&tool, fixture.path("rw/data")).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writable"), "{stderr}");
}

/// The program file gets execute access of its own (rule 5), so a second name of it inside a
/// writable path is refused as well.
#[test]
fn a_hard_link_of_the_program_into_a_writable_path_is_refused() {
    let fixture = Fixture::new("link-program");
    let program = fixture.copy_probe("bin");
    let run = || {
        let mut args = vec!["run".to_string()];
        args.extend(platform_args());
        args.extend(["--read-write".to_string(), fixture.arg("rw")]);
        args.extend([
            "--".to_string(),
            program.clone(),
            "read".to_string(),
            fixture.arg("rw/file"),
        ]);
        sandy(&args)
    };

    // Control: the same program without the link.
    let output = run();
    assert!(output.status.success(), "{output:?}");

    fs::hard_link(&program, fixture.path("rw/copy")).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("writable"), "{stderr}");
}

/// What a hard link still carries, so a change in it does not pass unnoticed: a file that lies
/// outside the policy and has a second name inside a writable path can be changed through that
/// name. sandy refuses the second name only when the other one is executable, the program or a
/// file sandy trusts. Refusing every one would stop the package managers that fill a project
/// from a shared cache with hard links (see "Links" in docs/DESIGN.md).
#[cfg(unix)]
#[test]
fn a_hard_link_to_a_file_outside_the_policy_stays_writable() {
    let fixture = Fixture::new("link-outside");
    let (outside, inside) = (fixture.path("secret/file"), fixture.arg("rw/linked"));
    fs::hard_link(&outside, &inside).unwrap();
    let lines = probe_inside(
        &fixture.access_args(),
        &[
            ("write", &inside),
            ("read", &fixture.arg("secret/file")),
            ("write", &fixture.arg("secret/file")),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    lines[2].assert_blocked();
    assert_eq!(fs::read(&outside).unwrap(), b"probe");
}

/// A policy file may be named relative to the current directory. The checks that protect it
/// take absolute paths, so sandy makes the name absolute before it applies them.
#[test]
fn accepts_a_policy_file_named_relative_to_the_current_directory() {
    let fixture = Fixture::new("policy-relative");
    fs::write(fixture.path("ro/policy.toml"), "version = 1\n").unwrap();
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    args.extend(["--policy".to_string(), "ro/policy.toml".to_string()]);
    let output = Command::new(sandy_path())
        .args(&args)
        .current_dir(&fixture.root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

/// check refuses what run would refuse: --parent-pid without end_with_parent.
#[test]
fn check_refuses_a_parent_pid_without_end_with_parent() {
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    args.extend(["--parent-pid".to_string(), std::process::id().to_string()]);
    let output = sandy(&args);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--parent-pid"), "{stderr}");
}

#[test]
fn metadata_outside_writable_paths_cannot_change() {
    let fixture = Fixture::new("metadata");
    let secret = fixture.arg("secret/file");
    let readable = fixture.arg("ro/file");
    for line in probe_outside(&[
        ("set-readonly", &secret),
        ("set-writable", &secret),
        ("set-readonly", &readable),
        ("set-writable", &readable),
    ]) {
        line.assert_ok();
    }
    let lines = probe_inside(
        &fixture.access_args(),
        &[("set-readonly", &secret), ("set-readonly", &readable)],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
    for file in ["secret/file", "ro/file"] {
        let permissions = fs::metadata(fixture.path(file)).unwrap().permissions();
        assert!(!permissions.readonly(), "{file} changed");
    }
}

/// What `udp-send-fd` sends through the socket it is given (see `sandy-probe`).
const UDP_SEND_PAYLOAD: &[u8] = b"sent through an inherited socket";

/// A socket on a standard stream was created before the sandbox, so the sandbox cannot take its
/// access away: the program sends, receives and accepts through it whatever the policy says.
/// sandy refuses to start the program instead.
#[test]
fn a_socket_on_standard_input_gives_no_network_access() {
    let outside = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = format!("0\u{1f}{}", outside.local_addr().unwrap());
    let actions = [("udp-send-fd", target.as_str())];
    let sender = || UdpSocket::bind("127.0.0.1:0").unwrap();

    let output = Command::new(probe_path())
        .args(probe_args(&actions))
        .stdin(stdin_from(sender()))
        .output()
        .unwrap();
    parse(&output)[0].assert_ok();
    assert_eq!(
        datagram(&outside, Duration::from_secs(5)).as_deref(),
        Some(UDP_SEND_PAYLOAD)
    );

    let refused = run_with_stdin(&run_args(&[], &actions), stdin_from(sender()));
    assert_refused(
        &refused,
        "standard input carries an unconnected IP datagram socket",
    );
    assert_eq!(datagram(&outside, Duration::from_millis(500)), None);

    // A listening socket on standard input lets the program accept connections from outside.
    // With `unix_sockets = "all"` the Linux filter allows `accept`, so the socket alone decides.
    let actions = [("accept-fd", "0")];
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    // A connection that is complete as soon as it is in the backlog, so the client needs no
    // accept to connect and the test does not race the program.
    let waiting = TcpStream::connect(address).unwrap();
    let output = Command::new(probe_path())
        .args(probe_args(&actions))
        .stdin(stdin_from(server.try_clone().unwrap()))
        .output()
        .unwrap();
    parse(&output)[0].assert_ok();
    drop(waiting);

    let waiting = TcpStream::connect(address).unwrap();
    let sandbox_args = ["--unix-sockets".to_string(), "all".to_string()];
    let refused = run_with_stdin(&run_args(&sandbox_args, &actions), stdin_from(server));
    // macOS has no SO_ACCEPTCONN, so there sandy names what the kernel does tell about the
    // socket: it has no peer.
    let state = if cfg!(target_os = "macos") {
        "an unconnected"
    } else {
        "a listening"
    };
    assert_refused(
        &refused,
        &format!("standard input carries {state} IP stream socket"),
    );
    drop(waiting);
}

/// With `ip = "client"` a connected TCP socket on standard input is accepted: it talks only to
/// its peer, like a connection the program makes itself. A listening socket and a datagram
/// socket are refused, also a connected datagram socket, which the program could disconnect and
/// then receive from every sender at the port its creator chose.
#[test]
fn ip_client_accepts_only_a_connection_on_standard_input() {
    let client = ["--ip".to_string(), "client".to_string()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let output = run_with_stdin(&run_args(&client, &[("pid", "-")]), stdin_from(stream));
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();

    let waiting = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let refused = run_with_stdin(&run_args(&client, &[("pid", "-")]), stdin_from(listener));
    let state = if cfg!(target_os = "macos") {
        "an unconnected"
    } else {
        "a listening"
    };
    assert_refused(
        &refused,
        &format!("standard input carries {state} IP stream socket"),
    );
    drop(waiting);

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let connected = UdpSocket::bind("127.0.0.1:0").unwrap();
    connected.connect(peer.local_addr().unwrap()).unwrap();
    let refused = run_with_stdin(&run_args(&client, &[("pid", "-")]), stdin_from(connected));
    assert_refused(
        &refused,
        "standard input carries a connected IP datagram socket",
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("ip = \"client\" cannot hold for it"),
        "{stderr}"
    );
}

/// A service that is handed its connection on standard input runs with `ip = "all"`. The peer is
/// an IPv6 address, which needs more room than an IPv4 one when sandy asks for it.
#[test]
fn a_connected_ipv6_socket_on_standard_input_runs_with_ip_all() {
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        return skip("ipv6-loopback", "this host cannot listen on ::1");
    };
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (connection, _) = listener.accept().unwrap();
    let sandbox_args = ["--ip".to_string(), "all".to_string()];
    let output = run_with_stdin(
        &run_args(&sandbox_args, &[("pid", "-")]),
        stdin_from(connection),
    );
    assert!(
        output.status.success(),
        "a connected IP socket must be allowed with ip = \"all\": {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse(&output)[0].assert_ok();
    drop(client);
}

/// A socket of a family that no policy lets the program create, such as a netlink socket for
/// sock_diag, through which the program could list every socket of the host. The program cannot
/// create one itself, also with `ip = "all"`, but one on a standard stream keeps working inside,
/// so sandy refuses it under every policy and names the family.
#[test]
fn a_socket_of_another_family_on_standard_input_is_refused() {
    let ip = ["--ip".to_string(), "all".to_string()];
    let run = |args: &[String], stdin| run_with_stdin(&run_args(args, &[("pid", "-")]), stdin);

    // Controls: with a pipe or a connected IP socket on standard input the same run starts.
    let output = run(&ip, Stdio::piped());
    assert!(output.status.success(), "{output:?}");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let output = run(&ip, stdin_from(client));
    assert!(output.status.success(), "{output:?}");

    for other in OTHER_FAMILIES {
        let name = other.name;
        if let Err(error) = other.socket() {
            skip(
                &format!("socket-family-{name}"),
                &format!("{name}: not creatable outside the sandbox ({error})"),
            );
            continue;
        }
        if let Some(action) = CREATE_SOCKET_ACTION {
            probe_inside(&ip, &[(action, name)])[0].assert_blocked();
        }
        for args in [&ip[..], &[]] {
            let refused = run(args, other.socket().unwrap());
            assert_refused(&refused, &format!("{};", other.named));
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(
                stderr.contains("no policy lets the program create one like it"),
                "{stderr}"
            );
        }
    }
}

/// A socket family besides Unix and IP that this platform can create without privileges.
struct OtherFamily {
    /// The target of `CREATE_SOCKET_ACTION`, and the name of the skip.
    name: &'static str,
    family: i32,
    kind: i32,
    protocol: i32,
    /// How sandy's message names the socket.
    named: &'static str,
}

/// The probe action that creates one of `OTHER_FAMILIES` inside the sandbox.
#[cfg(target_os = "linux")]
const CREATE_SOCKET_ACTION: Option<&str> = Some("socket");
#[cfg(target_os = "macos")]
const CREATE_SOCKET_ACTION: Option<&str> = Some("socket-family");
#[cfg(windows)]
const CREATE_SOCKET_ACTION: Option<&str> = None;

#[cfg(target_os = "linux")]
const OTHER_FAMILIES: &[OtherFamily] = &[
    // Only route netlink is allowed with `ip = "all"`; the family is the same.
    OtherFamily {
        name: "netlink-sock-diag",
        family: libc::AF_NETLINK,
        kind: libc::SOCK_RAW,
        protocol: 4,
        named: "socket of family 16 (AF_NETLINK), protocol 4",
    },
    OtherFamily {
        name: "vsock",
        family: 40,
        kind: libc::SOCK_STREAM,
        protocol: 0,
        named: "stream socket of family 40 (AF_VSOCK)",
    },
    // It has neither a name nor a peer to ask for.
    OtherFamily {
        name: "alg",
        family: libc::AF_ALG,
        kind: libc::SOCK_SEQPACKET,
        protocol: 0,
        named: "seqpacket socket of family 38 (AF_ALG)",
    },
];

#[cfg(target_os = "macos")]
const OTHER_FAMILIES: &[OtherFamily] = &[
    OtherFamily {
        name: "route",
        family: libc::PF_ROUTE,
        kind: libc::SOCK_RAW,
        protocol: 0,
        named: "socket of family 17 (AF_ROUTE)",
    },
    OtherFamily {
        name: "system",
        family: libc::PF_SYSTEM,
        kind: libc::SOCK_DGRAM,
        protocol: libc::SYSPROTO_CONTROL,
        named: "datagram socket of family 32 (AF_SYSTEM), protocol 2",
    },
];

#[cfg(windows)]
const OTHER_FAMILIES: &[OtherFamily] = &[OtherFamily {
    name: "bluetooth",
    family: 32,
    kind: 1,
    protocol: 3,
    named: "stream socket of family 32 (AF_BTH), protocol 3",
}];

impl OtherFamily {
    fn socket(&self) -> std::io::Result<Stdio> {
        new_socket(self.family, self.kind, self.protocol)
    }
}

/// A raw IP socket needs privileges that sandy does not give the program, so one on a standard
/// stream is refused under every policy. An ICMP datagram socket, which an unprivileged program
/// can create where the kernel allows it, follows `ip` like any other IP datagram socket.
#[test]
fn a_raw_ip_socket_on_standard_input_is_refused() {
    let ip = ["--ip".to_string(), "all".to_string()];
    let actions = [("pid", "-")];

    match icmp_datagram_socket() {
        Ok(socket) => {
            let output = run_with_stdin(&run_args(&ip, &actions), socket);
            assert!(output.status.success(), "{output:?}");
            assert_refused(
                &run_with_stdin(&run_args(&[], &actions), icmp_datagram_socket().unwrap()),
                "standard input carries an unconnected IP datagram socket;",
            );
        }
        Err(error) => skip(
            "icmp-datagram-socket",
            &format!("this host creates no ICMP datagram socket for this user: {error}"),
        ),
    }

    for args in [&ip[..], &[]] {
        let refused = match run_with_raw_socket(&run_args(args, &actions)) {
            Ok(refused) => refused,
            Err(error) => {
                return skip(
                    "raw-socket",
                    &format!("this test cannot create a raw IP socket: {error}"),
                );
            }
        };
        assert_refused(
            &refused,
            "standard input carries an unconnected IP raw socket;",
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("no policy lets the program create one like it"),
            "{stderr}"
        );
    }
}

#[cfg(unix)]
fn icmp_datagram_socket() -> std::io::Result<Stdio> {
    new_socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP)
}

#[cfg(windows)]
fn icmp_datagram_socket() -> std::io::Result<Stdio> {
    new_socket(2, 2, 1)
}

/// Runs sandy with `args` and a raw ICMP socket as its standard input. Creating one needs
/// CAP_NET_RAW, which the test has in a user and network namespace of its own: the child creates
/// the socket there before it executes sandy, and executing drops the capability again.
#[cfg(target_os = "linux")]
fn run_with_raw_socket(args: &[String]) -> std::io::Result<Output> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(sandy_path());
    command.args(args);
    // SAFETY: the closure runs in the forked child and makes only system calls.
    unsafe {
        command.pre_exec(|| {
            let raw = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fd = libc::socket(libc::AF_INET, raw, libc::IPPROTO_ICMP);
            if fd < 0 || libc::dup2(fd, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output()
}

/// Runs sandy with `args` and a raw ICMP socket as its standard input, which only root (macOS) or
/// an administrator (Windows) can create.
#[cfg(not(target_os = "linux"))]
fn run_with_raw_socket(args: &[String]) -> std::io::Result<Output> {
    #[cfg(unix)]
    let raw = (libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
    #[cfg(windows)]
    let raw = (2, 3, 1);
    Ok(run_with_stdin(args, new_socket(raw.0, raw.1, raw.2)?))
}

/// A new socket as a child's standard input.
#[cfg(unix)]
fn new_socket(family: i32, kind: i32, protocol: i32) -> std::io::Result<Stdio> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: socket takes no pointers.
    let fd = unsafe { libc::socket(family, kind, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor is new and nothing else in this process owns it.
    Ok(stdin_from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[cfg(windows)]
fn new_socket(family: i32, kind: i32, protocol: i32) -> std::io::Result<Stdio> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::{FromRawSocket, OwnedSocket};

    use windows_sys::Win32::Networking::WinSock::{
        INVALID_SOCKET, WSADATA, WSAGetLastError, WSAStartup, socket,
    };

    // Winsock answers only after it has started in this process. It is never stopped, which
    // would end the sockets of the other tests.
    let mut data = MaybeUninit::<WSADATA>::zeroed();
    // SAFETY: the structure is the one WSAStartup fills.
    unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
    // SAFETY: socket takes no pointers.
    let handle = unsafe { socket(family, kind, protocol) };
    if handle == INVALID_SOCKET {
        // SAFETY: WSAGetLastError has no preconditions.
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    // SAFETY: the socket is new and nothing else in this process owns it.
    Ok(stdin_from(unsafe {
        OwnedSocket::from_raw_socket(handle as u64)
    }))
}

/// The one socket that gives no more than a pipe: a connected Unix stream or seqpacket socket,
/// which is how libuv, journald and `ssh` without a terminal pass a standard stream. Refusing it
/// would break those callers, so sandy starts the program. A datagram pair can be pointed
/// elsewhere, so it is refused like any other Unix socket.
#[test]
fn a_connected_unix_socket_on_standard_input_still_runs() {
    use std::io::Write;

    const LINE: &[u8] = b"a line from the parent\n";
    let actions = [("read-line", "0")];
    let args = run_args(&[], &actions);
    let mut skipped = Vec::new();
    for kind in ["stream", "seqpacket"] {
        let Some((mut ours, theirs)) = unix_pair(kind) else {
            skipped.push(kind);
            continue;
        };
        ours.write_all(LINE).unwrap();
        let output = run_with_stdin(&args, theirs);
        assert!(
            output.status.success(),
            "a connected Unix {kind} socket must stay allowed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lines = parse(&output);
        assert_eq!(lines.len(), 1, "{lines:?}");
        lines[0].assert_ok();
        assert_eq!(lines[0].detail, "a line from the parent");
    }

    match unix_pair("datagram") {
        // The line is for the program that must not start: without it, a regression would let
        // the probe wait for input instead of failing the test.
        Some((mut ours, theirs)) => {
            ours.write_all(LINE).unwrap();
            assert_refused(
                &run_with_stdin(&args, theirs),
                "standard input carries a connected Unix datagram socket",
            );
        }
        None => skipped.push("datagram"),
    }
    if !skipped.is_empty() {
        skip(
            "unix-socket-pair",
            &format!(
                "this host makes no connected AF_UNIX pair of these kinds: {}",
                skipped.join(", ")
            ),
        );
    }
}

/// A connected AF_UNIX socket pair: the end the test writes to and the end a child gets as its
/// standard input. `None` when this host has no pair of that kind (macOS has no seqpacket
/// socket, Windows has no `socketpair`).
#[cfg(unix)]
fn unix_pair(kind: &str) -> Option<(fs::File, Stdio)> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let kind = match kind {
        "stream" => libc::SOCK_STREAM,
        "seqpacket" => libc::SOCK_SEQPACKET,
        "datagram" => libc::SOCK_DGRAM,
        other => panic!("unknown socket kind {other}"),
    };
    let mut pair = [-1 as libc::c_int; 2];
    // SAFETY: socketpair writes two descriptors into the array and reads nothing else.
    if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, pair.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: both descriptors are new and nothing else in this process owns them.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
    Some((fs::File::from(ours), Stdio::from(theirs)))
}

#[cfg(not(unix))]
fn unix_pair(_kind: &str) -> Option<(fs::File, Stdio)> {
    None
}

/// Writing the interrupt character into the master side of a pseudo-terminal makes the kernel
/// send SIGINT to the foreground group of the other side, with no check of who may signal whom.
/// With `signals = "isolated"` sandy therefore refuses a master on a standard stream; with
/// `signals = "any"` the program may signal every process of the user anyway. The slave side,
/// which a program gets when it runs in a terminal, stays accepted.
#[cfg(unix)]
#[test]
fn a_pseudo_terminal_master_on_a_standard_stream_needs_signals_any() {
    use common::unix::{discard_output, open_pty};

    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let Some(pty) = open_pty() else {
        return skip("pty", "no pseudo-terminal available");
    };
    // On macOS the victim, which leads the terminal's session, can only exit once the terminal's
    // output is read.
    discard_output(&pty);
    let isolated = ["--signals".to_string(), "isolated".to_string()];
    let any = ["--signals".to_string(), "any".to_string()];
    let interrupt = [("type-interrupt", "0")];
    let master = || Stdio::from(pty.master.try_clone().unwrap());

    let refused = run_with_stdin(&run_args(&isolated, &interrupt), master());
    assert_refused(
        &refused,
        "standard input carries the master side of a pseudo-terminal;",
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("Pass the slave side of the pseudo-terminal or a pipe instead"),
        "{stderr}"
    );
    let refused = Command::new(sandy_path())
        .args(run_args(&isolated, &[("pid", "-")]))
        .stdout(master())
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(EXIT_FAILURE), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("standard output carries the master side of a pseudo-terminal;"),
        "{stderr}"
    );

    let slave = Stdio::from(pty.slave.try_clone().unwrap());
    let lines = parse(&run_with_stdin(&run_args(&isolated, &interrupt), slave));
    assert_eq!(lines.len(), 1, "{lines:?}");
    lines[0].assert_ok();

    // The control: the same write from a program with `signals = "any"` reaches the process
    // outside the sandbox.
    let mut victim = await_interrupt(&pty);
    let lines = parse(&run_with_stdin(&run_args(&any, &interrupt), master()));
    assert_eq!(lines.len(), 1, "{lines:?}");
    lines[0].assert_ok();
    assert_eq!(victim.wait().unwrap().code(), Some(42));
}

/// A probe outside the sandbox that leads the session of `pty`, so its group is the foreground
/// group of the terminal, and exits with status 42 when SIGINT arrives within 5 seconds.
#[cfg(unix)]
fn await_interrupt(pty: &common::unix::Pty) -> std::process::Child {
    use std::io::BufRead;

    let mut command = Command::new(probe_path());
    command
        .args(probe_args(&[("await-signal", &libc::SIGINT.to_string())]))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    common::unix::with_terminal(pty)(&mut command);
    let mut victim = command.spawn().unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(victim.stderr.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.starts_with("await-signal ready"), "{ready:?}");
    victim
}

/// Runs sandy with `args` and `stdin` as its standard input.
fn run_with_stdin(args: &[String], stdin: Stdio) -> Output {
    Command::new(sandy_path())
        .args(args)
        .stdin(stdin)
        .output()
        .unwrap()
}

/// Checks that sandy refused to start the program, and why.
#[track_caller]
fn assert_refused(output: &Output, reason: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(EXIT_FAILURE),
        "sandy did not refuse the stream; it printed {stdout:?} and {stderr:?}"
    );
    assert!(stderr.contains(reason), "{stderr}");
    assert!(stdout.is_empty(), "the program must not run: {stdout}");
}

/// The next datagram, or `None` when none arrives within `timeout`.
fn datagram(listener: &UdpSocket, timeout: Duration) -> Option<Vec<u8>> {
    listener.set_read_timeout(Some(timeout)).unwrap();
    let mut buffer = [0u8; 128];
    let (read, _) = listener.recv_from(&mut buffer).ok()?;
    Some(buffer[..read].to_vec())
}

/// A lock needs only a descriptor or handle opened for reading, so the program can lock a file it
/// may only read, and a process outside that locks the same file fails while the program holds
/// the lock. On Windows the lock also keeps other processes from reading and writing the file.
/// It gives the program no access of its own. This records a limitation of every platform
/// document; if the lock fails inside, the platform has started to deny it.
#[test]
fn a_lock_on_a_readable_file_holds_off_other_processes() {
    use std::io::{BufRead, BufReader, Write};

    let fixture = Fixture::new("lock-read");
    let file = fixture.arg("ro/file");
    let lock = [("lock-read", file.as_str())];
    let held = [lock[0], ("sleep", "3000")];
    let mut sandy = Command::new(sandy_path())
        .args(run_args(&fixture.access_args(), &held))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(sandy.stdout.as_mut().unwrap())
        .read_line(&mut first)
        .unwrap();
    parse_line(first.trim_end()).assert_ok();

    let outside = probe_outside(&lock);
    assert_ne!(outside[0].result, "ok", "{outside:?}");
    // Linux and macOS locks are advisory, so a process that takes none still reads and writes.
    // Windows locks are mandatory: ERROR_LOCK_VIOLATION.
    let written = fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .write(b"x");
    let read = fs::read(&file);
    if cfg!(windows) {
        assert_eq!(written.unwrap_err().raw_os_error(), Some(33));
        assert_eq!(read.unwrap_err().raw_os_error(), Some(33));
    } else {
        written.unwrap();
        read.unwrap();
    }

    // Control: once the program has ended, the lock is free.
    assert!(sandy.wait().unwrap().success());
    probe_outside(&lock)[0].assert_ok();
}
