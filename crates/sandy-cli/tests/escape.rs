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
use std::net::TcpListener;
use std::process::Command;

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
