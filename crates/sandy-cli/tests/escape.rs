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
    fs::copy(sandy_path(), &copy).unwrap();
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
#[cfg(unix)]
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
#[cfg(unix)]
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
