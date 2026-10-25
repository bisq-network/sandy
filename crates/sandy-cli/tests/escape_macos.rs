//! macOS escape tests: routes out of a Seatbelt sandbox that the platform-neutral tests in
//! `escape.rs` do not cover. Each denial is checked against a control run outside the sandbox,
//! so a test cannot pass because the route was closed anyway.
//!
//! Some routes make another process do the work: LaunchServices (`open`), Apple events
//! (`osascript`) and launchd (`launchctl submit`). For them the evidence is a marker file that
//! the started process writes: outside the sandbox it must appear, inside it must not. These
//! tests need a logged-in GUI session, as on the GitHub macOS runners. If the control fails,
//! the host cannot show the route, and the test fails with that message.
#![cfg(target_os = "macos")]

mod common;

use std::ffi::{CString, c_char, c_int};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

/// Separates the program and its arguments in the target of the probe's `spawn` action.
const ARGUMENT_SEPARATOR: &str = "\u{1f}";
/// How long a control run may take to show its marker. Starting a new app bundle for the first
/// time can take several seconds.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to watch for a marker after a sandboxed attempt.
const ESCAPE_TIMEOUT: Duration = Duration::from_secs(10);
/// mDNSResponder, the name resolver; libSystem connects to it as /var/run/mDNSResponder.
const DNS_RESOLVER: &str = "/private/var/run/mDNSResponder";

/// The shared fixture plus a home directory with the places that matter on macOS.
fn home_fixture(name: &str) -> Fixture {
    let fixture = Fixture::new(&format!("macos-{name}"));
    add_home(&fixture);
    fixture
}

fn add_home(fixture: &Fixture) {
    for dir in ["home/Library/LaunchAgents", "home/Library/Keychains"] {
        fs::create_dir_all(fixture.path(dir)).unwrap();
    }
    // Stands in for the login keychain; the tests never touch the real one.
    fs::write(
        fixture.path("home/Library/Keychains/login.keychain-db"),
        b"keychain",
    )
    .unwrap();
}

/// The fixture's access options, with the fixture home as HOME.
fn home_args(fixture: &Fixture) -> Vec<String> {
    with(
        fixture.access_args(),
        &["--set-env", &format!("HOME={}", fixture.arg("home"))],
    )
}

/// An application bundle whose executable writes `marker` and exits. It has no window and no
/// Dock icon.
fn marker_app(fixture: &Fixture, name: &str, marker: &Path) -> PathBuf {
    let app = fixture.path(&format!("{name}.app"));
    let executables = app.join("Contents/MacOS");
    fs::create_dir_all(&executables).unwrap();
    let identifier = format!("sandy.escape-test.{name}.{}", std::process::id());
    fs::write(
        app.join("Contents/Info.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>marker</string>
  <key>CFBundleIdentifier</key><string>{identifier}</string>
  <key>CFBundleName</key><string>{name}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
"#
        ),
    )
    .unwrap();
    let script = executables.join("marker");
    let marker = marker.to_str().unwrap();
    assert!(!marker.contains('\''), "{marker}");
    fs::write(&script, format!("#!/bin/sh\n: > '{marker}'\n")).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    app
}

fn with(mut args: Vec<String>, extra: &[&str]) -> Vec<String> {
    args.extend(extra.iter().map(|arg| arg.to_string()));
    args
}

fn spawn_target(command: &[&str]) -> String {
    command.join(ARGUMENT_SEPARATOR)
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    path.exists()
}

/// Checks a route through which the probe makes another process write `marker`. Outside the
/// sandbox the marker must appear; inside it must not.
fn assert_route_closed(sandbox_args: &[String], command: &[&str], marker: &Path) {
    let target = spawn_target(command);
    let outside = probe_outside(&[("spawn", &target)]);
    assert!(
        wait_for(marker, CONTROL_TIMEOUT),
        "control failed: {} did not write the marker outside the sandbox, so this host cannot \
         show whether the sandbox closes the route: {outside:?}",
        command[0]
    );
    fs::remove_file(marker).unwrap();

    let inside = probe_inside(sandbox_args, &[("spawn", &target)]);
    assert!(
        !wait_for(marker, ESCAPE_TIMEOUT),
        "the sandboxed probe escaped through {}: {inside:?}",
        command[0]
    );
}

#[test]
fn launch_agents_cannot_be_written() {
    let fixture = home_fixture("launchagents");
    let agent = fixture.arg("home/Library/LaunchAgents/sandy.escape-test.plist");
    let agents = fixture.arg("home/Library/LaunchAgents");
    let actions = [("write", agent.as_str()), ("list", agents.as_str())];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();
    add_home(&fixture);

    let lines = probe_inside(&home_args(&fixture), &actions);
    lines[0].assert_blocked();
    lines[1].assert_blocked();
    assert!(!Path::new(&agent).exists());
}

#[test]
fn keychain_stand_in_cannot_be_read() {
    let fixture = home_fixture("keychain");
    let lines = controlled(
        &home_args(&fixture),
        &[
            (
                "read",
                &fixture.arg("home/Library/Keychains/login.keychain-db"),
            ),
            ("list", &fixture.arg("home/Library/Keychains")),
            ("list", &fixture.arg("home")),
        ],
    );
    for line in &lines {
        line.assert_blocked();
    }
}

#[test]
fn open_cannot_start_applications() {
    let fixture = home_fixture("open");
    let marker = fixture.path("open-marker");
    let app = marker_app(&fixture, "SandyOpenMarker", &marker);
    let args = with(home_args(&fixture), &["--read-exec", "/usr/bin/open"]);
    assert_route_closed(
        &args,
        &["/usr/bin/open", "-g", "-n", app.to_str().unwrap()],
        &marker,
    );
}

/// Apple events need LaunchServices to find and start the receiver and Mach services to deliver
/// the event. The receiver here is a marker app, because sending events to Terminal needs an
/// Automation consent that a CI runner cannot give.
#[test]
fn osascript_cannot_start_applications() {
    let fixture = home_fixture("osascript");
    let marker = fixture.path("osascript-marker");
    let app = marker_app(&fixture, "SandyOsascriptMarker", &marker);
    let script = format!("tell application {:?} to launch", app.to_str().unwrap());
    let args = with(home_args(&fixture), &["--read-exec", "/usr/bin/osascript"]);
    assert_route_closed(&args, &["/usr/bin/osascript", "-e", &script], &marker);
}

#[test]
fn launchctl_cannot_submit_jobs() {
    let fixture = home_fixture("launchctl");
    let marker = fixture.path("launchctl-marker");
    let label = format!("sandy.escape-test.launchctl.{}", std::process::id());
    let job = format!(": > '{}'", marker.to_str().unwrap());
    let args = with(home_args(&fixture), &["--read-exec", "/bin/launchctl"]);
    let remove_job = || {
        let _ = Command::new("/bin/launchctl")
            .args(["remove", &label])
            .output();
    };
    // A submitted job restarts when it exits, so remove it before the marker is checked again.
    let target = spawn_target(&[
        "/bin/launchctl",
        "submit",
        "-l",
        &label,
        "--",
        "/bin/sh",
        "-c",
        &job,
    ]);
    let outside = probe_outside(&[("spawn", &target)]);
    let shown = wait_for(&marker, CONTROL_TIMEOUT);
    remove_job();
    assert!(
        shown,
        "control failed: launchctl submit did not run the job outside the sandbox: {outside:?}"
    );
    std::thread::sleep(Duration::from_secs(1));
    let _ = fs::remove_file(&marker);

    let inside = probe_inside(&args, &[("spawn", &target)]);
    let escaped = wait_for(&marker, ESCAPE_TIMEOUT);
    remove_job();
    assert!(!escaped, "the sandboxed probe submitted a job: {inside:?}");
}

/// The resolver socket follows `ip`: name resolution is part of IP networking, also of
/// `ip = "client"`. With `unix_sockets = "all"` it is reachable like every other Unix socket, on
/// every platform.
#[test]
fn name_resolver_follows_ip() {
    let fixture = home_fixture("resolver");
    let actions = [
        ("unix-connect", DNS_RESOLVER),
        ("unix-connect", "/var/run/mDNSResponder"),
    ];
    let denied = controlled(&home_args(&fixture), &actions);
    denied[0].assert_blocked();
    denied[1].assert_blocked();

    for value in ["all", "client"] {
        let ip = with(home_args(&fixture), &["--ip", value]);
        let lines = probe_inside(&ip, &actions);
        lines[0].assert_ok();
        lines[1].assert_ok();
    }

    let unix_sockets = with(home_args(&fixture), &["--unix-sockets", "all"]);
    let lines = probe_inside(&unix_sockets, &actions);
    lines[0].assert_ok();
    lines[1].assert_ok();
}

#[test]
fn names_resolve_when_ip_is_allowed() {
    let fixture = home_fixture("resolve");
    let ip = with(home_args(&fixture), &["--ip", "all"]);
    let lines = controlled(&ip, &[("resolve", "localhost")]);
    lines[0].assert_ok();
}

#[test]
fn isolated_signals_cannot_reach_the_parent() {
    let fixture = home_fixture("signals");
    // The probe replaces sandy, so this test process is its parent.
    let parent = std::process::id().to_string();
    let isolated = with(home_args(&fixture), &["--signals", "isolated"]);
    let lines = controlled(&isolated, &[("signal", &parent)]);
    lines[0].assert_blocked();

    let any = with(home_args(&fixture), &["--signals", "any"]);
    let lines = probe_inside(&any, &[("signal", &parent)]);
    lines[0].assert_ok();
}

#[test]
fn inherited_descriptors_are_closed() {
    let fixture = home_fixture("descriptors");
    let file = fs::File::open(fixture.path("secret/file")).unwrap();
    // Rust opens files close-on-exec. Clearing the flag makes sandy inherit the descriptor, as
    // it would inherit one from a careless parent.
    // SAFETY: F_SETFD on a descriptor this test owns has no memory safety requirements.
    let cleared = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) };
    assert_eq!(cleared, 0);
    let fd = file.as_raw_fd().to_string();
    let lines = controlled(&home_args(&fixture), &[("fd-read", &fd)]);
    lines[0].assert_blocked();
    drop(file);
}

#[test]
fn setuid_programs_do_not_start() {
    let fixture = home_fixture("setuid");
    let setuid = "/usr/bin/sudo";
    let mode = fs::metadata(setuid).unwrap().permissions().mode();
    assert_ne!(mode & 0o4000, 0, "precondition: {setuid} is setuid");
    // Both programs are executable by policy, so only the setuid bit can make a difference.
    let args = with(
        home_args(&fixture),
        &["--read-exec", setuid, "--read-exec", "/usr/bin/true"],
    );
    let lines = controlled(&args, &[("exec", "/usr/bin/true"), ("exec", setuid)]);
    lines[0].assert_ok();
    lines[1].assert_blocked();
}

#[test]
fn children_inherit_the_sandbox() {
    let fixture = home_fixture("children");
    let child = fixture.copy_probe("bin");
    let secret_new = fixture.arg("secret/new");
    let target = spawn_target(&[&child, "write", &secret_new]);
    for line in probe_outside(&[("spawn", &target)]) {
        line.assert_ok();
    }
    assert!(fixture.path("secret/new").exists());
    fs::remove_file(fixture.path("secret/new")).unwrap();

    let lines = probe_inside(&home_args(&fixture), &[("spawn", &target)]);
    lines[0].assert_ok();
    assert!(!fixture.path("secret/new").exists());
}

/// Copies and clones work inside writable paths and from readable ones, but never bring a file
/// from outside the policy into a writable path or create one outside it. Hard links are denied
/// everywhere. All results are collected first, so one run shows the whole picture.
#[test]
fn clones_and_links_stay_inside_the_policy() {
    let fixture = home_fixture("clone");
    let pair = |from: &str, to: &str| {
        format!(
            "{}{ARGUMENT_SEPARATOR}{}",
            fixture.arg(from),
            fixture.arg(to)
        )
    };
    let cases = [
        ("copy", pair("rw/file", "rw/copied"), true),
        ("copy", pair("ro/file", "rw/copied-from-ro"), true),
        ("clone", pair("rw/file", "rw/cloned"), true),
        ("clone", pair("secret/file", "rw/stolen"), false),
        ("clone", pair("rw/file", "secret/planted"), false),
        ("clone", pair("ro/file", "ro/planted"), false),
        ("hardlink", pair("secret/file", "rw/linked-secret"), false),
        ("hardlink", pair("rw/file", "rw/linked"), false),
    ];
    let actions: Vec<(&str, &str)> = cases
        .iter()
        .map(|(action, target, _)| (*action, target.as_str()))
        .collect();
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();
    add_home(&fixture);

    let lines = probe_inside(&home_args(&fixture), &actions);
    let wrong: Vec<String> = cases
        .iter()
        .zip(&lines)
        .filter(|((_, _, allowed), line)| (line.result == "ok") != *allowed)
        .map(|((action, target, allowed), line)| {
            let target = target.replace(ARGUMENT_SEPARATOR, " -> ");
            format!(
                "{action} {target}: expected allowed={allowed}, got {} {}",
                line.result, line.detail
            )
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for leaked in [
        "rw/stolen",
        "secret/planted",
        "ro/planted",
        "rw/linked-secret",
    ] {
        assert!(!fixture.path(leaked).exists(), "{leaked} exists");
    }
}

/// A process outside the sandbox, attached the way debuggers attach. macOS lets a process of the
/// same user attach only to a program signed with the get-task-allow entitlement, so the victim
/// is a copy of the probe signed that way. If the host refuses the attach outside the sandbox
/// anyway, nothing can be checked and the test records a skip.
#[test]
fn ptrace_cannot_attach_outside_the_sandbox() {
    let fixture = home_fixture("ptrace");
    let victim_path = fixture.copy_probe("secret");
    let entitlements = fixture.path("secret/entitlements.plist");
    fs::write(
        &entitlements,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
"#,
    )
    .unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&entitlements)
        .arg(&victim_path)
        .output()
        .unwrap();
    assert!(signed.status.success(), "codesign failed: {signed:?}");
    let victim = || {
        Command::new(&victim_path)
            .args(["sleep", "60000"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap()
    };

    let mut outside_victim = victim();
    let outside = probe_outside(&[("ptrace-attach", &outside_victim.id().to_string())]);
    let _ = outside_victim.kill();
    let _ = outside_victim.wait();
    if outside[0].result != "ok" {
        skip(
            "ptrace",
            &format!(
                "this host refuses ptrace attach outside the sandbox: {}",
                outside[0].detail
            ),
        );
        return;
    }

    let mut inside_victim = victim();
    let lines = probe_inside(
        &home_args(&fixture),
        &[("ptrace-attach", &inside_victim.id().to_string())],
    );
    let _ = inside_victim.kill();
    let _ = inside_victim.wait();
    lines[0].assert_blocked();
}

/// The root of a writable path can be written in place, but not deleted, moved or replaced:
/// otherwise the program could put a symbolic link in its place, and the next run would resolve
/// the path to the link's target. Every action below is allowed by the other rules of the
/// profile (both ends lie in writable paths), so only the anchor rule can deny it.
#[test]
fn writable_roots_cannot_be_deleted_or_replaced() {
    let fixture = Fixture::new("macos-anchors");
    let prepare = || {
        fixture.reset();
        fs::create_dir_all(fixture.path("rw2/sub")).unwrap();
        fs::create_dir_all(fixture.path("rw3")).unwrap();
        fs::write(fixture.path("wfile"), b"content").unwrap();
        fs::write(fixture.path("rw/other"), b"other").unwrap();
    };
    prepare();
    let args = with(
        fixture.access_args(),
        &[
            "--read-write",
            &fixture.arg("rw2"),
            "--read-write",
            &fixture.arg("rw3"),
            "--read-write",
            &fixture.arg("wfile"),
        ],
    );
    let pair = |from: &str, to: &str| spawn_target(&[&fixture.arg(from), &fixture.arg(to)]);
    let (wfile, rw3) = (fixture.arg("wfile"), fixture.arg("rw3"));
    let (move_dir, over_file) = (pair("rw2", "rw/moved"), pair("rw/other", "wfile"));
    let actions = [
        ("write", wfile.as_str()),
        ("rename", move_dir.as_str()),
        ("rmdir", rw3.as_str()),
        ("rename", over_file.as_str()),
        ("delete", wfile.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    prepare();

    let lines = probe_inside(&args, &actions);
    lines[0].assert_ok();
    for line in &lines[1..] {
        line.assert_blocked();
    }
    for root in ["rw2/sub", "rw3", "wfile", "rw/other"] {
        assert!(fixture.path(root).exists(), "{root} was moved or deleted");
    }
}

/// macOS ignores a second profile, so sandy inside a sandbox must refuse instead of starting a
/// program that would be confined only by the outer profile.
#[test]
fn sandy_refuses_to_run_inside_a_sandbox() {
    let fixture = Fixture::new("macos-nested");
    let inner = fixture.path("bin/sandy");
    copy_executable(sandy_path(), &inner);
    let inner = inner.to_str().unwrap().to_string();
    let probe = fixture.copy_probe("bin");
    let readable = fixture.arg("ro/file");
    // A program that only reads a file the policy grants, so it needs nothing from the host.
    let mut inner_run = vec!["run".to_string()];
    inner_run.extend(fixture.access_args());
    inner_run.extend([probe, "read".to_string(), readable]);
    // Control: outside a sandbox the copy runs the program.
    let output = Command::new(&inner).args(&inner_run).output().unwrap();
    assert!(output.status.success(), "control: {output:?}");
    parse(&output)[0].assert_ok();

    let mut outer = vec!["run".to_string()];
    outer.extend(fixture.access_args());
    outer.extend(["--".to_string(), inner]);
    let output = sandy(outer.iter().chain(&inner_run));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(parse(&output).is_empty(), "the program started: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already runs in a Seatbelt sandbox"),
        "{output:?}"
    );
}

/// sandy's Rust runtime ignores SIGPIPE; the target must start with the default action again.
/// Every other disposition the caller set (here SIGHUP ignored, as nohup does) must survive.
/// The probe records its dispositions before its own Rust runtime changes SIGPIPE.
#[test]
fn signal_dispositions_pass_through_except_sigpipe() {
    let fixture = home_fixture("dispositions");
    let actions = [("signal-disposition", "1"), ("signal-disposition", "13")];
    let ignoring_sighup = |program: String, args: Vec<String>| {
        let mut command = Command::new(program);
        command.args(args);
        // SAFETY: signal(2) is async-signal-safe, so it may run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            });
        }
        command.output().unwrap()
    };

    let outside = parse(&ignoring_sighup(probe_path(), probe_args(&actions)));
    assert_eq!(outside[0].detail, "ignore", "control: {outside:?}");

    let output = ignoring_sighup(sandy_path(), run_args(&home_args(&fixture), &actions));
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(
        (lines[0].result.as_str(), lines[0].detail.as_str()),
        ("ok", "ignore"),
        "SIGHUP ignored by the caller must stay ignored"
    );
    assert_eq!(
        (lines[1].result.as_str(), lines[1].detail.as_str()),
        ("ok", "default"),
        "SIGPIPE must start with the default action"
    );
}

unsafe extern "C" {
    /// Asks whether process `pid` may perform `operation` under its Seatbelt profile; returns 1
    /// for a denial. Exported by libSystem; sandy's backend loads it the same way.
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
}

/// `sandbox_check` filter type for a path argument.
const SANDBOX_FILTER_PATH: c_int = 1;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The probe as a server on `inner` in the sandbox, with sandy relaying `outer` to it.
fn start_exposed_server(fixture: &Fixture, inner: u16, outer: u16) -> Child {
    start_exposed_server_with(fixture, inner, outer, &[])
}

/// Like `start_exposed_server`, with more sandbox options.
fn start_exposed_server_with(fixture: &Fixture, inner: u16, outer: u16, extra: &[&str]) -> Child {
    let mut args = with(
        home_args(fixture),
        &[
            "--ip",
            "all",
            "--expose",
            &format!("127.0.0.1:{outer}={inner}"),
        ],
    );
    args.extend(extra.iter().map(|arg| arg.to_string()));
    let accept = format!("127.0.0.1:{inner}");
    Command::new(sandy_path())
        .args(run_args(&args, &[("tcp-accept", &accept)]))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Waits until sandy has become the probe, so the program, not sandy, runs under its PID.
fn wait_for_program(pid: u32) {
    let start = Instant::now();
    loop {
        let output = Command::new("/bin/ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&output.stdout)
            .trim()
            .ends_with("sandy-probe")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "sandy never became the program");
        std::thread::sleep(Duration::from_millis(50));
    }
}

const WAIT: Duration = Duration::from_secs(20);

/// The one process that listens on `port`, found with lsof.
fn listener_pid(port: u16) -> libc::pid_t {
    let start = Instant::now();
    loop {
        let output = Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let pids: Vec<libc::pid_t> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
        if pids.len() == 1 {
            return pids[0];
        }
        assert!(
            start.elapsed() < WAIT,
            "no single listener on {port}: {text:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parent_of(pid: libc::pid_t) -> libc::pid_t {
    let output = Command::new("/bin/ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse()
        .unwrap_or_else(|_| panic!("no parent for {pid}: {text:?}"))
}

/// Lets the sandboxed server accept one connection through the relay and finish.
fn finish_server(server: Child, outer: u16) -> std::process::Output {
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    let mut server = server;
    let start = Instant::now();
    while server.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < WAIT, "the server never accepted");
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(200));
    }
    server.wait_with_output().unwrap()
}

/// The relay of an exposed port runs outside the program's sandbox, so it must not be the
/// program's child (the program could reap it or signal it as its own), the program must not hold
/// the relay's listener, and the relay's own profile must deny files. The profile is asked from
/// outside with sandbox_check, which reports what the relay's sandbox would decide.
#[test]
fn relay_is_confined_and_not_a_child_of_the_program() {
    let fixture = home_fixture("relay");
    let (inner, outer) = (free_port(), free_port());
    let server = start_exposed_server(&fixture, inner, outer);
    let program = server.id() as libc::pid_t;
    wait_for_program(server.id());
    let relay = listener_pid(outer);
    assert_ne!(relay, program, "the program holds the relay's listener");
    assert_ne!(
        parent_of(relay),
        program,
        "the relay is a child of the program"
    );

    let secret = CString::new(fixture.arg("secret/file")).unwrap();
    let readable = CString::new(fixture.arg("ro/file")).unwrap();
    // SAFETY: a null operation asks only whether the process is sandboxed.
    let sandboxed = unsafe { sandbox_check(relay, std::ptr::null(), 0) };
    // SAFETY: the operation and the path are NUL-terminated strings that outlive the calls.
    let (secret_denied, readable_denied) = unsafe {
        (
            sandbox_check(
                relay,
                c"file-read-data".as_ptr(),
                SANDBOX_FILTER_PATH,
                secret.as_ptr(),
            ),
            sandbox_check(
                relay,
                c"file-read-data".as_ptr(),
                SANDBOX_FILTER_PATH,
                readable.as_ptr(),
            ),
        )
    };
    let output = finish_server(server, outer);
    assert_eq!(sandboxed, 1, "the relay is not sandboxed");
    assert_eq!(
        secret_denied, 1,
        "the relay may read files outside the policy"
    );
    assert_eq!(readable_denied, 1, "the relay may read the program's files");
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();
}

/// The relay watches the program's process ID with kqueue, so it ends even when the program is
/// killed without any chance to clean up.
#[test]
fn relay_ends_when_the_program_is_killed() {
    let fixture = home_fixture("relay-kill");
    let (inner, outer) = (free_port(), free_port());
    let mut server = start_exposed_server(&fixture, inner, outer);
    wait_for_program(server.id());
    let relay = listener_pid(outer);
    // SAFETY: kill with signal 0 only checks that the process exists.
    let running = unsafe { libc::kill(relay, 0) } == 0;
    assert!(running, "the relay is not running");

    server.kill().unwrap();
    server.wait().unwrap();
    let start = Instant::now();
    // SAFETY: as above.
    while unsafe { libc::kill(relay, 0) } == 0 {
        assert!(start.elapsed() < WAIT, "the relay outlived the program");
        std::thread::sleep(Duration::from_millis(100));
    }
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
}

/// A loopback service outside the sandbox that counts the connections it accepts.
fn counting_service() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (port, count)
}

/// The forward relay leads only to the forwarded address: a second service outside, on another
/// port, never sees a connection through it. The relay's profile allows network-outbound only to
/// the target ports (unit-tested); sandbox_check has no filter for network addresses, so this
/// test checks the routing.
#[test]
fn forward_relay_reaches_only_the_forward_target() {
    use std::sync::atomic::Ordering;
    let fixture = home_fixture("forward-only");
    let (target, target_count) = counting_service();
    let (other, other_count) = counting_service();
    let inner = free_port();
    let args = with(
        home_args(&fixture),
        &[
            "--ip",
            "all",
            "--forward",
            &format!("{inner}=127.0.0.1:{target}"),
        ],
    );
    let inner_address = format!("127.0.0.1:{inner}");
    let lines = probe_inside(
        &args,
        &[
            ("tcp-connect", inner_address.as_str()),
            ("tcp-connect", inner_address.as_str()),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
    let start = Instant::now();
    while target_count.load(Ordering::SeqCst) < 2 {
        assert!(
            start.elapsed() < WAIT,
            "the forwarded service saw too few connections"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        other_count.load(Ordering::SeqCst),
        0,
        "port {other} was reached through the relay"
    );
}

/// The forward relay listens on the program's loopback port outside the sandbox and ends with
/// the program, also when the program is killed with SIGKILL.
#[test]
fn forward_relay_ends_when_the_program_is_killed() {
    let fixture = home_fixture("forward-kill");
    let (target, _) = counting_service();
    let inner = free_port();
    let args = with(
        home_args(&fixture),
        &[
            "--ip",
            "all",
            "--forward",
            &format!("{inner}=127.0.0.1:{target}"),
        ],
    );
    let mut program = Command::new(sandy_path())
        .args(run_args(&args, &[("sleep", "60000")]))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_program(program.id());
    let relay = listener_pid(inner);
    assert_ne!(
        relay,
        program.id() as libc::pid_t,
        "the program holds the relay's listener"
    );
    assert_ne!(
        parent_of(relay),
        program.id() as libc::pid_t,
        "the relay is the program's child"
    );

    program.kill().unwrap();
    program.wait().unwrap();
    let start = Instant::now();
    // SAFETY: kill with signal 0 only checks that the process exists.
    while unsafe { libc::kill(relay, 0) } == 0 {
        assert!(start.elapsed() < WAIT, "the relay outlived the program");
        std::thread::sleep(Duration::from_millis(100));
    }
    let address = format!("127.0.0.1:{inner}").parse().unwrap();
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
}

/// Rule 5 of "Forwarded ports" in DESIGN.md: when the program ends, the relay closes its
/// listeners at once. The drain of one second applies only to connections it already accepted,
/// so a connection attempt shortly after the program ended must be refused.
#[test]
fn relay_stops_listening_as_soon_as_the_program_ends() {
    let fixture = home_fixture("relay-stop");
    let (inner, outer) = (free_port(), free_port());
    let server = start_exposed_server(&fixture, inner, outer);
    let output = finish_server(server, outer);
    assert!(output.status.success(), "{output:?}");
    std::thread::sleep(Duration::from_millis(300));
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "the relay still accepts after the program ended"
    );
}

/// What the probe's tcp-send action writes.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";

/// Accepts one connection and returns everything it receives, or nothing after the deadline.
fn receive_one(listener: TcpListener) -> std::thread::JoinHandle<Vec<u8>> {
    use std::io::Read;
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let start = Instant::now();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(WAIT)).unwrap();
                    let mut data = Vec::new();
                    let _ = stream.read_to_end(&mut data);
                    return data;
                }
                Err(_) if start.elapsed() < WAIT => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return Vec::new(),
            }
        }
    })
}

/// The drain of rule 5: a program that connects through a forwarded port, writes and exits at
/// once does not lose its data.
#[test]
fn forward_relay_delivers_data_sent_just_before_exit() {
    let fixture = home_fixture("forward-drain");
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = service.local_addr().unwrap().port();
    let received = receive_one(service);
    let inner = free_port();
    let args = with(
        home_args(&fixture),
        &[
            "--ip",
            "all",
            "--forward",
            &format!("{inner}=127.0.0.1:{target}"),
        ],
    );
    let lines = probe_inside(&args, &[("tcp-send", &format!("127.0.0.1:{inner}"))]);
    lines[0].assert_ok();
    assert_eq!(received.join().unwrap(), TCP_SEND_PAYLOAD);
}

/// What a relay serves once it is continued after a stop. With the default `signals = "any"`
/// the program can stop its relay, and nothing on macOS ends a stopped relay (docs/macos.md).
/// While it is stopped, the kernel completes the handshakes for its listener: the program's own
/// connection before it ends, and a client's after. The continued relay accepts the whole
/// backlog of a listener that became ready before the end, so it serves both. This records
/// that: the connection made after the end reaches the forwarded service.
#[test]
fn a_continued_relay_serves_a_connection_made_after_the_program_ended() {
    use std::io::{Read, Write};
    let fixture = home_fixture("relay-continued");
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = service.local_addr().unwrap().port();
    let (sender, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for mut stream in service.incoming().flatten() {
            let mut data = Vec::new();
            let _ = stream.read_to_end(&mut data);
            let _ = sender.send(data);
        }
    });
    let inner = free_port();
    let address = format!("127.0.0.1:{inner}");
    let args = with(
        home_args(&fixture),
        &[
            "--ip",
            "all",
            "--forward",
            &format!("{inner}=127.0.0.1:{target}"),
        ],
    );
    // The program waits until the test has stopped the relay, then connects, sends and ends.
    let program = Command::new(sandy_path())
        .args(run_args(
            &args,
            &[("sleep", "3000"), ("tcp-send", address.as_str())],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // sandy binds the listener before it starts the relay, so lsof can name sandy itself until
    // sandy has become the program.
    wait_for_program(program.id());
    let relay = listener_pid(inner);
    assert_ne!(
        relay,
        program.id() as libc::pid_t,
        "the program holds the listener"
    );
    // SAFETY: kill takes a process ID and a signal.
    unsafe { libc::kill(relay, libc::SIGSTOP) };
    let output = program.wait_with_output().unwrap();
    let lines = parse(&output);
    assert_eq!(lines.len(), 2, "{output:?}");
    lines[1].assert_ok();

    let mut late = TcpStream::connect(&address).unwrap();
    late.write_all(b"late").unwrap();
    late.shutdown(std::net::Shutdown::Write).unwrap();
    // SAFETY: as above.
    unsafe { libc::kill(relay, libc::SIGCONT) };
    let start = Instant::now();
    // SAFETY: kill with signal 0 only checks that the process exists.
    while unsafe { libc::kill(relay, 0) } == 0 {
        assert!(start.elapsed() < WAIT, "the continued relay did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut served = Vec::new();
    while served.len() < 2 {
        match received.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(data) => served.push(data),
            Err(_) => break,
        }
    }
    drop(late);
    assert!(
        served.iter().any(|data| data == TCP_SEND_PAYLOAD),
        "the program's own connection was lost: {served:?}"
    );
    assert!(
        served.iter().any(|data| data == b"late"),
        "the continued relay no longer serves a connection made after the program ended; the \
         documented limitation is stale: {served:?}"
    );
}

/// `process.children = "none"`: fork, vfork and posix_spawn (without POSIX_SPAWN_SETEXEC) all
/// fail, while threads still work. The control runs the same actions with children allowed.
#[test]
fn children_none_denies_every_way_to_create_a_process() {
    let fixture = home_fixture("children-none");
    let child = fixture.copy_probe("bin");
    let actions = [
        ("fork", "-"),
        ("vfork", "-"),
        ("posix-spawn", child.as_str()),
        ("exec", child.as_str()),
        ("thread", "-"),
    ];
    for line in probe_inside(&home_args(&fixture), &actions) {
        line.assert_ok();
    }
    let none = with(home_args(&fixture), &["--children", "none"]);
    let lines = probe_inside(&none, &actions);
    for line in &lines[..4] {
        line.assert_blocked();
    }
    lines[4].assert_ok();
}

/// Replacing the program's own image creates no process, so it stays allowed: the new image runs
/// and prints the line of its own action.
#[test]
fn children_none_still_lets_the_program_replace_itself() {
    let fixture = home_fixture("children-exec");
    let none = with(home_args(&fixture), &["--children", "none"]);
    let target = spawn_target(&[&probe_path(), "sleep", "0"]);
    let output = sandy(run_args(&none, &[("execve", &target)]));
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    assert_eq!(lines[0].action, "sleep", "{output:?}");
    lines[0].assert_ok();
}

/// sandy forks the relay before it applies the program's profile, so the relays of exposed and
/// forwarded ports keep working with `process.children = "none"`.
#[test]
fn children_none_keeps_the_relays_working() {
    let fixture = home_fixture("children-relay");
    let (inner, outer) = (free_port(), free_port());
    let server = start_exposed_server_with(&fixture, inner, outer, &["--children", "none"]);
    let output = finish_server(server, outer);
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();

    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = service.local_addr().unwrap().port();
    let received = receive_one(service);
    let inner = free_port();
    let args = with(
        home_args(&fixture),
        &[
            "--ip",
            "all",
            "--children",
            "none",
            "--forward",
            &format!("{inner}=127.0.0.1:{target}"),
        ],
    );
    let lines = probe_inside(&args, &[("tcp-send", &format!("127.0.0.1:{inner}"))]);
    lines[0].assert_ok();
    assert_eq!(received.join().unwrap(), TCP_SEND_PAYLOAD);
}

/// Whether the integer sysctl `name` is 1. A name this Mac does not know counts as 0.
fn sysctl_flag(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    let mut value: c_int = 0;
    let mut size = std::mem::size_of::<c_int>();
    // SAFETY: name is a C string; value and size describe a buffer of size bytes; no new value.
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    result == 0 && value == 1
}

/// On Apple silicon, code without an arm64 version runs through Rosetta, which cannot load its
/// runtime inside the sandbox. sandy refuses such a program before it starts, instead of starting
/// it to abort. A translated sandy refuses every program, because it would execute even universal
/// programs as x86_64.
#[test]
fn code_that_needs_rosetta_is_refused_before_it_starts() {
    if !sysctl_flag("hw.optional.arm64") {
        skip("apple-silicon", "not Apple silicon");
        return;
    }
    let fixture = Fixture::new("macos-rosetta");
    // A thin x86_64 Mach-O header is enough: sandy decides before it executes the file.
    let program = fixture.path("bin").join("x86_64-only");
    let mut header = vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01];
    header.resize(32, 0);
    fs::write(&program, header).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    // The tests and sandy are built for the same architecture.
    let reason = if sysctl_flag("sysctl.proc_translated") {
        "sandy runs as x86_64 code through Rosetta"
    } else {
        "has no arm64 code"
    };

    let with = |mode: &str, program: &str| {
        let mut args = vec![mode.to_string()];
        args.extend(fixture.access_args());
        args.extend(["--".to_string(), program.to_string()]);
        sandy(args)
    };
    let output = with("check", program.to_str().unwrap());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(reason),
        "{output:?}"
    );
    let output = with("run", program.to_str().unwrap());
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{output:?}"
    );

    // Control: a native sandy accepts the probe, which has arm64 code.
    if reason == "has no arm64 code" {
        let output = with("check", &probe_path());
        assert!(output.status.success(), "{output:?}");
    }
}

/// F_MAKECOMPRESSED (80) and F_TRANSFEREXTENTS (110) can change a file through a read-only
/// descriptor; the profile denies them. Outside the sandbox the calls reach the file system and
/// fail there for want of real arguments (ESTALE, EBADF); inside, the profile refuses them first.
#[test]
fn file_changing_fcntls_are_denied_on_read_only_descriptors() {
    let fixture = Fixture::new("macos-fcntl");
    let file = fixture.arg("ro/file");
    let targets: Vec<String> = ["80", "110"]
        .iter()
        .map(|command| format!("{file}{ARGUMENT_SEPARATOR}{command}"))
        .collect();
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|target| ("fcntl-read-only", target.as_str()))
        .collect();
    for line in probe_outside(&actions) {
        assert_eq!(line.result, "error", "control: {line:?}");
    }
    for line in probe_inside(&fixture.access_args(), &actions) {
        assert_eq!(line.result, "denied", "{line:?}");
    }
}

/// Runs the probe with `actions` inside the sandbox with `stdin` as its standard input, so a
/// test can give the program a descriptor of its own choosing.
fn probe_inside_with_stdin(
    sandbox_args: &[String],
    actions: &[(&str, &str)],
    stdin: fs::File,
) -> Vec<ProbeLine> {
    let output = Command::new(sandy_path())
        .args(run_args(sandbox_args, actions))
        .stdin(Stdio::from(stdin))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sandy run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse(&output)
}

/// Runs the probe with `actions` outside the sandbox with `stdin` as its standard input.
fn probe_outside_with_stdin(actions: &[(&str, &str)], stdin: fs::File) -> Vec<ProbeLine> {
    let output = Command::new(probe_path())
        .args(probe_args(actions))
        .stdin(Stdio::from(stdin))
        .output()
        .unwrap();
    assert!(output.status.success(), "probe failed outside: {output:?}");
    parse(&output)
}

/// `/dev/fd/N` and the links `/dev/stdin`, `/dev/stdout` and `/dev/stderr` name the program's
/// own open descriptors. Opening one duplicates the descriptor instead of opening the file
/// again, so it reaches nothing the program does not already hold.
#[test]
fn descriptor_paths_name_the_programs_own_descriptors() {
    let fixture = Fixture::new("macos-devfd");
    // Both paths lead to descriptor 0 and share its file offset, so only the first read of the
    // two sees the content.
    let actions = [
        ("list", "/dev/fd"),
        ("read", "/dev/fd/0"),
        ("read", "/dev/stdin"),
    ];
    let open = || fs::File::open(fixture.path("ro/file")).unwrap();

    for line in probe_outside_with_stdin(&actions, open()) {
        line.assert_ok();
    }
    let inside = probe_inside_with_stdin(&fixture.access_args(), &actions, open());
    for line in &inside {
        line.assert_ok();
    }
    assert_eq!(inside[1].detail, "7 bytes", "{inside:?}");
}

/// A descriptor path cannot widen access: writing through `/dev/fd/0` of a read-only descriptor
/// fails in the kernel (`dupfdopen` refuses a mode the original descriptor lacks), inside the
/// sandbox and outside it alike.
#[test]
fn a_descriptor_path_grants_no_more_than_the_descriptor() {
    let fixture = Fixture::new("macos-devfd-write");
    let actions = [("write", "/dev/fd/0")];
    let open = || fs::File::open(fixture.path("rw/file")).unwrap();

    probe_outside_with_stdin(&actions, open())[0].assert_blocked();
    probe_inside_with_stdin(&fixture.access_args(), &actions, open())[0].assert_blocked();
    assert_eq!(fs::read(fixture.path("rw/file")).unwrap(), b"content");
}

/// A descriptor path does reach the file behind the descriptor for metadata: outside the
/// sandbox, chmod, utimes, chflags and setattrlist on `/dev/fd/0` change the file that a
/// read-only standard input names. Seatbelt judges these calls by the path of that file, not by
/// `/dev/fd` (measured on macOS 26.5: granting the tree `file-write*` changes nothing), so inside
/// the sandbox they stay denied for a file the policy only lets the program read, and work for
/// one in a writable path.
#[test]
fn a_descriptor_path_changes_no_metadata() {
    use std::os::macos::fs::MetadataExt;
    let fixture = Fixture::new("macos-devfd-metadata");
    let actions = [
        ("set-readonly", "/dev/fd/0"),
        ("utimes-set", "/dev/fd/0"),
        ("chflags-set", "/dev/fd/0"),
        ("setattr", "/dev/fd/0"),
    ];
    let open = || fs::File::open(fixture.path("ro/file")).unwrap();

    for line in probe_outside_with_stdin(&actions, open()) {
        line.assert_ok();
    }
    fixture.reset();
    let before = fs::metadata(fixture.path("ro/file")).unwrap();
    for line in probe_inside_with_stdin(&fixture.access_args(), &actions, open()) {
        line.assert_blocked();
    }
    let after = fs::metadata(fixture.path("ro/file")).unwrap();
    assert_eq!(after.st_mode(), before.st_mode());
    assert_eq!(after.st_mtime(), before.st_mtime());
    assert_eq!(after.st_flags(), before.st_flags());

    let writable = fs::File::open(fixture.path("rw/file")).unwrap();
    for line in probe_inside_with_stdin(&fixture.access_args(), &actions, writable) {
        line.assert_ok();
    }
}

/// Mach port rights are not descriptors: an exception handler port of the caller's task passes
/// through `posix_spawn` and `execve` into the program, which could then send a forged exception
/// message to the caller's crash handler. sandy resets the task's exception ports before it
/// applies the profile, the crash port that Crashpad's handler takes and the corpse notification
/// port among them. The caller keeps the receive right in a process of its own, as a crash
/// reporter does, so the control shows a live right and not a dead name.
#[test]
fn inherited_mach_exception_ports_are_reset() {
    let fixture = Fixture::new("macos-excports");
    let report = [probe_path(), "exception-ports".to_string(), "-".to_string()];
    let control = with_exception_port(&report);
    control[0].assert_ok();
    assert_ne!(
        control[0].detail, "0",
        "the control kept no exception port, so this host cannot show the route"
    );

    let mut inside = vec![sandy_path()];
    inside.extend(run_args(
        &fixture.access_args(),
        &[("exception-ports", "-")],
    ));
    let lines = with_exception_port(&inside);
    lines[0].assert_ok();
    assert_eq!(
        lines[0].detail, "0",
        "the program inherited exception handler ports"
    );
}

/// Installs a Mach exception handler port and then execs `command`, which reports what it
/// inherited.
fn with_exception_port(command: &[String]) -> Vec<ProbeLine> {
    let target = command.join(ARGUMENT_SEPARATOR);
    let output = Command::new(probe_path())
        .args(["exception-port-exec", &target])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exception-port-exec failed: {output:?}"
    );
    parse(&output)
}

/// A thin x86_64 Mach-O header at `path`, enough for sandy to judge the file without running it.
fn write_x86_64_program(path: &Path) {
    let mut header = vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01];
    header.resize(32, 0);
    fs::write(path, header).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The kernel runs a script's interpreter, so the interpreter decides whether Rosetta is needed.
/// sandy reads the `#!` line and judges that file, as it does for the program itself.
#[test]
fn a_script_with_an_x86_64_interpreter_is_refused_before_it_starts() {
    if !sysctl_flag("hw.optional.arm64") || sysctl_flag("sysctl.proc_translated") {
        skip(
            "apple-silicon",
            "the interpreter is only judged on Apple silicon that runs sandy natively",
        );
        return;
    }
    let fixture = Fixture::new("macos-rosetta-script");
    let interpreter = fixture.path("bin").join("x86_64-only");
    write_x86_64_program(&interpreter);
    let script = fixture.path("bin").join("script");
    fs::write(&script, format!("#!{}\n", interpreter.display())).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let mut args = vec!["check".to_string()];
    args.extend(fixture.access_args());
    args.extend(["--".to_string(), script.to_str().unwrap().to_string()]);
    let output = sandy(args);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("has no arm64 code"), "{report}");
    assert!(
        report.contains(interpreter.to_str().unwrap()),
        "the reason does not name the interpreter: {report}"
    );
}

/// What `check` returns when this host cannot enforce a requirement of the policy.
const EXIT_NOT_ENFORCEABLE: i32 = 1;

/// The minimal system set is compared like the policy paths: /System/Volumes/Data/private/etc
/// is a second name of /private/etc, which holds entries of the set, so a writable path on it is
/// refused like `--read-write /private/etc`. A comparison of path prefixes does not see it,
/// because the firmlink is no symbolic link and `canonicalize` keeps the spelling.
#[test]
fn refuses_a_writable_firmlink_spelling_of_a_system_set_directory() {
    let alias = "/System/Volumes/Data/private/etc";
    if !Path::new(alias).exists() {
        return skip(
            "data-volume-firmlink",
            "this host has no /System/Volumes/Data spelling of /private",
        );
    }
    let output = sandy(["check", "--read-write", alias]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(EXIT_NOT_ENFORCEABLE), "{report}");
    assert!(report.contains("minimal system set"), "{report}");
}

/// Seatbelt matches a path through the firmlink, so a policy path spelled through the data
/// volume grants nothing, under either spelling. This records the limitation in docs/macos.md;
/// the control grants the same directory under its own name.
#[test]
fn a_policy_path_through_the_data_volume_grants_nothing() {
    let fixture = Fixture::new("macos-data-volume");
    let alias = format!("/System/Volumes/Data{}", fixture.arg("rw"));
    if !Path::new(&alias).exists() {
        return skip(
            "data-volume-firmlink",
            "this host has no /System/Volumes/Data spelling of the fixture",
        );
    }
    let plain = fixture.path("rw/plain").to_str().unwrap().to_string();
    let through = format!("{alias}/through");
    let actions = [("write", plain.as_str()), ("write", through.as_str())];
    for line in probe_inside(
        &with(Vec::new(), &["--read-write", &fixture.arg("rw")]),
        &actions,
    ) {
        line.assert_ok();
    }
    for line in probe_inside(&with(Vec::new(), &["--read-write", &alias]), &actions) {
        assert_eq!(
            line.result, "denied",
            "a data volume spelling grants access now; the documented limitation is stale: \
             {line:?}"
        );
    }
}

/// `check` with the environment the trusted locations are read from: a home directory and a PATH
/// of the test's own, so the result does not depend on the account that runs the suite.
fn check_with_environment(home: &str, path: &str, writable: &str) -> std::process::Output {
    Command::new(sandy_path())
        .args(["check", "--read-write", writable])
        .env("HOME", home)
        .env("PATH", path)
        .output()
        .unwrap()
}

/// A writable path that holds the home directory lets the program write a launch agent, which
/// launchd starts at the next login outside the sandbox, or a zsh startup file (README rule 8).
/// sandy refuses such a policy; a directory below the home directory stays writable.
#[test]
fn refuses_a_writable_path_over_the_home_directory() {
    let fixture = home_fixture("trusted-home");
    let check = |writable: &str| check_with_environment(&fixture.arg("home"), "/usr/bin", writable);

    for writable in ["home", "home/Library"] {
        let refused = check(&fixture.arg(writable));
        let report = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(
            refused.status.code(),
            Some(EXIT_NOT_ENFORCEABLE),
            "{report}"
        );
        assert!(report.contains("runs outside the sandbox"), "{report}");
    }

    let allowed = check(&fixture.arg("home/Library/Keychains"));
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
}

/// Checks each `(location, beside)` pair of paths below the fixture's home directory, with that
/// directory as HOME: a writable path that is the location is refused, and the path beside it,
/// the control, is accepted.
fn assert_refused_beside_an_accepted_path(fixture: &Fixture, cases: &[(&str, &str)]) {
    for (location, beside) in cases {
        let check = |name: &str| {
            check_with_environment(
                &fixture.arg("home"),
                "/usr/bin",
                &fixture.arg(&format!("home/{name}")),
            )
        };
        let refused = check(location);
        let report = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(
            refused.status.code(),
            Some(EXIT_NOT_ENFORCEABLE),
            "{location}: {report}"
        );
        assert!(report.contains("runs outside the sandbox"), "{report}");

        let allowed = check(beside);
        assert_eq!(
            allowed.status.code(),
            Some(0),
            "{beside}: {}",
            String::from_utf8_lossy(&allowed.stdout)
        );
    }
}

/// The startup files of bash and fish and the git configuration run code outside the sandbox at
/// the next shell or git command, on macOS as on Linux (README rule 8): Terminal.app starts login
/// shells, which read `.bash_login`. sandy refuses a writable path that reaches one, also
/// `~/.config`, which holds the fish and git configuration; the path beside each stays writable.
#[test]
fn refuses_a_writable_path_over_a_shell_or_git_startup_file() {
    let fixture = home_fixture("trusted-tools");
    let files = [
        (".bash_login", ".bash_history"),
        (".bash_logout", ".bash_history"),
        (".bash_aliases", ".bash_history"),
        (".gitconfig", ".gitignore"),
    ];
    let directories = [
        (".config", ".cache"),
        (".config/fish", ".config/other"),
        (".config/git", ".config/other"),
        (".bashrc.d", "data"),
    ];
    for (location, beside) in files {
        fs::write(fixture.path(&format!("home/{location}")), b"").unwrap();
        fs::write(fixture.path(&format!("home/{beside}")), b"").unwrap();
    }
    for (location, beside) in directories {
        fs::create_dir_all(fixture.path(&format!("home/{location}"))).unwrap();
        fs::create_dir_all(fixture.path(&format!("home/{beside}"))).unwrap();
    }
    assert_refused_beside_an_accepted_path(&fixture, &files);
    assert_refused_beside_an_accepted_path(&fixture, &directories);
}

/// A directory on PATH inside a writable path lets the program leave a command there that the
/// user runs outside the sandbox by name. Such a policy is ordinary work, so sandy enforces it
/// and warns, naming the directory (README rule 8). The same writable path without that PATH
/// entry says nothing.
#[test]
fn warns_about_a_writable_path_that_holds_a_directory_on_path() {
    let fixture = home_fixture("trusted-path");
    fs::create_dir_all(fixture.path("rw/bin")).unwrap();
    let check = |path: &str| check_with_environment(&fixture.arg("home"), path, &fixture.arg("rw"));

    let warned = check(&format!("{}:/usr/bin", fixture.arg("rw/bin")));
    let report = String::from_utf8_lossy(&warned.stdout);
    let warnings = String::from_utf8_lossy(&warned.stderr);
    assert_eq!(warned.status.code(), Some(0), "{report}{warnings}");
    let names_it =
        |line: &str| line.starts_with("warning: ") && line.contains(&fixture.arg("rw/bin"));
    assert!(warnings.lines().any(names_it), "{warnings}");

    let quiet = check("/usr/bin");
    let warnings = String::from_utf8_lossy(&quiet.stderr);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(!warnings.contains(&fixture.arg("rw/bin")), "{warnings}");
}

/// A service or a desktop application starts sandy with a minimal PATH, while the user's shell
/// looks for commands in `~/.local/bin`, `~/bin` and cargo's `bin` directory. sandy warns about a
/// writable path that holds one of them although its own PATH lacks it, and the advice keeps the
/// directory out of the writable paths. The path beside each says nothing.
#[test]
fn warns_about_a_usual_bin_directory_that_is_not_on_sandys_path() {
    let fixture = home_fixture("trusted-usual-path");
    let cases = [
        (".local/bin", ".local/opt"),
        ("bin", "data"),
        (".cargo/bin", ".cargo/registry"),
    ];
    for (directory, beside) in cases {
        fs::create_dir_all(fixture.path(&format!("home/{directory}"))).unwrap();
        fs::create_dir_all(fixture.path(&format!("home/{beside}"))).unwrap();
    }
    let check = |name: &str| {
        check_with_environment(
            &fixture.arg("home"),
            "/usr/bin",
            &fixture.arg(&format!("home/{name}")),
        )
    };
    for (directory, beside) in cases {
        let bin = fixture.arg(&format!("home/{directory}"));
        let warned = check(directory);
        let warnings = String::from_utf8_lossy(&warned.stderr);
        assert_eq!(
            warned.status.code(),
            Some(0),
            "{directory}: {}{warnings}",
            String::from_utf8_lossy(&warned.stdout)
        );
        let names_it = |line: &str| {
            line.starts_with("warning: ")
                && line.contains(&bin)
                && line.contains("make only the subdirectories the program needs writable")
        };
        assert!(warnings.lines().any(names_it), "{warnings}");

        let quiet = check(beside);
        let warnings = String::from_utf8_lossy(&quiet.stderr);
        assert_eq!(quiet.status.code(), Some(0), "{beside}: {warnings}");
        assert!(!warnings.contains(&bin), "{warnings}");
    }
}

/// A writable path that holds a directory on PATH and a location that is refused stays refused:
/// the warning never replaces the refusal.
#[test]
fn refuses_a_writable_path_that_holds_a_directory_on_path_and_a_launch_agent_folder() {
    let fixture = home_fixture("trusted-both");
    fs::create_dir_all(fixture.path("home/bin")).unwrap();
    let refused = check_with_environment(
        &fixture.arg("home"),
        &format!("{}:/usr/bin", fixture.arg("home/bin")),
        &fixture.arg("home"),
    );
    let report = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(
        refused.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{report}"
    );
    assert!(report.contains("runs outside the sandbox"), "{report}");
    // The directory on PATH is warned about as well, so the refusal did win over a warning.
    let warnings = String::from_utf8_lossy(&refused.stderr);
    let names_it =
        |line: &str| line.starts_with("warning: ") && line.contains(&fixture.arg("home/bin"));
    assert!(warnings.lines().any(names_it), "{warnings}");
}
