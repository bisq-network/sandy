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

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    let script = format!("Application({:?}).activate()", app.to_str().unwrap());
    let args = with(home_args(&fixture), &["--read-exec", "/usr/bin/osascript"]);
    assert_route_closed(
        &args,
        &["/usr/bin/osascript", "-l", "JavaScript", "-e", &script],
        &marker,
    );
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

/// The resolver socket follows `ip`: name resolution is part of IP networking. With
/// `unix_sockets = "all"` it is reachable like every other Unix socket, on every platform.
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

    let ip = with(home_args(&fixture), &["--ip", "all"]);
    let lines = probe_inside(&ip, &actions);
    lines[0].assert_ok();
    lines[1].assert_ok();

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
