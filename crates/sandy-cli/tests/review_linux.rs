//! Tests written during the Linux sandbox security review. They encode invariants that were
//! checked by hand and held, so a future change that breaks one is caught. Each denial has a
//! control run outside the sandbox, like the other escape tests.
#![cfg(target_os = "linux")]

mod common;

use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// The Landlock ABI of the running kernel, 0 without Landlock.
fn landlock_abi() -> i64 {
    // SAFETY: with a null attribute, size 0 and the VERSION flag the kernel only returns the ABI.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    abi.max(0)
}

/// A process outside the sandbox that waits for SIGUSR1 and exits with code 42 when it gets it.
/// It is killed when dropped.
struct Victim(Child);

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_victim() -> Victim {
    // await-signal installs a SIGUSR1 (10) handler and exits 42 on delivery, else exits after 5s.
    let child = Command::new(probe_path())
        .args(["await-signal", "10"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Give the child time to install the handler before it is targeted.
    sleep(Duration::from_millis(300));
    Victim(child)
}

/// Returns `Some(code)` if the victim has exited within `grace`, otherwise `None`.
fn exit_code_within(victim: &mut Victim, grace: Duration) -> Option<i32> {
    let deadline = Instant::now() + grace;
    loop {
        match victim.0.try_wait().unwrap() {
            Some(status) => return status.code(),
            None if Instant::now() < deadline => sleep(Duration::from_millis(20)),
            None => return None,
        }
    }
}

/// Signal isolation must cover the SIGIO / F_SETOWN / F_SETSIG delivery path, not only kill().
/// With `signals = any` the signal reaches the outside victim; with `isolated` it must not.
#[test]
fn sigio_signal_respects_signal_isolation() {
    if landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }

    // Control inside the sandbox with signals = any: the victim gets SIGUSR1 and exits 42.
    let mut victim = spawn_victim();
    let pid = victim.0.id().to_string();
    let target = format!("{pid}:10");
    probe_inside(&args(&["--signals", "any"]), &[("sigio-signal", &target)]);
    assert_eq!(
        exit_code_within(&mut victim, Duration::from_secs(2)),
        Some(42),
        "control: SIGIO path should deliver with signals = any"
    );
    drop(victim);

    // With signals = isolated the SIGIO path must be blocked: the victim does not get the signal.
    let mut victim = spawn_victim();
    let pid = victim.0.id().to_string();
    let target = format!("{pid}:10");
    probe_inside(
        &args(&["--signals", "isolated"]),
        &[("sigio-signal", &target)],
    );
    assert_eq!(
        exit_code_within(&mut victim, Duration::from_millis(500)),
        None,
        "SIGIO path delivered a signal to an outside process under signals = isolated"
    );
}

/// pidfd_send_signal must be covered by signal isolation as well.
#[test]
fn pidfd_send_signal_respects_signal_isolation() {
    if landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let victim = spawn_victim();
    let pid = victim.0.id().to_string();
    // Control outside: sending signal 0 via a pidfd succeeds.
    probe_outside(&[("pidfd-signal", &pid)])[0].assert_ok();
    // Inside with isolation: the permission check fails.
    probe_inside(&args(&["--signals", "isolated"]), &[("pidfd-signal", &pid)])[0].assert_blocked();
    drop(victim);
}

/// A hard link cannot bring a file from outside the policy into a writable path.
#[test]
fn hardlink_from_outside_policy_is_denied() {
    let fixture = Fixture::new("review-hardlink");
    let secret = fixture.arg("secret/file"); // outside the policy
    let leaked = fixture.arg("rw/leaked"); // inside a writable path
    let target = format!("{secret}\u{1f}{leaked}");

    // Control outside the sandbox: the hard link and the read both work.
    probe_outside(&[("hardlink", &target), ("read", &leaked)])[0].assert_ok();
    let _ = std::fs::remove_file(fixture.path("rw/leaked"));

    let lines = probe_inside(
        &fixture.access_args(),
        &[("hardlink", &target), ("read", &leaked)],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
    assert!(
        !fixture.path("rw/leaked").exists(),
        "the hard link was created"
    );
}

/// Writable paths grant no symlink or FIFO creation, so the program cannot plant a link that a
/// later start or an outside process would follow.
#[test]
fn symlink_and_fifo_in_writable_paths_are_denied() {
    let fixture = Fixture::new("review-special");
    let secret = fixture.arg("secret/file");
    let link = fixture.arg("rw/link");
    let fifo = fixture.arg("rw/fifo");
    let symlink_target = format!("{link}::{secret}");

    probe_outside(&[("symlink", &symlink_target), ("mkfifo", &fifo)])[0].assert_ok();
    let _ = std::fs::remove_file(fixture.path("rw/link"));
    let _ = std::fs::remove_file(fixture.path("rw/fifo"));

    let lines = probe_inside(
        &fixture.access_args(),
        &[("symlink", &symlink_target), ("mkfifo", &fifo)],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
}

/// `symlinks = "allow"` grants Landlock's make-symlink right on writable paths and nothing else:
/// the program can make and rename links there, a FIFO stays denied, a link in a read path too,
/// and a link to a file outside the policy leads nowhere, because Landlock checks the file a
/// link resolves to. A link to a file of the writable path works. Each call works outside.
#[test]
fn symlinks_allow_makes_links_that_reach_nothing_new() {
    let fixture = Fixture::new("review-symlinks-allow");
    let make = |link: &str, target: &str| format!("{}::{}", fixture.arg(link), fixture.arg(target));
    let outside_link = make("rw/outside", "secret/file");
    let inside_link = make("rw/inside", "rw/file");
    let read_link = make("ro/link", "ro/file");
    let fifo = fixture.arg("rw/fifo");
    // The probe takes the two paths of a rename apart at U+001F.
    let renamed = format!(
        "{}\u{1f}{}",
        fixture.arg("rw/inside"),
        fixture.arg("rw/renamed")
    );
    let actions = [
        ("symlink", outside_link.as_str()),
        ("symlink", inside_link.as_str()),
        ("symlink", read_link.as_str()),
        ("mkfifo", fifo.as_str()),
        ("rename", renamed.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();

    // The default refuses every one of them with EACCES. The rename needs a link to move, and
    // the refused link before it leaves none, so one is made outside first; the link inside then
    // takes another name, where nothing exists yet.
    std::os::unix::fs::symlink(fixture.path("rw/file"), fixture.path("rw/inside")).unwrap();
    let other_inside_link = make("rw/inside-too", "rw/file");
    let mut denied = actions;
    denied[1] = ("symlink", other_inside_link.as_str());
    for line in probe_inside(&fixture.access_args(), &denied) {
        line.assert_blocked();
        assert!(line.detail.contains("(os error 13)"), "{line:?}");
    }
    assert!(fixture.path("rw/inside").is_symlink());
    fixture.reset();

    let mut allow = fixture.access_args();
    allow.extend(args(&["--symlinks", "allow"]));
    let (through_outside, through_renamed) = (fixture.arg("rw/outside"), fixture.arg("rw/renamed"));
    let mut reads = actions.to_vec();
    reads.extend([
        ("read", through_outside.as_str()),
        ("read", through_renamed.as_str()),
    ]);
    let lines = probe_inside(&allow, &reads);
    lines[0].assert_ok();
    lines[1].assert_ok();
    lines[2].assert_blocked();
    lines[3].assert_blocked();
    lines[4].assert_ok();
    lines[5].assert_blocked();
    lines[6].assert_ok();
    assert_eq!(
        std::fs::read_link(fixture.path("rw/outside")).unwrap(),
        fixture.path("secret/file")
    );
}
