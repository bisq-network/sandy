//! Tests written during the macOS sandbox security review. Each denial has a control run outside
//! the sandbox, like the other escape tests, so a test cannot pass because the action was
//! impossible anyway. Tests whose name says "stays", "cannot" or "does not" encode an invariant
//! that held; `fsgetpath_discloses_out_of_policy_paths` is a proof of concept for a confirmed
//! finding and documents the current (insecure) behavior.
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use common::*;

/// `DEV:INODE` of a path, read outside the sandbox. The probe turns it into `/.vol/DEV/INODE` or
/// passes it to fsgetpath.
fn dev_inode(path: &Path) -> String {
    let metadata = fs::metadata(path).unwrap();
    format!("{}:{}", metadata.dev(), metadata.ino())
}

fn with(mut args: Vec<String>, extra: &[&str]) -> Vec<String> {
    args.extend(extra.iter().map(|arg| arg.to_string()));
    args
}

/// Opening a file by device and inode through volfs (`/.vol/<dev>/<inode>`) must be checked like
/// any other open: reading a file outside the policy this way is denied.
#[test]
fn volfs_content_read_stays_inside_the_policy() {
    let fixture = Fixture::new("macos-volfs");
    let secret = dev_inode(&fixture.path("secret/file"));
    let allowed = dev_inode(&fixture.path("ro/file"));
    let actions = [
        ("vol-read", secret.as_str()),
        ("vol-read", allowed.as_str()),
    ];

    let outside = probe_outside(&actions);
    if outside[0].result != "ok" {
        eprintln!(
            "control: this host cannot read via /.vol ({}); nothing to check",
            outside[0].detail
        );
        return;
    }

    let lines = probe_inside(&fixture.access_args(), &actions);
    lines[0].assert_blocked();
}

/// Finding 1.1 of the review: `fsgetpath` resolves the path of a file named only by device and
/// inode, and no file operation checks it. The profile now denies the by-id system calls
/// (`syscall-unix`), so the path of a file outside the policy stays hidden.
#[test]
fn fsgetpath_does_not_disclose_out_of_policy_paths() {
    let fixture = Fixture::new("macos-fsgetpath");
    let secret = dev_inode(&fixture.path("secret/file"));
    let actions = [("fsgetpath", secret.as_str())];

    let outside = probe_outside(&actions);
    if outside[0].result != "ok" {
        eprintln!(
            "control: fsgetpath does not work on this host ({}); nothing to check",
            outside[0].detail
        );
        return;
    }

    let lines = probe_inside(&fixture.access_args(), &actions);
    lines[0].assert_blocked();
    assert!(
        !lines[0].detail.contains("/secret/"),
        "fsgetpath disclosed the path: {}",
        lines[0].detail
    );
}

/// `(deny default)` must refuse creation of the non-IP socket families that are useful without a
/// connect: a routing socket (interfaces, routes, ARP), a kernel-control socket (per-process
/// network statistics) and a raw link-layer socket. Creation is gated by `system-socket`, which
/// the profile allows only for AF_UNIX.
#[test]
fn dangerous_socket_families_cannot_be_created() {
    let fixture = Fixture::new("macos-sockets");
    let families = ["route", "system", "ndrv", "key"];
    let actions: Vec<(&str, &str)> = families
        .iter()
        .map(|family| ("socket-family", *family))
        .collect();

    let outside = probe_outside(&actions);
    let inside = probe_inside(&fixture.access_args(), &actions);
    let mut checked = 0;
    for ((family, out), inside) in families.iter().zip(&outside).zip(&inside) {
        if out.result != "ok" {
            eprintln!(
                "skip {family}: not creatable outside the sandbox ({})",
                out.detail
            );
            continue;
        }
        assert_ne!(
            inside.result, "ok",
            "the sandbox let the program create a {family} socket: {}",
            inside.detail
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no dangerous socket family was creatable outside; test proved nothing"
    );
}

/// IP socket creation (AF_INET, AF_INET6) is allowed inside the sandbox, but this grants no IP
/// capability: the shared tests `ip_networking_is_denied_by_default` show that bind, listen and
/// connect are denied. This test records that creation itself is not blocked.
#[test]
fn ip_socket_creation_is_allowed_but_inert() {
    let fixture = Fixture::new("macos-ipsocket");
    let actions = [("socket-family", "inet"), ("socket-family", "inet6")];
    let outside = probe_outside(&actions);
    if outside.iter().any(|line| line.result != "ok") {
        eprintln!("control: IP sockets not creatable outside; nothing to check");
        return;
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    // Documented deviation: creation succeeds. The IP-deny guarantee is enforced at bind/connect.
    assert_eq!(inside[0].result, "ok", "{:?}", inside[0]);
    assert_eq!(inside[1].result, "ok", "{:?}", inside[1]);
}

/// A PF_SYSTEM kernel control socket, through which the network statistics control would reveal
/// every process's network activity, is unreachable: its creation is denied by `system-socket`,
/// and even if it existed, resolving the control by name (CTLIOCGINFO) is a denied file-ioctl.
#[test]
fn kernel_control_socket_is_unreachable() {
    let fixture = Fixture::new("macos-nstat");
    let outside = probe_outside(&[("nstat-open", "")]);
    if outside[0].result != "ok" {
        eprintln!(
            "control: this host does not let an ordinary user resolve the statistics control \
             ({}); nothing to check",
            outside[0].detail
        );
        return;
    }
    let inside = probe_inside(&fixture.access_args(), &[("nstat-open", "")]);
    inside[0].assert_blocked();
}

/// Metadata changes by path (flags, times, extended attributes) must be denied outside writable
/// paths, the same as the mode change the shared test already covers.
#[test]
fn metadata_by_path_outside_writable_is_denied() {
    let fixture = Fixture::new("macos-metadata");
    let secret = fixture.arg("secret/file");
    let readable = fixture.arg("ro/file");
    let actions = [
        ("chflags-set", secret.as_str()),
        ("utimes-set", secret.as_str()),
        ("setxattr-set", secret.as_str()),
        ("getxattr-get", secret.as_str()),
        ("chflags-set", readable.as_str()),
        ("utimes-set", readable.as_str()),
        ("setxattr-set", readable.as_str()),
    ];
    // getxattr of a missing attribute returns an error even outside, so the control checks only
    // the write actions.
    let outside = probe_outside(&actions);
    for (index, line) in outside.iter().enumerate() {
        if index == 3 {
            continue;
        }
        line.assert_ok();
    }

    let inside = probe_inside(&fixture.access_args(), &actions);
    for line in &inside {
        line.assert_blocked();
    }
    for file in ["secret/file", "ro/file"] {
        assert!(fixture.path(file).exists(), "{file} disappeared");
    }
}

/// A symbolic link planted in a writable path must not reach its target. macOS allows creating the
/// link (there is no symlink-creation right as on Landlock), but the sandbox resolves it at access
/// time and checks the real path, so reading through it is denied.
#[test]
fn symlink_in_writable_path_does_not_grant_its_target() {
    let fixture = Fixture::new("macos-symlink");
    let link = fixture.arg("rw/link");
    let secret = fixture.arg("secret/file");
    let make = format!("{link}::{secret}");

    // Control outside: the link is created and reading through it yields the secret.
    let outside = probe_outside(&[("symlink", &make), ("read", &link)]);
    outside[0].assert_ok();
    outside[1].assert_ok();
    let _ = fs::remove_file(fixture.path("rw/link"));

    let inside = probe_inside(
        &fixture.access_args(),
        &[("symlink", &make), ("read", &link)],
    );
    // Creating the link inside a writable path is allowed on macOS.
    inside[0].assert_ok();
    // Reading through it must be denied: it resolves to a file outside the policy.
    inside[1].assert_blocked();
}

/// The host name port (mach_host_self) is a task special port inherited across exec and needs no
/// mach-lookup. System-wide virtual memory statistics are readable through it. This is machine
/// information, not user files, but it is a disclosure the profile does not stop. Recorded as an
/// info finding.
#[test]
fn host_name_port_statistics_are_readable() {
    let fixture = Fixture::new("macos-hoststats");
    probe_outside(&[("host-vm-stats", "")])[0].assert_ok();
    let inside = probe_inside(&fixture.access_args(), &[("host-vm-stats", "")]);
    assert_eq!(
        inside[0].result, "ok",
        "host VM statistics readable inside the sandbox: {}",
        inside[0].detail
    );
}

/// `sysctl.proc_cputype` is in the readable-sysctl allowlist and is checked by name, so one might
/// fear a per-pid existence and architecture oracle. It is not: macOS itself denies the read for a
/// process the caller cannot inspect, already outside the sandbox. The sandbox cannot add a
/// capability the host does not grant, so the allowlist entry is benign for other processes.
#[test]
fn sysctl_proc_cputype_is_not_a_cross_process_oracle() {
    let fixture = Fixture::new("macos-proccputype");
    // A process outside the sandbox: the test runner itself.
    let outside_pid = std::process::id().to_string();
    let outside = probe_outside(&[("sysctl-proc-cputype", &outside_pid)]);
    if outside[0].result != "ok" {
        eprintln!(
            "macOS denies sysctl.proc_cputype for another process even outside the sandbox ({}); \
             it is not an oracle",
            outside[0].detail
        );
        return;
    }
    // Should the host ever allow it, the sandbox must not turn it into a cross-process oracle.
    let inside = probe_inside(
        &fixture.access_args(),
        &[("sysctl-proc-cputype", &outside_pid)],
    );
    inside[0].assert_blocked();
}

/// A victim program sandboxed by a second sandy run with the same policy, killed when dropped.
struct Victim(Child);

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sandboxed_victim(sandbox_args: &[String]) -> Victim {
    let child = Command::new(sandy_path())
        .args(run_args(sandbox_args, &[("sleep", "60000")]))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Give sandy time to apply the profile and exec the probe before it is targeted.
    sleep(Duration::from_millis(500));
    Victim(child)
}

/// `signals = "isolated"` uses `(allow signal (target self) (target same-sandbox))`. Apple does
/// not document whether `same-sandbox` means the same sandbox instance or any process with the
/// same profile. This test checks whether one sandy run can signal another run with the same
/// policy. It held: the signal is blocked, so the scope is per-instance.
#[test]
fn isolated_signals_do_not_cross_sandbox_instances() {
    let fixture = Fixture::new("macos-samesandbox");
    let isolated = with(fixture.access_args(), &["--signals", "isolated"]);
    let victim = spawn_sandboxed_victim(&isolated);
    let pid = victim.0.id().to_string();

    probe_outside(&[("signal", &pid)])[0].assert_ok();

    let inside = probe_inside(&isolated, &[("signal", &pid)]);
    inside[0].assert_blocked();
    drop(victim);
}
