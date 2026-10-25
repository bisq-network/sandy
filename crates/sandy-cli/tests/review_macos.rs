//! Tests written during the macOS sandbox security reviews. Each denial has a control run
//! outside the sandbox, like the other escape tests, so a test cannot pass because the action
//! was impossible anyway. Tests whose name says "stays", "cannot" or "does not" encode an
//! invariant that held. The others record what the sandbox does where it cannot stop something,
//! so that a change shows up as a failing test: the tests around process groups, process ids and
//! the paths that `unix_sockets = "all"` lets the program test bound limitations that
//! `docs/macos.md` describes.
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::unix::*;
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

/// `gethostuuid` returns the hardware UUID of the Mac, a stable identifier that survives a
/// reinstall and is the same for every user. The profile blocks the same value through IOKit
/// (`IOPlatformUUID` needs `iokit-get-properties`) and denies the system call too.
#[test]
fn host_uuid_is_not_readable_inside_the_sandbox() {
    let fixture = Fixture::new("macos-hostuuid");
    controlled(&fixture.access_args(), &[("host-uuid", "-")])[0].assert_blocked();
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
        skip(
            "volfs",
            &format!("this host cannot read via /.vol: {}", outside[0].detail),
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
        skip(
            "fsgetpath",
            &format!(
                "fsgetpath does not work on this host: {}",
                outside[0].detail
            ),
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
            // One feature per family, so that the expected-skip list names each one: a
            // family that stops working outside must not hide behind another that never did.
            skip(
                &format!("socket-family-{family}"),
                &format!(
                    "{family}: not creatable outside the sandbox ({})",
                    out.detail
                ),
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
        skip(
            "ip-sockets",
            "IP sockets are not creatable outside the sandbox",
        );
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
        skip(
            "nstat-control",
            &format!(
                "this host does not let an ordinary user resolve the statistics control: {}",
                outside[0].detail
            ),
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

/// The descriptor variants of the metadata calls take the check of the path variants
/// (`MetadataConfined`: "by path and through open descriptors alike"): a descriptor opened for
/// reading on a `read` path changes neither mode, owner, flags, times nor extended attributes.
/// On Linux the same descriptor once could.
#[test]
fn metadata_through_a_read_only_descriptor_is_denied() {
    let fixture = Fixture::new("macos-fd-metadata");
    let file = fixture.arg("ro/file");
    let targets: Vec<String> = ["fchmod", "fchown", "fchflags", "futimes", "fsetxattr"]
        .iter()
        .map(|call| format!("{file}{ARGUMENT_SEPARATOR}{call}"))
        .collect();
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|target| ("fd-metadata", target.as_str()))
        .collect();

    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();
    for line in probe_inside(&fixture.access_args(), &actions) {
        line.assert_blocked();
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
        skip(
            "sysctl-proc-cputype",
            &format!(
                "macOS denies sysctl.proc_cputype for another process even outside the sandbox, \
                 so it is not an oracle: {}",
                outside[0].detail
            ),
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

/// Separates the program and its arguments in the target of `spawn-join`.
const ARGUMENT_SEPARATOR: &str = "\u{1f}";

/// The by-id calls that reach no file operation, so no path rule of the profile can stop them:
/// the profile denies them by system call number. None of them may hand the program the path of
/// a file outside the policy. `openbyid_np` needs a privilege that no ordinary process has, so
/// outside the sandbox it fails too and the test only records that.
#[test]
fn by_id_lookups_do_not_reach_files_outside_the_policy() {
    let fixture = Fixture::new("macos-byid");
    let secret = dev_inode(&fixture.path("secret/file"));
    let volume = format!("{}{ARGUMENT_SEPARATOR}file", fixture.arg("secret"));
    let actions = [
        ("fsgetpath-ext", secret.as_str()),
        ("vol-getattr", secret.as_str()),
        ("openbyid", secret.as_str()),
        ("searchfs", volume.as_str()),
    ];

    let outside = probe_outside(&actions);
    let inside = probe_inside(&fixture.access_args(), &actions);
    let mut disclosed = Vec::new();
    for ((action, _), (out, inside)) in actions.iter().zip(outside.iter().zip(&inside)) {
        if inside.detail.contains("/secret/") {
            disclosed.push(format!("{action}: {}", inside.detail));
            continue;
        }
        if out.result != "ok" {
            // The host refuses the call to every process, so the sandbox adds nothing here.
            // One feature per call, for the same reason as the socket families above.
            skip(
                &format!("by-id-call-{action}"),
                &format!("{action} does not work outside the sandbox: {}", out.detail),
            );
            continue;
        }
        inside.assert_blocked();
    }
    assert!(
        disclosed.is_empty(),
        "by-id calls disclosed paths outside the policy: {disclosed:?}"
    );
}

/// `getattrlistbulk` returns the metadata of every entry of a directory in one call. The one
/// directory outside the policy that the program can open is the root directory, which dyld
/// needs. This records what that reveals: the names and file ids of the entries of `/`, and
/// nothing of a directory the policy does not grant.
#[test]
fn bulk_listing_reaches_only_the_root_directory() {
    let fixture = Fixture::new("macos-bulk");
    let secret = fixture.arg("secret");
    let actions = [
        ("getattrlistbulk", "/"),
        ("getattrlistbulk", secret.as_str()),
    ];

    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    // Recorded, not a guarantee: the root directory is readable, so its entries come back.
    inside[0].assert_ok();
    assert!(
        inside[0].detail.contains("usr#"),
        "the root listing lost its entries: {}",
        inside[0].detail
    );
    inside[1].assert_blocked();
}

/// The answers inside the sandbox for `action` on an existing path outside the policy and on a
/// path that does not exist. The control outside shows that the first one exists.
fn existing_and_missing(
    fixture: &Fixture,
    action: &str,
    existing: &str,
    missing: &str,
) -> Vec<ProbeLine> {
    let actions = [(action, existing), (action, missing)];
    let outside = probe_outside(&actions);
    outside[0].assert_ok();
    assert_eq!(outside[1].result, "error", "{outside:?}");
    probe_inside(&fixture.access_args(), &actions)
}

/// An existing path outside the policy must answer exactly like a missing one: ENOENT.
fn assert_looks_missing(existing: &ProbeLine, missing: &ProbeLine) {
    assert_eq!(existing.result, "error", "{existing:?}");
    assert!(existing.detail.ends_with("(os error 2)"), "{existing:?}");
    assert_eq!(existing.detail, missing.detail, "{existing:?} {missing:?}");
}

/// `stat` of a path outside the policy answers ENOENT, as for a path that does not exist, so the
/// program cannot tell whether the path exists. It once answered EPERM for an existing path.
#[test]
fn metadata_outside_the_policy_looks_missing() {
    let fixture = Fixture::new("macos-visibility");
    let lines = existing_and_missing(
        &fixture,
        "metadata",
        &fixture.arg("secret/file"),
        &fixture.arg("secret/no-such-file"),
    );
    assert_looks_missing(&lines[0], &lines[1]);
}

/// `access` reaches only file-test-existence, which `(deny default)` does not cover. It once
/// answered for every path outside the policy.
#[test]
fn access_outside_the_policy_looks_missing() {
    let fixture = Fixture::new("macos-access");
    let lines = existing_and_missing(
        &fixture,
        "access",
        &fixture.arg("secret/file"),
        &fixture.arg("secret/no-such-file"),
    );
    assert_looks_missing(&lines[0], &lines[1]);
    probe_inside(
        &fixture.access_args(),
        &[("access", &fixture.arg("ro/file"))],
    )[0]
    .assert_ok();
}

/// `statfs` once answered for every path outside the policy, with the device and the directory
/// the volume is mounted on.
#[test]
fn statfs_outside_the_policy_looks_missing() {
    let fixture = Fixture::new("macos-statfs");
    let lines = existing_and_missing(
        &fixture,
        "statfs",
        &fixture.arg("secret/file"),
        &fixture.arg("secret/no-such-file"),
    );
    assert_looks_missing(&lines[0], &lines[1]);
    probe_inside(
        &fixture.access_args(),
        &[("statfs", &fixture.arg("ro/file"))],
    )[0]
    .assert_ok();
}

/// `chdir` into a directory outside the policy once succeeded.
#[test]
fn chdir_outside_the_policy_looks_missing() {
    let fixture = Fixture::new("macos-chdir");
    let lines = existing_and_missing(
        &fixture,
        "chdir",
        &fixture.arg("secret"),
        &fixture.arg("no-such-directory"),
    );
    assert_looks_missing(&lines[0], &lines[1]);
    probe_inside(&fixture.access_args(), &[("chdir", &fixture.arg("ro"))])[0].assert_ok();
}

/// `getattrlist` answers a request for ATTR_CMN_FULLPATH without reading the file's attributes,
/// so the profile decides it by file-test-existence alone. It once disclosed the path of a file
/// outside the policy; now that answers like a missing path. Inside the policy the path still
/// comes back, which `realpath(3)` needs.
#[test]
fn getattrlist_does_not_disclose_paths_outside_the_policy() {
    let fixture = Fixture::new("macos-getattr");
    let only_the_path = |path: String| format!("{path}{ARGUMENT_SEPARATOR}fullpath");
    let lines = existing_and_missing(
        &fixture,
        "getattr",
        &only_the_path(fixture.arg("secret/file")),
        &only_the_path(fixture.arg("secret/no-such-file")),
    );
    assert_looks_missing(&lines[0], &lines[1]);
    let inside = probe_inside(
        &fixture.access_args(),
        &[("getattr", &only_the_path(fixture.arg("ro/file")))],
    );
    assert!(inside[0].detail.ends_with("/ro/file"), "{inside:?}");
}

/// `/.vol/DEV/INODE` names a file by its inode number, and `getattrlist` with ATTR_CMN_FULLPATH
/// on it turned an inode number into a path, the disclosure that the `fsgetpath` denial closed.
/// Seatbelt checks such a lookup against the real path of the file, so the inode of a file
/// outside the policy now answers like an inode that does not exist, to every call.
#[test]
fn volfs_names_no_file_outside_the_policy() {
    let fixture = Fixture::new("macos-volfs-names");
    let metadata = fs::metadata(fixture.path("secret/file")).unwrap();
    let secret = format!("/.vol/{}/{}", metadata.dev(), metadata.ino());
    // An inode number far above every file of a test volume.
    let unused = format!("/.vol/{}/{}", metadata.dev(), u64::from(u32::MAX) * 64);
    if probe_outside(&[("access", secret.as_str())])[0].result != "ok" {
        return skip("volfs", "this host has no /.vol");
    }
    for (action, existing, missing) in [
        ("access", secret.clone(), unused.clone()),
        ("statfs", secret.clone(), unused.clone()),
        (
            "getattr",
            format!("{secret}{ARGUMENT_SEPARATOR}fullpath"),
            format!("{unused}{ARGUMENT_SEPARATOR}fullpath"),
        ),
    ] {
        let lines = existing_and_missing(&fixture, action, &existing, &missing);
        assert_looks_missing(&lines[0], &lines[1]);
    }
}

/// Paths outside the policy look missing, but a write to a `read` path must still say that it is
/// refused: ENOENT would tell the program that a directory it can list does not exist. Outside
/// the policy a write answers ENOENT like every other call.
#[test]
fn writes_to_a_read_path_stay_refused() {
    let fixture = Fixture::new("macos-read-writes");
    let new_file = fixture.arg("ro/new");
    let new_dir = fixture.arg("ro/dir");
    let file = fixture.arg("ro/file");
    let secret = fixture.arg("secret/file");
    let actions = [
        ("write", file.as_str()),
        ("write", new_file.as_str()),
        ("mkdir", new_dir.as_str()),
        ("delete", file.as_str()),
        ("write", secret.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    fixture.reset();
    let inside = probe_inside(&fixture.access_args(), &actions);
    for line in &inside[..4] {
        assert_eq!(line.result, "denied", "{line:?}");
    }
    assert!(inside[4].detail.ends_with("(os error 2)"), "{inside:?}");
    assert!(fixture.path("ro/file").exists());
}

/// Programs spell paths through the links `/etc`, `/tmp` and `/var` of the system set, and so do
/// the links of the time zone database. Seatbelt checks the existence of the spelled path too, so
/// the profile allows the check for paths below these links; the real path is checked as well,
/// so a path the policy does not grant still looks missing.
#[test]
fn paths_through_the_system_links_reach_only_granted_files() {
    let fixture = Fixture::new("macos-links");
    let readable = fixture.arg("ro/file");
    let Some(through_var) = readable.strip_prefix("/private") else {
        return skip(
            "private-temp-dir",
            "the temporary directory is not below /private/var",
        );
    };
    let actions = [
        ("read", "/etc/localtime"),
        ("read", through_var),
        ("access", "/etc/passwd"),
        ("access", "/etc/no-such-file"),
    ];
    let outside = probe_outside(&actions);
    for line in &outside[..3] {
        line.assert_ok();
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    inside[0].assert_ok();
    inside[1].assert_ok();
    assert_looks_missing(&inside[2], &inside[3]);
}

/// With `unix_sockets = "all"` the program reaches every Unix socket of the user, also outside
/// the policy. Seatbelt checks the lookup of the socket's path as file-test-existence before the
/// kernel knows that the path is a socket, so the profile allows that check for every path. This
/// records what it gives back: `access`, `statfs`, `chdir` and the path from `getattrlist`, also
/// by inode number through `/.vol`, answer for paths outside the policy again (docs/macos.md).
#[test]
fn unix_sockets_all_reaches_sockets_and_tests_paths_outside_the_policy() {
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new("macos-unix-outside");
    let socket = fixture.path("secret/socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    let socket = socket.to_str().unwrap().to_string();
    let directory = fixture.arg("secret");
    let secret = fixture.arg("secret/file");
    let missing = fixture.arg("secret/no-such-file");
    let metadata = fs::metadata(fixture.path("secret/file")).unwrap();
    let by_inode = format!(
        "/.vol/{}/{}{ARGUMENT_SEPARATOR}fullpath",
        metadata.dev(),
        metadata.ino()
    );
    let actions = [
        ("unix-connect", socket.as_str()),
        ("access", missing.as_str()),
        ("access", secret.as_str()),
        ("statfs", secret.as_str()),
        ("chdir", directory.as_str()),
        ("getattr", by_inode.as_str()),
        ("metadata", secret.as_str()),
    ];
    let denied = probe_inside(&fixture.access_args(), &actions);
    denied[0].assert_blocked();
    assert_looks_missing(&denied[2], &denied[1]);

    let unix = with(fixture.access_args(), &["--unix-sockets", "all"]);
    let inside = probe_inside(&unix, &actions);
    inside[0].assert_ok();
    assert_eq!(inside[1].result, "error", "{inside:?}");
    for line in &inside[2..6] {
        assert_eq!(
            line.result, "ok",
            "existence is hidden with unix_sockets = \"all\" now; the documented limitation \
             is stale: {line:?}"
        );
    }
    assert!(inside[5].detail.ends_with("/secret/file"), "{inside:?}");
    // Every other call still answers like a missing path.
    assert!(inside[6].detail.ends_with("(os error 2)"), "{inside:?}");
}

/// `setattrlist` writes the metadata that `getattrlist` reads, so it must be denied outside
/// writable paths like every other metadata change.
#[test]
fn setattrlist_cannot_change_files_outside_writable_paths() {
    let fixture = Fixture::new("macos-setattr");
    let secret = fixture.arg("secret/file");
    let readable = fixture.arg("ro/file");
    let writable = fixture.arg("rw/file");
    let actions = [
        ("setattr", secret.as_str()),
        ("setattr", readable.as_str()),
        ("setattr", writable.as_str()),
    ];

    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    inside[0].assert_blocked();
    inside[1].assert_blocked();
    inside[2].assert_ok();
}

/// `getfsstat` lists every mounted volume with the directory it is mounted on. It takes no path,
/// so no file rule of the profile applies to it; the profile denies it by system call number
/// (getfsstat and getfsstat64, the latter the one libc calls), like the by-id lookups. The list
/// names the disks of the system, including attached external disks, which is information about
/// the system outside the sandbox that no documented guarantee needs. The control outside the
/// sandbox shows the call works there.
#[test]
fn the_volume_list_is_denied() {
    let fixture = Fixture::new("macos-getfsstat");
    probe_outside(&[("getfsstat", "")])[0].assert_ok();
    let inside = probe_inside(&fixture.access_args(), &[("getfsstat", "")]);
    inside[0].assert_blocked();
}

/// `proc_pidinfo`, `proc_pidpath` and `proc_listallpids` once answered EPERM for a live process
/// outside the sandbox and ESRCH for a process ID that nothing uses. Now every process but the
/// program's own answers ESRCH, as if it did not exist.
#[test]
fn other_processes_look_gone() {
    let fixture = Fixture::new("macos-pidinfo");
    let live = std::process::id().to_string();
    let unused = "99998";
    let actions = [
        ("pid-info", live.as_str()),
        ("pid-info", unused),
        ("pid-path", live.as_str()),
        ("pid-path", unused),
        ("list-pids", ""),
        ("pid-info", "self"),
        ("pid-path", "self"),
    ];
    let outside = probe_outside(&actions);
    for index in [0, 2, 4, 5, 6] {
        outside[index].assert_ok();
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    for pair in [[0, 1], [2, 3]] {
        let (live, unused) = (&inside[pair[0]], &inside[pair[1]]);
        assert!(live.detail.ends_with("(os error 3)"), "{live:?}");
        assert_eq!(live.detail, unused.detail, "{live:?} {unused:?}");
    }
    assert!(inside[4].detail.ends_with("(os error 3)"), "{inside:?}");
    inside[5].assert_ok();
    inside[6].assert_ok();
}

/// `getpriority`, `getpgid` and `getsid` answer for any process ID, and no profile operation
/// covers them, so the profile denies them by system call number. That refuses the program's
/// own process too.
#[test]
fn priority_group_and_session_queries_are_denied() {
    let fixture = Fixture::new("macos-pidquery");
    let live = std::process::id().to_string();
    let unused = "99998";
    let mut actions = Vec::new();
    for call in ["getpriority", "getpgid", "getsid"] {
        for pid in [live.as_str(), unused, "self"] {
            actions.push((call, pid));
        }
    }
    let outside = probe_outside(&actions);
    let inside = probe_inside(&fixture.access_args(), &actions);
    for (index, (out, inside)) in outside.iter().zip(&inside).enumerate() {
        if index % 3 == 1 {
            assert_eq!(out.result, "error", "control: {out:?}");
        } else {
            out.assert_ok();
        }
        assert_eq!(inside.result, "denied", "{inside:?}");
    }
}

/// `kill(pid, 0)` checks permission without sending anything, so it tells a live process from a
/// process ID that nothing uses: EPERM against ESRCH. `signals = "isolated"` stops the signal
/// but not the answer, so the program can still find out which process ids exist. A
/// `(with errno ESRCH)` on the signal rule does not change the answer, and denying `kill` by
/// number would take every signal away, also to the program's own children. macOS itself gives
/// the same answer for a process of another user, so this records a limit, not a defect.
#[test]
fn process_ids_outside_the_sandbox_stay_countable() {
    let fixture = Fixture::new("macos-pidprobe");
    let isolated = with(fixture.access_args(), &["--signals", "isolated"]);
    let live = std::process::id().to_string();
    // A process id that nothing uses: one above every live process of this run.
    let unused = "99998";
    let actions = [("signal", live.as_str()), ("signal", unused)];

    let outside = probe_outside(&actions);
    outside[0].assert_ok();
    assert_eq!(outside[1].result, "error", "{outside:?}");

    let inside = probe_inside(&isolated, &actions);
    inside[0].assert_blocked();
    inside[1].assert_blocked();
    assert_ne!(
        inside[0].detail, inside[1].detail,
        "a live process id and an unused one now give the same answer; the documented \
         limitation is stale"
    );
}

/// The kernel sends SIGIO to the owner of a socket, and `F_SETOWN` names any process as the
/// owner. XNU sends it without the check that `(allow signal (target self) (target
/// same-sandbox))` hooks, so `signals = "isolated"` must not be trusted to stop it. This
/// records whether the signal arrives.
#[test]
fn sigio_through_f_setown_follows_no_signal_policy() {
    let fixture = Fixture::new("macos-sigio");
    let isolated = with(fixture.access_args(), &["--signals", "isolated"]);

    // Control outside the sandbox: SIGIO (23 on Darwin) reaches the victim, which exits 42.
    let mut victim = spawn_victim();
    let pid = victim.0.id().to_string();
    probe_outside(&[("sigio-signal", &pid)])[0].assert_ok();
    assert_eq!(
        exit_code_within(&mut victim, Duration::from_secs(2)),
        Some(42),
        "control: the SIGIO path does not deliver on this host"
    );
    drop(victim);

    let mut victim = spawn_victim();
    let pid = victim.0.id().to_string();
    let inside = probe_inside(&isolated, &[("sigio-signal", &pid)]);
    inside[0].assert_blocked();
    let delivered = exit_code_within(&mut victim, Duration::from_secs(2)) == Some(42);
    assert!(
        !delivered,
        "SIGIO reached a process outside the sandbox under signals = isolated: {:?}",
        inside[0]
    );
}

/// `F_SETOWN` is not the only way to name the owner that SIGIO goes to: the ioctls FIOSETOWN,
/// SIOCSPGRP (sockets) and TIOCSPGRP (pipes) set the same owner. Seatbelt checks `file-ioctl`
/// only for files and devices, so the ioctl allowlist does not reach sockets and pipes, and no
/// operation of the profile language does (`socket-ioctl` compiles and stops none of them,
/// measured on macOS 26.5 and 27.0.1). This records that the signal still arrives under
/// `signals = "isolated"`, as docs/macos.md says.
#[test]
fn sigio_through_owner_ioctls_follows_no_signal_policy() {
    let fixture = Fixture::new("macos-sigio-ioctl");
    let isolated = with(fixture.access_args(), &["--signals", "isolated"]);
    for route in [
        "socket:fiosetown",
        "socket:siocspgrp",
        "pipe:fiosetown",
        "pipe:tiocspgrp",
    ] {
        let mut victim = spawn_victim();
        let target = format!("{}:{route}", victim.0.id());
        probe_outside(&[("sigio-signal", &target)])[0].assert_ok();
        assert_eq!(
            exit_code_within(&mut victim, Duration::from_secs(2)),
            Some(42),
            "control: SIGIO through {route} does not deliver on this host"
        );
        drop(victim);

        let mut victim = spawn_victim();
        let target = format!("{}:{route}", victim.0.id());
        let inside = probe_inside(&isolated, &[("sigio-signal", &target)]);
        inside[0].assert_ok();
        assert_eq!(
            exit_code_within(&mut victim, Duration::from_secs(2)),
            Some(42),
            "SIGIO through {route} no longer reaches a process outside the sandbox; the \
             documented limitation is stale: {:?}",
            inside[0]
        );
    }
}

/// A victim outside the sandbox that waits for SIGIO (23) and exits with 42 when it arrives.
fn spawn_victim() -> Victim {
    let child = Command::new(probe_path())
        .args(["await-signal", "23"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Give the child time to install the handler before it is targeted.
    sleep(Duration::from_millis(300));
    Victim(child)
}

/// The victim's exit code, or `None` when it is still running after `grace`.
fn exit_code_within(victim: &mut Victim, grace: Duration) -> Option<i32> {
    let deadline = std::time::Instant::now() + grace;
    loop {
        match victim.0.try_wait().unwrap() {
            Some(status) => return status.code(),
            None if std::time::Instant::now() < deadline => sleep(Duration::from_millis(20)),
            None => return None,
        }
    }
}

/// The terminal ioctls that make the kernel signal a process group are outside the profile's
/// ioctl allowlist: TIOCSPGRP would give the terminal to another job of the session, which then
/// stops at its next read, and TIOCSWINSZ makes the kernel send SIGWINCH to the foreground
/// group. Both are denied in every mode, so `signals = "isolated"` needs no rule of its own.
#[test]
fn the_terminal_signal_ioctls_are_denied() {
    let fixture = Fixture::new("macos-ttyioctl");
    let actions = [("tcsetpgrp", "0"), ("tiocswinsz", "0")];
    // tcsetpgrp needs the terminal to be the caller's controlling terminal, so each run becomes
    // a session of its own with a pseudo-terminal, as a shell's session is. macOS revokes a
    // terminal when its session leader ends, which leaves every descriptor of it invalid, so
    // the second run needs a terminal of its own.
    let on_a_terminal = |mut command: Command| {
        let pty = open_pty()?;
        with_terminal(&pty)(&mut command);
        Some(parse(&command.output().unwrap()))
    };

    let mut control = Command::new(probe_path());
    control.args(probe_args(&actions));
    let Some(control) = on_a_terminal(control) else {
        return skip("pty", "no pseudo-terminal available");
    };
    for line in &control {
        line.assert_ok();
    }

    let mut inside = Command::new(sandy_path());
    inside.args(run_args(&fixture.access_args(), &actions));
    for line in &on_a_terminal(inside).unwrap() {
        line.assert_blocked();
    }
}

/// `signals = "isolated"` does not keep the program out of the process groups of the terminal
/// session it was started in: SBPL cannot filter the arguments of `setpgid`, so denying it
/// would deny every process group, and `posix_spawn` would change the group inside the kernel
/// anyway. This records both routes. `children = "contained"` closes them, because it denies
/// setpgid, setsid and posix_spawn.
#[test]
fn a_program_can_join_a_process_group_outside_the_sandbox() {
    let fixture = Fixture::new("macos-joinpg");
    let isolated = with(fixture.access_args(), &["--signals", "isolated"]);
    // SAFETY: getpgrp takes no arguments.
    let outside_group = unsafe { libc::getpgrp() }.to_string();
    let program = fixture.copy_probe("bin");
    let spawn = format!(
        "{outside_group}{ARGUMENT_SEPARATOR}{program}{ARGUMENT_SEPARATOR}sleep{ARGUMENT_SEPARATOR}5000"
    );
    let actions = [
        ("setpgid-join", outside_group.as_str()),
        ("spawn-join", spawn.as_str()),
    ];

    let inside = probe_inside(&isolated, &actions);
    inside[0].assert_ok();
    inside[1].assert_ok();
    // The profile denies getpgid, so the group is read here, outside the sandbox.
    let spawned: libc::pid_t = inside[1]
        .detail
        .split_whitespace()
        .nth(1)
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| panic!("no process ID: {:?}", inside[1]));
    // SAFETY: getpgid takes a process ID.
    let group = unsafe { libc::getpgid(spawned) };
    assert_eq!(
        group.to_string(),
        outside_group,
        "the spawned process did not join the group: {:?}",
        inside[1]
    );

    // `contained` denies both routes: setpgid by system call number, and posix_spawn as a whole.
    let contained = with(
        fixture.access_args(),
        &["--signals", "isolated", "--children", "contained"],
    );
    let contained = probe_inside(&contained, &actions);
    contained[0].assert_blocked();
    contained[1].assert_blocked();
}

/// A terminal session like a shell's. A session leader owns a pseudo-terminal and keeps its
/// foreground group, and starts two background jobs, each in a process group of its own: a
/// victim outside the sandbox that only sleeps, and the job under test, in whose arguments
/// `{job}` stands for the victim's process group. The kernel stops a whole process group when
/// one of its processes reads the terminal in the background, and that send has no permission
/// check behind it, so a session of this shape is what shows whether a program can reach
/// another job.
struct JobSession {
    /// Held open: with no descriptor of the master left, a read of the terminal returns at
    /// once instead of waiting, and the kernel stops no one.
    _pty: Pty,
    leader: Child,
    victim: u32,
    job: u32,
    /// The probe lines of the jobs; the leader's own `start-job` lines are taken out.
    lines: mpsc::Receiver<ProbeLine>,
    /// Lines of the job that arrived while `start` still waited for a `start-job` line.
    early: Vec<ProbeLine>,
}

impl JobSession {
    /// `None` when the host has no pseudo-terminal.
    fn start(job: &[String]) -> Option<JobSession> {
        let pty = open_pty()?;
        let victim = [probe_path(), "sleep".to_string(), "60000".to_string()];
        let actions = [
            ("start-job", victim.join(ARGUMENT_SEPARATOR)),
            ("start-job", job.join(ARGUMENT_SEPARATOR)),
            ("sleep", "60000".to_string()),
        ];
        let actions: Vec<(&str, &str)> = actions
            .iter()
            .map(|(action, target)| (*action, target.as_str()))
            .collect();
        let mut command = Command::new(probe_path());
        command
            .args(probe_args(&actions))
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        with_terminal(&pty)(&mut command);
        let mut leader = command.spawn().unwrap();
        let output = BufReader::new(leader.stdout.take().unwrap());
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in output.lines().map_while(Result::ok) {
                if sender.send(parse_line(&line)).is_err() {
                    return;
                }
            }
        });
        let mut started = Vec::new();
        let mut early = Vec::new();
        while started.len() < 2 {
            let line = lines.recv_timeout(Duration::from_secs(10)).unwrap();
            // The job can report before the leader reports having started it.
            if line.action == "start-job" {
                line.assert_ok();
                started.push(line.detail.parse().unwrap());
            } else {
                early.push(line);
            }
        }
        Some(JobSession {
            _pty: pty,
            leader,
            victim: started[0],
            job: started[1],
            lines,
            early,
        })
    }

    /// The job's probe line, or `None` if the victim stopped or ten seconds passed first.
    fn job_line(&mut self) -> Option<ProbeLine> {
        if !self.early.is_empty() {
            return Some(self.early.remove(0));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !self.victim_stopped() {
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(50)) {
                return Some(line);
            }
        }
        None
    }

    fn victim_stopped(&self) -> bool {
        process_status(self.victim as libc::pid_t) == Some(libc::SSTOP)
    }
}

impl Drop for JobSession {
    fn drop(&mut self) {
        // None of these processes forks, so one signal per group is enough. The leader goes
        // last: its children are reaped once it has ended and they belong to process 1.
        for group in [self.victim, self.job, self.leader.id()] {
            // SAFETY: kill takes a process group ID and a signal.
            unsafe { libc::kill(-(group as libc::pid_t), libc::SIGKILL) };
        }
        let _ = self.leader.kill();
        let _ = self.leader.wait();
    }
}

/// The BSD process status of `pid` (`SSTOP` for a stopped process), or `None` when it is gone.
fn process_status(pid: libc::pid_t) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer has exactly the size passed.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole structure.
    Some(unsafe { info.assume_init() }.pbi_status)
}

/// The `JobSession` job that runs the probe in the sandbox with `extra` options.
fn sandboxed_job(fixture: &Fixture, extra: &[&str], actions: &[(&str, &str)]) -> Vec<String> {
    let mut job = vec![sandy_path()];
    job.extend(run_args(&with(fixture.access_args(), extra), actions));
    job
}

/// What the gap above costs in practice: a program with isolated signals joins the process
/// group of another job of its terminal session, reads the terminal, and the kernel stops that
/// job with it. `children = "contained"` denies the move, and the job outside keeps running.
#[test]
fn a_background_read_stops_another_job_of_the_terminal() {
    let fixture = Fixture::new("macos-jobstop");
    let join = [("setpgid-join", "{job}")];

    let mut outside = vec![probe_path()];
    outside.extend(probe_args(&join));
    let Some(mut control) = JobSession::start(&outside) else {
        return skip("pty", "no pseudo-terminal available");
    };
    // The control stops itself together with the victim, so it reports no line.
    let line = control.job_line();
    assert!(
        line.is_none(),
        "the control was not stopped: {line:?}, victim status {:?}",
        process_status(control.victim as libc::pid_t)
    );
    assert!(control.victim_stopped(), "the control stopped no job");
    drop(control);

    // Recorded, not a guarantee: isolated signals do not stop this.
    let isolated = sandboxed_job(&fixture, &["--signals", "isolated"], &join);
    let mut session = JobSession::start(&isolated).unwrap();
    assert!(
        session.job_line().is_none() && session.victim_stopped(),
        "the program no longer stops another job; the documented limitation is stale"
    );
    drop(session);

    let contained = sandboxed_job(
        &fixture,
        &["--signals", "isolated", "--children", "contained"],
        &join,
    );
    let mut session = JobSession::start(&contained).unwrap();
    let line = session.job_line();
    assert!(!session.victim_stopped(), "the program stopped another job");
    assert_eq!(
        line.as_ref().map(|line| line.result.as_str()),
        Some("denied"),
        "{line:?}"
    );
}
