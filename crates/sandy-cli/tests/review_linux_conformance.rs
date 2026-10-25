//! Tests written during the Linux conformance review (docs/linux.md against the code). Each one
//! checks a documented guarantee that no other test covered, with a control run outside the
//! sandbox like the other escape tests.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

use common::linux::*;
use common::unix::*;
use common::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn run_with(program: String, arguments: Vec<String>, configure: &dyn Fn(&mut Command)) -> Output {
    let mut command = Command::new(program);
    command.args(arguments);
    configure(&mut command);
    command.output().unwrap()
}

/// Runs the probe in the sandbox with `configure` applied to the sandy command.
fn probe_inside_with(
    sandbox_args: &[String],
    actions: &[(&str, &str)],
    configure: &dyn Fn(&mut Command),
) -> Vec<ProbeLine> {
    let output = run_with(sandy_path(), run_args(sandbox_args, actions), configure);
    assert!(
        output.status.success(),
        "sandy run failed: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "probe output: {lines:?}");
    lines
}

fn is_eperm(line: &ProbeLine) -> bool {
    line.result == "denied" && line.detail.contains("os error 1)")
}

fn has_errno(line: &ProbeLine, errno: i32) -> bool {
    line.result != "ok" && line.detail.contains(&format!("os error {errno})"))
}

/// The sandbox options of both process models: the exec model, and `children = "contained"`,
/// in which a forked child confines itself. `contained` needs isolated signals (Landlock ABI 6).
fn process_models(base: &[String]) -> Vec<Vec<String>> {
    let mut models = vec![base.to_vec()];
    if landlock_abi() >= 6 {
        let mut contained = base.to_vec();
        contained.extend(args(&["--children", "contained", "--signals", "isolated"]));
        models.push(contained);
    } else {
        skip(
            "landlock-abi-6",
            "children = contained needs Landlock ABI 6; only the exec model is checked",
        );
    }
    models
}

/// docs/linux.md, launch step 3 and step 4 of "Contained child processes": the program starts
/// with the signal mask and dispositions of sandy's caller, except SIGPIPE, which gets its
/// default action back (the Rust runtime ignores it). In the contained model sandy blocks every
/// signal and resets SIGCHLD for itself, and the forked program must restore both.
#[test]
fn the_callers_signal_state_reaches_the_program() {
    let caller = |command: &mut Command| {
        // SAFETY: signal, sigemptyset, sigaddset and sigprocmask are async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR2);
                if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    };
    let (hup, chld, pipe) = (
        libc::SIGHUP.to_string(),
        libc::SIGCHLD.to_string(),
        libc::SIGPIPE.to_string(),
    );
    let actions = [
        ("signal-disposition", hup.as_str()),
        ("signal-disposition", chld.as_str()),
        ("signal-disposition", pipe.as_str()),
        ("status-field", "SigBlk"),
    ];
    let outside = parse(&run_with(probe_path(), probe_args(&actions), &caller));
    assert_eq!(outside[0].detail, "ignore", "control: {outside:?}");
    assert_eq!(outside[1].detail, "ignore", "control: {outside:?}");
    let blocked = &outside[3].detail;
    assert_ne!(blocked, "0000000000000000", "control: {outside:?}");

    for sandbox_args in process_models(&args(&["--read", "/proc"])) {
        let lines = probe_inside_with(&sandbox_args, &actions, &caller);
        assert_eq!(
            lines[0].detail, "ignore",
            "SIGHUP, {sandbox_args:?}: {lines:?}"
        );
        assert_eq!(
            lines[1].detail, "ignore",
            "SIGCHLD, {sandbox_args:?}: {lines:?}"
        );
        assert_eq!(
            lines[2].detail, "default",
            "SIGPIPE, {sandbox_args:?}: {lines:?}"
        );
        assert_eq!(
            &lines[3].detail, blocked,
            "mask, {sandbox_args:?}: {lines:?}"
        );
    }
}

/// The contained model forks the program, which confines itself (docs/linux.md, "Contained child
/// processes", step 4). It must end up exactly as confined as in the exec model: no_new_privs,
/// all four filters, Landlock, no inherited descriptor, and none of sandy's or the guard's pipes.
#[test]
fn the_contained_program_is_confined_like_the_exec_model() {
    let fixture = Fixture::new("conformance-contained");
    let file = fs::File::open(fixture.path("secret/file")).unwrap();
    let raw = file.as_raw_fd();
    let inherit = move |command: &mut Command| {
        // SAFETY: dup2 and fcntl are async-signal-safe; descriptor 9 is free in the child.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(raw, 9) < 0 || libc::fcntl(9, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    };
    let secret = fixture.arg("secret/file");
    let readable = fixture.arg("ro/file");
    let actions = [
        ("read-fd", "9"),
        ("read", secret.as_str()),
        ("read", readable.as_str()),
        ("list", "/proc/self/fd"),
        ("status-field", "NoNewPrivs"),
        ("status-field", "Seccomp"),
        ("status-field", "Seccomp_filters"),
    ];
    let outside = parse(&run_with(probe_path(), probe_args(&actions), &inherit));
    outside[0].assert_ok();
    outside[1].assert_ok();

    let mut base = fixture.access_args();
    base.extend(args(&["--read", "/proc"]));
    for sandbox_args in process_models(&base) {
        let lines = probe_inside_with(&sandbox_args, &actions, &inherit);
        let context = format!("{sandbox_args:?}: {lines:?}");
        lines[0].assert_blocked();
        lines[1].assert_blocked();
        lines[2].assert_ok();
        // Standard input, output and error, and the descriptor of the listing itself.
        assert_eq!(lines[3].detail, "4 entries", "{context}");
        assert_eq!(lines[4].detail, "1", "{context}");
        assert_eq!(lines[5].detail, "2", "{context}");
        // The four filters of the default policy (see `no_new_privs_and_seccomp_are_active`).
        let inherited: u32 = outside[6].detail.parse().unwrap();
        let filters: u32 = lines[6].detail.parse().unwrap();
        assert_eq!(filters, inherited + 4, "{context}");
    }
}

/// The denylist on the running kernel (docs/linux.md, "Denylist"). The unit tests in
/// `sandy-linux` check the filter program with an interpreter; this checks that the kernel
/// returns EPERM for each call inside the sandbox. A call whose control already fails with a
/// permission error outside (for example because it needs a capability) shows nothing and is
/// skipped. Arguments are invalid on purpose: outside, the kernel then fails the call without
/// changing anything, except `personality` and `unshare`, which change only the probe itself.
#[test]
fn denylisted_calls_fail_with_eperm_on_the_kernel() {
    let call = |nr: libc::c_long, arguments: &[libc::c_long]| {
        let mut target = nr.to_string();
        for argument in arguments {
            target.push_str(&format!(":{argument}"));
        }
        target
    };
    const READ_IMPLIES_EXEC: libc::c_long = 0x040_0000;
    const UFFD_USER_MODE_ONLY: libc::c_long = 1;
    const PTRACE_ATTACH: libc::c_long = 16;
    const IPC_STAT: libc::c_long = 2;
    let mut calls = vec![
        call(libc::SYS_ptrace, &[PTRACE_ATTACH, 0]),
        call(libc::SYS_process_vm_readv, &[0, 0, 0, 0, 0, 0]),
        call(libc::SYS_process_madvise, &[-1, 0, 0, 0, 0]),
        call(libc::SYS_pidfd_getfd, &[-1, 0, 0]),
        call(libc::SYS_kcmp, &[0, 0, 0, 0, 0]),
        call(libc::SYS_msgctl, &[-1, IPC_STAT, 0]),
        call(libc::SYS_semctl, &[-1, 0, IPC_STAT, 0]),
        call(libc::SYS_mq_open, &[0, 0, 0, 0]),
        call(libc::SYS_setns, &[-1, 0]),
        call(libc::SYS_chroot, &[0]),
        call(libc::SYS_open_tree, &[-1, 0, 0]),
        call(libc::SYS_bpf, &[0, 0, 0]),
        call(libc::SYS_perf_event_open, &[0, 0, -1, -1, 0]),
        call(libc::SYS_userfaultfd, &[UFFD_USER_MODE_ONLY]),
        call(libc::SYS_keyctl, &[0, -1, 0]),
        call(libc::SYS_add_key, &[0, 0, 0, 0, 0]),
        call(libc::SYS_request_key, &[0, 0, 0, 0]),
        call(libc::SYS_quotactl_fd, &[-1, 0, 0, 0]),
        // The security module calls of Linux 6.8, which the libc crate does not have yet.
        call(459, &[0, 0, 0, 0]),
        call(460, &[0, 0, 0, 0]),
        call(461, &[0, 0, 0]),
        call(
            libc::SYS_clock_settime,
            &[libc::CLOCK_REALTIME as libc::c_long, 0],
        ),
        call(libc::SYS_personality, &[READ_IMPLIES_EXEC]),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        const MODIFY_LDT_READ: libc::c_long = 0;
        calls.push(call(libc::SYS_modify_ldt, &[MODIFY_LDT_READ, 0, 0]));
    }
    // Last: it moves the probe outside into a new user namespace.
    calls.push(call(
        libc::SYS_unshare,
        &[libc::CLONE_NEWUSER as libc::c_long],
    ));
    let actions: Vec<(&str, &str)> = calls.iter().map(|c| ("raw-syscall", c.as_str())).collect();

    let outside = probe_outside(&actions);
    let inside = probe_inside(&[], &actions);
    let mut checked = 0;
    for (control, line) in outside.iter().zip(&inside) {
        if control.result == "denied" || control.detail.contains("os error 38)") {
            skip(
                "denylist-sample",
                &format!("{}: fails outside: {}", control.target, control.detail),
            );
            continue;
        }
        assert!(is_eperm(line), "control {control:?}, inside {line:?}");
        checked += 1;
    }
    assert!(checked >= 10, "too few calls could be checked: {outside:?}");
}

/// docs/linux.md, "Metadata": with the default `path_metadata = "deny"` every metadata call by
/// path fails, also in writable paths, while the calls on an open descriptor keep working; with
/// `allow` the path calls work. `path_metadata_follows_the_policy` checks chmod only.
#[test]
fn every_metadata_call_by_path_follows_the_policy() {
    let fixture = Fixture::new("conformance-metadata");
    let file = fixture.arg("rw/file");
    let by_path = [
        ("setxattr-path", file.as_str()),
        ("chown-path", file.as_str()),
        ("utime-path", file.as_str()),
    ];
    let by_descriptor = [("setxattr-fd", file.as_str()), ("utime-fd", file.as_str())];
    let actions: Vec<(&str, &str)> = by_path.iter().chain(&by_descriptor).copied().collect();
    let outside = probe_outside(&actions);
    // tmpfs before Linux 6.6 has no user extended attributes.
    let usable: Vec<bool> = outside.iter().map(|line| line.result == "ok").collect();
    for (line, usable) in outside.iter().zip(&usable) {
        if !usable {
            skip(
                "metadata-calls",
                &format!("{} fails outside: {}", line.action, line.detail),
            );
        }
    }
    let lines = probe_inside(&fixture.access_args(), &actions);
    for (index, line) in lines.iter().enumerate() {
        if !usable[index] {
            continue;
        }
        if index < by_path.len() {
            assert!(is_eperm(line), "{line:?}");
        } else {
            line.assert_ok();
        }
    }
    let mut allow = fixture.access_args();
    allow.extend(args(&["--linux-path-metadata", "allow"]));
    for (line, usable) in probe_inside(&allow, &by_path).iter().zip(&usable) {
        if *usable {
            line.assert_ok();
        }
    }
}

/// docs/linux.md, "Device ioctls and the terminal": from Landlock ABI 5 the device ioctl right
/// exists only in writable paths. A terminal that the program opens through a `read` path
/// refuses device ioctls; through a `read_write` path it allows them.
#[test]
fn device_ioctls_need_a_writable_path() {
    if landlock_abi() < 5 {
        return skip("landlock-abi-5", "Landlock checks device ioctls from ABI 5");
    }
    let Some(pty) = open_pty() else {
        return skip("pty", "no pseudo-terminal available");
    };
    let terminal = fs::read_link(format!("/proc/self/fd/{}", pty.slave.as_raw_fd())).unwrap();
    let terminal = terminal.to_str().unwrap();
    probe_outside(&[("winsize-path", terminal)])[0].assert_ok();
    let read = probe_inside(&args(&["--read", terminal]), &[("winsize-path", terminal)]);
    read[0].assert_blocked();
    let write = probe_inside(
        &args(&["--read-write", terminal]),
        &[("winsize-path", terminal)],
    );
    write[0].assert_ok();
}

/// A socket pair stays allowed with `unix_sockets = "none"`, and one end can be bound to a name.
/// A pathname needs the Landlock right to make a socket, which writable paths get only with
/// `unix_sockets = "all"` (docs/linux.md, "Rights per access level").
#[test]
fn socket_pairs_cannot_create_pathname_sockets() {
    let fixture = Fixture::new("conformance-bind");
    let socket = fixture.arg("rw/socket");
    probe_outside(&[("socketpair-bind", &socket)])[0].assert_ok();
    fs::remove_file(&socket).unwrap();
    let lines = probe_inside(&fixture.access_args(), &[("socketpair-bind", &socket)]);
    lines[0].assert_blocked();
    assert!(!Path::new(&socket).exists());
    let mut all = fixture.access_args();
    all.extend(args(&["--unix-sockets", "all"]));
    probe_inside(&all, &[("socketpair-bind", &socket)])[0].assert_ok();
}

/// With `ip = "none"` and `unix_sockets = "none"` the program cannot bind one end of a socket pair
/// to an abstract name. The Landlock abstract socket scope checks connect and send, not bind, so
/// the filter denies bind: otherwise a program (or a process it leaves behind) could take a name
/// that a service outside the sandbox binds later, for example an X server or an application's
/// single-instance socket, and that service would fail with EADDRINUSE.
#[test]
fn socket_pairs_cannot_take_abstract_names() {
    let name = format!("@sandy-conformance-{}", std::process::id());
    probe_outside(&[("socketpair-bind", &name)])[0].assert_ok();
    let lines = probe_inside(&[], &[("socketpair-bind", &name)]);
    lines[0].assert_blocked();
}

/// The minimal system set contains the crypto policy files that the OpenSSL configuration
/// includes on Fedora and RHEL. `/etc/crypto-policies/back-ends` holds symbolic links into
/// `/usr/share/crypto-policies`, so the set needs both; otherwise OpenSSL inside the sandbox
/// would silently run without the system crypto policy.
#[test]
fn the_crypto_policy_files_are_readable() {
    let directory = Path::new("/etc/crypto-policies/back-ends");
    let Ok(entries) = fs::read_dir(directory) else {
        return skip(
            "crypto-policies",
            "no /etc/crypto-policies/back-ends on this host",
        );
    };
    let files: Vec<String> = entries
        .filter_map(|entry| Some(entry.ok()?.path().to_str()?.to_string()))
        .filter(|path| fs::read(path).is_ok())
        .collect();
    if files.is_empty() {
        return skip("crypto-policies", "no readable crypto policy files");
    }
    let actions: Vec<(&str, &str)> = files.iter().map(|path| ("read", path.as_str())).collect();
    for line in probe_inside(&[], &actions) {
        line.assert_ok();
    }
}

/// `sandy check` names every `.include` of the host's OpenSSL configuration that the policy does
/// not cover, because OpenSSL drops an include it cannot read without an error and then runs
/// with weaker built-in defaults. The minimal system set covers the includes of this host, so
/// the default policy must warn about none; a policy that grants only the configuration file
/// itself must warn about each target.
#[test]
fn unreadable_openssl_includes_are_reported() {
    let configs = ["/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf"];
    // An include whose target is missing is skipped by OpenSSL and by sandy alike (Ubuntu 25.10
    // names two that a default installation does not have), so only an existing one counts.
    let with_includes = configs.into_iter().find(|config| {
        let text = fs::read_to_string(config).unwrap_or_default();
        text.lines().any(|line| {
            let target = line.trim().strip_prefix(".include").unwrap_or_default();
            let target = target.trim_start().trim_start_matches('=').trim();
            target.starts_with('/') && Path::new(target).exists()
        })
    });
    let Some(config) = with_includes else {
        return skip(
            "openssl-includes",
            "the OpenSSL configuration of this host includes no file that exists",
        );
    };
    let probe = probe_path();
    let covered = sandy(["check", probe.as_str()]);
    let warnings = String::from_utf8_lossy(&covered.stderr);
    assert!(
        !warnings.contains("OpenSSL configuration"),
        "the minimal system set should cover the includes of {config}: {warnings}"
    );
    // Only the configuration file, so its includes are out of reach. `check` reports this
    // although it refuses the policy for another reason (no loader without the system set).
    let alone = sandy([
        "check",
        "--system",
        "none",
        "--read",
        config,
        probe.as_str(),
    ]);
    let warnings = String::from_utf8_lossy(&alone.stderr);
    assert!(warnings.contains("OpenSSL configuration"), "{warnings}");
    // The remedy is in the message. It names the canonical target, which is what a rule binds
    // to, so it can differ from the path the configuration file spells.
    assert!(warnings.contains("Add --read /"), "{warnings}");
}

/// Records a documented limitation (docs/linux.md, "cgroup limits"): a program in the sandbox
/// cannot see the limits of the cgroup it runs in, because neither /proc nor /sys/fs/cgroup is
/// in the minimal system set. Resource limits are a non-goal, so sandy sets none; `sandy check`
/// names the limit it found and what to pass to the program.
#[test]
fn a_cgroup_limit_is_invisible_and_reported() {
    let probe = probe_path();
    let limited = Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "-p", "MemoryMax=512M"])
        .args(["-p", "CPUQuota=100%", "--", &sandy_path(), "check", &probe])
        .output()
        .unwrap();
    if !limited.status.success() {
        return skip(
            "user-systemd-scope",
            &format!(
                "no user scope with a memory limit here: {}",
                String::from_utf8_lossy(&limited.stderr).trim()
            ),
        );
    }
    let warnings = String::from_utf8_lossy(&limited.stderr);
    assert!(warnings.contains("cgroup limit"), "{warnings}");
    assert!(
        warnings.contains("536870912 bytes from memory.max"),
        "{warnings}"
    );
    // systemd applies CPUQuota only where the user's manager has the cpu controller, which
    // Ubuntu 22.04 does not delegate.
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let delegated = format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.subtree_control"
    );
    let controllers = fs::read_to_string(&delegated).unwrap_or_default();
    if controllers.split_whitespace().any(|name| name == "cpu") {
        assert!(warnings.contains("--set-env GOMAXPROCS=1"), "{warnings}");
    } else {
        skip(
            "user-cpu-controller",
            &format!("{delegated} does not name the cpu controller: {controllers:?}"),
        );
    }
    // The program itself sees neither the value nor its own cgroup.
    let inside = probe_inside(&[], &[("read", "/proc/self/cgroup")]);
    inside[0].assert_blocked();
}

/// docs/linux.md, "Paths outside the policy are visible": an unprivileged fanotify group would
/// watch a directory outside the policy and report the files in it that change. Landlock has no
/// hook for it, so `fanotify_init` fails with `ENOSYS`, which is what a kernel without fanotify
/// returns; a program falls back to inotify.
#[test]
fn fanotify_groups_cannot_be_created() {
    let fixture = Fixture::new("conformance-fanotify");
    let secret = fixture.arg("secret");
    let outside = probe_outside(&[("fanotify-init", &secret)]);
    if outside[0].result != "ok" {
        return skip(
            "fanotify",
            &format!(
                "unprivileged fanotify does not work here: {}",
                outside[0].detail
            ),
        );
    }
    let inside = probe_inside(&fixture.access_args(), &[("fanotify-init", &secret)]);
    assert!(has_errno(&inside[0], libc::ENOSYS), "{inside:?}");
}

/// docs/linux.md, "Metadata": the extended attribute reads that take a path fail with `ENOTSUP`,
/// also for a file the policy allows, because the call names a path and Landlock does not check
/// it. The descriptor variants keep working, so a program reads the attributes of the files it
/// may open. With `path_metadata = "allow"` the path reads work again, like the path writes.
#[test]
fn extended_attributes_by_path_are_unreadable() {
    let fixture = Fixture::new("conformance-getxattr");
    let (secret, readable) = (fixture.arg("secret/file"), fixture.arg("ro/file"));
    let prepare = [
        ("setxattr-fd", secret.as_str()),
        ("setxattr-fd", readable.as_str()),
    ];
    let prepared = probe_outside(&prepare);
    if let Some(line) = prepared.iter().find(|line| line.result != "ok") {
        // tmpfs before Linux 6.6 has no user extended attributes.
        return skip(
            "extended-attributes",
            &format!("{} fails outside: {}", line.action, line.detail),
        );
    }
    let actions = [
        ("listxattr-path", secret.as_str()),
        ("listxattr-path", readable.as_str()),
        ("getxattr-fd", readable.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    let inside = probe_inside(&fixture.access_args(), &actions);
    assert!(has_errno(&inside[0], libc::ENOTSUP), "{inside:?}");
    assert!(has_errno(&inside[1], libc::ENOTSUP), "{inside:?}");
    inside[2].assert_ok();

    let mut allow = fixture.access_args();
    allow.extend(args(&["--linux-path-metadata", "allow"]));
    for line in probe_inside(&allow, &actions) {
        line.assert_ok();
    }
}

/// Records a documented limitation (docs/linux.md, "Paths outside the policy are visible"): an
/// inotify watch on a directory the program cannot list reports the names of the entries that
/// appear in it. Landlock has no hook for `inotify_add_watch`, and closing this would need a
/// mount namespace. The writer creates the entry again and again, so the watch cannot miss it
/// however the two runs interleave.
#[test]
fn inotify_reports_names_in_unlistable_directories() {
    let fixture = Fixture::new("conformance-inotify");
    let secret = fixture.arg("secret");
    let entry = fixture.path("secret/new-report-2026.pdf");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = fs::write(&entry, b"x");
                let _ = fs::remove_file(&entry);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    let actions = [("inotify-name", secret.as_str()), ("list", secret.as_str())];
    let lines = probe_inside(&fixture.access_args(), &actions);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
    assert_eq!(lines[0].detail, "new-report-2026.pdf", "{lines:?}");
    lines[1].assert_blocked();
}

/// Records a limitation that docs/linux.md, "Paths outside the policy are visible" now names: a
/// directory that the caller passes as standard input stays listable, because Landlock checks
/// the directory right when a path is opened and this descriptor was opened before the sandbox.
/// Opening an entry through it still needs a policy path.
#[test]
fn a_directory_on_standard_input_stays_listable() {
    let fixture = Fixture::new("conformance-dirfd");
    let secret = fixture.path("secret");
    // A fresh descriptor per run: two runs that share one would also share its directory
    // position, and the second would see no entry.
    let on_stdin = move |command: &mut Command| {
        let directory = fs::File::open(&secret).unwrap();
        command.stdin(std::process::Stdio::from(directory));
    };
    let file = fixture.arg("secret/file");
    let actions = [("list-fd", "0"), ("read", file.as_str())];
    let outside = parse(&run_with(probe_path(), probe_args(&actions), &on_stdin));
    outside[0].assert_ok();
    let lines = probe_inside_with(&fixture.access_args(), &actions, &on_stdin);
    assert_eq!(lines[0].detail, outside[0].detail, "{lines:?}");
    lines[1].assert_blocked();
}

/// docs/linux.md, "/proc": without a `/proc` grant the program cannot read `/proc/self/status`
/// and the other files of its own process, but `readlink("/proc/self/exe")` works, because
/// `readlink` is not a Landlock right. `std::env::current_exe` and the runtimes that use it
/// therefore keep working, which the documentation used to deny.
#[test]
fn the_programs_own_path_is_readable_without_proc() {
    let actions = [("current-exe", "-"), ("read", "/proc/self/status")];
    let outside = probe_outside(&actions);
    outside[0].assert_ok();
    let inside = probe_inside(&[], &actions);
    assert_eq!(inside[0].detail, outside[0].detail, "{inside:?}");
    inside[1].assert_blocked();
}

/// docs/linux.md, "Refusals": the kernel opens the loader that a program names in its ELF
/// header, so sandy refuses a policy that does not let the program execute it instead of letting
/// `execve` fail with "Permission denied" after the sandbox is in place. `system = "none"` leaves
/// the loaders of the minimal system set out, which is the case every host can show; a loader in
/// a system location that the set does not name is covered by the unit tests of `sandy-linux`.
#[test]
fn a_program_whose_loader_is_not_granted_is_refused() {
    let without_system = args(&["--system", "none"]);
    let run = sandy(run_args(&without_system, &[("open", "/etc/hostname")]));
    if run.status.success() {
        return skip(
            "dynamic-program",
            "the probe runs without a loader grant on this host, so it needs no loader",
        );
    }
    // The run cannot work, so `check` must say so instead of reporting every requirement as
    // enforced and leaving the failure to the `execve`.
    let probe = probe_path();
    let refused = sandy(["check", "--system", "none", probe.as_str()]);
    let report = String::from_utf8_lossy(&refused.stdout);
    assert!(
        report.contains("the kernel executes the loader"),
        "{report}"
    );
    assert_eq!(refused.status.code(), Some(1), "{report}");
    // The minimal system set grants the loader, so the same program is enforceable with it.
    let granted = sandy(["check", probe.as_str()]);
    assert!(granted.status.success(), "{granted:?}");
}

/// docs/linux.md, "Minimal system set": /etc/passwd is not in the set, so `getpwuid` finds no
/// entry for the user. A policy that needs the account name, home directory or shell of the
/// user adds `--read /etc/passwd`; /etc/nsswitch.conf is not needed, because glibc falls back
/// to the files back end.
#[test]
fn the_user_account_needs_a_grant_for_etc_passwd() {
    let actions = [("getpwuid", "-")];
    let outside = probe_outside(&actions);
    outside[0].assert_ok();
    probe_inside(&[], &actions)[0].assert_blocked();
    let granted = probe_inside(&args(&["--read", "/etc/passwd"]), &actions);
    assert_eq!(granted[0].detail, outside[0].detail, "{granted:?}");
}

/// docs/linux.md, "Metadata": the file system ioctls that change a file or a directory are
/// denied, so a `read` path grants none of them. They would otherwise work on every descriptor,
/// because Landlock checks ioctls only on device files. fs-verity needs a file system that
/// supports it, so that part runs in the build's temporary directory and is skipped elsewhere.
#[test]
fn file_system_ioctls_cannot_change_readable_files() {
    let fixture = Fixture::new("conformance-fdioctl");
    let (readable, writable) = (fixture.arg("ro/file"), fixture.arg("rw/file"));
    for file in [&readable, &writable] {
        let actions = [
            ("setflags-ro", file.as_str()),
            ("fsxattr-ro", file.as_str()),
        ];
        let outside = probe_outside(&actions);
        let inside = probe_inside(&fixture.access_args(), &actions);
        for (control, line) in outside.iter().zip(&inside) {
            if control.result != "ok" {
                skip(
                    "file-system-ioctls",
                    &format!("{} fails outside: {}", control.action, control.detail),
                );
                continue;
            }
            assert!(is_eperm(line), "control {control:?}, inside {line:?}");
        }
    }

    let Ok(parent) = Path::new(env!("CARGO_TARGET_TMPDIR")).canonicalize() else {
        return skip(
            "build-tmpdir",
            "the temporary directory of the build is not on this host",
        );
    };
    let fixture = Fixture::new_in(&parent, "conformance-verity");
    let verity = [("enable-verity", fixture.arg("ro/file"))];
    let verity: Vec<(&str, &str)> = verity
        .iter()
        .map(|(action, target)| (*action, target.as_str()))
        .collect();
    let outside = probe_outside(&verity);
    if outside[0].result != "ok" {
        return skip(
            "fs-verity",
            &format!("no fs-verity here: {}", outside[0].detail),
        );
    }
    // The control made the file permanently read-only, so the run inside needs a new one.
    fixture.reset();
    let inside = probe_inside(&fixture.access_args(), &verity);
    assert!(is_eperm(&inside[0]), "{inside:?}");
}

/// Records a documented limitation (docs/linux.md, "Metadata through open files"): `fchmod`,
/// `fsetxattr` and `futimens` work on a descriptor that a `read` path opened. seccomp sees only
/// the descriptor number, not how the file was opened, and Landlock has no metadata right. If
/// this test fails, sandy gained a way to tell the two apart and the limitation list should say
/// so.
#[test]
fn metadata_calls_on_a_read_only_descriptor_still_work() {
    let fixture = Fixture::new("conformance-fdmeta");
    let file = fixture.arg("ro/file");
    let actions = [
        ("fchmod-ro", file.as_str()),
        ("utime-ro", file.as_str()),
        ("setxattr-fd", file.as_str()),
    ];
    let outside = probe_outside(&actions);
    let inside = probe_inside(&fixture.access_args(), &actions);
    for (control, line) in outside.iter().zip(&inside) {
        if control.result != "ok" {
            skip(
                "metadata-calls",
                &format!("{} fails outside: {}", control.action, control.detail),
            );
            continue;
        }
        line.assert_ok();
    }
}

/// docs/linux.md, "Denylist": the program may switch address space randomization off for
/// itself, which `setarch -R` and record and replay debuggers need. Other personality values
/// stay denied; `denylisted_calls_fail_with_eperm_on_the_kernel` checks `READ_IMPLIES_EXEC`.
#[test]
fn address_randomization_can_be_switched_off() {
    const ADDR_NO_RANDOMIZE: libc::c_long = 0x4_0000;
    let call = format!("{}:{ADDR_NO_RANDOMIZE}", libc::SYS_personality);
    controlled(&[], &[("raw-syscall", &call)])[0].assert_ok();
}
