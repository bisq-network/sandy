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

fn skip(reason: &str) {
    eprintln!("skipped: {reason}");
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

/// The sandbox options of both process models: the exec model, and `children = "contained"`,
/// in which a forked child confines itself. `contained` needs isolated signals (Landlock ABI 6).
fn process_models(base: &[String]) -> Vec<Vec<String>> {
    let mut models = vec![base.to_vec()];
    if landlock_abi() >= 6 {
        let mut contained = base.to_vec();
        contained.extend(args(&["--children", "contained", "--signals", "isolated"]));
        models.push(contained);
    } else {
        skip("children = contained needs Landlock ABI 6; only the exec model is checked");
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
/// both filters, Landlock, no inherited descriptor, and none of sandy's or the guard's pipes.
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
        let filters: u32 = lines[6].detail.parse().unwrap();
        assert!(filters >= 2, "{context}");
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
            skip(&format!(
                "{}: fails outside: {}",
                control.target, control.detail
            ));
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
            skip(&format!("{} fails outside: {}", line.action, line.detail));
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
        return skip("Landlock checks device ioctls from ABI 5");
    }
    let Some(pty) = open_pty() else {
        return skip("no pseudo-terminal available");
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
        return skip("no /etc/crypto-policies/back-ends on this host");
    };
    let files: Vec<String> = entries
        .filter_map(|entry| Some(entry.ok()?.path().to_str()?.to_string()))
        .filter(|path| fs::read(path).is_ok())
        .collect();
    if files.is_empty() {
        return skip("no readable crypto policy files");
    }
    let actions: Vec<(&str, &str)> = files.iter().map(|path| ("read", path.as_str())).collect();
    for line in probe_inside(&[], &actions) {
        line.assert_ok();
    }
}

/// Records a documented limitation (docs/linux.md, "Paths outside the policy are visible"): an
/// unprivileged fanotify group can watch a directory outside the policy and learn when files in
/// it change, like an inotify watch. It reports events, not contents. If this test fails, the
/// kernel or the filter changed and the limitation list should say so.
#[test]
fn fanotify_watches_paths_outside_the_policy() {
    let fixture = Fixture::new("conformance-fanotify");
    let secret = fixture.arg("secret");
    let outside = probe_outside(&[("fanotify-init", &secret)]);
    if outside[0].result != "ok" {
        return skip(&format!(
            "unprivileged fanotify does not work here: {}",
            outside[0].detail
        ));
    }
    probe_inside(&fixture.access_args(), &[("fanotify-init", &secret)])[0].assert_ok();
}
