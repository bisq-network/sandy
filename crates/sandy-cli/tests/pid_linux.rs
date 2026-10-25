//! `children = "contained"` with a PID namespace on Linux: the program runs as PID 2 below an init
//! of sandy, and the namespace ends with the program (docs/linux.md, "Contained child processes").
//! Every check has a control without the namespace where one exists.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use common::*;

const MECHANISM: &str = "a PID namespace of the sandbox's own";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn contained() -> Vec<String> {
    args(&["--children", "contained", "--signals", "isolated"])
}

fn has_errno(line: &ProbeLine, errno: i32) -> bool {
    line.result != "ok" && line.detail.contains(&format!("os error {errno})"))
}

/// Whether `contained` runs the program in a PID namespace here, as `check` says; records a skip
/// when not. Where user namespaces are unusable, `contained` keeps its process group alone.
fn pid_namespace_works() -> bool {
    let mut check = vec!["check".to_string()];
    check.extend(contained());
    let output = sandy(&check);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() && stdout.contains(MECHANISM) {
        return true;
    }
    skip(
        "pid-namespace",
        &format!(
            "contained gets no PID namespace here: {}",
            stdout
                .lines()
                .find(|line| line.contains("child processes") || line.contains("signals"))
                .unwrap_or("check failed")
        ),
    );
    false
}

/// The program is PID 2, and a signal from the program to its init, PID 1, even SIGKILL, ends
/// nothing: the program goes on to its next action.
#[test]
fn the_program_runs_as_pid_2_below_an_init_of_sandy() {
    if !pid_namespace_works() {
        return;
    }
    let lines = probe_inside(
        &contained(),
        &[
            ("pid", "-"),
            ("kill-signal", "1:15"),
            ("kill-signal", "1:9"),
            ("pid", "-"),
        ],
    );
    assert_eq!(lines[0].detail, "2", "{lines:?}");
    // With the Landlock signal scope the init is outside the program's domain (EPERM); without,
    // the kernel drops a signal from inside the namespace to a PID 1 without a handler.
    for line in &lines[1..3] {
        assert!(
            line.result == "ok" || has_errno(line, libc::EPERM),
            "{lines:?}"
        );
    }
    assert_eq!(lines[3].detail, "2", "{lines:?}");
}

/// An orphan of the program is re-parented to the init, which reaps it: no zombie stays.
#[test]
fn orphans_are_reaped() {
    if !pid_namespace_works() {
        return;
    }
    let lines = probe_inside(&contained(), &[("orphan-reaped", "-")]);
    assert_eq!(lines[0].detail, "reaped", "{lines:?}");
}

/// A policy that grants /proc keeps `contained` without a PID namespace, also with the file system
/// view: a /proc of the namespace would hide the host's files the policy grants. So /proc/meminfo
/// stays readable, and /proc lists the host's processes as without `contained`.
#[test]
fn a_proc_grant_keeps_its_host_files_with_contained() {
    if !pid_namespace_works() {
        return;
    }
    let mut sandbox_args = contained();
    sandbox_args.extend(args(&["--view", "policy", "--read", "/proc"]));
    let mut check = vec!["check".to_string()];
    check.extend(sandbox_args.iter().cloned());
    let stdout = String::from_utf8_lossy(&sandy(&check).stdout).into_owned();
    if common::linux::landlock_abi() < 6 {
        // Without the namespace nothing isolates signals below ABI 6.
        assert!(
            stdout.contains("gets no PID namespace while the policy"),
            "{stdout}"
        );
        return;
    }
    assert!(!stdout.contains(MECHANISM), "{stdout}");
    let lines = probe_inside(
        &sandbox_args,
        &[("read", "/proc/meminfo"), ("proc-pids", "/proc")],
    );
    lines[0].assert_ok();
    assert!(lines[1].detail.split(',').count() > 10, "{lines:?}");
}

/// The init is undumpable, so its /proc files belong to root: no other process of the user reads
/// its environment, which is sandy's. Control: the program's, which execve made dumpable again.
#[test]
fn the_init_is_undumpable() {
    if !pid_namespace_works() {
        return;
    }
    let (reader, mut child) = spawn_with_status(&contained(), &[("sleep", "3000")]);
    let mut first = String::new();
    BufReader::new(reader).read_line(&mut first).unwrap();
    let program: u32 = first.trim().strip_prefix("pid ").unwrap().parse().unwrap();
    let init = children_of(child.id())
        .into_iter()
        .find(|&pid| {
            let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .is_some_and(|ids| ids.split_whitespace().nth(1) == Some("1"))
        })
        .expect("no init");
    let environ = |pid: u32| fs::read(format!("/proc/{pid}/environ"));
    let init_environ = environ(init);
    let program_environ = environ(program);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        init_environ.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied)
    );
    assert!(program_environ.is_ok(), "{program_environ:?}");
}

/// Processes outside the namespace have no process ID inside it, so the program reaches none of
/// them by ID: kill and pidfd_open answer ESRCH. With `signals = "any"` and no namespace the same
/// calls reach the test process.
#[test]
fn processes_outside_are_unreachable_by_id() {
    if !pid_namespace_works() {
        return;
    }
    let outside = std::process::id().to_string();
    let actions = [
        ("signal", outside.as_str()),
        ("pidfd-open", outside.as_str()),
    ];
    for line in probe_inside(&args(&["--signals", "any"]), &actions) {
        line.assert_ok();
    }
    for line in probe_inside(&contained(), &actions) {
        assert!(has_errno(&line, libc::ESRCH), "{line:?}");
    }
}

/// The program's process group holds only its own processes: the guard is outside it, so a
/// SIGKILL to the whole group ends the program and what it started, and sandy reports the
/// program's signal death, not a guard that ended. Below Landlock ABI 6 nothing but the namespace
/// and the group keep such a signal from the guard.
#[test]
fn a_signal_to_the_programs_group_reaches_only_the_program() {
    if !pid_namespace_works() {
        return;
    }
    let output = sandy(run_args(&contained(), &[("kill-signal", "0:9")]));
    assert_eq!(output.status.code(), Some(128 + 9), "{output:?}");
}

/// Below Landlock ABI 6, `signals = "isolated"` holds for `contained` through the PID namespace,
/// and `check` names that mechanism. From ABI 6 the Landlock scope comes first.
#[test]
fn check_names_the_pid_namespace_for_isolated_signals_below_abi_6() {
    if !pid_namespace_works() {
        return;
    }
    let mut check = vec!["check".to_string()];
    check.extend(contained());
    let stdout = String::from_utf8_lossy(&sandy(&check).stdout).into_owned();
    let line = stdout
        .lines()
        .find(|line| line.contains("signals limited to the sandbox"))
        .unwrap_or_default()
        .to_string();
    assert!(line.starts_with("enforced"), "{stdout}");
    if common::linux::landlock_abi() < 6 {
        assert!(line.contains(MECHANISM), "{line}");
        // Without contained there is no namespace, and the ABI cannot isolate signals.
        let alone = sandy(["check", "--signals", "isolated"]);
        assert_eq!(alone.status.code(), Some(1), "{alone:?}");
    } else {
        assert!(line.contains("Landlock ABI 6 signal scope"), "{line}");
    }
}

/// The status record names the program by its process ID outside the namespace, which is sandy's
/// child, so that a caller can signal it and sandy can follow its stops; inside it is PID 2.
#[test]
fn the_status_record_names_the_program_outside_its_namespace() {
    if !pid_namespace_works() {
        return;
    }
    let (reader, mut child) = spawn_with_status(&contained(), &[("sleep", "3000")]);
    let mut first = String::new();
    BufReader::new(reader).read_line(&mut first).unwrap();
    let pid: u32 = first.trim().strip_prefix("pid ").unwrap().parse().unwrap();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        field("NSpid:"),
        vec![pid.to_string(), "2".to_string()],
        "{status}"
    );
    assert_eq!(field("PPid:"), vec![child.id().to_string()], "{status}");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The residual of `contained` without a namespace, sandy and the guard both killed with
/// SIGKILL, ends the program here: the init watches sandy through a pidfd and ends, and with it
/// every process of the namespace.
#[test]
fn the_namespace_ends_when_sandy_and_the_guard_are_killed() {
    if !pid_namespace_works() {
        return;
    }
    let (reader, mut child) = spawn_with_status(&contained(), &[("sleep", "30000")]);
    let mut first = String::new();
    BufReader::new(reader).read_line(&mut first).unwrap();
    let program: u32 = first.trim().strip_prefix("pid ").unwrap().parse().unwrap();
    let sandy = child.id();
    // The guard is sandy's child that leads a group of its own and is not in the namespace.
    let guard = children_of(sandy)
        .into_iter()
        .find(|&pid| {
            let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let single = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .is_some_and(|ids| ids.split_whitespace().count() == 1);
            let live = !status.lines().any(|line| line.starts_with("State:\tZ"));
            single && live && pid != program
        })
        .expect("no guard");
    kill_process(guard);
    kill_process(sandy);
    let _ = child.wait();
    assert!(
        ends_soon(program, END_TIMEOUT),
        "the program outlived sandy and the guard"
    );
}

/// A host can give sandy user and network namespaces and still refuse it a PID namespace, as one
/// whose `user.max_pid_namespaces` is 0 does. With `ip = "private"` or `view = "policy"` the run of
/// `contained` asks for all of them in one `unshare`, so `check` tries the PID namespace too and
/// refuses where `run` does. `contained` alone tries it in every plan and keeps its process group
/// without one, from Landlock ABI 6; below, where only the namespace isolates signals, both
/// refuse. Control: without the outer filter all of them work.
#[test]
fn check_tries_the_pid_namespace_where_the_run_needs_one() {
    if !pid_namespace_works() {
        return;
    }
    let mut modes = vec![Vec::new(), args(&["--ip", "private"])];
    if sandy(["check", "--view", "policy"]).status.success() {
        modes.push(args(&["--view", "policy"]));
    }
    for mode in modes {
        let mut sandbox_args = contained();
        sandbox_args.extend(mode.iter().cloned());
        let mut check = vec!["check".to_string()];
        check.extend(sandbox_args.iter().cloned());
        let run = run_args(&sandbox_args, &[("pid", "-")]);
        assert_eq!(sandy(&check).status.code(), Some(0), "{mode:?}");
        assert_eq!(sandy(&run).status.code(), Some(0), "{mode:?}");

        let checked = without_pid_namespaces(&check);
        let ran = without_pid_namespaces(&run);
        if mode.is_empty() && common::linux::landlock_abi() >= 6 {
            assert_eq!(checked.status.code(), Some(0), "{checked:?}");
            assert!(
                !String::from_utf8_lossy(&checked.stdout).contains(MECHANISM),
                "{checked:?}"
            );
            assert_eq!(ran.status.code(), Some(0), "{ran:?}");
        } else if mode.is_empty() {
            // Below ABI 6 only the namespace isolates signals, so both refuse without it.
            assert_eq!(checked.status.code(), Some(1), "{checked:?}");
            assert_eq!(ran.status.code(), Some(EXIT_FAILURE), "{ran:?}");
        } else {
            assert_eq!(ran.status.code(), Some(EXIT_FAILURE), "{mode:?}: {ran:?}");
            assert_eq!(checked.status.code(), Some(1), "{mode:?}: {checked:?}");
            assert!(
                String::from_utf8_lossy(&checked.stdout)
                    .contains("a trial of the sandbox's namespaces failed"),
                "{checked:?}"
            );
        }
    }
}

/// Runs sandy with `arguments` where `unshare` and `clone` fail with EPERM whenever they ask for a
/// new PID namespace, and every other call works.
fn without_pid_namespaces(arguments: &[String]) -> std::process::Output {
    use std::mem::offset_of;
    let statement = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let load = |offset: usize| statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset as u32);
    let equals = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    let filter = [
        load(offset_of!(libc::seccomp_data, nr)),
        jump(equals, libc::SYS_unshare as u32, 2, 0),
        jump(equals, libc::SYS_clone as u32, 1, 0),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        // The flags, the first argument of both calls; CLONE_NEWPID is in their low word.
        load(offset_of!(libc::seccomp_data, args)),
        jump(
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            libc::CLONE_NEWPID as u32,
            0,
            1,
        ),
        statement(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    let address = &program as *const libc::sock_fprog as usize;
    let mut command = Command::new(sandy_path());
    command.args(arguments);
    // SAFETY: prctl is async-signal-safe, and the filter it reads lives until the child has
    // started, because `output` returns only after the spawn.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, address) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output().unwrap()
}

/// The PID namespace belongs to a user namespace of sandy's own, which maps only the user's own
/// IDs, so files of root show the owner 65534 inside, as with `ip = "private"`. Control: without
/// `contained` there is no namespace, and the owner is root.
#[test]
fn files_of_root_show_the_owner_65534_in_the_pid_namespace() {
    if !pid_namespace_works() {
        return;
    }
    let actions = [("lstat", "/")];
    let outside = probe_inside(&[], &actions);
    assert_eq!(outside[0].detail, "directory owner 0", "{outside:?}");
    let inside = probe_inside(&contained(), &actions);
    assert_eq!(inside[0].detail, "directory owner 65534", "{inside:?}");
}

/// The children of process `parent`, from the parent field of `/proc/PID/stat`.
fn children_of(parent: u32) -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let stat = fs::read_to_string(entry.path().join("stat")).ok()?;
            let ppid: u32 = stat[stat.rfind(')')? + 2..]
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect()
}

/// Starts sandy with `--status-fd 3` and returns the read end of the record and the child.
fn spawn_with_status(
    sandbox_args: &[String],
    actions: &[(&str, &str)],
) -> (fs::File, std::process::Child) {
    let mut ends = [0; 2];
    // SAFETY: pipe2 writes two new close-on-exec descriptors into `ends`.
    let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(made, 0, "cannot create the status pipe");
    // SAFETY: both descriptors are new and nothing else owns them.
    let (reader, writer) = unsafe {
        (
            fs::File::from_raw_fd(ends[0]),
            OwnedFd::from_raw_fd(ends[1]),
        )
    };
    let raw = writer.as_raw_fd();
    let mut run = run_args(sandbox_args, actions);
    run.splice(1..1, args(&["--status-fd", "3"]));
    let mut command = Command::new(sandy_path());
    command
        .args(run)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: dup2 is async-signal-safe and the closure calls nothing else.
    unsafe {
        command.pre_exec(move || match libc::dup2(raw, 3) {
            3 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        });
    }
    let child = command.spawn().unwrap();
    drop(writer);
    (reader, child)
}
