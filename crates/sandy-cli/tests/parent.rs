//! `process.end_with_parent`: the program ends when the process that started sandy ends.

mod common;

use std::fs;
use std::process::Command;
use std::time::Duration;

use common::*;

/// How long the program would run on its own, in milliseconds: much longer than the test.
const LONG_SLEEP: &str = "60000";
/// How long the parent runs after it started sandy, in milliseconds, so that sandy has started
/// the program before its parent ends.
const PARENT_LIFE: &str = "2000";

fn ending_with_parent(fixture: &Fixture) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend(["--signals", "isolated", "--end-with-parent"].map(String::from));
    args
}

/// Why this host cannot end the program with sandy's parent, if it cannot.
fn unsupported() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return Some("signal isolation needs Landlock ABI 6");
    }
    None
}

/// Starts sandy through a probe outside the sandbox, which ends `PARENT_LIFE` after it started
/// sandy. Returns sandy's process ID, after the probe has ended. The probe writes into a file:
/// on Windows, sandy would inherit a pipe from the probe and keep it open.
fn start_through_parent(
    fixture: &Fixture,
    sandbox_args: &[String],
    program: &[(&str, &str)],
) -> u32 {
    start_through(
        "start",
        Command::new(probe_path()),
        fixture,
        sandbox_args,
        program,
    )
}

/// As `start_through_parent`, with `parent` as the probe's command and `action` as the way it
/// starts sandy.
fn start_through(
    action: &str,
    mut parent: Command,
    fixture: &Fixture,
    sandbox_args: &[String],
    program: &[(&str, &str)],
) -> u32 {
    let start = sandy_command(sandbox_args, program);
    let report = fixture.path("parent-report");
    let status = parent
        .args(probe_args(&[(action, &start), ("sleep", PARENT_LIFE)]))
        .stdout(fs::File::create(&report).unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "the parent failed: {status:?}");
    started_process(&fs::read_to_string(&report).unwrap())
}

/// The sandy command line in the form the probe's starting actions take.
fn sandy_command(sandbox_args: &[String], program: &[(&str, &str)]) -> String {
    let mut command = vec![sandy_path()];
    command.extend(run_args(sandbox_args, program));
    command.join("\u{1f}")
}

/// The process ID in the first line of a probe report.
fn started_process(report: &str) -> u32 {
    let first = report.lines().next().unwrap_or_default();
    let fields: Vec<&str> = first.split('\t').collect();
    assert_eq!(
        fields.get(2),
        Some(&"ok"),
        "the parent could not start sandy: {first}"
    );
    fields[3].parse().unwrap()
}

/// `--parent-pid` and `--parent-start` with the placeholders the probe replaces with its own
/// process ID and start.
fn named_probe_parent(with_token: bool) -> Vec<String> {
    let mut args = vec!["--parent-pid".to_string(), "%pid%".to_string()];
    if with_token {
        args.extend(["--parent-start", "%start%"].map(String::from));
    }
    args
}

#[test]
fn the_program_ends_with_sandys_parent() {
    let fixture = Fixture::new("parent");
    let args = ending_with_parent(&fixture);
    if let Some(reason) = unsupported() {
        let output = sandy(run_args(&args, &[("env", "PATH")]));
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        skip("landlock-abi-6", &format!("{reason}; sandy refused"));
        return;
    }

    // Control: without the option, sandy and the program outlive the parent.
    let mut control = args.clone();
    control.retain(|arg| arg != "--end-with-parent");
    let pid = start_through_parent(&fixture, &control, &[("sleep", LONG_SLEEP)]);
    let ended = ends_soon(pid, Duration::from_secs(3));
    if !ended {
        kill_process(pid);
    }
    assert!(!ended, "control: sandy ended with its parent");

    // The program ends at the first request (SIGTERM on Linux and macOS), before the watcher's
    // 5 s grace period would end it by force.
    let pid = start_through_parent(&fixture, &args, &[("sleep", LONG_SLEEP)]);
    assert!(
        ends_soon(pid, Duration::from_secs(3)),
        "sandy {pid} did not end promptly with its parent"
    );
}

#[test]
fn end_with_parent_needs_isolated_signals() {
    let fixture = Fixture::new("parent-signals");
    let mut args = fixture.access_args();
    args.push("--end-with-parent".to_string());
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signals = \"isolated\""), "{stderr}");
}

/// A program that ignores SIGTERM is killed after the grace period.
#[cfg(unix)]
#[test]
fn a_program_that_ignores_the_request_is_killed() {
    let fixture = Fixture::new("parent-ignore");
    if unsupported().is_some() {
        return;
    }
    let program = [("ignore-signal", "15"), ("sleep", LONG_SLEEP)];
    let pid = start_through_parent(&fixture, &ending_with_parent(&fixture), &program);
    let parent_ended = std::time::Instant::now();
    assert!(
        ends_soon(pid, END_TIMEOUT),
        "sandy {pid} outlived its parent"
    );
    // The watcher waits 5 s after SIGTERM before it sends SIGKILL.
    assert!(
        parent_ended.elapsed() > Duration::from_secs(3),
        "the program ended after {:?}, before the grace period",
        parent_ended.elapsed()
    );
}

/// With `children = "contained"`, the watcher signals the supervising sandy, which ends the
/// program's whole process group.
#[cfg(unix)]
#[test]
fn contained_processes_end_with_sandys_parent() {
    let fixture = Fixture::new("parent-contained");
    if unsupported().is_some() {
        return;
    }
    let mut args = ending_with_parent(&fixture);
    args.extend(["--children", "contained"].map(String::from));
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    // On macOS, `contained` denies posix_spawn, which std's Command uses, so the probe forks.
    let action = if cfg!(target_os = "macos") {
        "start-forked"
    } else {
        "start"
    };
    let pid = start_through_parent(&fixture, &args, &[(action, &start), ("sleep", LONG_SLEEP)]);
    assert!(
        ends_soon(pid, END_TIMEOUT),
        "sandy {pid} outlived its parent"
    );
    // The process the program started runs the fixture's copy of the probe.
    let left = running(&program);
    assert!(left.is_empty(), "processes {left:?} outlived sandy");
}

/// The processes that run the executable `program`.
#[cfg(target_os = "macos")]
fn running(program: &str) -> Vec<u32> {
    let mut pids = vec![0 as libc::c_int; 8192];
    let size = (pids.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int;
    // SAFETY: the buffer holds `size` bytes.
    let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), size) };
    pids.truncate(count.max(0) as usize);
    pids.into_iter()
        .filter(|&pid| {
            let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            // SAFETY: the buffer holds the size passed.
            let length =
                unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
            length > 0 && &path[..length as usize] == program.as_bytes()
        })
        .map(|pid| pid as u32)
        .collect()
}

/// The processes whose command line starts with `program`.
#[cfg(target_os = "linux")]
fn running(program: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let command_line = fs::read(entry.path().join("cmdline")).ok()?;
            command_line.starts_with(program.as_bytes()).then_some(pid)
        })
        .collect()
}

/// The caller names its own process ID with `--parent-pid`; sandy refuses when its parent is
/// another process.
#[test]
fn a_named_parent_must_be_sandys_parent() {
    let fixture = Fixture::new("parent-named");
    let mut args = ending_with_parent(&fixture);
    let own = std::process::id().to_string();
    let other = (std::process::id() + 1).to_string();
    args.extend(["--parent-pid".to_string(), other.clone()]);
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    if unsupported().is_some() {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("not {other}")), "{stderr}");

    let last = args.len() - 1;
    args[last] = own;
    probe_inside(&args, &[("env", "PATH")]);

    let mut without_option = fixture.access_args();
    without_option.extend(["--parent-pid".to_string(), std::process::id().to_string()]);
    let output = sandy(run_args(&without_option, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

/// A parent that ends before sandy's `main` runs. The kernel gives sandy another parent at
/// once, so `getppid` can no longer find the caller. With its own process ID and start, the
/// caller says which process it means, and sandy refuses because that process is gone.
#[cfg(unix)]
#[test]
fn a_parent_that_ended_before_sandy_ran_is_refused() {
    let fixture = Fixture::new("parent-early");
    if unsupported().is_some() {
        return;
    }
    let mut args = ending_with_parent(&fixture);
    args.extend(named_probe_parent(true));
    let (pid, errors) = start_orphaned(&fixture, &args, &[("sleep", LONG_SLEEP)]);
    let ended = ends_soon(pid, END_TIMEOUT);
    if !ended {
        kill_process(pid);
    }
    assert!(
        ended,
        "sandy {pid} started the program for a parent that is gone"
    );
    let errors = fs::read_to_string(errors).unwrap();
    assert!(errors.contains("has already ended"), "{errors}");

    // Without a token sandy knows only that it has a parent, not which process started it.
    let (pid, errors) = start_orphaned(
        &fixture,
        &ending_with_parent(&fixture),
        &[("sleep", LONG_SLEEP)],
    );
    if cfg!(target_os = "macos") {
        // macOS has no subreaper: the parent of an orphan is launchd, which sandy refuses.
        let ended = ends_soon(pid, END_TIMEOUT);
        if !ended {
            kill_process(pid);
        }
        assert!(ended, "sandy {pid} watched launchd");
        let errors = fs::read_to_string(errors).unwrap();
        assert!(errors.contains("launchd"), "{errors}");
    } else {
        // Linux gives the orphan to the nearest subreaper, an ordinary process that sandy
        // cannot tell from a caller that is still there, so it starts the program.
        let running = is_running(pid);
        kill_process(pid);
        assert!(running, "sandy {pid} refused without being asked to");
        skip(
            "orphan-detection-without-a-token",
            "Linux re-parents an orphan to the nearest subreaper, which sandy cannot tell from \
             its caller; only --parent-start closes this",
        );
    }
}

/// Starts sandy through a probe that ends before sandy runs. Returns sandy's process ID and the
/// file that holds what it wrote to standard error.
#[cfg(unix)]
fn start_orphaned(
    fixture: &Fixture,
    sandbox_args: &[String],
    program: &[(&str, &str)],
) -> (u32, std::path::PathBuf) {
    let start = sandy_command(sandbox_args, program);
    let report = fixture.path("orphan-report");
    let errors = fixture.path("orphan-errors");
    let status = Command::new(probe_path())
        .args(probe_args(&[("start-orphaned", &start)]))
        .stdout(fs::File::create(&report).unwrap())
        .stderr(fs::File::create(&errors).unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "the parent failed: {status:?}");
    (
        started_process(&fs::read_to_string(&report).unwrap()),
        errors,
    )
}

/// A wrapper between the caller and sandy is sandy's parent, so `--parent-pid` alone is refused.
/// The caller adds the start of its own process, and sandy then watches the caller.
#[test]
fn a_named_parent_can_be_reached_through_a_wrapper() {
    let fixture = Fixture::new("parent-wrapper");
    let mut args = ending_with_parent(&fixture);
    args.extend(["--parent-pid".to_string(), std::process::id().to_string()]);
    let output = through_wrapper(&args, &[("env", "PATH")]);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    if unsupported().is_some() {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--parent-start"), "{stderr}");

    args.extend(["--parent-start".to_string(), start_token().to_string()]);
    let output = through_wrapper(&args, &[("env", "PATH")]);
    assert!(
        output.status.success(),
        "sandy refused the named parent behind a wrapper: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A token that does not belong to the named process is refused.
    let last = args.len() - 1;
    args[last] = (start_token() + 1).to_string();
    let output = through_wrapper(&args, &[("env", "PATH")]);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--parent-start"), "{stderr}");
}

/// Runs sandy from a shell, so the shell and not this process is sandy's parent. `exit` keeps
/// the shell from replacing itself with sandy, which it does for a script of one command.
fn through_wrapper(sandbox_args: &[String], program: &[(&str, &str)]) -> std::process::Output {
    let args = run_args(sandbox_args, program);
    let mut command = if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.arg("/c").arg(sandy_path()).args(args);
        command
    } else {
        let mut words = vec![shell_word(&sandy_path())];
        words.extend(args.iter().map(|arg| shell_word(arg)));
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("{}\nexit $?", words.join(" ")));
        command
    };
    command.output().unwrap()
}

/// A shell word that holds `value` literally.
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The program ends with the named parent even when a wrapper started sandy.
#[test]
fn the_program_ends_with_a_named_parent_behind_a_wrapper() {
    let fixture = Fixture::new("parent-wrapper-end");
    if unsupported().is_some() {
        return;
    }
    let mut args = ending_with_parent(&fixture);
    args.extend(named_probe_parent(true));
    // The program says that it runs, because the wrapper hides sandy's exit status and a
    // wrapper that already ended leaves a zombie, which still looks like a running process.
    let marker = fixture.arg("rw/started");
    let start = sandy_command(&args, &[("write", &marker), ("sleep", LONG_SLEEP)]);
    let report = fixture.path("parent-report");
    let mut parent = Command::new(probe_path())
        .args(probe_args(&[
            ("start-wrapped", &start),
            ("sleep", PARENT_LIFE),
        ]))
        .stdout(fs::File::create(&report).unwrap())
        .spawn()
        .unwrap();
    let pid = wait_for_report(&report);
    let started = exists_soon(&fixture.path("rw/started"));
    let _ = parent.wait();
    let ended = ends_soon(pid, END_TIMEOUT);
    if !ended {
        kill_process(pid);
    }
    assert!(started, "sandy refused the named parent behind a wrapper");
    assert!(ended, "the wrapped sandy {pid} outlived its named parent");
}

/// Whether `path` appears within five seconds.
fn exists_soon(path: &std::path::Path) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The process ID in `report`, once the probe has written its first line there.
fn wait_for_report(report: &std::path::Path) -> u32 {
    for _ in 0..100 {
        let written = fs::read_to_string(report).unwrap();
        if !written.lines().next().unwrap_or_default().is_empty() {
            return started_process(&written);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the parent did not start sandy");
}

/// The program stops itself while sandy's parent leads a process group of its own, in the
/// session of the test. When the parent ends, that group is orphaned and has a stopped member,
/// so the kernel sends SIGHUP and SIGCONT to every member. Such a signal does not pass the
/// Landlock signal scope, so it must not reach the watcher. The program ignores SIGHUP and
/// SIGTERM, so only the watcher's SIGKILL ends it. (If the process that adopts the program is in
/// the test's session, the group is not orphaned and the test passes without checking this.)
#[cfg(unix)]
#[test]
fn a_stopped_program_cannot_end_the_watcher_through_its_process_group() {
    use std::os::unix::process::CommandExt;

    let fixture = Fixture::new("parent-orphaned");
    if unsupported().is_some() {
        return;
    }
    let program = [
        ("ignore-signal", "1"),
        ("ignore-signal", "15"),
        ("stop-self", "4000"),
        ("sleep", LONG_SLEEP),
    ];
    let mut parent = Command::new(probe_path());
    parent.process_group(0);
    let pid = start_through(
        "start",
        parent,
        &fixture,
        &ending_with_parent(&fixture),
        &program,
    );
    let ended = ends_soon(pid, END_TIMEOUT);
    if !ended {
        kill_process(pid);
    }
    assert!(ended, "sandy {pid} outlived its parent");
}

/// Ctrl+C, a shell's SIGHUP to its jobs when the terminal closes, and `kill 0` signal the whole
/// process group of sandy's caller. The program ignores SIGINT; the signal must not end the
/// watcher, which then ends the program when the parent ends.
#[cfg(unix)]
#[test]
fn a_signal_to_the_callers_process_group_does_not_end_the_watcher() {
    use std::os::unix::process::CommandExt;

    let fixture = Fixture::new("parent-group-signal");
    if unsupported().is_some() {
        return;
    }
    let program = [("ignore-signal", "2"), ("sleep", LONG_SLEEP)];
    let mut sandy_command = vec![sandy_path()];
    sandy_command.extend(run_args(&ending_with_parent(&fixture), &program));
    let start = sandy_command.join("\u{1f}");
    let report = fixture.path("parent-report");
    let mut parent = Command::new(probe_path())
        .process_group(0)
        .args(probe_args(&[("start", &start), ("sleep", LONG_SLEEP)]))
        .stdout(fs::File::create(&report).unwrap())
        .spawn()
        .unwrap();
    let mut pid = None;
    for _ in 0..100 {
        let report = fs::read_to_string(&report).unwrap();
        if let Some(line) = report.lines().next() {
            pid = line
                .split('\t')
                .nth(3)
                .and_then(|pid| pid.parse::<u32>().ok());
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let pid = pid.expect("the parent did not start sandy");
    // Time for the program to ignore SIGINT; if it has not, it ends and the test passes anyway.
    std::thread::sleep(Duration::from_secs(1));
    // SAFETY: kill takes a process group ID and a signal.
    unsafe { libc::kill(-(parent.id() as libc::pid_t), libc::SIGINT) };
    let _ = parent.wait();
    let ended = ends_soon(pid, END_TIMEOUT);
    if !ended {
        kill_process(pid);
    }
    assert!(ended, "sandy {pid} outlived its parent");
}
