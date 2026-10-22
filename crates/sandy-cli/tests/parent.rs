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
    if cfg!(target_os = "macos") {
        return Some("end_with_parent is not implemented on macOS");
    }
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
    start_through(Command::new(probe_path()), fixture, sandbox_args, program)
}

/// As `start_through_parent`, with `parent` as the probe's command.
fn start_through(
    mut parent: Command,
    fixture: &Fixture,
    sandbox_args: &[String],
    program: &[(&str, &str)],
) -> u32 {
    let mut sandy_command = vec![sandy_path()];
    sandy_command.extend(run_args(sandbox_args, program));
    let start = sandy_command.join("\u{1f}");
    let report = fixture.path("parent-report");
    let status = parent
        .args(probe_args(&[("start", &start), ("sleep", PARENT_LIFE)]))
        .stdout(fs::File::create(&report).unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "the parent failed: {status:?}");
    let report = fs::read_to_string(&report).unwrap();
    let first = report.lines().next().unwrap_or_default();
    let fields: Vec<&str> = first.split('\t').collect();
    assert_eq!(
        fields.get(2),
        Some(&"ok"),
        "the parent could not start sandy: {first}"
    );
    fields[3].parse().unwrap()
}

#[test]
fn the_program_ends_with_sandys_parent() {
    let fixture = Fixture::new("parent");
    let args = ending_with_parent(&fixture);
    if let Some(reason) = unsupported() {
        let output = sandy(run_args(&args, &[("env", "PATH")]));
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        eprintln!("skipped: {reason}; sandy refused");
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

    // The program ends at the first request (SIGTERM on Linux), before the watcher's 5 s grace
    // period would end it by force.
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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
    let pid = start_through_parent(&fixture, &args, &[("start", &start), ("sleep", LONG_SLEEP)]);
    assert!(
        ends_soon(pid, END_TIMEOUT),
        "sandy {pid} outlived its parent"
    );
    // The process the program started runs the fixture's copy of the probe.
    let left = running(&program);
    assert!(left.is_empty(), "processes {left:?} outlived sandy");
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

/// The program stops itself while sandy's parent leads a process group of its own, in the
/// session of the test. When the parent ends, that group is orphaned and has a stopped member,
/// so the kernel sends SIGHUP and SIGCONT to every member. Such a signal does not pass the
/// Landlock signal scope, so it must not reach the watcher. The program ignores SIGHUP and
/// SIGTERM, so only the watcher's SIGKILL ends it. (If the process that adopts the program is in
/// the test's session, the group is not orphaned and the test passes without checking this.)
#[cfg(target_os = "linux")]
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
    let pid = start_through(parent, &fixture, &ending_with_parent(&fixture), &program);
    let ended = ends_soon(pid, END_TIMEOUT);
    if !ended {
        kill_process(pid);
    }
    assert!(ended, "sandy {pid} outlived its parent");
}

/// Ctrl+C, a shell's SIGHUP to its jobs when the terminal closes, and `kill 0` signal the whole
/// process group of sandy's caller. The program ignores SIGINT; the signal must not end the
/// watcher, which then ends the program when the parent ends.
#[cfg(target_os = "linux")]
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
