//! `process.children`: with `none` the program cannot start processes, and with `contained`
//! every process it started ends when it ends.

mod common;

use std::time::Instant;

use common::*;

/// How long the processes the program starts would run on their own, in milliseconds: much
/// longer than the test.
const LONG_SLEEP: &str = "60000";

#[test]
fn children_none_denies_starting_programs() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("children");
    let program = fixture.copy_probe("bin");

    // Control: the same policy without the option starts the program.
    let lines = probe_inside(&fixture.access_args(), &[("exec", &program)]);
    lines[0].assert_ok();

    let mut args = fixture.access_args();
    args.extend(["--children".to_string(), "none".to_string()]);
    let lines = probe_inside(&args, &[("exec", &program)]);
    lines[0].assert_blocked();
}

/// Options for `children = "contained"`, which needs isolated signals.
fn contained(fixture: &Fixture) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend(["--children", "contained", "--signals", "isolated"].map(String::from));
    args
}

/// Why this host cannot run `children = "contained"`, if it cannot.
fn unsupported() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        return Some("children = \"contained\" is not implemented on macOS");
    }
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return Some("signal isolation needs Landlock ABI 6");
    }
    None
}

#[test]
fn children_contained_ends_what_the_program_leaves_behind() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("contained");
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    if let Some(reason) = unsupported() {
        let output = sandy(run_args(&contained(&fixture), &[("start", &start)]));
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        eprintln!("skipped: {reason}; sandy refused");
        return;
    }

    // Control: without containment the process outlives the program. Windows ends the processes
    // of the program's job in any case.
    #[cfg(unix)]
    {
        let lines = probe_inside(&fixture.access_args(), &[("start", &start)]);
        lines[0].assert_ok();
        let pid: u32 = lines[0].detail.parse().unwrap();
        let survived = is_running(pid);
        kill_process(pid);
        assert!(survived, "control: process {pid} ended with the program");
    }

    let started = Instant::now();
    let lines = probe_inside(&contained(&fixture), &[("start", &start)]);
    // sandy ends the process; it does not wait until the process ends by itself.
    assert!(
        started.elapsed() < END_TIMEOUT,
        "sandy returned only after {:?}",
        started.elapsed()
    );
    lines[0].assert_ok();
    let pid: u32 = lines[0].detail.parse().unwrap();
    assert!(
        ends_soon(pid, END_TIMEOUT),
        "process {pid} outlived the program"
    );
}

#[test]
fn children_contained_needs_isolated_signals() {
    let fixture = Fixture::new("contained-signals");
    let mut args = contained(&fixture);
    args.truncate(args.len() - 2);
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signals = \"isolated\""), "{stderr}");
}
