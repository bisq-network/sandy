//! The diagnostic mode of `run` (`--explain`) on Linux: it must name the paths the policy does
//! not grant, stay off by default, and change nothing the sandbox enforces.
//!
//! The case it exists for is the program that says nothing: `read-optional` reports success
//! whether it could read the file or not, as programs do with data they can do without.
#![cfg(target_os = "linux")]

mod common;

use std::process::Output;

use common::*;

/// The prefix of every line of the diagnostic mode on standard error.
const EXPLAIN: &str = "sandy explain: ";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// The lines of the diagnostic mode, without their prefix.
fn explained(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| line.strip_prefix(EXPLAIN).map(str::to_string))
        .collect()
}

fn run(sandbox_args: &[String], actions: &[(&str, &str)]) -> Output {
    sandy(run_args(sandbox_args, actions))
}

#[test]
fn the_mode_names_a_path_the_program_does_not_complain_about() {
    let fixture = Fixture::new("explain-silent");
    let secret = fixture.arg("secret/file");
    let actions = [("read-optional", secret.as_str())];
    let output = run(&fixture.access_args(), &actions);
    let lines = parse(&output);
    assert!(output.status.success(), "{output:?}");
    // The program is content: it ran without the file and reported no failure.
    assert_eq!(lines[0].result, "ok", "{lines:?}");
    assert_eq!(lines[0].detail, "without it", "{lines:?}");
    assert!(
        explained(&output).is_empty(),
        "the mode is off: {:?}",
        explained(&output)
    );

    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let output = run(&with_mode, &actions);
    assert!(output.status.success(), "{output:?}");
    let lines = explained(&output);
    assert!(
        lines.iter().any(|line| line.contains("on.")),
        "no line says the mode is on: {lines:?}"
    );
    let named = lines
        .iter()
        .any(|line| line.contains(&format!("cannot read {secret}")) && line.contains("read"));
    assert!(named, "the denied path is not named: {lines:?}");
    assert!(
        lines
            .last()
            .is_some_and(|line| line.contains("watched calls")),
        "no summary: {lines:?}"
    );

    // Control: the same path once the policy grants it. The mode stays on and reports nothing.
    let mut granted = with_mode.clone();
    granted.extend(args(&["--read", &fixture.arg("secret")]));
    let output = run(&granted, &actions);
    let lines = explained(&output);
    assert_eq!(parse(&output)[0].detail, "7 bytes", "{output:?}");
    assert!(
        !lines.iter().any(|line| line.contains(&secret)),
        "a granted path is reported: {lines:?}"
    );
}

/// The mode must not be a way around the sandbox: what the program may do is the same with it
/// and without it, and so is the exit status.
#[test]
fn the_mode_changes_nothing_the_sandbox_enforces() {
    let fixture = Fixture::new("explain-enforce");
    let program = fixture.copy_probe("bin");
    let actions = [
        ("read", fixture.arg("ro/file")),
        ("read", fixture.arg("secret/file")),
        ("write", fixture.arg("rw/file")),
        ("write", fixture.arg("secret/new")),
        ("mkdir", fixture.arg("secret/dir")),
        ("exec", program),
        ("read", "/etc/shadow".to_string()),
    ];
    let actions: Vec<(&str, &str)> = actions
        .iter()
        .map(|(action, target)| (*action, target.as_str()))
        .collect();
    let plain = run(&fixture.access_args(), &actions);
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let explained_run = run(&with_mode, &actions);

    assert_eq!(
        plain.status.code(),
        explained_run.status.code(),
        "the exit status differs: {plain:?} {explained_run:?}"
    );
    let results = |output: &Output| {
        parse(output)
            .into_iter()
            .map(|line| format!("{} {} {}", line.action, line.target, line.result))
            .collect::<Vec<_>>()
    };
    let plain_results = results(&plain);
    assert_eq!(plain_results.len(), actions.len(), "{plain:?}");
    assert_eq!(
        plain_results,
        results(&explained_run),
        "the sandbox allowed something else with the mode on"
    );
    // The run is only a control when the sandbox denied something at all.
    assert!(
        plain_results.iter().any(|line| line.ends_with("denied")),
        "nothing was denied: {plain_results:?}"
    );
    assert!(
        explained(&explained_run).len() > 1,
        "the mode reported nothing: {explained_run:?}"
    );
}

/// Every process of the program is watched, not only the first: the filter is inherited.
#[test]
fn the_mode_names_a_path_a_child_of_the_program_uses() {
    let fixture = Fixture::new("explain-child");
    let program = fixture.copy_probe("bin");
    let denied = fixture.arg("secret/file");
    // `spawn` runs the probe again and waits for it, so the read happens in a child process.
    let child = format!("{program}\u{1f}read-optional\u{1f}{denied}");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let output = run(&with_mode, &[("spawn", child.as_str())]);
    assert!(output.status.success(), "{output:?}");
    let lines = explained(&output);
    assert!(
        lines.iter().any(|line| line.contains(&denied)),
        "the child's path is not named: {lines:?}"
    );
}

#[test]
fn the_mode_works_while_sandy_contains_the_children() {
    let fixture = Fixture::new("explain-contained");
    let denied = fixture.arg("secret/file");
    let mut with_mode = fixture.access_args();
    with_mode.extend(args(&[
        "--signals",
        "isolated",
        "--children",
        "contained",
        "--explain",
    ]));
    let output = run(&with_mode, &[("read-optional", denied.as_str())]);
    assert!(output.status.success(), "{output:?}");
    let lines = explained(&output);
    assert!(
        lines.iter().any(|line| line.contains(&denied)),
        "the path is not named: {lines:?}"
    );
}

/// sandy stays the program's parent in this mode, so it cannot pass on the signals that
/// `end_with_parent` sends it. The combination is refused instead of ending the program late.
#[test]
fn the_mode_is_refused_with_end_with_parent() {
    let fixture = Fixture::new("explain-parent");
    let mut with_mode = fixture.access_args();
    with_mode.extend(args(&[
        "--signals",
        "isolated",
        "--end-with-parent",
        "--explain",
    ]));
    let output = run(&with_mode, &[("read", &fixture.arg("ro/file"))]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(stderr.contains("end_with_parent"), "{stderr}");

    // Control: the same policy with `contained`, where the supervising sandy passes them on.
    let mut contained = fixture.access_args();
    contained.extend(args(&[
        "--signals",
        "isolated",
        "--children",
        "contained",
        "--end-with-parent",
        "--explain",
    ]));
    let output = run(&contained, &[("read", &fixture.arg("ro/file"))]);
    assert!(output.status.success(), "{output:?}");
}

/// The mode must leave the program no descriptor of its own: neither the socket that carries
/// the notification descriptor nor that descriptor itself may survive the execve, or the
/// program would hold the listener of its own filter.
#[test]
fn the_mode_leaves_the_program_no_descriptor() {
    let fixture = Fixture::new("explain-descriptors");
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&["--read", "/proc"]));
    let actions = [("list", "/proc/self/fd")];
    let plain = run(&sandbox_args, &actions);
    let mut with_mode = sandbox_args.clone();
    with_mode.push("--explain".to_string());
    let explained = run(&with_mode, &actions);
    let descriptors = |output: &Output| {
        let line = parse(output).remove(0);
        line.assert_ok();
        line.detail
    };
    assert_eq!(descriptors(&plain), descriptors(&explained));
}

/// A reader of the report that goes away must not take the watcher with it: the program would
/// lose its watcher and every watched call would fail with ENOSYS from then on.
#[test]
fn a_closed_report_does_not_break_the_program() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let fixture = Fixture::new("explain-closed-report");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let (late, secret) = (fixture.arg("rw/late"), fixture.arg("secret/file"));
    let actions = [
        ("sleep", "500"),
        // Reported while nothing reads the report any more.
        ("read-optional", secret.as_str()),
        ("write", late.as_str()),
    ];
    let mut child = Command::new(sandy_path())
        .args(run_args(&with_mode, &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The banner comes before the program runs. Closing the pipe here leaves the rest of the
    // report without a reader while the program sleeps.
    let mut banner = String::new();
    let stderr = child.stderr.take().expect("the report pipe");
    BufReader::new(stderr).read_line(&mut banner).unwrap();
    assert!(banner.starts_with(EXPLAIN), "{banner:?}");

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "{lines:?}");
    lines[2].assert_ok();
    assert!(fixture.path("rw/late").exists(), "the write did not happen");
}

/// sandy waits for the program in this mode, so it must pass on the program's exit status.
#[test]
fn the_program_keeps_its_exit_status() {
    let fixture = Fixture::new("explain-status");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let output = run(&with_mode, &[("exit", "7")]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
}
