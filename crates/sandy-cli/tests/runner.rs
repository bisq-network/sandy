//! What the host that runs the suite must deliver.
//!
//! libtest knows no outcome between ok and failed, so a check that cannot run on this host
//! reports ok like a check that ran. `common::skip` records every such check; this file compares
//! the skips of a run with the list committed for the runner, so a check that quietly
//! disappears becomes a diff to review instead of a silent pass. It also holds the Landlock ABI
//! floor of a Linux runner.
//!
//! The variables that steer the accounting:
//!
//! - `SANDY_TEST_SKIP_LOG`: the file every skip of the run is appended to.
//! - `SANDY_TEST_RUNNER`: the name of this runner. It names the expected-skip list in
//!   `tests/expected-skips/`.
//! - `SANDY_TEST_REQUIRE`: features that must not be skipped on this host, separated by commas,
//!   or `all`. Skipping one fails that test.
//! - `SANDY_TEST_MIN_LANDLOCK_ABI`: the lowest Landlock ABI this runner must report.
//!
//! `skips_match_the_expected_list` needs the log of a whole run, so it is ignored by default and
//! runs after the suite:
//!
//! ```sh
//! export SANDY_TEST_SKIP_LOG=$PWD/skips.log SANDY_TEST_RUNNER=my-host
//! rm -f "$SANDY_TEST_SKIP_LOG"
//! cargo test --workspace --all-targets --no-fail-fast
//! cargo test -p sandy-cli --test runner -- --ignored --exact skips_match_the_expected_list
//! ```

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::*;

/// The expected skips of each runner, embedded so a test binary that was copied to another host
/// carries them (see `SANDY_TEST_BIN_DIR`). A new runner needs a file and a line here.
const EXPECTED_SKIPS: &[(&str, &str)] = &[
    ("fedora-44", include_str!("expected-skips/fedora-44.txt")),
    (
        "macos-26-arm",
        include_str!("expected-skips/macos-26-arm.txt"),
    ),
];

/// Set for the test binary that the self-checks below start, so that one test skips a feature.
const SELF_CHECK_VARIABLE: &str = "SANDY_TEST_SELF_CHECK";

/// The value of `name`, or `None` when it is unset or empty. A workflow that leaves a matrix
/// value out passes an empty string.
fn variable(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

#[test]
#[ignore = "needs the skip log of a whole run: see the comment at the top of this file"]
fn skips_match_the_expected_list() {
    let runner = variable("SANDY_TEST_RUNNER").expect("SANDY_TEST_RUNNER names this runner");
    let log = variable("SANDY_TEST_SKIP_LOG").expect("SANDY_TEST_SKIP_LOG is the log of the run");
    let happened = logged_skips(&log);
    let list = |skips: &BTreeSet<String>| {
        skips
            .iter()
            .map(|skip| format!("{skip}\n"))
            .collect::<String>()
    };
    let Some((_, text)) = EXPECTED_SKIPS.iter().find(|(name, _)| *name == runner) else {
        panic!(
            "no tests/expected-skips/{runner}.txt. Commit this run's skips as that file and add \
             it to EXPECTED_SKIPS in tests/runner.rs:\n{}",
            list(&happened)
        );
    };
    let expected = expected_skips(text);

    let mut problems: Vec<String> = happened
        .difference(&expected)
        .map(|skip| format!("not checked, and not expected to be skipped on {runner}: {skip}"))
        .collect();
    problems.extend(
        expected.difference(&happened).map(|skip| {
            format!("expected to be skipped on {runner}, but no test skipped it: {skip}")
        }),
    );
    assert!(
        problems.is_empty(),
        "the skips of this run differ from tests/expected-skips/{runner}.txt:\n{}\n\nA skip that \
         appeared means a check stopped running on this runner: find out why, or record it in \
         the list. A skip that disappeared means the list is stale, or the check it covered was \
         removed. The skips of this run:\n{}",
        problems.join("\n"),
        list(&happened)
    );
    println!(
        "{} checks were skipped on {runner}, as expected",
        happened.len()
    );
}

/// The whole log line is `BINARY<TAB>TEST<TAB>FEATURE<TAB>REASON`; the reason holds host
/// specifics (a path, an error message) and is not compared. Repeated skips of the same check
/// count once. A run that skips nothing writes no file at all, so a missing file is an empty
/// log; `SANDY_TEST_SKIP_LOG` must therefore be set for the whole run, not only for this test.
fn logged_skips(path: &str) -> BTreeSet<String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert!(fields.len() >= 4, "malformed line in {path}: {line:?}");
            fields[..3].join(" ")
        })
        .collect()
}

/// One `BINARY TEST FEATURE` per line. Blank lines and lines that start with `#` are comments.
fn expected_skips(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "expected BINARY TEST FEATURE: {line:?}");
            fields.join(" ")
        })
        .collect()
}

/// A runner that loses Landlock, or gains an older kernel, would make every check that needs a
/// Landlock right skip while the suite stays green. Unset, this runner states no floor and
/// there is nothing to check.
#[cfg(target_os = "linux")]
#[test]
fn landlock_abi_meets_the_minimum() {
    let Some(minimum) = variable("SANDY_TEST_MIN_LANDLOCK_ABI") else {
        return;
    };
    let minimum: i64 = minimum
        .parse()
        .expect("SANDY_TEST_MIN_LANDLOCK_ABI is a number");
    let abi = common::linux::landlock_abi();
    assert!(
        abi >= minimum,
        "this host reports Landlock ABI {abi}, below the {minimum} this runner must have"
    );
}

/// Drives the self-checks below: with `SANDY_TEST_SELF_CHECK` set it skips one fixed feature, so
/// the checks can see what `common::skip` does with it. A normal run records nothing here.
#[test]
fn self_check_driver() {
    if std::env::var_os(SELF_CHECK_VARIABLE).is_some() {
        skip("self-check", "drives the skip accounting self-checks");
    }
}

/// A skipped check lands in the log, named by binary, test and feature.
#[test]
fn a_skipped_check_is_logged() {
    let log = log_path("logged");
    let output = run_self_check(&log, None);
    assert!(output.status.success(), "the driver failed: {output:?}");
    let logged = fs::read_to_string(&log).unwrap();
    assert_eq!(
        logged.lines().collect::<Vec<&str>>(),
        ["runner\tself_check_driver\tself-check\tdrives the skip accounting self-checks"],
        "skip log: {logged:?}"
    );
    let _ = fs::remove_file(&log);
}

/// A feature that `SANDY_TEST_REQUIRE` demands cannot be skipped: the test fails instead of
/// reporting ok, and the log still shows what was not checked.
#[test]
fn a_required_check_cannot_be_skipped() {
    let log = log_path("required");
    let output = run_self_check(&log, Some("pty,self-check"));
    assert!(
        !output.status.success(),
        "skipping a required feature passed: {output:?}"
    );
    // libtest prints the panic of a failing test to its standard output.
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains("SANDY_TEST_REQUIRE demands self-check"),
        "the failure does not name the required feature: {report}"
    );
    assert!(
        fs::read_to_string(&log).unwrap().contains("\tself-check\t"),
        "the skip was not logged before the test failed"
    );
    let _ = fs::remove_file(&log);
}

fn log_path(name: &str) -> String {
    let path: PathBuf =
        std::env::temp_dir().join(format!("sandy-skips-{name}-{}.log", std::process::id()));
    let _ = fs::remove_file(&path);
    path.to_str().unwrap().to_string()
}

/// Runs `self_check_driver` in a new test process, which writes its skips to `log`.
fn run_self_check(log: &str, require: Option<&str>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "self_check_driver"])
        .env(SELF_CHECK_VARIABLE, "1")
        .env(SKIP_LOG_VARIABLE, log)
        .env_remove(REQUIRE_VARIABLE);
    if let Some(require) = require {
        command.env(REQUIRE_VARIABLE, require);
    }
    command.output().unwrap()
}
