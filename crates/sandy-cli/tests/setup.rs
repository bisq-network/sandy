//! What `sandy setup` does on every platform, and `SANDY_STARTED_AS`: the names a sandy that
//! handed over to the copy `sandy setup --install-copy` installed was started under, which the
//! copy checks like its own (README.md, "Commands"). The variable can only add checks: every
//! sandy checks its names and removes it from its environment, so the program never sees it.

mod common;

use std::fs;
use std::process::Command;

use common::*;

const STARTED_AS: &str = "SANDY_STARTED_AS";

fn arguments(mode: &str, sandbox_args: &[String]) -> Vec<String> {
    let mut arguments = vec![mode.to_string()];
    arguments.extend(platform_args());
    arguments.extend_from_slice(sandbox_args);
    arguments
}

/// A name in the variable that lies in a writable path refuses the policy, as sandy's own file
/// would there, because the next start runs that file. A name that does not exist is left out,
/// like a name sandy was started under that is gone. Control: the same check without the
/// variable.
#[test]
fn started_as_names_are_checked_like_sandys_own() {
    let fixture = Fixture::new("started-as");
    let name = fixture
        .path("rw")
        .join(format!("sandy{}", std::env::consts::EXE_SUFFIX));
    fs::write(&name, b"not sandy").unwrap();
    let check = arguments("check", &fixture.access_args());
    let refusal = format!("{} lies inside writable path", name.display());

    let control = sandy(&check);
    assert!(
        !String::from_utf8_lossy(&control.stderr).contains(&refusal),
        "{control:?}"
    );

    let missing = fixture.path("ro").join("gone");
    for names in [vec![name.clone()], vec![missing.clone(), name.clone()]] {
        let output = Command::new(sandy_path())
            .env(STARTED_AS, std::env::join_paths(&names).unwrap())
            .args(&check)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stderr}");
        assert!(stderr.contains(&refusal), "{stderr}");
    }

    let output = Command::new(sandy_path())
        .env(STARTED_AS, &missing)
        .args(&check)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), control.status.code(), "{output:?}");
}

/// The variable is sandy's, not the program's: a policy that passes it on passes nothing.
/// Control: another variable passed the same way arrives.
#[test]
fn started_as_never_reaches_the_program() {
    let other = "SANDY_TEST_PASSED";
    let sandbox_args: Vec<String> = ["--pass-env", STARTED_AS, "--pass-env", other]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
    let output = Command::new(sandy_path())
        .env(STARTED_AS, std::env::temp_dir().join("gone"))
        .env(other, "passed")
        .args(run_args(
            &sandbox_args,
            &[("env", STARTED_AS), ("env", other)],
        ))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), 2, "{output:?}");
    assert_eq!(
        (lines[0].result.as_str(), lines[0].detail.as_str()),
        ("error", "not set")
    );
    lines[1].assert_ok();
    assert_eq!(lines[1].detail, "passed");
}

/// macOS needs no setup, so setup, its removal and `--elevate` have nothing to do and ask for
/// nothing.
#[cfg(target_os = "macos")]
#[test]
fn setup_has_nothing_to_do_on_macos() {
    for command in [
        &["setup"][..],
        &["setup", "--elevate"],
        &["setup", "--install-copy", "--elevate"],
        &["setup", "--remove", "--elevate"],
    ] {
        let output = sandy(command);
        assert!(output.status.success(), "{command:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("this platform needs no setup"),
            "{command:?}: {output:?}"
        );
    }
}
