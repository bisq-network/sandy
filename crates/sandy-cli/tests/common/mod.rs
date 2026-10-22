//! Helpers shared by the escape tests. Each test file includes this module with `mod common;`.

// Each test file uses a different subset of the helpers.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const EXIT_FAILURE: i32 = 125;

/// Directory that holds `sandy` and `sandy-probe` when the tests run on another host than the
/// one that built them (for example a test VM). Unset, the paths Cargo built are used.
const BIN_DIR_VARIABLE: &str = "SANDY_TEST_BIN_DIR";

fn binary(name: &str, built: &str) -> String {
    match std::env::var_os(BIN_DIR_VARIABLE) {
        Some(dir) => Path::new(&dir)
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
            .to_str()
            .unwrap()
            .to_string(),
        None => built.to_string(),
    }
}

pub fn sandy_path() -> String {
    binary("sandy", env!("CARGO_BIN_EXE_sandy"))
}

pub fn probe_path() -> String {
    binary("sandy-probe", env!("CARGO_BIN_EXE_sandy-probe"))
}

/// A directory tree with one directory per access level and a file in each.
pub struct Fixture {
    pub root: PathBuf,
}

impl Fixture {
    pub fn new(name: &str) -> Fixture {
        Fixture::new_in(&std::env::temp_dir(), name)
    }

    /// A fixture below `parent` instead of the temporary directory.
    pub fn new_in(parent: &Path, name: &str) -> Fixture {
        let root = parent.join(format!("sandy-{name}-{}", std::process::id()));
        // A second Fixture value would remove the tree when the first one is dropped.
        let mut fixture = Fixture { root };
        fixture.reset();
        fixture.root = fixture.root.canonicalize().unwrap();
        fixture
    }

    /// Recreates the tree, so a test can repeat actions that change it.
    pub fn reset(&self) {
        let _ = fs::remove_dir_all(&self.root);
        for dir in ["ro", "rw", "bin", "secret"] {
            fs::create_dir_all(self.root.join(dir)).unwrap();
        }
        for dir in ["ro", "rw", "secret"] {
            fs::write(self.root.join(dir).join("file"), b"content").unwrap();
        }
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    pub fn arg(&self, relative: &str) -> String {
        self.path(relative).to_str().unwrap().to_string()
    }

    /// Sandbox options that allow the fixture's directories at their levels.
    pub fn access_args(&self) -> Vec<String> {
        vec![
            "--read".into(),
            self.arg("ro"),
            "--read-write".into(),
            self.arg("rw"),
            "--read-exec".into(),
            self.arg("bin"),
        ]
    }

    /// Copies the probe executable into `dir`, so the tests can execute a program there.
    pub fn copy_probe(&self, dir: &str) -> String {
        let probe = probe_path();
        let name = Path::new(&probe).file_name().unwrap();
        let destination = self.path(dir).join(name);
        fs::copy(&probe, &destination).unwrap();
        destination.to_str().unwrap().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
pub struct ProbeLine {
    pub action: String,
    pub target: String,
    pub result: String,
    pub detail: String,
}

impl ProbeLine {
    pub fn assert_ok(&self) {
        assert_eq!(
            self.result, "ok",
            "expected {} {} to succeed: {}",
            self.action, self.target, self.detail
        );
    }

    pub fn assert_blocked(&self) {
        assert_ne!(
            self.result, "ok",
            "expected the sandbox to block {} {}",
            self.action, self.target
        );
    }
}

/// Options every sandbox run needs on this platform.
pub fn platform_args() -> Vec<String> {
    if cfg!(windows) {
        vec!["--appcontainer".into(), "sandy.escape-tests".into()]
    } else {
        Vec::new()
    }
}

pub fn sandy<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(sandy_path()).args(args).output().unwrap()
}

pub fn parse(output: &Output) -> Vec<ProbeLine> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let mut fields = line.splitn(4, '\t');
            let mut next = || fields.next().unwrap_or_default().to_string();
            ProbeLine {
                action: next(),
                target: next(),
                result: next(),
                detail: next(),
            }
        })
        .collect()
}

pub fn probe_args(actions: &[(&str, &str)]) -> Vec<String> {
    actions
        .iter()
        .flat_map(|(action, target)| [action.to_string(), target.to_string()])
        .collect()
}

pub fn probe_outside(actions: &[(&str, &str)]) -> Vec<ProbeLine> {
    let output = Command::new(probe_path())
        .args(probe_args(actions))
        .output()
        .unwrap();
    assert!(output.status.success(), "probe failed outside: {output:?}");
    parse(&output)
}

/// The full `sandy run` argument list that runs the probe with `actions`.
pub fn run_args(sandbox_args: &[String], actions: &[(&str, &str)]) -> Vec<String> {
    let mut args = vec!["run".to_string()];
    args.extend(platform_args());
    args.extend_from_slice(sandbox_args);
    args.push("--".into());
    args.push(probe_path());
    args.extend(probe_args(actions));
    args
}

pub fn probe_inside(sandbox_args: &[String], actions: &[(&str, &str)]) -> Vec<ProbeLine> {
    let output = sandy(run_args(sandbox_args, actions));
    assert!(
        output.status.success(),
        "sandy run failed: status {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "probe output: {lines:?}");
    lines
}

/// Runs `actions` outside and inside the sandbox. All must succeed outside.
pub fn controlled(sandbox_args: &[String], actions: &[(&str, &str)]) -> Vec<ProbeLine> {
    for line in probe_outside(actions) {
        line.assert_ok();
    }
    probe_inside(sandbox_args, actions)
}
