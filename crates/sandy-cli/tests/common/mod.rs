//! Helpers shared by the escape tests. Each test file includes this module with `mod common;`.

// Each test file uses a different subset of the helpers.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

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

/// AppContainer of the Windows test runs without IP networking. It must not be exempt from
/// loopback isolation, or sandy refuses policies without IP networking.
pub const APPCONTAINER: &str = "sandy.escape-tests";

/// AppContainer of the Windows test runs with `--ip all`. `prepare_loopback_exemption` exempts
/// it from loopback isolation, so the program can connect to listeners on 127.0.0.1.
pub const APPCONTAINER_LOOPBACK: &str = "sandy.escape-tests.loopback";

/// Options every sandbox run needs on this platform.
pub fn platform_args() -> Vec<String> {
    if cfg!(windows) {
        vec!["--appcontainer".into(), APPCONTAINER.into()]
    } else {
        Vec::new()
    }
}

/// On Windows, a run with `--ip all` uses the AppContainer with the loopback exemption, unless
/// the test names an AppContainer itself. These options go after the sandbox options, because
/// the last --appcontainer wins.
fn loopback_args(sandbox_args: &[String]) -> Vec<String> {
    let allows_ip = sandbox_args
        .windows(2)
        .any(|pair| pair[0] == "--ip" && pair[1] == "all");
    let names_container = sandbox_args.iter().any(|arg| arg == "--appcontainer");
    if cfg!(windows) && allows_ip && !names_container {
        prepare_loopback_exemption();
        vec!["--appcontainer".into(), APPCONTAINER_LOOPBACK.into()]
    } else {
        Vec::new()
    }
}

/// Installs the loopback exemption for `APPCONTAINER_LOOPBACK` once per test process. It needs
/// administrator rights; `sandy setup` does nothing when the exemption is already there.
pub fn prepare_loopback_exemption() {
    static SETUP: std::sync::Once = std::sync::Once::new();
    SETUP.call_once(|| {
        let output = sandy([
            "setup",
            "--appcontainer",
            APPCONTAINER_LOOPBACK,
            "--ip",
            "all",
        ]);
        assert!(
            output.status.success(),
            "`sandy setup --appcontainer {APPCONTAINER_LOOPBACK} --ip all` failed; it needs \
             administrator rights once per machine: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
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
    args.extend(loopback_args(sandbox_args));
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

/// Starts the probe's `tcp-accept` on a free loopback port, outside the sandbox when
/// `sandbox_args` is `None`, and connects to it from this process while it waits. Returns
/// whether a connection was made and the probe's report.
pub fn inbound_tcp(sandbox_args: Option<&[String]>) -> (bool, ProbeLine) {
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let target = address.to_string();
    let actions = [("tcp-accept", target.as_str())];
    let mut command = match sandbox_args {
        None => {
            let mut command = Command::new(probe_path());
            command.args(probe_args(&actions));
            command
        }
        Some(sandbox_args) => {
            let mut command = Command::new(sandy_path());
            command.args(run_args(sandbox_args, &actions));
            command
        }
    };
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let connected = connects_while_running(&mut child, address);
    let output = child.wait_with_output().unwrap();
    let mut lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    (connected, lines.remove(0))
}

/// Connects to `address` from this process while `child` runs, for at most 8 seconds.
fn connects_while_running(child: &mut Child, address: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
            return true;
        }
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Windows: whether this host refuses child processes of AppContainer processes. The GitHub
/// Actions images windows-2022 and windows-2025 do (docs/windows.md, limitation 11). The canary
/// starts a system program that every AppContainer may read and execute, outside and inside the
/// sandbox; only a denial inside, with success outside, counts. The message goes to stderr
/// directly, so it shows also when the test harness captures output.
#[cfg(windows)]
pub fn appcontainer_children_blocked() -> bool {
    use std::io::Write;

    let system = std::env::var("SystemRoot").expect("SystemRoot is set");
    let canary = format!(r"{system}\System32\whoami.exe");
    if probe_outside(&[("exec", &canary)])[0].result != "ok" {
        return false;
    }
    let blocked = probe_inside(&[], &[("exec", &canary)])[0].result == "denied";
    if blocked {
        let _ = writeln!(
            std::io::stderr(),
            "skipped: this host does not let AppContainer processes start child processes \
             (see docs/windows.md limitation 11)"
        );
    }
    blocked
}
