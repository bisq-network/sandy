//! Helpers shared by the escape tests. Each test file includes this module with `mod common;`.

// Each test file uses a different subset of the helpers.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const EXIT_FAILURE: i32 = 125;

/// Directory that holds `sandy` and `sandy-probe` when the tests run on another host than the
/// one that built them (for example a test VM). Unset, the paths Cargo built are used.
const BIN_DIR_VARIABLE: &str = "SANDY_TEST_BIN_DIR";

/// Features that must be checkable on this host, separated by commas, or `all` for every
/// feature. Skipping one of them fails the test instead of passing quietly.
pub const REQUIRE_VARIABLE: &str = "SANDY_TEST_REQUIRE";

/// File that each skip is appended to, one line
/// `BINARY<TAB>TEST<TAB>FEATURE<TAB>REASON` per skip. `tests/runner.rs` compares the file with
/// the skips the runner is expected to have.
pub const SKIP_LOG_VARIABLE: &str = "SANDY_TEST_SKIP_LOG";

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

/// The harness that runs a program with a lower reported Landlock ABI, `None` when it is not
/// next to the other binaries (see `SANDY_TEST_BIN_DIR`).
#[cfg(target_os = "linux")]
pub fn abi_cap_path() -> Option<String> {
    let path = binary("sandy-abi-cap", env!("CARGO_BIN_EXE_sandy-abi-cap"));
    Path::new(&path).exists().then_some(path)
}

/// Records that this test could not check `feature` on this host, and why.
///
/// libtest knows no outcome between ok and failed, so the test still reports ok and a check
/// that did not run would look like one that passed. This makes the missing check visible: the
/// skip goes to standard error (also for a test that passes, so the log of a run lists what it
/// did not check) and to the skip log, which `tests/runner.rs` compares with the skips the
/// runner is expected to have. A feature that `SANDY_TEST_REQUIRE` names must be checkable, so
/// skipping it fails the test.
///
/// `feature` names what the host lacks, not the test: several tests skip the same feature, and
/// the expected-skip lists stay readable when the name is stable (`pty`, `landlock-abi-6`). The
/// reason carries the detail.
pub fn skip(feature: &str, reason: &str) {
    let reason = reason.replace(['\t', '\n', '\r'], " ");
    // Straight to the descriptor: libtest captures `eprintln!` and shows it only for a test that
    // fails.
    let _ = writeln!(std::io::stderr(), "skipped: {feature}: {reason}");
    record_skip(feature, &reason);
    assert!(
        !is_required(feature),
        "{REQUIRE_VARIABLE} demands {feature} on this host, but the check was skipped: {reason}"
    );
}

fn record_skip(feature: &str, reason: &str) {
    let Some(path) = std::env::var_os(SKIP_LOG_VARIABLE) else {
        return;
    };
    let line = format!("{}\t{}\t{feature}\t{reason}\n", test_binary(), test_name());
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|error| {
            panic!(
                "cannot open the skip log {}: {error}",
                Path::new(&path).display()
            )
        });
    // One append of one short line, so tests that run next to each other in this process and in
    // other test binaries can share the log without interleaving.
    log.write_all(line.as_bytes()).unwrap();
}

fn is_required(feature: &str) -> bool {
    let Ok(list) = std::env::var(REQUIRE_VARIABLE) else {
        return false;
    };
    list.split(',')
        .map(str::trim)
        .any(|wanted| wanted == feature || wanted == "all")
}

/// The name of the running test. libtest names each test's thread after the test.
pub fn test_name() -> String {
    std::thread::current().name().unwrap_or("unknown").into()
}

/// The name of the running test binary without Cargo's hash suffix, so it is the name the
/// expected-skip lists use: `escape_linux-1f3c9a0b2d4e5f60` becomes `escape_linux`.
pub fn test_binary() -> String {
    let path = std::env::current_exe().unwrap_or_default();
    let name = path.file_stem().unwrap_or_default().to_string_lossy();
    match name.rsplit_once('-') {
        Some((stem, hash)) if hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            stem.to_string()
        }
        _ => name.into_owned(),
    }
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
        copy_executable(&probe, &destination);
        destination.to_str().unwrap().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        // On Windows each test uses its own AppContainer name (see `appcontainer_name`). Remove
        // the profile so runs do not accumulate profiles on CI and the VM. Best effort: deleting
        // a name that was never created does nothing.
        #[cfg(windows)]
        delete_test_profiles();
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

/// The AppContainer name for the current test, without the loopback exemption. sandy enforces
/// one AppContainer name per resolved policy while runs overlap, so every test uses its own
/// name; a shared name would make tests that run different policies in parallel refuse each
/// other. The name is a hash of the test binary and the test's thread name, so it is unique per
/// test and stable across runs of the same build (the elevated and the limited VM phase use the
/// same name). It must stay out of the loopback exemption, or sandy refuses policies without IP
/// networking.
pub fn appcontainer_name() -> String {
    format!("sandy.escape-tests.{}", test_tag())
}

/// The AppContainer name for the current test with the loopback exemption (see
/// `prepare_loopback_exemption`), so the program can connect to listeners on 127.0.0.1.
pub fn appcontainer_loopback_name() -> String {
    format!("sandy.escape-tests.lb.{}", test_tag())
}

/// A short, stable, per-test identifier. libtest names each test's thread after the test, so the
/// thread name is unique within a binary and the same on every run; the binary name keeps names
/// from different test binaries apart. Hashed to keep the AppContainer name within its 64
/// character limit.
fn test_tag() -> String {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let thread = std::thread::current()
        .name()
        .unwrap_or("shared")
        .to_string();
    // FNV-1a, 64 bits. A stable, dependency-free hash; collisions across the test set are
    // negligible and would only make two tests share a name.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in format!("{binary}\u{0}{thread}").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Options every sandbox run needs on this platform.
pub fn platform_args() -> Vec<String> {
    if cfg!(windows) {
        vec!["--appcontainer".into(), appcontainer_name()]
    } else {
        Vec::new()
    }
}

/// On Windows, a run with `--ip all` or `--ip client` uses this test's AppContainer with the
/// loopback exemption, unless the test names an AppContainer itself. These options go after the
/// sandbox options, because the last --appcontainer wins.
fn loopback_args(sandbox_args: &[String]) -> Vec<String> {
    let allows_ip = sandbox_args
        .windows(2)
        .any(|pair| pair[0] == "--ip" && (pair[1] == "all" || pair[1] == "client"));
    let names_container = sandbox_args.iter().any(|arg| arg == "--appcontainer");
    if cfg!(windows) && allows_ip && !names_container {
        prepare_loopback_exemption();
        vec!["--appcontainer".into(), appcontainer_loopback_name()]
    } else {
        Vec::new()
    }
}

/// Installs the loopback exemption for this test's `appcontainer_loopback_name`. It needs
/// administrator rights, which the elevated VM phase and the CI runners have. Without them
/// `sandy setup` changes nothing and ends with status 3, also when the exemption is there
/// already, so the limited VM phase reuses the exemption the elevated phase created for the
/// same name, which `check` of a policy without IP networking reports.
pub fn prepare_loopback_exemption() {
    let name = appcontainer_loopback_name();
    let output = sandy(["setup", "--appcontainer", &name, "--ip", "all"]);
    if output.status.code() == Some(3) {
        let check = sandy(["check", "--appcontainer", &name]);
        assert!(
            String::from_utf8_lossy(&check.stdout).contains("is exempt from loopback isolation"),
            "`sandy setup --appcontainer {name} --ip all` needs administrator rights, so the \
             elevated phase or a CI runner must create the exemption before a non-admin run \
             reuses it: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(
        output.status.success(),
        "`sandy setup --appcontainer {name} --ip all` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The AppContainer SID of `container` in the `S-1-15-2-...` form that `icacls` and
/// `CheckNetIsolation` take. Windows derives it from the name without regard to case.
#[cfg(windows)]
pub fn appcontainer_sid(container: &str) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::FreeSid;
    use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;

    let wide: Vec<u16> = container.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid = std::ptr::null_mut();
    // SAFETY: the name is NUL-terminated and sid is a valid out pointer.
    let hresult = unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut sid) };
    assert!(hresult >= 0, "cannot derive the SID of {container}");
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid holds a SID the call above allocated; text is a valid out pointer.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
    // SAFETY: text is a NUL-terminated string the function allocated.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: text holds len units before its NUL.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: both buffers come from the calls above and are freed exactly once.
    unsafe {
        LocalFree(text.cast());
        FreeSid(sid);
    }
    value
}

/// Removes this test's AppContainer profiles (both the plain and the loopback name). Best effort.
#[cfg(windows)]
pub fn delete_test_profiles() {
    use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
    for name in [appcontainer_name(), appcontainer_loopback_name()] {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the name is NUL-terminated.
        unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    }
}

pub fn sandy<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(sandy_path()).args(args).output().unwrap()
}

/// Runs `program`, which a test has just copied into its fixture. The tests run in threads of one
/// process, so a child another thread forked holds a copy of every descriptor open at that
/// moment, including the one a `fs::copy` of this file was writing through. The kernel refuses to
/// execute a file that someone may still write, so this waits out that window instead of failing.
pub fn run_copied<I, S>(program: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<_> = args.into_iter().collect();
    for _ in 0..100 {
        match Command::new(program).args(&args).output() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            result => return result.unwrap(),
        }
    }
    panic!("{} stayed busy for two seconds", program.display());
}

/// Copies the executable `from` to `to` for a test to run. A child that another thread forked
/// while the copy was written still holds the descriptor the copy wrote through until it executes
/// its own program, and until then the kernel refuses to execute the copy, also when the probe
/// does so inside the sandbox, where nothing waits. Nobody opens the copy for writing again, so
/// once one execve of it succeeds every later one does too: running it once here, with no
/// arguments, waits out that window for every later use.
pub fn copy_executable(from: impl AsRef<Path>, to: impl AsRef<Path>) {
    fs::copy(from, &to).unwrap();
    #[cfg(unix)]
    run_copied(to.as_ref(), std::iter::empty::<&str>());
}

/// A socket as the standard input of a child, so a test can hand the program a socket it opened
/// itself. On Windows a socket is a kernel handle like any other, but its Rust type is not, so
/// it takes the detour through the raw handle.
#[cfg(unix)]
pub fn stdin_from<T: Into<std::os::fd::OwnedFd>>(socket: T) -> Stdio {
    Stdio::from(socket.into())
}

#[cfg(windows)]
pub fn stdin_from<T: Into<std::os::windows::io::OwnedSocket>>(socket: T) -> Stdio {
    use std::os::windows::io::{FromRawHandle, IntoRawSocket, OwnedHandle, RawHandle};

    let handle = socket.into().into_raw_socket() as usize as RawHandle;
    // SAFETY: into_raw_socket gave up the only owner of the handle, which OwnedHandle takes on.
    Stdio::from(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub fn parse(output: &Output) -> Vec<ProbeLine> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(parse_line)
        .collect()
}

pub fn parse_line(line: &str) -> ProbeLine {
    let mut fields = line.splitn(4, '\t');
    let mut next = || fields.next().unwrap_or_default().to_string();
    ProbeLine {
        action: next(),
        target: next(),
        result: next(),
        detail: next(),
    }
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
    let mut child = probe_command(sandbox_args, &[("tcp-accept", target.as_str())])
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

/// The probe with `actions`, outside the sandbox when `sandbox_args` is `None`.
pub fn probe_command(sandbox_args: Option<&[String]>, actions: &[(&str, &str)]) -> Command {
    match sandbox_args {
        None => {
            let mut command = Command::new(probe_path());
            command.args(probe_args(actions));
            command
        }
        Some(sandbox_args) => {
            let mut command = Command::new(sandy_path());
            command.args(run_args(sandbox_args, actions));
            command
        }
    }
}

/// Starts the probe's `udp-receive` on a free loopback port, outside the sandbox when
/// `sandbox_args` is `None`, and sends datagrams to it from this process while it waits. Returns
/// the probe's report.
pub fn inbound_udp(sandbox_args: Option<&[String]>) -> ProbeLine {
    let address = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let target = address.to_string();
    sends_while_running(
        probe_command(sandbox_args, &[("udp-receive", target.as_str())]),
        address,
    )
}

/// Runs `command`, a probe with one action that waits for a datagram on `address`, and sends
/// datagrams there from this process until it ends, for at most 12 seconds.
pub fn sends_while_running(mut command: Command, address: SocketAddr) -> ProbeLine {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        // A send fails while nothing is bound yet on some platforms; the next one counts.
        let _ = sender.send_to(b"inbound", address);
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    let mut lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    lines.remove(0)
}

/// Runs the probe's `udp-reply` against a socket of this process, outside the sandbox when
/// `sandbox_args` is `None`, and answers the datagram the probe sends from that socket or, with
/// `third_party`, from another one, which the probe never sent to. Returns the probe's report and
/// the address the answer came from.
pub fn udp_answer(sandbox_args: Option<&[String]>, third_party: bool) -> (ProbeLine, SocketAddr) {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").unwrap();
    let answering = if third_party { &other } else { &peer };
    let from = answering.local_addr().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    let target = peer.local_addr().unwrap().to_string();
    let child = probe_command(sandbox_args, &[("udp-reply", target.as_str())])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut buffer = [0; 16];
    if let Ok((_, program)) = peer.recv_from(&mut buffer) {
        answering.send_to(b"answer", program).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let mut lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    (lines.remove(0), from)
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
/// sandbox; only a denial inside, with success outside, counts. A caller that returns because of
/// this leaves its check undone, so the canary records the skip for the calling test.
#[cfg(windows)]
pub fn appcontainer_children_blocked() -> bool {
    let system = std::env::var("SystemRoot").expect("SystemRoot is set");
    let canary = format!(r"{system}\System32\whoami.exe");
    if probe_outside(&[("exec", &canary)])[0].result != "ok" {
        return false;
    }
    let blocked = probe_inside(&[], &[("exec", &canary)])[0].result == "denied";
    if blocked {
        skip(
            "appcontainer-children",
            "this host does not let AppContainer processes start child processes (see \
             docs/windows.md limitation 11)",
        );
    }
    blocked
}

/// When this process started, in the form `--parent-start` takes on this platform: clock ticks
/// since boot from field 22 of `/proc/self/stat`. This is the recipe a caller follows (see
/// docs/linux.md).
#[cfg(target_os = "linux")]
pub fn start_token() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let after_name = &stat[stat.rfind(')').unwrap() + 1..];
    // Field 3 is the first after the name, so field 22 is the twentieth.
    after_name
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

/// Microseconds since the epoch, from `PROC_PIDTBSDINFO` (see docs/macos.md).
#[cfg(target_os = "macos")]
pub fn start_token() -> u64 {
    use std::mem::{MaybeUninit, size_of};

    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer has exactly the size passed.
    let written = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::pid_t,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    assert_eq!(written, size, "cannot read the start time of this process");
    // SAFETY: proc_pidinfo filled the whole structure.
    let info = unsafe { info.assume_init() };
    info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
}

/// The creation time of this process in 100 ns units (see docs/windows.md).
#[cfg(windows)]
pub fn start_token() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: the pseudo handle is valid and every pointer is writable.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), creation, exit, kernel, user) };
    assert_ne!(ok, 0, "cannot read the creation time of this process");
    u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime)
}

/// Runs sandy with `args` plus a `--status-fd` channel, and returns its output and the record
/// it wrote there (see `sandy_core::StatusReport`). `args` must start with `run`; the option is
/// inserted after it.
#[cfg(unix)]
pub fn sandy_with_status(args: &[String]) -> (Output, String) {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt;

    /// The descriptor sandy gets. Free in a test process, which has 0, 1 and 2 plus the pipes
    /// of the harness, and the child gets nothing else.
    const CHANNEL: RawFd = 3;

    let mut ends = [0; 2];
    // SAFETY: pipe writes two new descriptors into `ends`. macOS has no pipe2, so the flag
    // comes after; the tests fork only through Command, which this thread drives.
    let made = unsafe { libc::pipe(ends.as_mut_ptr()) };
    assert_eq!(made, 0, "cannot create the status pipe");
    for end in ends {
        // Close-on-exec, so a child that another test thread starts in the meantime does not
        // hold the write end open.
        // SAFETY: F_SETFD only changes the flags of an open descriptor.
        let marked = unsafe { libc::fcntl(end, libc::F_SETFD, libc::FD_CLOEXEC) };
        assert_eq!(marked, 0, "cannot mark the status pipe close-on-exec");
    }
    // SAFETY: both descriptors are new and nothing else owns them.
    let (mut reader, writer) = unsafe {
        (
            fs::File::from_raw_fd(ends[0]),
            OwnedFd::from_raw_fd(ends[1]),
        )
    };
    let raw = writer.as_raw_fd();
    let mut command = Command::new(sandy_path());
    command
        .args(with_status_option(args, CHANNEL.to_string()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: dup2 is async-signal-safe and the closure calls nothing else.
    unsafe {
        command.pre_exec(move || match libc::dup2(raw, CHANNEL) {
            CHANNEL => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        });
    }
    let child = command.spawn().unwrap();
    // Only sandy holds the write end now, so the read below ends when sandy exits.
    drop(writer);
    let output = child.wait_with_output().unwrap();
    let mut record = String::new();
    reader.read_to_string(&mut record).unwrap();
    (output, record)
}

#[cfg(windows)]
pub fn sandy_with_status(args: &[String]) -> (Output, String) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};

    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    // The write handle must be inheritable for sandy to get it; sandy clears the flag at once.
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: TRUE,
    };
    // SAFETY: both out pointers are writable and the attributes are filled in.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) };
    assert_ne!(ok, 0, "cannot create the status pipe");
    // SAFETY: both handles are new and nothing else owns them.
    let (reader, writer) = unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    };
    let channel = (writer.as_raw_handle() as usize).to_string();
    let output = Command::new(sandy_path())
        .args(with_status_option(args, channel))
        .output()
        .unwrap();
    drop(writer);
    // Another test thread may have started a process that holds the write end open, so the
    // record is read by what is in the pipe and not until its end.
    let mut available = 0u32;
    // SAFETY: reader is a valid pipe handle; only `available` is written.
    let ok = unsafe {
        PeekNamedPipe(
            reader.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "cannot read the status record");
    let mut record = vec![0u8; available as usize];
    if available > 0 {
        std::io::Read::read_exact(&mut fs::File::from(reader), &mut record).unwrap();
    }
    (output, String::from_utf8_lossy(&record).into_owned())
}

/// `args` with `--status-fd CHANNEL` after the command word, where sandy takes options.
fn with_status_option(args: &[String], channel: String) -> Vec<String> {
    let mut with_option = args.to_vec();
    with_option.splice(1..1, ["--status-fd".to_string(), channel]);
    with_option
}

/// How long a process may take to end after sandy has ended it.
pub const END_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(unix)]
pub fn is_running(pid: u32) -> bool {
    // SAFETY: signal 0 only checks whether the process exists.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(windows)]
pub fn is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: the handle is checked before use and closed afterwards.
    unsafe {
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if process.is_null() {
            return false;
        }
        let running = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        CloseHandle(process);
        running
    }
}

/// Whether process `pid` ends within `timeout`.
pub fn ends_soon(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Ends process `pid`, which a test started and left running.
#[cfg(unix)]
pub fn kill_process(pid: u32) {
    // SAFETY: kill takes a process ID and a signal.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
}

#[cfg(windows)]
pub fn kill_process(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    // SAFETY: the handle is checked before use and closed afterwards.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !process.is_null() {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

/// Helpers for the Linux tests.
#[cfg(target_os = "linux")]
pub mod linux {
    /// The Landlock ABI of the running kernel, 0 without Landlock.
    pub fn landlock_abi() -> i64 {
        // SAFETY: with a null attribute, size 0 and the VERSION flag the kernel only returns the
        // ABI.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                1u32,
            )
        };
        abi.max(0)
    }
}

/// Helpers for the Linux and macOS tests.
#[cfg(unix)]
pub mod unix {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    const TIOCSCTTY: libc::c_ulong = 0x2000_7461;
    #[cfg(not(target_os = "macos"))]
    const TIOCSCTTY: libc::c_ulong = libc::TIOCSCTTY as libc::c_ulong;

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        /// In libSystem since macOS 10.13.4, not in the libc crate.
        fn ptsname_r(fd: libc::c_int, buf: *mut libc::c_char, buflen: libc::size_t) -> libc::c_int;
    }
    #[cfg(not(target_os = "macos"))]
    use libc::ptsname_r;

    /// A pseudo-terminal pair. The child that gets the slave as standard input makes it its
    /// controlling terminal, so TIOCSTI is not refused for a foreign terminal.
    pub struct Pty {
        pub master: OwnedFd,
        pub slave: OwnedFd,
    }

    pub fn open_pty() -> Option<Pty> {
        // SAFETY: the calls get valid flags and buffers; every descriptor is owned right away.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
            if master < 0 {
                return None;
            }
            let master = OwnedFd::from_raw_fd(master);
            if libc::grantpt(master.as_raw_fd()) != 0 || libc::unlockpt(master.as_raw_fd()) != 0 {
                return None;
            }
            let mut name = [0 as libc::c_char; 128];
            if ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) != 0 {
                return None;
            }
            let slave = libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            );
            if slave < 0 {
                return None;
            }
            Some(Pty {
                master,
                slave: OwnedFd::from_raw_fd(slave),
            })
        }
    }

    /// The processes of process group `group` that have not ended; zombies do not count.
    pub fn live_members(group: libc::pid_t) -> Vec<libc::pid_t> {
        members(group)
            .into_iter()
            .filter_map(|(pid, live)| live.then_some(pid))
            .collect()
    }

    /// Whether `group` has ended: no live process in it, and nothing changes in it for a moment.
    /// Processes that fork in a loop live only microseconds, so one look can miss them all; while
    /// they run, members come and go.
    pub fn group_ended(group: libc::pid_t) -> bool {
        let before = members(group);
        if before.iter().any(|&(_, live)| live) {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        members(group) == before
    }

    /// The processes of process group `group`, sorted, each with whether it is live (not a
    /// zombie).
    fn members(group: libc::pid_t) -> Vec<(libc::pid_t, bool)> {
        #[cfg(target_os = "macos")]
        let mut found: Vec<(libc::pid_t, bool)> = {
            use std::mem::{MaybeUninit, size_of};
            let mut pids = vec![0 as libc::pid_t; 4096];
            let size = (pids.len() * size_of::<libc::pid_t>()) as libc::c_int;
            // SAFETY: the buffer holds `size` bytes.
            let count = unsafe { libc::proc_listpgrppids(group, pids.as_mut_ptr().cast(), size) };
            pids.truncate(count.max(0) as usize);
            pids.into_iter()
                .filter_map(|pid| {
                    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
                    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
                    // SAFETY: the buffer has exactly the size passed.
                    let written = unsafe {
                        libc::proc_pidinfo(
                            pid,
                            libc::PROC_PIDTBSDINFO,
                            0,
                            info.as_mut_ptr().cast(),
                            size,
                        )
                    };
                    if written != size {
                        return None;
                    }
                    // SAFETY: proc_pidinfo filled the whole structure.
                    let status = unsafe { info.assume_init() }.pbi_status;
                    Some((pid, status != libc::SZOMB))
                })
                .collect()
        };
        #[cfg(not(target_os = "macos"))]
        let mut found: Vec<(libc::pid_t, bool)> = {
            let Ok(entries) = std::fs::read_dir("/proc") else {
                return Vec::new();
            };
            entries
                .flatten()
                .filter_map(|entry| {
                    let pid: libc::pid_t = entry.file_name().to_str()?.parse().ok()?;
                    let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
                    // After the name in parentheses: state, parent, process group.
                    let mut fields = stat[stat.rfind(')')? + 2..].split_whitespace();
                    let state = fields.next()?;
                    let pgrp: libc::pid_t = fields.nth(1)?.parse().ok()?;
                    (pgrp == group).then_some((pid, !matches!(state, "Z" | "X")))
                })
                .collect()
        };
        found.sort_unstable();
        found
    }

    /// Whether a live process is in `group`. kill fails with ESRCH for an empty group, and with
    /// EPERM on macOS for one with only zombies. Faster than `live_members` for processes that
    /// live only microseconds.
    pub fn group_alive(group: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks whether the group has a process that may be signaled.
        unsafe { libc::kill(-group, 0) == 0 }
    }

    /// Ends every process of `group`, also those forked while it is signaled. For cleaning up
    /// after a test.
    pub fn kill_group(group: libc::pid_t) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // SAFETY: kill takes a process group ID and a signal.
        while unsafe { libc::kill(-group, libc::SIGKILL) } == 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// Reads and discards what the terminal shows (the echo of typed input, for example), as a
    /// terminal emulator does. On macOS a session leader that exits waits until its terminal's
    /// output is read, so a test that types input needs this to see the leader end.
    pub fn discard_output(pty: &Pty) {
        let mut master = std::fs::File::from(pty.master.try_clone().unwrap());
        std::thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            while matches!(std::io::Read::read(&mut master, &mut buffer), Ok(read) if read > 0) {}
        });
    }

    /// Makes the pseudo-terminal the standard input and the controlling terminal of a new
    /// session for `command`.
    pub fn with_terminal(pty: &Pty) -> impl Fn(&mut Command) + '_ {
        move |command| {
            command.stdin(Stdio::from(pty.slave.try_clone().unwrap()));
            // SAFETY: setsid and ioctl are async-signal-safe.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 || libc::ioctl(0, TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
}
