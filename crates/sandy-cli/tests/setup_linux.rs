//! `sandy setup` on Linux (docs/linux.md, "Setup on Ubuntu"). Under Ubuntu's AppArmor
//! restriction of unprivileged user namespaces, setup installs a profile that lets one
//! root-owned sandy use them, and `--install-copy` installs such a sandy first. The tests that
//! need root use `sudo -n` and skip where it asks for a password. They change the host, so they
//! run one at a time and take back everything they installed, also when they fail.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::*;

const EXIT_NEEDS_SETUP: i32 = 2;
const EXIT_NOT_DONE: i32 = 3;
const PROFILES: &str = "/etc/apparmor.d";
const LOADED: &str = "/sys/kernel/security/apparmor/policy/profiles";
const COPY_DIRECTORY: &str = "/usr/local/libexec/sandy";

/// The tests share the host's profiles and the copy's path.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn restricted() -> bool {
    read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1"
        && read("/sys/module/apparmor/parameters/enabled") == "Y"
}

/// Whether this test may use `sudo -n` and the host restricts user namespaces with AppArmor;
/// records a skip when not.
fn root_on_a_restricted_host() -> bool {
    let sudo = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .output();
    if !sudo.is_ok_and(|output| output.status.success()) {
        skip(
            "passwordless-sudo",
            "the test needs root, and sudo -n asks for a password here",
        );
        return false;
    }
    if !restricted() {
        skip(
            "apparmor-userns-restriction",
            "this host does not restrict user namespaces with AppArmor, so setup has nothing \
             to do",
        );
        return false;
    }
    true
}

fn sudo<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The profile file sandy setup writes for `path` (DESIGN.md, "Goals").
fn profile_file(path: &Path) -> PathBuf {
    Path::new(PROFILES).join(profile_name(path))
}

fn profile_name(path: &Path) -> String {
    format!("sandy-setup{}", path.to_str().unwrap().replace('/', "."))
}

fn is_loaded(name: &str) -> bool {
    fs::read_dir(LOADED).unwrap().flatten().any(|entry| {
        fs::read_to_string(entry.path().join("name")).is_ok_and(|loaded| loaded.trim() == name)
    })
}

/// Whether nothing of a setup for `path` is left: no profile file and no loaded profile.
fn assert_no_profile(path: &Path) {
    let file = profile_file(path);
    assert!(!file.exists(), "{} stayed", file.display());
    assert!(
        !is_loaded(&profile_name(path)),
        "the profile of {} stayed loaded",
        path.display()
    );
}

fn copy_path() -> PathBuf {
    Path::new(COPY_DIRECTORY)
        .join(env!("CARGO_PKG_VERSION"))
        .join("sandy")
}

fn check_private(sandy: &Path) -> Output {
    Command::new(sandy)
        .args(["check", "--ip", "private"])
        .output()
        .unwrap()
}

/// A run of `sandy` that listens on the sandbox's own loopback, which needs the namespaces.
fn run_private(sandy: &Path, actions: &[(&str, &str)]) -> Output {
    let probe = probe_path();
    let directory = Path::new(&probe).parent().unwrap().to_str().unwrap();
    Command::new(sandy)
        .args(["run", "--ip", "private", "--read-exec", directory, "--"])
        .arg(&probe)
        .args(probe_args(actions))
        .output()
        .unwrap()
}

/// Unloads and deletes what a setup for `path` may have left, without sandy, so that a test
/// that failed half-way leaves nothing behind either.
fn clean_up(path: &Path) {
    let name = profile_name(path);
    if is_loaded(&name) {
        let mut remove = Command::new("sudo")
            .args(["-n", "tee", "/sys/kernel/security/apparmor/.remove"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let _ = std::io::Write::write_all(&mut remove.stdin.take().unwrap(), name.as_bytes());
        let _ = remove.wait();
    }
    sudo(["rm".as_ref(), "-f".as_ref(), profile_file(path).as_os_str()]);
}

/// A directory only root can change, with a copy of the built sandy in it, as a package would
/// install it. Each one has a path of its own, so a test that fails cannot leave a profile
/// that the next one sees. Dropping it takes back the setup of that sandy and the directory.
struct Installed {
    directory: PathBuf,
    sandy: PathBuf,
}

impl Installed {
    fn new() -> Installed {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let directory = PathBuf::from(format!(
            "/opt/sandy-setup-test-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        let sandy = directory.join("sandy");
        let installed = Installed { directory, sandy };
        let made = sudo([
            "install".as_ref(),
            "-d".as_ref(),
            "-m".as_ref(),
            "0755".as_ref(),
            installed.directory.as_os_str(),
        ]);
        assert!(made.status.success(), "{}", text(&made));
        let copied = sudo([
            "install".as_ref(),
            "-m".as_ref(),
            "0755".as_ref(),
            sandy_path().as_ref(),
            installed.sandy.as_os_str(),
        ]);
        assert!(copied.status.success(), "{}", text(&copied));
        installed
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        sudo([
            self.sandy.as_os_str(),
            "setup".as_ref(),
            "--remove".as_ref(),
        ]);
        clean_up(&self.sandy);
        sudo(["rm".as_ref(), "-rf".as_ref(), self.directory.as_os_str()]);
    }
}

/// Takes back what `--install-copy` installed, also when a test fails: the copy of this
/// version, its profile, and the copy's directory when the test created it.
struct CopyRemoval {
    directory_existed: bool,
}

impl Drop for CopyRemoval {
    fn drop(&mut self) {
        sudo([sandy_path().as_str(), "setup", "--remove", "--install-copy"]);
        let copy = copy_path();
        clean_up(&copy);
        sudo([
            "rm".as_ref(),
            "-rf".as_ref(),
            copy.parent().unwrap().as_os_str(),
        ]);
        if !self.directory_existed {
            sudo(["rmdir", COPY_DIRECTORY]);
        }
    }
}

/// Runs `command` and stops it after `limit`, so a test cannot hang on a prompt.
fn output_within(command: &mut Command, limit: Duration) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            panic!("{command:?} did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = child.wait().unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Without root, setup does what needs no rights: where the restriction does not apply it has
/// nothing to do, also with `--elevate`, which then asks for no password; where it applies,
/// setup refuses with status 3 and says how to get the rights. A removal with nothing to remove
/// asks for nothing either way.
#[test]
fn setup_without_root_does_nothing_or_names_the_rights_it_needs() {
    let _serial = serial();
    if restricted() {
        let output = sandy(["setup"]);
        assert_eq!(
            output.status.code(),
            Some(EXIT_NOT_DONE),
            "{}",
            text(&output)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("setup needs root"), "{stderr}");
        assert!(stderr.contains("--elevate"), "{stderr}");
        assert!(stderr.contains("ip = \"private\""), "{stderr}");
    } else {
        for command in [
            &["setup"][..],
            &["setup", "--install-copy"],
            &["setup", "--elevate"],
            &["setup", "--elevate", "--install-copy"],
        ] {
            let output = sandy(command);
            assert!(output.status.success(), "{command:?}: {}", text(&output));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("nothing to do"), "{command:?}: {stdout}");
        }
    }
    if !Path::new(COPY_DIRECTORY).exists() {
        for command in [
            &["setup", "--remove", "--install-copy"][..],
            &["setup", "--remove", "--install-copy", "--elevate"],
        ] {
            let output = sandy(command);
            assert!(output.status.success(), "{command:?}: {}", text(&output));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("nothing to remove"),
                "{command:?}: {stdout}"
            );
        }
    }
}

/// (a) A sandy that only root can change, as a package installs it: setup as root loads its
/// profile, and that sandy, run by the user, enforces `ip = "private"`. Setup again changes
/// nothing; `--remove` unloads and deletes the profile, and the check needs setup again.
#[test]
fn setup_prepares_a_sandy_that_only_root_can_change() {
    let _serial = serial();
    if !root_on_a_restricted_host() {
        return;
    }
    let installed = Installed::new();
    let sandy = &installed.sandy;
    assert_eq!(check_private(sandy).status.code(), Some(EXIT_NEEDS_SETUP));

    let setup = sudo([sandy.as_os_str(), "setup".as_ref()]);
    assert!(setup.status.success(), "{}", text(&setup));
    let file = profile_file(sandy);
    assert!(
        String::from_utf8_lossy(&setup.stdout).contains(file.to_str().unwrap()),
        "{}",
        text(&setup)
    );
    let profile = fs::read_to_string(&file).unwrap();
    assert!(
        profile.starts_with(&format!(
            "# Written by sandy setup for {}.",
            sandy.display()
        )),
        "{profile}"
    );
    assert!(is_loaded(&profile_name(sandy)));

    let check = check_private(sandy);
    assert!(check.status.success(), "{}", text(&check));
    let run = run_private(sandy, &[("tcp-listen", "127.0.0.1:0")]);
    assert!(run.status.success(), "{}", text(&run));
    parse(&run)[0].assert_ok();

    let again = sudo([sandy.as_os_str(), "setup".as_ref()]);
    assert!(again.status.success(), "{}", text(&again));
    assert_eq!(fs::read_to_string(&file).unwrap(), profile);

    // (d) The removal takes back the profile, and a second one has nothing to remove.
    let removed = sudo([sandy.as_os_str(), "setup".as_ref(), "--remove".as_ref()]);
    assert!(removed.status.success(), "{}", text(&removed));
    assert_no_profile(sandy);
    assert_eq!(check_private(sandy).status.code(), Some(EXIT_NEEDS_SETUP));
    let again = sudo([sandy.as_os_str(), "setup".as_ref(), "--remove".as_ref()]);
    assert!(again.status.success(), "{}", text(&again));
    assert!(String::from_utf8_lossy(&again.stdout).contains("nothing to remove"));
}

/// (b) A profile gives user namespaces to whatever file is at its path, so setup refuses a
/// sandy that its user can replace, also when root runs it, and says what to do instead.
#[test]
fn setup_refuses_a_sandy_its_user_can_change() {
    let _serial = serial();
    if !root_on_a_restricted_host() {
        return;
    }
    let portable = PathBuf::from(sandy_path()).canonicalize().unwrap();
    assert_ne!(fs::metadata(&portable).unwrap().uid(), 0);
    let output = sudo([portable.as_os_str(), "setup".as_ref()]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_DONE),
        "{}",
        text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for advice in [
        "not allowed for this binary",
        "--install-copy",
        "package",
        "ip = \"private\"",
    ] {
        assert!(stderr.contains(advice), "{advice}: {stderr}");
    }
    assert_no_profile(&portable);
    assert!(!copy_path().exists());
}

/// (c) `--install-copy` installs a root-owned copy of the running sandy and prepares it. The
/// portable sandy then hands over to it: its check enforces `ip = "private"` and its runs work,
/// but its own file is still checked against the policy, because the next start runs it, and
/// the variable that carries it never reaches the program. The removal takes back the copy,
/// its profile and its directories.
#[test]
fn install_copy_lets_a_portable_sandy_hand_over() {
    let _serial = serial();
    if !root_on_a_restricted_host() {
        return;
    }
    let portable = PathBuf::from(sandy_path()).canonicalize().unwrap();
    let copy = copy_path();
    if copy.parent().unwrap().exists() {
        return skip(
            "no-installed-copy",
            "a copy of this version of sandy is installed, and the test leaves it alone",
        );
    }
    let copy_directory_existed = Path::new(COPY_DIRECTORY).exists();
    let _removal = CopyRemoval {
        directory_existed: copy_directory_existed,
    };
    assert_eq!(
        check_private(&portable).status.code(),
        Some(EXIT_NEEDS_SETUP)
    );

    let setup = sudo([
        portable.as_os_str(),
        "setup".as_ref(),
        "--install-copy".as_ref(),
    ]);
    assert!(setup.status.success(), "{}", text(&setup));
    let metadata = fs::metadata(&copy).unwrap();
    assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (0, 0o755));
    assert!(fs::read(&copy).unwrap() == fs::read(&portable).unwrap());
    assert!(is_loaded(&profile_name(&copy)));
    assert!(!profile_file(&portable).exists());

    let check = check_private(&portable);
    assert!(check.status.success(), "{}", text(&check));
    let run = Command::new(&portable)
        .env("SANDY_STARTED_AS", "/nonexistent")
        .args(["run", "--ip", "private", "--pass-env", "SANDY_STARTED_AS"])
        .args([
            "--read-exec",
            Path::new(&probe_path()).parent().unwrap().to_str().unwrap(),
            "--",
            probe_path().as_str(),
        ])
        .args(probe_args(&[
            ("tcp-listen", "127.0.0.1:0"),
            ("env", "SANDY_STARTED_AS"),
        ]))
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", text(&run));
    let lines = parse(&run);
    lines[0].assert_ok();
    assert_eq!(
        (lines[1].result.as_str(), lines[1].detail.as_str()),
        ("error", "not set")
    );

    // The copy is started under its own path and the name "sandy", so only the variable can
    // tell it which file the next start runs.
    let directory = portable.parent().unwrap();
    let output = Command::new(&portable)
        .arg0("sandy")
        .args(["check", "--ip", "private", "--read-write"])
        .arg(directory)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(EXIT_FAILURE),
        "{}",
        text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("{} lies inside writable path", portable.display())),
        "{stderr}"
    );

    // (d) The removal leaves nothing of the copy behind.
    let removed = sudo([
        portable.as_os_str(),
        "setup".as_ref(),
        "--remove".as_ref(),
        "--install-copy".as_ref(),
    ]);
    assert!(removed.status.success(), "{}", text(&removed));
    assert_no_profile(&copy);
    assert!(!copy.parent().unwrap().exists());
    assert_eq!(Path::new(COPY_DIRECTORY).exists(), copy_directory_existed);
    assert_eq!(
        check_private(&portable).status.code(),
        Some(EXIT_NEEDS_SETUP)
    );
    let again = sudo([
        portable.as_os_str(),
        "setup".as_ref(),
        "--remove".as_ref(),
        "--install-copy".as_ref(),
    ]);
    assert!(again.status.success(), "{}", text(&again));
    assert!(String::from_utf8_lossy(&again.stdout).contains("nothing to remove"));
}

/// Setup writes and removes only files that carry its marker: a file of someone else at the
/// profile's path stays, setup refuses with status 3, and the removal has nothing to remove.
#[test]
fn setup_leaves_a_profile_file_it_did_not_write() {
    let _serial = serial();
    if !root_on_a_restricted_host() {
        return;
    }
    let installed = Installed::new();
    let file = profile_file(&installed.sandy);
    let foreign = "# Not written by sandy.\n";
    let mut tee = Command::new("sudo")
        .args(["-n", "tee"])
        .arg(&file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut tee.stdin.take().unwrap(), foreign.as_bytes()).unwrap();
    assert!(tee.wait().unwrap().success());
    struct Foreign(PathBuf);
    impl Drop for Foreign {
        fn drop(&mut self) {
            sudo(["rm".as_ref(), "-f".as_ref(), self.0.as_os_str()]);
        }
    }
    let _foreign = Foreign(file.clone());

    let setup = sudo([installed.sandy.as_os_str(), "setup".as_ref()]);
    assert_eq!(setup.status.code(), Some(EXIT_NOT_DONE), "{}", text(&setup));
    assert!(
        String::from_utf8_lossy(&setup.stderr).contains("sandy did not write it"),
        "{}",
        text(&setup)
    );
    let removed = sudo([
        installed.sandy.as_os_str(),
        "setup".as_ref(),
        "--remove".as_ref(),
    ]);
    assert!(removed.status.success(), "{}", text(&removed));
    assert!(String::from_utf8_lossy(&removed.stdout).contains("nothing to remove"));
    assert_eq!(fs::read_to_string(&file).unwrap(), foreign);
    assert!(!is_loaded(&profile_name(&installed.sandy)));
}

/// (e) `--elevate` asks pkexec for root's rights. Over SSH no authentication agent runs for the
/// session, so pkexec gives none: setup ends with status 3, installs nothing, and names the
/// sudo command to run instead. A portable sandy without `--install-copy` is refused before
/// pkexec runs.
#[test]
fn elevate_without_an_authentication_agent_is_not_done() {
    let _serial = serial();
    if !restricted() {
        return skip(
            "apparmor-userns-restriction",
            "this host does not restrict user namespaces with AppArmor, so setup has nothing \
             to do and asks for no rights",
        );
    }
    let graphical = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some());
    if std::env::var_os("SSH_CONNECTION").is_none() || graphical {
        return skip(
            "session-without-authentication-agent",
            "only an SSH session without a display is known to have no authentication agent; \
             elsewhere pkexec could show a prompt",
        );
    }
    if !Path::new("/usr/bin/pkexec").exists() {
        return skip("pkexec", "pkexec is not installed");
    }
    let limit = Duration::from_secs(60);
    let portable = PathBuf::from(sandy_path()).canonicalize().unwrap();

    let refused = output_within(Command::new(&portable).args(["setup", "--elevate"]), limit);
    assert_eq!(
        refused.status.code(),
        Some(EXIT_NOT_DONE),
        "{}",
        text(&refused)
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--install-copy"),
        "{}",
        text(&refused)
    );

    let output = output_within(
        Command::new(&portable).args(["setup", "--elevate", "--install-copy"]),
        limit,
    );
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_DONE),
        "{}",
        text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "run: sudo {} setup --install-copy",
            portable.display()
        )),
        "{stderr}"
    );
    assert!(!copy_path().exists());
    assert_no_profile(&copy_path());

    if !root_on_a_restricted_host() {
        return;
    }
    let installed = Installed::new();
    let output = output_within(
        Command::new(&installed.sandy).args(["setup", "--elevate"]),
        limit,
    );
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_DONE),
        "{}",
        text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains(&format!("run: sudo {} setup", installed.sandy.display())),
        "{}",
        text(&output)
    );
    assert_no_profile(&installed.sandy);
}
