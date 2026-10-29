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

/// Whether this test may use `sudo -n`; records a skip when not.
fn passwordless_sudo() -> bool {
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
    true
}

/// Whether this test may use `sudo -n` and the host restricts user namespaces with AppArmor;
/// records a skip when not.
fn root_on_a_restricted_host() -> bool {
    if !passwordless_sudo() {
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

/// Where an `Installed` goes: the first of these directories that only root can change, along
/// its whole path. The GitHub Ubuntu images make /opt writable by everyone (mode 777), and setup
/// rightly refuses a sandy below it.
const INSTALL_PARENTS: [&str; 3] = ["/opt", "/usr/local/lib", "/usr/lib"];

fn only_root_can_change(path: &Path) -> bool {
    path.ancestors().all(|directory| {
        fs::symlink_metadata(directory)
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    })
}

impl Installed {
    fn new() -> Installed {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let parent = INSTALL_PARENTS
            .into_iter()
            .map(Path::new)
            .find(|parent| only_root_can_change(parent))
            .expect("none of the install parents can be changed by root alone");
        let directory = parent.join(format!(
            "sandy-setup-test-{}-{}",
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

/// Runs `sandy` with `args` where it may hold only one descriptor beyond 0, 1 and 2, or without a
/// limit.
fn with_descriptors(sandy: &Path, args: &[&str], limit: Option<libc::rlim_t>) -> Output {
    let mut command = Command::new(sandy);
    command.args(args);
    if let Some(limit) = limit {
        // SAFETY: setrlimit is async-signal-safe, and the closure calls nothing else.
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                match libc::setrlimit(libc::RLIMIT_NOFILE, &limit) {
                    0 => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                }
            });
        }
    }
    command.output().unwrap()
}

/// Once the copy is installed, a check of it that fails for a reason that can pass is an error
/// with status 125, in `check` and `run`: running on as the portable sandy would report that the
/// host needs setup, which is not so, and could make sandy pick a weaker fallback level. Here
/// sandy may open one file at a time, so it cannot list the loaded profiles and read one of
/// them. Control: without the limit it hands over.
#[test]
fn a_failed_check_of_the_installed_copy_is_an_error() {
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
    let _removal = CopyRemoval {
        directory_existed: Path::new(COPY_DIRECTORY).exists(),
    };
    let setup = sudo([
        portable.as_os_str(),
        "setup".as_ref(),
        "--install-copy".as_ref(),
    ]);
    assert!(setup.status.success(), "{}", text(&setup));

    let probe = probe_path();
    let directory = Path::new(&probe).parent().unwrap().to_str().unwrap();
    let check = ["check", "--ip", "private"];
    let run = [
        "run",
        "--ip",
        "private",
        "--read-exec",
        directory,
        "--",
        &probe,
        "pid",
        "-",
    ];
    for args in [&check[..], &run[..]] {
        let handed = with_descriptors(&portable, args, None);
        assert!(handed.status.success(), "{args:?}: {}", text(&handed));
        let failed = with_descriptors(&portable, args, Some(4));
        assert_eq!(
            failed.status.code(),
            Some(EXIT_FAILURE),
            "{args:?}: {}",
            text(&failed)
        );
        assert!(failed.stdout.is_empty(), "{args:?}: {}", text(&failed));
        let stderr = String::from_utf8_lossy(&failed.stderr);
        assert!(
            stderr.contains(&format!(
                "cannot tell whether to hand over to the installed copy {}",
                copy.display()
            )),
            "{args:?}: {stderr}"
        );
    }
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

const UNPRIVILEGED_USERNS_CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";

/// Writes `value` to the sysctl file `path` as root.
fn set_sysctl(path: &str, value: &str) {
    let mut tee = Command::new("sudo")
        .args(["-n", "tee", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut tee.stdin.take().unwrap(), value.as_bytes()).unwrap();
    assert!(
        tee.wait().unwrap().success(),
        "cannot set {path} to {value}"
    );
}

/// Sets a sysctl back to the value it had, also when a test fails.
struct Restore {
    path: &'static str,
    value: String,
}

impl Drop for Restore {
    fn drop(&mut self) {
        set_sysctl(self.path, &self.value);
    }
}

/// Where the host disables user namespaces for unprivileged processes, `check` reports them
/// unavailable (status 1), and setup, which only lifts the AppArmor restriction, installs
/// nothing and ends with status 3, with root, without it and with `--elevate`, which then asks
/// for nothing. The test turns `kernel.unprivileged_userns_clone` off for its duration.
#[test]
fn setup_cannot_enable_disabled_user_namespaces() {
    let _serial = serial();
    if !passwordless_sudo() {
        return;
    }
    let before = read(UNPRIVILEGED_USERNS_CLONE);
    if before.is_empty() {
        return skip(
            "unprivileged-userns-clone",
            "only Debian and Ubuntu kernels have kernel.unprivileged_userns_clone",
        );
    }
    // A setup that wrongly went ahead would install the copy too; take it back then.
    let copy_existed = copy_path().parent().unwrap().exists();
    let _removal = (!copy_existed).then(|| CopyRemoval {
        directory_existed: Path::new(COPY_DIRECTORY).exists(),
    });
    let installed = Installed::new();
    let _restore = Restore {
        path: UNPRIVILEGED_USERNS_CLONE,
        value: before,
    };
    set_sysctl(UNPRIVILEGED_USERNS_CLONE, "0");

    let check = check_private(&installed.sandy);
    assert_eq!(check.status.code(), Some(1), "{}", text(&check));
    assert!(
        String::from_utf8_lossy(&check.stdout).contains("kernel.unprivileged_userns_clone = 0"),
        "{}",
        text(&check)
    );
    let sandy = installed.sandy.as_os_str();
    for output in [
        sudo([sandy, "setup".as_ref()]),
        sudo([sandy, "setup".as_ref(), "--install-copy".as_ref()]),
        output_within(
            Command::new(sandy).args(["setup", "--elevate"]),
            Duration::from_secs(60),
        ),
        sandy_output(sandy, &["setup"]),
    ] {
        assert_eq!(
            output.status.code(),
            Some(EXIT_NOT_DONE),
            "{}",
            text(&output)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        for part in [
            "user namespaces are disabled on this host",
            "setup cannot change that",
            "until setup is done, run policies without ip = \"private\"",
        ] {
            assert!(stderr.contains(part), "{part}: {stderr}");
        }
    }
    assert_no_profile(&installed.sandy);
    assert_eq!(copy_path().parent().unwrap().exists(), copy_existed);
}

fn sandy_output(sandy: &std::ffi::OsStr, args: &[&str]) -> Output {
    Command::new(sandy).args(args).output().unwrap()
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

/// A polkit rule that lets this user run pkexec without a password, as an administrator's
/// password would for one call. Dropping it takes the rule back.
struct PasswordlessPkexec(PathBuf);

impl PasswordlessPkexec {
    /// `None` when polkit does not take the rule within a few seconds.
    fn install(user: &str) -> Option<PasswordlessPkexec> {
        let rule = PathBuf::from(format!(
            "/etc/polkit-1/rules.d/00-sandy-test-{}.rules",
            std::process::id()
        ));
        let text = format!(
            "polkit.addRule(function(action, subject) {{\n  if (action.id == \
             \"org.freedesktop.policykit.exec\" && subject.user == \"{user}\") {{\n    return \
             polkit.Result.YES;\n  }}\n}});\n"
        );
        let mut tee = Command::new("sudo")
            .args(["-n", "tee"])
            .arg(&rule)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut tee.stdin.take().unwrap(), text.as_bytes()).unwrap();
        assert!(
            tee.wait().unwrap().success(),
            "cannot write {}",
            rule.display()
        );
        let installed = PasswordlessPkexec(rule);
        // polkitd reads its rules again when the directory changes.
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            let tried = output_within(
                Command::new("/usr/bin/pkexec").arg("/bin/true"),
                Duration::from_secs(30),
            );
            if tried.status.success() {
                return Some(installed);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
}

impl Drop for PasswordlessPkexec {
    fn drop(&mut self) {
        sudo(["rm".as_ref(), "-f".as_ref(), self.0.as_os_str()]);
    }
}

/// The directory of the copies, made by the test with a default ACL that gives this user every
/// right in what is created below it. Dropping it removes it, and `/usr/local/libexec` when the
/// test made that too.
struct SharedCopyDirectory {
    libexec_existed: bool,
}

impl Drop for SharedCopyDirectory {
    fn drop(&mut self) {
        sudo(["rm", "-rf", COPY_DIRECTORY]);
        if !self.libexec_existed {
            sudo(["rmdir", "/usr/local/libexec"]);
        }
    }
}

/// (f) `--elevate --install-copy` through pkexec, as an administrator who types the password runs
/// it: the fixed script creates the copy's directories and the copy so that only root can change
/// them, also below a directory whose default ACL gives this user write in everything created
/// there. Otherwise this user could replace the copy before root runs it. The copy's setup then
/// loads the profile, and the portable sandy hands over to it.
#[test]
fn elevate_installs_a_copy_that_only_root_can_change() {
    let _serial = serial();
    if !root_on_a_restricted_host() {
        return;
    }
    if !Path::new("/usr/bin/pkexec").exists() {
        return skip("pkexec", "pkexec is not installed");
    }
    if Path::new(COPY_DIRECTORY).exists() {
        return skip(
            "no-installed-copy",
            "a copy of sandy is installed, and the test leaves it alone",
        );
    }
    if Command::new("setfacl").arg("--version").output().is_err() {
        return skip("setfacl", "setfacl is not installed");
    }
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    let user = user.trim();
    let Some(_pkexec) = PasswordlessPkexec::install(user) else {
        return skip(
            "passwordless-pkexec",
            "polkit did not take a rule that lets this user run pkexec",
        );
    };
    let _shared = SharedCopyDirectory {
        libexec_existed: Path::new("/usr/local/libexec").exists(),
    };
    let made = sudo(["install", "-d", "-m", "0755", COPY_DIRECTORY]);
    assert!(made.status.success(), "{}", text(&made));
    let acl = sudo([
        "setfacl",
        "-d",
        "-m",
        &format!("u:{user}:rwx"),
        COPY_DIRECTORY,
    ]);
    assert!(acl.status.success(), "{}", text(&acl));
    let _removal = CopyRemoval {
        directory_existed: true,
    };

    let portable = PathBuf::from(sandy_path()).canonicalize().unwrap();
    let output = output_within(
        Command::new(&portable).args(["setup", "--elevate", "--install-copy"]),
        Duration::from_secs(120),
    );
    let copy = copy_path();
    let planted = copy.parent().unwrap().join("planted");
    let created = fs::File::create(&planted).map(drop);
    assert_eq!(
        created.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "this user can create files next to the copy: {}",
        text(&output)
    );
    let opened = fs::OpenOptions::new().write(true).open(&copy).map(drop);
    assert_eq!(
        opened.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "this user can change the copy: {}",
        text(&output)
    );
    assert!(output.status.success(), "{}", text(&output));
    assert!(is_loaded(&profile_name(&copy)));
    let check = check_private(&portable);
    assert!(check.status.success(), "{}", text(&check));
}
