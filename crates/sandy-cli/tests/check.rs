//! `sandy check` must not report a policy as enforced when `sandy run` would then refuse it, and
//! it warns about settings that give up part of the isolation.
//!
//! Every test has a control: the same check with a policy that keeps the isolation, or the `run`
//! that the check is supposed to predict.

mod common;

use std::fs;
use std::net::TcpListener;
use std::process::Command;

use common::*;

/// The prefix of the advice `check` writes to standard error. The requirement lines on standard
/// output stay as README.md documents them, so a caller that reads them keeps working.
const WARNING: &str = "warning: ";

/// What `check` exits with when a requirement cannot be enforced on this host.
const NOT_ENFORCEABLE: i32 = 1;

/// The variable that names the user's home directory.
const HOME: &str = if cfg!(windows) { "USERPROFILE" } else { "HOME" };

/// Runs `sandy check` with `args` after `platform_args`, with the home directory set to `home`.
fn check_with_home(home: &std::path::Path, args: &[String]) -> std::process::Output {
    let mut all = vec!["check".to_string()];
    all.extend(platform_args());
    all.extend_from_slice(args);
    Command::new(sandy_path())
        .args(&all)
        .env(HOME, home)
        .output()
        .unwrap()
}

#[test]
fn check_warns_about_settings_that_give_up_isolation() {
    let fixture = Fixture::new("check-warn");
    let home = fixture.path("ro/home");
    fs::create_dir_all(&home).unwrap();
    let output = check_with_home(
        &home,
        &[
            "--unix-sockets".to_string(),
            "all".to_string(),
            "--signals".to_string(),
            "any".to_string(),
            "--linux-path-metadata".to_string(),
            "allow".to_string(),
            "--read-write".to_string(),
            fixture.arg("rw"),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    assert!(!stdout.contains(WARNING), "{stdout}");
    for setting in [
        "unix_sockets = \"all\"",
        "signals = \"any\"",
        "path_metadata = \"allow\"",
    ] {
        assert!(stderr.contains(setting), "{setting} is not named: {stderr}");
    }

    // Control: a policy that keeps the isolation, and a home directory outside the writable path.
    // It still gets the warnings of what this platform gives only in part (the tests below), so
    // the control looks for the warnings above.
    let output = check_with_home(
        &fixture.path("ro"),
        &[
            "--signals".to_string(),
            "isolated".to_string(),
            "--read-write".to_string(),
            fixture.arg("rw"),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for named in [
        "unix_sockets",
        "signals = \"any\"",
        "path_metadata",
        "holds the home directory",
    ] {
        assert!(!warns(&stderr, named), "{stderr}");
    }
}

/// A writable path that holds the home directory lets the program change shell startup files
/// and autostart entries, which run outside the sandbox (README rule 8). The backend refuses
/// such a policy, and the warning says what the program could reach.
#[test]
fn check_refuses_a_writable_path_that_holds_the_home_directory() {
    let fixture = Fixture::new("check-home");
    let home = fixture.path("rw/home");
    fs::create_dir_all(&home).unwrap();
    let output = check_with_home(&home, &["--read-write".to_string(), fixture.arg("rw")]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(NOT_ENFORCEABLE),
        "{stdout}{stderr}"
    );
    assert!(stdout.contains("runs outside the sandbox"), "{stdout}");
    assert!(
        stderr.contains(&fixture.path("rw").display().to_string()),
        "the writable path that holds the home directory is not named: {stderr}"
    );

    // Control: the same policy with the home directory beside the writable path.
    let output = check_with_home(
        &fixture.path("ro"),
        &["--read-write".to_string(), fixture.arg("rw")],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// cargo's configuration names programs that the next cargo command runs outside the sandbox
/// (`build.rustc-wrapper`), so a writable path that reaches it is refused, in `.cargo` of the
/// home directory and in `CARGO_HOME` (README rule 8). The registry beside it stays writable.
#[test]
fn check_refuses_a_writable_path_over_the_cargo_configuration() {
    let fixture = Fixture::new("check-cargo");
    for directory in ["home/.cargo/registry", "cargo/registry"] {
        fs::create_dir_all(fixture.path(directory)).unwrap();
    }
    for file in [
        "home/.cargo/config.toml",
        "home/.cargo/config",
        "cargo/config.toml",
    ] {
        fs::write(fixture.path(file), b"").unwrap();
    }
    let check = |writable: &str| {
        let mut all = vec!["check".to_string()];
        all.extend(platform_args());
        all.extend(["--read-write".to_string(), fixture.arg(writable)]);
        Command::new(sandy_path())
            .args(&all)
            .env(HOME, fixture.path("home"))
            .env("CARGO_HOME", fixture.path("cargo"))
            .output()
            .unwrap()
    };
    let cases = [
        ("home/.cargo", "home/.cargo/registry"),
        ("home/.cargo/config.toml", "home/.cargo/registry"),
        ("home/.cargo/config", "home/.cargo/registry"),
        ("cargo", "cargo/registry"),
        ("cargo/config.toml", "cargo/registry"),
    ];
    for (location, beside) in cases {
        let refused = check(location);
        let stdout = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(
            refused.status.code(),
            Some(NOT_ENFORCEABLE),
            "{location}: {stdout}"
        );
        assert!(stdout.contains("runs outside the sandbox"), "{stdout}");

        let allowed = check(beside);
        assert!(
            allowed.status.success(),
            "{beside}: {}",
            String::from_utf8_lossy(&allowed.stdout)
        );
    }
}

/// A command line option replaces the value of the policy file, also with a weaker one. The
/// caller is trusted, so sandy obeys, but `check` says which option widened the policy.
#[test]
fn check_warns_when_an_option_weakens_the_policy_file() {
    let fixture = Fixture::new("check-weaken");
    let policy = fixture.path("ro/policy.toml");
    fs::write(
        &policy,
        "version = 1\n[network]\nunix_sockets = \"none\"\n[process]\nsignals = \"isolated\"\n\
         children = \"none\"\n",
    )
    .unwrap();
    let with = |args: &[&str]| {
        let mut all = vec!["check".to_string()];
        all.extend(platform_args());
        all.extend(["--policy".to_string(), policy.to_str().unwrap().to_string()]);
        all.extend(args.iter().map(|arg| arg.to_string()));
        let output = sandy(&all);
        String::from_utf8_lossy(&output.stderr).into_owned()
    };

    // Control: the same policy file without options that change it.
    let stderr = with(&[]);
    assert!(!stderr.contains("replaces"), "{stderr}");

    let stderr = with(&["--unix-sockets", "all", "--children", "allowed"]);
    assert!(
        stderr.contains("--unix-sockets all replaces unix_sockets = \"none\""),
        "{stderr}"
    );
    assert!(
        stderr.contains("--children allowed replaces children = \"none\""),
        "{stderr}"
    );

    // contained is weaker than none: the program may start processes again, and they only have
    // to end with it.
    let stderr = with(&["--children", "contained"]);
    assert!(
        stderr.contains("--children contained replaces children = \"none\""),
        "{stderr}"
    );

    // An option that keeps or raises the restriction says nothing.
    let stderr = with(&["--children", "none", "--unix-sockets", "none"]);
    assert!(!stderr.contains("replaces"), "{stderr}");
}

/// Runs `sandy check` with `args` and returns its standard error.
fn check_warnings(args: &[&str]) -> String {
    let mut all = vec!["check".to_string()];
    all.extend(platform_args());
    all.extend(args.iter().map(|arg| arg.to_string()));
    String::from_utf8_lossy(&sandy(&all).stderr).into_owned()
}

/// Whether a warning line of `stderr` names `text`.
fn warns(stderr: &str, text: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.starts_with(WARNING) && line.contains(text))
}

/// A loopback address with a port that nothing listens on, for the relays that check binds.
#[cfg(unix)]
fn free_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

/// `--forward` options for a free program port. `to` is held by a listener of its own, so the
/// two ports differ; the relay connects to it only when the program does.
#[cfg(unix)]
fn forward_args(to: &TcpListener) -> [String; 4] {
    let port = free_address().rsplit_once(':').unwrap().1.to_string();
    [
        "--ip".to_string(),
        "all".to_string(),
        "--forward".to_string(),
        format!("{port}={}", to.local_addr().unwrap()),
    ]
}

/// In the exec model the program runs in the process group sandy was started in, and the kernel
/// stops that whole group when the program reads the terminal from the background
/// (docs/linux.md, "Signals and the terminal"). check says so for isolated signals, and not
/// where the program has a group of its own or may signal every process anyway.
#[cfg(target_os = "linux")]
#[test]
fn check_warns_that_a_terminal_read_stops_the_group_sandy_was_started_in() {
    let gap = "the group sandy was started in";
    let stderr = check_warnings(&["--signals", "isolated"]);
    assert!(warns(&stderr, gap), "{stderr}");

    let stderr = check_warnings(&["--signals", "isolated", "--children", "contained"]);
    assert!(!warns(&stderr, gap), "{stderr}");
    let stderr = check_warnings(&["--signals", "any"]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// The relay of a forwarded port serves a connection whose owner the kernel no longer knows,
/// which lets another user deliver a write (docs/linux.md, "Exposed and forwarded ports").
#[cfg(target_os = "linux")]
#[test]
fn check_warns_that_a_forwarded_port_takes_a_write_of_another_user() {
    let gap = "another local user can deliver a write";
    let to = TcpListener::bind("127.0.0.1:0").unwrap();
    let forward = forward_args(&to);
    let stderr = check_warnings(&forward.each_ref().map(String::as_str));
    assert!(warns(&stderr, gap), "{stderr}");

    // Control: an exposed port is meant for other users.
    let expose = format!("{}=8080", free_address());
    let stderr = check_warnings(&["--ip", "all", "--expose", &expose]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// The kernel sends SIGIO, and SIGURG for urgent TCP data, to the owner of a socket or a pipe
/// without the check that isolated signals are (docs/macos.md, "Signals the profile does not
/// cover"). SIGURG needs TCP, so check names it only with IP networking.
#[cfg(target_os = "macos")]
#[test]
fn check_warns_that_isolated_signals_leave_sigio_open() {
    let stderr = check_warnings(&["--signals", "isolated"]);
    assert!(warns(&stderr, "send SIGIO to a process"), "{stderr}");
    let stderr = check_warnings(&["--signals", "isolated", "--ip", "all"]);
    assert!(warns(&stderr, "send SIGIO and SIGURG"), "{stderr}");

    let stderr = check_warnings(&["--signals", "any", "--ip", "all"]);
    assert!(!warns(&stderr, "SIGIO"), "{stderr}");
}

/// A program with isolated signals can join another job of its terminal session and have the
/// kernel stop it; `children = "contained"` denies the move (docs/macos.md, "Signals the
/// profile does not cover").
#[cfg(target_os = "macos")]
#[test]
fn check_warns_that_isolated_signals_leave_job_control_open() {
    let gap = "another job of its terminal session";
    let stderr = check_warnings(&["--signals", "isolated"]);
    assert!(warns(&stderr, gap), "{stderr}");

    let stderr = check_warnings(&["--signals", "isolated", "--children", "contained"]);
    assert!(!warns(&stderr, gap), "{stderr}");
    let stderr = check_warnings(&["--signals", "any"]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// `children = "contained"` denies `posix_spawn`, which many runtimes start processes with
/// (docs/macos.md, "Contained child processes").
#[cfg(target_os = "macos")]
#[test]
fn check_warns_that_contained_children_cannot_use_posix_spawn() {
    let gap = "denies posix_spawn";
    let stderr = check_warnings(&["--signals", "isolated", "--children", "contained"]);
    assert!(warns(&stderr, gap), "{stderr}");

    let stderr = check_warnings(&["--signals", "isolated", "--children", "none"]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// macOS cannot tell the relay who is at the other end of a connection, so a forwarded port
/// serves every local user (docs/macos.md, "Who may connect, and who may stop the relay").
#[cfg(target_os = "macos")]
#[test]
fn check_warns_that_a_forwarded_port_serves_every_user() {
    let gap = "serves every local user";
    let to = TcpListener::bind("127.0.0.1:0").unwrap();
    let forward = forward_args(&to);
    let stderr = check_warnings(&forward.each_ref().map(String::as_str));
    assert!(warns(&stderr, gap), "{stderr}");

    // Control: an exposed port is meant for other users.
    let expose = format!("{}=8080", free_address());
    let stderr = check_warnings(&["--ip", "all", "--expose", &expose]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// With `signals = "any"` the program can stop its relay, and nothing on macOS ends a stopped
/// relay (docs/macos.md, "Who may connect, and who may stop the relay").
#[cfg(target_os = "macos")]
#[test]
fn check_warns_that_a_stopped_relay_has_no_time_limit() {
    let gap = "outlive the program without limit";
    let expose = format!("{}=8080", free_address());
    let stderr = check_warnings(&["--ip", "all", "--expose", &expose]);
    assert!(warns(&stderr, gap), "{stderr}");
    let to = TcpListener::bind("127.0.0.1:0").unwrap();
    let forward = forward_args(&to);
    let stderr = check_warnings(&forward.each_ref().map(String::as_str));
    assert!(warns(&stderr, gap), "{stderr}");

    let stderr = check_warnings(&["--ip", "all", "--expose", &expose, "--signals", "isolated"]);
    assert!(!warns(&stderr, gap), "{stderr}");
    let stderr = check_warnings(&["--ip", "all"]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// A file moved out of a granted directory keeps the grant it inherited there
/// (docs/windows.md, "Links and identity"). A grant of a single file has no such children.
#[cfg(windows)]
#[test]
fn check_warns_that_a_grant_follows_a_moved_file() {
    let fixture = Fixture::new("check-moved");
    let gap = "follows the file, not the path";
    let stderr = check_warnings(&["--read", &fixture.arg("ro")]);
    assert!(warns(&stderr, gap), "{stderr}");

    let stderr = check_warnings(&["--read", &fixture.arg("ro/file")]);
    assert!(!warns(&stderr, gap), "{stderr}");
}

/// `run` binds the listeners of exposed and forwarded ports outside the sandbox, so a port that
/// another process holds makes it refuse. `check` binds them too and reports the same.
#[test]
fn check_reports_an_exposed_port_that_is_already_in_use() {
    let fixture = Fixture::new("check-busy");
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = held.local_addr().unwrap();
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--expose".to_string(),
        format!("{busy}=8080"),
    ]);
    // On Windows the relay needs the AppContainer that holds the loopback exemption, which the
    // helpers add only to a `run`. Named here, both the check and the run use it.
    #[cfg(windows)]
    {
        prepare_loopback_exemption();
        sandbox_args.extend(["--appcontainer".to_string(), appcontainer_loopback_name()]);
    }

    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    args.extend_from_slice(&sandbox_args);
    let output = sandy(&args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(NOT_ENFORCEABLE),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("UNAVAILABLE"), "{stdout}");
    assert!(stdout.contains(&busy.to_string()), "{stdout}");

    // run refuses the same policy, and the port is free again after the check.
    let output = sandy(run_args(
        &sandbox_args,
        &[("read", &fixture.arg("ro/file"))],
    ));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");

    // Control: a free port, so nothing but the busy port made the difference.
    drop(held);
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    args.extend_from_slice(&sandbox_args);
    let output = sandy(&args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
}

/// The kernel executes the interpreter of a script, which needs execute access of its own. sandy
/// reports that before it starts: the `execve` would otherwise fail with "Permission denied"
/// after the sandbox is already in place. Windows has no `#!` line.
#[cfg(unix)]
#[test]
fn check_reports_a_script_whose_interpreter_cannot_be_executed() {
    let fixture = Fixture::new("check-shebang");
    let script = fixture.path("bin/script.sh");
    // /bin/echo, not a shell: macOS runs /bin/sh through a program that execs a variant of it,
    // which needs more than the one path, and this test is about the one path.
    fs::write(&script, "#!/bin/echo\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let script = script.to_str().unwrap().to_string();
    let sandy_with = |sandbox_args: &[String], mode: &str| {
        let mut args = vec![mode.to_string()];
        args.extend(platform_args());
        args.extend_from_slice(sandbox_args);
        args.extend(["--".to_string(), script.clone()]);
        sandy(&args)
    };

    let output = sandy_with(&fixture.access_args(), "check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(NOT_ENFORCEABLE), "{stdout}");
    assert!(stdout.contains("UNAVAILABLE"), "{stdout}");
    assert!(stdout.contains("interpreter"), "{stdout}");
    let output = sandy_with(&fixture.access_args(), "run");
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");

    // Control: the same script with its interpreter in a read_exec path runs. The interpreter
    // gets the script's path as its argument, so its output shows that it ran.
    let mut allowed = fixture.access_args();
    allowed.extend(["--read-exec".to_string(), "/bin/echo".to_string()]);
    let output = sandy_with(&allowed, "check");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = sandy_with(&allowed, "run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("script.sh"), "{stdout}");
}

/// `children = "contained"` runs the program in a process group of its own, and sandy's own
/// filter denies `setpgid` inside such a sandbox, so one contained sandbox cannot hold another.
/// check said it could, and run then failed with "cannot create the program's process group".
#[cfg(target_os = "linux")]
#[test]
fn check_reports_contained_children_inside_a_contained_sandbox() {
    if common::linux::landlock_abi() < 6 {
        return skip(
            "landlock-abi-6",
            "children = contained needs Landlock ABI 6",
        );
    }
    let fixture = Fixture::new("check-nested");
    let inner = fixture.path("bin/sandy");
    copy_executable(sandy_path(), &inner);
    let contained = ["--signals", "isolated", "--children", "contained"];
    let inner_check: Vec<String> = [inner.to_str().unwrap(), "check"]
        .into_iter()
        .chain(contained)
        .map(str::to_string)
        .collect();

    // Control: the same check outside a sandbox.
    let output = sandy(&inner_check[1..]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // The inner sandy needs /proc for the mount table and its own thread count.
    let mut args: Vec<String> = ["run"].iter().map(|a| a.to_string()).collect();
    args.extend(contained.map(str::to_string));
    args.extend([
        "--read-exec".to_string(),
        fixture.arg("bin"),
        "--read".to_string(),
        "/proc".to_string(),
        "--".to_string(),
    ]);
    args.extend(inner_check);
    let output = sandy(&args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(NOT_ENFORCEABLE),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("UNAVAILABLE  child processes end"),
        "{stdout}"
    );

    // run refuses it too, instead of failing while it starts the program.
    let mut run = args.clone();
    let position = run.iter().position(|arg| arg == "check").unwrap();
    run[position] = "run".to_string();
    run.extend([
        "--read-exec".to_string(),
        "/usr/bin".to_string(),
        "--read".to_string(),
        "/proc".to_string(),
        "--".to_string(),
        "/usr/bin/true".to_string(),
    ]);
    let output = sandy(&run);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("process group"), "{stderr}");
}

/// `check --explain-path` says which rule decides a path. A backend that cannot answer must
/// refuse the question instead of printing a guess that a caller would act on.
#[test]
fn explain_path_says_which_rule_decides_a_path() {
    let fixture = Fixture::new("explain-path");
    let mut args = fixture.access_args();
    for path in ["ro/file", "rw/file", "secret/file"] {
        args.push("--explain-path".to_string());
        args.push(fixture.arg(path));
    }
    let output = check_with_home(&fixture.path("ro"), &args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !cfg!(target_os = "linux") {
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stdout}{stderr}");
        assert!(
            stderr.contains("--explain-path is not available"),
            "{stderr}"
        );
        return;
    }
    assert!(output.status.success(), "{stdout}{stderr}");
    for (path, answer) in [
        (
            "ro/file",
            format!("the rule {} allows read", fixture.arg("ro")),
        ),
        (
            "rw/file",
            format!("the rule {} allows read and write", fixture.arg("rw")),
        ),
        ("secret/file", "no rule covers it".to_string()),
    ] {
        let line = format!("{}: {answer}", fixture.arg(path));
        assert!(stdout.contains(&line), "no line {line:?} in:\n{stdout}");
    }
    // Control: the requirement lines a caller reads are still the first lines of the output.
    assert!(stdout.starts_with("backend: "), "{stdout}");
}

/// The diagnostic mode belongs to `run`, and a backend that cannot report what it denied must
/// refuse it: a mode that prints nothing would read as "nothing was denied".
#[test]
fn explain_is_refused_where_it_reports_nothing() {
    let output = sandy(["check", "--explain"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stderr}");
    assert!(stderr.contains("--explain belongs to run"), "{stderr}");

    let fixture = Fixture::new("explain-unavailable");
    let mut args = fixture.access_args();
    args.push("--explain".to_string());
    let output = sandy(run_args(&args, &[("read", &fixture.arg("ro/file"))]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    if cfg!(target_os = "linux") {
        assert!(output.status.success(), "{output:?}");
        assert!(stderr.contains("sandy explain: "), "{stderr}");
    } else {
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stderr}");
        assert!(stderr.contains("--explain is not available"), "{stderr}");
    }
}

/// Every program on macOS is linked dynamically, and `system = "none"` leaves out the root
/// directory, /usr/lib and the dyld shared cache, so no program starts with it. check reported
/// such a policy as enforced and the program then died at its start. A policy that reads the root
/// directory brings those paths itself.
#[cfg(target_os = "macos")]
#[test]
fn check_refuses_system_none_without_the_root_directory() {
    let output = sandy(["check", "--system", "none"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(NOT_ENFORCEABLE), "{stdout}");
    assert!(stdout.contains("UNAVAILABLE"), "{stdout}");
    assert!(stdout.contains("dyld"), "{stdout}");

    // Control: with the root directory readable the policy is enforceable and the program runs.
    let output = sandy([
        "check",
        "--system",
        "none",
        "--read",
        "/",
        "--",
        "/usr/bin/true",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let output = sandy([
        "run",
        "--system",
        "none",
        "--read",
        "/",
        "--",
        "/usr/bin/true",
    ]);
    assert!(output.status.success(), "{output:?}");
}

/// check applies the profile in a helper process, because a profile that compiles can still be
/// refused when it is applied. The trial must not refuse a policy that works: it reports a
/// problem only when the helper cannot apply the profile.
#[cfg(target_os = "macos")]
#[test]
fn the_trial_profile_does_not_refuse_a_working_policy() {
    let fixture = Fixture::new("check-trial");
    let program = fixture.copy_probe("bin");
    let mut policy = fixture.access_args();
    policy.extend(
        [
            "--signals",
            "isolated",
            "--children",
            "contained",
            "--end-with-parent",
        ]
        .map(String::from),
    );
    let mut args = vec!["check".to_string()];
    args.extend(policy.clone());
    args.extend(["--".to_string(), program]);
    let output = sandy(&args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("UNAVAILABLE"), "{stdout}");

    // Control: the same policy runs, so the trial agreed with the run.
    let lines = probe_inside(&policy, &[("read", &fixture.arg("ro/file"))]);
    lines[0].assert_ok();
}

/// Windows does not nest sandy's job, which sets UI restrictions, inside a job that has UI
/// restrictions of its own, so `run` fails there and `check` must say so. sandy reads the UI
/// restrictions of the job it is in, which for a chain of jobs is only the innermost one.
#[cfg(windows)]
#[test]
fn check_and_run_agree_inside_nested_jobs() {
    const READ_CLIPBOARD: u32 = 0x2;
    let fixture = Fixture::new("check-jobs");
    let mut check = vec!["check".to_string()];
    check.extend(platform_args());
    let run = run_args(&fixture.access_args(), &[("read", &fixture.arg("ro/file"))]);

    // Control: a chain of jobs without UI restrictions holds sandy's job, so the policy runs.
    let (code, output) = windows::sandy_in_jobs(&[0, 0], &check);
    assert_eq!(code, 0, "{output}");
    let (code, output) = windows::sandy_in_jobs(&[0, 0], &run);
    assert_eq!(code, 0, "{output}");

    // The UI restrictions of the outer job are the ones Windows refuses to nest under, and sandy
    // reads the restrictions of the inner job, which has none.
    for chain in [[READ_CLIPBOARD, 0], [0, READ_CLIPBOARD]] {
        let (code, output) = windows::sandy_in_jobs(&chain, &check);
        assert_eq!(code as i32, NOT_ENFORCEABLE, "{chain:?}: {output}");
        assert!(output.contains("UI restrictions"), "{chain:?}: {output}");
        let (code, output) = windows::sandy_in_jobs(&chain, &run);
        assert_eq!(code as i32, EXIT_FAILURE, "{chain:?}: {output}");
    }
}

#[cfg(windows)]
mod windows {
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JobObjectBasicUIRestrictions, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
    };

    /// Starts sandy with `sandy_args` inside a chain of new jobs, the outermost first, each with
    /// the UI restrictions of its entry. Returns the exit code and the standard output.
    pub fn sandy_in_jobs(ui: &[u32], sandy_args: &[String]) -> (u32, String) {
        let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: both out pointers are valid.
        let piped = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
        assert_ne!(piped, 0);
        // SAFETY: CreatePipe returned two new handles that this function owns.
        let (read, write) = unsafe {
            (
                OwnedHandle::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            )
        };
        // SAFETY: write is a valid handle; only its inherit flag changes.
        unsafe {
            SetHandleInformation(
                write.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        };
        let jobs: Vec<OwnedHandle> = ui
            .iter()
            .map(|restrictions| {
                // SAFETY: null attributes and name create an unnamed job.
                let job = unsafe {
                    OwnedHandle::from_raw_handle(CreateJobObjectW(
                        std::ptr::null(),
                        std::ptr::null(),
                    ))
                };
                if *restrictions != 0 {
                    let limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                        UIRestrictionsClass: *restrictions,
                    };
                    // SAFETY: the structure matches the information class and outlives the call.
                    let ok = unsafe {
                        SetInformationJobObject(
                            job.as_raw_handle(),
                            JobObjectBasicUIRestrictions,
                            (&limits as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                        )
                    };
                    assert_ne!(ok, 0);
                }
                job
            })
            .collect();

        let mut line = format!("\"{}\"", crate::common::sandy_path());
        for arg in sandy_args {
            line.push_str(&format!(" \"{arg}\""));
        }
        let mut line: Vec<u16> = line.encode_utf16().chain([0]).collect();
        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = write.as_raw_handle();
        startup.hStdError = write.as_raw_handle();
        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: line is NUL-terminated and writable; startup and info outlive the call.
        let created = unsafe {
            CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut info,
            )
        };
        assert_ne!(created, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: CreateProcessW returned two new handles that this function owns.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(info.hProcess),
                OwnedHandle::from_raw_handle(info.hThread),
            )
        };
        // The order makes the chain: every job joins the one assigned before it.
        for job in &jobs {
            // SAFETY: the job and the suspended process are valid handles.
            let assigned =
                unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) };
            assert_ne!(assigned, 0, "{}", std::io::Error::last_os_error());
        }
        // SAFETY: thread is the suspended main thread of sandy.
        unsafe { ResumeThread(thread.as_raw_handle()) };
        drop(write);
        let mut output = String::new();
        let _ = std::fs::File::from(read).read_to_string(&mut output);
        let mut code = 0u32;
        // SAFETY: process is valid; code is a writable u32.
        unsafe {
            WaitForSingleObject(process.as_raw_handle(), INFINITE);
            GetExitCodeProcess(process.as_raw_handle(), &mut code);
        }
        (code, output)
    }
}
