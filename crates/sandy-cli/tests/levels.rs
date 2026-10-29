//! Fallback levels: `check` and `run` take the first level of a policy that the host enforces,
//! say which and why, and never more than that; and `--policy -` reads the policy from standard
//! input, which the program then does not get.
//!
//! Each platform has a policy whose base it cannot enforce for a lasting reason of its own (see
//! `natural`), so these tests reach a fallback level the way a real host does, with the base
//! itself as the control: pinned with `--level`, it is refused.

mod common;

use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::*;

const NOT_ENFORCEABLE: i32 = 1;

/// A policy whose base this host cannot enforce and whose level `weaker` it can, with the
/// command that runs sandy so that it sees the host that way.
struct Natural {
    /// The policy text without paths; `policy` adds them.
    text: String,
    /// The program that runs sandy, with its arguments, or nothing.
    wrapper: Vec<String>,
}

/// Linux: isolated signals need Landlock ABI 6 or a PID namespace, so under `sandy-abi-cap 4` a
/// base that asks for them alone cannot be enforced, and a level with `signals = "any"` can.
#[cfg(target_os = "linux")]
fn natural() -> Option<Natural> {
    let Some(cap) = abi_cap_path() else {
        skip("abi-cap", "sandy-abi-cap is not next to the other binaries");
        return None;
    };
    Some(Natural {
        text: "[process]\nsignals = \"isolated\"\n\
               [[fallback]]\nname = \"weaker\"\nprocess.signals = \"any\"\n"
            .to_string(),
        wrapper: vec![cap, "4".to_string()],
    })
}

/// macOS: the profile that hides the paths outside the policy cannot also allow every Unix
/// socket (docs/macos.md), so such a base is never enforceable there.
#[cfg(target_os = "macos")]
fn natural() -> Option<Natural> {
    Some(Natural {
        text: "[filesystem]\nview = \"policy\"\n[network]\nunix_sockets = \"all\"\n\
               [[fallback]]\nname = \"weaker\"\nfilesystem.view = \"all\"\n"
            .to_string(),
        wrapper: Vec::new(),
    })
}

/// Windows has no way to hide the paths outside the policy. Each level needs an AppContainer
/// name of its own.
#[cfg(windows)]
fn natural() -> Option<Natural> {
    Some(Natural {
        text: format!(
            "[filesystem]\nview = \"policy\"\n[windows]\nappcontainer_name = \"{}\"\n\
             [[fallback]]\nname = \"weaker\"\nfilesystem.view = \"all\"\n\
             windows.appcontainer_name = \"{}\"\n",
            appcontainer_name(),
            level_appcontainer_name()
        ),
        wrapper: Vec::new(),
    })
}

/// The policy file of `natural` in the fixture, with the fixture's paths in the base. It lies
/// outside every writable path, as sandy requires of its policy.
fn policy(fixture: &Fixture, natural: &Natural) -> String {
    let path = fixture.path("policy.toml");
    let text = format!(
        "version = 1\n[filesystem]\nread = [{:?}]\nread_write = [{:?}]\n{}",
        fixture.arg("ro"),
        fixture.arg("rw"),
        natural.text.replacen("[filesystem]\n", "", 1)
    );
    fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

fn sandy_as(natural: &Natural, args: &[String]) -> Output {
    let mut command = match natural.wrapper.split_first() {
        Some((program, rest)) => {
            let mut command = Command::new(program);
            command.args(rest).arg(sandy_path());
            command
        }
        None => Command::new(sandy_path()),
    };
    command.args(args).output().unwrap()
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| arg.to_string()).collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `check` plans the base, finds it unenforceable, plans the next level, and names the level
/// that runs; its JSON form says the same.
#[test]
fn check_takes_the_first_level_this_host_enforces() {
    let Some(natural) = natural() else { return };
    let fixture = Fixture::new("levels-check");
    let policy = policy(&fixture, &natural);
    let output = sandy_as(
        &natural,
        &strings(&["check", "--policy", &policy, "--", &probe_path()]),
    );
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    let base = lines.iter().position(|line| *line == "[base]").unwrap();
    let weaker = lines.iter().position(|line| *line == "[weaker]").unwrap();
    assert!(
        lines[base..weaker]
            .iter()
            .any(|line| line.starts_with("UNAVAILABLE")),
        "{stdout}"
    );
    assert!(
        !lines[weaker..]
            .iter()
            .any(|line| line.starts_with("UNAVAILABLE")),
        "{stdout}"
    );
    assert_eq!(lines.last(), Some(&"level: weaker"), "{stdout}");

    let output = sandy_as(
        &natural,
        &strings(&["check", "--json", "--policy", &policy, "--", &probe_path()]),
    );
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    for part in [
        "\"selected\":\"weaker\"",
        "\"setup_would_help\":false",
        "{\"name\":\"base\",\"enforceable\":false,\"needs_setup\":false,",
        "{\"name\":\"weaker\",\"enforceable\":true,\"needs_setup\":false,",
        "\"missing\":[{\"requirement\":\"",
    ] {
        assert!(stdout.contains(part), "{part}: {stdout}");
    }
    assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
}

/// `run` takes the same level, warns that it runs a fallback level and why, and writes the
/// level to the status record before the program's process ID.
#[test]
fn run_takes_the_first_level_this_host_enforces() {
    let Some(natural) = natural() else { return };
    let fixture = Fixture::new("levels-run");
    let policy = policy(&fixture, &natural);
    let args = strings(&[
        "run",
        "--policy",
        &policy,
        "--",
        &probe_path(),
        "read",
        &fixture.arg("ro/file"),
    ]);
    let output = sandy_as(&natural, &args);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    parse(&output)[0].assert_ok();
    assert!(
        stderr.starts_with(
            "warning: running fallback level weaker: this host cannot enforce level base ("
        ),
        "{stderr}"
    );

    #[cfg(unix)]
    let (output, record) = sandy_with_status_under(&natural.wrapper, &args);
    #[cfg(windows)]
    let (output, record) = sandy_with_status(&args);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let lines: Vec<&str> = record.lines().collect();
    assert_eq!(lines.first(), Some(&"level weaker"), "{record}");
    assert!(lines[1].starts_with("pid "), "{record}");
}

/// `--level` pins one level: the base this host cannot enforce is refused rather than replaced,
/// and the level that it can enforce runs without the warning.
#[test]
fn a_pinned_level_is_never_replaced() {
    let Some(natural) = natural() else { return };
    let fixture = Fixture::new("levels-pinned");
    let policy = policy(&fixture, &natural);
    let probe = probe_path();
    let read = fixture.arg("ro/file");

    let output = sandy_as(
        &natural,
        &strings(&[
            "check", "--policy", &policy, "--level", "base", "--", &probe,
        ]),
    );
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(NOT_ENFORCEABLE), "{stdout}");
    assert!(!stdout.contains("[weaker]"), "{stdout}");
    assert_eq!(stdout.lines().last(), Some("level: none"), "{stdout}");

    let output = sandy_as(
        &natural,
        &strings(&[
            "run", "--policy", &policy, "--level", "base", "--", &probe, "read", &read,
        ]),
    );
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stderr}");
    assert!(
        stderr.contains("enforces no level of the policy"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "the program ran: {output:?}");

    let output = sandy_as(
        &natural,
        &strings(&[
            "run", "--policy", &policy, "--level", "weaker", "--", &probe, "read", &read,
        ]),
    );
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    parse(&output)[0].assert_ok();
}

/// The parent options belong to the policy, not to the level that runs: a caller that runs
/// `check` with `--parent-pid` and then `run --level` with the level `check` named, as the
/// README recommends, passes the same options to both, also for a level that does not end with
/// its parent, which then ignores them.
#[test]
fn a_pinned_level_takes_the_parent_options_of_the_policy() {
    let fixture = Fixture::new("levels-parent");
    #[cfg(windows)]
    let (base_name, level_name) = (
        format!(
            "[windows]\nappcontainer_name = \"{}\"\n",
            appcontainer_name()
        ),
        format!(
            "windows.appcontainer_name = \"{}\"\n",
            level_appcontainer_name()
        ),
    );
    #[cfg(unix)]
    let (base_name, level_name) = (String::new(), String::new());
    let natural = Natural {
        text: format!(
            "[process]\nsignals = \"isolated\"\nend_with_parent = true\n{base_name}\
             [[fallback]]\nname = \"weaker\"\nprocess.signals = \"any\"\n\
             process.end_with_parent = false\n{level_name}"
        ),
        wrapper: Vec::new(),
    };
    let policy = policy(&fixture, &natural);
    let probe = probe_path();
    let parent = std::process::id().to_string();

    let output = sandy_as(
        &natural,
        &strings(&[
            "check",
            "--policy",
            &policy,
            "--level",
            "weaker",
            "--parent-pid",
            &parent,
            "--",
            &probe,
        ]),
    );
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    assert_eq!(stdout.lines().last(), Some("level: weaker"), "{stdout}");

    let output = sandy_as(
        &natural,
        &strings(&[
            "run",
            "--policy",
            &policy,
            "--level",
            "weaker",
            "--parent-pid",
            &parent,
            "--",
            &probe,
            "read",
            &fixture.arg("ro/file"),
        ]),
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    parse(&output)[0].assert_ok();
}

/// A policy without levels reads and reports as a plain policy: no level lines, no level in the
/// status record.
#[test]
fn a_policy_without_levels_has_no_level_lines() {
    let fixture = Fixture::new("levels-none");
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    args.extend(fixture.access_args());
    let output = sandy(&args);
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.starts_with("backend: "), "{stdout}");
    assert!(
        stdout
            .lines()
            .skip(1)
            .all(|line| line.starts_with("enforced ")),
        "{stdout}"
    );

    let (output, record) = sandy_with_status(&run_args(&fixture.access_args(), &[("exit", "0")]));
    assert!(output.status.success(), "{output:?}");
    assert!(record.starts_with("pid "), "{record}");
}

/// What a policy with levels refuses: an option that sets a key a level sets, a level name it
/// does not have, and a check without the program, whose loader and interpreter run decides
/// with.
#[test]
fn levels_refuse_what_would_be_unclear() {
    let Some(natural) = natural() else { return };
    let fixture = Fixture::new("levels-refusals");
    let policy = policy(&fixture, &natural);
    let probe = probe_path();
    let option = if cfg!(target_os = "linux") {
        ["--signals", "isolated"]
    } else {
        ["--view", "policy"]
    };
    for (args, message) in [
        (
            strings(&[
                "check", "--policy", &policy, option[0], option[1], "--", &probe,
            ]),
            "which fallback level weaker of the policy sets too",
        ),
        (
            strings(&[
                "check", "--policy", &policy, "--level", "other", "--", &probe,
            ]),
            "the policy has no level \"other\"; its levels are base, weaker",
        ),
        (
            strings(&["check", "--policy", &policy]),
            "needs the PROGRAM",
        ),
    ] {
        let output = sandy_as(&natural, &args);
        let stderr = text(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(EXIT_FAILURE),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
}

/// Runs sandy with `input` on its standard input.
fn sandy_input(args: &[String], input: &[u8]) -> Output {
    let mut child = Command::new(sandy_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // sandy may refuse before it reads everything; a broken pipe then says nothing here.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

/// `--policy -` reads the policy from standard input, and the program reads the null device
/// there instead of what the caller wrote. The control gives the same line to the program
/// with the policy in a file.
#[test]
fn a_policy_on_standard_input_leaves_none_for_the_program() {
    let fixture = Fixture::new("levels-input");
    let text_of_policy = format!(
        "version = 1\n[filesystem]\nread = [{:?}]\n",
        fixture.arg("ro")
    );
    let mut args = vec!["run".to_string(), "--policy".into(), "-".into()];
    args.extend(platform_args());
    args.extend(strings(&["--", &probe_path(), "read-line", "-", "read"]));
    args.push(fixture.arg("ro/file"));
    let mut input = text_of_policy.clone().into_bytes();
    let output = sandy_input(&args, &input);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let lines = parse(&output);
    lines[0].assert_ok();
    assert_eq!(lines[0].detail, "", "{lines:?}");
    // The policy took effect: its read path is readable.
    lines[1].assert_ok();

    let file = fixture.path("policy.toml");
    fs::write(&file, &text_of_policy).unwrap();
    let position = args.iter().position(|arg| arg == "-").unwrap();
    let mut from_file = args.clone();
    from_file[position] = file.to_str().unwrap().to_string();
    let output = sandy_input(&from_file, b"from the caller\n");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(parse(&output)[0].detail, "from the caller");

    // Longer than 1 MiB, or not UTF-8: refused before anything runs.
    input.resize(1024 * 1024 + 1, b'\n');
    for bad in [input, b"version = 1\n# \xff\n".to_vec()] {
        let output = sandy_input(&args, &bad);
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        assert!(output.stdout.is_empty(), "the program ran: {output:?}");
    }
}

/// `check --policy -` reads the policy the same way.
#[test]
fn check_reads_the_policy_from_standard_input() {
    let mut args = strings(&["check", "--policy", "-"]);
    args.extend(platform_args());
    let output = sandy_input(&args, b"version = 1\n[network]\nip = \"none\"\n");
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    assert!(stdout.contains("IP networking denied"), "{stdout}");
    let output = sandy_input(&args, b"version = 1\n[network]\nip = \"some\"\n");
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

/// A terminal stays readable after the end of input the caller types (^D), so reading to the end
/// is not enough: sandy replaces standard input with the null device, and the program does not
/// read the line the caller typed after the policy. Without the replacement it would.
#[cfg(unix)]
#[test]
fn the_program_never_reads_the_callers_terminal_after_the_policy() {
    use std::io::Write;
    use std::os::fd::AsFd;

    let Some(pty) = unix::open_pty() else {
        return skip("pty", "cannot open a pseudo-terminal");
    };
    let mut args = strings(&[
        "run",
        "--policy",
        "-",
        "--",
        &probe_path(),
        "read-line",
        "-",
    ]);
    args.splice(1..1, platform_args());
    let child = Command::new(sandy_path())
        .args(&args)
        .stdin(Stdio::from(pty.slave.as_fd().try_clone_to_owned().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(pty.slave);
    let mut master = fs::File::from(pty.master);
    // ^D at the start of a line ends the input for one read, and the next line waits for the
    // next reader.
    master
        .write_all(b"version = 1\n\x04typed after the policy\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let lines = parse(&output);
    lines[0].assert_ok();
    assert_eq!(lines[0].detail, "", "the program read the caller's input");
}

/// The downgrade that levels must never allow: a process limit at its end, which any process of
/// the user counts against, leaves the trial of the namespaces no fork. The base with a private
/// network is then undecided, not unavailable, so `check` and `run` fail with status 125 instead
/// of taking the level with the host's network. Control: without the limit the base runs.
#[cfg(target_os = "linux")]
#[test]
fn a_passing_failure_never_selects_a_weaker_level() {
    use std::os::unix::process::CommandExt;

    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        return skip("unprivileged", "root has no process limit");
    }
    let fixture = Fixture::new("levels-limit");
    let policy = fixture.path("policy.toml");
    fs::write(
        &policy,
        "version = 1\n[network]\nip = \"private\"\n\
         [[fallback]]\nname = \"host-network\"\nnetwork.ip = \"all\"\n",
    )
    .unwrap();
    let policy = policy.to_str().unwrap().to_string();
    let probe = probe_path();
    let check = strings(&["check", "--policy", &policy, "--", &probe]);
    let run = strings(&["run", "--policy", &policy, "--", &probe, "exit", "0"]);
    let output = sandy(&check);
    if !text(&output.stdout).ends_with("level: base\n") {
        return skip(
            "user-namespaces",
            &format!("the base does not run here: {}", text(&output.stdout)),
        );
    }
    let ran = sandy(&run);
    assert!(ran.status.success(), "{}", text(&ran.stderr));
    assert!(ran.stderr.is_empty(), "{}", text(&ran.stderr));

    let limited = |args: &[String]| {
        let mut command = Command::new(sandy_path());
        command.args(args);
        // SAFETY: setrlimit is async-signal-safe, and the closure calls nothing else.
        unsafe {
            command.pre_exec(|| {
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                match libc::setrlimit(libc::RLIMIT_NPROC, &none) {
                    0 => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                }
            });
        }
        command.output().unwrap()
    };
    let output = limited(&check);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stdout}");
    assert!(!stdout.contains("[host-network]"), "{stdout}");
    assert!(!stdout.contains("level: "), "{stdout}");
    assert!(
        text(&output.stderr).contains("level base: sandy cannot tell now"),
        "{}",
        text(&output.stderr)
    );
    let output = limited(&run);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{stderr}");
    assert!(!stderr.contains("running fallback level"), "{stderr}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
