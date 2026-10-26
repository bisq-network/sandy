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

/// Whether this host can isolate signals, which `contained` and `end_with_parent` need (Landlock
/// ABI 6). Records the skip when it cannot.
fn isolates_signals() -> bool {
    if common::linux::landlock_abi() >= 6 {
        return true;
    }
    skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    false
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

/// The mode names only what Landlock denies. A file that does not exist is missing with every
/// grant, Landlock does not check an `O_PATH` open or the pipe that `/dev/stdin` leads to, and
/// removing a symbolic link removes the link in its own directory, wherever it points. Naming
/// those would advise grants that change nothing, one of them on the link's target. The denied
/// read of an existing file in the same run is the control that the mode reports at all.
#[test]
fn the_mode_names_only_what_landlock_denies() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let fixture = Fixture::new("explain-accurate");
    let (secret, missing) = (fixture.arg("secret/file"), fixture.arg("secret/missing"));
    let target = fixture.path("secret/target");
    std::fs::write(&target, b"x").unwrap();
    let link = fixture.path("rw/link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (target, link) = (
        target.to_str().unwrap().to_string(),
        link.to_str().unwrap().to_string(),
    );
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let stdin = "/dev/stdin".to_string();
    let actions = [
        ("read-optional", missing.as_str()),
        ("opath-read", target.as_str()),
        ("delete", link.as_str()),
        ("read", stdin.as_str()),
        ("read-optional", secret.as_str()),
    ];
    let mut child = Command::new(sandy_path())
        .args(run_args(&with_mode, &actions))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let results = parse(&output);
    assert_eq!(
        results[2].result, "ok",
        "the link was not removed: {results:?}"
    );
    results[3].assert_ok();
    let lines = explained(&output);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("cannot read {secret}:"))),
        "the denied read is not named: {lines:?}"
    );
    for path in [&missing, &target, &link, &stdin] {
        assert!(
            !lines.iter().any(|line| line.contains(path.as_str())),
            "{path} is named although Landlock did not deny it: {lines:?}"
        );
    }
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

/// With `contained`, the supervising sandy is undumpable from before it forks the program, and
/// the program makes itself dumpable again, because the watcher reads the path of its execve out
/// of its memory: no watched path may be unreadable.
#[test]
fn the_mode_works_while_sandy_contains_the_children() {
    if !isolates_signals() {
        return;
    }
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
    let summary = lines.last().expect("a summary");
    assert!(!summary.contains("could not be read"), "{lines:?}");
}

/// sandy stays the program's parent in this mode. Like the supervisor of `contained`, it is
/// undumpable from before the fork, so a program with a write grant on `/proc` cannot raise its
/// out-of-memory priority and have the kernel end it first, while the program may raise its own
/// (the control). The program's paths stay readable for the watcher.
#[test]
fn the_program_cannot_raise_the_oom_priority_of_sandy() {
    let fixture = Fixture::new("explain-oom");
    let mut with_mode = fixture.access_args();
    with_mode.extend(args(&["--explain", "--read-write", "/proc"]));
    let output = run(
        &with_mode,
        &[("oom-raise", "self"), ("oom-raise", "parent")],
    );
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    lines[0].assert_ok();
    lines[1].assert_blocked();
    let explained = explained(&output);
    let summary = explained.last().expect("a summary");
    assert!(!summary.contains("could not be read"), "{explained:?}");
}

/// sandy stays the program's parent in this mode, so it cannot pass on the signals that
/// `end_with_parent` sends it. The combination is refused instead of ending the program late.
#[test]
fn the_mode_is_refused_with_end_with_parent() {
    if !isolates_signals() {
        return;
    }
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

/// sandy stays the program's parent in the mode, as with `contained`, and must not keep what its
/// caller left open while the program runs: a socket the caller leaked into sandy would keep its
/// port busy. The control is the poll itself: the program still runs when the descriptor closes.
#[test]
fn sandy_closes_what_it_inherited_while_the_program_runs() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    const INHERITED: libc::c_int = 47;
    let fixture = Fixture::new("explain-closes");
    let mut sandbox_args = fixture.access_args();
    sandbox_args.push("--explain".to_string());
    let (read, write) = std::io::pipe().unwrap();
    let write_fd = write.as_raw_fd();
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&sandbox_args, &[("read-line", "-")]))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: dup2 is async-signal-safe; it makes the write end descriptor `INHERITED` of sandy,
    // without close-on-exec.
    unsafe {
        command.pre_exec(move || match libc::dup2(write_fd, INHERITED) {
            INHERITED => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        });
    }
    let mut sandy = command.spawn().unwrap();
    drop(write);
    let mut poll = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polls one open descriptor for at most ten seconds.
    let ready = unsafe { libc::poll(&mut poll, 1, 10_000) };
    let running = sandy.try_wait().unwrap().is_none();
    drop(sandy.stdin.take());
    let status = sandy.wait().unwrap();
    assert!(
        ready == 1 && poll.revents & libc::POLLHUP != 0,
        "sandy kept the descriptor it inherited (poll {ready}, events {:#x})",
        poll.revents
    );
    assert!(running, "sandy ended before the check: {status:?}");
    assert!(status.success(), "{status:?}");
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

/// Ctrl+C reaches the program and sandy alike, because both are in the terminal's foreground
/// group. sandy must stay until the program has ended: a program that goes on after Ctrl+C, as
/// one that cleans up does, would otherwise lose its watcher halfway, and every watched call it
/// makes from then on would fail with ENOSYS. The program here ignores the signal and writes a
/// file afterwards; sandy must report its exit status and the closing line, not die of SIGINT.
#[test]
fn ctrl_c_does_not_take_the_watcher_from_the_program() {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};

    let fixture = Fixture::new("explain-ctrl-c");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let after = fixture.arg("rw/after");
    let actions = [
        ("ignore-signal", "2"),
        ("sleep", "300"),
        ("write", after.as_str()),
    ];
    let mut child = Command::new(sandy_path())
        .args(run_args(&with_mode, &actions))
        // A group of their own, as a shell gives a job, so the signal reaches only these two.
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    parse_line(first.trim_end()).assert_ok();
    // What the terminal does on Ctrl+C.
    // SAFETY: kill takes a process group ID; the group is the one created above.
    assert_eq!(unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) }, 0);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();

    let lines: Vec<ProbeLine> = rest.lines().map(parse_line).collect();
    assert_eq!(lines.len(), 2, "{rest}");
    lines[1].assert_ok();
    assert_eq!(
        status.signal(),
        None,
        "sandy died of a signal before the program ended: {stderr}"
    );
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("watched calls"),
        "no closing line: {stderr}"
    );
}

/// sandy stays the program's parent in this mode, so a caller that signals sandy's process ID
/// must still reach the program, as it does in the exec model: sandy passes the signal on and
/// reports how the program ended. The program exits with 42 when SIGTERM arrives.
#[test]
fn a_signal_sent_to_sandy_reaches_the_program() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    let fixture = Fixture::new("explain-sigterm");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let mut child = Command::new(sandy_path())
        .args(run_args(&with_mode, &[("await-signal", "15")]))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The probe says when its handler is in place; the report of the mode comes on the same
    // stream.
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while line.trim_end() != "await-signal ready" {
        line.clear();
        assert_ne!(
            stderr.read_line(&mut line).unwrap(),
            0,
            "the program did not start"
        );
    }
    std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
    // To sandy's process ID alone, as a caller that holds sandy's handle sends it.
    // SAFETY: kill takes a process ID and a signal; the test started the process.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let status = child.wait().unwrap();
    assert_eq!(
        status.signal(),
        None,
        "sandy died of the signal: {status:?}"
    );
    assert_eq!(
        status.code(),
        Some(42),
        "the program did not get it: {status:?}"
    );
}

/// A caller that ignores SIGCHLD passes that on to sandy, and the kernel then reaps sandy's
/// children by itself, so sandy could not learn how the program ended.
#[test]
fn the_program_keeps_its_exit_status_when_the_caller_ignores_sigchld() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let fixture = Fixture::new("explain-sigchld");
    let mut with_mode = fixture.access_args();
    with_mode.push("--explain".to_string());
    let mut command = Command::new(sandy_path());
    command.args(run_args(&with_mode, &[("exit", "7")]));
    // SAFETY: signal is async-signal-safe and the closure calls nothing else.
    unsafe {
        command.pre_exec(|| match libc::signal(libc::SIGCHLD, libc::SIG_IGN) {
            libc::SIG_ERR => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
}

/// The watcher thread confines itself with a seccomp filter of its own, because it parses bytes
/// the program controls outside the sandbox, and sandy's main thread, which forwards signals and
/// waits for the program, has none (docs/linux.md, "Diagnostic mode"). The kernel shows the mode
/// of every thread in its status file: 2 for a filter.
#[test]
fn the_watcher_thread_confines_itself() {
    let mut sandy = std::process::Command::new(sandy_path())
        .args(run_args(&args(&["--explain"]), &[("sleep", "3000")]))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let modes = || -> Vec<String> {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{}/task", sandy.id())) else {
            return Vec::new();
        };
        tasks
            .flatten()
            .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
            .filter_map(|status| {
                let line = status.lines().find(|line| line.starts_with("Seccomp:"))?;
                Some(line.trim_start_matches("Seccomp:").trim().to_string())
            })
            .collect()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut seen = modes();
    while seen.iter().filter(|mode| *mode == "2").count() != 1
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(20));
        seen = modes();
    }
    kill_process(sandy.id());
    let _ = sandy.wait();
    assert_eq!(seen.len(), 2, "sandy and its watcher: {seen:?}");
    assert!(seen.contains(&"0".to_string()), "{seen:?}");
    assert!(seen.contains(&"2".to_string()), "{seen:?}");
}
