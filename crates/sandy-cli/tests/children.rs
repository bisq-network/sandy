//! `process.children`: with `none` the program cannot start processes, and with `contained`
//! every process it started ends when it ends.

mod common;

use std::time::Instant;

use common::*;

/// How long the processes the program starts would run on their own, in milliseconds: much
/// longer than the test.
const LONG_SLEEP: &str = "60000";

#[test]
fn children_none_denies_starting_programs() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("children");
    let program = fixture.copy_probe("bin");

    // Control: the same policy without the option starts the program.
    let lines = probe_inside(&fixture.access_args(), &[("exec", &program)]);
    lines[0].assert_ok();

    let mut args = fixture.access_args();
    args.extend(["--children".to_string(), "none".to_string()]);
    let lines = probe_inside(&args, &[("exec", &program)]);
    lines[0].assert_blocked();
}

/// Options for `children = "contained"`, which needs isolated signals.
fn contained(fixture: &Fixture) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend(["--children", "contained", "--signals", "isolated"].map(String::from));
    args
}

/// The probe action that starts a process without waiting for it. On macOS, `contained` denies
/// posix_spawn, which std's Command uses, so the probe forks there.
const START: &str = if cfg!(target_os = "macos") {
    "start-forked"
} else {
    "start"
};

/// Why this host cannot run `children = "contained"`, if it cannot.
fn unsupported() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    if common::linux::landlock_abi() < 6 {
        return Some("signal isolation needs Landlock ABI 6");
    }
    None
}

#[test]
fn children_contained_ends_what_the_program_leaves_behind() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("contained");
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    if let Some(reason) = unsupported() {
        let output = sandy(run_args(&contained(&fixture), &[(START, &start)]));
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        skip("landlock-abi-6", &format!("{reason}; sandy refused"));
        return;
    }

    // Control: without containment the process outlives the program. Windows ends the processes
    // of the program's job in any case.
    #[cfg(unix)]
    {
        let lines = probe_inside(&fixture.access_args(), &[(START, &start)]);
        lines[0].assert_ok();
        let pid: u32 = lines[0].detail.parse().unwrap();
        let survived = is_running(pid);
        kill_process(pid);
        assert!(survived, "control: process {pid} ended with the program");
    }

    let started = Instant::now();
    let lines = probe_inside(&contained(&fixture), &[(START, &start)]);
    // sandy ends the process; it does not wait until the process ends by itself.
    assert!(
        started.elapsed() < END_TIMEOUT,
        "sandy returned only after {:?}",
        started.elapsed()
    );
    lines[0].assert_ok();
    let pid: u32 = lines[0].detail.parse().unwrap();
    assert!(
        ends_soon(pid, END_TIMEOUT),
        "process {pid} outlived the program"
    );
}

#[test]
fn children_contained_needs_isolated_signals() {
    let fixture = Fixture::new("contained-signals");
    let mut args = contained(&fixture);
    args.truncate(args.len() - 2);
    let output = sandy(run_args(&args, &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signals = \"isolated\""), "{stderr}");
}

/// Tests of `contained` that need Unix process groups and signals.
#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::{LONG_SLEEP, contained, unsupported};
    use crate::common::unix::{group_alive, group_ended, kill_group, live_members};
    use crate::common::*;

    /// How many processes `fork-walk` keeps forking.
    const WALKERS: &str = "4";

    /// Reads one probe line from `reader` and returns its detail field.
    fn detail(reader: &mut impl BufRead) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.trim_end()
            .split('\t')
            .nth(3)
            .unwrap_or_default()
            .to_string()
    }

    fn signal(child: &Child, signal: libc::c_int) {
        // SAFETY: kill takes a process ID and a signal; the test started the process.
        unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    }

    /// Whether no live process is left in `group` within `timeout`.
    fn group_ends(group: libc::pid_t, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if group_ended(group) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        group_ended(group)
    }

    /// Starts sandy with `actions`, the first of which is `fork-walk`, and returns sandy and the
    /// program's process group, which the probe reports.
    fn start_walkers(fixture: &Fixture, after: (&str, &str)) -> (Child, libc::pid_t) {
        let actions = [("fork-walk", WALKERS), after];
        let mut sandy = Command::new(sandy_path())
            .args(run_args(&contained(fixture), &actions))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
        let group: libc::pid_t = detail(&mut stdout).parse().unwrap();
        // The rest of the output is not needed; the program must not block on a full pipe.
        std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
        (sandy, group)
    }

    /// A program can keep starting processes, so that one of them is inside fork at almost every
    /// moment. On macOS such a process can escape one SIGKILL to the group, so whoever ends the
    /// group repeats it. When sandy is killed, the guard alone ends the group.
    #[test]
    fn processes_that_keep_forking_end_when_sandy_is_killed() {
        let fixture = Fixture::new("contained-walk-kill");
        if unsupported().is_some() {
            return;
        }
        // Control: outside the sandbox the processes outlive the probe that started them.
        let output = Command::new(probe_path())
            .args(probe_args(&[("fork-walk", WALKERS)]))
            .process_group(0)
            .output()
            .unwrap();
        let lines = parse(&output);
        lines[0].assert_ok();
        let group: libc::pid_t = lines[0].detail.parse().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let survived = group_alive(group);
        kill_group(group);
        assert!(survived, "control: the processes ended with the probe");

        let (mut sandy, group) = start_walkers(&fixture, ("sleep", LONG_SLEEP));
        std::thread::sleep(Duration::from_millis(500));
        // The program still sleeps, so only the guard can end the group.
        sandy.kill().unwrap();
        sandy.wait().unwrap();
        let ended = group_ends(group, END_TIMEOUT);
        let left = live_members(group);
        kill_group(group);
        assert!(
            ended,
            "processes {left:?} of the program's group outlived sandy"
        );
    }

    /// While sandy is stopped, the guard still ends the group when the program exits.
    #[test]
    fn processes_that_keep_forking_end_while_sandy_is_stopped() {
        let fixture = Fixture::new("contained-walk-stop");
        if unsupported().is_some() {
            return;
        }
        let (mut sandy, group) = start_walkers(&fixture, ("sleep", "500"));
        signal(&sandy, libc::SIGSTOP);
        // The program exits after half a second; the guard ends the group then.
        let ended = group_ends(group, END_TIMEOUT);
        let left = live_members(group);
        signal(&sandy, libc::SIGCONT);
        let _ = sandy.wait();
        kill_group(group);
        assert!(
            ended,
            "processes {left:?} outlived the program while sandy was stopped"
        );
    }

    /// The relay of an exposed port ends at most a second after the program (rule 5 of
    /// "Forwarded ports"), also while the supervising sandy is stopped and does not end.
    #[test]
    fn the_relay_ends_with_the_program_while_sandy_is_stopped() {
        let fixture = Fixture::new("contained-relay-stop");
        if unsupported().is_some() {
            return;
        }
        let port = |_| {
            TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let (outer, inner) = (port(0), port(1));
        let mut args = contained(&fixture);
        args.extend([
            "--ip".to_string(),
            "all".to_string(),
            "--expose".to_string(),
            format!("127.0.0.1:{outer}={inner}"),
        ]);
        // The program reports that it runs, then sleeps for a second and exits.
        let file = fixture.arg("ro/file");
        let mut sandy = Command::new(sandy_path())
            .args(run_args(&args, &[("read", &file), ("sleep", "1000")]))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // The listen port is reachable as soon as sandy binds it, which is before it forks the
        // relay, the guard and the program. Only the program's own report says that there is a
        // program to end with; stopping sandy before its fork would leave none.
        let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        parse_line(line.trim_end()).assert_ok();
        let address = format!("127.0.0.1:{outer}").parse().unwrap();
        let reachable = || TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok();
        assert!(reachable(), "the relay never listened");
        signal(&sandy, libc::SIGSTOP);
        // The program exits after a second, the relay at most a second later.
        let deadline = Instant::now() + END_TIMEOUT;
        while reachable() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let still = reachable();
        signal(&sandy, libc::SIGCONT);
        let _ = sandy.wait();
        assert!(
            !still,
            "the relay outlived the program while sandy was stopped"
        );
    }

    /// sandy forwards signals to the program, also those that sandy's caller ignores and those
    /// that are ignored by default (SIGIO), which macOS would discard while they are blocked.
    /// The program installs its own handler and exits with 42 when the signal arrives.
    #[test]
    fn ignored_signals_reach_the_program() {
        let fixture = Fixture::new("contained-ignored-signals");
        if unsupported().is_some() {
            return;
        }
        for (signal_number, caller_ignores) in [
            (libc::SIGINT, true),
            (libc::SIGHUP, true),
            (libc::SIGIO, false),
            (libc::SIGUSR1, false),
        ] {
            let target = signal_number.to_string();
            let mut command = Command::new(sandy_path());
            command
                .args(run_args(&contained(&fixture), &[("await-signal", &target)]))
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            if caller_ignores {
                // SAFETY: signal(2) is async-signal-safe, so it may run between fork and exec.
                unsafe {
                    command.pre_exec(move || {
                        libc::signal(signal_number, libc::SIG_IGN);
                        Ok(())
                    });
                }
            }
            let mut sandy = command.spawn().unwrap();
            // Before the program's handler is in place the signal would end sandy or the
            // program, so wait for the probe's report.
            let mut stderr = BufReader::new(sandy.stderr.take().unwrap());
            let mut line = String::new();
            stderr.read_line(&mut line).unwrap();
            assert_eq!(
                line.trim_end(),
                "await-signal ready",
                "the program did not start"
            );
            signal(&sandy, signal_number);
            let deadline = Instant::now() + END_TIMEOUT;
            let status = loop {
                if let Some(status) = sandy.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() > deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            if status.is_none() {
                let _ = sandy.kill();
                let _ = sandy.wait();
            }
            assert_eq!(
                status.and_then(|status| status.code()),
                Some(42),
                "signal {signal_number} (ignored by the caller: {caller_ignores})"
            );
        }
    }
}
