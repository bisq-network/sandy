//! Linux-specific escape tests. Like `escape.rs`, each denial is checked against a control run
//! outside the sandbox. Behavior that depends on the Landlock ABI is checked against the ABI
//! the kernel reports, so the tests pass on every kernel that sandy supports.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::linux::*;
use common::unix::*;
use common::*;

/// What `check` returns when this host cannot enforce a requirement of the policy.
const EXIT_NOT_ENFORCEABLE: i32 = 1;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// Runs the probe outside the sandbox with `configure` applied to the command.
fn probe_outside_with(actions: &[(&str, &str)], configure: impl Fn(&mut Command)) -> Output {
    let mut command = Command::new(probe_path());
    command.args(probe_args(actions));
    configure(&mut command);
    command.output().unwrap()
}

/// Runs the probe in the sandbox with `configure` applied to the sandy command.
fn probe_inside_with(
    sandbox_args: &[String],
    actions: &[(&str, &str)],
    configure: impl Fn(&mut Command),
) -> Vec<ProbeLine> {
    let mut command = Command::new(sandy_path());
    command.args(run_args(sandbox_args, actions));
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "sandy run failed: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "probe output: {lines:?}");
    lines
}

fn parent_pid() -> String {
    // sandy replaces itself with the probe, so the probe's parent is this test process.
    std::process::id().to_string()
}

#[test]
fn session_bus_is_unreachable() {
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let socket = address
        .split(';')
        .find_map(|entry| entry.strip_prefix("unix:path="))
        .map(|path| path.split(',').next().unwrap_or(path).to_string())
        .unwrap_or_else(|| format!("/run/user/{uid}/bus"));
    if !Path::new(&socket).exists() {
        return skip("session-bus", &format!("no socket at {socket}"));
    }
    let directory = Path::new(&socket).parent().unwrap().to_str().unwrap();
    // Reading the socket's directory is allowed, so only the socket rules stop the connection.
    let readable = args(&["--read", directory]);
    let lines = controlled(&readable, &[("unix-connect", &socket)]);
    lines[0].assert_blocked();

    let mut all = readable.clone();
    all.extend(args(&["--unix-sockets", "all"]));
    probe_inside(&all, &[("unix-connect", &socket)])[0].assert_ok();
}

#[test]
fn abstract_unix_socket_is_unreachable() {
    let name = format!("sandy-escape-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let _listener = UnixListener::bind_addr(&address).unwrap();
    let lines = controlled(&[], &[("unix-connect-abstract", &name)]);
    lines[0].assert_blocked();
    let all = args(&["--unix-sockets", "all"]);
    probe_inside(&all, &[("unix-connect-abstract", &name)])[0].assert_ok();
}

#[test]
fn datagram_socket_pairs_are_denied() {
    let actions = [
        ("socketpair", "stream"),
        ("socketpair", "seqpacket"),
        ("socketpair", "dgram"),
    ];
    let lines = controlled(&[], &actions);
    lines[0].assert_ok();
    lines[1].assert_ok();
    lines[2].assert_blocked();
    let all = args(&["--unix-sockets", "all"]);
    probe_inside(&all, &actions[2..])[0].assert_ok();
}

#[test]
fn only_route_netlink_is_available_with_ip() {
    let ip = args(&["--ip", "all"]);
    let lines = controlled(&ip, &[("socket", "netlink-route"), ("socket", "inet6")]);
    lines[0].assert_ok();
    lines[1].assert_ok();
    for family in ["netlink-sock-diag", "vsock", "alg"] {
        let control = probe_outside(&[("socket", family)]);
        if control[0].result != "ok" {
            skip(
                "socket-family",
                &format!("socket {family} fails outside: {}", control[0].detail),
            );
            continue;
        }
        probe_inside(&ip, &[("socket", family)])[0].assert_blocked();
    }
    let lines = probe_inside(&[], &[("socket", "netlink-route"), ("socket", "inet")]);
    lines[0].assert_blocked();
    lines[1].assert_blocked();
}

/// A denied family fails with `EAFNOSUPPORT`, as on a kernel that does not have it, so that a
/// program which probes for a family falls back instead of treating the failure as fatal.
#[test]
fn denied_socket_families_look_unsupported() {
    let unsupported = "os error 97";
    let lines = controlled(&args(&["--ip", "all"]), &[("socket", "unix")]);
    assert!(lines[0].detail.contains(unsupported), "{lines:?}");
    let lines = controlled(&[], &[("socket", "inet"), ("socket", "unix")]);
    for line in lines {
        assert!(line.detail.contains(unsupported), "{line:?}");
    }
}

/// Yama's ptrace_scope. From 1 up it limits ptrace and `/proc/<pid>/mem` to descendants, also
/// outside the sandbox. `None` when Yama is not active.
fn yama_ptrace_scope() -> Option<u32> {
    let scope = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok()?;
    scope.trim().parse().ok()
}

#[test]
fn parent_memory_and_environment_are_unreadable() {
    let parent = parent_pid();
    let (mem, environ) = (
        format!("/proc/{parent}/mem"),
        format!("/proc/{parent}/environ"),
    );
    let candidates = [("open", mem.as_str()), ("read", environ.as_str())];
    // A control run that Yama blocks shows nothing about the sandbox, so that action is skipped.
    // Any other control failure fails the test.
    let mut actions = Vec::new();
    for (action, control) in candidates.iter().zip(probe_outside(&candidates)) {
        if control.result == "ok" {
            actions.push(*action);
        } else if control.result == "denied" && yama_ptrace_scope().is_some_and(|scope| scope >= 1)
        {
            skip(
                "ptrace",
                &format!(
                    "{} {}: Yama ptrace_scope blocks it outside the sandbox",
                    control.action, control.target
                ),
            );
        } else {
            control.assert_ok();
        }
    }
    actions.push(("read", "/proc/self/status"));
    // With /proc readable, only the process isolation stops these reads.
    let lines = probe_inside(&args(&["--read", "/proc"]), &actions);
    let (status, isolated) = lines.split_last().unwrap();
    status.assert_ok();
    for line in isolated {
        line.assert_blocked();
    }
}

#[test]
fn parent_cannot_be_traced() {
    let parent = parent_pid();
    let control = probe_outside(&[("ptrace-seize", &parent)]);
    if control[0].result != "ok" {
        return skip(
            "ptrace",
            &format!("ptrace fails outside: {}", control[0].detail),
        );
    }
    probe_inside(&[], &[("ptrace-seize", &parent)])[0].assert_blocked();
}

#[test]
fn signals_to_outside_processes_follow_the_policy() {
    let parent = parent_pid();
    let isolated = args(&["--signals", "isolated"]);
    if landlock_abi() < 6 {
        let output = sandy(run_args(&isolated, &[("signal", &parent)]));
        assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
        return skip(
            "landlock-abi-6",
            "signal isolation needs Landlock ABI 6; sandy refused",
        );
    }
    controlled(&isolated, &[("signal", &parent)])[0].assert_blocked();
    probe_inside(&[], &[("signal", &parent)])[0].assert_ok();
}

#[test]
fn terminal_input_injection_is_denied() {
    let Some(pty) = open_pty() else {
        return skip("pty", "no pseudo-terminal available");
    };
    let actions = [("tiocgwinsz", "0"), ("tiocsti", "0")];
    let control = parse(&probe_outside_with(&actions, with_terminal(&pty)));
    control[0].assert_ok();
    // Since Linux 6.2, dev.tty.legacy_tiocsti = 0 makes TIOCSTI fail with EIO for users
    // without CAP_SYS_ADMIN. The seccomp filter fails it with EPERM, which the probe reports
    // as denied, so the two causes stay distinguishable.
    assert_ne!(control[1].result, "denied", "{control:?}");
    let lines = probe_inside_with(&[], &actions, with_terminal(&pty));
    // The terminal was opened before the sandbox, so ordinary terminal ioctls still work.
    lines[0].assert_ok();
    assert_eq!(lines[1].result, "denied", "{lines:?}");
}

/// A lease or a delegation needs only a read descriptor of a file or directory the user owns.
/// While the program held one, a process outside that opens the file for writing, or changes
/// the directory, would wait for up to `/proc/sys/fs/lease-break-time` (45 seconds by default).
#[test]
fn leases_and_delegations_are_denied() {
    let fixture = Fixture::new("linux-lease");
    let (file, dir) = (fixture.arg("ro/file"), fixture.arg("ro"));
    let mut actions = vec![("lease-read", file.as_str())];
    let delegations = [("delegation", file.as_str()), ("delegation", dir.as_str())];
    let control = probe_outside(&delegations[..1]);
    if control[0].result == "ok" {
        actions.extend(delegations);
    } else {
        skip(
            "delegations",
            &format!("no delegations here: {}", control[0].detail),
        );
    }
    for line in controlled(&fixture.access_args(), &actions) {
        assert_eq!(line.result, "denied", "{line:?}");
    }
}

/// A line discipline other than the terminal's own can come from a kernel module that the
/// kernel loads on demand (`dev.tty.ldisc_autoload`). The probe sets the discipline the terminal
/// already has, so the control run loads nothing; the filter denies the request either way.
#[test]
fn the_terminal_line_discipline_cannot_change() {
    let Some(pty) = open_pty() else {
        return skip("pty", "no pseudo-terminal available");
    };
    let actions = [("tiocsetd", "0")];
    parse(&probe_outside_with(&actions, with_terminal(&pty)))[0].assert_ok();
    let lines = probe_inside_with(&[], &actions, with_terminal(&pty));
    assert_eq!(lines[0].result, "denied", "{lines:?}");
}

/// A terminal session like a shell's. A session leader owns a pseudo-terminal and keeps its
/// foreground group, and starts two background jobs, each in a process group of its own: a
/// victim outside the sandbox that only sleeps, and then the job under test, in whose arguments
/// `{job}` stands for the victim's process group. The kernel sends the job control signals of a
/// terminal to a whole process group without the permission check that the Landlock signal scope
/// hooks, so a session of this shape is what shows whether a program can reach another job.
struct JobSession {
    pty: Pty,
    leader: Child,
    victim: u32,
    job: u32,
    /// The probe lines of the jobs; the leader's own `start-job` lines are taken out.
    lines: mpsc::Receiver<ProbeLine>,
    /// Lines of the job that arrived while `start` still waited for a `start-job` line.
    early: Vec<ProbeLine>,
}

impl JobSession {
    /// `None` when the host has no pseudo-terminal.
    fn start(job: &[String]) -> Option<JobSession> {
        let pty = open_pty()?;
        let victim = [probe_path(), "sleep".to_string(), "60000".to_string()];
        let actions = [
            ("start-job", job_target(&victim)),
            ("start-job", job_target(job)),
            ("sleep", "60000".to_string()),
        ];
        let actions: Vec<(&str, &str)> = actions
            .iter()
            .map(|(action, target)| (*action, target.as_str()))
            .collect();
        let mut command = Command::new(probe_path());
        command
            .args(probe_args(&actions))
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        with_terminal(&pty)(&mut command);
        let mut leader = command.spawn().unwrap();
        let output = BufReader::new(leader.stdout.take().unwrap());
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in output.lines().map_while(Result::ok) {
                if sender.send(parse_line(&line)).is_err() {
                    return;
                }
            }
        });
        let mut started = Vec::new();
        let mut early = Vec::new();
        while started.len() < 2 {
            let line = lines.recv_timeout(Duration::from_secs(10)).unwrap();
            // The job can report before the leader reports having started it.
            if line.action == "start-job" {
                line.assert_ok();
                started.push(line.detail.parse().unwrap());
            } else {
                early.push(line);
            }
        }
        Some(JobSession {
            pty,
            leader,
            victim: started[0],
            job: started[1],
            lines,
            early,
        })
    }

    /// The job's probe line, or `None` if the victim stopped or ten seconds passed first.
    fn job_line(&mut self) -> Option<ProbeLine> {
        if !self.early.is_empty() {
            return Some(self.early.remove(0));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !self.victim_stopped() {
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(50)) {
                return Some(line);
            }
        }
        None
    }

    fn victim_stopped(&self) -> bool {
        read_proc(self.victim, "status")
            .is_some_and(|status| status_value(&status, "State").starts_with('T'))
    }

    /// The process group that owns the terminal.
    fn foreground(&self) -> libc::pid_t {
        // SAFETY: tcgetpgrp on the master reads the foreground group of the slave.
        unsafe { libc::tcgetpgrp(self.pty.master.as_raw_fd()) }
    }
}

impl Drop for JobSession {
    fn drop(&mut self) {
        // None of these processes forks, so one signal per group is enough. The leader goes
        // last: its children are reaped once it has ended and they belong to process 1.
        for group in [self.victim, self.job, self.leader.id()] {
            // SAFETY: kill takes a process group ID and a signal.
            unsafe { libc::kill(-(group as libc::pid_t), libc::SIGKILL) };
        }
        let _ = self.leader.kill();
        let _ = self.leader.wait();
    }
}

/// A command line for `start-job`: the program and its arguments, separated by U+001F.
fn job_target(command: &[String]) -> String {
    command.join("\u{1f}")
}

/// The `JobSession` job that runs the probe in the sandbox with isolated signals.
fn isolated_job(actions: &[(&str, &str)]) -> Vec<String> {
    let mut job = vec![sandy_path()];
    job.extend(run_args(&args(&["--signals", "isolated"]), actions));
    job
}

/// A background job that reads the terminal is stopped by the kernel, with every other process
/// of its group. `signals = "isolated"` must therefore keep the program out of the groups of
/// other jobs.
#[test]
fn other_jobs_of_the_terminal_cannot_be_stopped() {
    if landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let join = [("setpgid-join", "{job}")];
    let mut outside = vec![probe_path()];
    outside.extend(probe_args(&join));
    let Some(mut control) = JobSession::start(&outside) else {
        return skip("pty", "no pseudo-terminal available");
    };
    // The control stops itself together with the victim, so it reports no line.
    assert!(control.job_line().is_none(), "the control was not stopped");
    assert!(control.victim_stopped(), "the control stopped no job");
    drop(control);

    let mut session = JobSession::start(&isolated_job(&join)).unwrap();
    let line = session.job_line();
    assert!(!session.victim_stopped(), "the program stopped another job");
    assert_eq!(
        line.as_ref().map(|line| line.result.as_str()),
        Some("denied")
    );
    // A process group of the program's own stays possible.
    probe_inside(&args(&["--signals", "isolated"]), &[("setpgid", "-")])[0].assert_ok();
}

/// With the terminal's foreground, the program could stop the job that had it: that job is
/// stopped as soon as it reads the terminal again.
#[test]
fn the_terminal_cannot_be_taken_from_the_foreground_job() {
    if landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let take = [("tcsetpgrp", "0")];
    let mut outside = vec![probe_path()];
    outside.extend(probe_args(&take));
    let Some(mut control) = JobSession::start(&outside) else {
        return skip("pty", "no pseudo-terminal available");
    };
    let line = control.job_line().unwrap();
    line.assert_ok();
    assert_eq!(
        control.foreground().to_string(),
        line.detail.replace("group ", "")
    );
    drop(control);

    let mut session = JobSession::start(&isolated_job(&take)).unwrap();
    assert_eq!(session.job_line().unwrap().result, "denied");
    assert_eq!(session.foreground(), session.leader.id() as libc::pid_t);
}

/// Changing the window size of a terminal makes the kernel send SIGWINCH to its foreground
/// group, which is outside the sandbox when the program inherited the user's terminal.
#[test]
fn terminal_resize_cannot_signal_outside() {
    if landlock_abi() < 6 {
        return skip("landlock-abi-6", "signal isolation needs Landlock ABI 6");
    }
    let Some(pty) = open_pty() else {
        return skip("pty", "no pseudo-terminal available");
    };
    let resize = [("tiocswinsz", "0")];
    let on_the_terminal = |command: &mut Command| {
        command.stdin(Stdio::from(pty.slave.try_clone().unwrap()));
    };
    // SIGWINCH goes to the foreground group, so the victim owns the terminal and the probe does
    // not: it only holds a descriptor of it, as a program that inherited the user's terminal.
    let watch = || {
        let mut command = Command::new(probe_path());
        command
            .args(probe_args(&[("await-signal", "28")]))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        with_terminal(&pty)(&mut command);
        let mut victim = command.spawn().unwrap();
        let mut ready = String::new();
        BufReader::new(victim.stderr.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert!(ready.starts_with("await-signal ready"), "{ready:?}");
        victim
    };

    let mut victim = watch();
    parse(&probe_outside_with(&resize, on_the_terminal))[0].assert_ok();
    assert_eq!(victim.wait().unwrap().code(), Some(42));

    let mut victim = watch();
    let lines = probe_inside_with(&args(&["--signals", "isolated"]), &resize, on_the_terminal);
    assert_eq!(lines[0].result, "denied", "{lines:?}");
    assert_ne!(victim.wait().unwrap().code(), Some(42));
}

/// Before Landlock ABI 3 the kernel cannot check truncation, so sandy's filter denies
/// `truncate` and read-only opens with `O_TRUNC` for every path, also a writable one
/// (docs/linux.md, "Truncation"). `sandy-abi-cap` runs that code path on this kernel: it answers
/// the ABI query with 2, sandy then handles only the rights of ABI 2 and adds the filter rules.
/// `EPERM` shows that the filter refused the call, where Landlock refuses with `EACCES`.
#[test]
fn truncation_is_denied_everywhere_before_abi_3() {
    if landlock_abi() < 3 {
        return skip(
            "landlock-abi-3",
            "this kernel runs the rules of ABI 1 and 2 without the cap",
        );
    }
    let Some(cap) = abi_cap_path() else {
        return skip("abi-cap", "sandy-abi-cap is not next to the other binaries");
    };
    let fixture = Fixture::new("linux-truncate-cap");
    let (readable, writable) = (fixture.arg("ro/file"), fixture.arg("rw/file"));
    let actions = [
        ("truncate", readable.as_str()),
        ("open-rdonly-trunc", readable.as_str()),
        ("truncate", writable.as_str()),
    ];
    // Control: with the ABI of this kernel, Landlock checks truncation and the writable path
    // allows it. `read_only_and_outside_files_cannot_be_truncated` checks the rest of that case.
    probe_inside(&fixture.access_args(), &actions)[2].assert_ok();
    fixture.reset();

    let output = Command::new(&cap)
        .arg("2")
        .arg(sandy_path())
        .args(run_args(&fixture.access_args(), &actions))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sandy run under the ABI cap failed: {output:?}"
    );
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "probe output: {lines:?}");
    for line in &lines {
        assert_eq!(line.result, "denied", "{line:?}");
        assert!(line.detail.contains("os error 1)"), "not EPERM: {line:?}");
    }
    assert_eq!(fs::read(fixture.path("rw/file")).unwrap(), b"content");

    // The cap reached sandy: it reports the ABI it was given, not the one the kernel has.
    let report = Command::new(cap)
        .args(["2", &sandy_path(), "check"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&report.stdout);
    assert!(report.status.success(), "{stdout}");
    assert!(stdout.contains("Landlock ABI 2"), "{stdout}");
    assert!(!stdout.contains("UNAVAILABLE"), "{stdout}");
}

#[test]
fn io_uring_is_denied() {
    let control = probe_outside(&[("io-uring-setup", "-")]);
    if control[0].result != "ok" {
        return skip(
            "io-uring",
            &format!("io_uring fails outside: {}", control[0].detail),
        );
    }
    probe_inside(&[], &[("io-uring-setup", "-")])[0].assert_blocked();
}

#[test]
fn inherited_descriptors_are_closed() {
    let fixture = Fixture::new("linux-fd");
    let file = fs::File::open(fixture.path("secret/file")).unwrap();
    let raw = file.as_raw_fd();
    let inherit = |command: &mut Command| {
        // SAFETY: dup2 and fcntl are async-signal-safe; descriptor 9 is free in the child.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(raw, 9) < 0 || libc::fcntl(9, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    };
    let actions = [("read-fd", "9")];
    parse(&probe_outside_with(&actions, inherit))[0].assert_ok();
    probe_inside_with(&fixture.access_args(), &actions, inherit)[0].assert_blocked();
}

#[test]
fn no_new_privs_and_seccomp_are_active() {
    let proc_readable = args(&["--read", "/proc"]);
    let lines = probe_inside(
        &proc_readable,
        &[
            ("status-field", "NoNewPrivs"),
            ("status-field", "Seccomp"),
            ("status-field", "Seccomp_filters"),
        ],
    );
    assert_eq!(lines[0].detail, "1", "{lines:?}");
    assert_eq!(lines[1].detail, "2", "{lines:?}");
    let filters: u32 = lines[2].detail.parse().unwrap();
    assert!(filters >= 2, "{lines:?}");
}

#[test]
fn files_of_the_user_outside_the_policy_stay_unchanged() {
    let fixture = Fixture::new("linux-home");
    let home = fixture.path("home");
    let reset = || {
        fixture.reset();
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::write(home.join(".bashrc"), b"original").unwrap();
    };
    reset();
    let bashrc = fixture.arg("home/.bashrc");
    let autostart = fixture.arg("home/.config/autostart/entry.desktop");
    let ssh = fixture.arg("home/.ssh");
    let actions = [
        ("write", bashrc.as_str()),
        ("write", autostart.as_str()),
        ("mkdir", ssh.as_str()),
        ("set-readonly", bashrc.as_str()),
        ("delete", bashrc.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    let mut readable_home = fixture.access_args();
    readable_home.extend(args(&["--read", &fixture.arg("home")]));
    for sandbox_args in [fixture.access_args(), readable_home] {
        reset();
        for line in probe_inside(&sandbox_args, &actions) {
            line.assert_blocked();
        }
        assert_eq!(fs::read(home.join(".bashrc")).unwrap(), b"original");
        assert!(!home.join(".config/autostart/entry.desktop").exists());
        assert!(!home.join(".ssh").exists());
        let permissions = fs::metadata(home.join(".bashrc")).unwrap().permissions();
        assert!(!permissions.readonly());
    }
}

#[test]
fn path_metadata_follows_the_policy() {
    let fixture = Fixture::new("linux-pathmeta");
    let file = fixture.arg("rw/file");
    for line in probe_outside(&[("set-readonly", &file), ("set-writable", &file)]) {
        line.assert_ok();
    }
    // By default the path-based calls are denied, also in writable paths; the descriptor-based
    // call keeps working there.
    let lines = probe_inside(
        &fixture.access_args(),
        &[("set-readonly", &file), ("fchmod-readonly", &file)],
    );
    lines[0].assert_blocked();
    lines[1].assert_ok();
    assert!(fs::metadata(&file).unwrap().permissions().readonly());

    fixture.reset();
    let mut allow = fixture.access_args();
    allow.extend(args(&["--linux-path-metadata", "allow"]));
    probe_inside(&allow, &[("set-readonly", &file)])[0].assert_ok();
    assert!(fs::metadata(&file).unwrap().permissions().readonly());
}

#[test]
fn setuid_and_setgid_bits_cannot_be_set() {
    let fixture = Fixture::new("linux-setid");
    let file = fixture.arg("rw/file");
    let actions = [
        ("fchmod-setuid", file.as_str()),
        ("chmod-setuid", file.as_str()),
    ];
    for line in probe_outside(&actions) {
        line.assert_ok();
    }
    let mut allow = fixture.access_args();
    allow.extend(args(&["--linux-path-metadata", "allow"]));
    for sandbox_args in [fixture.access_args(), allow] {
        fixture.reset();
        for line in probe_inside(&sandbox_args, &actions) {
            line.assert_blocked();
        }
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o6000, 0, "mode {mode:o}");
    }
}

/// A process outside the sandbox that a test may change. It is killed when dropped.
struct Victim(std::process::Child);

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn other_processes_cannot_be_changed() {
    let victim = Victim(
        Command::new(probe_path())
            .args(["sleep", "600000"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = victim.0.id().to_string();
    // Each action writes back the current value, so the victim does not change.
    let calls = [
        "renice-same",
        "prlimit-same",
        "affinity-same",
        "ioprio-same",
    ];
    let other: Vec<(&str, &str)> = calls.iter().map(|call| (*call, pid.as_str())).collect();
    for line in controlled(&[], &other) {
        line.assert_blocked();
    }
    // Process ID 0, the caller, always works.
    let caller: Vec<(&str, &str)> = calls.iter().map(|call| (*call, "0")).collect();
    for line in probe_inside(&[], &caller) {
        line.assert_ok();
    }
    // The program's own ID works only where no process it started can outlive it and see the ID
    // go to another process.
    let own: Vec<(&str, &str)> = calls.iter().map(|call| (*call, "self")).collect();
    for line in probe_inside(&[], &own) {
        line.assert_blocked();
    }
    let no_children = ["--children".to_string(), "none".to_string()];
    for line in probe_inside(&no_children, &own) {
        line.assert_ok();
    }
}

#[test]
fn mount_and_namespace_listing_is_denied() {
    // statmount, listmount and listns. With null arguments a kernel that has the call fails
    // with EFAULT, which shows the call reached it; the filter fails it with EPERM first.
    let calls = ["457", "458", "470"];
    let actions: Vec<(&str, &str)> = calls.iter().map(|nr| ("raw-syscall", *nr)).collect();
    for control in probe_outside(&actions) {
        if control.detail.contains("os error 38") {
            skip(
                "mount-listing-calls",
                &format!("system call {} is not in this kernel", control.target),
            );
        } else {
            assert!(control.detail.contains("os error 14"), "{control:?}");
        }
    }
    for line in probe_inside(&[], &actions) {
        assert_eq!(line.result, "denied", "{line:?}");
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn read_proc(pid: u32, file: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/{file}")).ok()
}

/// The inode of the socket that listens on 127.0.0.1:`port`. /proc/net/tcp shows the local
/// address in hexadecimal (127.0.0.1 is 0100007F on little-endian hosts) and LISTEN as 0A.
fn listener_inode(port: u16) -> Option<String> {
    let local = format!("0100007F:{port:04X}");
    let table = fs::read_to_string("/proc/net/tcp").ok()?;
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let listening = fields.get(1) == Some(&local.as_str()) && fields.get(3) == Some(&"0A");
        listening.then(|| fields.get(9).map(|inode| inode.to_string()))?
    })
}

/// The processes that hold the socket with `inode`.
fn socket_holders(inode: &str) -> Vec<u32> {
    let socket = format!("socket:[{inode}]");
    let Ok(processes) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    processes
        .filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let mut descriptors = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
            let holds = descriptors.any(|fd| {
                fd.and_then(|fd| fs::read_link(fd.path()))
                    .is_ok_and(|link| link.as_os_str() == socket.as_str())
            });
            holds.then_some(pid)
        })
        .collect()
}

fn parent_of(pid: u32) -> Option<u32> {
    status_value(&read_proc(pid, "status")?, "PPid")
        .parse()
        .ok()
}

fn status_value(status: &str, name: &str) -> String {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn has_ended(pid: u32) -> bool {
    read_proc(pid, "status").is_none_or(|status| status_value(&status, "State").starts_with('Z'))
}

#[test]
fn relay_is_confined_and_ends_with_the_program() {
    let (inner, outer) = (free_port(), free_port());
    let expose = format!("127.0.0.1:{outer}={inner}");
    check_relay(&args(&["--ip", "all", "--expose", &expose]), outer, 1);
}

#[test]
fn forward_relay_is_confined_and_ends_with_the_program() {
    let (inner, service) = (free_port(), free_port());
    let forward = format!("{inner}=127.0.0.1:{service}");
    // For a forwarded port the relay listens on the program's port, and it holds a second
    // socket: the netlink socket with which it checks who connects.
    check_relay(&args(&["--ip", "all", "--forward", &forward]), inner, 2);
}

/// The process of the relay that listens on 127.0.0.1:`port` for the program `program_pid`,
/// once it serves. sandy executes the program only after the relay has reported that it is
/// ready, and sandy gives up its own copy of the listener first. The intermediate process of the
/// double fork, a child of the program's process, can still hold the listener for a moment. The
/// relay is ready when it is the only holder and its parent is not the program.
fn ready_relay(port: u16, program_pid: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let executed =
            read_proc(program_pid, "comm").is_some_and(|comm| comm.trim() == "sandy-probe");
        let holders = listener_inode(port)
            .map(|inode| socket_holders(&inode))
            .unwrap_or_default();
        if let [relay] = holders[..]
            && executed
            && parent_of(relay).is_some_and(|parent| parent != program_pid)
        {
            return relay;
        }
        let parents: Vec<_> = holders.iter().map(|&pid| parent_of(pid)).collect();
        assert!(
            Instant::now() < deadline,
            "no ready relay on port {port}: program executed {executed}, listener holders \
             {holders:?} with parents {parents:?}, program {program_pid}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs a sleeping program with `sandbox_args`, finds the relay that listens on 127.0.0.1:`port`
/// and checks its confinement, then kills the program and checks that the relay ends. `sockets`
/// is how many sockets the relay holds.
fn check_relay(sandbox_args: &[String], port: u16, sockets: usize) {
    let mut program = Victim(
        Command::new(sandy_path())
            .args(run_args(sandbox_args, &[("sleep", "600000")]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let program_pid = program.0.id();
    let relay = ready_relay(port, program_pid);

    let status = read_proc(relay, "status").unwrap();
    assert_eq!(status_value(&status, "NoNewPrivs"), "1", "{status}");
    assert_eq!(status_value(&status, "Seccomp"), "2", "{status}");
    assert_ne!(
        status_value(&status, "PPid"),
        program_pid.to_string(),
        "{status}"
    );
    // The relay holds /dev/null as its standard descriptors, its sockets and the pidfd; nothing
    // that opens files, and nothing of the caller's.
    let descriptors: Vec<String> = fs::read_dir(format!("/proc/{relay}/fd"))
        .unwrap()
        .map(|entry| {
            let link = fs::read_link(entry.unwrap().path()).unwrap();
            link.to_string_lossy().into_owned()
        })
        .collect();
    let count = |kept: &dyn Fn(&String) -> bool| descriptors.iter().filter(|d| kept(d)).count();
    assert_eq!(count(&|d| d == "/dev/null"), 3, "{descriptors:?}");
    assert_eq!(count(&|d| d == "anon_inode:[pidfd]"), 1, "{descriptors:?}");
    assert_eq!(
        count(&|d| d.starts_with("socket:")),
        sockets,
        "{descriptors:?}"
    );
    assert_eq!(descriptors.len(), 4 + sockets, "{descriptors:?}");
    // The program does not hold the listener.
    let program_descriptors = fs::read_dir(format!("/proc/{program_pid}/fd"))
        .unwrap()
        .count();
    assert_eq!(program_descriptors, 3);

    let address = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(TcpStream::connect_timeout(&address, Duration::from_secs(5)).is_ok());
    // SAFETY: kill takes no pointers.
    unsafe { libc::kill(program_pid as libc::pid_t, libc::SIGKILL) };
    program.0.wait().unwrap();
    // DESIGN.md: no relay outlives the program by more than one second. The margin covers slow
    // test machines. The main thread of the relay can show as a zombie while its other threads,
    // which share the listener, are still exiting, so the test also waits for the port to close.
    let deadline = Instant::now() + Duration::from_secs(1) + Duration::from_secs(2);
    let refused = || TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err();
    while !(has_ended(relay) && refused()) {
        assert!(
            Instant::now() < deadline,
            "the relay outlived the program by more than one second plus margin"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Accepts one connection on `listener` before the deadline.
fn accepts_within(listener: &std::net::TcpListener, wait: Duration) -> bool {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if listener.accept().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn forward_relay_reaches_only_its_target() {
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inner = free_port();
    let forward = format!("{inner}={}", target.local_addr().unwrap());
    let sandbox_args = args(&["--ip", "all", "--forward", &forward]);
    // The program connects and exits without sending anything, so the kernel has dropped the
    // owner of its socket by the time the relay accepts (rule 6 of "Forwarded ports").
    let lines = probe_inside(
        &sandbox_args,
        &[("tcp-connect", &format!("127.0.0.1:{inner}"))],
    );
    lines[0].assert_ok();
    assert!(accepts_within(&target, Duration::from_secs(20)));
    // The relay connects only to the target; the other listener sees nothing.
    assert!(!accepts_within(&other, Duration::from_millis(500)));
}

/// Rule 6 of "Forwarded ports": a peer that closed its socket before the relay accepted it has
/// no owner left for the kernel to report, and the relay serves it rather than drop what is in
/// every ordinary run the program's own connection. Stopping the relay makes the late accept
/// certain; a program that connects and exits reaches it by itself most of the time, on some
/// kernels always. This is also the window another local user can retry into (docs/linux.md).
#[test]
fn forward_relay_serves_a_peer_that_closed_before_it_accepted() {
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inner = free_port();
    let forward = format!("{inner}={}", target.local_addr().unwrap());
    let sandbox_args = args(&["--ip", "all", "--forward", &forward]);
    let program = Victim(
        Command::new(sandy_path())
            .args(run_args(&sandbox_args, &[("sleep", "600000")]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let relay = ready_relay(inner, program.0.id()) as libc::pid_t;
    // SAFETY: kill takes no pointers.
    unsafe { libc::kill(relay, libc::SIGSTOP) };
    let address = format!("127.0.0.1:{inner}").parse().unwrap();
    // The kernel completes the handshake while the relay is stopped.
    let client = TcpStream::connect_timeout(&address, Duration::from_secs(20)).unwrap();
    drop(client);
    // Long enough for the kernel to replace the closed socket with a record without an owner.
    std::thread::sleep(Duration::from_millis(200));
    // SAFETY: as above.
    unsafe { libc::kill(relay, libc::SIGCONT) };
    assert!(accepts_within(&target, Duration::from_secs(20)));
    // It was the relay that answered, not a relay the watchdog killed while it was stopped.
    assert!(
        !has_ended(relay as u32),
        "the relay did not survive the stop"
    );
}

/// Rule 5 of "Forwarded ports": the relay closes its listeners as soon as the program ends.
#[test]
fn relay_stops_listening_as_soon_as_the_program_ends() {
    let (inner, outer) = (free_port(), free_port());
    let expose = format!("127.0.0.1:{outer}={inner}");
    let sandbox_args = args(&["--ip", "all", "--expose", &expose]);
    let mut server = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[("tcp-accept", &format!("127.0.0.1:{inner}"))],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    // Early attempts can reach the relay before the program listens; the relay closes them.
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the server never accepted");
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = server.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "the relay still accepts after the program ended"
    );
}

/// What the probe's tcp-send action writes.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";

/// Rule 5 of "Forwarded ports": a program that connects through a forwarded port, writes and
/// exits at once does not lose its data.
#[test]
fn forward_relay_delivers_data_sent_just_before_exit() {
    use std::io::Read;
    let service = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = service.local_addr().unwrap();
    service.set_nonblocking(true).unwrap();
    // Returns what the first connection sends, or nothing if none arrives before the deadline.
    let received = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = service.accept() {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .unwrap();
                let mut data = Vec::new();
                let _ = stream.read_to_end(&mut data);
                return data;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Vec::new()
    });
    let inner = free_port();
    let forward = format!("{inner}={target}");
    let sandbox_args = args(&["--ip", "all", "--forward", &forward]);
    let lines = probe_inside(
        &sandbox_args,
        &[("tcp-send", &format!("127.0.0.1:{inner}"))],
    );
    lines[0].assert_ok();
    assert_eq!(received.join().unwrap(), TCP_SEND_PAYLOAD);
}

/// Every way to create a process, as probe actions. fork and vfork exist only on x86_64.
fn process_actions(program: &str) -> Vec<(&'static str, String)> {
    let mut actions = vec![
        ("clone-process", "-".to_string()),
        ("posix-spawn", program.to_string()),
        ("exec", program.to_string()),
    ];
    if cfg!(target_arch = "x86_64") {
        actions.extend([("fork", "-".to_string()), ("vfork", "-".to_string())]);
    }
    actions
}

#[test]
fn children_none_denies_every_way_to_create_a_process() {
    let fixture = Fixture::new("linux-children");
    let program = fixture.copy_probe("bin");
    let owned = process_actions(&program);
    let mut actions: Vec<(&str, &str)> = owned.iter().map(|(a, t)| (*a, t.as_str())).collect();
    actions.push(("thread", "-"));
    // Control: outside and inside without the option, every action works.
    controlled(&fixture.access_args(), &actions)
        .iter()
        .for_each(ProbeLine::assert_ok);
    let mut none = fixture.access_args();
    none.extend(args(&["--children", "none"]));
    let lines = probe_inside(&none, &actions);
    let (thread, processes) = lines.split_last().unwrap();
    for line in processes {
        assert_eq!(line.result, "denied", "{line:?}");
    }
    thread.assert_ok();
}

#[test]
fn relays_work_with_children_none() {
    use std::io::Read;
    // Forward: the program's data reaches a service outside.
    let service = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = service.local_addr().unwrap();
    let received = std::thread::spawn(move || {
        service.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = service.accept() {
                stream.set_nonblocking(false).unwrap();
                let mut data = Vec::new();
                let _ = stream.read_to_end(&mut data);
                return data;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Vec::new()
    });
    let inner = free_port();
    let forward = format!("{inner}={target}");
    let sandbox_args = args(&["--ip", "all", "--children", "none", "--forward", &forward]);
    let lines = probe_inside(
        &sandbox_args,
        &[("tcp-send", &format!("127.0.0.1:{inner}"))],
    );
    lines[0].assert_ok();
    assert_eq!(received.join().unwrap(), TCP_SEND_PAYLOAD);

    // Expose: a client outside reaches the program.
    let (inner, outer) = (free_port(), free_port());
    let expose = format!("127.0.0.1:{outer}={inner}");
    let sandbox_args = args(&["--ip", "all", "--children", "none", "--expose", &expose]);
    let mut server = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[("tcp-accept", &format!("127.0.0.1:{inner}"))],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the server never accepted");
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = server.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();
}

#[test]
fn opening_for_ioctl_only_is_denied() {
    let fixture = Fixture::new("linux-ioctlopen");
    let lines = controlled(
        &fixture.access_args(),
        &[
            ("open-ioctl-only", &fixture.arg("secret/file")),
            ("open-ioctl-only", &fixture.arg("rw/file")),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
}

/// Why `open` with access mode 3 has to be denied, and with it `openat2`: Landlock checks no
/// right for such an open, so the descriptor reaches a file the policy grants nothing on, and
/// the metadata calls on a descriptor then change that file. Landlock has no hook for them at
/// any ABI, so no ABI makes `openat2` safe to allow. The day a kernel closes this, the run
/// outside the sandbox fails here and the decision can be taken again (see "Access mode 3" in
/// docs/linux.md).
#[test]
fn landlock_alone_allows_access_mode_3() {
    let fixture = Fixture::new("linux-mode3");
    let target = fixture.path("secret/file");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let argument = fixture.arg("secret/file");
    let actions = [("landlock-ioctl-only", argument.as_str())];
    probe_outside(&actions)[0].assert_ok();
    let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "fchmod on the descriptor changed nothing");
    probe_inside(&fixture.access_args(), &actions)[0].assert_blocked();
}

/// `openat2` is not in the allowlist, so it fails with `ENOSYS`. Its flags live in an
/// `open_how` structure in memory, which seccomp cannot read, so the rule against access mode 3
/// cannot be applied to it (see `landlock_alone_allows_access_mode_3`). Every kernel with
/// Landlock has `openat2`, so the run outside the sandbox needs no host check.
#[test]
fn openat2_is_not_in_the_allowlist() {
    let fixture = Fixture::new("linux-openat2");
    let argument = fixture.arg("ro/file");
    let lines = controlled(&fixture.access_args(), &[("openat2-read", &argument)]);
    lines[0].assert_blocked();
    assert!(lines[0].detail.contains("os error 38"), "{lines:?}");
}

#[test]
fn system_v_shared_memory_is_unreachable() {
    struct Segment(libc::c_int);
    impl Drop for Segment {
        fn drop(&mut self) {
            // SAFETY: removes the segment this test created.
            unsafe { libc::shmctl(self.0, libc::IPC_RMID, std::ptr::null_mut()) };
        }
    }
    // SAFETY: creates a private segment; the guard removes it.
    let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
    if id < 0 {
        return skip("sysv-shm", "System V shared memory is unavailable");
    }
    let segment = Segment(id);
    let id = segment.0.to_string();
    controlled(&[], &[("shm-attach", &id)])[0].assert_blocked();
}

fn setuid_root_su() -> Option<PathBuf> {
    ["/usr/bin/su", "/bin/su"].iter().find_map(|path| {
        let path = Path::new(path).canonicalize().ok()?;
        let metadata = fs::metadata(&path).ok()?;
        (metadata.uid() == 0 && metadata.permissions().mode() & 0o4000 != 0).then_some(path)
    })
}

fn effective_uid(line: &ProbeLine) -> &str {
    line.detail.split(' ').nth(1).unwrap_or_default()
}

#[test]
fn setuid_programs_do_not_gain_privileges() {
    let Some(su) = setuid_root_su() else {
        return skip("setuid-su", "no setuid-root su");
    };
    // su waits for a password on the open stdin pipe and is killed before it gets one.
    let command = format!("{} -c true nobody", su.display());
    let control = probe_outside(&[("setuid-exec", &command)]);
    if control[0].result != "ok" || effective_uid(&control[0]) != "0" {
        return skip(
            "setuid-su",
            &format!("su does not run as root outside: {control:?}"),
        );
    }
    let sandbox_args = args(&["--read", "/proc", "--read-exec", su.to_str().unwrap()]);
    let lines = probe_inside(&sandbox_args, &[("setuid-exec", &command)]);
    lines[0].assert_ok();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() }.to_string();
    assert_eq!(effective_uid(&lines[0]), uid, "{lines:?}");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn foreign_system_call_abi_kills_the_program() {
    let control = probe_outside_with(&[("int80-getpid", "-")], |_| {});
    if !control.status.success() || parse(&control)[0].result != "ok" {
        return skip(
            "int80",
            "the 32-bit system call entry is unavailable outside",
        );
    }
    let output = sandy(run_args(&[], &[("int80-getpid", "-")]));
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{output:?}");
}

#[test]
fn common_programs_run_under_the_default_policy() {
    let fixture = Fixture::new("linux-programs");
    let readable = fixture.arg("ro");
    let programs: [&[&str]; 7] = [
        &["/usr/bin/true"],
        &["/usr/bin/env"],
        &["/usr/bin/ls", "-l", &readable],
        &["/usr/bin/cat", &format!("{readable}/file")],
        &["/bin/sh", "-c", "exit 0"],
        &["/usr/bin/date"],
        &["/usr/bin/python3", "-I", "-c", "pass"],
    ];
    for program in programs {
        let Ok(path) = Path::new(program[0]).canonicalize() else {
            skip(
                "common-programs",
                &format!("{} is not installed", program[0]),
            );
            continue;
        };
        let mut run = args(&["run", "--read", &readable, "--"]);
        run.push(path.to_str().unwrap().to_string());
        run.extend(args(&program[1..]));
        let output = sandy(&run);
        assert!(
            output.status.success(),
            "{program:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A writable path that overlaps the minimal system set would let the program change code or
/// configuration that other programs trust, here /etc/ld.so.cache, /etc/ld.so.preload (also when
/// it does not exist) and /etc/hosts. sandy refuses before the program starts.
#[test]
fn a_writable_path_over_the_system_set_is_refused() {
    let output = sandy(run_args(
        &args(&["--read-write", "/etc"]),
        &[("env", "PATH")],
    ));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(output.stdout.is_empty(), "the program ran: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("overlaps"), "{stderr}");

    // With system = "none" sandy adds no system paths, so nothing overlaps.
    let check = sandy(["check", "--system", "none", "--read-write", "/etc"]);
    assert!(
        !String::from_utf8_lossy(&check.stdout).contains("overlaps"),
        "{check:?}"
    );
}

/// `check` with the environment the trusted locations are read from: a home directory and a PATH
/// of the test's own, so the result does not depend on the account that runs the suite.
fn check_with_environment(home: &str, path: &str, writable: &str) -> Output {
    Command::new(sandy_path())
        .args(["check", "--read-write", writable])
        .env("HOME", home)
        .env("PATH", path)
        .output()
        .unwrap()
}

/// A writable path that holds the home directory lets the program change shell startup files and
/// autostart entries, which run outside the sandbox at the next login (README rule 8). sandy
/// refuses such a policy; a directory below the home directory stays writable.
#[test]
fn refuses_a_writable_path_over_the_home_directory() {
    let fixture = Fixture::new("trusted-home");
    fs::create_dir_all(fixture.path("home/data")).unwrap();
    let check = |writable: &str| check_with_environment(&fixture.arg("home"), "/usr/bin", writable);

    let refused = check(&fixture.arg("home"));
    let stdout = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(
        refused.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{stdout}"
    );
    assert!(stdout.contains("runs outside the sandbox"), "{stdout}");

    let allowed = check(&fixture.arg("home/data"));
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
}

/// A directory on PATH inside a writable path lets the program leave a command there that the
/// user runs outside the sandbox by name. Such a policy is ordinary work, so sandy enforces it
/// and warns, naming the directory (README rule 8). The same writable path without that PATH
/// entry says nothing.
#[test]
fn warns_about_a_writable_path_that_holds_a_directory_on_path() {
    let fixture = Fixture::new("trusted-path");
    fs::create_dir_all(fixture.path("rw/bin")).unwrap();
    let check = |path: &str| check_with_environment(&fixture.arg("home"), path, &fixture.arg("rw"));

    let warned = check(&format!("{}:/usr/bin", fixture.arg("rw/bin")));
    let stdout = String::from_utf8_lossy(&warned.stdout);
    let stderr = String::from_utf8_lossy(&warned.stderr);
    assert_eq!(warned.status.code(), Some(0), "{stdout}{stderr}");
    let names_it =
        |line: &str| line.starts_with("warning: ") && line.contains(&fixture.arg("rw/bin"));
    assert!(stderr.lines().any(names_it), "{stderr}");

    let quiet = check("/usr/bin");
    let stderr = String::from_utf8_lossy(&quiet.stderr);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(!stderr.contains(&fixture.arg("rw/bin")), "{stderr}");
}

/// A writable path that holds a directory on PATH and a location that is refused stays refused:
/// the warning never replaces the refusal.
#[test]
fn refuses_a_writable_path_that_holds_a_directory_on_path_and_a_startup_file() {
    let fixture = Fixture::new("trusted-both");
    fs::create_dir_all(fixture.path("home/bin")).unwrap();
    let refused = check_with_environment(
        &fixture.arg("home"),
        &format!("{}:/usr/bin", fixture.arg("home/bin")),
        &fixture.arg("home"),
    );
    let stdout = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(
        refused.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{stdout}"
    );
    assert!(stdout.contains("runs outside the sandbox"), "{stdout}");
    // The directory on PATH is warned about as well, so the refusal did win over a warning.
    let stderr = String::from_utf8_lossy(&refused.stderr);
    let names_it =
        |line: &str| line.starts_with("warning: ") && line.contains(&fixture.arg("home/bin"));
    assert!(stderr.lines().any(names_it), "{stderr}");
}

/// A bind mount of a subdirectory of a writable path shares no ancestor with that path, so
/// comparing the identity of the ancestors alone does not see that read_exec on the alias makes
/// the writable directory executable. sandy compares where the paths lie inside the file system.
///
/// Mounting needs a mount namespace. The nested user namespace maps the mounting user back to an
/// unprivileged one, so sandy runs without capabilities, as it would on a normal host.
#[test]
fn refuses_a_read_exec_alias_of_a_writable_subdirectory() {
    let fixture = Fixture::new("bind-alias");
    for dir in ["rw/sub", "ro/sub", "alias", "control"] {
        fs::create_dir_all(fixture.path(dir)).unwrap();
    }
    let check = |path: &str| {
        format!(
            "{} check --read-write {} --read-exec {path} >/dev/null 2>&1",
            sandy_path(),
            fixture.arg("rw")
        )
    };
    // The alias of the writable subdirectory, and a control alias of a directory outside the
    // writable path, which stays allowed.
    let script = format!(
        "mount --bind {}/sub {} || exit 97\n\
         mount --bind {}/sub {} || exit 97\n\
         exec unshare --user --map-user=1000 --map-group=1000 sh -c '\
           {}; echo alias=$?; {}; echo control=$?'\n",
        fixture.arg("rw"),
        fixture.arg("alias"),
        fixture.arg("ro"),
        fixture.arg("control"),
        check(&fixture.arg("alias")),
        check(&fixture.arg("control")),
    );
    let Ok(output) = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-c", &script])
        .output()
    else {
        return skip("unshare", "unshare is not installed");
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name)?.parse::<i32>().ok())
    };
    let (Some(alias), Some(control)) = (code("alias="), code("control=")) else {
        return skip(
            "unshare",
            &format!(
                "no unprivileged user namespace with a mount namespace: {:?}, {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        );
    };
    assert_eq!(control, 0, "the control alias was refused: {stdout}");
    assert_eq!(alias, EXIT_FAILURE, "{stdout}");
}

/// Runs `script` as the root of a new user and mount namespace, so that it can bind-mount, and
/// returns the exit codes it printed as `<name>=<code>` lines, in the order of `names`. `None`
/// when this host does not let an unprivileged user create such a namespace, or when the script
/// could not set its mounts up.
fn namespace_exit_codes(script: &str, names: &[&str]) -> Option<Vec<i32>> {
    let Ok(output) = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-c", script])
        .output()
    else {
        skip("unshare", "unshare is not installed");
        return None;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let codes: Vec<i32> = names
        .iter()
        .filter_map(|name| {
            let prefix = format!("{name}=");
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
        })
        .collect();
    if codes.len() == names.len() {
        return Some(codes);
    }
    skip(
        "unshare",
        &format!(
            "no unprivileged user namespace with a mount namespace: {:?}, {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
    );
    None
}

/// A 64-bit little-endian ELF file with one program header, which names `interpreter`. `check`
/// reads the header to learn which loader the kernel would execute; it never runs the file.
fn elf_with_interpreter(path: &Path, interpreter: &str) {
    let mut bytes = vec![0u8; 64 + 56];
    bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
    bytes[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let interpreter = format!("{interpreter}\0");
    let at = bytes.len() as u64;
    bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&at.to_le_bytes());
    bytes[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    bytes.extend_from_slice(interpreter.as_bytes());
    fs::write(path, bytes).unwrap();
}

/// The minimal system set is compared like the policy paths: an alias of a directory that holds
/// entries of the set is that directory, so a writable path on an alias of /etc is refused like
/// `--read-write /etc`. The control alias holds nothing of the set and stays allowed.
#[test]
fn refuses_a_writable_alias_of_a_system_set_directory() {
    let fixture = Fixture::new("system-alias");
    for dir in ["alias", "control"] {
        fs::create_dir_all(fixture.path(dir)).unwrap();
    }
    let check = |path: &str| format!("{} check --read-write {path} >/dev/null 2>&1", sandy_path());
    let script = format!(
        "mount --bind /etc {} || exit 97\n\
         mount --bind {} {} || exit 97\n\
         exec unshare --user --map-user=1000 --map-group=1000 sh -c '\
           {}; echo alias=$?; {}; echo control=$?'\n",
        fixture.arg("alias"),
        fixture.arg("ro"),
        fixture.arg("control"),
        check(&fixture.arg("alias")),
        check(&fixture.arg("control")),
    );
    let Some(codes) = namespace_exit_codes(&script, &["alias", "control"]) else {
        return;
    };
    assert_eq!(codes[1], 0, "the control alias was refused: {codes:?}");
    assert_eq!(codes[0], EXIT_NOT_ENFORCEABLE, "{codes:?}");
}

/// sandy grants execute on the loader the program names in its header, but never when the loader
/// lies in a writable path: the program could replace what the kernel executes. The writable path
/// is an alias of the directory that holds the loader, which a comparison of path prefixes does
/// not see. The control run grants the same loader with an unrelated writable path.
#[test]
fn refuses_a_loader_in_an_alias_of_a_writable_path() {
    let fixture = Fixture::new("loader-alias");
    for dir in ["alias", "control"] {
        fs::create_dir_all(fixture.path(dir)).unwrap();
    }
    // A loader in a system location that the minimal system set does not name, as a
    // distribution outside the FHS layout has. The tmpfs below makes it writable for the test.
    let loader = "/usr/local/lib/ld-sandy-test.so";
    let program = fixture.path("bin/program");
    elf_with_interpreter(&program, loader);
    let check = |path: &str| {
        format!(
            "{} check --read-write {path} {} >/dev/null 2>&1",
            sandy_path(),
            program.display()
        )
    };
    let script = format!(
        "mount -t tmpfs none /usr/local || exit 97\n\
         mkdir -p /usr/local/lib || exit 97\n\
         : > {loader} || exit 97\n\
         mount --bind /usr/local {} || exit 97\n\
         exec unshare --user --map-user=1000 --map-group=1000 sh -c '\
           {}; echo alias=$?; {}; echo control=$?'\n",
        fixture.arg("alias"),
        check(&fixture.arg("alias")),
        check(&fixture.arg("control")),
    );
    let Some(codes) = namespace_exit_codes(&script, &["alias", "control"]) else {
        return;
    };
    assert_eq!(codes[1], 0, "the control run was refused: {codes:?}");
    assert_eq!(codes[0], EXIT_NOT_ENFORCEABLE, "{codes:?}");
}
