//! macOS behavior of `process.children = "contained"`: sandy stays the program's parent, keeps
//! every process the program starts in one process group, and ends that group. See
//! `crates/sandy-macos/src/macos/contain.rs`.
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::{MaybeUninit, size_of};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::unix::*;
use common::*;

const TIMEOUT: Duration = Duration::from_secs(10);
/// How long the program and the processes it starts would run on their own, in milliseconds.
const LONG_SLEEP: &str = "60000";

fn contained(fixture: &Fixture) -> Vec<String> {
    let mut args = fixture.access_args();
    args.extend(["--children", "contained", "--signals", "isolated"].map(String::from));
    args
}

/// The kernel's record of process `pid`, or `None` when it does not exist.
fn info(pid: libc::pid_t) -> Option<libc::proc_bsdinfo> {
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
    // SAFETY: proc_pidinfo filled the whole structure.
    (written == size).then(|| unsafe { info.assume_init() })
}

/// A zombie has ended, although signal 0 still reaches it until its parent reaps it.
fn is_running(pid: libc::pid_t) -> bool {
    info(pid).is_some_and(|info| info.pbi_status != libc::SZOMB)
}

fn ends_soon(pid: libc::pid_t) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if !is_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn exits_soon(child: &mut Child) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

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

/// Waits until `parent` has a child named `name`, that is, until sandy has started the program.
fn wait_for_child(parent: u32, name: &str) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        let mut children = [0 as libc::pid_t; 64];
        let size = (children.len() * size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: the buffer holds `size` bytes.
        let count = unsafe {
            libc::proc_listchildpids(parent as libc::pid_t, children.as_mut_ptr().cast(), size)
        };
        for &child in &children[..count.max(0) as usize] {
            let named = info(child).is_some_and(|info| {
                let comm: Vec<u8> = info
                    .pbi_comm
                    .iter()
                    .take_while(|&&byte| byte != 0)
                    .map(|&byte| byte as u8)
                    .collect();
                comm == name.as_bytes()
            });
            if named {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("sandy {parent} did not start {name}");
}

/// Reads `child`'s output to its end in a thread. The end comes when every process that holds
/// the pipe has ended.
fn output_end(child: &mut Child) -> mpsc::Receiver<Vec<u8>> {
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.read_to_end(&mut output);
        let _ = sender.send(output);
    });
    receiver
}

#[test]
fn processes_cannot_leave_the_group() {
    let fixture = Fixture::new("contained-group");
    // Separate runs: after setsid, the probe leads its group and setpgid fails outside too.
    for action in ["setsid", "setpgid"] {
        controlled(&contained(&fixture), &[(action, "-")])[0].assert_blocked();
    }
}

/// posix_spawn's POSIX_SPAWN_SETSID and POSIX_SPAWN_SETPGROUP would leave the group inside the
/// kernel, so `contained` denies posix_spawn as a whole. fork and execve still start programs.
#[test]
fn posix_spawn_is_denied_and_fork_works() {
    let fixture = Fixture::new("contained-spawn");
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}exit\u{1f}0");

    // Control: without containment the same policy spawns.
    let lines = probe_inside(
        &fixture.access_args(),
        &[("posix-spawn", &program), ("start", &start)],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();

    let lines = probe_inside(
        &contained(&fixture),
        &[
            ("posix-spawn", &program),
            ("start", &start),
            ("start-forked", &start),
            ("fork", "-"),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
    lines[2].assert_ok();
    lines[3].assert_ok();
}

#[test]
fn the_program_cannot_signal_sandy() {
    let fixture = Fixture::new("contained-parent");
    controlled(&contained(&fixture), &[("signal-parent", "-")])[0].assert_blocked();
}

#[test]
fn the_guard_ends_the_group_when_sandy_is_killed() {
    let fixture = Fixture::new("contained-guard");
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    let actions = [("start-forked", start.as_str()), ("sleep", LONG_SLEEP)];
    let mut sandy = Command::new(sandy_path())
        .args(run_args(&contained(&fixture), &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
    let pid: libc::pid_t = detail(&mut stdout).parse().unwrap();
    sandy.stdout = Some(stdout.into_inner());
    let output = output_end(&mut sandy);

    // The program still sleeps, so only the guard can end the group.
    sandy.kill().unwrap();
    sandy.wait().unwrap();
    assert!(ends_soon(pid), "process {pid} outlived sandy");
    assert!(
        output.recv_timeout(TIMEOUT).is_ok(),
        "the program outlived sandy"
    );
}

#[test]
fn signals_reach_the_program_and_its_status_is_reported() {
    let fixture = Fixture::new("contained-status");
    let output = sandy(run_args(&contained(&fixture), &[("exit", "7")]));
    assert_eq!(output.status.code(), Some(7), "{output:?}");

    let mut sandy = Command::new(sandy_path())
        .args(run_args(&contained(&fixture), &[("sleep", LONG_SLEEP)]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_child(sandy.id(), "sandy-probe");
    // SAFETY: sends SIGTERM to sandy, which this test started.
    unsafe { libc::kill(sandy.id() as libc::pid_t, libc::SIGTERM) };
    // The program does not handle SIGTERM, so it ends by the signal: 128 + 15.
    assert_eq!(sandy.wait().unwrap().code(), Some(143));
}

/// Writing the `--status-fd` record is best effort: a caller that closed its end of the
/// channel gets no record, and the program runs as it would without the option. Such a write
/// raises SIGPIPE, which must neither end sandy before it starts the program nor reach the
/// program through the supervising sandy of `contained`, which passes signals on.
#[test]
fn a_status_channel_nobody_reads_changes_nothing() {
    use std::os::fd::AsRawFd;

    let fixture = Fixture::new("contained-status-unread");
    for sandbox_args in [fixture.access_args(), contained(&fixture)] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let raw = writer.as_raw_fd();
        let mut args = run_args(&sandbox_args, &[("sleep", "200"), ("exit", "7")]);
        args.splice(1..1, ["--status-fd".to_string(), "3".to_string()]);
        let mut command = Command::new(sandy_path());
        command.args(args);
        // SAFETY: inherit_as is async-signal-safe and the closure calls nothing else.
        unsafe {
            command.pre_exec(move || inherit_as(raw, 3));
        }
        let output = command.output().unwrap();
        drop(writer);
        assert_eq!(
            output.status.code(),
            Some(7),
            "{sandbox_args:?}: {output:?}"
        );
        parse(&output)[0].assert_ok();
    }
}

#[test]
fn a_failed_start_is_reported() {
    let fixture = Fixture::new("contained-start");
    // execve fails with ENOEXEC in the forked child, after the sandbox is applied.
    let data = fixture.path("bin").join("not-a-program");
    fs::write(&data, b"data").unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
    let mut args = vec!["run".to_string()];
    args.extend(contained(&fixture));
    args.extend(["--".to_string(), data.to_str().unwrap().to_string()]);
    let output = sandy(args);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot execute"), "{stderr}");
}

/// The forked program gets no descriptor of sandy's beyond 0, 1 and 2, as after posix_spawn with
/// POSIX_SPAWN_CLOEXEC_DEFAULT in the exec model. The inherited descriptor has a high number,
/// because std's spawn uses low ones in the child for its own pipe.
#[test]
fn the_program_inherits_only_the_standard_descriptors() {
    const INHERITED: libc::c_int = 47;
    let fixture = Fixture::new("contained-descriptors");
    // Without a writer, an inherited read end reads to its end at once instead of blocking.
    let (read, write) = std::io::pipe().unwrap();
    drop(write);
    let read_fd = std::os::fd::AsRawFd::as_raw_fd(&read);
    let with_descriptor = |program: String, args: Vec<String>| {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: inherit_as is async-signal-safe; it makes the pipe's read end descriptor
        // `INHERITED` of the child, without close-on-exec.
        unsafe {
            command.pre_exec(move || inherit_as(read_fd, INHERITED));
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        parse(&output).remove(0)
    };
    let target = INHERITED.to_string();
    let actions = [("fd-read", target.as_str())];
    // Control: the probe reads the descriptor when it inherits it.
    with_descriptor(probe_path(), probe_args(&actions)).assert_ok();
    with_descriptor(sandy_path(), run_args(&contained(&fixture), &actions)).assert_blocked();
}

/// The supervising sandy closes what it inherited beyond 0, 1 and 2 and keeps only its own
/// descriptors, such as the status record's. A listening socket that the caller let it inherit
/// would otherwise stay bound for as long as the program runs, although neither the program nor
/// the helpers get it (`the_program_inherits_only_the_standard_descriptors`). The test asks
/// `lsof` which processes of the run hold the port, not whether the port answers: macOS sets
/// close-on-exec on a new socket only after creating it, so a process that another test of this
/// binary starts in that moment can hold a copy too (the port answered in 1 of 10 runs on the
/// macos-26 runner while `lsof` found no listener). Control: `lsof` finds the caller's copy, and
/// the record arrives in full.
#[test]
fn sandy_keeps_no_inherited_descriptor_while_the_program_runs() {
    use std::os::fd::AsRawFd;
    const INHERITED: libc::c_int = 47;
    const STATUS: libc::c_int = 48;

    let fixture = Fixture::new("contained-closed");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (status_read, status_write) = std::io::pipe().unwrap();
    let (socket, record) = (listener.as_raw_fd(), status_write.as_raw_fd());
    let mut args = run_args(&contained(&fixture), &[("read-line", "-"), ("exit", "7")]);
    args.splice(1..1, ["--status-fd".to_string(), STATUS.to_string()]);
    let mut command = Command::new(sandy_path());
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    // SAFETY: inherit_as is async-signal-safe; it gives the child both descriptors without
    // close-on-exec.
    unsafe {
        command.pre_exec(move || {
            inherit_as(socket, INHERITED)?;
            inherit_as(record, STATUS)
        });
    }
    let mut sandy = command.spawn().unwrap();
    drop(status_write);
    let mut status = BufReader::new(status_read);
    let mut started = String::new();
    status.read_line(&mut started).unwrap();
    assert!(started.starts_with("pid "), "{started:?}");

    let caller = holders(&[std::process::id()], port);
    assert!(
        caller.contains("LISTEN"),
        "control: lsof does not find the caller's listener: {caller:?}"
    );
    drop(listener);
    let run = process_tree(sandy.id());
    let held = holders(&run, port);
    writeln!(sandy.stdin.take().unwrap(), "end").unwrap();
    assert_eq!(sandy.wait().unwrap().code(), Some(7));
    let mut rest = String::new();
    status.read_to_string(&mut rest).unwrap();
    assert!(
        held.is_empty(),
        "a process of the run ({run:?}) kept the listener sandy inherited:\n{held}"
    );
    assert_eq!(rest, "exited 7\n");
}

/// `root` and every process below it, from `ps`.
fn process_tree(root: u32) -> Vec<u32> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .output()
        .unwrap();
    let pairs: Vec<(u32, u32)> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace().map(|field| field.parse().ok());
            Some((fields.next()??, fields.next()??))
        })
        .collect();
    let mut tree = vec![root];
    let mut next = 0;
    while let Some(&parent) = tree.get(next) {
        tree.extend(
            pairs
                .iter()
                .filter(|(_, ppid)| *ppid == parent)
                .map(|(pid, _)| *pid),
        );
        next += 1;
    }
    tree
}

/// The TCP sockets on `port` that the processes `pids` hold, as `lsof` lists them; empty when
/// there are none.
fn holders(pids: &[u32], port: u16) -> String {
    let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
    let output = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pids.join(","), &format!("-iTCP:{port}")])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_program_reads_the_terminal() {
    let fixture = Fixture::new("contained-terminal");
    let Some(pty) = open_pty() else {
        skip("pty", "no pseudo-terminal available");
        return;
    };
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&contained(&fixture), &[("read-line", "-")]))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    with_terminal(&pty)(&mut command);
    let mut sandy = command.spawn().unwrap();
    discard_output(&pty);
    fs::File::from(pty.master.try_clone().unwrap())
        .write_all(b"hello\n")
        .unwrap();

    // A program outside the terminal's foreground group would stop when it reads.
    let deadline = Instant::now() + TIMEOUT;
    while sandy.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            sandy.kill().unwrap();
            panic!("the program could not read the terminal");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = sandy.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    lines[0].assert_ok();
    assert_eq!(lines[0].detail, "hello");
}

/// With a terminal, a stopped program stops sandy too (job control). The program can stop itself,
/// have one of its processes continue it, and end while sandy stays stopped. The guard still ends
/// the group when the program ends.
#[test]
fn a_program_that_stops_sandy_cannot_outlive_its_end() {
    let fixture = Fixture::new("contained-stop");
    let Some(pty) = open_pty() else {
        skip("pty", "no pseudo-terminal available");
        return;
    };
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    let actions = [("start-forked", start.as_str()), ("stop-self", "300")];
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&contained(&fixture), &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    with_terminal(&pty)(&mut command);
    let mut sandy = command.spawn().unwrap();
    discard_output(&pty);
    let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
    let left: libc::pid_t = detail(&mut stdout).parse().unwrap();
    // The second line comes after a child of the program has continued it; then it exits.
    detail(&mut stdout);

    let ended = ends_soon(left);
    let left_status = info(left).map(|info| info.pbi_status);
    let sandy_status = info(sandy.id() as libc::pid_t).map(|info| info.pbi_status);
    kill_and_reap(&mut sandy);
    assert!(
        ended,
        "process {left} (status {left_status:?}) outlived the program; sandy has status \
         {sandy_status:?}"
    );
}

/// The forked program starts with the signal actions of sandy's caller, as in the exec model:
/// sandy restores the actions it caught (SIGCHLD, SIGWINCH, SIGINFO) and sets only SIGPIPE,
/// which its Rust runtime ignores, back to the default.
#[test]
fn signal_actions_pass_through_except_sigpipe() {
    let fixture = Fixture::new("contained-actions");
    // SIGHUP, SIGPIPE, SIGCHLD, SIGWINCH, SIGINFO.
    let actions = ["1", "13", "20", "28", "29"].map(|signal| ("signal-disposition", signal));
    let ignoring = |program: String, args: Vec<String>| {
        let mut command = Command::new(program);
        command.args(args);
        // SAFETY: signal(2) is async-signal-safe, so it may run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                for signal in [libc::SIGHUP, libc::SIGCHLD, libc::SIGWINCH] {
                    libc::signal(signal, libc::SIG_IGN);
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        parse(&output)
            .into_iter()
            .map(|line| line.detail)
            .collect::<Vec<_>>()
    };
    let expected = ["ignore", "default", "ignore", "ignore", "default"];
    assert_eq!(
        ignoring(probe_path(), probe_args(&actions)),
        expected,
        "control"
    );
    assert_eq!(
        ignoring(sandy_path(), run_args(&contained(&fixture), &actions)),
        expected
    );
}

/// A process that sandy's caller started before it executed sandy is sandy's child, but the
/// program did not start it. sandy does not wait for it.
#[test]
fn sandy_does_not_wait_for_children_it_inherited() {
    let fixture = Fixture::new("contained-inherited");
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&contained(&fixture), &[("exit", "0")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: fork, close, sleep and _exit are async-signal-safe. The forked process becomes a
    // child of sandy once this process executes sandy.
    unsafe {
        command.pre_exec(|| {
            if libc::fork() == 0 {
                // Closes the spawn's error pipe, so that spawn() returns at once.
                for fd in 3..1024 {
                    libc::close(fd);
                }
                libc::sleep(5);
                libc::_exit(0);
            }
            Ok(())
        });
    }
    let mut sandy = command.spawn().unwrap();
    let exited = exits_soon(&mut sandy);
    kill_and_reap(&mut sandy);
    assert!(
        exited,
        "sandy waited for a process the program did not start"
    );
}

/// `sandy ... | reader`: the reader is in sandy's process group and reads the terminal while the
/// program runs (it waits a second, so sandy has started the program). The program does not use
/// the terminal, so sandy's job keeps it.
#[test]
fn another_process_of_the_job_reads_the_terminal() {
    let fixture = Fixture::new("contained-pipeline");
    let Some(pty) = open_pty() else {
        skip("pty", "no pseudo-terminal available");
        return;
    };
    let quote = |arg: &String| format!("'{arg}'");
    let sandy_command: Vec<String> = [sandy_path()]
        .into_iter()
        .chain(run_args(&contained(&fixture), &[("sleep", "3000")]))
        .map(|arg| quote(&arg))
        .collect();
    let script = format!(
        "{} >/dev/null | (sleep 1; read line < /dev/tty; echo got=$line)",
        sandy_command.join(" ")
    );
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    with_terminal(&pty)(&mut command);
    let mut shell = command.spawn().unwrap();
    discard_output(&pty);
    fs::File::from(pty.master.try_clone().unwrap())
        .write_all(b"hello\n")
        .unwrap();
    let output = output_end(&mut shell);
    let result = output.recv_timeout(TIMEOUT);
    kill_and_reap(&mut shell);
    let output = String::from_utf8_lossy(&result.expect("the reader could not read the terminal"))
        .into_owned();
    assert!(output.contains("got=hello"), "{output}");
}
