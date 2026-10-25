//! Linux behavior of `process.children = "contained"`: sandy stays the program's parent, keeps
//! every process the program starts in one process group, and ends that group. See
//! `crates/sandy-linux/src/contain.rs`.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::linux::*;
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

/// Whether this host can isolate signals, which `contained` needs: with Landlock ABI 6, or below
/// it with a PID namespace. Where it cannot, checks that sandy refuses.
fn supported(fixture: &Fixture) -> bool {
    let check = sandy(["check", "--children", "contained", "--signals", "isolated"]);
    if landlock_abi() >= 6 || check.status.success() {
        return true;
    }
    let output = sandy(run_args(&contained(fixture), &[("env", "PATH")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    skip(
        "landlock-abi-6",
        "signal isolation needs Landlock ABI 6 or a PID namespace; sandy refused",
    );
    false
}

/// The state letter of a process in `/proc/PID/stat`, or `-` when it does not exist.
fn state(pid: libc::pid_t) -> char {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat[stat.rfind(')')? + 2..].chars().next())
        .unwrap_or('-')
}

/// A zombie has ended, although signal 0 still reaches it until its parent reaps it.
fn is_running(pid: libc::pid_t) -> bool {
    !matches!(state(pid), 'Z' | '-')
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

/// Waits until `parent` has a child that runs `name`, that is, until sandy has started the
/// program.
fn wait_for_child(parent: u32, name: &str) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        for entry in fs::read_dir("/proc").unwrap().flatten() {
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            // The name is in parentheses and may contain spaces; the parent follows the state.
            let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
                continue;
            };
            let parent_field = stat[close + 1..].split_whitespace().nth(1);
            if &stat[open + 1..close] == name && parent_field == Some(&parent.to_string()) {
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
    if !supported(&fixture) {
        return;
    }
    // Separate runs: after setsid, the probe leads its group and setpgid fails outside too.
    for action in ["setsid", "setpgid"] {
        controlled(&contained(&fixture), &[(action, "-")])[0].assert_blocked();
    }
}

#[test]
fn the_program_cannot_signal_sandy() {
    let fixture = Fixture::new("contained-parent");
    if !supported(&fixture) {
        return;
    }
    controlled(&contained(&fixture), &[("signal-parent", "-")])[0].assert_blocked();
}

#[test]
fn the_guard_ends_the_group_when_sandy_is_killed() {
    let fixture = Fixture::new("contained-guard");
    if !supported(&fixture) {
        return;
    }
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    let actions = [("start", start.as_str()), ("sleep", LONG_SLEEP)];
    let mut sandy = Command::new(sandy_path())
        .args(run_args(&contained(&fixture), &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let reported: libc::pid_t = line.trim_end().split('\t').nth(3).unwrap().parse().unwrap();
    let pid = common::linux::outside_id(sandy.id(), reported);
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
    if !supported(&fixture) {
        return;
    }
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

#[test]
fn a_failed_start_is_reported() {
    let fixture = Fixture::new("contained-start");
    if !supported(&fixture) {
        return;
    }
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

#[test]
fn the_program_reads_the_terminal() {
    let fixture = Fixture::new("contained-terminal");
    if !supported(&fixture) {
        return;
    }
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
    if !supported(&fixture) {
        return;
    }
    let Some(pty) = open_pty() else {
        skip("pty", "no pseudo-terminal available");
        return;
    };
    let program = fixture.copy_probe("bin");
    let start = format!("{program}\u{1f}sleep\u{1f}{LONG_SLEEP}");
    let actions = [("start", start.as_str()), ("stop-self", "300")];
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&contained(&fixture), &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    with_terminal(&pty)(&mut command);
    let mut sandy = command.spawn().unwrap();
    let mut stdout = BufReader::new(sandy.stdout.take().unwrap());
    let left = common::linux::outside_id(sandy.id(), detail(&mut stdout).parse().unwrap());
    // The second line comes after a child of the program has continued it; then it exits.
    detail(&mut stdout);

    let ended = ends_soon(left);
    let left_state = state(left);
    let sandy_state = state(sandy.id() as libc::pid_t);
    kill_and_reap(&mut sandy);
    assert!(
        ended,
        "process {left} (state {left_state}) outlived the program; sandy is in state {sandy_state}"
    );
}

/// A process that sandy's caller started before it executed sandy is sandy's child, but the
/// program did not start it. sandy does not wait for it.
#[test]
fn sandy_does_not_wait_for_children_it_inherited() {
    let fixture = Fixture::new("contained-inherited");
    if !supported(&fixture) {
        return;
    }
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&contained(&fixture), &[("exit", "0")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: fork, close_range, prctl, sleep and _exit are async-signal-safe. The forked process
    // becomes a child of sandy once this process executes sandy.
    unsafe {
        command.pre_exec(|| {
            if libc::fork() == 0 {
                // Closes the spawn's error pipe, so that spawn() returns at once.
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
                // Ends with its parent, which becomes sandy, so the test leaves nothing behind.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                libc::sleep(30);
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

/// When sandy's caller made it a child subreaper (the flag survives execve), the relay becomes
/// sandy's child. The relay ends after sandy; sandy must not wait for it.
#[test]
fn a_relay_does_not_keep_sandy_from_exiting() {
    let fixture = Fixture::new("contained-relay");
    if !supported(&fixture) {
        return;
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut args = contained(&fixture);
    args.extend([
        "--ip".to_string(),
        "all".to_string(),
        "--expose".to_string(),
        format!("127.0.0.1:{port}=8931"),
    ]);
    let mut command = Command::new(sandy_path());
    command
        .args(run_args(&args, &[("exit", "0")]))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: prctl is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut sandy = command.spawn().unwrap();
    let exited = exits_soon(&mut sandy);
    kill_and_reap(&mut sandy);
    assert!(exited, "sandy did not exit after the program ended");
}

/// `sandy ... | reader`: the reader is in sandy's process group and reads the terminal while the
/// program runs (it waits a second, so sandy has started the program). The program does not use
/// the terminal, so sandy's job keeps it.
#[test]
fn another_process_of_the_job_reads_the_terminal() {
    let fixture = Fixture::new("contained-pipeline");
    if !supported(&fixture) {
        return;
    }
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

/// A program with a write grant on `/proc` could set the out-of-memory priority of sandy's own
/// processes to the maximum, so that the kernel ends the supervisor and the guard before anything
/// else and the program's group outlives them. Both are undumpable, which gives their `/proc`
/// files to root, and both from their first instruction: sandy runs under a filter that holds
/// every `prctl(PR_SET_DUMPABLE, 0)` for a while, so a process that became undumpable only after
/// a fork would leave the program that long to write. The first action is the control: the
/// program may raise its own priority, so a denial for the other two is not the missing grant.
#[test]
fn a_program_cannot_raise_the_oom_priority_of_sandys_helpers() {
    let fixture = Fixture::new("contained-oom");
    if !supported(&fixture) {
        return;
    }
    let mut args = contained(&fixture);
    args.extend(["--read-write", "/proc"].map(String::from));
    // Without a file system view the host's /proc keeps the PID namespace away, and below
    // Landlock ABI 6 nothing else isolates signals.
    let mut check = vec!["check".to_string()];
    check.extend(args.iter().cloned());
    if !sandy(&check).status.success() {
        let refused = sandy(run_args(&args, &[("env", "PATH")]));
        assert_eq!(refused.status.code(), Some(EXIT_FAILURE), "{refused:?}");
        return skip(
            "landlock-abi-6",
            "with /proc granted and no view, contained gets no PID namespace, and signal \
             isolation needs Landlock ABI 6; sandy refused",
        );
    }
    let actions = [
        ("oom-raise", "self"),
        ("oom-raise", "parent"),
        ("oom-raise", "group"),
    ];
    let output = late_undumpable::sandy(&run_args(&args, &actions), Duration::from_millis(500));
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), actions.len(), "{lines:?}");
    lines[0].assert_ok();
    // The supervisor, which is the program's parent, and the guard, which leads its group.
    lines[1].assert_blocked();
    lines[2].assert_blocked();
}

/// Runs sandy under a seccomp filter that holds every `prctl(PR_SET_DUMPABLE, 0)` of sandy and of
/// the processes it starts, so that the order of that call and a fork shows up reliably.
mod late_undumpable {
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Output, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64`.
    #[cfg(target_arch = "x86_64")]
    const NATIVE: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const NATIVE: u32 = 183 | 0x8000_0000 | 0x4000_0000;
    /// The `_IOC` type of the seccomp notification requests, `'!'`.
    const SECCOMP_IOC: u32 = 0x21;

    /// Runs sandy with `args`; each `prctl(PR_SET_DUMPABLE, 0)` waits `delay` before it runs.
    pub fn sandy(args: &[String], delay: Duration) -> Output {
        let mut filter = filter();
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        let program_address = &program as *const libc::sock_fprog as usize;
        let mut ends = [0; 2];
        // SAFETY: socketpair writes two new descriptors into `ends`.
        let made = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                ends.as_mut_ptr(),
            )
        };
        assert_eq!(made, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: both descriptors are new and owned here.
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        let theirs_fd = theirs.as_raw_fd();
        let mut command = Command::new(super::common::sandy_path());
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure runs in the forked child before execve and calls only prctl,
        // seccomp, sendmsg and close, which are async-signal-safe; the filter program it points
        // to lives in this stack frame until `spawn` has returned.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let listener = libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    program_address as *const libc::sock_fprog,
                );
                if listener < 0 {
                    return Err(io::Error::last_os_error());
                }
                let sent = send_descriptor(theirs_fd, listener as RawFd);
                libc::close(listener as RawFd);
                sent
            });
        }
        let child = command.spawn().unwrap();
        drop(theirs);
        drop(filter);
        let listener = receive_descriptor(&ours);
        let done = Arc::new(AtomicBool::new(false));
        let supervisor = {
            let done = Arc::clone(&done);
            std::thread::spawn(move || supervise(&listener, delay, &done))
        };
        let output = child.wait_with_output().unwrap();
        done.store(true, Ordering::Relaxed);
        supervisor.join().unwrap();
        output
    }

    /// Notifies for `prctl(PR_SET_DUMPABLE, 0)` of this architecture and allows every other call.
    fn filter() -> Vec<libc::sock_filter> {
        let arg =
            |index: usize| (offset_of!(libc::seccomp_data, args) + index * size_of::<u64>()) as u32;
        vec![
            load(offset_of!(libc::seccomp_data, arch) as u32),
            equals(NATIVE, 0, 7),
            load(offset_of!(libc::seccomp_data, nr) as u32),
            equals(libc::SYS_prctl as u32, 0, 5),
            load(arg(0)),
            equals(libc::PR_SET_DUMPABLE as u32, 0, 3),
            load(arg(1)),
            equals(0, 0, 1),
            ret(libc::SECCOMP_RET_USER_NOTIF),
            ret(libc::SECCOMP_RET_ALLOW),
        ]
    }

    /// Answers each notification after `delay` by letting the call run, until `done`.
    fn supervise(listener: &OwnedFd, delay: Duration, done: &AtomicBool) {
        let mut sizes = libc::seccomp_notif_sizes {
            seccomp_notif: 0,
            seccomp_notif_resp: 0,
            seccomp_data: 0,
        };
        // SAFETY: the kernel writes the three sizes into the structure.
        let read = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_NOTIF_SIZES,
                0,
                &mut sizes as *mut libc::seccomp_notif_sizes,
            )
        };
        assert_eq!(read, 0, "{}", io::Error::last_os_error());
        let receive = request(0, sizes.seccomp_notif);
        let send = request(1, sizes.seccomp_notif_resp);
        // 64-bit elements keep the buffers aligned for the structures of the kernel's size.
        let mut notification = vec![0u64; usize::from(sizes.seccomp_notif).div_ceil(8)];
        let mut response = vec![0u64; usize::from(sizes.seccomp_notif_resp).div_ceil(8)];
        while !done.load(Ordering::Relaxed) {
            let mut watched = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll reads and writes the one structure passed.
            if unsafe { libc::poll(&mut watched, 1, 100) } <= 0
                || watched.revents & libc::POLLIN == 0
            {
                continue;
            }
            notification.fill(0);
            let request = notification.as_mut_ptr().cast::<libc::seccomp_notif>();
            // SAFETY: the buffer has the size the kernel reported for this request.
            if unsafe { libc::ioctl(listener.as_raw_fd(), receive, request) } < 0 {
                continue;
            }
            std::thread::sleep(delay);
            response.fill(0);
            let answer = response.as_mut_ptr().cast::<libc::seccomp_notif_resp>();
            // SAFETY: both buffers are large enough for their structures; the ioctl filled the
            // request, and the answer is zeroed apart from the two fields set here.
            unsafe {
                (*answer).id = (*request).id;
                (*answer).flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
                libc::ioctl(listener.as_raw_fd(), send, answer);
            }
        }
    }

    /// Sends `descriptor` over the stream socket `socket`. Async-signal-safe.
    fn send_descriptor(socket: RawFd, descriptor: RawFd) -> io::Result<()> {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        // A control buffer for one descriptor, aligned like a cmsghdr.
        let mut control = [0u64; 4];
        // SAFETY: msghdr is plain data; the fields set below point into this stack frame, and
        // CMSG_FIRSTHDR returns a header inside `control`, which is large enough for one
        // descriptor.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            libc::CMSG_DATA(header)
                .cast::<RawFd>()
                .write_unaligned(descriptor);
            if libc::sendmsg(socket, &message, 0) != 1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn receive_descriptor(socket: &OwnedFd) -> OwnedFd {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0u64; 4];
        // SAFETY: as in `send_descriptor`; recvmsg writes at most the buffers it was given, and
        // the descriptor it received is new and owned here.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control) as _;
            let read = libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC);
            assert_eq!(
                read,
                1,
                "sandy did not start: {}",
                io::Error::last_os_error()
            );
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null(), "no descriptor arrived");
            OwnedFd::from_raw_fd(libc::CMSG_DATA(header).cast::<RawFd>().read_unaligned())
        }
    }

    /// A `SECCOMP_IOWR(number, structure)` request number, as linux/seccomp.h builds it.
    fn request(number: u32, size: u16) -> libc::Ioctl {
        const READ_WRITE: u32 = 3;
        (READ_WRITE << 30 | u32::from(size) << 16 | SECCOMP_IOC << 8 | number) as libc::Ioctl
    }

    fn load(offset: u32) -> libc::sock_filter {
        statement((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, offset)
    }

    fn ret(value: u32) -> libc::sock_filter {
        statement((libc::BPF_RET | libc::BPF_K) as u16, value)
    }

    /// Continues with the next instruction when the loaded word is `value`, and jumps `otherwise`
    /// instructions ahead when it is not.
    fn equals(value: u32, then: u8, otherwise: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: then,
            jf: otherwise,
            k: value,
        }
    }

    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
}
