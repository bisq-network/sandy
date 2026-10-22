//! Linux-specific escape tests. Like `escape.rs`, each denial is checked against a control run
//! outside the sandbox. Behavior that depends on the Landlock ABI is checked against the ABI
//! the kernel reports, so the tests pass on every kernel that sandy supports.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn skip(reason: &str) {
    eprintln!("skipped: {reason}");
}

/// The Landlock ABI of the running kernel, 0 without Landlock.
fn landlock_abi() -> i64 {
    // SAFETY: with a null attribute, size 0 and the VERSION flag the kernel only returns the ABI.
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
        return skip(&format!("no session bus socket at {socket}"));
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
            skip(&format!(
                "socket {family} fails outside: {}",
                control[0].detail
            ));
            continue;
        }
        probe_inside(&ip, &[("socket", family)])[0].assert_blocked();
    }
    let lines = probe_inside(&[], &[("socket", "netlink-route"), ("socket", "inet")]);
    lines[0].assert_blocked();
    lines[1].assert_blocked();
}

#[test]
fn parent_memory_and_environment_are_unreadable() {
    let parent = parent_pid();
    let (mem, environ) = (
        format!("/proc/{parent}/mem"),
        format!("/proc/{parent}/environ"),
    );
    // With /proc readable, only the process isolation stops these reads.
    let proc_readable = args(&["--read", "/proc"]);
    let lines = controlled(
        &proc_readable,
        &[
            ("open", &mem),
            ("read", &environ),
            ("read", "/proc/self/status"),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
    lines[2].assert_ok();
}

#[test]
fn parent_cannot_be_traced() {
    let parent = parent_pid();
    let control = probe_outside(&[("ptrace-seize", &parent)]);
    if control[0].result != "ok" {
        return skip(&format!("ptrace fails outside: {}", control[0].detail));
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
        return skip("Landlock ABI 6 is required for signal isolation; sandy refused");
    }
    controlled(&isolated, &[("signal", &parent)])[0].assert_blocked();
    probe_inside(&[], &[("signal", &parent)])[0].assert_ok();
}

/// A pseudo-terminal pair. The child that gets the slave as standard input makes it its
/// controlling terminal, so TIOCSTI is not refused for a foreign terminal.
struct Pty {
    _master: OwnedFd,
    slave: OwnedFd,
}

fn open_pty() -> Option<Pty> {
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
        if libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) != 0 {
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
            _master: master,
            slave: OwnedFd::from_raw_fd(slave),
        })
    }
}

fn with_terminal(pty: &Pty) -> impl Fn(&mut Command) + '_ {
    move |command| {
        command.stdin(Stdio::from(pty.slave.try_clone().unwrap()));
        // SAFETY: setsid and ioctl are async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

#[test]
fn terminal_input_injection_is_denied() {
    let Some(pty) = open_pty() else {
        return skip("no pseudo-terminal available");
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

#[test]
fn io_uring_is_denied() {
    let control = probe_outside(&[("io-uring-setup", "-")]);
    if control[0].result != "ok" {
        return skip(&format!("io_uring fails outside: {}", control[0].detail));
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
        return skip("System V shared memory is unavailable");
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
        return skip("no setuid-root su");
    };
    // su waits for a password on the open stdin pipe and is killed before it gets one.
    let command = format!("{} -c true nobody", su.display());
    let control = probe_outside(&[("setuid-exec", &command)]);
    if control[0].result != "ok" || effective_uid(&control[0]) != "0" {
        return skip(&format!("su does not run as root outside: {control:?}"));
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
        return skip("the 32-bit system call entry is unavailable outside");
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
            skip(&format!("{} is not installed", program[0]));
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
