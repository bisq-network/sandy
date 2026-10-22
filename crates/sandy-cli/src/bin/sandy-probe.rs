//! Test helper for the escape tests.
//!
//! Usage: `sandy-probe ACTION TARGET [ACTION TARGET]...`
//!
//! It tries each action and prints one line per action:
//! `ACTION<TAB>TARGET<TAB>RESULT<TAB>DETAIL`. RESULT is `ok`, `denied` (the operating system
//! refused with a permission error) or `error` (any other failure).

use std::fs;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() % 2 != 0 {
        eprintln!("usage: sandy-probe ACTION TARGET [ACTION TARGET]...");
        std::process::exit(2);
    }
    for pair in args.chunks(2) {
        let (action, target) = (&pair[0], &pair[1]);
        let (result, detail) = match perform(action, target) {
            Ok(detail) => ("ok", detail),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                ("denied", error.to_string())
            }
            Err(error) => ("error", error.to_string()),
        };
        let detail = detail.replace(['\t', '\n', '\r'], " ");
        println!("{action}\t{target}\t{result}\t{detail}");
    }
}

fn perform(action: &str, target: &str) -> io::Result<String> {
    match action {
        "read" => {
            let mut content = Vec::new();
            fs::File::open(target)?.read_to_end(&mut content)?;
            Ok(format!("{} bytes", content.len()))
        }
        "list" => Ok(format!("{} entries", fs::read_dir(target)?.count())),
        "write" => fs::write(target, b"probe").map(|()| String::new()),
        "delete" => fs::remove_file(target).map(|()| String::new()),
        "mkdir" => fs::create_dir(target).map(|()| String::new()),
        "set-readonly" => set_readonly(target, true),
        "set-writable" => set_readonly(target, false),
        "exec" => {
            let status = Command::new(target)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            Ok(format!("exit {status}"))
        }
        "tcp-connect" => {
            TcpStream::connect_timeout(&socket_address(target)?, CONNECT_TIMEOUT)?;
            Ok(String::new())
        }
        "tcp-listen" => {
            let listener = TcpListener::bind(socket_address(target)?)?;
            Ok(listener.local_addr()?.to_string())
        }
        "udp-send" => {
            let address = socket_address(target)?;
            let local = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            UdpSocket::bind(local)?.send_to(b"probe", address)?;
            Ok(String::new())
        }
        "unix-connect" => unix_connect(target),
        "env" => std::env::var_os(target)
            .map(|value| value.to_string_lossy().into_owned())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not set")),
        "signal" => signal(target),
        "sleep" => {
            let millis = target
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid duration"))?;
            std::thread::sleep(Duration::from_millis(millis));
            Ok(String::new())
        }
        "spawn" => spawn(target),
        "fd-read" => fd_read(target),
        "resolve" => {
            let addresses = (target, 0).to_socket_addrs()?.count();
            Ok(format!("{addresses} addresses"))
        }
        "tcp-accept" => tcp_accept(target),
        "pipe-connect" => fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(target)
            .map(|_| String::new()),
        "open-process-read" => windows_actions::open_process(target, false),
        "open-process-terminate" => windows_actions::open_process(target, true),
        "handle-path" => windows_actions::handle_path(target),
        "write-dac" => windows_actions::write_dac(target),
        "reg-set-hkcu" => windows_actions::registry_set(target),
        "reg-get-hkcu" => windows_actions::registry_get(target),
        "reg-delete-hkcu" => windows_actions::registry_delete(target),
        "afunix-connect" => windows_actions::afunix_connect(target),
        "ctrl-break-console" => windows_actions::ctrl_break_console(),
        "copy-self" => {
            fs::copy(std::env::current_exe()?, target).map(|bytes| format!("{bytes} bytes"))
        }
        "copy" => {
            let (from, to) = pair(target)?;
            fs::copy(from, to).map(|bytes| format!("{bytes} bytes"))
        }
        "hardlink" => {
            let (from, to) = pair(target)?;
            fs::hard_link(from, to).map(|()| String::new())
        }
        "signal-disposition" => initial_signals::disposition(target),
        action if linux::ACTIONS.contains(&action) => linux::perform(action, target),
        action if macos::ACTIONS.contains(&action) => macos::perform(action, target),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown action",
        )),
    }
}

/// Changes the permissions through the path (Unix `chmod`, Windows file attributes).
fn set_readonly(target: &str, readonly: bool) -> io::Result<String> {
    let mut permissions = fs::metadata(target)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(readonly);
    fs::set_permissions(target, permissions).map(|()| String::new())
}

/// Separates the program and its arguments in the target of `spawn`.
const ARGUMENT_SEPARATOR: char = '\u{1f}';

/// Runs a program with arguments (separated by U+001F) and succeeds when it exits with 0.
fn spawn(target: &str) -> io::Result<String> {
    let mut parts = target.split(ARGUMENT_SEPARATOR);
    let program = parts.next().unwrap_or_default();
    let output = Command::new(program)
        .args(parts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        Ok(String::new())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first_line = stderr.lines().next().unwrap_or_default();
        Err(io::Error::other(format!("{}: {first_line}", output.status)))
    }
}

/// Splits a target of the form `FROM<U+001F>TO`.
fn pair(target: &str) -> io::Result<(&str, &str)> {
    target
        .split_once(ARGUMENT_SEPARATOR)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected FROM U+001F TO"))
}

/// Reads an inherited file descriptor to its end.
#[cfg(unix)]
fn fd_read(target: &str) -> io::Result<String> {
    use std::os::fd::FromRawFd;

    let fd: i32 = target
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid descriptor"))?;
    // SAFETY: fcntl(F_GETFD) only checks that fd is open; it has no memory safety requirements.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is open and nothing else in this process uses it; the File owns it from here.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(format!("{} bytes", content.len()))
}

#[cfg(not(unix))]
fn fd_read(_target: &str) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
}

fn socket_address(target: &str) -> io::Result<SocketAddr> {
    target
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address"))
}

#[cfg(unix)]
fn unix_connect(target: &str) -> io::Result<String> {
    std::os::unix::net::UnixStream::connect(target).map(|_| String::new())
}

#[cfg(not(unix))]
fn unix_connect(_target: &str) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
}

/// Sends signal 0: the kernel performs the permission check but delivers nothing.
#[cfg(unix)]
fn signal(target: &str) -> io::Result<String> {
    let pid: libc::pid_t = target
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
    // SAFETY: kill with signal 0 has no memory safety requirements.
    if unsafe { libc::kill(pid, 0) } == 0 {
        Ok(String::new())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal(_target: &str) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
}

/// Actions for the Linux escape tests (`tests/escape_linux.rs`).
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    pub const ACTIONS: &[&str] = &[
        "open",
        "open-ioctl-only",
        "fchmod-readonly",
        "status-field",
        "read-fd",
        "ptrace-seize",
        "unix-connect-abstract",
        "socketpair",
        "socket",
        "io-uring-setup",
        "tiocsti",
        "tiocgwinsz",
        "shm-attach",
        "setuid-exec",
        "int80-getpid",
        "fchmod-setuid",
        "chmod-setuid",
        "renice-same",
        "prlimit-same",
        "affinity-same",
        "ioprio-same",
        "sigio-signal",
        "pidfd-signal",
        "fanotify-init",
        "await-signal",
        "symlink",
        "mkfifo",
        "opath-read",
        "rename-in",
        "raw-syscall",
        "move-pages",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "open" => fs::File::open(target).map(|_| String::new()),
            "open-ioctl-only" => open_ioctl_only(target),
            "fchmod-readonly" => fchmod_readonly(target),
            "status-field" => status_field(target),
            "read-fd" => read_fd(number(target)?),
            "ptrace-seize" => ptrace_seize(number(target)?),
            "unix-connect-abstract" => {
                let address = SocketAddr::from_abstract_name(target.as_bytes())?;
                UnixStream::connect_addr(&address).map(|_| String::new())
            }
            "socketpair" => socketpair(target),
            "socket" => socket(target),
            "io-uring-setup" => io_uring_setup(),
            "tiocsti" => tiocsti(number(target)?),
            "tiocgwinsz" => tiocgwinsz(number(target)?),
            "shm-attach" => shm_attach(number(target)?),
            "setuid-exec" => setuid_exec(target),
            "int80-getpid" => int80_getpid(),
            "fchmod-setuid" => {
                let file = fs::OpenOptions::new().write(true).open(target)?;
                file.set_permissions(fs::Permissions::from_mode(SETUID_MODE))?;
                Ok(String::new())
            }
            "chmod-setuid" => fs::set_permissions(target, fs::Permissions::from_mode(SETUID_MODE))
                .map(|()| String::new()),
            "renice-same" => renice_same(pid(target)?),
            "prlimit-same" => prlimit_same(pid(target)?),
            "affinity-same" => affinity_same(pid(target)?),
            "ioprio-same" => ioprio_same(pid(target)?),
            "sigio-signal" => sigio_signal(target),
            "pidfd-signal" => pidfd_signal(target),
            "fanotify-init" => fanotify_init(target),
            "await-signal" => await_signal(target),
            "symlink" => symlink(target),
            "mkfifo" => mkfifo(target),
            "opath-read" => opath_read(target),
            "rename-in" => rename_in(target),
            "raw-syscall" => raw_syscall(target),
            "move-pages" => move_pages(target),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    const SETUID_MODE: u32 = 0o4755;

    /// A process ID, or `self` for the probe's own one.
    fn pid(target: &str) -> io::Result<libc::pid_t> {
        if target == "self" {
            return Ok(std::process::id() as libc::pid_t);
        }
        number(target)
    }

    fn check_long(result: libc::c_long) -> io::Result<libc::c_long> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    // The *-same actions read a setting of a process and write the same value back. The kernel
    // checks the permission to change the process, but nothing changes.

    fn renice_same(pid: libc::pid_t) -> io::Result<String> {
        // SAFETY: getpriority returns the raw kernel value (20 - nice) through syscall, so -1 is
        // never a valid result.
        let raw =
            check_long(unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, pid) })?;
        let nice = 20 - raw;
        // SAFETY: setpriority takes no pointers.
        check_long(unsafe { libc::syscall(libc::SYS_setpriority, libc::PRIO_PROCESS, pid, nice) })?;
        Ok(format!("nice {nice}"))
    }

    fn prlimit_same(pid: libc::pid_t) -> io::Result<String> {
        let mut limit = libc::rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: prlimit64 writes one rlimit64 through the last pointer.
        check_long(unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                pid,
                libc::RLIMIT_NOFILE,
                ptr::null::<libc::rlimit64>(),
                &mut limit as *mut libc::rlimit64,
            )
        })?;
        // SAFETY: prlimit64 reads one rlimit64 through the third pointer.
        check_long(unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                pid,
                libc::RLIMIT_NOFILE,
                &limit as *const libc::rlimit64,
                ptr::null_mut::<libc::rlimit64>(),
            )
        })?;
        Ok(String::new())
    }

    fn affinity_same(pid: libc::pid_t) -> io::Result<String> {
        // SAFETY: cpu_set_t is a plain bit set; all zeros is a valid value.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        // SAFETY: the kernel writes at most `size` bytes into `set`.
        check(unsafe { libc::sched_getaffinity(pid, size, &mut set) })?;
        // SAFETY: the kernel reads `size` bytes from `set`.
        check(unsafe { libc::sched_setaffinity(pid, size, &set) })?;
        Ok(String::new())
    }

    fn ioprio_same(pid: libc::pid_t) -> io::Result<String> {
        const IOPRIO_WHO_PROCESS: libc::c_int = 1;
        // SAFETY: ioprio_get and ioprio_set take no pointers.
        let priority =
            check_long(unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, pid) })?;
        // SAFETY: as above.
        check_long(unsafe {
            libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid, priority)
        })?;
        Ok(String::new())
    }

    fn number<T: FromStr>(target: &str) -> io::Result<T> {
        target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid number"))
    }

    /// Delivers a signal to another process through the F_SETOWN / F_SETSIG / SIGIO path.
    ///
    /// `target` is `PID` or `PID:SIGNUM` (default signal is SIGKILL). The kernel delivers the
    /// signal from `send_sigio_to_task`, which checks `security_file_send_sigiotask` rather than
    /// the `task_kill` hook that Landlock's signal scope implements. `kill(PID, SIGNUM)` would be
    /// refused under `signals = "isolated"`; this path is a separate route.
    fn sigio_signal(target: &str) -> io::Result<String> {
        let (pid_str, sig_str) = target.split_once(':').unwrap_or((target, "9"));
        let pid: libc::pid_t = number(pid_str)?;
        let signum: libc::c_int = number(sig_str)?;
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let result = (|| {
            // F_SETSIG (10) chooses the signal that SIGIO delivery sends; libc lacks the constant.
            const F_SETSIG: libc::c_int = 10;
            // SAFETY: F_SETOWN takes an int argument, no pointers.
            check(unsafe { libc::fcntl(read_fd, libc::F_SETOWN, pid) })?;
            // SAFETY: F_SETSIG takes an int argument, no pointers.
            check(unsafe { libc::fcntl(read_fd, F_SETSIG, signum) })?;
            // SAFETY: F_GETFL takes no argument.
            let flags = check(unsafe { libc::fcntl(read_fd, libc::F_GETFL) })?;
            // SAFETY: F_SETFL takes an int argument, no pointers.
            check(unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_ASYNC) })?;
            // Making the read end readable generates SIGIO, delivered to `pid` as `signum`.
            let byte = *b"x";
            // SAFETY: writes one byte from a valid buffer to the pipe.
            if unsafe { libc::write(write_fd, byte.as_ptr().cast(), 1) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // Give the kernel a moment to deliver the signal before the descriptors close.
            std::thread::sleep(Duration::from_millis(50));
            Ok(format!("delivered signal {signum} to {pid}"))
        })();
        close(read_fd);
        close(write_fd);
        result
    }

    /// Opens a pidfd for another process and sends it signal 0 (permission check, no delivery).
    fn pidfd_signal(target: &str) -> io::Result<String> {
        let pid: libc::pid_t = number(target)?;
        // SAFETY: pidfd_open takes a pid and flags, no pointers.
        let pidfd = check(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int })?;
        // SAFETY: pidfd_send_signal with a null siginfo sends the bare signal.
        let result = check(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                0,
                ptr::null::<libc::c_void>(),
                0,
            ) as libc::c_int
        });
        close(pidfd);
        result.map(|_| String::new())
    }

    /// Tries to create an fanotify group and mark `target`. Unprivileged callers normally fail
    /// with EPERM; success would allow watching (and, in some classes, reading) files by path
    /// outside the policy.
    fn fanotify_init(target: &str) -> io::Result<String> {
        const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
        const FAN_CLASS_NOTIF: libc::c_uint = 0x0000_0000;
        // SAFETY: fanotify_init takes two ints, no pointers.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                FAN_CLOEXEC | FAN_CLASS_NOTIF,
                libc::O_RDONLY as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = fd as libc::c_int;
        const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
        const FAN_ACCESS: u64 = 0x0000_0001;
        const FAN_MODIFY: u64 = 0x0000_0002;
        let path = CString::new(target)?;
        // SAFETY: fanotify_mark reads the NUL-terminated path; dirfd AT_FDCWD is -100.
        let marked = unsafe {
            libc::syscall(
                libc::SYS_fanotify_mark,
                fd,
                FAN_MARK_ADD,
                FAN_ACCESS | FAN_MODIFY,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        let outcome = if marked < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(format!("fanotify group watching {target}"))
        };
        close(fd);
        outcome
    }

    /// Installs a handler for `SIGNUM` and waits up to five seconds for it. Exits with code 42 on
    /// delivery. Used as the victim of `sigio-signal` in the escape test.
    fn await_signal(target: &str) -> io::Result<String> {
        use std::sync::atomic::{AtomicBool, Ordering};
        static GOT: AtomicBool = AtomicBool::new(false);
        extern "C" fn handler(_sig: libc::c_int) {
            GOT.store(true, Ordering::SeqCst);
        }
        let signum: libc::c_int = number(target)?;
        // SAFETY: installs a signal handler with an empty mask and no flags.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as *const () as usize;
            check(libc::sigaction(signum, &action, ptr::null_mut()))?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if GOT.load(Ordering::SeqCst) {
                std::process::exit(42);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no signal"))
    }

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    fn close(fd: libc::c_int) {
        // SAFETY: closes a descriptor this module opened and owns.
        unsafe { libc::close(fd) };
    }

    /// Opens with access mode 3: no read or write access, only ioctl.
    fn open_ioctl_only(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: `path` is a valid C string.
        let fd = check(unsafe { libc::open(path.as_ptr(), libc::O_ACCMODE | libc::O_CLOEXEC) })?;
        close(fd);
        Ok(String::new())
    }

    /// Changes the permissions through an open descriptor (fchmod).
    fn fchmod_readonly(target: &str) -> io::Result<String> {
        let file = fs::OpenOptions::new().write(true).open(target)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions).map(|()| String::new())
    }

    fn status_field(name: &str) -> io::Result<String> {
        let status = fs::read_to_string("/proc/self/status")?;
        field(&status, name).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no field"))
    }

    /// The value of `name:` in a /proc status file, with whitespace collapsed.
    fn field(status: &str, name: &str) -> Option<String> {
        status.lines().find_map(|line| {
            let value = line.strip_prefix(name)?.strip_prefix(':')?;
            Some(value.split_whitespace().collect::<Vec<_>>().join(" "))
        })
    }

    fn read_fd(fd: libc::c_int) -> io::Result<String> {
        let mut buffer = [0u8; 64];
        // SAFETY: the buffer is valid for its length.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{count} bytes"))
    }

    /// PTRACE_SEIZE does not stop the tracee. The kernel detaches it when the probe exits.
    fn ptrace_seize(pid: libc::pid_t) -> io::Result<String> {
        let null = ptr::null_mut::<libc::c_void>();
        // SAFETY: PTRACE_SEIZE with null address and data reads no memory of this process.
        if unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null, null) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::new())
    }

    fn socketpair(kind: &str) -> io::Result<String> {
        let kind = match kind {
            "stream" => libc::SOCK_STREAM,
            "seqpacket" => libc::SOCK_SEQPACKET,
            "dgram" => libc::SOCK_DGRAM,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid type")),
        };
        let mut fds = [0; 2];
        // SAFETY: socketpair writes two descriptors into `fds`.
        check(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                kind | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        })?;
        fds.into_iter().for_each(close);
        Ok(String::new())
    }

    fn socket(kind: &str) -> io::Result<String> {
        const AF_ALG: libc::c_int = 38;
        const AF_VSOCK: libc::c_int = 40;
        const NETLINK_ROUTE: libc::c_int = 0;
        const NETLINK_SOCK_DIAG: libc::c_int = 4;
        let (family, kind, protocol) = match kind {
            "unix" => (libc::AF_UNIX, libc::SOCK_STREAM, 0),
            "inet" => (libc::AF_INET, libc::SOCK_STREAM, 0),
            "inet6" => (libc::AF_INET6, libc::SOCK_STREAM, 0),
            "netlink-route" => (libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE),
            "netlink-sock-diag" => (libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_SOCK_DIAG),
            "vsock" => (AF_VSOCK, libc::SOCK_STREAM, 0),
            "alg" => (AF_ALG, libc::SOCK_SEQPACKET, 0),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid family",
                ));
            }
        };
        // SAFETY: socket takes no pointers.
        let fd = check(unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, protocol) })?;
        close(fd);
        Ok(String::new())
    }

    fn io_uring_setup() -> io::Result<String> {
        // struct io_uring_params is 120 bytes; zero means default settings.
        let mut params = [0u32; 30];
        // SAFETY: the kernel reads and writes `params`, which has the size of the struct.
        let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        close(fd as libc::c_int);
        Ok(String::new())
    }

    fn tiocsti(fd: libc::c_int) -> io::Result<String> {
        let byte: libc::c_char = b' ' as libc::c_char;
        // SAFETY: TIOCSTI reads one byte through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCSTI, &byte as *const libc::c_char) })?;
        Ok(String::new())
    }

    fn tiocgwinsz(fd: libc::c_int) -> io::Result<String> {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ writes a winsize through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size as *mut libc::winsize) })?;
        Ok(format!("{}x{}", size.ws_row, size.ws_col))
    }

    fn shm_attach(id: libc::c_int) -> io::Result<String> {
        // SAFETY: shmat with a null address lets the kernel choose where to map the segment.
        let address = unsafe { libc::shmat(id, ptr::null(), libc::SHM_RDONLY) };
        if address as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `address` is the mapping shmat just created.
        unsafe { libc::shmdt(address) };
        Ok(String::new())
    }

    /// Starts `PROGRAM ARGS...` (split at spaces) with a stdin pipe that stays open, then reports
    /// the real, effective, saved and filesystem user IDs of the process after the exec.
    fn setuid_exec(target: &str) -> io::Result<String> {
        let mut words = target.split(' ');
        let program = words.next().unwrap_or_default();
        let name: String = Path::new(program)
            .file_name()
            .map(|name| name.to_string_lossy().chars().take(15).collect())
            .unwrap_or_default();
        let mut child = Command::new(program)
            .args(words)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let result = user_ids_after_exec(child.id(), &name);
        let _ = child.kill();
        let _ = child.wait();
        result
    }

    /// A process that already exited stays readable as a zombie until it is waited for.
    fn user_ids_after_exec(pid: u32, name: &str) -> io::Result<String> {
        let path = format!("/proc/{pid}/status");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = fs::read_to_string(&path)?;
            if field(&status, "Name").as_deref() == Some(name) {
                return field(&status, "Uid")
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no Uid field"));
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "exec not observed"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Queries, through `move_pages`, the NUMA node of one page of another process. The kernel
    /// gates cross-process access with `mm_access` (a ptrace-mode check), which Landlock's ptrace
    /// scope hooks. A permission error means the sandbox blocks it; `ok` means it is reachable.
    fn move_pages(target: &str) -> io::Result<String> {
        let pid: libc::pid_t = number(target)?;
        let page: *const libc::c_void = 0x1000 as *const libc::c_void;
        let pages = [page];
        let mut status = [0i32; 1];
        // SAFETY: move_pages reads one page pointer and writes one status int; nodes is null, so
        // it only queries. A bad page address yields a per-page status, not undefined behavior.
        let result = unsafe {
            libc::syscall(
                libc::SYS_move_pages,
                pid,
                1usize,
                pages.as_ptr(),
                ptr::null::<libc::c_int>(),
                status.as_mut_ptr(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("queried process {pid}, status {}", status[0]))
    }

    /// `NR` or `NR:A0:A1:...`: invokes the raw system call `NR` with up to six integer arguments
    /// (default 0). Reports the return value, or `denied`/`error` from errno. Used to see whether
    /// the seccomp filter lets a given call through to the kernel.
    fn raw_syscall(target: &str) -> io::Result<String> {
        let mut parts = target.split(':');
        let nr: libc::c_long = number(parts.next().unwrap_or_default())?;
        let mut args = [0 as libc::c_long; 6];
        for (slot, value) in args.iter_mut().zip(parts) {
            *slot = number(value)?;
        }
        // SAFETY: a raw syscall with integer arguments has no memory safety requirement here;
        // callers pass 0 for pointer arguments.
        let result =
            unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("ret {result}"))
    }

    /// `LINK::DEST`: creates a symbolic link at `LINK` that points to `DEST`.
    fn symlink(target: &str) -> io::Result<String> {
        let (link, dest) = target
            .split_once("::")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected LINK::DEST"))?;
        std::os::unix::fs::symlink(dest, link).map(|()| format!("{link} -> {dest}"))
    }

    /// Creates a FIFO at `target`.
    fn mkfifo(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: mknod reads the NUL-terminated path; S_IFIFO needs no device number.
        check(unsafe { libc::mknod(path.as_ptr(), libc::S_IFIFO | 0o600, 0) })?;
        Ok(String::new())
    }

    /// `SRC::DST`: creates a hard link `DST` to the existing file `SRC`. If `SRC` is outside the
    /// policy and `DST` is in a writable path, a success would bring the outside inode into a
    /// readable location.
    /// Opens `target` with O_PATH (needs no Landlock right), then tries to reopen it readable
    /// through the O_PATH descriptor with AT_EMPTY_PATH and read its first bytes.
    fn opath_read(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: open with a valid C string path.
        let dirfd = check(unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })?;
        let empty = CString::new("").unwrap();
        // SAFETY: openat with AT_EMPTY_PATH reopens the file the O_PATH fd refers to.
        let reopened = unsafe {
            libc::openat(
                dirfd,
                empty.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::AT_EMPTY_PATH,
            )
        };
        if reopened < 0 {
            let error = io::Error::last_os_error();
            close(dirfd);
            return Err(error);
        }
        let result = read_fd(reopened);
        close(reopened);
        close(dirfd);
        result
    }

    /// `SRC::DST`: renames `SRC` to `DST` (rename brings no new inode in, but tests the Refer
    /// boundary for moving an outside file into a writable directory).
    fn rename_in(target: &str) -> io::Result<String> {
        let (src, dst) = target
            .split_once("::")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected SRC::DST"))?;
        fs::rename(src, dst).map(|()| format!("{src} -> {dst}"))
    }

    /// getpid through the 32-bit system call entry (number 20 in the i386 table).
    #[cfg(target_arch = "x86_64")]
    fn int80_getpid() -> io::Result<String> {
        let result: i32;
        // SAFETY: the i386 getpid call takes no arguments and touches no memory. The 32-bit entry
        // may clobber r8 to r11.
        unsafe {
            std::arch::asm!(
                "int 0x80",
                inlateout("eax") 20i32 => result,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                options(nostack),
            );
        }
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(result.to_string())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn int80_getpid() -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "x86_64 only"))
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use std::io;

    pub const ACTIONS: &[&str] = &[];

    pub fn perform(_action: &str, _target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }
}

/// Accepts one TCP connection on `target` within `ACCEPT_TIMEOUT`. The escape tests connect from
/// outside the sandbox while this action waits.
fn tcp_accept(target: &str) -> io::Result<String> {
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
    let listener = TcpListener::bind(socket_address(target)?)?;
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + ACCEPT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((_, peer)) => return Ok(format!("accepted {peer}")),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no connection"));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Windows-specific actions. They report `Unsupported` elsewhere.
#[cfg(windows)]
mod windows_actions {
    use std::fs;
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::ptr;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, TRUE};
    use windows_sys::Win32::Networking::WinSock::{
        AF_UNIX, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, WSADATA, WSAGetLastError,
        WSAStartup, closesocket, connect, socket,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, GetFinalPathNameByHandleW, WRITE_DAC,
    };
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey,
        RegDeleteKeyValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, PROCESS_VM_READ};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
    }

    /// Opens the process with `PROCESS_VM_READ` or `PROCESS_TERMINATE`. It never reads memory
    /// and never terminates anything.
    pub fn open_process(target: &str, terminate: bool) -> io::Result<String> {
        let pid: u32 = target.parse().map_err(|_| invalid("invalid pid"))?;
        let access = if terminate {
            PROCESS_TERMINATE
        } else {
            PROCESS_VM_READ
        };
        // SAFETY: OpenProcess has no memory safety preconditions.
        let handle = unsafe { OpenProcess(access, FALSE, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: handle is a new handle owned by this function.
        unsafe { CloseHandle(handle) };
        Ok(String::new())
    }

    /// Prints the file a handle value refers to in this process. A handle that was not
    /// inherited is invalid here, or refers to another object.
    pub fn handle_path(target: &str) -> io::Result<String> {
        let value: usize = target.parse().map_err(|_| invalid("invalid handle"))?;
        let mut buffer = [0u16; 1024];
        // SAFETY: the kernel validates the handle value; the buffer length is passed.
        let len = unsafe {
            GetFinalPathNameByHandleW(value as HANDLE, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        } as usize;
        if len == 0 || len >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(String::from_utf16_lossy(&buffer[..len]))
    }

    /// Opens a file or directory for changing its DACL.
    pub fn write_dac(target: &str) -> io::Result<String> {
        fs::OpenOptions::new()
            .access_mode(WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(target)
            .map(|_| String::new())
    }

    /// `KEY\VALUE` below HKEY_CURRENT_USER.
    fn registry_target(target: &str) -> io::Result<(Vec<u16>, Vec<u16>)> {
        let (key, value) = target
            .rsplit_once('\\')
            .ok_or_else(|| invalid("expected KEY\\VALUE"))?;
        Ok((wide(key), wide(value)))
    }

    fn status(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    pub fn registry_set(target: &str) -> io::Result<String> {
        let (key, value) = registry_target(target)?;
        let mut handle: HKEY = ptr::null_mut();
        // SAFETY: key is NUL-terminated and handle is a valid out pointer.
        status(unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut handle,
            )
        })?;
        let data = wide("probe");
        // SAFETY: handle is open; data is NUL-terminated and its size in bytes is passed.
        let result = status(unsafe {
            RegSetValueExW(
                handle,
                value.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        });
        // SAFETY: handle is open and closed exactly once.
        unsafe { RegCloseKey(handle) };
        result.map(|()| String::new())
    }

    pub fn registry_get(target: &str) -> io::Result<String> {
        let (key, value) = registry_target(target)?;
        let mut buffer = [0u16; 256];
        let mut size = (buffer.len() * 2) as u32;
        // SAFETY: key and value are NUL-terminated; size holds the buffer size in bytes.
        status(unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        })?;
        let units = (size as usize / 2).saturating_sub(1);
        Ok(String::from_utf16_lossy(&buffer[..units]))
    }

    pub fn registry_delete(target: &str) -> io::Result<String> {
        let (key, value) = registry_target(target)?;
        // SAFETY: key and value are NUL-terminated.
        status(unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) })
            .map(|()| String::new())
    }

    /// Connects to an AF_UNIX socket file.
    pub fn afunix_connect(target: &str) -> io::Result<String> {
        // SAFETY: WSADATA is plain data; WSAStartup fills it.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: data is a valid out pointer.
        let code = unsafe { WSAStartup(0x0202, &mut data) };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        let mut address = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        if target.len() >= address.sun_path.len() {
            return Err(invalid("path too long"));
        }
        for (slot, byte) in address.sun_path.iter_mut().zip(target.bytes()) {
            *slot = byte as i8;
        }
        // SAFETY: socket has no memory safety preconditions.
        let handle = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if handle == INVALID_SOCKET {
            // SAFETY: WSAGetLastError has no preconditions.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        // SAFETY: address is a SOCKADDR_UN and its size is passed.
        let result = unsafe {
            connect(
                handle,
                (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(),
                std::mem::size_of::<SOCKADDR_UN>() as i32,
            )
        };
        let outcome = if result == 0 {
            Ok(String::new())
        } else {
            // SAFETY: WSAGetLastError has no preconditions.
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        };
        // SAFETY: handle is an open socket, closed exactly once.
        unsafe { closesocket(handle) };
        outcome
    }

    /// Sends Ctrl+Break to every process attached to the console of this process, and
    /// survives it itself.
    pub fn ctrl_break_console() -> io::Result<String> {
        unsafe extern "system" fn ignore(_event: u32) -> windows_sys::core::BOOL {
            TRUE
        }
        // SAFETY: ignore has the signature of a HandlerRoutine and lives for the whole process.
        if unsafe { SetConsoleCtrlHandler(Some(ignore), TRUE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GenerateConsoleCtrlEvent has no memory safety preconditions.
        if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Handlers run on new threads in each process; give them time before this one exits.
        std::thread::sleep(Duration::from_millis(500));
        Ok(String::new())
    }
}

#[cfg(not(windows))]
mod windows_actions {
    use std::io;

    fn unsupported() -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }

    pub fn open_process(_target: &str, _terminate: bool) -> io::Result<String> {
        unsupported()
    }

    pub fn handle_path(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn write_dac(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn registry_set(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn registry_get(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn registry_delete(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn afunix_connect(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn ctrl_break_console() -> io::Result<String> {
        unsupported()
    }
}

/// Actions for the macOS escape tests (`tests/escape_macos.rs`).
#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, c_char};
    use std::io;
    use std::ptr;

    pub const ACTIONS: &[&str] = &["clone", "ptrace-attach"];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "clone" => clone(target),
            "ptrace-attach" => ptrace_attach(target),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    /// clonefile(2) with a source path, which the kernel does not open for reading first.
    fn clone(target: &str) -> io::Result<String> {
        let (from, to) = super::pair(target)?;
        let c = |path: &str| {
            CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))
        };
        let (from, to) = (c(from)?, c(to)?);
        // SAFETY: both arguments are NUL-terminated strings that outlive the call.
        if unsafe { libc::clonefile(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            Ok(String::new())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Attaches with PT_ATTACHEXC, as debuggers do, and detaches at once.
    fn ptrace_attach(target: &str) -> io::Result<String> {
        let pid: libc::pid_t = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
        // SAFETY: PT_ATTACHEXC reads no memory through its pointer argument.
        if unsafe { libc::ptrace(libc::PT_ATTACHEXC, pid, ptr::null_mut(), 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: PT_DETACH with address 1 resumes the process where it stopped; no memory is
        // accessed.
        unsafe {
            libc::ptrace(
                libc::PT_DETACH,
                pid,
                ptr::without_provenance_mut::<c_char>(1),
                0,
            )
        };
        Ok("attached".to_string())
    }
}

#[cfg(not(target_os = "macos"))]
mod macos {
    use std::io;

    pub const ACTIONS: &[&str] = &[];

    pub fn perform(_action: &str, _target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }
}

/// Signal dispositions as the program inherited them. The Rust runtime ignores SIGPIPE before
/// main runs, so a load-time initializer records them first.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod initial_signals {
    use std::io;
    use std::mem::MaybeUninit;
    use std::ptr;
    use std::sync::atomic::{AtomicU8, Ordering};

    const SIGNALS: usize = 32;
    const DEFAULT: u8 = 1;
    const IGNORE: u8 = 2;
    const HANDLER: u8 = 3;

    static DISPOSITIONS: [AtomicU8; SIGNALS] = [const { AtomicU8::new(0) }; SIGNALS];

    #[used]
    #[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
    #[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
    static RECORD: extern "C" fn() = record;

    extern "C" fn record() {
        for (signal, slot) in DISPOSITIONS.iter().enumerate().skip(1) {
            let mut action = MaybeUninit::<libc::sigaction>::zeroed();
            // SAFETY: a null new action only reads the current one into a valid buffer.
            if unsafe { libc::sigaction(signal as libc::c_int, ptr::null(), action.as_mut_ptr()) }
                == 0
            {
                // SAFETY: sigaction succeeded and filled the buffer.
                let handler = unsafe { action.assume_init() }.sa_sigaction;
                let value = match handler {
                    libc::SIG_DFL => DEFAULT,
                    libc::SIG_IGN => IGNORE,
                    _ => HANDLER,
                };
                slot.store(value, Ordering::Relaxed);
            }
        }
    }

    pub fn disposition(target: &str) -> io::Result<String> {
        let signal: usize = target
            .parse()
            .ok()
            .filter(|signal| (1..SIGNALS).contains(signal))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid signal"))?;
        match DISPOSITIONS[signal].load(Ordering::Relaxed) {
            DEFAULT => Ok("default".to_string()),
            IGNORE => Ok("ignore".to_string()),
            HANDLER => Ok("handler".to_string()),
            _ => Err(io::Error::other("not recorded")),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod initial_signals {
    use std::io;

    pub fn disposition(_target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }
}
