//! Test helper for the escape tests.
//!
//! Usage: `sandy-probe ACTION TARGET [ACTION TARGET]...`
//!
//! It tries each action and prints one line per action:
//! `ACTION<TAB>TARGET<TAB>RESULT<TAB>DETAIL`. RESULT is `ok`, `denied` (the operating system
//! refused with a permission error) or `error` (any other failure).

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// What `tcp-send` writes before it exits.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";

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
        // Flush now so a later action that crashes the process does not lose earlier results.
        use std::io::Write;
        let _ = io::stdout().flush();
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
        "signal-stop" => signal_stop(target),
        "sleep" => {
            let millis = target
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid duration"))?;
            std::thread::sleep(Duration::from_millis(millis));
            Ok(String::new())
        }
        "spawn" => spawn(target),
        "start" => start(target),
        // argv[0] as the program received it; the target is ignored.
        "arg0" => Ok(std::env::args_os()
            .next()
            .map(|arg| arg.to_string_lossy().into_owned())
            .unwrap_or_default()),
        "exit" => std::process::exit(
            target
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid status"))?,
        ),
        "read-line" => {
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            Ok(line.trim_end().to_string())
        }
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
        "afunix-accept" => windows_actions::afunix_accept(target),
        "com-activate" => windows_actions::com_activate(target),
        "load-library" => windows_actions::load_library(target),
        // Connects to the AF_UNIX socket whose path the file `target` holds; the test writes the
        // path there while the program runs.
        "afunix-connect-file" => {
            windows_actions::afunix_connect(fs::read_to_string(target)?.trim())
        }
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
        "tcp-send" => {
            let mut stream = TcpStream::connect_timeout(&socket_address(target)?, CONNECT_TIMEOUT)?;
            stream.write_all(TCP_SEND_PAYLOAD)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            Ok(format!("{} bytes", TCP_SEND_PAYLOAD.len()))
        }
        // ADDRESS<U+001F>COUNT: listens on ADDRESS, greets each connection with "hi\n" and keeps
        // them all open until COUNT were accepted (at most a minute), then returns.
        "tcp-serve" => {
            let (address, count) = pair(target)?;
            let count: usize = count
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
            let listener = TcpListener::bind(socket_address(address)?)?;
            listener.set_nonblocking(true)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut held = Vec::with_capacity(count);
            while held.len() < count {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false)?;
                        stream.write_all(b"hi\n")?;
                        held.push(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("{} of {count} connections", held.len()),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(format!("{count} connections"))
        }
        // ADDRESS<U+001F>COUNT: sends COUNT bytes, ends its side and returns, as a program that
        // writes a stream and exits.
        "tcp-send-many" => {
            let (address, count) = pair(target)?;
            let count: usize = count
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
            let mut stream =
                TcpStream::connect_timeout(&socket_address(address)?, CONNECT_TIMEOUT)?;
            let chunk = vec![b'x'; 64 * 1024];
            let mut left = count;
            while left > 0 {
                let part = left.min(chunk.len());
                stream.write_all(&chunk[..part])?;
                left -= part;
            }
            stream.shutdown(std::net::Shutdown::Write)?;
            Ok(format!("{count} bytes"))
        }
        action if unix::ACTIONS.contains(&action) => unix::perform(action, target),
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

/// Starts a program with arguments (separated by U+001F) without waiting for it and reports its
/// process ID. The program gets no standard streams, so it does not keep the caller's output open.
fn start(target: &str) -> io::Result<String> {
    let mut parts = target.split(ARGUMENT_SEPARATOR);
    let program = parts.next().unwrap_or_default();
    let child = Command::new(program)
        .args(parts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child.id().to_string())
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

/// Sends SIGSTOP to the process the target names. With `-` as the target the process ID comes
/// from the first line of standard input, because a test cannot know the ID of a process that
/// sandy starts before the program runs.
#[cfg(unix)]
fn signal_stop(target: &str) -> io::Result<String> {
    let mut from_stdin = String::new();
    let id = if target == "-" {
        io::stdin().read_line(&mut from_stdin)?;
        from_stdin.trim()
    } else {
        target
    };
    let pid: libc::pid_t = id
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
    // SAFETY: kill takes a process ID and a signal.
    if unsafe { libc::kill(pid, libc::SIGSTOP) } == 0 {
        Ok(pid.to_string())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_stop(_target: &str) -> io::Result<String> {
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
        "oom-raise",
        "prlimit-same",
        "affinity-same",
        "ioprio-same",
        "sigio-signal",
        "pidfd-signal",
        "fanotify-init",
        "symlink",
        "mkfifo",
        "opath-read",
        "rename-in",
        "raw-syscall",
        "move-pages",
        "fork",
        "vfork",
        "clone-process",
        "posix-spawn",
        "thread",
        "socketpair-bind",
        "setxattr-path",
        "setxattr-fd",
        "chown-path",
        "utime-path",
        "utime-fd",
        "winsize-path",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "socketpair-bind" => socketpair_bind(target),
            "setxattr-path" => setxattr_path(target),
            "setxattr-fd" => setxattr_fd(target),
            "chown-path" => chown_path(target),
            "utime-path" => utime_path(target),
            "utime-fd" => utime_fd(target),
            "winsize-path" => winsize_path(target),
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
            "oom-raise" => oom_raise(target),
            "prlimit-same" => prlimit_same(pid(target)?),
            "affinity-same" => affinity_same(pid(target)?),
            "ioprio-same" => ioprio_same(pid(target)?),
            "sigio-signal" => sigio_signal(target),
            "pidfd-signal" => pidfd_signal(target),
            "fanotify-init" => fanotify_init(target),
            "symlink" => symlink(target),
            "mkfifo" => mkfifo(target),
            "opath-read" => opath_read(target),
            "rename-in" => rename_in(target),
            "raw-syscall" => raw_syscall(target),
            "move-pages" => move_pages(target),
            "fork" => fork_raw(),
            "vfork" => vfork_raw(),
            "clone-process" => clone_process(),
            "posix-spawn" => posix_spawn(target),
            "thread" => std::thread::spawn(|| 42)
                .join()
                .map(|value| format!("joined {value}"))
                .map_err(|_| io::Error::other("the thread panicked")),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    const SETUID_MODE: u32 = 0o4755;

    /// Binds one end of a stream socket pair to `target`: an abstract name when it starts with
    /// `@`, otherwise a pathname. socketpair stays allowed with `unix_sockets = "none"`, so this
    /// shows whether the program can still take a name that processes outside the sandbox use.
    fn socketpair_bind(target: &str) -> io::Result<String> {
        let (is_abstract, name) = match target.strip_prefix('@') {
            Some(name) => (true, name),
            None => (false, target),
        };
        // SAFETY: sockaddr_un is plain data; all zeros is a valid value.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // An abstract name starts after a NUL byte.
        let start = usize::from(is_abstract);
        if start + name.len() >= address.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        for (slot, byte) in address.sun_path[start..].iter_mut().zip(name.bytes()) {
            *slot = byte as libc::c_char;
        }
        // Abstract names have no terminating NUL; pathnames include it.
        let length = std::mem::size_of::<libc::sa_family_t>()
            + start
            + name.len()
            + usize::from(!is_abstract);
        let mut fds = [0; 2];
        // SAFETY: socketpair writes two descriptors into `fds`.
        check(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        })?;
        // SAFETY: `address` is a valid sockaddr_un and `length` does not exceed its size.
        let bound = check(unsafe {
            libc::bind(
                fds[0],
                (&address as *const libc::sockaddr_un).cast(),
                length as libc::socklen_t,
            )
        });
        fds.into_iter().for_each(close);
        bound.map(|_| format!("bound {target}"))
    }

    const XATTR_NAME: &[u8] = b"user.sandy-probe\0";

    /// setxattr through the path.
    fn setxattr_path(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: the path and the name are NUL-terminated; the value is one valid byte.
        check(unsafe {
            libc::setxattr(
                path.as_ptr(),
                XATTR_NAME.as_ptr().cast(),
                b"x".as_ptr().cast(),
                1,
                0,
            )
        })?;
        Ok(String::new())
    }

    /// fsetxattr through a descriptor opened for reading.
    fn setxattr_fd(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::File::open(target)?;
        // SAFETY: the name is NUL-terminated; the value is one valid byte.
        check(unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                XATTR_NAME.as_ptr().cast(),
                b"x".as_ptr().cast(),
                1,
                0,
            )
        })?;
        Ok(String::new())
    }

    /// chown through the path, keeping owner and group (-1): the kernel performs the call but
    /// nothing changes.
    fn chown_path(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: the path is NUL-terminated.
        check(unsafe { libc::fchownat(libc::AT_FDCWD, path.as_ptr(), u32::MAX, u32::MAX, 0) })?;
        Ok(String::new())
    }

    /// utimensat with a path; null times mean "now".
    fn utime_path(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: the path is NUL-terminated and the times pointer may be null.
        check(unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), ptr::null(), 0) })?;
        Ok(String::new())
    }

    /// futimens on a descriptor opened for writing; null times mean "now".
    fn utime_fd(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::OpenOptions::new().write(true).open(target)?;
        // SAFETY: the times pointer may be null.
        check(unsafe { libc::futimens(file.as_raw_fd(), ptr::null()) })?;
        Ok(String::new())
    }

    /// Opens a terminal device by path and queries its window size, a device ioctl.
    fn winsize_path(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY)
            .open(target)?;
        tiocgwinsz(file.as_raw_fd())
    }

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

    /// Raises the out-of-memory priority of a process to the maximum through `/proc`, which the
    /// kernel allows for every process of the same user whose `/proc` entry may be written. The
    /// target is `self`, `parent` for the process that started this one, `group` for the leader
    /// of its process group, or a process ID.
    fn oom_raise(target: &str) -> io::Result<String> {
        let pid = match target {
            // SAFETY: getppid and getpgrp have no preconditions.
            "parent" => unsafe { libc::getppid() },
            // SAFETY: as above.
            "group" => unsafe { libc::getpgrp() },
            id => pid(id)?,
        };
        let path = format!("/proc/{pid}/oom_score_adj");
        let before = fs::read_to_string(&path)?;
        fs::write(&path, b"1000")?;
        Ok(format!("pid {pid} was {}", before.trim()))
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

    /// Waits for `child` and reports its exit status.
    fn reap(child: libc::pid_t) -> io::Result<String> {
        let mut status = 0;
        // SAFETY: waits for a child this process created.
        if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("child {child} exited with {status}"))
    }

    /// The fork system call itself (glibc's fork() uses clone).
    #[cfg(target_arch = "x86_64")]
    fn fork_raw() -> io::Result<String> {
        // SAFETY: the child only calls _exit.
        match unsafe { libc::syscall(libc::SYS_fork) } {
            -1 => Err(io::Error::last_os_error()),
            // SAFETY: ends the child at once.
            0 => unsafe { libc::_exit(0) },
            child => reap(child as libc::pid_t),
        }
    }

    /// The vfork system call. The child shares the parent's memory and stack, so it calls exit in
    /// the same assembly block and never returns into Rust code.
    #[cfg(target_arch = "x86_64")]
    fn vfork_raw() -> io::Result<String> {
        let result: i64;
        // SAFETY: the child runs only the exit system call; the parent continues with the result
        // of vfork in rax. rcx and r11 are clobbered by the syscall instruction.
        unsafe {
            std::arch::asm!(
                "syscall",
                "test rax, rax",
                "jnz 2f",
                "mov eax, 60",
                "xor edi, edi",
                "syscall",
                "2:",
                inlateout("rax") libc::SYS_vfork => result,
                out("rcx") _,
                out("r11") _,
                out("rdi") _,
                options(nostack),
            );
        }
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result as i32));
        }
        reap(result as libc::pid_t)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn fork_raw() -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "x86_64 only"))
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn vfork_raw() -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "x86_64 only"))
    }

    /// clone without CLONE_THREAD and without CLONE_VM: a new process with its own memory.
    fn clone_process() -> io::Result<String> {
        // SAFETY: without CLONE_VM the child has its own copy of the memory and only calls _exit.
        match unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) } {
            -1 => Err(io::Error::last_os_error()),
            // SAFETY: ends the child at once.
            0 => unsafe { libc::_exit(0) },
            child => reap(child as libc::pid_t),
        }
    }

    /// posix_spawn of `target` without arguments, as the C library does it (clone with
    /// CLONE_VM | CLONE_VFORK).
    fn posix_spawn(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        let argv = [path.as_ptr().cast_mut(), ptr::null_mut()];
        let envp = [ptr::null_mut::<libc::c_char>()];
        let mut child: libc::pid_t = 0;
        // SAFETY: path, argv and envp are valid, null-terminated, and outlive the call.
        let error = unsafe {
            libc::posix_spawn(
                &mut child,
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        reap(child)
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

    /// Creates an fanotify group and marks `target`, as an unprivileged process can since Linux
    /// 5.13: a notification group that reports file IDs (FAN_REPORT_FID) and inode marks only.
    /// It reports events, not file contents.
    fn fanotify_init(target: &str) -> io::Result<String> {
        const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
        const FAN_CLASS_NOTIF: libc::c_uint = 0x0000_0000;
        const FAN_REPORT_FID: libc::c_uint = 0x0000_0200;
        // SAFETY: fanotify_init takes two ints, no pointers.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_FID,
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
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegGetValueW, RegSetValueExW,
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

    /// Sets the value, and creates the key if a fresh user profile does not have it yet.
    pub fn registry_set(target: &str) -> io::Result<String> {
        let (key, value) = registry_target(target)?;
        let mut handle: HKEY = ptr::null_mut();
        // SAFETY: key is NUL-terminated; handle is a valid out pointer; the class, security
        // attributes and disposition are optional and null.
        status(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
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

    /// Listens on an AF_UNIX socket file and accepts one connection within 10 seconds. The
    /// escape tests connect from outside the sandbox while this action waits.
    pub fn afunix_accept(target: &str) -> io::Result<String> {
        use windows_sys::Win32::Networking::WinSock::{
            FD_SET, SOCKET, TIMEVAL, accept, bind, listen, select,
        };

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
        let last_error = || {
            // SAFETY: WSAGetLastError has no preconditions.
            io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
        };
        // SAFETY: socket has no memory safety preconditions.
        let listener: SOCKET = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if listener == INVALID_SOCKET {
            return Err(last_error());
        }
        let outcome = (|| {
            // SAFETY: address is a SOCKADDR_UN and its size is passed.
            let bound = unsafe {
                bind(
                    listener,
                    (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(),
                    std::mem::size_of::<SOCKADDR_UN>() as i32,
                )
            };
            // SAFETY: listener is a bound socket.
            if bound != 0 || unsafe { listen(listener, 1) } != 0 {
                return Err(last_error());
            }
            let mut ready = FD_SET {
                fd_count: 1,
                fd_array: [0; 64],
            };
            ready.fd_array[0] = listener;
            let timeout = TIMEVAL {
                tv_sec: 10,
                tv_usec: 0,
            };
            // SAFETY: ready holds one valid socket; the other sets are null.
            let count =
                unsafe { select(0, &mut ready, ptr::null_mut(), ptr::null_mut(), &timeout) };
            match count {
                0 => Err(io::Error::new(io::ErrorKind::TimedOut, "no connection")),
                n if n < 0 => Err(last_error()),
                _ => {
                    // SAFETY: listener has a pending connection; the peer address is not needed.
                    let peer = unsafe { accept(listener, ptr::null_mut(), ptr::null_mut()) };
                    if peer == INVALID_SOCKET {
                        return Err(last_error());
                    }
                    // SAFETY: peer is an open socket, closed exactly once.
                    unsafe { closesocket(peer) };
                    Ok("accepted".to_string())
                }
            }
        })();
        // SAFETY: listener is an open socket, closed exactly once.
        unsafe { closesocket(listener) };
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

    /// Loads `target` as a module with `LoadLibraryExW`. This maps the image for execution and
    /// needs `FILE_EXECUTE` on the file, so it is an execute vector that runs in this process and
    /// does not need a child process (unlike `exec`). `ERROR_ACCESS_DENIED` reports `denied`.
    pub fn load_library(target: &str) -> io::Result<String> {
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryExW;
        let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the path is NUL-terminated; a zero flag uses the default load.
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), 0) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: LoadLibraryExW returned a module this process owns.
        unsafe { FreeLibrary(module) };
        Ok(format!("loaded {target}"))
    }

    /// Activates a named out-of-process COM server with CLSCTX_LOCAL_SERVER and reports whether an
    /// interface pointer was returned. This triggers DCOM activation of a system service. If the
    /// AppContainer cannot reach the service, the activation fails with an access or launch error.
    /// A success means the AppContainer could start or bind to a process outside the sandbox.
    pub fn com_activate(target: &str) -> io::Result<String> {
        use std::ffi::c_void;

        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        use windows_sys::core::GUID;

        // ole32.dll is loaded at run time, not imported, so the probe process still starts in the
        // AppContainer (a static import of ole32 fails DllMain there with STATUS_DLL_INIT_FAILED).
        // This matches what an attacker with arbitrary native code would do.
        const CLSCTX_LOCAL_SERVER: u32 = 0x4;
        const COINIT_MULTITHREADED: u32 = 0x0;
        type CoInitializeEx = unsafe extern "system" fn(*const c_void, u32) -> i32;
        type CoCreateInstance = unsafe extern "system" fn(
            *const GUID,
            *mut c_void,
            u32,
            *const GUID,
            *mut *mut c_void,
        ) -> i32;
        type CoUninitialize = unsafe extern "system" fn();

        // Named out-of-process servers that run in a system service.
        let clsid = match target {
            // CLSID_TaskScheduler: creating a task would run a process outside the AppContainer.
            "task-scheduler" => GUID {
                data1: 0x0f87_369f,
                data2: 0xa4e5,
                data3: 0x4cfc,
                data4: [0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd],
            },
            // CLSID_BackgroundCopyManager (BITS): a transfer would fetch from the network.
            "bits" => GUID {
                data1: 0x4991_d34b,
                data2: 0x80a1,
                data3: 0x4291,
                data4: [0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97],
            },
            _ => return Err(invalid("unknown CLSID name")),
        };
        // IID_IUnknown.
        let iid_unknown = GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        // Only `release` is called; the first two entries fix the layout so `release` sits in the
        // third slot of the vtable.
        #[repr(C)]
        #[allow(dead_code)]
        struct IUnknownVtbl {
            query_interface:
                unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
            add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
            release: unsafe extern "system" fn(*mut c_void) -> u32,
        }

        let ole32 = wide("ole32.dll");
        // SAFETY: the name is NUL-terminated.
        let module = unsafe { LoadLibraryW(ole32.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::other(
                "cannot load ole32.dll in the AppContainer",
            ));
        }
        let resolve = |name: &std::ffi::CStr| {
            // SAFETY: module is loaded and the name is NUL-terminated.
            unsafe { GetProcAddress(module, name.as_ptr().cast()) }
        };
        let (Some(co_init), Some(co_create), Some(co_uninit)) = (
            resolve(c"CoInitializeEx"),
            resolve(c"CoCreateInstance"),
            resolve(c"CoUninitialize"),
        ) else {
            return Err(io::Error::other("COM entry points missing"));
        };
        // SAFETY: the resolved exports have the documented signatures.
        let co_init: CoInitializeEx = unsafe { std::mem::transmute(co_init) };
        // SAFETY: as above.
        let co_create: CoCreateInstance = unsafe { std::mem::transmute(co_create) };
        // SAFETY: as above.
        let co_uninit: CoUninitialize = unsafe { std::mem::transmute(co_uninit) };

        // SAFETY: a null reserved pointer and a valid apartment flag initialize COM for this thread.
        let hr = unsafe { co_init(ptr::null(), COINIT_MULTITHREADED) };
        if hr < 0 {
            return Err(io::Error::from_raw_os_error(hr));
        }
        let mut object: *mut c_void = ptr::null_mut();
        // SAFETY: both GUIDs are valid; object is a writable out pointer; no aggregation.
        let hr = unsafe {
            co_create(
                &clsid,
                ptr::null_mut(),
                CLSCTX_LOCAL_SERVER,
                &iid_unknown,
                &mut object,
            )
        };
        let outcome = if hr >= 0 && !object.is_null() {
            // SAFETY: object points to a COM interface whose first field is its vtable; Release is
            // the third IUnknown method.
            unsafe {
                let vtbl = *object.cast::<*const IUnknownVtbl>();
                ((*vtbl).release)(object);
            }
            Ok(format!("activated {target}"))
        } else {
            Err(io::Error::from_raw_os_error(hr))
        };
        // SAFETY: COM was initialized on this thread above.
        unsafe { co_uninit() };
        outcome
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

    pub fn afunix_accept(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn com_activate(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn load_library(_target: &str) -> io::Result<String> {
        unsupported()
    }
}

/// Actions for the macOS escape tests (`tests/escape_macos.rs`) and the macOS security review
/// (`tests/review_macos.rs`).
#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, c_char};
    use std::fs;
    use std::io::{self, Read};
    use std::ptr;

    pub const ACTIONS: &[&str] = &[
        "clone",
        "ptrace-attach",
        "vol-read",
        "fsgetpath",
        "socket-family",
        "nstat-open",
        "chflags-set",
        "utimes-set",
        "setxattr-set",
        "getxattr-get",
        "host-vm-stats",
        "symlink",
        "sysctl-proc-cputype",
        "fork",
        "vfork",
        "posix-spawn",
        "execve",
        "thread",
        "rename",
        "rmdir",
        "host-uuid",
        "fcntl-read-only",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "rename" => {
                let (from, to) = super::pair(target)?;
                fs::rename(from, to).map(|()| String::new())
            }
            "rmdir" => fs::remove_dir(target).map(|()| String::new()),
            "host-uuid" => host_uuid(),
            "fcntl-read-only" => fcntl_read_only(target),
            "fork" => fork(false),
            "vfork" => fork(true),
            "posix-spawn" => posix_spawn(target),
            "execve" => execve(target),
            "thread" => std::thread::spawn(|| 1 + 1)
                .join()
                .map(|_| String::new())
                .map_err(|_| io::Error::other("the thread panicked")),
            "clone" => clone(target),
            "ptrace-attach" => ptrace_attach(target),
            "vol-read" => vol_read(target),
            "fsgetpath" => fsgetpath_action(target),
            "socket-family" => socket_family(target),
            "nstat-open" => nstat_open(),
            "chflags-set" => chflags_set(target),
            "utimes-set" => utimes_set(target),
            "setxattr-set" => setxattr_set(target),
            "getxattr-get" => getxattr_get(target),
            "host-vm-stats" => host_vm_stats(),
            "symlink" => symlink(target),
            "sysctl-proc-cputype" => sysctl_proc_cputype(target),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    unsafe extern "C" {
        /// Not in the libc crate for macOS. The child may only call _exit.
        fn vfork() -> libc::pid_t;
    }

    /// `PATH<U+001F>COMMAND`: opens PATH read-only and calls fcntl with COMMAND and argument 0.
    /// The error tells whether the call reached the file system (for example ESTALE or EBADF)
    /// or a policy refused it first (EPERM).
    fn fcntl_read_only(target: &str) -> io::Result<String> {
        let (path, command) = super::pair(target)?;
        let command: libc::c_int = command
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid command"))?;
        let file = fs::File::open(path)?;
        // SAFETY: fcntl with an integer argument on an open descriptor.
        let result = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&file), command, 0) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(result.to_string())
    }

    /// The hardware UUID of the machine (gethostuuid), a stable identifier of the Mac.
    fn host_uuid() -> io::Result<String> {
        let mut id = [0u8; 16];
        let wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: gethostuuid writes 16 bytes into `id` and reads `wait`.
        if unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}...",
            id[0], id[1], id[2], id[3]
        ))
    }

    /// fork or vfork; the child exits at once.
    fn fork(shared: bool) -> io::Result<String> {
        // SAFETY: the child calls only _exit, which is allowed after fork and after vfork.
        let pid = unsafe { if shared { vfork() } else { libc::fork() } };
        if pid == -1 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: ends the child without touching the parent's state.
            unsafe { libc::_exit(0) };
        }
        wait(pid)
    }

    /// posix_spawn without POSIX_SPAWN_SETEXEC, so it creates a new process.
    fn posix_spawn(program: &str) -> io::Result<String> {
        let program = c_string(program)?;
        let argv = [program.as_ptr().cast_mut(), ptr::null_mut()];
        let envp = [ptr::null_mut()];
        let mut pid = 0;
        // SAFETY: program and both arrays are valid and NULL-terminated; null file actions and
        // attributes mean defaults.
        let error = unsafe {
            libc::posix_spawn(
                &mut pid,
                program.as_ptr(),
                ptr::null(),
                ptr::null(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        wait(pid)
    }

    /// Replaces this process with `PROGRAM<U+001F>ARG...`. Returns only on failure; on success
    /// the new image prints the lines of its own actions.
    fn execve(target: &str) -> io::Result<String> {
        let parts: Vec<CString> = target
            .split(super::ARGUMENT_SEPARATOR)
            .map(c_string)
            .collect::<io::Result<_>>()?;
        let mut argv: Vec<*const c_char> = parts.iter().map(|part| part.as_ptr()).collect();
        argv.push(ptr::null());
        // SAFETY: the program and every argument are NUL-terminated and argv ends with NULL.
        unsafe { libc::execv(argv[0], argv.as_ptr()) };
        Err(io::Error::last_os_error())
    }

    fn wait(pid: libc::pid_t) -> io::Result<String> {
        let mut status = 0;
        // SAFETY: waits for the child this process just created.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("child {pid} ended"))
    }

    fn c_string(text: &str) -> io::Result<CString> {
        CString::new(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))
    }

    /// `LINK::DEST`: creates a symbolic link at LINK that points to DEST. macOS, unlike Landlock,
    /// has no separate symlink-creation right, so this works inside a writable path. The review
    /// checks that reading through such a link does not reach DEST.
    fn symlink(target: &str) -> io::Result<String> {
        let (link, dest) = target
            .split_once("::")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected LINK::DEST"))?;
        std::os::unix::fs::symlink(dest, link).map(|()| format!("{link} -> {dest}"))
    }

    /// Reads `sysctl.proc_cputype` for another process id. The sandbox gates sysctl reads by name,
    /// and this name is in the allowlist, so it may act as a per-pid existence and architecture
    /// oracle even though process listing (kern.proc.*) is denied.
    fn sysctl_proc_cputype(target: &str) -> io::Result<String> {
        let mut pid: libc::pid_t = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
        let name = c"sysctl.proc_cputype";
        let mut cpu: libc::cpu_type_t = 0;
        let mut len = std::mem::size_of::<libc::cpu_type_t>();
        // SAFETY: sysctlbyname reads the NUL-terminated name and `pid` (newlen bytes), and writes
        // up to `len` bytes into `cpu`, updating `len`. The newp pointer is not written.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut cpu as *mut libc::cpu_type_t).cast(),
                &mut len,
                (&mut pid as *mut libc::pid_t).cast(),
                std::mem::size_of::<libc::pid_t>(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("cputype {cpu}"))
    }

    fn cstr(value: &str) -> io::Result<CString> {
        CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte"))
    }

    /// Parses `DEV:INODE` (the st_dev and st_ino the test read outside the sandbox).
    fn dev_inode(target: &str) -> io::Result<(u64, u64)> {
        let (dev, inode) = target
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected DEV:INODE"))?;
        let parse = |value: &str| {
            value
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DEV:INODE"))
        };
        Ok((parse(dev)?, parse(inode)?))
    }

    /// Opens a file by device and inode through the volfs path `/.vol/<dev>/<inode>`, which names
    /// a file without walking its directory path. If the sandbox checks only the textual path, a
    /// file outside the policy could be reachable this way.
    fn vol_read(target: &str) -> io::Result<String> {
        let (dev, inode) = dev_inode(target)?;
        let path = format!("/.vol/{dev}/{inode}");
        let mut content = Vec::new();
        fs::File::open(&path)?.read_to_end(&mut content)?;
        Ok(format!("{} bytes via {path}", content.len()))
    }

    /// A file system id, as fsgetpath expects it: `val[0]` is the device number.
    #[repr(C)]
    struct Fsid {
        val: [i32; 2],
    }

    unsafe extern "C" {
        /// Public since macOS 10.13: resolves the path of a file named by device and inode.
        fn fsgetpath(
            buffer: *mut c_char,
            size: libc::size_t,
            fsid: *const Fsid,
            objid: u64,
        ) -> libc::ssize_t;
    }

    /// Asks the kernel for the path of a file named only by device and inode (fsgetpath). A
    /// success reveals the location of a file the policy does not grant.
    fn fsgetpath_action(target: &str) -> io::Result<String> {
        let (dev, inode) = dev_inode(target)?;
        let fsid = Fsid {
            val: [dev as i32, 0],
        };
        let mut buffer = [0 as c_char; 1024];
        // SAFETY: fsgetpath reads the two-int fsid and writes up to buffer.len() bytes into
        // buffer, which outlives the call.
        let length = unsafe { fsgetpath(buffer.as_mut_ptr(), buffer.len(), &fsid, inode) };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = (length as usize).min(buffer.len()).saturating_sub(1);
        let bytes: Vec<u8> = buffer[..end].iter().map(|c| *c as u8).collect();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Creates a socket of a non-Unix family. `(deny default)` should refuse socket creation of
    /// every family except AF_UNIX, which the profile re-allows for socketpair.
    fn socket_family(target: &str) -> io::Result<String> {
        let (family, kind, protocol) = match target {
            "route" => (libc::PF_ROUTE, libc::SOCK_RAW, 0),
            "system" => (libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL),
            "ndrv" => (libc::PF_NDRV, libc::SOCK_RAW, 0),
            "key" => (libc::PF_KEY, libc::SOCK_RAW, 2),
            "inet" => (libc::AF_INET, libc::SOCK_STREAM, 0),
            "inet6" => (libc::AF_INET6, libc::SOCK_STREAM, 0),
            "vsock" => (libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown family",
                ));
            }
        };
        // SAFETY: socket takes no pointers.
        let fd = unsafe { libc::socket(family, kind, protocol) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: closing a descriptor this function owns.
        unsafe { libc::close(fd) };
        Ok(format!("fd {fd}"))
    }

    /// Creates a PF_SYSTEM kernel control socket and resolves the network statistics control by
    /// name with CTLIOCGINFO. The name resolution is a file-ioctl, which the profile denies except
    /// for four harmless requests, so even a created socket cannot reach the statistics control.
    fn nstat_open() -> io::Result<String> {
        // SAFETY: socket takes no pointers.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut info: libc::ctl_info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: [0; libc::MAX_KCTL_NAME],
        };
        let name = b"com.apple.network.statistics";
        for (slot, byte) in info.ctl_name.iter_mut().zip(name.iter()) {
            *slot = *byte as c_char;
        }
        // SAFETY: CTLIOCGINFO reads ctl_name and writes ctl_id, both inside the valid `info`.
        let result = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) };
        let outcome = if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(format!("ctl_id {}", info.ctl_id))
        };
        // SAFETY: closing a descriptor this function owns.
        unsafe { libc::close(fd) };
        outcome
    }

    /// Changes file flags by path (chflags). file-write-flags is part of file-write*, denied
    /// outside writable paths.
    fn chflags_set(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        // SAFETY: chflags reads the NUL-terminated path; UF_HIDDEN is a plain flag.
        if unsafe { libc::chflags(path.as_ptr(), libc::UF_HIDDEN) } == 0 {
            Ok(String::new())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Changes access and modification times by path (utimes). file-write-times is part of
    /// file-write*.
    fn utimes_set(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        let times = [
            libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        ];
        // SAFETY: utimes reads the path and two timevals.
        if unsafe { libc::utimes(path.as_ptr(), times.as_ptr()) } == 0 {
            Ok(String::new())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Writes an extended attribute by path (setxattr). file-write-xattr is part of file-write*.
    fn setxattr_set(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        let name = c"user.sandy.review";
        let value = b"x";
        // SAFETY: setxattr reads the path, the name and `value` of the given length.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        if result == 0 {
            Ok(String::new())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Reads an extended attribute by path (getxattr). It needs read access to the file, so a file
    /// outside the policy must be unreachable.
    fn getxattr_get(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        let name = c"com.apple.FinderInfo";
        let mut buffer = [0u8; 32];
        // SAFETY: getxattr reads the path and name and writes up to buffer.len() bytes.
        let read = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                0,
            )
        };
        if read < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(format!("{read} bytes"))
        }
    }

    /// Reads system-wide virtual memory statistics through the host name port (mach_host_self).
    /// This needs no mach-lookup: the port is a task special port inherited across exec.
    fn host_vm_stats() -> io::Result<String> {
        // mach_host_self is the documented way to get the host name port; the libc binding is
        // marked deprecated but is the only one available.
        #[allow(deprecated)]
        // SAFETY: mach_host_self returns a send right and takes no arguments.
        let host = unsafe { libc::mach_host_self() };
        // SAFETY: vm_statistics64 is plain integer data; all zeros is a valid starting value.
        let mut info: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
        let mut count = libc::HOST_VM_INFO64_COUNT;
        // SAFETY: host_statistics64 writes a vm_statistics64 into `info`; `count` bounds the write
        // and is updated in place.
        let kr = unsafe {
            libc::host_statistics64(
                host,
                libc::HOST_VM_INFO64,
                (&mut info as *mut libc::vm_statistics64).cast(),
                &mut count,
            )
        };
        if kr == 0 {
            Ok(format!("free_count {}", info.free_count))
        } else {
            Err(io::Error::other(format!("host_statistics64 returned {kr}")))
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

/// Actions on Linux and macOS for `process.children` and `process.end_with_parent`
/// (`tests/children*.rs`, `tests/parent.rs`).
#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::time::{Duration, Instant};

    pub const ACTIONS: &[&str] = &[
        "setsid",
        "setpgid",
        "signal-parent",
        "stop-self",
        "ignore-signal",
        "start-forked",
        "fork-walk",
        "await-signal",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "fork-walk" => fork_walk(target),
            "await-signal" => await_signal(target),
            // SAFETY: setsid has no arguments.
            "setsid" => check(unsafe { libc::setsid() }).map(|_| String::new()),
            // SAFETY: setpgid takes process IDs; 0 and 0 make the caller a group leader.
            "setpgid" => check(unsafe { libc::setpgid(0, 0) }).map(|_| String::new()),
            // Signal 0 only checks permission. The parent is sandy with children = "contained".
            "signal-parent" => {
                // SAFETY: kill and getppid take and return process IDs.
                check(unsafe { libc::kill(libc::getppid(), 0) }).map(|_| String::new())
            }
            "stop-self" => stop_self(target),
            "ignore-signal" => {
                let signal = target
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid number"))?;
                // SAFETY: setting a signal to SIG_IGN has no memory safety requirements.
                match unsafe { libc::signal(signal, libc::SIG_IGN) } {
                    libc::SIG_ERR => Err(io::Error::last_os_error()),
                    _ => Ok(String::new()),
                }
            }
            "start-forked" => start_forked(target),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    /// As `start`, but with fork and execve instead of posix_spawn: std uses fork as soon as a
    /// `pre_exec` closure is set. On macOS, `children = "contained"` denies posix_spawn.
    fn start_forked(target: &str) -> io::Result<String> {
        let mut parts = target.split(super::ARGUMENT_SEPARATOR);
        let program = parts.next().unwrap_or_default();
        let mut command = Command::new(program);
        command
            .args(parts)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the closure does nothing, so it is async-signal-safe.
        unsafe { command.pre_exec(|| Ok(())) };
        Ok(command.spawn()?.id().to_string())
    }

    /// Installs a handler for signal `target`, writes "await-signal ready" to standard error,
    /// and exits with status 42 when the signal arrives within 5 seconds.
    fn await_signal(target: &str) -> io::Result<String> {
        use std::sync::atomic::{AtomicBool, Ordering};
        static GOT: AtomicBool = AtomicBool::new(false);
        extern "C" fn handler(_sig: libc::c_int) {
            GOT.store(true, Ordering::SeqCst);
        }
        let signum: libc::c_int = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid number"))?;
        // SAFETY: installs a signal handler with an empty mask and no flags.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as *const () as usize;
            check(libc::sigaction(signum, &action, ptr::null_mut()))?;
        }
        // Standard error is unbuffered: a test that reads it knows that the handler is in place.
        eprintln!("await-signal ready");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if GOT.load(Ordering::SeqCst) {
                std::process::exit(42);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no signal"))
    }

    /// How long the processes of `fork-walk` keep forking at most.
    const WALK_SECONDS: libc::time_t = 30;

    /// Starts `target` processes that never stop forking: each forks a child and exits at once,
    /// and the child does the same. So at almost every moment one of them is inside fork, as in
    /// a program that starts processes in a loop. Reports the probe's process group.
    fn fork_walk(target: &str) -> io::Result<String> {
        let count: usize = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
        let null = std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        let null = std::os::fd::AsRawFd::as_raw_fd(&null);
        // A test that fails must not leave them running: each ends after this many seconds.
        // SAFETY: time with a null pointer only returns the time.
        let deadline = unsafe { libc::time(ptr::null_mut()) } + WALK_SECONDS;
        for _ in 0..count {
            // SAFETY: fork has no preconditions; the probe is single-threaded here.
            match unsafe { libc::fork() } {
                -1 => return Err(io::Error::last_os_error()),
                // SAFETY: the children only call dup2, time, fork, usleep and _exit, which are
                // async-signal-safe.
                0 => unsafe {
                    // Off the caller's output, which would otherwise never see its end.
                    for fd in 0..=2 {
                        libc::dup2(null, fd);
                    }
                    loop {
                        if libc::time(ptr::null_mut()) > deadline {
                            libc::_exit(0);
                        }
                        match libc::fork() {
                            0 => {}
                            -1 => {
                                libc::usleep(1000);
                            }
                            _ => libc::_exit(0),
                        }
                    }
                },
                _ => {}
            }
        }
        // SAFETY: getpgrp has no preconditions.
        Ok(unsafe { libc::getpgrp() }.to_string())
    }

    /// Stops the probe with SIGSTOP. A child it forks first continues it after `target`
    /// milliseconds, as a program that wants to leave its supervisor stopped would.
    fn stop_self(target: &str) -> io::Result<String> {
        let millis: u64 = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid duration"))?;
        // SAFETY: getpid has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the child only sleeps, signals the parent and calls _exit.
        match unsafe { libc::fork() } {
            -1 => Err(io::Error::last_os_error()),
            0 => {
                std::thread::sleep(Duration::from_millis(millis));
                // SAFETY: kill and _exit take a process ID and a status.
                unsafe {
                    libc::kill(parent, libc::SIGCONT);
                    libc::_exit(0)
                }
            }
            // SAFETY: stops the probe itself.
            _ => check(unsafe { libc::kill(parent, libc::SIGSTOP) }).map(|_| String::new()),
        }
    }

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}

#[cfg(not(unix))]
mod unix {
    use std::io;

    pub const ACTIONS: &[&str] = &[];

    pub fn perform(_action: &str, _target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
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
