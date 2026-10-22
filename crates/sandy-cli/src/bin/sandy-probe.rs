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
        action if linux::ACTIONS.contains(&action) => linux::perform(action, target),
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
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    fn number<T: FromStr>(target: &str) -> io::Result<T> {
        target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid number"))
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
