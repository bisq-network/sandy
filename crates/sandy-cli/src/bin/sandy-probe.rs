//! Test helper for the escape tests.
//!
//! Usage: `sandy-probe ACTION TARGET [ACTION TARGET]...`
//!
//! It tries each action and prints one line per action:
//! `ACTION<TAB>TARGET<TAB>RESULT<TAB>DETAIL`. RESULT is `ok`, `denied` (the operating system
//! refused with a permission error) or `error` (any other failure).

use std::fs;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// What `tcp-send` writes before it exits.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";
/// What `udp-send-fd` sends through the socket it was passed.
const UDP_SEND_PAYLOAD: &[u8] = b"sent through an inherited socket";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.len().is_multiple_of(2) {
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
        // A program that treats a file it cannot read as one that is not there: it reports
        // success either way. Many programs do this with data they can do without, and the
        // sandbox then takes something away without anyone noticing.
        "read-optional" => Ok(match fs::read(target) {
            Ok(content) => format!("{} bytes", content.len()),
            Err(_) => "without it".to_string(),
        }),
        "list" => Ok(format!("{} entries", fs::read_dir(target)?.count())),
        "write" => fs::write(target, b"probe").map(|()| String::new()),
        "truncate" => truncate(target),
        "open-rdonly-trunc" => open_read_only_truncate(target),
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
        "tcp-connect-read" => tcp_connect_read(target),
        // Listens on ADDRESS and connects to that listener from the same process, as the parts of
        // one program talk over loopback, and passes one byte through.
        "tcp-self" => tcp_self(target),
        // BROKER<U+001F>DESTINATION: asks the SOCKS5 broker on BROKER to CONNECT to DESTINATION, a
        // program's egress through `network.egress`. DESTINATION is `IP:port`, sent as an address,
        // or `name:port`, sent as a domain name (which the broker refuses). Reports the SOCKS5
        // reply code; it sends no data.
        "socks5-connect" => socks5_connect(target),
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
        // Binds ADDRESS and waits for one datagram, which the escape tests send from outside.
        "udp-receive" => {
            let socket = UdpSocket::bind(socket_address(target)?)?;
            datagram_from(&socket)
        }
        // Sends a datagram to ADDRESS from a port the system chooses, as a client does, and waits
        // for one datagram on that socket, from whichever sender.
        "udp-reply" => {
            let address = socket_address(target)?;
            let local = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(local)?;
            socket.send_to(b"probe", address)?;
            datagram_from(&socket)
        }
        // SERVER<U+001F>NAME: asks the DNS server SERVER for the A records of NAME over UDP, as a
        // resolver library does, and names the response code and the number of answers.
        "dns-query" => {
            let (server, name) = pair(target)?;
            dns_query(socket_address(server)?, name)
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
        "start-wrapped" => start_wrapped(target),
        // The probe's own process ID; the target is ignored.
        "pid" => Ok(std::process::id().to_string()),
        // When the probe's own process started, in the form `--parent-start` takes; the target
        // is ignored.
        "start-token" => start_token().map(|token| token.to_string()),
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
        "grant-all-packages" => windows_actions::grant_all_packages(target),
        "open-process-right" => windows_actions::open_process_right(target),
        "open-thread-right" => windows_actions::open_thread_right(target),
        "list-processes" => windows_actions::list_processes(),
        "session-id" => windows_actions::session_id(),
        "wts-processes" => windows_actions::wts_processes(),
        "enum-windows" => windows_actions::enum_windows(),
        "icmp-echo" => windows_actions::icmp_echo(target),
        "junction" => windows_actions::junction(target),
        "symbolic-link" => windows_actions::symbolic_link(target),
        "appcontainer-run" => windows_actions::appcontainer_run(target),
        "tcp-listen-bind" => windows_actions::tcp_listen_reuse(target, false),
        "tcp-listen-reuse" => windows_actions::tcp_listen_reuse(target, true),
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
        "lock-read" => lock_read(target),
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
        // STREAM<U+001F>ADDRESS: sends a datagram to ADDRESS from the socket the caller passed as
        // standard stream STREAM (0, 1 or 2), without creating a socket of its own.
        "udp-send-fd" => {
            let (stream, address) = pair(target)?;
            let socket: ManuallyDrop<UdpSocket> = standard_socket(stream)?;
            let sent = socket.send_to(UDP_SEND_PAYLOAD, socket_address(address)?)?;
            Ok(format!("{sent} bytes"))
        }
        // Accepts one connection on the listening socket the caller passed as standard stream
        // STREAM (0, 1 or 2).
        "accept-fd" => accept_fd(target),
        action if win32k::ACTIONS.contains(&action) => win32k::perform(action, target),
        action if unix::ACTIONS.contains(&action) => unix::perform(action, target),
        action if linux::ACTIONS.contains(&action) => linux::perform(action, target),
        action if view::ACTIONS.contains(&action) => view::perform(action, target),
        action if macos::ACTIONS.contains(&action) => macos::perform(action, target),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown action",
        )),
    }
}

/// Empties a file through its path: `truncate(2)` on Unix, and on Windows an open that
/// truncates, because there is no call for it. Both need the right to write the file's data,
/// which no read grant gives.
#[cfg(unix)]
fn truncate(target: &str) -> io::Result<String> {
    let path = path_argument(target)?;
    // SAFETY: the path is NUL-terminated; truncate has no other requirement.
    if unsafe { libc::truncate(path.as_ptr(), 0) } == 0 {
        Ok(String::new())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn truncate(target: &str) -> io::Result<String> {
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(target)
        .map(|_| String::new())
}

/// An exclusive lock on all of `target`, opened for reading only, without waiting: `flock` on
/// Unix, `LockFileEx` on Windows. The probe keeps the file open, so the lock holds until it
/// exits.
#[cfg(unix)]
fn lock_read(target: &str) -> io::Result<String> {
    use std::os::fd::AsRawFd;

    let file = ManuallyDrop::new(fs::File::open(target)?);
    // SAFETY: flock takes an open descriptor and flags.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::new())
}

#[cfg(windows)]
fn lock_read(target: &str) -> io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let file = ManuallyDrop::new(fs::File::open(target)?);
    // SAFETY: OVERLAPPED is plain data, and all zeros mean offset 0 and no event.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let flags = LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY;
    // SAFETY: the handle is an open file and overlapped outlives this synchronous call.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if locked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::new())
}

/// Empties a file through a read-only open with `O_TRUNC`, which asks for no write access.
/// Rust's `OpenOptions` refuses read with truncate before any system call, so this opens the
/// file directly.
#[cfg(unix)]
fn open_read_only_truncate(target: &str) -> io::Result<String> {
    let path = path_argument(target)?;
    // SAFETY: the path is NUL-terminated.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_TRUNC | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a descriptor that nothing else in this process uses.
    unsafe { libc::close(descriptor) };
    Ok(String::new())
}

#[cfg(not(unix))]
fn open_read_only_truncate(_target: &str) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
}

#[cfg(unix)]
fn path_argument(target: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))
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
    let target = expand(target)?;
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

/// What `expand` replaces with the probe's own process ID and start, so a test can give sandy
/// the `--parent-pid` and `--parent-start` of the process that starts it.
const PID_PLACEHOLDER: &str = "%pid%";
const START_PLACEHOLDER: &str = "%start%";

fn expand(target: &str) -> io::Result<String> {
    let mut expanded = target.replace(PID_PLACEHOLDER, &std::process::id().to_string());
    if expanded.contains(START_PLACEHOLDER) {
        expanded = expanded.replace(START_PLACEHOLDER, &start_token()?.to_string());
    }
    Ok(expanded)
}

/// When this process started, in the form `--parent-start` takes on this platform: clock ticks
/// since boot from field 22 of `/proc/self/stat`.
#[cfg(target_os = "linux")]
fn start_token() -> io::Result<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "no start time");
    let after_name = &stat[stat.rfind(')').ok_or_else(invalid)? + 1..];
    // Field 3 is the first after the name, so field 22 is the twentieth.
    after_name
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse().ok())
        .ok_or_else(invalid)
}

/// Microseconds since the epoch, from `PROC_PIDTBSDINFO`.
#[cfg(target_os = "macos")]
fn start_token() -> io::Result<u64> {
    use std::mem::{MaybeUninit, size_of};

    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer has exactly the size passed.
    let written = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::pid_t,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: proc_pidinfo filled the whole structure.
    let info = unsafe { info.assume_init() };
    Ok(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// The creation time of this process in 100 ns units, from `GetProcessTimes`.
#[cfg(windows)]
fn start_token() -> io::Result<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: the pseudo handle is valid and every pointer is writable.
    if unsafe { GetProcessTimes(GetCurrentProcess(), creation, exit, kernel, user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime))
}

/// Starts a program (arguments separated by U+001F) through a shell, so the program's direct
/// parent is the shell and not the probe. Reports the shell's process ID; the shell ends when
/// the program does, and passes its status on. The `exit` keeps the shell from replacing
/// itself with the program, which most shells do for a script of one command.
#[cfg(unix)]
fn start_wrapped(target: &str) -> io::Result<String> {
    let script: Vec<String> = expand(target)?
        .split(ARGUMENT_SEPARATOR)
        .map(shell_word)
        .collect();
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{}\nexit $?", script.join(" ")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child.id().to_string())
}

/// A shell word that holds `value` literally.
#[cfg(unix)]
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// As above through `cmd /c`, which waits for the program instead of replacing itself with it,
/// so the reported process ID is the shell's and it ends when the program ends.
#[cfg(windows)]
fn start_wrapped(target: &str) -> io::Result<String> {
    let target = expand(target)?;
    let child = Command::new("cmd")
        .arg("/c")
        .args(target.split(ARGUMENT_SEPARATOR))
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

/// Speaks SOCKS5 to the broker on the first address and asks it to CONNECT to the second. The
/// second is `IP:port`, sent as an IPv4 or IPv6 address (ATYP 1 or 4), or `name:port`, sent as a
/// domain name (ATYP 3). Reports `reply N`, the SOCKS5 reply code; reply 0 means the broker made
/// the connection. It does not exchange data, so it never waits on what the destination says.
fn socks5_connect(target: &str) -> io::Result<String> {
    let (broker, destination) = pair(target)?;
    let mut request = vec![5u8, 1, 0];
    // A socket address, also an IPv6 one with a scope (`[fe80::1%12]:80`), goes as an address;
    // anything else as a domain name.
    let port = match destination.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(v4)) => {
            request.push(1);
            request.extend(v4.ip().octets());
            v4.port()
        }
        Ok(SocketAddr::V6(v6)) => {
            request.push(4);
            request.extend(v6.ip().octets());
            v6.port()
        }
        Err(_) => {
            let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "expected NAME:PORT");
            let (name, port) = destination.rsplit_once(':').ok_or_else(invalid)?;
            request.push(3);
            request.push(u8::try_from(name.len()).map_err(|_| invalid())?);
            request.extend(name.as_bytes());
            port.parse().map_err(|_| invalid())?
        }
    };
    request.extend(port.to_be_bytes());

    let mut stream = TcpStream::connect_timeout(&socket_address(broker)?, CONNECT_TIMEOUT)?;
    // The broker may take its whole connect timeout of 10 seconds before it replies.
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::other(format!("bad method answer {greeting:?}")));
    }
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    if reply[0] != 5 {
        return Err(io::Error::other(format!("bad reply version {}", reply[0])));
    }
    Ok(format!("reply {}", reply[1]))
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

fn tcp_self(target: &str) -> io::Result<String> {
    let listener = TcpListener::bind(socket_address(target)?)?;
    let address = listener.local_addr()?;
    let mut client = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(b"x")?;
    server.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    let mut byte = [0];
    server.read_exact(&mut byte)?;
    Ok(format!("through {address}"))
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
        "tiocsetd",
        "lease-read",
        "delegation",
        "fchmod-ro",
        "utime-ro",
        "setflags-ro",
        "fsxattr-ro",
        "enable-verity",
        "listxattr-path",
        "getxattr-fd",
        "inotify-name",
        "list-fd",
        "getpwuid",
        "current-exe",
        "openat2-read",
        "landlock-ioctl-only",
        "open-stdin",
        "tcp-bind",
        "unix-listen",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "socketpair-bind" => socketpair_bind(target),
            "tcp-bind" => tcp_bind(target),
            "unix-listen" => std::os::unix::net::UnixListener::bind(target).map(|_| String::new()),
            "listxattr-path" => listxattr_path(target),
            "getxattr-fd" => getxattr_fd(target),
            "inotify-name" => inotify_name(target),
            "list-fd" => list_fd(number(target)?),
            "getpwuid" => getpwuid(),
            "current-exe" => Ok(std::env::current_exe()?.display().to_string()),
            "setxattr-path" => setxattr_path(target),
            "setxattr-fd" => setxattr_fd(target),
            "chown-path" => chown_path(target),
            "utime-path" => utime_path(target),
            "utime-fd" => utime_fd(target),
            "winsize-path" => winsize_path(target),
            "tiocsetd" => tiocsetd(number(target)?),
            "lease-read" => lease_read(target),
            "delegation" => delegation(target),
            "fchmod-ro" => fchmod_ro(target),
            "utime-ro" => utime_ro(target),
            "setflags-ro" => setflags_ro(target),
            "fsxattr-ro" => fsxattr_ro(target),
            "enable-verity" => enable_verity(target),
            "open" => fs::File::open(target).map(|_| String::new()),
            "open-ioctl-only" => open_ioctl_only(target),
            // Opens `target` for reading and writing in place of standard input, so that the
            // actions that take descriptor 0 act on it.
            "open-stdin" => {
                use std::os::fd::AsRawFd;
                use std::os::unix::fs::OpenOptionsExt;

                let file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOCTTY)
                    .open(target)?;
                // SAFETY: dup2 takes two descriptors; the file stays open until it returns.
                check(unsafe { libc::dup2(file.as_raw_fd(), 0) }).map(|_| String::new())
            }
            "openat2-read" => openat2_read(target),
            "landlock-ioctl-only" => landlock_ioctl_only(target),
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

    /// Binds a TCP socket to the IPv4 address `target` without listening, which Rust's standard
    /// library cannot do.
    fn tcp_bind(target: &str) -> io::Result<String> {
        let address = std::net::SocketAddrV4::from_str(target)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let socket = check(
            // SAFETY: socket takes no pointers.
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) },
        )?;
        let name = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: address.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*address.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `name` is a sockaddr_in of the size passed.
        let bound = check(unsafe {
            libc::bind(
                socket,
                (&raw const name).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        });
        close(socket);
        bound.map(|_| String::new())
    }

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

    /// listxattr through the path, which reads the names of the extended attributes of a file
    /// the program may not open.
    fn listxattr_path(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        let mut names = [0u8; 1024];
        // SAFETY: the path is NUL-terminated; the buffer has the length passed.
        let size =
            unsafe { libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{size} bytes of names"))
    }

    /// fgetxattr through a descriptor opened for reading.
    fn getxattr_fd(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::File::open(target)?;
        let mut value = [0u8; 64];
        // SAFETY: the name is NUL-terminated; the buffer has the length passed.
        let size = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                XATTR_NAME.as_ptr().cast(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{size} bytes"))
    }

    /// Watches `target` with inotify and reports the name of the first entry that appears in it,
    /// for at most five seconds. A caller creates entries in a loop, so the watch cannot miss
    /// them all.
    fn inotify_name(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: inotify_init1 takes flags only.
        let fd = check(unsafe { libc::inotify_init1(libc::IN_CLOEXEC) })?;
        // SAFETY: the path is NUL-terminated.
        let watch = check(unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_CREATE) });
        if let Err(error) = watch {
            close(fd);
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut events = [0u8; 4096];
        let name = loop {
            if Instant::now() >= deadline {
                break Err(io::Error::new(io::ErrorKind::TimedOut, "no entry appeared"));
            }
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one descriptor, a timeout in milliseconds.
            if unsafe { libc::poll(&mut poll, 1, 200) } <= 0 {
                continue;
            }
            // SAFETY: the buffer has the length passed.
            let read = unsafe { libc::read(fd, events.as_mut_ptr().cast(), events.len()) };
            if read <= 0 {
                break Err(io::Error::last_os_error());
            }
            // The name follows the event header and is padded with NUL bytes.
            let header = std::mem::size_of::<libc::inotify_event>();
            let name = &events[header..read as usize];
            let end = name.iter().position(|&byte| byte == 0).unwrap_or(0);
            break Ok(String::from_utf8_lossy(&name[..end]).into_owned());
        };
        close(fd);
        name
    }

    /// Lists the directory an inherited descriptor refers to, for example a directory passed as
    /// standard input.
    fn list_fd(fd: libc::c_int) -> io::Result<String> {
        // SAFETY: fdopendir takes over the descriptor, which closedir closes.
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut entries = 0;
        // SAFETY: readdir returns a pointer into the stream until it is exhausted.
        while !unsafe { libc::readdir(dir) }.is_null() {
            entries += 1;
        }
        // SAFETY: the stream is open and not used afterwards.
        unsafe { libc::closedir(dir) };
        Ok(format!("{entries} entries"))
    }

    /// The account name of this user, which glibc reads from /etc/passwd.
    fn getpwuid() -> io::Result<String> {
        // SAFETY: getpwuid returns a pointer to static storage or null.
        let entry = unsafe { libc::getpwuid(libc::getuid()) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(0) => io::Error::new(io::ErrorKind::NotFound, "no entry for this user"),
                _ => error,
            });
        }
        // SAFETY: a non-null entry has a NUL-terminated name.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).pw_name) };
        Ok(name.to_string_lossy().into_owned())
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

    /// Access mode 3 as the kernel reads it. musl's `O_ACCMODE` also holds O_PATH.
    const IOCTL_ONLY: libc::c_int = 3;

    /// Opens with access mode 3: no read or write access, only ioctl.
    fn open_ioctl_only(target: &str) -> io::Result<String> {
        let path = CString::new(target)?;
        // SAFETY: `path` is a valid C string.
        let fd = check(unsafe { libc::open(path.as_ptr(), IOCTL_ONLY | libc::O_CLOEXEC) })?;
        close(fd);
        Ok(String::new())
    }

    /// Opens with openat2, the call GNU tar uses for the directories of an archive.
    fn openat2_read(target: &str) -> io::Result<String> {
        /// `struct open_how`, the flags of openat2. They live in memory, which is why the
        /// seccomp filter cannot check them.
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let path = CString::new(target)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0,
        };
        // SAFETY: `path` is a valid C string, and the kernel reads `how` for the size given.
        let fd = check(unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                size_of::<OpenHow>(),
            ) as libc::c_int
        })?;
        close(fd);
        Ok(String::new())
    }

    /// What Landlock alone does with access mode 3, the reason the filter denies openat2: the
    /// probe puts itself in a Landlock domain that grants no path, and then opens `target` with
    /// access mode 3 and changes its permissions through the descriptor. Handling the two rights
    /// that decide an open is enough, because such an open asks for neither of them, so Landlock
    /// checks no right for it (see "Access mode 3" in docs/linux.md).
    ///
    /// It restricts this process, so it must be the only action of a probe run.
    fn landlock_ioctl_only(target: &str) -> io::Result<String> {
        const READ_FILE: u64 = 1 << 2;
        const WRITE_FILE: u64 = 1 << 1;
        // The kernel reads as many bytes of the ruleset attribute as the size gives, so the
        // first field on its own is the attribute of the first Landlock ABI.
        let handled_access_fs: u64 = READ_FILE | WRITE_FILE;
        // SAFETY: the kernel reads `handled_access_fs` for the size given.
        let ruleset = check(unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &handled_access_fs,
                size_of::<u64>(),
                0,
            ) as libc::c_int
        })?;
        // SAFETY: prctl takes no pointer here, and restrict_self takes the ruleset descriptor.
        let restricted = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) == 0
        };
        let failure = io::Error::last_os_error();
        close(ruleset);
        if !restricted {
            return Err(failure);
        }
        let path = CString::new(target)?;
        // SAFETY: `path` is a valid C string.
        let readable = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if readable >= 0 {
            close(readable);
            return Err(io::Error::other("the domain allows a read-only open"));
        }
        // SAFETY: `path` is a valid C string.
        let fd = check(unsafe { libc::open(path.as_ptr(), IOCTL_ONLY | libc::O_CLOEXEC) })?;
        // SAFETY: fchmod takes a descriptor this function owns.
        let changed = check(unsafe { libc::fchmod(fd, 0o600) });
        close(fd);
        changed.map(|_| String::new())
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
        let size = super::unix::window_size(fd)?;
        Ok(format!("{}x{}", size.ws_row, size.ws_col))
    }

    // The `-ro` actions change metadata through a descriptor opened read-only, which a `read`
    // path grants. Each writes back the value it read, so the kernel checks the permission but
    // nothing changes.

    fn fchmod_ro(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::File::open(target)?;
        let mode = file.metadata()?.permissions().mode();
        // SAFETY: fchmod takes a descriptor and a mode.
        check(unsafe { libc::fchmod(file.as_raw_fd(), mode) })?;
        Ok(format!("mode {:o}", mode & 0o7777))
    }

    /// futimens on a descriptor opened read-only; null times mean "now".
    fn utime_ro(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::File::open(target)?;
        // SAFETY: the times pointer may be null.
        check(unsafe { libc::futimens(file.as_raw_fd(), ptr::null()) })?;
        Ok(String::new())
    }

    /// FS_IOC_GETFLAGS and FS_IOC_SETFLAGS: the inode flags that `chattr` changes.
    fn setflags_ro(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
        const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
        let file = fs::File::open(target)?;
        let mut flags: libc::c_long = 0;
        // SAFETY: FS_IOC_GETFLAGS writes a long through the pointer.
        check(unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) })?;
        // SAFETY: FS_IOC_SETFLAGS reads a long through the pointer.
        check(unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS as _, &flags) })?;
        Ok(format!("flags {flags:#x}"))
    }

    /// FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR: inode attributes and the project ID.
    fn fsxattr_ro(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        const FS_IOC_FSGETXATTR: libc::c_ulong = 0x801c_581f;
        const FS_IOC_FSSETXATTR: libc::c_ulong = 0x401c_5820;
        /// struct fsxattr.
        #[repr(C)]
        #[derive(Default)]
        struct FsXattr {
            xflags: u32,
            extent_size: u32,
            extent_count: u32,
            project_id: u32,
            cow_extent_size: u32,
            padding: [u8; 8],
        }
        let file = fs::File::open(target)?;
        let mut attributes = FsXattr::default();
        // SAFETY: FS_IOC_FSGETXATTR writes one fsxattr through the pointer.
        check(unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FSGETXATTR as _, &mut attributes) })?;
        // SAFETY: FS_IOC_FSSETXATTR reads one fsxattr through the pointer.
        check(unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FSSETXATTR as _, &attributes) })?;
        Ok(format!("xflags {:#x}", attributes.xflags))
    }

    /// Enables fs-verity on `target`, opened read-only. The content of the file is then
    /// permanently read-only; the file can still be removed.
    fn enable_verity(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        const FS_IOC_ENABLE_VERITY: libc::c_ulong = 0x4080_6685;
        /// struct fsverity_enable_arg, with FS_VERITY_HASH_ALG_SHA256 and no salt or signature.
        #[repr(C)]
        struct EnableVerity {
            version: u32,
            hash_algorithm: u32,
            block_size: u32,
            salt_size: u32,
            salt_ptr: u64,
            signature_size: u32,
            reserved1: u32,
            signature_ptr: u64,
            reserved2: [u64; 11],
        }
        let request = EnableVerity {
            version: 1,
            hash_algorithm: 1,
            block_size: 4096,
            salt_size: 0,
            salt_ptr: 0,
            signature_size: 0,
            reserved1: 0,
            signature_ptr: 0,
            reserved2: [0; 11],
        };
        let file = fs::File::open(target)?;
        // SAFETY: FS_IOC_ENABLE_VERITY reads one fsverity_enable_arg through the pointer; the
        // salt and signature pointers are null with size 0.
        check(unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_ENABLE_VERITY as _, &request) })?;
        Ok(String::new())
    }

    /// Takes a read lease on `target`, opened read-only, and gives it up again. While the lease
    /// is held, a process outside that opens the file for writing waits.
    fn lease_read(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        let file = fs::File::open(target)?;
        // SAFETY: F_SETLEASE takes an int argument.
        check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) })?;
        // SAFETY: as above.
        check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) })?;
        Ok(String::new())
    }

    /// Takes a read delegation (F_SETDELEG, Linux 7) on the file or directory `target`, opened
    /// read-only. Closing the descriptor gives it up. While a directory is delegated, a process
    /// outside that creates, renames or removes an entry in it waits.
    fn delegation(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;
        const F_SETDELEG: libc::c_int = 1040;
        /// struct delegation.
        #[repr(C)]
        struct Delegation {
            flags: u32,
            kind: u16,
            padding: u16,
        }
        let request = Delegation {
            flags: 0,
            kind: libc::F_RDLCK as u16,
            padding: 0,
        };
        let file = fs::File::open(target)?;
        // SAFETY: F_SETDELEG reads one struct delegation through the pointer.
        check(unsafe { libc::fcntl(file.as_raw_fd(), F_SETDELEG, &request as *const Delegation) })?;
        Ok(String::new())
    }

    /// Sets the line discipline of terminal `fd` to the one it already has, so that the kernel
    /// loads no discipline module outside the sandbox. Another value would, and the filter
    /// denies the request whatever the value is.
    fn tiocsetd(fd: libc::c_int) -> io::Result<String> {
        let mut discipline: libc::c_int = 0;
        // SAFETY: TIOCGETD writes an int through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCGETD, &mut discipline as *mut libc::c_int) })?;
        // SAFETY: TIOCSETD reads an int through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCSETD, &discipline as *const libc::c_int) })?;
        Ok(format!("discipline {discipline}"))
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

/// Connects and reads until the other side closes. A connection that is still open when the
/// relay accepts it keeps the owner the relay looks up, which a connection that closed first
/// does not (docs/linux.md, "Exposed and forwarded ports").
fn tcp_connect_read(target: &str) -> io::Result<String> {
    const READ_TIMEOUT: Duration = Duration::from_secs(20);
    let mut stream = TcpStream::connect_timeout(&socket_address(target)?, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut received = Vec::new();
    stream.read_to_end(&mut received)?;
    Ok(format!("{} bytes", received.len()))
}

/// One DNS query for the A records of `name`, sent from a port the system chooses to `server`.
/// Only a response with the query's ID counts.
fn dns_query(server: SocketAddr, name: &str) -> io::Result<String> {
    let id = (std::process::id() as u16).to_be_bytes();
    // Header: ID, recursion desired, one question.
    let mut query = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.').filter(|label| !label.is_empty()) {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|&length| length < 64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "label too long"))?;
        query.push(length);
        query.extend(label.as_bytes());
    }
    // The root label, type A, class IN.
    query.extend([0, 0, 1, 0, 1]);
    let local = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local)?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.send_to(&query, server)?;
    let mut response = [0; 512];
    loop {
        let (length, _) = socket.recv_from(&mut response)?;
        let is_response = response[2] & 0x80 != 0;
        if length >= 12 && response[..2] == id && is_response {
            let answers = u16::from_be_bytes([response[6], response[7]]);
            return Ok(format!("rcode {}, {answers} answers", response[3] & 0x0f));
        }
    }
}

/// Waits up to 10 seconds for one datagram on `socket` and names its sender.
fn datagram_from(socket: &UdpSocket) -> io::Result<String> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buffer = [0; 64];
    match socket.recv_from(&mut buffer) {
        Ok((_, sender)) => Ok(format!("from {sender}")),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(io::Error::new(io::ErrorKind::TimedOut, "no datagram"))
        }
        Err(error) => Err(error),
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

/// Accepts one connection on the listening socket the caller passed as a standard stream. The
/// socket was created outside the sandbox, so the program listens without binding a port itself.
fn accept_fd(stream: &str) -> io::Result<String> {
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
    let listener: ManuallyDrop<TcpListener> = standard_socket(stream)?;
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + ACCEPT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((_, peer)) => return Ok(format!("accepted {peer}")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "no connection"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Which standard stream an action names: 0, 1 or 2.
fn standard_stream(stream: &str) -> io::Result<u32> {
    match stream {
        "0" => Ok(0),
        "1" => Ok(1),
        "2" => Ok(2),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected the standard stream 0, 1 or 2",
        )),
    }
}

/// The socket a standard stream carries, borrowed: the returned value never closes it, because
/// the stream stays in use. On Windows a standard handle has a number of its own, so the actions
/// name the stream instead of the handle.
#[cfg(unix)]
fn standard_socket<T: std::os::fd::FromRawFd>(stream: &str) -> io::Result<ManuallyDrop<T>> {
    let fd = standard_stream(stream)? as std::os::fd::RawFd;
    // SAFETY: F_GETFD only checks that fd is open; it has no memory safety requirements.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor is open, and ManuallyDrop keeps the value from closing it, so the
    // standard stream it belongs to stays untouched.
    Ok(ManuallyDrop::new(unsafe { T::from_raw_fd(fd) }))
}

#[cfg(windows)]
fn standard_socket<T: std::os::windows::io::FromRawSocket>(
    stream: &str,
) -> io::Result<ManuallyDrop<T>> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    // The standard library starts Winsock when it creates the first socket of the process. An
    // inherited one is not created here, so nothing has started it yet.
    // SAFETY: WSADATA is plain data; WSAStartup fills it.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: data is a valid out pointer.
    let code = unsafe { WSAStartup(0x0202, &mut data) };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code));
    }
    let which = match standard_stream(stream)? {
        0 => STD_INPUT_HANDLE,
        1 => STD_OUTPUT_HANDLE,
        _ => STD_ERROR_HANDLE,
    };
    // SAFETY: GetStdHandle has no preconditions.
    let handle = unsafe { GetStdHandle(which) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the standard stream is closed",
        ));
    }
    // SAFETY: the handle is open, and ManuallyDrop keeps the value from closing it, so the
    // standard stream it belongs to stays untouched.
    Ok(ManuallyDrop::new(unsafe {
        T::from_raw_socket(handle as std::os::windows::io::RawSocket)
    }))
}

#[cfg(not(any(unix, windows)))]
fn standard_socket<T>(stream: &str) -> io::Result<ManuallyDrop<T>> {
    standard_stream(stream)?;
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
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

    /// Grants ALL APPLICATION PACKAGES, which every AppContainer process belongs to, full access
    /// to `target`, including `FILE_EXECUTE`. This is the self-re-grant an AppContainer can do
    /// wherever it holds `WRITE_DAC`: the escape tests check that its own profile folder is not
    /// such a place.
    pub fn grant_all_packages(target: &str) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
            SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
        };
        use windows_sys::Win32::Security::{
            ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, WinBuiltinAnyPackageSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };

        let mut sid = [0u32; 17];
        let mut size = (sid.len() * 4) as u32;
        // SAFETY: the buffer is SECURITY_MAX_SID_SIZE bytes, aligned for a SID, and size tells
        // the function its length.
        if unsafe {
            CreateWellKnownSid(
                WinBuiltinAnyPackageSid,
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(target)?;
        let handle = {
            use std::os::windows::io::AsRawHandle;
            file.as_raw_handle()
        };
        let mut current: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the handle is open for READ_CONTROL; the out pointers are valid.
        let error = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut current,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.as_mut_ptr().cast(),
            },
        };
        let mut merged: *mut ACL = ptr::null_mut();
        // SAFETY: access names one entry whose SID outlives the call; current is the DACL of the
        // file or null, which SetEntriesInAclW accepts.
        let error = unsafe { SetEntriesInAclW(1, &access, current, &mut merged) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        // SAFETY: the handle is open for WRITE_DAC and merged is a valid ACL.
        let error = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                merged,
                ptr::null_mut(),
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(String::new())
    }

    /// `PID U+001F RIGHT`: opens the process with one named access right and closes it again.
    /// Nothing is read, written or ended.
    pub fn open_process_right(target: &str) -> io::Result<String> {
        use windows_sys::Win32::System::Threading::{
            PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
            PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
        };
        let (pid, right) = split_right(target)?;
        let access = match right {
            "vm-write" => PROCESS_VM_WRITE,
            "vm-operation" => PROCESS_VM_OPERATION,
            "dup-handle" => PROCESS_DUP_HANDLE,
            "create-thread" => PROCESS_CREATE_THREAD,
            "set-information" => PROCESS_SET_INFORMATION,
            "set-quota" => PROCESS_SET_QUOTA,
            "suspend-resume" => PROCESS_SUSPEND_RESUME,
            "query-information" => PROCESS_QUERY_INFORMATION,
            "all-access" => PROCESS_ALL_ACCESS,
            _ => return Err(invalid("unknown process right")),
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

    /// `THREAD ID U+001F RIGHT`: opens the thread with one named access right and closes it
    /// again. Nothing is suspended, resumed or changed.
    pub fn open_thread_right(target: &str) -> io::Result<String> {
        use windows_sys::Win32::System::Threading::{
            OpenThread, THREAD_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
            THREAD_SET_CONTEXT, THREAD_SET_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
        };
        let (tid, right) = split_right(target)?;
        let access = match right {
            "terminate" => THREAD_TERMINATE,
            "suspend-resume" => THREAD_SUSPEND_RESUME,
            "get-context" => THREAD_GET_CONTEXT,
            "set-context" => THREAD_SET_CONTEXT,
            "set-information" => THREAD_SET_INFORMATION,
            "query-information" => THREAD_QUERY_INFORMATION,
            "all-access" => THREAD_ALL_ACCESS,
            _ => return Err(invalid("unknown thread right")),
        };
        // SAFETY: OpenThread has no memory safety preconditions.
        let handle = unsafe { OpenThread(access, FALSE, tid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: handle is a new handle owned by this function.
        unsafe { CloseHandle(handle) };
        Ok(String::new())
    }

    /// `ID U+001F RIGHT`.
    fn split_right(target: &str) -> io::Result<(u32, &str)> {
        let (id, right) = target
            .split_once('\u{1f}')
            .ok_or_else(|| invalid("expected ID U+001F RIGHT"))?;
        let id = id.parse().map_err(|_| invalid("invalid id"))?;
        Ok((id, right))
    }

    /// Lists the processes this token can see, three ways: a Toolhelp snapshot, `EnumProcesses`
    /// and `NtQuerySystemInformation(SystemProcessInformation)`. The detail is
    /// `toolhelp=N enumproc=M ntqsi=K self=PID names=a.exe,b.exe`, where the names are the
    /// distinct executable names of the Toolhelp entries, so a caller can tell an AppContainer's
    /// filtered list (only its own processes and the pid 0 placeholder) from the full list a
    /// control outside the sandbox sees.
    pub fn list_processes() -> io::Result<String> {
        use std::collections::BTreeSet;
        use windows_sys::Wdk::System::SystemInformation::{
            NtQuerySystemInformation, SystemProcessInformation,
        };
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::ProcessStatus::EnumProcesses;

        /// Counts the process entries `NtQuerySystemInformation(SystemProcessInformation)`
        /// returns. The entries form a linked list whose `NextEntryOffset` (the first `u32` of
        /// each entry) reaches the next one and is zero on the last.
        fn ntqsi_process_count() -> io::Result<usize> {
            let mut buffer = vec![0u8; 1 << 20];
            loop {
                let mut needed = 0u32;
                // SAFETY: the buffer and its length are passed; needed is a valid out pointer.
                let status = unsafe {
                    NtQuerySystemInformation(
                        SystemProcessInformation,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        &mut needed,
                    )
                };
                // STATUS_INFO_LENGTH_MISMATCH: grow the buffer and try again.
                if status == 0xC0000004u32 as i32 {
                    buffer.resize((needed as usize).max(buffer.len() * 2), 0);
                    continue;
                }
                if status < 0 {
                    return Err(io::Error::from_raw_os_error(status));
                }
                let mut offset = 0usize;
                let mut count = 0usize;
                loop {
                    if offset + 4 > buffer.len() {
                        break;
                    }
                    count += 1;
                    let next =
                        u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                    if next == 0 {
                        break;
                    }
                    offset += next;
                }
                return Ok(count);
            }
        }

        // Toolhelp: count the entries and collect their executable names.
        // SAFETY: a process snapshot takes no process id.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the structure is plain data; dwSize is set before use.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut toolhelp = 0usize;
        let mut names = BTreeSet::new();
        // SAFETY: snapshot is valid and entry has its size set.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            toolhelp += 1;
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            names.insert(String::from_utf16_lossy(&entry.szExeFile[..len]));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: snapshot is a handle this function owns.
        unsafe { CloseHandle(snapshot) };

        // EnumProcesses: the count of process ids it returns.
        let mut pids = vec![0u32; 8192];
        let mut returned = 0u32;
        // SAFETY: the buffer length in bytes is passed; returned is a valid out pointer.
        let ok = unsafe {
            EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * size_of::<u32>()) as u32,
                &mut returned,
            )
        };
        let enumproc = if ok == 0 {
            return Err(io::Error::last_os_error());
        } else {
            returned as usize / size_of::<u32>()
        };

        // NtQuerySystemInformation: walk the linked list and count the entries.
        let ntqsi = ntqsi_process_count()?;

        let names: Vec<_> = names.into_iter().collect();
        Ok(format!(
            "toolhelp={toolhelp} enumproc={enumproc} ntqsi={ntqsi} self={} names={}",
            std::process::id(),
            names.join(",")
        ))
    }

    /// This process's Terminal Services session id (`ProcessIdToSessionId`). A sandboxed program
    /// shares sandy's session; the detail is `session=N`.
    pub fn session_id() -> io::Result<String> {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

        let mut session = 0u32;
        // SAFETY: session is a valid out pointer.
        let ok = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("session={session}"))
    }

    /// Lists the processes `WTSEnumerateProcessesW` returns for the current server, a route that
    /// does not go through the Toolhelp or NT process list. The detail is `wts=N`.
    pub fn wts_processes() -> io::Result<String> {
        use windows_sys::Win32::System::RemoteDesktop::{
            WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFOW, WTSEnumerateProcessesW, WTSFreeMemory,
        };

        let mut info: *mut WTS_PROCESS_INFOW = ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: info and count are valid out pointers; version 1 is required.
        let ok = unsafe {
            WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: info points to memory WTS allocated; free it exactly once.
        unsafe { WTSFreeMemory(info.cast()) };
        Ok(format!("wts={count}"))
    }

    /// Counts the top-level windows `EnumWindows` returns. `user32.dll` is loaded at run time so
    /// a session where it cannot initialize in an AppContainer (docs/windows.md limitation 13)
    /// reports the load error instead of failing at startup. The detail is `windows=N`.
    pub fn enum_windows() -> io::Result<String> {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        unsafe extern "system" fn count(_window: HANDLE, param: isize) -> i32 {
            // SAFETY: param is the &mut usize this function passed as lParam.
            unsafe { *(param as *mut usize) += 1 };
            TRUE
        }

        let module = {
            let wide = wide("user32.dll");
            // SAFETY: the name is NUL-terminated.
            unsafe { LoadLibraryW(wide.as_ptr()) }
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the module is loaded and the name is NUL-terminated.
        let address = unsafe { GetProcAddress(module, c"EnumWindows".as_ptr().cast()) }
            .ok_or_else(io::Error::last_os_error)?;
        type Export = unsafe extern "system" fn() -> isize;
        type EnumWindows = unsafe extern "system" fn(
            unsafe extern "system" fn(HANDLE, isize) -> i32,
            isize,
        ) -> i32;
        // SAFETY: EnumWindows has this signature.
        let enum_windows = unsafe { std::mem::transmute::<Export, EnumWindows>(address) };
        let mut total = 0usize;
        // SAFETY: count is a valid callback and total outlives the call.
        let ok = unsafe { enum_windows(count, &mut total as *mut usize as isize) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("windows={total}"))
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

    /// Reaches a named COM service and reports whether it answered. Both targets end at a
    /// process outside the AppContainer and the job; a success means the program could drive it.
    ///
    /// `bits` is an out-of-process server, so `CoCreateInstance` with `CLSCTX_LOCAL_SERVER` is
    /// the whole attempt. `task-scheduler` is not: `CLSID_TaskScheduler` lives in `taskschd.dll`
    /// and loads in the caller, which says nothing about the boundary and fails outside the
    /// sandbox too with `CLSCTX_LOCAL_SERVER`. Its boundary is `ITaskService::Connect`, which
    /// binds to the Schedule service over RPC, so the probe loads the class in process and
    /// calls that.
    ///
    /// The detail carries the `HRESULT`, and `E_ACCESSDENIED` is reported as `denied`, so a test
    /// can tell a refusal at the boundary from a failure to load COM at all.
    pub fn com_activate(target: &str) -> io::Result<String> {
        use std::ffi::c_void;

        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        use windows_sys::core::GUID;

        // ole32.dll is loaded at run time, not imported, so the probe process still starts in the
        // AppContainer (a static import of ole32 fails DllMain there with STATUS_DLL_INIT_FAILED).
        // This matches what an attacker with arbitrary native code would do.
        const CLSCTX_INPROC_SERVER: u32 = 0x1;
        const CLSCTX_LOCAL_SERVER: u32 = 0x4;
        const COINIT_MULTITHREADED: u32 = 0x0;
        const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
        /// `VARIANT`, 24 bytes; all zero is `VT_EMPTY`, which `Connect` reads as "this
        /// computer, the caller's own credentials".
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Variant {
            vt: u16,
            reserved: [u16; 3],
            value: [u64; 2],
        }
        type CoInitializeEx = unsafe extern "system" fn(*const c_void, u32) -> i32;
        type CoCreateInstance = unsafe extern "system" fn(
            *const GUID,
            *mut c_void,
            u32,
            *const GUID,
            *mut *mut c_void,
        ) -> i32;
        type CoUninitialize = unsafe extern "system" fn();

        // IID_IUnknown.
        let iid_unknown = GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        let (clsid, iid, context) = match target {
            // CLSID_TaskScheduler and IID_ITaskService: a task would run a process outside the
            // AppContainer.
            "task-scheduler" => (
                GUID {
                    data1: 0x0f87_369f,
                    data2: 0xa4e5,
                    data3: 0x4cfc,
                    data4: [0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd],
                },
                GUID {
                    data1: 0x2fab_a4c7,
                    data2: 0x4da9,
                    data3: 0x4013,
                    data4: [0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85],
                },
                CLSCTX_INPROC_SERVER,
            ),
            // CLSID_BackgroundCopyManager (BITS): a transfer would fetch from the network.
            "bits" => (
                GUID {
                    data1: 0x4991_d34b,
                    data2: 0x80a1,
                    data3: 0x4291,
                    data4: [0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97],
                },
                iid_unknown,
                CLSCTX_LOCAL_SERVER,
            ),
            _ => return Err(invalid("unknown CLSID name")),
        };

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
        let mut hr = unsafe { co_create(&clsid, ptr::null_mut(), context, &iid, &mut object) };
        if hr >= 0 && !object.is_null() {
            if target == "task-scheduler" {
                // ITaskService::Connect is the eleventh method: three of IUnknown, four more of
                // IDispatch, then GetFolder, GetRunningTasks and NewTask.
                type Connect = unsafe extern "system" fn(
                    *mut c_void,
                    Variant,
                    Variant,
                    Variant,
                    Variant,
                ) -> i32;
                // SAFETY: object is an ITaskService; its first field is the vtable, whose slot
                // 10 is Connect with this signature. Four VT_EMPTY arguments mean this
                // computer and the caller's own credentials.
                hr = unsafe {
                    let vtbl = *object.cast::<*const *const c_void>();
                    let connect: Connect = std::mem::transmute(*vtbl.add(10));
                    connect(
                        object,
                        Variant::default(),
                        Variant::default(),
                        Variant::default(),
                        Variant::default(),
                    )
                };
            }
            // SAFETY: object points to a COM interface whose first field is its vtable; Release
            // is the third IUnknown method.
            unsafe {
                let vtbl = *object.cast::<*const *const c_void>();
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtbl.add(2));
                release(object);
            }
        }
        // SAFETY: COM was initialized on this thread above.
        unsafe { co_uninit() };
        let detail = format!("hr={:#010x}", hr as u32);
        match hr {
            hr if hr >= 0 => Ok(format!("reached {target} {detail}")),
            E_ACCESSDENIED => Err(io::Error::new(io::ErrorKind::PermissionDenied, detail)),
            _ => Err(io::Error::other(detail)),
        }
    }

    /// Makes the new directory `LINK` a junction (mount point) to the existing directory
    /// `TARGET`. Target: `TARGET U+001F LINK`, the order of `hardlink`. An AppContainer process
    /// outside its writable paths is refused this, which is why the escape test can plant one
    /// only outside the sandbox.
    pub fn junction(target: &str) -> io::Result<String> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        };
        use windows_sys::Win32::System::IO::DeviceIoControl;
        /// `FSCTL_SET_REPARSE_POINT` and `IO_REPARSE_TAG_MOUNT_POINT`.
        const SET_REPARSE_POINT: u32 = 0x0009_00A4;
        const MOUNT_POINT: u32 = 0xA000_0003;

        let (existing, link) = super::pair(target)?;
        fs::create_dir(link)?;
        let result = (|| {
            let directory = fs::OpenOptions::new()
                .access_mode(FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(link)?;
            // An NT substitute name: `\??\C:\path`, so strip a `\\?\` verbatim prefix first.
            let plain = existing.strip_prefix(r"\\?\").unwrap_or(existing);
            let substitute: Vec<u16> = format!(r"\??\{plain}").encode_utf16().collect();
            let print: Vec<u16> = plain.encode_utf16().collect();
            let mut names = substitute.clone();
            names.push(0);
            names.extend(&print);
            names.push(0);
            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend(MOUNT_POINT.to_le_bytes());
            buffer.extend((8 + 2 * names.len() as u16).to_le_bytes());
            buffer.extend(0u16.to_le_bytes());
            buffer.extend(0u16.to_le_bytes());
            buffer.extend((2 * substitute.len() as u16).to_le_bytes());
            buffer.extend((2 * substitute.len() as u16 + 2).to_le_bytes());
            buffer.extend((2 * print.len() as u16).to_le_bytes());
            for unit in names {
                buffer.extend(unit.to_le_bytes());
            }
            let mut returned = 0u32;
            // SAFETY: the handle is open; the buffer holds a mount point reparse buffer of the
            // length passed; there is no output buffer.
            let ok = unsafe {
                DeviceIoControl(
                    std::os::windows::io::AsRawHandle::as_raw_handle(&directory),
                    SET_REPARSE_POINT,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(String::new())
        })();
        if result.is_err() {
            let _ = fs::remove_dir(link);
        }
        result
    }

    /// A symbolic link `LINK` to `TARGET`, a directory link when `TARGET` is a directory.
    /// Target: `TARGET U+001F LINK`. Creating one needs `SeCreateSymbolicLinkPrivilege`, which
    /// the AppContainer token never holds, so this always fails inside the sandbox.
    pub fn symbolic_link(target: &str) -> io::Result<String> {
        let (existing, link) = super::pair(target)?;
        if std::path::Path::new(existing).is_dir() {
            std::os::windows::fs::symlink_dir(existing, link)?;
        } else {
            std::os::windows::fs::symlink_file(existing, link)?;
        }
        Ok(String::new())
    }

    /// Sends one ICMP echo request to the IPv4 address `target` through the ICMP functions of
    /// the IP helper library, which need no socket of the caller, and waits up to three seconds
    /// for the reply.
    pub fn icmp_echo(target: &str) -> io::Result<String> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, IP_SUCCESS, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
        };

        let address: std::net::Ipv4Addr = target
            .parse()
            .map_err(|_| invalid("invalid IPv4 address"))?;
        // SAFETY: IcmpCreateFile has no preconditions.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let request = *b"sandy-probe";
        // One reply, its data and room for an ICMP error message, as the documentation asks.
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + request.len() + 8 + 64];
        // SAFETY: handle is open; the request and reply buffers are valid for their lengths;
        // the address is in network byte order, as IPAddr is.
        let count = unsafe {
            IcmpSendEcho(
                handle,
                u32::from_ne_bytes(address.octets()),
                request.as_ptr().cast(),
                request.len() as u16,
                ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                3000,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: handle is open and closed exactly once.
        unsafe { IcmpCloseHandle(handle) };
        if count == 0 {
            return Err(error);
        }
        // SAFETY: the call wrote at least one ICMP_ECHO_REPLY to the start of the buffer.
        let echo = unsafe { reply.as_ptr().cast::<ICMP_ECHO_REPLY>().read_unaligned() };
        if echo.Status != IP_SUCCESS {
            return Err(io::Error::other(format!("status {}", echo.Status)));
        }
        Ok(format!(
            "reply from {}",
            std::net::Ipv4Addr::from(echo.Address.to_ne_bytes())
        ))
    }

    /// Cross-user conformance probe (`tests/crossuser_windows.rs`). An AppContainer SID is derived
    /// from the name alone, so a process another user starts in a profile of the same name gets
    /// the same SID. This creates such a profile for the current user, runs a child `sandy-probe`
    /// in it, and gives the child a chosen set of capability SIDs, so a second user can measure
    /// what the shared SID (and a capability a first user's run put on an object) reaches of that
    /// first user's sandboxed run.
    ///
    /// Target: `NAME <US> CAPS <US> ACTION <US> TARGET`. CAPS is a comma-separated list of SDDL
    /// capability SID strings, empty for none: the well-known network capabilities (`S-1-15-3-1`
    /// internetClient, `S-1-15-3-2` internetClientServer, `S-1-15-3-3` privateNetworkClientServer)
    /// or a `sandy.grant...`/relay capability SID read off an object with `icacls`. The child
    /// prints its own `ACTION<TAB>TARGET<TAB>RESULT<TAB>DETAIL` line on the inherited standard
    /// output; this prints `appcontainer-run<TAB>NAME<TAB>ok|error<TAB>DETAIL` after it.
    /// Binds and listens on an IPv4 address, optionally with `SO_REUSEADDR`. Used by the
    /// port-takeover check: another user tries to bind an address and port a first user's run
    /// already holds inside the same-named AppContainer. Reports `ok` with the bound address, or
    /// the Winsock error (10048 `WSAEADDRINUSE`, 10013 `WSAEACCES`).
    pub fn tcp_listen_reuse(target: &str, reuse: bool) -> io::Result<String> {
        use std::mem::size_of;
        use std::net::SocketAddrV4;

        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, IN_ADDR, IN_ADDR_0, SO_REUSEADDR, SOCK_STREAM, SOCKADDR_IN, SOL_SOCKET, bind,
            htons, listen, setsockopt,
        };

        let address: SocketAddrV4 = target
            .parse()
            .map_err(|_| invalid("expected an IPv4 ADDRESS:PORT"))?;
        // SAFETY: WSADATA is plain data; WSAStartup fills it.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: data is a valid out pointer.
        if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let last = || {
            // SAFETY: WSAGetLastError has no preconditions.
            io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
        };
        // SAFETY: socket has no memory safety preconditions.
        let handle = unsafe { socket(i32::from(AF_INET), SOCK_STREAM, 0) };
        if handle == INVALID_SOCKET {
            return Err(last());
        }
        let outcome = (|| {
            if reuse {
                let on: u32 = 1;
                // SAFETY: handle is a valid socket; on is a u32 whose size is passed.
                let set = unsafe {
                    setsockopt(
                        handle,
                        SOL_SOCKET,
                        SO_REUSEADDR,
                        (&on as *const u32).cast(),
                        size_of::<u32>() as i32,
                    )
                };
                if set != 0 {
                    return Err(last());
                }
            }
            let sockaddr = SOCKADDR_IN {
                sin_family: AF_INET,
                // SAFETY: htons byte-swaps a u16.
                sin_port: unsafe { htons(address.port()) },
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr is a SOCKADDR_IN and its size is passed.
            let bound = unsafe {
                bind(
                    handle,
                    (&sockaddr as *const SOCKADDR_IN).cast(),
                    size_of::<SOCKADDR_IN>() as i32,
                )
            };
            if bound != 0 {
                return Err(last());
            }
            // SAFETY: handle is a bound socket.
            if unsafe { listen(handle, 1) } != 0 {
                return Err(last());
            }
            Ok(format!("listening on {address}"))
        })();
        // SAFETY: handle is an open socket, closed exactly once.
        unsafe { closesocket(handle) };
        outcome
    }

    pub fn appcontainer_run(target: &str) -> io::Result<String> {
        use std::mem::size_of;
        use std::os::windows::ffi::OsStrExt;

        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE,
            LocalFree,
        };
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::Isolation::{
            CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        };
        use windows_sys::Win32::Security::{
            FreeSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
        };
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        };

        // Split into four fields; the fourth keeps any further US, so an inner action whose own
        // target holds one (socks5-connect) passes through unchanged.
        let fields: Vec<&str> = target.splitn(4, '\u{1f}').collect();
        let [name, caps, action, inner] = fields.as_slice() else {
            return Err(invalid(
                "appcontainer-run needs NAME\u{1f}CAPS\u{1f}ACTION\u{1f}TARGET",
            ));
        };

        // Register the profile for the current user (the same SID as any other user's profile of
        // the name) so a process can be created in it, and derive the SID for the token.
        let name_w = wide(name);
        let description = wide("sandy cross-user probe");
        let mut profile: PSID = ptr::null_mut();
        // SAFETY: the strings are NUL-terminated, no capabilities are passed, profile is a valid
        // out pointer.
        let hr = unsafe {
            CreateAppContainerProfile(
                name_w.as_ptr(),
                name_w.as_ptr(),
                description.as_ptr(),
                ptr::null(),
                0,
                &mut profile,
            )
        };
        const ALREADY_EXISTS: i32 = (0x8007_0000u32 | ERROR_ALREADY_EXISTS) as i32;
        if hr >= 0 {
            // SAFETY: on success the function allocated a SID that must be freed.
            unsafe { FreeSid(profile) };
        } else if hr != ALREADY_EXISTS {
            return Err(io::Error::other(format!(
                "cannot create the AppContainer profile {name:?}: {hr:#010x}"
            )));
        }
        let mut app_sid: PSID = ptr::null_mut();
        // SAFETY: name_w is NUL-terminated and app_sid is a valid out pointer.
        let hr =
            unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut app_sid) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "cannot derive the AppContainer SID of {name:?}: {hr:#010x}"
            )));
        }

        // Convert each capability SID string. The pointers stay valid until after CreateProcessW.
        let mut cap_sids: Vec<PSID> = Vec::new();
        let free_all = |cap_sids: &[PSID], app_sid: PSID| {
            for &sid in cap_sids {
                // SAFETY: each SID was allocated by ConvertStringSidToSidW with LocalAlloc.
                unsafe { LocalFree(sid.cast()) };
            }
            // SAFETY: app_sid came from DeriveAppContainerSidFromAppContainerName.
            unsafe { FreeSid(app_sid) };
        };
        for cap in caps.split(',').filter(|c| !c.is_empty()) {
            let cap_w = wide(cap);
            let mut psid: PSID = ptr::null_mut();
            // SAFETY: cap_w is NUL-terminated and psid is a valid out pointer.
            if unsafe { ConvertStringSidToSidW(cap_w.as_ptr(), &mut psid) } == 0 {
                free_all(&cap_sids, app_sid);
                return Err(io::Error::other(format!("invalid capability SID {cap:?}")));
            }
            cap_sids.push(psid);
        }
        let mut attributes: Vec<SID_AND_ATTRIBUTES> = cap_sids
            .iter()
            .map(|&sid| SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_ENABLED as u32,
            })
            .collect();
        let security = SECURITY_CAPABILITIES {
            AppContainerSid: app_sid,
            Capabilities: if attributes.is_empty() {
                ptr::null_mut()
            } else {
                attributes.as_mut_ptr()
            },
            CapabilityCount: attributes.len() as u32,
            Reserved: 0,
        };

        // One attribute: the security capabilities that make the child an AppContainer process.
        let mut size = 0usize;
        // SAFETY: a null list with a size pointer only queries the required size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let mut list: Vec<usize> = vec![0; size.div_ceil(size_of::<usize>())];
        let attr_list =
            list.as_mut_ptr().cast::<core::ffi::c_void>() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: the buffer is at least `size` bytes and pointer-aligned.
        if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) } == 0 {
            free_all(&cap_sids, app_sid);
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the list is initialized; security outlives the CreateProcessW call below.
        let set = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&security as *const SECURITY_CAPABILITIES).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if set == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: the list was initialized above.
            unsafe { DeleteProcThreadAttributeList(attr_list) };
            free_all(&cap_sids, app_sid);
            return Err(error);
        }

        // The child inherits this process's standard output, so its one result line comes
        // through. The standard handles must be inheritable; duplicate them so and close the
        // copies after.
        let mut to_close: Vec<HANDLE> = Vec::new();
        let mut std_handle = |which| {
            // SAFETY: GetStdHandle has no preconditions.
            let handle = unsafe { GetStdHandle(which) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return handle;
            }
            let mut copy: HANDLE = ptr::null_mut();
            // SAFETY: the current-process pseudo handle is valid and copy is a valid out pointer.
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    GetCurrentProcess(),
                    &mut copy,
                    0,
                    TRUE,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 {
                handle
            } else {
                to_close.push(copy);
                copy
            }
        };
        let stdin_handle = std_handle(STD_INPUT_HANDLE);
        let stdout_handle = std_handle(STD_OUTPUT_HANDLE);
        let stderr_handle = std_handle(STD_ERROR_HANDLE);
        let close_std = |to_close: &[HANDLE]| {
            for &handle in to_close {
                // SAFETY: each handle is a fresh duplicate owned here.
                unsafe { CloseHandle(handle) };
            }
        };

        let exe = std::env::current_exe()?;
        let program: Vec<u16> = exe.as_os_str().encode_wide().collect();
        let args = [
            action.encode_utf16().collect::<Vec<u16>>(),
            inner.encode_utf16().collect::<Vec<u16>>(),
        ];
        let mut command_line = match sandy_windows::cmdline::command_line(&program, &args) {
            Ok(line) => line,
            Err(error) => {
                // SAFETY: the list was initialized above.
                unsafe { DeleteProcThreadAttributeList(attr_list) };
                close_std(&to_close);
                free_all(&cap_sids, app_sid);
                return Err(io::Error::other(error.to_string()));
            }
        };
        let application: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin_handle;
        startup.StartupInfo.hStdOutput = stdout_handle;
        startup.StartupInfo.hStdError = stderr_handle;
        startup.lpAttributeList = attr_list;
        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: application and command_line are NUL-terminated, command_line is writable, the
        // inherited environment holds the LOCALAPPDATA and SystemRoot an AppContainer needs, and
        // startup and the values it points to outlive the call.
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                TRUE,
                EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS,
                ptr::null(),
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        // SAFETY: the list was initialized above.
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        if ok == 0 {
            let error = io::Error::last_os_error();
            close_std(&to_close);
            free_all(&cap_sids, app_sid);
            return Err(error);
        }
        let (process, thread) = (info.hProcess, info.hThread);
        // SAFETY: process is a valid handle; wait at most 90 seconds for the child.
        unsafe { WaitForSingleObject(process, 90_000) };
        let mut code = 0u32;
        // SAFETY: process is a valid handle and code is a valid out pointer.
        unsafe { GetExitCodeProcess(process, &mut code) };
        // SAFETY: both handles are valid and closed exactly once.
        unsafe {
            CloseHandle(thread);
            CloseHandle(process);
        }
        close_std(&to_close);
        free_all(&cap_sids, app_sid);
        Ok(format!("child exit {code}"))
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

    pub fn grant_all_packages(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn open_process_right(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn open_thread_right(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn junction(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn symbolic_link(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn list_processes() -> io::Result<String> {
        unsupported()
    }

    pub fn session_id() -> io::Result<String> {
        unsupported()
    }

    pub fn wts_processes() -> io::Result<String> {
        unsupported()
    }

    pub fn enum_windows() -> io::Result<String> {
        unsupported()
    }

    pub fn icmp_echo(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn appcontainer_run(_target: &str) -> io::Result<String> {
        unsupported()
    }

    pub fn tcp_listen_reuse(_target: &str, _reuse: bool) -> io::Result<String> {
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
        "icmp-socket-echo",
        "fork",
        "vfork",
        "posix-spawn",
        "execve",
        "thread",
        "rename",
        "rmdir",
        "host-uuid",
        "fcntl-read-only",
        "exception-ports",
        "exception-port-exec",
        "fsgetpath-ext",
        "openbyid",
        "searchfs",
        "vol-getattr",
        "getattr",
        "setattr",
        "getattrlistbulk",
        "getfsstat",
        "metadata",
        "sigio-signal",
        "spawn-join",
        "fd-metadata",
        "access",
        "statfs",
        "chdir",
        "pid-info",
        "pid-path",
        "list-pids",
        "getpgid",
        "getsid",
        "getpriority",
        "necp-open",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "exception-ports" => exception_ports(),
            "exception-port-exec" => exception_port_exec(target),
            "fsgetpath-ext" => fsgetpath_ext(target),
            "openbyid" => openbyid(target),
            "searchfs" => searchfs(target),
            "vol-getattr" => vol_getattr(target),
            "getattr" => getattr(target),
            "setattr" => setattr(target),
            "getattrlistbulk" => getattrlistbulk(target),
            "getfsstat" => getfsstat(),
            "metadata" => metadata(target),
            "sigio-signal" => sigio_signal(target),
            "spawn-join" => spawn_join(target),
            "fd-metadata" => fd_metadata(target),
            "access" => path_call(target, |path| {
                // SAFETY: access reads the NUL-terminated path.
                unsafe { libc::access(path, libc::F_OK) }
            }),
            "statfs" => statfs(target),
            "chdir" => path_call(target, |path| {
                // SAFETY: chdir reads the NUL-terminated path.
                unsafe { libc::chdir(path) }
            }),
            "pid-info" => pid_info(pid(target)?),
            "pid-path" => pid_path(pid(target)?),
            "list-pids" => list_pids(),
            // SAFETY: getpgid takes a process ID and changes nothing.
            "getpgid" => process_query(target, |pid| unsafe { libc::getpgid(pid) }),
            // SAFETY: getsid takes a process ID and changes nothing.
            "getsid" => process_query(target, |pid| unsafe { libc::getsid(pid) }),
            "getpriority" => process_query(target, |pid| {
                // SAFETY: getpriority takes a process ID and changes nothing.
                unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) }
            }),
            "necp-open" => necp_open(),
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
            "icmp-socket-echo" => icmp_socket_echo(target),
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

    /// A call that takes only a path and returns 0 or -1.
    fn path_call(target: &str, call: impl Fn(*const c_char) -> libc::c_int) -> io::Result<String> {
        let path = cstr(target)?;
        if call(path.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::new())
    }

    /// The volume a path lies on, with its device and the directory it is mounted on.
    fn statfs(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        // SAFETY: statfs is plain data, and the call fills all of it.
        let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: the path is NUL-terminated and `volume` is a statfs the call may write.
        if unsafe { libc::statfs(path.as_ptr(), &mut volume) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!(
            "{} on {}",
            c_text(&volume.f_mntfromname),
            c_text(&volume.f_mntonname)
        ))
    }

    /// The text of a NUL-terminated C string buffer.
    fn c_text(field: &[c_char]) -> String {
        let bytes: Vec<u8> = field
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// A process ID, or `self` for the probe's own.
    fn pid(target: &str) -> io::Result<libc::pid_t> {
        if target == "self" {
            return Ok(std::process::id() as libc::pid_t);
        }
        target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))
    }

    /// The name and owner of a process (`proc_pidinfo` with PROC_PIDTBSDINFO).
    fn pid_info(pid: libc::pid_t) -> io::Result<String> {
        // SAFETY: proc_bsdinfo is plain data.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the call writes at most `size` bytes into `info`.
        let written = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if written != size {
            return Err(io::Error::last_os_error());
        }
        Ok(format!(
            "uid {} name {}",
            info.pbi_uid,
            c_text(&info.pbi_name)
        ))
    }

    /// The executable of a process (`proc_pidpath`).
    fn pid_path(pid: libc::pid_t) -> io::Result<String> {
        let mut path = [0 as c_char; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the call writes at most the buffer's length into it.
        let length =
            unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if length <= 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(c_text(&path))
    }

    /// How many processes `proc_listallpids` names.
    fn list_pids() -> io::Result<String> {
        // SAFETY: a null buffer asks for the number of processes only.
        let count = unsafe { libc::proc_listallpids(ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{count} processes"))
    }

    /// getpgid, getsid or getpriority of the process `target` names: -1 with errno set means
    /// the call failed. getpriority may return -1 as a priority, so errno is cleared first.
    fn process_query(
        target: &str,
        call: impl Fn(libc::pid_t) -> libc::c_int,
    ) -> io::Result<String> {
        let pid = pid(target)?;
        // SAFETY: __error returns the address of this thread's errno.
        unsafe { *libc::__error() = 0 };
        let value = call(pid);
        let error = io::Error::last_os_error();
        if value == -1 && error.raw_os_error() != Some(0) {
            return Err(error);
        }
        Ok(value.to_string())
    }

    /// necp_open(2), the descriptor Network.framework asks NECP through. The descriptor is
    /// guarded: closing it would raise EXC_GUARD, so it stays open until the probe exits.
    fn necp_open() -> io::Result<String> {
        const SYS_NECP_OPEN: libc::c_int = 501;
        // SAFETY: necp_open takes flags and returns a descriptor or -1.
        let descriptor = unsafe { libc::syscall(SYS_NECP_OPEN, 0) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::new())
    }

    /// Sends one ICMP echo request to the IPv4 address `target` through an ICMP datagram socket,
    /// which an ordinary user may create, and waits up to three seconds for the reply.
    fn icmp_socket_echo(target: &str) -> io::Result<String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let address: std::net::Ipv4Addr = target
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 address"))?;
        // SAFETY: socket has no memory arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor is new and owned by nothing else.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval {
            tv_sec: 3,
            tv_usec: 0,
        };
        // SAFETY: the value is a timeval of the size passed.
        let set = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if set != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sockaddr_in is plain data, and zero is a valid value for every field.
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        raw.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        raw.sin_family = libc::AF_INET as libc::sa_family_t;
        raw.sin_addr.s_addr = u32::from(address).to_be();
        // Type 8 (echo request), code 0, identifier and sequence 0, and the checksum of that.
        let request = [8u8, 0, 0xf7, 0xff, 0, 0, 0, 0];
        // SAFETY: the buffer and the address are valid for the lengths passed.
        let sent = unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const raw).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut reply = [0u8; 128];
        // SAFETY: the buffer is valid for its length.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{received} bytes"))
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
        Ok(text(&buffer, length as usize))
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

    /// Changes metadata through a descriptor opened for reading: `PATH<U+001F>CALL` with CALL
    /// one of `fchmod`, `fchown` (to the owner it has), `fchflags`, `futimes` and `fsetxattr`.
    fn fd_metadata(target: &str) -> io::Result<String> {
        use std::os::fd::AsRawFd;

        let (path, call) = super::pair(target)?;
        let file = fs::File::open(path)?;
        let fd = file.as_raw_fd();
        let times = [libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        }; 2];
        let value = b"x";
        // SAFETY: each call takes the open descriptor and, where it reads memory, a buffer of the
        // length it is given.
        let result = unsafe {
            match call {
                "fchmod" => libc::fchmod(fd, 0o600),
                "fchown" => libc::fchown(fd, libc::getuid(), libc::getgid()),
                "fchflags" => libc::fchflags(fd, libc::UF_HIDDEN),
                "futimes" => libc::futimes(fd, times.as_ptr()),
                "fsetxattr" => libc::fsetxattr(
                    fd,
                    c"user.sandy.review".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    0,
                ),
                _ => {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown call"));
                }
            }
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::new())
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

    /// Every machine-independent exception, the value of `EXC_MASK_ALL` in
    /// `<mach/exception_types.h>` (measured on macOS 26.5), plus `EXC_MASK_CRASH` (0x400), which
    /// is not part of it and which Crashpad's handler takes, and `EXC_MASK_CORPSE_NOTIFY`
    /// (0x2000), whose handler gets the task of a crashed program.
    const EXC_MASK_HANDLED: u32 = 0x1bfe | 0x400 | 0x2000;
    const EXCEPTION_DEFAULT: u32 = 1;
    const THREAD_STATE_NONE: i32 = 0;
    const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
    const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
    /// The name of a send right whose receive right is gone.
    const MACH_PORT_DEAD: libc::mach_port_t = !0;
    /// `EXC_TYPES_COUNT`: the most slots `task_get_exception_ports` can return.
    const EXCEPTION_SLOTS: usize = 14;

    unsafe extern "C" {
        fn task_get_exception_ports(
            task: libc::mach_port_t,
            mask: u32,
            masks: *mut u32,
            count: *mut u32,
            handlers: *mut libc::mach_port_t,
            behaviors: *mut u32,
            flavors: *mut i32,
        ) -> libc::kern_return_t;
        fn task_set_exception_ports(
            task: libc::mach_port_t,
            mask: u32,
            handler: libc::mach_port_t,
            behavior: u32,
            flavor: i32,
        ) -> libc::kern_return_t;
        fn mach_port_allocate(
            task: libc::mach_port_t,
            right: u32,
            name: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
        fn mach_port_insert_right(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
            right: libc::mach_port_t,
            kind: u32,
        ) -> libc::kern_return_t;
    }

    /// The task port of this process. The libc binding is deprecated in favour of the mach2
    /// crate, which sandy does not depend on.
    #[allow(deprecated)]
    fn task_self() -> libc::mach_port_t {
        // SAFETY: mach_task_self only reads the port name that libSystem set up at start.
        unsafe { libc::mach_task_self() }
    }

    /// How many live Mach exception handler ports the task holds. A handler port is a send
    /// right, so it needs no `mach-lookup`: a program that inherits one can send a message to the
    /// crash handler of whoever started sandy. A dead name, whose receiver is gone, reaches
    /// nobody and does not count.
    fn exception_ports() -> io::Result<String> {
        let mut masks = [0u32; EXCEPTION_SLOTS];
        let mut handlers = [0 as libc::mach_port_t; EXCEPTION_SLOTS];
        let mut behaviors = [0u32; EXCEPTION_SLOTS];
        let mut flavors = [0i32; EXCEPTION_SLOTS];
        let mut count = EXCEPTION_SLOTS as u32;
        // SAFETY: every array holds EXCEPTION_SLOTS entries, which `count` states; the call
        // writes no more and updates `count`.
        let result = unsafe {
            task_get_exception_ports(
                task_self(),
                EXC_MASK_HANDLED,
                masks.as_mut_ptr(),
                &mut count,
                handlers.as_mut_ptr(),
                behaviors.as_mut_ptr(),
                flavors.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::other(format!(
                "task_get_exception_ports returned {result}"
            )));
        }
        let live = handlers[..count as usize]
            .iter()
            .filter(|port| **port != 0 && **port != MACH_PORT_DEAD)
            .count();
        Ok(live.to_string())
    }

    /// Installs a Mach exception handler port on this task and starts the program in `target`
    /// (program and arguments separated by U+001F) in a forked child, as a caller with a crash
    /// reporter starts sandy. Mach port rights are not descriptors: the child gets a send right
    /// to the handler and keeps it across the exec. The probe holds the receive right and waits
    /// for the child, so the right stays live, and exits with the child's status.
    fn exception_port_exec(target: &str) -> io::Result<String> {
        let mut port: libc::mach_port_t = 0;
        let task = task_self();
        // SAFETY: mach_port_allocate writes one port name into `port`; the other two calls take
        // that name and no pointers.
        let result = unsafe {
            match mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut port) {
                0 => match mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND) {
                    0 => task_set_exception_ports(
                        task,
                        EXC_MASK_HANDLED,
                        port,
                        EXCEPTION_DEFAULT,
                        THREAD_STATE_NONE,
                    ),
                    error => error,
                },
                error => error,
            }
        };
        if result != 0 {
            return Err(io::Error::other(format!(
                "installing the exception port returned {result}"
            )));
        }
        let mut parts = target.split(super::ARGUMENT_SEPARATOR);
        let program = cstr(parts.next().unwrap_or_default())?;
        let arguments: Vec<CString> = std::iter::once(Ok(program.clone()))
            .chain(parts.map(cstr))
            .collect::<io::Result<_>>()?;
        let argv: Vec<*const c_char> = arguments
            .iter()
            .map(|argument| argument.as_ptr())
            .chain(std::iter::once(ptr::null()))
            .collect();
        // SAFETY: the probe has one thread, so the child may run any code; it leaves through
        // execv or `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: every pointer refers to a CString that lives until execv returns, and the
            // array ends with a null pointer.
            unsafe {
                libc::execv(program.as_ptr(), argv.as_ptr());
                libc::_exit(127)
            }
        }
        if child < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        if unsafe { libc::waitpid(child, &mut status, 0) } != child {
            return Err(io::Error::last_os_error());
        }
        std::process::exit(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        })
    }

    /// A function of libSystem that the SDK headers do not declare.
    fn symbol(name: &std::ffi::CStr) -> io::Result<*mut libc::c_void> {
        // SAFETY: RTLD_DEFAULT searches the images that are already loaded; the name is a C
        // string.
        let found = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        if found.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("libSystem has no {}", name.to_string_lossy()),
            ));
        }
        Ok(found)
    }

    /// The path of a file named by volume id and inode number, through `fsgetpath_ext`, the
    /// newer variant of fsgetpath. The profile denies it by system call number.
    fn fsgetpath_ext(target: &str) -> io::Result<String> {
        type Call =
            unsafe extern "C" fn(*mut c_char, libc::size_t, *const Fsid, u64, u32) -> libc::ssize_t;
        let found = symbol(c"fsgetpath_ext")?;
        // SAFETY: this is the signature of fsgetpath_ext in libSystem.
        let call = unsafe { std::mem::transmute::<*mut libc::c_void, Call>(found) };
        let (dev, inode) = dev_inode(target)?;
        let fsid = Fsid {
            val: [dev as i32, 0],
        };
        let mut buffer = [0 as c_char; 1024];
        // SAFETY: the call reads the two-int fsid and writes at most buffer.len() bytes.
        let length = unsafe { call(buffer.as_mut_ptr(), buffer.len(), &fsid, inode, 0) };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(text(&buffer, length as usize))
    }

    /// Opens a file by volume id and inode number (`openbyid_np`) and reads one byte. XNU asks
    /// for a private privilege first, so this fails outside the sandbox as well; the profile
    /// denies the system call in any case.
    fn openbyid(target: &str) -> io::Result<String> {
        #[repr(C)]
        struct ObjectId {
            number: u32,
            generation: u32,
        }
        type Call = unsafe extern "C" fn(*const Fsid, *const ObjectId, libc::c_int) -> libc::c_int;
        let found = symbol(c"openbyid_np")?;
        // SAFETY: this is the signature of openbyid_np in libSystem.
        let call = unsafe { std::mem::transmute::<*mut libc::c_void, Call>(found) };
        let (dev, inode) = dev_inode(target)?;
        let fsid = Fsid {
            val: [dev as i32, 0],
        };
        let object = ObjectId {
            number: inode as u32,
            generation: 0,
        };
        // SAFETY: the call reads both structures and returns a descriptor or -1.
        let descriptor = unsafe { call(&fsid, &object, libc::O_RDONLY) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut byte = [0u8; 1];
        // SAFETY: reads one byte into a buffer of one byte from a descriptor this function owns.
        let read = unsafe { libc::read(descriptor, byte.as_mut_ptr().cast(), 1) };
        // SAFETY: closing a descriptor this function owns.
        unsafe { libc::close(descriptor) };
        Ok(format!("{read} bytes"))
    }

    const SRCHFS_START: libc::c_uint = 0x0000_0001;
    const SRCHFS_MATCHFILES: libc::c_uint = 0x0000_0008;

    /// An attribute list that asks for common attributes only.
    fn common_attributes(attributes: libc::attrgroup_t) -> libc::attrlist {
        libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: attributes,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        }
    }

    /// The name search of `searchfs`: the attribute buffer holds its own size, then the
    /// reference to the name, then the name itself.
    #[repr(C)]
    struct NameSearch {
        size: u32,
        name: libc::attrreference_t,
        text: [u8; 64],
    }

    #[repr(C)]
    struct SearchBlock {
        return_attributes: *mut libc::attrlist,
        return_buffer: *mut libc::c_void,
        return_buffer_size: libc::size_t,
        max_matches: libc::c_ulong,
        time_limit: libc::timeval,
        search_parameters1: *mut libc::c_void,
        size_of_search_parameters1: libc::size_t,
        search_parameters2: *mut libc::c_void,
        size_of_search_parameters2: libc::size_t,
        search_attributes: libc::attrlist,
    }

    /// Searches the catalog of a volume for a file name, without walking any directory
    /// (`searchfs`). `target` is `VOLUME_PATH<U+001F>NAME`: the volume is the one the path lies
    /// on. The profile denies the system call, so inside the sandbox this never searches.
    fn searchfs(target: &str) -> io::Result<String> {
        type Call = unsafe extern "C" fn(
            *const c_char,
            *mut SearchBlock,
            *mut libc::c_ulong,
            libc::c_uint,
            libc::c_uint,
            *mut libc::c_void,
        ) -> libc::c_int;
        let found = symbol(c"searchfs")?;
        // SAFETY: this is the signature of searchfs in libSystem.
        let call = unsafe { std::mem::transmute::<*mut libc::c_void, Call>(found) };
        let (volume, name) = super::pair(target)?;
        let volume = cstr(volume)?;
        let mut wanted = NameSearch {
            size: std::mem::size_of::<NameSearch>() as u32,
            name: libc::attrreference_t {
                attr_dataoffset: std::mem::size_of::<libc::attrreference_t>() as i32,
                attr_length: name.len() as u32 + 1,
            },
            text: [0; 64],
        };
        if name.len() >= wanted.text.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        wanted.text[..name.len()].copy_from_slice(name.as_bytes());
        let mut returned = common_attributes(libc::ATTR_CMN_NAME);
        let mut matches = [0u8; 4096];
        let mut block = SearchBlock {
            return_attributes: &mut returned,
            return_buffer: matches.as_mut_ptr().cast(),
            return_buffer_size: matches.len(),
            max_matches: 8,
            time_limit: libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            },
            search_parameters1: (&raw mut wanted).cast(),
            size_of_search_parameters1: std::mem::size_of::<NameSearch>(),
            search_parameters2: ptr::null_mut(),
            size_of_search_parameters2: 0,
            search_attributes: common_attributes(libc::ATTR_CMN_NAME),
        };
        // `struct searchstate` is opaque; it is 556 bytes on every macOS that has searchfs.
        let mut state = [0u8; 556];
        let mut count: libc::c_ulong = 0;
        // SAFETY: the block points to buffers that outlive the call, and each size field matches
        // its buffer.
        let result = unsafe {
            call(
                volume.as_ptr(),
                &mut block,
                &mut count,
                0,
                SRCHFS_START | SRCHFS_MATCHFILES,
                state.as_mut_ptr().cast(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("{count} matches"))
    }

    /// The full path of a file named by volume id and inode number, through `getattrlist` on its
    /// `/.vol` path, which names the file without walking its directories.
    fn vol_getattr(target: &str) -> io::Result<String> {
        let (dev, inode) = dev_inode(target)?;
        full_path(&format!("/.vol/{dev}/{inode}"))
    }

    /// The modification time and the full path of `target` through `getattrlist`, which is the
    /// one file call that returns a path instead of taking one (ATTR_CMN_FULLPATH).
    /// `PATH<U+001F>fullpath` or `PATH<U+001F>modtime` asks for one of the two alone.
    fn getattr(target: &str) -> io::Result<String> {
        match target.split_once(super::ARGUMENT_SEPARATOR) {
            Some((path, "fullpath")) => attributes(path, libc::ATTR_CMN_FULLPATH),
            Some((path, "modtime")) => attributes(path, libc::ATTR_CMN_MODTIME),
            Some((path, _)) => full_path(path),
            None => full_path(target),
        }
    }

    /// One attribute of `path`, reported as the kernel returned it.
    fn attributes(path: &str, wanted: libc::attrgroup_t) -> io::Result<String> {
        let path = cstr(path)?;
        let mut list = common_attributes(wanted);
        let mut buffer = [0u8; 2048];
        // SAFETY: the call writes at most buffer.len() bytes into the buffer.
        let result = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&raw mut list).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if wanted == libc::ATTR_CMN_FULLPATH {
            return read_reference(&buffer, 4);
        }
        let seconds = i64::from_ne_bytes(
            buffer[4..12]
                .try_into()
                .map_err(|_| io::Error::other("the attribute buffer is malformed"))?,
        );
        Ok(format!("mtime {seconds}"))
    }

    fn full_path(path: &str) -> io::Result<String> {
        let path = cstr(path)?;
        let mut wanted = common_attributes(libc::ATTR_CMN_MODTIME | libc::ATTR_CMN_FULLPATH);
        let mut buffer = [0u8; 2048];
        // SAFETY: the call writes at most buffer.len() bytes into the buffer.
        let result = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&raw mut wanted).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // The buffer starts with its own length, then the attributes in the order of their
        // bits: the modification time (a timespec), then the reference to the path.
        let seconds = i64::from_ne_bytes(
            buffer[4..12]
                .try_into()
                .map_err(|_| io::Error::other("the attribute buffer is malformed"))?,
        );
        let path = read_reference(&buffer, 4 + std::mem::size_of::<libc::timespec>())?;
        Ok(format!("{path} mtime {seconds}"))
    }

    /// Sets the modification time of `target` through `setattrlist`, the counterpart of
    /// getattrlist. Writing metadata outside a writable path must be denied.
    fn setattr(target: &str) -> io::Result<String> {
        let path = cstr(target)?;
        let mut wanted = common_attributes(libc::ATTR_CMN_MODTIME);
        let time = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        // SAFETY: the attribute buffer holds exactly the one timespec the list asks for.
        let result = unsafe {
            libc::setattrlist(
                path.as_ptr(),
                (&raw mut wanted).cast(),
                (&raw const time).cast_mut().cast(),
                std::mem::size_of::<libc::timespec>(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::new())
    }

    /// Reads the variable-length attribute at `at` as text: the reference holds the offset of
    /// the data, counted from the reference itself.
    fn read_reference(buffer: &[u8], at: usize) -> io::Result<String> {
        let invalid = || io::Error::other("the attribute buffer is malformed");
        let header = buffer.get(at..at + 8).ok_or_else(invalid)?;
        let offset = i32::from_ne_bytes(header[..4].try_into().map_err(|_| invalid())?);
        let length = u32::from_ne_bytes(header[4..].try_into().map_err(|_| invalid())?) as usize;
        let start = at.checked_add_signed(offset as isize).ok_or_else(invalid)?;
        let data = buffer
            .get(start..start + length.saturating_sub(1))
            .ok_or_else(invalid)?;
        Ok(String::from_utf8_lossy(data).into_owned())
    }

    /// Lists a directory with `getattrlistbulk`, which returns the metadata of every entry in one
    /// call instead of one `stat` per name. Reports the entries it returned with their file ids.
    /// `PATH<U+001F>objtype` also asks for the type of each entry.
    fn getattrlistbulk(target: &str) -> io::Result<String> {
        let (target, object_type) = match target.split_once(super::ARGUMENT_SEPARATOR) {
            Some((path, "objtype")) => (path, libc::ATTR_CMN_OBJTYPE),
            _ => (target, 0),
        };
        let path = cstr(target)?;
        // SAFETY: the path is a C string; O_RDONLY on a directory needs no mode.
        let directory = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if directory < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut wanted = common_attributes(
            libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_NAME
                | object_type
                | libc::ATTR_CMN_FILEID,
        );
        let mut buffer = [0u8; 8192];
        // SAFETY: the call writes at most buffer.len() bytes into the buffer.
        let count = unsafe {
            libc::getattrlistbulk(
                directory,
                (&raw mut wanted).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        // SAFETY: closing a descriptor this function owns.
        unsafe { libc::close(directory) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut entries = Vec::new();
        let mut at = 0usize;
        for _ in 0..count {
            let length = u32::from_ne_bytes(
                buffer
                    .get(at..at + 4)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| io::Error::other("the entry is cut short"))?,
            ) as usize;
            // After the length comes the set of attributes that are present (five words), then
            // the attributes themselves in order; the type takes four bytes.
            let name = read_reference(&buffer, at + 4 + 20)?;
            let id_at = at + 4 + 20 + 8 + if object_type == 0 { 0 } else { 4 };
            let id = u64::from_ne_bytes(
                buffer
                    .get(id_at..id_at + 8)
                    .and_then(|bytes| bytes.try_into().ok())
                    .unwrap_or_default(),
            );
            entries.push(format!("{name}#{id}"));
            at += length;
        }
        Ok(format!("{count} entries: {}", entries.join(" ")))
    }

    /// Every mounted volume (`getfsstat`), with the directory it is mounted on. This needs no
    /// path, so no file rule of the profile applies to it.
    fn getfsstat() -> io::Result<String> {
        // SAFETY: a null buffer asks for the number of volumes only.
        let count = unsafe { libc::getfsstat(ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut volumes: Vec<libc::statfs> = Vec::with_capacity(count as usize);
        let size = count as usize * std::mem::size_of::<libc::statfs>();
        // SAFETY: the buffer holds `count` statfs values, which `size` states; getfsstat fills
        // the first `got` of them.
        let got = unsafe {
            let got = libc::getfsstat(volumes.as_mut_ptr(), size as libc::c_int, libc::MNT_NOWAIT);
            if got >= 0 {
                volumes.set_len(got as usize);
            }
            got
        };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let names: Vec<String> = volumes
            .iter()
            .map(|volume| {
                let bytes: Vec<u8> = volume
                    .f_mntonname
                    .iter()
                    .take_while(|byte| **byte != 0)
                    .map(|byte| *byte as u8)
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            })
            .collect();
        Ok(format!("{got} volumes: {}", names.join(" ")))
    }

    /// The metadata of a path, without following a final symbolic link (`lstat`). It tells
    /// whether a path outside the policy can be told apart from one that does not exist.
    fn metadata(target: &str) -> io::Result<String> {
        let metadata = fs::symlink_metadata(target)?;
        Ok(format!("{} bytes", metadata.len()))
    }

    /// Asks the kernel to send SIGIO to another process: `F_SETOWN` names the owner of a
    /// socket pair end (or a pipe with `PID:pipe`), `O_ASYNC` turns on the signal, and the write
    /// makes the other end readable. The owner needs no relation to this process.
    /// `PID:KIND:IOCTL` names the owner with the ioctl `fiosetown`, `siocspgrp` or `tiocspgrp`
    /// instead of `F_SETOWN`.
    fn sigio_signal(target: &str) -> io::Result<String> {
        let mut fields = target.splitn(3, ':');
        let pid = fields.next().unwrap_or_default();
        let kind = fields.next().unwrap_or("socket");
        let request = match fields.next() {
            None => None,
            Some("fiosetown") => Some(libc::FIOSETOWN),
            Some("siocspgrp") => Some(libc::SIOCSPGRP),
            Some("tiocspgrp") => Some(libc::TIOCSPGRP),
            Some(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ioctl"));
            }
        };
        let pid: libc::pid_t = pid
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: both calls write two descriptors into `ends`.
        let made = unsafe {
            match kind {
                "pipe" => libc::pipe(ends.as_mut_ptr()),
                _ => libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, ends.as_mut_ptr()),
            }
        };
        if made != 0 {
            return Err(io::Error::last_os_error());
        }
        let (owned, other) = (ends[0], ends[1]);
        let result = (|| {
            // SAFETY: F_SETOWN and F_SETFL take an integer argument, F_GETFL none; the owner
            // ioctls read one int.
            unsafe {
                let named = match request {
                    None => libc::fcntl(owned, libc::F_SETOWN, pid),
                    Some(request) => libc::ioctl(owned, request, &pid),
                };
                if named == -1 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(owned, libc::F_GETFL);
                if flags == -1 || libc::fcntl(owned, libc::F_SETFL, flags | libc::O_ASYNC) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            let byte = *b"x";
            // SAFETY: writes one byte from a valid buffer.
            if unsafe { libc::write(other, byte.as_ptr().cast(), 1) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // Let the kernel deliver the signal before the descriptors close.
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(format!("SIGIO to {pid}"))
        })();
        // SAFETY: closing descriptors this function owns.
        unsafe {
            libc::close(owned);
            libc::close(other);
        }
        result
    }

    /// Starts a program in another process group with posix_spawn and POSIX_SPAWN_SETPGROUP:
    /// `PGID<U+001F>PROGRAM<U+001F>ARGUMENT...`. The kernel changes the group itself, where no
    /// profile rule for `setpgid` sees it. Reports the new process and the group it ended up in.
    fn spawn_join(target: &str) -> io::Result<String> {
        let (group, command) = super::pair(target)?;
        let group: libc::pid_t = group
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid group"))?;
        let mut parts = command.split(super::ARGUMENT_SEPARATOR);
        let program = cstr(parts.next().unwrap_or_default())?;
        let arguments: Vec<CString> = std::iter::once(Ok(program.clone()))
            .chain(parts.map(cstr))
            .collect::<io::Result<_>>()?;
        let argv: Vec<*mut c_char> = arguments
            .iter()
            .map(|argument| argument.as_ptr().cast_mut())
            .chain(std::iter::once(ptr::null_mut()))
            .collect();
        let mut attributes: libc::posix_spawnattr_t = ptr::null_mut();
        let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
        let discard = cstr("/dev/null")?;
        let mut child: libc::pid_t = 0;
        // SAFETY: the attributes and file actions are initialized before use and destroyed
        // afterwards; argv ends with a null pointer and the strings outlive the call.
        let result = unsafe {
            libc::posix_spawnattr_init(&mut attributes);
            libc::posix_spawnattr_setflags(&mut attributes, libc::POSIX_SPAWN_SETPGROUP as i16);
            libc::posix_spawnattr_setpgroup(&mut attributes, group);
            // The child would otherwise write its own report into the output of this process.
            libc::posix_spawn_file_actions_init(&mut actions);
            for descriptor in 0..=2 {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    descriptor,
                    discard.as_ptr(),
                    libc::O_RDWR,
                    0,
                );
            }
            let result = libc::posix_spawn(
                &mut child,
                program.as_ptr(),
                &actions,
                &attributes,
                argv.as_ptr(),
                ptr::null(),
            );
            libc::posix_spawn_file_actions_destroy(&mut actions);
            libc::posix_spawnattr_destroy(&mut attributes);
            result
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        // SAFETY: getpgid takes a process ID.
        let joined = unsafe { libc::getpgid(child) };
        Ok(format!("pid {child} group {joined}"))
    }

    /// The text in a C string buffer that a call filled with `length` bytes, including its
    /// terminating NUL.
    fn text(buffer: &[c_char], length: usize) -> String {
        let end = length.min(buffer.len()).saturating_sub(1);
        let bytes: Vec<u8> = buffer[..end].iter().map(|byte| *byte as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
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
        "start-job",
        "setpgid-join",
        "tcsetpgrp",
        "tiocswinsz",
        "signal-parent",
        "stop-self",
        "ignore-signal",
        "raise-signal",
        "start-forked",
        "start-orphaned",
        "fork-walk",
        "await-signal",
        "type-interrupt",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "fork-walk" => fork_walk(target),
            "await-signal" => await_signal(target),
            "start-job" => start_job(target),
            "setpgid-join" => setpgid_join(number(target)?),
            "tcsetpgrp" => tcsetpgrp(number(target)?),
            "tiocswinsz" => tiocswinsz(number(target)?),
            // SAFETY: setsid has no arguments.
            "setsid" => check(unsafe { libc::setsid() }).map(|_| String::new()),
            // SAFETY: setpgid takes process IDs; 0 and 0 make the caller a group leader.
            "setpgid" => check(unsafe { libc::setpgid(0, 0) }).map(|_| String::new()),
            // Signal 0 only checks permission. The parent is sandy with children = "contained".
            "signal-parent" => {
                // SAFETY: getppid has no preconditions.
                let parent = unsafe { libc::getppid() };
                // A parent outside the probe's PID namespace has no ID in it, and kill(0) would
                // signal the probe's own group.
                if parent == 0 {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                // SAFETY: kill takes a process ID and a signal.
                check(unsafe { libc::kill(parent, 0) }).map(|_| String::new())
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
            // Ends the probe by signal `target`, so a caller sees a signal death.
            "raise-signal" => {
                let signal = number(target)?;
                // SAFETY: restoring the default action has no memory safety requirements.
                if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: raise sends the signal to this process.
                check(unsafe { libc::raise(signal) })?;
                Err(io::Error::other("the signal did not end the probe"))
            }
            "start-forked" => start_forked(target),
            "start-orphaned" => start_orphaned(target),
            // Writes the interrupt character, Ctrl+C, to descriptor `target`. Into the master side
            // of a pseudo-terminal, that is a user typing it.
            "type-interrupt" => {
                // SAFETY: write reads one byte from the buffer.
                let written = unsafe { libc::write(number(target)?, [3u8].as_ptr().cast(), 1) };
                check(written as libc::c_int).map(|_| String::new())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    /// Starts a program (arguments separated by U+001F) from a child process that waits until
    /// its own parent has ended, so the program has no parent any more before its first
    /// instruction. Reports the child's process ID. Unlike `start`, the child keeps the standard
    /// streams, so the caller can read what the program writes.
    fn start_orphaned(target: &str) -> io::Result<String> {
        use std::ffi::CString;

        let target = super::expand(target)?;
        let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "the target holds a NUL");
        let args = target
            .split(super::ARGUMENT_SEPARATOR)
            .map(|part| CString::new(part).map_err(invalid))
            .collect::<io::Result<Vec<CString>>>()?;
        let argv: Vec<*const libc::c_char> = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain([ptr::null()])
            .collect();
        // Read before the fork. The child must not ask getppid for it: when the probe has
        // already exited by the time the child first runs, getppid answers with the process
        // the child was given to instead, and a wait for that value to change never ends.
        // SAFETY: getpid has no preconditions.
        let probe = unsafe { libc::getpid() };
        // SAFETY: the probe has one thread, so the child may run any code. It only waits for
        // its parent to end and then leaves through execv or `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let pause = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            // SAFETY: getppid has no preconditions.
            while unsafe { libc::getppid() } == probe {
                // SAFETY: nanosleep reads a valid timespec and writes nothing.
                unsafe { libc::nanosleep(&pause, ptr::null_mut()) };
            }
            // SAFETY: both arrays live in this process and argv ends with a null pointer.
            unsafe {
                libc::execv(argv[0], argv.as_ptr());
                libc::_exit(127)
            }
        }
        check(child).map(|child| child.to_string())
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
    const WALK_SECONDS: i64 = 30;

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
        let deadline = unsafe { libc::time(ptr::null_mut()) } as i64 + WALK_SECONDS;
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
                        if (libc::time(ptr::null_mut()) as i64) > deadline {
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

    /// The job that the last `start-job` started. Its process group is its process ID, because
    /// `start-job` makes it a group leader.
    static LAST_JOB: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

    /// Starts `PROGRAM ARGS...` (separated by U+001F) in a process group of its own, with the
    /// standard streams of the probe, and reports its process ID. A terminal job control test
    /// needs a background job: the probe that starts it keeps the terminal's foreground. In the
    /// arguments, `{job}` stands for the job that the last `start-job` started, so one job can
    /// act on another without the test knowing process IDs in advance.
    fn start_job(target: &str) -> io::Result<String> {
        use std::os::unix::process::CommandExt;
        use std::sync::atomic::Ordering;
        let last = LAST_JOB.load(Ordering::SeqCst).to_string();
        let target = target.replace("{job}", &last);
        let mut parts = target.split(super::ARGUMENT_SEPARATOR);
        let program = parts.next().unwrap_or_default();
        let mut command = Command::new(program);
        command.args(parts);
        // SAFETY: setpgid is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let job = command.spawn()?.id() as i32;
        LAST_JOB.store(job, Ordering::SeqCst);
        Ok(job.to_string())
    }

    /// Joins process group `pgid` and then reads standard input. With a terminal there, the
    /// group is a background job of it, so the kernel stops every process in the group,
    /// including the ones that were there before; the read then does not return while the stop
    /// holds.
    fn setpgid_join(pgid: libc::pid_t) -> io::Result<String> {
        // SAFETY: setpgid takes process IDs.
        check(unsafe { libc::setpgid(0, pgid) })?;
        let mut byte = 0u8;
        // SAFETY: the buffer is valid for one byte.
        if unsafe { libc::read(0, (&raw mut byte).cast(), 1) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("joined {pgid}"))
    }

    /// Makes the probe's process group the foreground group of terminal `fd`. The job that had
    /// the foreground stops as soon as it reads the terminal again. SIGTTOU is ignored first, as
    /// a shell does: the kernel sends it to a background group that changes the terminal, which
    /// would otherwise stop the probe before the call takes effect.
    fn tcsetpgrp(fd: libc::c_int) -> io::Result<String> {
        // SAFETY: setting a signal to SIG_IGN has no memory safety requirements.
        unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        // SAFETY: getpgrp takes no arguments.
        let group = unsafe { libc::getpgrp() };
        // SAFETY: tcsetpgrp takes a descriptor and a process group ID.
        check(unsafe { libc::tcsetpgrp(fd, group) })?;
        Ok(format!("group {group}"))
    }

    /// The window size of terminal `fd`.
    pub fn window_size(fd: libc::c_int) -> io::Result<libc::winsize> {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ writes a winsize through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size as *mut libc::winsize) })?;
        Ok(size)
    }

    /// Makes terminal `fd` one row taller. The kernel sends SIGWINCH to its foreground process
    /// group, which is outside the sandbox when the program inherited the user's terminal.
    fn tiocswinsz(fd: libc::c_int) -> io::Result<String> {
        let mut size = window_size(fd)?;
        size.ws_row += 1;
        // SAFETY: TIOCSWINSZ reads a winsize through the pointer.
        check(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size as *const libc::winsize) })?;
        Ok(format!("{}x{}", size.ws_row, size.ws_col))
    }

    fn number<T: std::str::FromStr>(target: &str) -> io::Result<T> {
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

/// Actions for `windows.win32k` (`tests/escape_windows.rs`): a win32k system call, and the
/// lockdown that Windows reports for this process and for the processes it can query.
#[cfg(windows)]
mod win32k {
    use std::io;
    use std::process::{Command, Stdio};
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessMitigationPolicy, OpenProcess, PROCESS_QUERY_INFORMATION,
        ProcessSystemCallDisablePolicy,
    };

    pub const ACTIONS: &[&str] = &["win32k-call", "win32k-policy", "win32k-of", "spawn-output"];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "win32k-call" => call(),
            // SAFETY: the pseudo handle of this process has no preconditions.
            "win32k-policy" => policy(unsafe { GetCurrentProcess() }),
            "win32k-of" => policy_of(target),
            "spawn-output" => spawn_output(target),
            _ => unreachable!("listed in ACTIONS"),
        }
    }

    type Export = unsafe extern "system" fn() -> isize;

    /// Reaches win32k by creating a memory device context through `gdi32.dll`, which the probe
    /// loads at run time, so the probe itself starts where gdi32 cannot. The call needs win32k:
    /// under the lockdown gdi32 fails to initialize (`DisallowWin32kSystemCalls` stops the kernel
    /// side), so the load fails and the action reports the error; without it the call returns a
    /// device context handle. A raw `win32u` stub is not enough: it crashes without gdi32's
    /// client-side setup, so the library is the honest vector.
    fn call() -> io::Result<String> {
        let wide: Vec<u16> = "gdi32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the name is NUL-terminated.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let export = |name: &std::ffi::CStr| {
            // SAFETY: the module is loaded and the name is NUL-terminated.
            unsafe { GetProcAddress(module, name.as_ptr().cast()) }
                .ok_or_else(io::Error::last_os_error)
        };
        type Create = unsafe extern "system" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void;
        type Delete = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        // SAFETY: the exports have these signatures.
        let (create, delete) = unsafe {
            (
                std::mem::transmute::<Export, Create>(export(c"CreateCompatibleDC")?),
                std::mem::transmute::<Export, Delete>(export(c"DeleteDC")?),
            )
        };
        // SAFETY: a null device context asks for one compatible with the screen.
        let context = unsafe { create(ptr::null_mut()) };
        if context.is_null() {
            return Err(io::Error::other("no device context"));
        }
        // SAFETY: context is the device context created above.
        unsafe { delete(context) };
        Ok(format!("{context:p}"))
    }

    /// The flags of `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY` of `process`; bit 0 is
    /// `DisallowWin32kSystemCalls`.
    fn policy(process: HANDLE) -> io::Result<String> {
        let mut flags = 0u32;
        // SAFETY: the structure is one u32 of flags and its size is passed.
        let ok = unsafe {
            GetProcessMitigationPolicy(
                process,
                ProcessSystemCallDisablePolicy,
                (&mut flags as *mut u32).cast(),
                size_of::<u32>(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(format!("flags {flags:#x}"))
    }

    /// `policy` of every other process named `target` that this process may query, as
    /// `PID=FLAGS` separated by spaces. In an AppContainer these are the processes of the same
    /// AppContainer, such as the program's console host and the relays.
    fn policy_of(target: &str) -> io::Result<String> {
        // SAFETY: a process snapshot has no preconditions.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = Vec::new();
        // SAFETY: snapshot is valid and entry has its size set.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            let pid = entry.th32ProcessID;
            if pid != std::process::id() && name.eq_ignore_ascii_case(target) {
                // SAFETY: OpenProcess has no memory safety preconditions.
                let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) };
                if !handle.is_null() {
                    let flags = policy(handle).unwrap_or_else(|error| error.to_string());
                    found.push(format!("{pid}={}", flags.trim_start_matches("flags ")));
                    // SAFETY: handle is open and owned here.
                    unsafe { CloseHandle(handle) };
                }
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: snapshot is a handle this function owns.
        unsafe { CloseHandle(snapshot) };
        if found.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no such process to query",
            ));
        }
        Ok(found.join(" "))
    }

    /// Runs a program with arguments (separated by U+001F) and reports its exit status and
    /// standard output.
    fn spawn_output(target: &str) -> io::Result<String> {
        let mut parts = target.split(super::ARGUMENT_SEPARATOR);
        let program = parts.next().unwrap_or_default();
        let output = Command::new(program)
            .args(parts)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        Ok(format!(
            "{} {}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        ))
    }
}

#[cfg(not(windows))]
mod win32k {
    use std::io;

    pub const ACTIONS: &[&str] = &[];

    pub fn perform(_action: &str, _target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }
}

/// Actions for the file system view and the PID namespace (`tests/view_linux.rs`,
/// `tests/pid_linux.rs`): what a path looks like to the calls that do not open it, whether a file
/// maps as code, and which processes the program sees.
#[cfg(target_os = "linux")]
mod view {
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    pub const ACTIONS: &[&str] = &[
        "lstat",
        "access-path",
        "readlink",
        "inotify-watch",
        "mmap-exec",
        "statfs",
        "link-count",
        "mount-source",
        "mount-listed",
        "kill-signal",
        "pidfd-open",
        "proc-pids",
        "orphan-reaped",
    ];

    pub fn perform(action: &str, target: &str) -> io::Result<String> {
        match action {
            "lstat" => {
                let metadata = fs::symlink_metadata(target)?;
                let kind = match metadata.file_type() {
                    kind if kind.is_symlink() => "link",
                    kind if kind.is_dir() => "directory",
                    _ => "file",
                };
                Ok(format!("{kind} owner {}", metadata.uid()))
            }
            "access-path" => {
                let path = CString::new(target)?;
                // SAFETY: access takes a NUL-terminated path.
                check(unsafe { libc::access(path.as_ptr(), libc::F_OK) }).map(|_| String::new())
            }
            "readlink" => fs::read_link(target).map(|link| link.display().to_string()),
            "inotify-watch" => {
                let path = CString::new(target)?;
                // SAFETY: inotify_init1 takes flags only.
                let fd = check(unsafe { libc::inotify_init1(libc::IN_CLOEXEC) })?;
                // SAFETY: the path is NUL-terminated.
                let watch =
                    unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_ALL_EVENTS) };
                let watched = check(watch).map(|_| String::new());
                // SAFETY: closes the descriptor created above.
                unsafe { libc::close(fd) };
                watched
            }
            // Maps the first page of the file as code, as a loader does with a library.
            "mmap-exec" => {
                let file = fs::File::open(target)?;
                // SAFETY: a new private mapping of an open file, unmapped right away.
                unsafe {
                    let page = libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_PRIVATE,
                        file.as_raw_fd(),
                        0,
                    );
                    if page == libc::MAP_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    libc::munmap(page, 4096);
                }
                Ok(String::new())
            }
            "statfs" => {
                let path = CString::new(target)?;
                // SAFETY: statfs is plain data, which the call fills in.
                let mut status: libc::statfs = unsafe { std::mem::zeroed() };
                // SAFETY: the path is NUL-terminated and the struct is writable.
                check(unsafe { libc::statfs(path.as_ptr(), &mut status) })?;
                Ok(format!(
                    "type {:x} blocks {} files {}",
                    status.f_type, status.f_blocks, status.f_files
                ))
            }
            "link-count" => Ok(fs::symlink_metadata(target)?.nlink().to_string()),
            // The device or source field of the mount at `target` in /proc/self/mountinfo.
            "mount-source" => {
                let table = fs::read_to_string("/proc/self/mountinfo")?;
                table
                    .lines()
                    .filter(|line| line.split(' ').nth(4) == Some(target))
                    .filter_map(|line| line.split_once(" - ")?.1.split(' ').nth(1))
                    .next_back()
                    .map(str::to_string)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such mount"))
            }
            // Whether PATH is a mount point in the mount table of process PID: `PID:PATH`.
            "mount-listed" => {
                let (pid, path) = target
                    .split_once(':')
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "PID:PATH"))?;
                let table = fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
                table
                    .lines()
                    .any(|line| line.split(' ').nth(4) == Some(path))
                    .then(String::new)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not listed"))
            }
            // Sends signal SIGNAL to process PID: `PID:SIGNAL`.
            "kill-signal" => {
                let (pid, signal) = target
                    .split_once(':')
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "PID:SIGNAL"))?;
                // SAFETY: kill takes a process ID and a signal.
                check(unsafe { libc::kill(number(pid)?, number(signal)?) }).map(|_| String::new())
            }
            "pidfd-open" => {
                let pid: libc::pid_t = number(target)?;
                // SAFETY: pidfd_open takes a process ID and flags; the descriptor is closed.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: closes the descriptor opened above.
                unsafe { libc::close(fd as libc::c_int) };
                Ok(String::new())
            }
            // The process IDs that the /proc at `target` lists, sorted and separated by commas.
            "proc-pids" => {
                let mut pids: Vec<u32> = fs::read_dir(target)?
                    .flatten()
                    .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                    .collect();
                pids.sort_unstable();
                let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
                Ok(pids.join(","))
            }
            // Leaves an orphan behind: a child forks a grandchild, reports its ID and ends, and the
            // grandchild ends a moment later. After another moment the grandchild is gone when
            // something reaped it, and a zombie, which signal 0 still reaches, when nothing did.
            "orphan-reaped" => {
                let mut ends = [0; 2];
                // SAFETY: pipe2 writes two new descriptors into `ends`.
                check(unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) })?;
                // SAFETY: the probe has one thread; the children only write, sleep and end.
                let orphan = unsafe {
                    let child = libc::fork();
                    if child == 0 {
                        let grandchild = libc::fork();
                        if grandchild == 0 {
                            libc::usleep(100_000);
                            libc::_exit(0);
                        }
                        libc::write(ends[1], (&raw const grandchild).cast(), 4);
                        libc::_exit(0);
                    }
                    libc::close(ends[1]);
                    libc::waitpid(child, std::ptr::null_mut(), 0);
                    let mut orphan: libc::pid_t = 0;
                    let read = libc::read(ends[0], (&raw mut orphan).cast(), 4);
                    libc::close(ends[0]);
                    if read != 4 {
                        return Err(io::Error::other("the child reported no grandchild"));
                    }
                    libc::usleep(500_000);
                    orphan
                };
                // SAFETY: kill with signal 0 only checks that the process exists.
                match unsafe { libc::kill(orphan, 0) } {
                    0 => Ok("a zombie".to_string()),
                    _ => Ok("reaped".to_string()),
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown action",
            )),
        }
    }

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    fn number(text: &str) -> io::Result<libc::c_int> {
        text.parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a number"))
    }
}

#[cfg(not(target_os = "linux"))]
mod view {
    use std::io;

    pub const ACTIONS: &[&str] = &[];

    pub fn perform(_action: &str, _target: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
    }
}
