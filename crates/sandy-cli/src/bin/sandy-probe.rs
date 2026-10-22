//! Test helper for the escape tests.
//!
//! Usage: `sandy-probe ACTION TARGET [ACTION TARGET]...`
//!
//! It tries each action and prints one line per action:
//! `ACTION<TAB>TARGET<TAB>RESULT<TAB>DETAIL`. RESULT is `ok`, `denied` (the operating system
//! refused with a permission error) or `error` (any other failure).

use std::fs;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
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
