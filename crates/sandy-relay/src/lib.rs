//! The relay behind `network.expose`. It accepts connections on a loopback listener that clients
//! outside the sandbox can reach and forwards the bytes of each one to a loopback port of the
//! sandboxed program.
//!
//! The relay only copies bytes; it never interprets them. Each backend decides where the relay
//! process runs, how it is confined, and how it ends together with the program.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Connections beyond this number are closed at once, so clients cannot exhaust threads.
pub const MAX_CONNECTIONS: usize = 256;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// Accepts connections on `listener` and relays each one to `target` until the process ends.
/// Returns only if the listener cannot be used at all.
pub fn serve(listener: TcpListener, target: SocketAddr) -> io::Result<()> {
    listener.set_nonblocking(false)?;
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            // Accept fails for a single connection (reset before accept) or while descriptors
            // are exhausted; neither is a reason to stop serving.
            Err(_) => {
                thread::sleep(ACCEPT_ERROR_PAUSE);
                continue;
            }
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            drop(client);
            continue;
        }
        let active = Arc::clone(&active);
        let spawned = thread::Builder::new().spawn(move || {
            let _ = relay(client, target);
            active.fetch_sub(1, Ordering::AcqRel);
        });
        if spawned.is_err() {
            thread::sleep(ACCEPT_ERROR_PAUSE);
        }
    }
}

/// Relays one connection in both directions. Each direction ends with a half close, so a peer
/// that stops sending still receives the rest of the answer.
///
/// Both directions use the same two sockets from two threads instead of clones. On Windows a
/// clone (`try_clone`, which calls `WSADuplicateSocketW`) of a socket whose non-blocking connect
/// has just completed can report `WSAENOTCONN` for `shutdown`, although it sends. The half close
/// then never reaches the target, and both peers wait until Windows drops the connection.
fn relay(client: TcpStream, target: SocketAddr) -> io::Result<()> {
    let server = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)?;
    thread::scope(|scope| {
        thread::Builder::new().spawn_scoped(scope, || pump(&client, &server))?;
        pump(&server, &client);
        Ok(())
    })
}

fn pump(mut from: &TcpStream, mut to: &TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

/// Takes ownership of a listening socket that the parent process passed by descriptor or handle
/// number.
///
/// # Safety
///
/// `raw` must be an open socket owned by nobody else in this process.
#[cfg(unix)]
pub unsafe fn inherited_listener(raw: u64) -> io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let fd = i32::try_from(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "descriptor out of range"))?;
    // SAFETY: the caller guarantees that `fd` is an open socket nobody else owns.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    listener.local_addr()?;
    Ok(listener)
}

/// Takes ownership of a listening socket that the parent process passed by descriptor or handle
/// number.
///
/// # Safety
///
/// `raw` must be an open socket owned by nobody else in this process.
#[cfg(windows)]
pub unsafe fn inherited_listener(raw: u64) -> io::Result<TcpListener> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    // The standard library starts Winsock only when it creates a socket itself. Without this
    // call, every use of the inherited socket fails with WSANOTINITIALISED. Winsock stays
    // started until the process ends.
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: data is a writable WSADATA; 0x202 requests Winsock 2.2.
    let error = unsafe { WSAStartup(0x202, &mut data) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    // SAFETY: the caller guarantees that `raw` is an open socket nobody else owns.
    let listener = unsafe { TcpListener::from_raw_socket(raw) };
    listener.local_addr()?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A server that answers every request with "echo:" plus the request, after the client
    /// half-closes.
    fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                thread::spawn(move || {
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).unwrap();
                    stream.write_all(b"echo:").unwrap();
                    stream.write_all(&request).unwrap();
                });
            }
        });
        address
    }

    fn relay_to(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener, target));
        address
    }

    fn exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        answer
    }

    #[test]
    fn relays_both_directions_with_half_close() {
        let relay = relay_to(echo_server());
        assert_eq!(exchange(relay, b"hello"), b"echo:hello");
    }

    #[test]
    fn relays_concurrent_connections() {
        let relay = relay_to(echo_server());
        let clients: Vec<_> = (0..20)
            .map(|i| thread::spawn(move || exchange(relay, format!("{i}").as_bytes())))
            .collect();
        for (i, client) in clients.into_iter().enumerate() {
            assert_eq!(client.join().unwrap(), format!("echo:{i}").into_bytes());
        }
    }

    #[test]
    fn closes_the_client_when_the_target_is_not_listening() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = unused.local_addr().unwrap();
        drop(unused);
        let relay = relay_to(target);
        let mut stream = TcpStream::connect(relay).unwrap();
        let mut answer = Vec::new();
        let _ = stream.read_to_end(&mut answer);
        assert!(answer.is_empty());
    }
}
