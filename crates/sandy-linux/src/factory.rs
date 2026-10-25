//! The socket factory of exposed ports under `ip = "private"`. The relay accepts an exposed
//! connection on the host's loopback and must connect it to the program's port, which listens in
//! the sandbox's network namespace. A socket belongs to the namespace it was created in, so the
//! relay cannot make that connection with a socket of its own. The factory runs inside the
//! namespace and makes the socket:
//!
//! 1. Before the relay forks, `pair` makes a socket pair. The relay keeps the `Factory` side,
//!    the process that becomes the program keeps the `Pending` side.
//! 2. After `Namespaces::enter` and `drop_capabilities`, that process starts the factory as a
//!    helper (forked twice, a session of its own, `/dev/null` as its standard descriptors), so it
//!    holds no capability. It confines itself: no_new_privs, Landlock without file access, TCP
//!    bind or TCP connect (from ABI 4) and with the signal and abstract socket scopes (from ABI
//!    6), and a seccomp filter that allows only reading a request, sending the answer, creating
//!    an IPv4 or IPv6 TCP socket, and ending.
//! 3. For each exposed connection the relay asks for a socket of the address family of the
//!    program's port and connects it there itself, so the relay's Landlock rules decide which
//!    ports it reaches, as for its own sockets. The factory only creates sockets; it cannot
//!    connect, bind, listen or open a file.
//! 4. The factory ends when the relay ends: its end of the pair then reads nothing more. The
//!    relay polls its end too, and ends when the factory has ended, so the guard of
//!    `children = "contained"`, which watches the relay, ends the program then.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::time::Duration;

use landlock::{ABI, Scope};
use sandy_core::SandboxError;

use crate::filter;
use crate::helper::{self, Ready, receive_descriptor, send_descriptor, socket_pair};

/// The relay's side: it asks for one socket at a time.
#[derive(Debug)]
pub struct Factory(Mutex<OwnedFd>, RawFd);

/// The factory's side until the factory starts inside the namespace.
#[derive(Debug)]
pub struct Pending(OwnedFd);

/// The requests: one byte, the IP version of the socket wanted.
const IPV4: u8 = 4;
const IPV6: u8 = 6;

/// How long the relay waits for its connection to the program's port, as `sandy_relay::connect`
/// does for its own.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn pair() -> Result<(Factory, Pending), SandboxError> {
    let (relay, factory) = socket_pair(
        libc::SOCK_SEQPACKET,
        "the socket pair of the exposed ports' socket factory",
    )?;
    let fd = relay.as_raw_fd();
    Ok((Factory(Mutex::new(relay), fd), Pending(factory)))
}

impl Pending {
    /// Starts the factory in this process's network namespace and returns its process ID once it
    /// is confined.
    pub fn start(self, abi: ABI) -> Result<libc::pid_t, SandboxError> {
        helper::start("the socket factory", move |ready| {
            factory_main(&self.0, ready, abi)
        })
    }
}

impl Factory {
    /// The relay's end, which it polls to see the factory end.
    pub fn fd(&self) -> RawFd {
        self.1
    }

    /// A TCP connection to `target` from inside the sandbox's network namespace.
    pub fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        let socket = {
            let channel = self
                .0
                .lock()
                .map_err(|_| io::Error::other("the socket factory's lock is poisoned"))?;
            let request = if target.is_ipv4() { IPV4 } else { IPV6 };
            // SAFETY: writes one byte from a valid buffer to an open socket.
            if unsafe { libc::write(channel.as_raw_fd(), (&raw const request).cast(), 1) } != 1 {
                return Err(io::Error::last_os_error());
            }
            receive_descriptor(&channel)
                .ok_or_else(|| io::Error::other("the socket factory sent no socket"))?
        };
        connect(socket, target, CONNECT_TIMEOUT)
    }
}

/// Connects `socket` to `target` within `timeout`, which `TcpStream::connect_timeout` does only
/// with a socket of its own.
fn connect(socket: OwnedFd, target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let fd = socket.as_raw_fd();
    let check = |result: libc::c_int| {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    };
    // SAFETY: fcntl changes only the flags of an open descriptor.
    let flags = check(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    // SAFETY: as above.
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    let (address, length) = socket_address(target);
    // SAFETY: `address` is a socket address of `length` bytes.
    if unsafe { libc::connect(fd, (&raw const address).cast(), length) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        let ready = loop {
            // SAFETY: polls one open descriptor.
            match unsafe { libc::poll(&mut poll, 1, millis) } {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                ready => break check(ready)?,
            }
        };
        if ready == 0 {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let mut pending: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: SO_ERROR writes one int into `pending`.
        check(unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut pending).cast(),
                &mut size,
            )
        })?;
        if pending != 0 {
            return Err(io::Error::from_raw_os_error(pending));
        }
    }
    // SAFETY: as above.
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })?;
    Ok(TcpStream::from(socket))
}

/// `target` as the kernel reads it, and its length.
fn socket_address(target: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data, and all zeros is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match target {
        SocketAddr::V4(target) => {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: target.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(target.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large enough and aligned for every socket address.
            unsafe {
                (&raw mut storage)
                    .cast::<libc::sockaddr_in>()
                    .write(address)
            };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(target) => {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: target.port().to_be(),
                sin6_flowinfo: target.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: target.ip().octets(),
                },
                sin6_scope_id: target.scope_id(),
            };
            // SAFETY: as above.
            unsafe {
                (&raw mut storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(address)
            };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, length as libc::socklen_t)
}

fn factory_main(channel: &OwnedFd, ready: Ready, abi: ABI) {
    let mut keep = vec![channel.as_raw_fd(), ready.fd()];
    keep.extend(helper::STANDARD_DESCRIPTORS);
    let confined = filter::factory()
        .map_err(|error| SandboxError::new(format!("cannot build the factory's filter: {error}")))
        .and_then(|filters| {
            helper::confine(
                "the socket factory",
                &keep,
                abi,
                Some(&[]),
                Scope::Signal | Scope::AbstractUnixSocket,
                &filters,
            )
        });
    if let Err(error) = confined {
        ready.fail(&error.to_string());
    }
    ready.report();
    serve(channel);
}

/// Answers requests until the relay's end closes. A request it does not know ends the factory,
/// and with it the relay.
fn serve(channel: &OwnedFd) {
    loop {
        let mut request = 0u8;
        // SAFETY: reads one byte into a valid buffer.
        match unsafe { libc::read(channel.as_raw_fd(), (&raw mut request).cast(), 1) } {
            1 => {}
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            _ => return,
        }
        let family = match request {
            IPV4 => libc::AF_INET,
            IPV6 => libc::AF_INET6,
            _ => return,
        };
        // SAFETY: socket returns a new descriptor or -1.
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            // An answer without a socket: the relay drops this one connection.
            // SAFETY: writes one byte from a valid buffer to an open socket.
            if unsafe { libc::write(channel.as_raw_fd(), (&raw const request).cast(), 1) } != 1 {
                return;
            }
            continue;
        }
        // SAFETY: the descriptor was just created and nothing else owns it.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        if send_descriptor(channel.as_raw_fd(), socket.as_raw_fd()).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostCapabilities;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const OUTCOMES: [&str; 6] = [
        "ok",
        "confine failed",
        "a file could be opened",
        "a socket could be connected",
        "a socket could be bound",
        "a socket could listen",
    ];

    /// What a compromised factory would try after `confine`. Returns an index into `OUTCOMES`.
    fn try_escapes(abi: ABI, other: SocketAddr) -> i32 {
        let Ok(filters) = filter::factory() else {
            return 1;
        };
        let confined = helper::confine(
            "the socket factory",
            &[libc::STDERR_FILENO],
            abi,
            Some(&[]),
            Scope::Signal | Scope::AbstractUnixSocket,
            &filters,
        );
        if confined.is_err() {
            return 1;
        }
        if std::fs::File::open("/proc/self/status").is_ok() {
            return 2;
        }
        // Landlock checks TCP ports from ABI 4; the filter denies connect on every kernel.
        if TcpStream::connect(other).is_ok() {
            return 3;
        }
        if TcpListener::bind("127.0.0.1:0").is_ok() {
            return 4;
        }
        // SAFETY: socket returns a new descriptor or -1; listen on it changes nothing outside.
        let listens = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            fd >= 0 && libc::listen(fd, 1) == 0
        };
        if listens {
            return 5;
        }
        0
    }

    /// The child process applies the factory's confinement to itself and leaves through `_exit`.
    #[test]
    fn the_confined_factory_can_only_make_sockets() {
        if !crate::alone::in_own_process() {
            return;
        }
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = other.local_addr().unwrap();
        // SAFETY: the child only runs `try_escapes` and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = try_escapes(ABI::from(version), other);
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        let outcome = libc::WEXITSTATUS(status) as usize;
        assert_eq!(outcome, 0, "{}", OUTCOMES[outcome.min(OUTCOMES.len() - 1)]);
    }

    /// The factory, started as a helper here in the host's namespace, makes the sockets the relay
    /// connects to a listener in that namespace, for IPv4 and IPv6, and it ends when the relay's
    /// side closes.
    #[test]
    fn the_factory_serves_sockets_until_its_relay_ends() {
        if !crate::alone::in_own_process() {
            return;
        }
        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        // The helper needs one thread; a forked child of the test is one.
        // SAFETY: the child only runs the checks below and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = (|| {
                let (factory, pending) = pair().map_err(|_| 1)?;
                let pid = pending.start(ABI::from(version)).map_err(|_| 2)?;
                for address in ["127.0.0.1:0", "[::1]:0"] {
                    let Ok(listener) = TcpListener::bind(address) else {
                        continue;
                    };
                    let target = listener.local_addr().map_err(|_| 3)?;
                    let mut stream = factory.connect(target).map_err(|_| 4)?;
                    let (mut accepted, _) = listener.accept().map_err(|_| 5)?;
                    stream.write_all(b"x").map_err(|_| 6)?;
                    let mut byte = [0u8; 1];
                    accepted.read_exact(&mut byte).map_err(|_| 7)?;
                }
                let pidfd = helper::pidfd_open(pid, "the factory").map_err(|_| 8)?;
                drop(factory);
                let mut poll = libc::pollfd {
                    fd: pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: polls one open descriptor for at most ten seconds.
                if unsafe { libc::poll(&mut poll, 1, 10_000) } != 1 {
                    return Err(9);
                }
                Ok(())
            })();
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome.err().unwrap_or(0)) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "step {}",
            libc::WEXITSTATUS(status)
        );
    }
}
