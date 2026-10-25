//! The relay behind `network.expose` and `network.forward`. It accepts connections on one side
//! and copies the bytes of each one to a connection it opens on the other side: from an outside
//! loopback listener to the sandboxed program (`expose`), or from the program to a loopback
//! service outside (`forward`).
//!
//! The relay only copies bytes; it never interprets them. Each backend decides where the relay
//! process runs, how it is confined, and how it ends together with the program.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Connections of one listener beyond this number are closed at once, so clients cannot exhaust
/// threads. Each exposed or forwarded port has its own limit, so clients of one cannot take the
/// connections of another.
pub const MAX_CONNECTIONS: usize = 256;

/// After one direction of a connection has ended, the other may stay idle this long before the
/// relay ends the connection. Otherwise a peer that never sends again, after the other peer has
/// closed its side, would keep the connection and its slot for as long as it likes.
pub const HALF_CLOSED_IDLE: Duration = Duration::from_secs(60);

/// How often a direction that waits for data checks whether the connection was aborted or the
/// other direction has ended.
const READ_TICK: Duration = Duration::from_secs(1);
const BUFFER_SIZE: usize = 64 * 1024;

/// How long connections that a relay already accepted may still deliver data after the program
/// ends (docs/DESIGN.md, "Forwarded ports", rule 5).
pub const DRAIN: Duration = Duration::from_secs(1);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// Accepts connections on `listener` and relays each one to `target` until the process ends.
pub fn serve(listener: TcpListener, target: SocketAddr) -> io::Result<()> {
    listener.set_nonblocking(false)?;
    serve_with(
        || listener.accept().map(|(client, _)| client),
        move || connect(target),
    )
}

/// Opens a TCP connection to `target`, the way the relay connects to the other side.
pub fn connect(target: SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
}

/// Takes connections from `accept` and relays each one to a connection from `connect`, until the
/// process ends. `connect` runs once per accepted connection, on that connection's thread.
pub fn serve_with<A, C>(mut accept: A, connect: C) -> io::Result<()>
where
    A: FnMut() -> io::Result<TcpStream>,
    C: Fn() -> io::Result<TcpStream> + Send + Sync + 'static,
{
    let connections = Connections::new(connect);
    loop {
        match accept() {
            Ok(client) => {
                if !connections.start(client) {
                    thread::sleep(ACCEPT_ERROR_PAUSE);
                }
            }
            // Accept fails for a single connection (reset before accept) or while descriptors
            // are exhausted; neither is a reason to stop serving.
            Err(_) => thread::sleep(ACCEPT_ERROR_PAUSE),
        }
    }
}

/// The relayed connections of one server: it starts each on its own thread and counts the
/// active ones.
struct Connections<C> {
    connect: Arc<C>,
    active: Arc<AtomicUsize>,
}

impl<C> Connections<C>
where
    C: Fn() -> io::Result<TcpStream> + Send + Sync + 'static,
{
    fn new(connect: C) -> Connections<C> {
        Connections {
            connect: Arc::new(connect),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Relays `client` on a new thread, or closes it while `MAX_CONNECTIONS` are active. Returns
    /// false if no thread could start.
    fn start(&self, client: TcpStream) -> bool {
        if self.active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return true;
        }
        let active = Arc::clone(&self.active);
        let connect = Arc::clone(&self.connect);
        let spawned = thread::Builder::new().spawn(move || {
            if let Ok(server) = connect() {
                let _ = relay_streams(client, server);
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
        if spawned.is_err() {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    #[cfg(windows)]
    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

/// A request to stop a server that `serve_until` runs. Clones share the request.
#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    pub fn new() -> Stop {
        Stop::default()
    }

    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// How long `serve_until` waits for a connection before it checks for a stop request again.
#[cfg(windows)]
const STOP_CHECK: Duration = Duration::from_millis(50);

/// Serves like `serve_with` until `stop` is requested, then ends the way docs/DESIGN.md rule 5
/// asks:
/// 1. It still accepts the connections that are waiting in the listen backlog. Their handshake
///    completed, so the client already counts them as made; a program that connects, writes and
///    exits would otherwise lose its data.
/// 2. It closes the listener, so no later connection is taken.
/// 3. It waits up to `drain` for the accepted connections to finish, then returns. Connections
///    still open after that end with the process, with a reset (`abort_all`).
///
/// It never blocks in `accept` without a pending connection, so the stop takes effect within
/// `STOP_CHECK` without closing the listener under another thread.
#[cfg(windows)]
pub fn serve_until<L, A, C>(listener: L, mut accept: A, connect: C, stop: &Stop, drain: Duration)
where
    L: std::os::windows::io::AsRawSocket,
    A: FnMut(&L) -> io::Result<TcpStream>,
    C: Fn() -> io::Result<TcpStream> + Send + Sync + 'static,
{
    let connections = Connections::new(connect);
    let mut deadline: Option<Instant> = None;
    loop {
        if deadline.is_none() && stop.is_requested() {
            deadline = Some(Instant::now() + drain);
        }
        let stopping = deadline.is_some();
        let wait = if stopping { Duration::ZERO } else { STOP_CHECK };
        match pending(listener.as_raw_socket(), wait) {
            Ok(true) => match accept(&listener) {
                Ok(client) => {
                    if !connections.start(client) {
                        thread::sleep(ACCEPT_ERROR_PAUSE);
                    }
                }
                Err(_) if stopping => break,
                Err(_) => thread::sleep(ACCEPT_ERROR_PAUSE),
            },
            Ok(false) if stopping => break,
            Ok(false) => {}
            Err(_) if stopping => break,
            Err(_) => thread::sleep(ACCEPT_ERROR_PAUSE),
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
    }
    drop(listener);
    let deadline = deadline.unwrap_or_else(|| Instant::now() + drain);
    while connections.active() > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if connections.active() > 0 {
        abort_all();
    }
}

/// Whether a connection waits on the listening `socket`, waiting at most `wait`.
#[cfg(windows)]
fn pending(socket: std::os::windows::io::RawSocket, wait: Duration) -> io::Result<bool> {
    use windows_sys::Win32::Networking::WinSock::{
        POLLRDNORM, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
    };
    let mut entry = WSAPOLLFD {
        fd: socket as SOCKET,
        events: POLLRDNORM,
        revents: 0,
    };
    let millis = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: entry is one valid WSAPOLLFD and the count is 1.
    let ready = unsafe { WSAPoll(&mut entry, 1, millis) };
    if ready == SOCKET_ERROR {
        // SAFETY: WSAGetLastError has no preconditions.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(ready > 0)
}

/// Relays one accepted connection to `target` in both directions and returns when both are done.
/// Each direction ends with a half close, so a peer that stops sending still receives the rest of
/// the answer. Backends that run their own accept loop (to stop accepting when the program ends)
/// call this for each connection.
pub fn relay(client: TcpStream, target: SocketAddr) -> io::Result<()> {
    relay_streams(client, connect(target)?)
}

/// Relays between two connected streams in both directions and returns when both are done.
///
/// Both directions use the same two sockets from two threads instead of clones. On Windows a
/// clone (`try_clone`, which calls `WSADuplicateSocketW`) of a socket whose non-blocking connect
/// has just completed can report `WSAENOTCONN` for `shutdown`, although it sends. The half close
/// then never reaches the target, and both peers wait until Windows drops the connection.
///
/// A direction that reaches the end of its stream passes the end on as a half close. A direction
/// that fails (a reset, or a write the other peer refuses) aborts the connection: both sockets
/// close with a reset, so neither peer takes a cut stream for a complete one.
fn relay_streams(client: TcpStream, server: TcpStream) -> io::Result<()> {
    relay_streams_with(client, server, HALF_CLOSED_IDLE)
}

/// `relay_streams` with `idle` instead of `HALF_CLOSED_IDLE`.
fn relay_streams_with(client: TcpStream, server: TcpStream, idle: Duration) -> io::Result<()> {
    let _registered = Registered::new(&client, &server);
    let state = Connection::default();
    // Without a timeout a read would block until the peer sends, also after an abort. Both are
    // set before either direction starts: macOS refuses socket options (EINVAL) on a socket
    // whose two directions have ended, although its unread bytes can still be read, and the
    // other direction's half close can end the second one at any moment. Before anything is
    // relayed, a socket refuses it only once it has been reset.
    if client.set_read_timeout(Some(READ_TICK)).is_err()
        || server.set_read_timeout(Some(READ_TICK)).is_err()
    {
        state.abort([&client, &server]);
        return Ok(());
    }
    thread::scope(|scope| {
        thread::Builder::new().spawn_scoped(scope, || {
            pump(
                &client,
                &server,
                [&state.ended[0], &state.ended[1]],
                idle,
                &state,
            )
        })?;
        pump(
            &server,
            &client,
            [&state.ended[1], &state.ended[0]],
            idle,
            &state,
        );
        Ok(())
    })
}

/// What the two directions of one connection share.
#[derive(Default)]
struct Connection {
    /// Whether each direction has ended.
    ended: [AtomicBool; 2],
    aborted: AtomicBool,
}

impl Connection {
    /// Makes both sockets close with a reset and stops both directions within `READ_TICK`.
    fn abort(&self, sockets: [&TcpStream; 2]) {
        self.aborted.store(true, Ordering::Release);
        for socket in sockets {
            reset_on_close(raw(socket));
        }
    }
}

/// Copies `from` to `to` until `from` ends, the connection is aborted, or the other direction
/// has ended and this one stayed idle for `idle`. `[ended, other_ended]` are the end flags of
/// this direction and of the other one. `from` must have a read timeout.
fn pump(
    mut from: &TcpStream,
    mut to: &TcpStream,
    [ended, other_ended]: [&AtomicBool; 2],
    idle: Duration,
    connection: &Connection,
) {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut active = Instant::now();
    let mut saw_other_end = false;
    while !connection.aborted.load(Ordering::Acquire) {
        match from.read(&mut buffer) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                break;
            }
            Ok(read) => {
                if to.write_all(&buffer[..read]).is_err() {
                    connection.abort([from, to]);
                    break;
                }
                active = Instant::now();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if other_ended.load(Ordering::Acquire) {
                    if !saw_other_end {
                        // The idle time counts from the other direction's end at the earliest.
                        saw_other_end = true;
                        active = active.max(Instant::now());
                    }
                    if active.elapsed() >= idle {
                        let _ = to.shutdown(Shutdown::Write);
                        break;
                    }
                }
            }
            Err(_) => {
                connection.abort([from, to]);
                break;
            }
        }
    }
    ended.store(true, Ordering::Release);
}

#[cfg(unix)]
type RawSocket = std::os::fd::RawFd;
#[cfg(windows)]
type RawSocket = std::os::windows::io::RawSocket;

#[cfg(unix)]
fn raw(socket: &TcpStream) -> RawSocket {
    std::os::fd::AsRawFd::as_raw_fd(socket)
}

#[cfg(windows)]
fn raw(socket: &TcpStream) -> RawSocket {
    std::os::windows::io::AsRawSocket::as_raw_socket(socket)
}

/// Makes closing `socket` send a reset instead of the normal end (SO_LINGER with time 0).
#[cfg(unix)]
fn reset_on_close(socket: RawSocket) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: the option value is a valid linger structure of the size passed.
    unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
}

/// Makes closing `socket` send a reset instead of the normal end (SO_LINGER with time 0).
#[cfg(windows)]
fn reset_on_close(socket: RawSocket) {
    use windows_sys::Win32::Networking::WinSock::{
        LINGER, SO_LINGER, SOCKET, SOL_SOCKET, setsockopt,
    };
    let linger = LINGER {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: the option value is a valid LINGER structure of the size passed.
    unsafe {
        setsockopt(
            socket as SOCKET,
            SOL_SOCKET,
            SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of::<LINGER>() as i32,
        )
    };
}

/// The sockets of the connections this process relays now.
static ACTIVE: Mutex<Vec<(u64, [RawSocket; 2])>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Keeps the sockets of one connection in `ACTIVE` while it is relayed. It is dropped before the
/// sockets close, so `abort_all` never touches a socket number that another connection reuses.
struct Registered(u64);

impl Registered {
    fn new(client: &TcpStream, server: &TcpStream) -> Registered {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut active) = ACTIVE.lock() {
            active.push((id, [raw(client), raw(server)]));
        }
        Registered(id)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.lock() {
            active.retain(|(id, _)| *id != self.0);
        }
    }
}

/// Makes every connection that this process still relays close with a reset when the process
/// ends. A relay calls it when the drain of rule 5 runs out and it exits with connections open,
/// so no peer takes a cut stream for a complete one.
pub fn abort_all() {
    if let Ok(active) = ACTIVE.lock() {
        for (_, sockets) in active.iter() {
            for &socket in sockets {
                reset_on_close(socket);
            }
        }
    }
}

/// Raises this process's soft limit of open descriptors so that `listeners` listeners with
/// `MAX_CONNECTIONS` connections each fit: two descriptors per connection, plus some for the
/// process itself. The limit stays at or below the hard limit; macOS starts processes with a
/// soft limit of 256, which would allow only about 125 connections.
#[cfg(unix)]
pub fn raise_descriptor_limit(listeners: usize) -> io::Result<()> {
    let needed = (listeners * 2 * MAX_CONNECTIONS + 64) as libc::rlim_t;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if limit.rlim_cur >= needed {
        return Ok(());
    }
    limit.rlim_cur = needed.min(limit.rlim_max);
    // SAFETY: setrlimit reads a valid rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    // Check before taking ownership: an owned descriptor that turns out to be closed makes the
    // standard library abort when it is dropped.
    check_stream_socket(fd)?;
    // SAFETY: the caller guarantees that `fd` is an open socket nobody else owns, and the check
    // above confirmed that it is an open stream socket.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    listener.local_addr()?;
    Ok(listener)
}

#[cfg(unix)]
fn check_stream_socket(fd: i32) -> io::Result<()> {
    // SAFETY: F_GETFD only reads the descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: kind and length are valid, correctly sized out pointers.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if kind != libc::SOCK_STREAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not a stream socket",
        ));
    }
    Ok(())
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
    winsock_startup()?;
    // SAFETY: the caller guarantees that `raw` is an open socket nobody else owns.
    let listener = unsafe { TcpListener::from_raw_socket(raw) };
    listener.local_addr()?;
    Ok(listener)
}

/// Starts Winsock 2.2 for this process. The standard library starts it only when it creates a
/// socket itself; a socket that came from elsewhere (inherited, or created with the raw API)
/// fails with WSANOTINITIALISED without this call. Winsock stays started until the process ends.
#[cfg(windows)]
fn winsock_startup() -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: data is a writable WSADATA; 0x202 requests Winsock 2.2.
    let error = unsafe { WSAStartup(0x202, &mut data) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    Ok(())
}

/// Stream Unix domain sockets (AF_UNIX) on Windows, which the standard library does not offer.
///
/// A connected AF_UNIX stream socket is returned as a `TcpStream`: the standard library's
/// `TcpStream` on Windows only calls `recv`, `send`, `shutdown` and `closesocket` for reading,
/// writing, half-closing and dropping, and AF_UNIX stream sockets support all four with the same
/// semantics (measured on Windows 11). Methods that interpret socket addresses, such as
/// `peer_addr`, do not apply and are not used. This lets the relay copy bytes between an AF_UNIX
/// and a TCP connection with one implementation.
#[cfg(windows)]
pub mod unix {
    use std::io;
    use std::mem::size_of;
    use std::net::TcpStream;
    use std::os::windows::io::FromRawSocket;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Networking::WinSock::{
        AF_UNIX, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, SOCKET, WSAGetLastError,
        accept, bind, closesocket, connect, listen, socket,
    };

    /// The longest socket path, in bytes of UTF-8: `sun_path` holds 108 bytes including the
    /// terminating NUL.
    pub const MAX_PATH_BYTES: usize = 107;

    /// A listening AF_UNIX socket, closed on drop.
    #[derive(Debug)]
    pub struct Listener(SOCKET);

    impl Listener {
        /// Creates the socket file at `path` and listens on it.
        pub fn bind(path: &Path) -> io::Result<Listener> {
            let address = address(path)?;
            let listener = Listener(new_socket()?);
            // SAFETY: address is a SOCKADDR_UN and its size is passed.
            if unsafe { bind(listener.0, address_ptr(&address), address_len()) } != 0 {
                return Err(last_error());
            }
            // SAFETY: the socket is bound.
            if unsafe { listen(listener.0, 128) } != 0 {
                return Err(last_error());
            }
            Ok(listener)
        }

        /// Waits for the next connection.
        pub fn accept(&self) -> io::Result<TcpStream> {
            // SAFETY: the socket listens; null pointers ask for no peer address.
            let client = unsafe { accept(self.0, ptr::null_mut(), ptr::null_mut()) };
            if client == INVALID_SOCKET {
                return Err(last_error());
            }
            // SAFETY: accept returned a new connected socket that nothing else owns.
            Ok(unsafe { TcpStream::from_raw_socket(client as u64) })
        }
    }

    impl std::os::windows::io::AsRawSocket for Listener {
        fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
            self.0 as std::os::windows::io::RawSocket
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            // SAFETY: the socket is open and closed exactly once.
            unsafe { closesocket(self.0) };
        }
    }

    /// Whether this host can create AF_UNIX sockets (Windows 10 1803 and later can).
    pub fn available() -> io::Result<()> {
        let probe = new_socket()?;
        // SAFETY: probe is a new socket that nothing else owns, closed exactly once.
        unsafe { closesocket(probe) };
        Ok(())
    }

    /// Connects to the AF_UNIX socket at `path`.
    pub fn connect_to(path: &Path) -> io::Result<TcpStream> {
        let address = address(path)?;
        let stream = new_socket()?;
        // SAFETY: stream is a new socket that this function owns; address is a SOCKADDR_UN.
        let owned = unsafe { TcpStream::from_raw_socket(stream as u64) };
        // SAFETY: address is a SOCKADDR_UN and its size is passed.
        if unsafe { connect(stream, address_ptr(&address), address_len()) } != 0 {
            return Err(last_error());
        }
        Ok(owned)
    }

    fn new_socket() -> io::Result<SOCKET> {
        super::winsock_startup()?;
        // SAFETY: socket has no memory safety preconditions.
        let handle = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if handle == INVALID_SOCKET {
            return Err(last_error());
        }
        Ok(handle)
    }

    /// The `sockaddr_un` for `path`. Windows reads `sun_path` as UTF-8 (measured with a
    /// non-ASCII directory name).
    fn address(path: &Path) -> io::Result<SOCKADDR_UN> {
        let text = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path is not valid Unicode",
            )
        })?;
        let bytes = text.as_bytes();
        if bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path {text} is {} bytes; AF_UNIX allows at most {MAX_PATH_BYTES}",
                    bytes.len()
                ),
            ));
        }
        let mut address = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as i8;
        }
        Ok(address)
    }

    fn address_ptr(address: &SOCKADDR_UN) -> *const SOCKADDR {
        (address as *const SOCKADDR_UN).cast()
    }

    fn address_len() -> i32 {
        size_of::<SOCKADDR_UN>() as i32
    }

    fn last_error() -> io::Error {
        // SAFETY: WSAGetLastError has no preconditions.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }
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

    /// A connected pair: the end a peer holds, and the end the relay gets.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (relayed, _) = listener.accept().unwrap();
        (peer, relayed)
    }

    /// A peer that resets its connection must not look like one that ended it: the relay resets
    /// the other side too, so the target cannot take a cut stream for a complete one.
    #[test]
    fn a_reset_reaches_the_other_side() {
        let (client, client_end) = pair();
        let (mut target, target_end) = pair();
        let relay = thread::spawn(move || relay_streams(client_end, target_end));
        (&client).write_all(&[7; 100_000]).unwrap();
        reset_on_close(raw(&client));
        drop(client);
        let mut received = Vec::new();
        let result = target.read_to_end(&mut received);
        assert!(
            result.is_err(),
            "the target saw a normal end after {} bytes",
            received.len()
        );
        relay.join().unwrap().unwrap();
    }

    /// After one side has ended, a peer that never sends again does not keep the connection.
    #[test]
    fn a_half_closed_connection_ends_when_idle() {
        let (mut client, client_end) = pair();
        let (target, target_end) = pair();
        let idle = Duration::from_millis(100);
        let relay = thread::spawn(move || relay_streams_with(client_end, target_end, idle));
        // The target ends its side; the client stays open and silent.
        drop(target);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        let started = Instant::now();
        while !relay.is_finished() && started.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(relay.is_finished(), "the relay kept the idle connection");
        relay.join().unwrap().unwrap();
        // The relay closed its end of the client's connection.
        assert!(matches!(client.read(&mut [0; 1]), Ok(0) | Err(_)));
    }

    /// A peer that stays busy is not cut off by the idle limit.
    #[test]
    fn a_half_closed_connection_stays_while_data_flows() {
        let (client, client_end) = pair();
        let (mut target, target_end) = pair();
        let idle = Duration::from_millis(300);
        let relay = thread::spawn(move || relay_streams_with(client_end, target_end, idle));
        // The target ends its side first; the client then sends for longer than the limit.
        target.shutdown(Shutdown::Write).unwrap();
        for _ in 0..8 {
            (&client).write_all(b"tick").unwrap();
            thread::sleep(Duration::from_millis(100));
        }
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"tick".repeat(8));
        relay.join().unwrap().unwrap();
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

    /// A target that answers and ends its side at once, and a client that sends its request and
    /// ends its side before it reads: both ends of the relay end at nearly the same moment, in
    /// either order. Every request must still reach the target and every answer the client.
    #[test]
    fn a_request_and_an_answer_that_end_together_both_arrive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let (sender, requests) = std::sync::mpsc::channel();
        // It answers on the thread that accepts, so the answer and its end follow the accept
        // as closely as they can.
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let _ = stream.write_all(b"answer");
                let _ = stream.shutdown(Shutdown::Write);
                let mut request = Vec::new();
                let received = stream.read_to_end(&mut request).map(|_| request);
                let _ = sender.send(received.map_err(|error| error.kind()));
            }
        });
        let relay = relay_to(target);
        for round in 0..1000 {
            let mut client = TcpStream::connect(relay).unwrap();
            client.write_all(b"request").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut answer = Vec::new();
            let answered = client.read_to_end(&mut answer).map(|_| answer);
            let request = requests.recv_timeout(Duration::from_secs(10));
            assert_eq!(
                request,
                Ok(Ok(b"request".to_vec())),
                "round {round}: the target did not get the request"
            );
            assert_eq!(
                answered.map_err(|error| error.kind()),
                Ok(b"answer".to_vec()),
                "round {round}: the client did not get the answer"
            );
        }
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

    /// The forward relay copies between an AF_UNIX connection and a TCP connection; both
    /// directions and the half close work through the `TcpStream` wrapper.
    #[cfg(windows)]
    #[test]
    fn relays_from_a_unix_socket_to_tcp() {
        let echo = echo_server();
        let dir = std::env::temp_dir().join(format!("sandy-relay-unix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = unix::Listener::bind(&path).unwrap();
        thread::spawn(move || serve_with(|| listener.accept(), move || TcpStream::connect(echo)));

        let client = unix::connect_to(&path).unwrap();
        (&client).write_all(b"hello").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        (&client).read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"echo:hello");
        // Windows deletes a socket file while its socket still listens.
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(unix::connect_to(&path).is_err());
    }

    /// Rule 5: a connection that completed its handshake before the stop, and is still waiting
    /// in the backlog, is accepted and relayed; afterwards the listener is closed.
    #[cfg(windows)]
    #[test]
    fn a_stopped_server_still_relays_connections_already_made() {
        let echo = echo_server();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // The client connects, sends and half-closes before the server takes any connection.
        let client = TcpStream::connect(address).unwrap();
        (&client).write_all(b"late").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let stop = Stop::new();
        stop.request();
        serve_until(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            move || connect(echo),
            &stop,
            DRAIN,
        );
        let mut answer = Vec::new();
        (&client).read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"echo:late");
        assert!(TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_stop_request_ends_an_idle_server_promptly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stop = Stop::new();
        let request = stop.clone();
        let started = std::time::Instant::now();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            request.request();
        });
        serve_until(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            || Err(io::Error::other("unused")),
            &stop,
            DRAIN,
        );
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
    }

    /// A connection that never finishes delays the end by at most the drain time.
    #[cfg(windows)]
    #[test]
    fn the_drain_is_bounded() {
        // A target that accepts and then holds every connection open.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = silent.local_addr().unwrap();
        thread::spawn(move || {
            let mut held = Vec::new();
            for stream in silent.incoming() {
                held.push(stream);
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let stop = Stop::new();
        stop.request();
        let drain = Duration::from_millis(300);
        let started = std::time::Instant::now();
        serve_until(
            listener,
            |listener| listener.accept().map(|(client, _)| client),
            move || connect(target),
            &stop,
            drain,
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= drain && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn refuses_unix_socket_paths_beyond_the_limit() {
        let long = std::path::PathBuf::from(format!(r"C:\{}", "a".repeat(unix::MAX_PATH_BYTES)));
        let error = unix::connect_to(&long).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    }
}
