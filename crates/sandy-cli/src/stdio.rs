//! What the standard streams of this process carry. `run` asks before it applies the sandbox,
//! because the program inherits these streams as they are (see `sandy_core::streams`).

use sandy_core::streams::{Family, Kind, Socket, StandardStream};

/// The socket on `stream`, or `None` when the stream carries something else (a file, a pipe, a
/// terminal, a device) or is closed. An error means sandy could not find out, which `run` treats
/// like any other check it cannot perform.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn socket_on(stream: StandardStream) -> Result<Option<Socket>, String> {
    use std::io;
    use std::mem::{MaybeUninit, size_of};
    use std::os::fd::RawFd;

    let fd: RawFd = match stream {
        StandardStream::Input => 0,
        StandardStream::Output => 1,
        StandardStream::Error => 2,
    };
    let failed = |call: &str, error: io::Error| format!("cannot read {stream}: {call}: {error}");

    let mut status = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat only fills the structure.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        // A stream the caller closed stays closed for the program, which can open nothing with
        // the descriptor it leaves free: Landlock and the Seatbelt profile decide every open.
        return match error.raw_os_error() {
            Some(libc::EBADF) => Ok(None),
            _ => Err(failed("fstat", error)),
        };
    }
    // SAFETY: fstat filled the structure.
    let mode = unsafe { status.assume_init() }.st_mode;
    if mode & libc::S_IFMT != libc::S_IFSOCK {
        return Ok(None);
    }

    // From the socket rather than from its address: getsockname fails for some families, AF_ALG
    // on Linux and AF_ROUTE on macOS for example.
    #[cfg(target_os = "linux")]
    let (family, protocol) = (
        option(fd, libc::SO_DOMAIN).map_err(|error| failed("SO_DOMAIN", error))?,
        option(fd, libc::SO_PROTOCOL).map_err(|error| failed("SO_PROTOCOL", error))?,
    );
    #[cfg(target_os = "macos")]
    let (family, protocol) = socket_info(fd).map_err(|error| failed("proc_pidfdinfo", error))?;
    let family = match family {
        libc::AF_UNIX => Family::Unix,
        libc::AF_INET | libc::AF_INET6 => Family::Ip,
        number => Family::Other {
            number,
            name: family_name(number),
        },
    };

    // The obsolete link-layer type, which the kernel turns into an AF_PACKET socket. The libc
    // crate deprecates its name.
    #[cfg(target_os = "linux")]
    const SOCK_PACKET: libc::c_int = 10;
    let kind = match option(fd, libc::SO_TYPE).map_err(|error| failed("SO_TYPE", error))? {
        libc::SOCK_STREAM => Kind::Stream,
        libc::SOCK_SEQPACKET => Kind::Seqpacket,
        libc::SOCK_DGRAM => Kind::Datagram,
        libc::SOCK_RAW => Kind::Raw,
        #[cfg(target_os = "linux")]
        SOCK_PACKET => Kind::Raw,
        _ => Kind::Other,
    };
    // Only the message says whether the socket listens: a listening socket has no peer, so it is
    // already not a pipe whatever this answers. macOS has no SO_ACCEPTCONN and reports
    // ENOPROTOOPT for every socket, which leaves such a socket described by what the kernel does
    // say about it.
    let listening = option(fd, libc::SO_ACCEPTCONN).unwrap_or(0) != 0;

    let mut peer = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the buffer holds `length` bytes, which the call does not exceed.
    let connected = if unsafe { libc::getpeername(fd, peer.as_mut_ptr().cast(), &mut length) } == 0
    {
        true
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // All mean the socket has no peer; which one comes back differs per family. A family
            // without peers, AF_ALG for example, answers EOPNOTSUPP.
            Some(libc::ENOTCONN | libc::EINVAL | libc::EOPNOTSUPP) => false,
            _ => return Err(failed("getpeername", error)),
        }
    };

    Ok(Some(Socket {
        family,
        kind,
        protocol,
        connected,
        listening,
    }))
}

/// The names of the families a message is likely to name: those the platform docs list as
/// denied. Any other family is named by its number.
#[cfg(target_os = "linux")]
fn family_name(family: libc::c_int) -> Option<&'static str> {
    // Not in the libc crate for every Linux target.
    const AF_VSOCK: libc::c_int = 40;
    const AF_SMC: libc::c_int = 43;
    Some(match family {
        libc::AF_NETLINK => "AF_NETLINK",
        libc::AF_PACKET => "AF_PACKET",
        libc::AF_ALG => "AF_ALG",
        AF_VSOCK => "AF_VSOCK",
        AF_SMC => "AF_SMC",
        _ => return None,
    })
}

#[cfg(target_os = "macos")]
fn family_name(family: libc::c_int) -> Option<&'static str> {
    Some(match family {
        libc::AF_ROUTE => "AF_ROUTE",
        libc::AF_SYSTEM => "AF_SYSTEM",
        libc::AF_NDRV => "AF_NDRV",
        libc::PF_KEY => "PF_KEY",
        _ => return None,
    })
}

/// The family and the protocol of the socket `fd`, from `proc_pidfdinfo`, which answers for
/// every family. macOS has neither SO_DOMAIN nor SO_PROTOCOL.
#[cfg(target_os = "macos")]
fn socket_info(fd: std::os::fd::RawFd) -> Result<(libc::c_int, libc::c_int), std::io::Error> {
    use std::mem::{MaybeUninit, size_of};

    /// `struct socket_fdinfo` of <sys/proc_info.h>, which the libc crate does not have. Only
    /// `soi_protocol` and `soi_family` are named; the kernel answers only for a buffer of the
    /// whole size.
    #[repr(C)]
    struct SocketFdInfo {
        head: [u8; 180],
        protocol: libc::c_int,
        family: libc::c_int,
        rest: [u8; 604],
    }
    const _: () = assert!(size_of::<SocketFdInfo>() == 792);
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

    let mut info = MaybeUninit::<SocketFdInfo>::zeroed();
    let size = size_of::<SocketFdInfo>() as libc::c_int;
    // SAFETY: the buffer holds `size` bytes, which the call does not exceed.
    let filled = unsafe {
        libc::proc_pidfdinfo(
            std::process::id() as libc::c_int,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if filled != size {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the structure was zeroed, and proc_pidfdinfo filled all of it.
    let info = unsafe { info.assume_init() };
    Ok((info.family, info.protocol))
}

/// One integer socket option of `fd` at the socket level.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn option(fd: std::os::fd::RawFd, name: libc::c_int) -> Result<libc::c_int, std::io::Error> {
    use std::mem::size_of;

    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the buffer holds an int, which is the size the call is given.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn socket_on(stream: StandardStream) -> Result<Option<Socket>, String> {
    use std::mem::{MaybeUninit, size_of};

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNIX, SO_ACCEPTCONN, SO_PROTOCOL_INFOW, SOCK_DGRAM, SOCK_RAW,
        SOCK_SEQPACKET, SOCK_STREAM, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, SOL_SOCKET,
        WSAENOTCONN, WSAENOTSOCK, WSAGetLastError, WSAPROTOCOL_INFOW, getpeername, getsockopt,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let which = match stream {
        StandardStream::Input => STD_INPUT_HANDLE,
        StandardStream::Output => STD_OUTPUT_HANDLE,
        StandardStream::Error => STD_ERROR_HANDLE,
    };
    // SAFETY: GetStdHandle has no preconditions.
    let handle = unsafe { GetStdHandle(which) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(None);
    }
    let socket = handle as SOCKET;
    let failed = |call: &str, error: i32| format!("cannot read {stream}: {call}: error {error}");

    // Winsock answers only after it has started in this process. A console, a pipe and a file
    // all report WSAENOTSOCK, so this is also what tells a socket from everything else: a socket
    // and a named pipe share the file type FILE_TYPE_PIPE.
    start_winsock()?;
    let mut info = MaybeUninit::<WSAPROTOCOL_INFOW>::zeroed();
    let mut length = size_of::<WSAPROTOCOL_INFOW>() as i32;
    // SAFETY: the buffer holds `length` bytes, which the call does not exceed.
    let result = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW,
            info.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: WSAGetLastError has no preconditions.
        let error = unsafe { WSAGetLastError() };
        return match error {
            WSAENOTSOCK => Ok(None),
            error => Err(failed("SO_PROTOCOL_INFOW", error)),
        };
    }
    // SAFETY: getsockopt filled the structure.
    let info = unsafe { info.assume_init() };
    let family = match info.iAddressFamily as u16 {
        AF_UNIX => Family::Unix,
        AF_INET | AF_INET6 => Family::Ip,
        _ => Family::Other {
            number: info.iAddressFamily,
            name: family_name(info.iAddressFamily),
        },
    };
    let kind = match info.iSocketType {
        SOCK_STREAM => Kind::Stream,
        SOCK_SEQPACKET => Kind::Seqpacket,
        SOCK_DGRAM => Kind::Datagram,
        SOCK_RAW => Kind::Raw,
        _ => Kind::Other,
    };

    // Only the message says whether the socket listens: a listening socket has no peer, so it is
    // already not a pipe whatever this answers. A socket that cannot listen at all, a datagram
    // socket for example, answers WSAENOPROTOOPT instead of zero.
    let mut flag: i32 = 0;
    let mut length = size_of::<i32>() as i32;
    // SAFETY: the buffer holds an int, which is the size the call is given.
    let result = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            std::ptr::from_mut(&mut flag).cast(),
            &mut length,
        )
    };
    let listening = result != SOCKET_ERROR && flag != 0;

    // Room for every family: Winsock fails with WSAEFAULT when the peer's address, an IPv6 or
    // AF_UNIX one for example, does not fit.
    let mut peer = MaybeUninit::<SOCKADDR_STORAGE>::zeroed();
    let mut length = size_of::<SOCKADDR_STORAGE>() as i32;
    // SAFETY: the buffer holds `length` bytes, which the call does not exceed.
    let connected = if unsafe { getpeername(socket, peer.as_mut_ptr().cast(), &mut length) } == 0 {
        true
    } else {
        // SAFETY: WSAGetLastError has no preconditions.
        match unsafe { WSAGetLastError() } {
            WSAENOTCONN => false,
            error => return Err(failed("getpeername", error)),
        }
    };

    Ok(Some(Socket {
        family,
        kind,
        protocol: info.iProtocol,
        connected,
        listening,
    }))
}

/// The names of the families besides IP and Unix that Windows has providers for. Any other family
/// is named by its number.
#[cfg(windows)]
fn family_name(family: i32) -> Option<&'static str> {
    const AF_BTH: i32 = 32;
    const AF_HYPERV: i32 = 34;
    Some(match family {
        AF_BTH => "AF_BTH",
        AF_HYPERV => "AF_HYPERV",
        _ => return None,
    })
}

/// Starts Winsock for this process, once. It is never stopped: `WSACleanup` of the last user
/// ends every socket of the process, which would include the one on the standard stream that is
/// being looked at. The Rust standard library starts it the same way.
#[cfg(windows)]
fn start_winsock() -> Result<(), String> {
    use std::mem::MaybeUninit;
    use std::sync::OnceLock;

    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};

    static STARTED: OnceLock<i32> = OnceLock::new();
    let result = *STARTED.get_or_init(|| {
        let mut data = MaybeUninit::<WSADATA>::zeroed();
        // SAFETY: the structure is the one WSAStartup fills.
        unsafe { WSAStartup(0x0202, data.as_mut_ptr()) }
    });
    if result == 0 {
        Ok(())
    } else {
        Err(format!("cannot start Winsock: error {result}"))
    }
}

/// The other platforms have no backend that runs a program.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn socket_on(_stream: StandardStream) -> Result<Option<Socket>, String> {
    Ok(None)
}
