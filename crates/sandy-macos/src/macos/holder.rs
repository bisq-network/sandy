//! Holder binds for `ip = "private"` (`profile::held_ports`). Seatbelt's `localhost` is every
//! address of this Mac, so the profile that lets the program reach a forwarded port at loopback
//! lets it reach that port at the local network, link-local and VPN addresses too. sandy binds
//! the port at `0.0.0.0` and at `[::]` (IPv6 only) without listening: a connection to the port at
//! an address where nothing more specific listens then finds this socket, which never answers.
//!
//! `SO_REUSEADDR` keeps a connection of an earlier run that waits in `TIME_WAIT` from refusing the
//! bind, and still refuses it when another socket is bound at the same wildcard address, or a
//! socket of another user at any address of the port.

use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use sandy_core::SandboxError;

/// Binds `port` at the wildcard address of both families. The sockets hold the port until they
/// are closed.
pub fn hold(port: u16) -> Result<[OwnedFd; 2], SandboxError> {
    let bind = |address: SocketAddr| {
        bind_without_listening(address).map_err(|error| {
            let advice = if error.kind() == io::ErrorKind::AddrInUse {
                " (another socket uses the port there; forward a port that is free)"
            } else {
                ""
            };
            SandboxError::io(
                format!("cannot hold port {port} at {address} for ip = \"private\"{advice}"),
                error,
            )
        })
    };
    Ok([
        bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))?,
        bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))?,
    ])
}

fn bind_without_listening(address: SocketAddr) -> io::Result<OwnedFd> {
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket has no memory arguments.
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor is new and owned by nothing else.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fcntl on an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    set_flag(&socket, libc::SOL_SOCKET, libc::SO_REUSEADDR)?;
    let result = match address {
        SocketAddr::V4(v4) => {
            // SAFETY: sockaddr_in is plain data, and zero is a valid value for every field.
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_len = size_of::<libc::sockaddr_in>() as u8;
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = v4.port().to_be();
            raw.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            // SAFETY: raw is a sockaddr_in of the length passed.
            unsafe { libc::bind(fd, (&raw const raw).cast(), raw.sin_len.into()) }
        }
        SocketAddr::V6(v6) => {
            // Only IPv6: the IPv4 socket holds IPv4.
            set_flag(&socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
            // SAFETY: sockaddr_in6 is plain data, and zero is a valid value for every field.
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = v6.port().to_be();
            raw.sin6_addr.s6_addr = v6.ip().octets();
            // SAFETY: raw is a sockaddr_in6 of the length passed.
            unsafe { libc::bind(fd, (&raw const raw).cast(), raw.sin6_len.into()) }
        }
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn set_flag(socket: &OwnedFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: the value is a c_int of the size passed.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// The holder takes the wildcard addresses of the port, and leaves the loopback address to the
    /// relay's listener, whichever binds first.
    #[test]
    fn holds_the_wildcard_addresses_next_to_the_relay_listener() {
        let port = free_port();
        let held = hold(port).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        for wildcard in ["0.0.0.0", "::"] {
            let error = TcpListener::bind((wildcard, port)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse, "{wildcard}");
        }
        drop(held);
        drop(listener);

        let port = free_port();
        let listener = TcpListener::bind(("::1", port)).unwrap();
        let held = hold(port).unwrap();
        drop((held, listener));
        // Closed sockets hold nothing.
        let _free = TcpListener::bind(("0.0.0.0", port)).unwrap();
    }

    /// A process that listens on the port at a wildcard address would receive the program's
    /// connections to the other addresses of this Mac, so the hold fails.
    #[test]
    fn a_wildcard_listener_of_another_socket_refuses_the_hold() {
        for wildcard in ["0.0.0.0", "::"] {
            let other = TcpListener::bind((wildcard, 0)).unwrap();
            let port = other.local_addr().unwrap().port();
            let error = hold(port).unwrap_err().to_string();
            assert!(
                error.contains(&format!("cannot hold port {port}")),
                "{wildcard}: {error}"
            );
        }
    }
}
