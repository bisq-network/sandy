//! Holder binds for `ip = "private"` (`profile::held_ports`, `profile::broker_holds`).
//! Seatbelt's `localhost` is every address of this Mac, so the profile that lets the program
//! reach a forwarded or egress port at loopback lets it reach that port at the local network,
//! link-local and VPN addresses too. sandy binds the port without listening at `0.0.0.0`, at
//! `[::]` (IPv6 only) and at every address the Mac has now, except where its own listener or the
//! program listens: a connection to the port at such an address finds sandy's socket, which never
//! answers, and a socket that already holds one of them makes the bind, and so the run, fail.
//!
//! `SO_REUSEADDR` keeps a connection of an earlier run that waits in `TIME_WAIT` from refusing the
//! bind, and still refuses it when another socket is bound at the same address, or a socket of
//! another user at any address of the port. An address that the Mac gains later is held only by
//! the wildcard binds, next to which a process of sandy's user can still bind it.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use sandy_core::SandboxError;

use super::interfaces;

/// Binds `port` at the wildcard addresses and at every address of this Mac but `leave`. The
/// sockets hold the port until they are closed.
pub fn hold(port: u16, leave: &[IpAddr]) -> Result<Vec<OwnedFd>, SandboxError> {
    let refused = |address: SocketAddr, error: io::Error| {
        let advice = if error.kind() == io::ErrorKind::AddrInUse {
            " (another socket uses the port there; use a port that is free)"
        } else {
            ""
        };
        SandboxError::io(
            format!("cannot hold port {port} at {address} for ip = \"private\"{advice}"),
            error,
        )
    };
    let mut held = Vec::new();
    for wildcard in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Ipv6Addr::UNSPECIFIED.into(),
    ] {
        let address = SocketAddr::new(wildcard, port);
        held.push(bind_without_listening(address).map_err(|error| refused(address, error))?);
    }
    let addresses = interfaces::addresses().map_err(|error| {
        SandboxError::io("cannot read the addresses of this Mac's interfaces", error)
    })?;
    let mut done: Vec<SocketAddr> = Vec::new();
    for interface in addresses {
        let address = match interface.address {
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, interface.scope)),
            v4 => SocketAddr::new(v4, port),
        };
        if leave.contains(&interface.address) || done.contains(&address) {
            continue;
        }
        done.push(address);
        match bind_without_listening(address) {
            Ok(socket) => held.push(socket),
            // An address that is not ready yet, such as a tentative IPv6 address, takes no bind;
            // the wildcard bind holds it.
            Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {}
            Err(error) => return Err(refused(address, error)),
        }
    }
    Ok(held)
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
            raw.sin6_scope_id = v6.scope_id();
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

    fn at(interface: &interfaces::InterfaceAddress, port: u16) -> SocketAddr {
        match interface.address {
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, interface.scope)),
            v4 => SocketAddr::new(v4, port),
        }
    }

    /// The holder takes the wildcard addresses and every address of this Mac, and leaves the
    /// relay's listener its address, whichever binds first. Closed, its sockets hold nothing.
    #[test]
    fn holds_every_address_but_the_listeners() {
        let _binds = super::super::BINDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = free_port();
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let held = hold(port, &[loopback]).unwrap();
        let listener = TcpListener::bind((loopback, port)).unwrap();
        let mut others: Vec<SocketAddr> = interfaces::addresses()
            .unwrap()
            .iter()
            .filter(|interface| interface.address != loopback)
            .map(|interface| at(interface, port))
            .collect();
        others.extend(
            ["0.0.0.0", "[::]"].map(|ip| format!("{ip}:{port}").parse::<SocketAddr>().unwrap()),
        );
        for address in &others {
            let taken = TcpListener::bind(address).map(drop).map_err(|e| e.kind());
            assert!(
                matches!(
                    taken,
                    Err(io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable)
                ),
                "{address}: {taken:?}"
            );
        }
        drop((held, listener));
        for wildcard in ["0.0.0.0", "::"] {
            if let Err(error) = TcpListener::bind((wildcard, port)) {
                panic!("{wildcard}:{port} after the hold: {error}");
            }
        }

        let port = free_port();
        let listener = TcpListener::bind(("::1", port)).unwrap();
        drop((hold(port, &[Ipv6Addr::LOCALHOST.into()]).unwrap(), listener));
    }

    /// A socket that already listens on the port, at a wildcard address or at an address of this
    /// Mac, would receive the program's connections there, so the hold fails.
    #[test]
    fn a_listener_of_another_socket_refuses_the_hold() {
        let _binds = super::super::BINDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut addresses: Vec<IpAddr> =
            vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()];
        addresses.push(Ipv6Addr::LOCALHOST.into());
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("192.0.2.1:9").is_ok() {
            addresses.push(probe.local_addr().unwrap().ip());
        }
        for ip in addresses {
            let other = TcpListener::bind((ip, 0)).unwrap();
            let port = other.local_addr().unwrap().port();
            let error = hold(port, &[]).unwrap_err().to_string();
            assert!(
                error.contains(&format!("cannot hold port {port}")),
                "{ip}: {error}"
            );
        }
    }
}
