//! What only the host can tell the egress broker about a destination: whether an address is one
//! of this machine's own, and which subnets its interfaces are on (`sandy_core::destination`).
//!
//! The broker runs in its own AppContainer with the internetClient capability. It asks these
//! questions for every connection, so a destination that is this machine never leaves through
//! the broker even when the program picked it. The AppContainer's own loopback isolation stops
//! it from reaching this machine at the kernel level as well (docs/windows.md, "Egress broker").

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use sandy_core::destination::{HostNetwork, Subnet};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NETWORK_UNREACHABLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetBestRoute2, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// The Windows answer to `sandy_core::destination::HostNetwork`.
#[derive(Debug, Clone, Copy)]
pub struct WindowsHost;

impl HostNetwork for WindowsHost {
    fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
        let addresses = interface_addresses()?;
        // An address of one of this host's interfaces.
        if addresses.iter().any(|address| address.ip == ip) {
            return Ok(true);
        }
        // The directed broadcast of an IPv4 subnet of an interface.
        if let IpAddr::V4(ip) = ip
            && addresses.iter().any(|address| match address.ip {
                IpAddr::V4(network) => broadcast(network, address.prefix) == Some(ip),
                IpAddr::V6(_) => false,
            })
        {
            return Ok(true);
        }
        // A route the host delivers to itself (its own addresses, and `route add` on a loopback
        // interface) is a loopback route.
        best_route(ip).map(|route| route.is_some_and(|row| row.Loopback))
    }

    fn subnets(&self) -> io::Result<Vec<Subnet>> {
        Ok(interface_addresses()?
            .into_iter()
            .filter_map(|address| Subnet::new(address.ip, address.prefix))
            .collect())
    }
}

/// One address of an interface and the length of its on-link prefix.
struct InterfaceAddress {
    ip: IpAddr,
    prefix: u8,
}

/// The directed broadcast address of the IPv4 subnet `network`/`prefix`: all host bits set.
/// `None` for a prefix that leaves no host bits (/31 and /32), which has no broadcast.
fn broadcast(network: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        return None;
    }
    let host_bits = u32::MAX >> prefix;
    Some(Ipv4Addr::from(network.to_bits() | host_bits))
}

/// Every unicast address of every interface, also of interfaces that are down, with its on-link
/// prefix length. `GetAdaptersAddresses` returns them for both address families.
fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    // The size the call needs grows between the two calls only if an interface appears in
    // between, which the retry covers.
    let mut size: u32 = 16 * 1024;
    for _ in 0..3 {
        let mut buffer = vec![0u8; size as usize];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: buffer holds `size` bytes; the out pointer and size pointer are valid.
        let error = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                adapters,
                &mut size,
            )
        };
        if error == ERROR_BUFFER_OVERFLOW {
            continue; // `size` now holds the length the call needs.
        }
        if error != NO_ERROR {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        return Ok(collect_addresses(adapters));
    }
    Err(io::Error::other(
        "the list of network adapters kept growing",
    ))
}

/// Walks the adapter list and its unicast address lists into plain addresses.
fn collect_addresses(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<InterfaceAddress> {
    let mut addresses = Vec::new();
    let mut adapter = first;
    while !adapter.is_null() {
        // SAFETY: the list is NUL-terminated by a null `Next`, and the call filled it.
        let current = unsafe { &*adapter };
        let mut unicast = current.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: as above for the unicast list.
            let entry = unsafe { &*unicast };
            // SAFETY: `lpSockaddr` points to a sockaddr of `iSockaddrLength` bytes.
            if let Some(ip) = unsafe { sockaddr_ip(entry.Address.lpSockaddr) } {
                addresses.push(InterfaceAddress {
                    ip,
                    prefix: entry.OnLinkPrefixLength,
                });
            }
            unicast = entry.Next;
        }
        adapter = current.Next;
    }
    addresses
}

/// The best route to `ip`, or `None` when the host has no route to it.
fn best_route(ip: IpAddr) -> io::Result<Option<MIB_IPFORWARD_ROW2>> {
    route_to(&inet(ip))
}

/// `best_route` for a destination in the form `GetBestRoute2` takes. Any failure other than
/// "no route" leaves open whether the address is this host's, so it is an error, which the
/// broker answers with reply 1.
fn route_to(destination: &SOCKADDR_INET) -> io::Result<Option<MIB_IPFORWARD_ROW2>> {
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: zero is a valid value for every field.
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    // SAFETY: a null interface selects the best interface; the destination, route and source
    // out pointers are valid for the call.
    let error = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            destination,
            0,
            &mut route,
            &mut source,
        )
    };
    match error {
        NO_ERROR => Ok(Some(route)),
        // No route to the destination: it is not one of this host's own addresses.
        ERROR_NETWORK_UNREACHABLE => Ok(None),
        error => Err(io::Error::from_raw_os_error(error as i32)),
    }
}

/// `ip` as a `SOCKADDR_INET` for `GetBestRoute2`.
fn inet(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut inet: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(ip) => {
            inet.Ipv4.sin_family = AF_INET;
            inet.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            inet.Ipv6.sin6_family = AF_INET6;
            inet.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    inet
}

/// The IP address of a `SOCKADDR`, or `None` for a family other than IPv4 and IPv6.
///
/// # Safety
/// `sockaddr` is null or points to a `sockaddr` whose family field is valid.
unsafe fn sockaddr_ip(sockaddr: *const SOCKADDR) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    // SAFETY: a sockaddr starts with its family, whatever its concrete type.
    match unsafe { (*sockaddr).sa_family } {
        AF_INET => {
            let addr = sockaddr.cast::<SOCKADDR_IN>();
            // SAFETY: the family says this is a SOCKADDR_IN.
            let bytes = unsafe { (*addr).sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::from(bytes))
        }
        AF_INET6 => {
            let addr = sockaddr.cast::<SOCKADDR_IN6>();
            // SAFETY: the family says this is a SOCKADDR_IN6.
            let bytes = unsafe { (*addr).sin6_addr.u.Byte };
            Some(IpAddr::from(bytes))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failure of the route lookup is not an answer about the address. A destination of no
    /// address family makes `GetBestRoute2` fail with `ERROR_INVALID_PARAMETER`; an address
    /// without a route is an answer, and 127.0.0.1 is a loopback route.
    #[test]
    fn a_failed_route_lookup_is_an_error_not_a_missing_route() {
        // SAFETY: the structure is plain data; zero is a valid value for every field.
        let no_family: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        assert!(route_to(&no_family).is_err());
        // A documentation address: routed only on a host with a default IPv6 route.
        assert!(best_route("2001:db8::1".parse().unwrap()).is_ok());
        let loopback = best_route(Ipv4Addr::LOCALHOST.into()).unwrap();
        assert!(loopback.is_some_and(|route| route.Loopback));
    }
}
