//! The addresses of this Mac's interfaces (`getifaddrs`), for the holder binds of
//! `ip = "private"` and for the egress broker's answer about its host (`HostNetwork`).
//!
//! `getifaddrs` reads the routing sysctl (`CTL_NET`, `PF_ROUTE`, `NET_RT_IFLIST2`), so a process
//! with a profile needs `(allow sysctl-read (sysctl-name-prefix "net.route"))`; neither the exact
//! name `net.route` nor a longer prefix matches it (measured on macOS 27.0.1). It lists every
//! address, also of an interface that is down.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sandy_core::destination::{HostNetwork, Subnet};

/// One address of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    /// The interface index of an IPv6 link-local address, which a bind needs; 0 otherwise.
    pub scope: u32,
    /// The length of the subnet prefix, when the interface names one.
    pub prefix: Option<u8>,
    /// The subnet's broadcast address of an IPv4 interface that has one.
    pub broadcast: Option<Ipv4Addr>,
    /// The other end of a point-to-point link.
    pub peer: Option<IpAddr>,
}

/// Every IPv4 and IPv6 address of every interface.
pub fn addresses() -> io::Result<Vec<InterfaceAddress>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list, which freeifaddrs frees below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entry is an element of the list that getifaddrs returned.
        let interface = unsafe { &*entry };
        entry = interface.ifa_next;
        // SAFETY: the pointers of an entry are null or point at socket addresses.
        let Some((address, scope)) = (unsafe { ip_of(interface.ifa_addr) }) else {
            continue;
        };
        // SAFETY: as above.
        let other = unsafe { ip_of(interface.ifa_dstaddr) }.map(|(ip, _)| ip);
        let flags = interface.ifa_flags;
        found.push(InterfaceAddress {
            address,
            scope,
            // SAFETY: as above.
            prefix: unsafe { prefix_of(interface.ifa_netmask, address) },
            broadcast: match other {
                Some(IpAddr::V4(broadcast)) if flags & libc::IFF_BROADCAST as u32 != 0 => {
                    Some(broadcast)
                }
                _ => None,
            },
            peer: other.filter(|_| flags & libc::IFF_POINTOPOINT as u32 != 0),
        });
    }
    // SAFETY: the list came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// The IP address of the socket address `raw`, and the scope of an IPv6 link-local one. `None`
/// for a null pointer and for every other family.
///
/// # Safety
///
/// `raw` is null or points at a socket address of the length it names.
unsafe fn ip_of(raw: *const libc::sockaddr) -> Option<(IpAddr, u32)> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: the caller's promise; the family and length are the first two bytes.
    let (family, length) = unsafe { (i32::from((*raw).sa_family), usize::from((*raw).sa_len)) };
    match family {
        libc::AF_INET if length >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: an AF_INET address of its full length.
            let v4 = unsafe { &*raw.cast::<libc::sockaddr_in>() };
            Some((Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)).into(), 0))
        }
        libc::AF_INET6 if length >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: an AF_INET6 address of its full length.
            let v6 = unsafe { &*raw.cast::<libc::sockaddr_in6>() };
            let mut octets = v6.sin6_addr.s6_addr;
            let mut scope = v6.sin6_scope_id;
            // The kernel's own form of a link-local address carries the interface in the third
            // and fourth byte.
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            if link_local && (octets[2], octets[3]) != (0, 0) {
                scope = u32::from(u16::from_be_bytes([octets[2], octets[3]]));
                (octets[2], octets[3]) = (0, 0);
            }
            Some((Ipv6Addr::from(octets).into(), scope))
        }
        _ => None,
    }
}

/// The prefix length of the netmask `raw` of `address`. The kernel shortens a netmask to its
/// last byte that is not zero, so the bytes it leaves out count as zero.
///
/// # Safety
///
/// `raw` is null or points at a socket address of the length it names.
unsafe fn prefix_of(raw: *const libc::sockaddr, address: IpAddr) -> Option<u8> {
    if raw.is_null() {
        return None;
    }
    // Where the address starts in sockaddr_in and in sockaddr_in6.
    let (start, size) = if address.is_ipv4() { (4, 4) } else { (8, 16) };
    // SAFETY: the caller's promise; the length is the first byte.
    let length = usize::from(unsafe { (*raw).sa_len });
    let mut mask = [0u8; 16];
    for (index, byte) in mask[..size].iter_mut().enumerate() {
        if start + index < length {
            // SAFETY: within the length the socket address names.
            *byte = unsafe { *raw.cast::<u8>().add(start + index) };
        }
    }
    let ones: u32 = mask[..size].iter().map(|byte| byte.leading_ones()).sum();
    u8::try_from(ones).ok()
}

/// The egress broker's answer about this Mac, read again for every connection, because its
/// addresses change while the program runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct Interfaces;

impl HostNetwork for Interfaces {
    /// macOS delivers to itself only the addresses of its interfaces and the broadcast address
    /// of their subnets: it has no local routes without an address, 127.0.0.2 included
    /// (docs/macos.md, "The private network"), and `check` refuses multicast before it asks.
    fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
        Ok(addresses()?.iter().any(|interface| {
            interface.address == ip || interface.broadcast.map(IpAddr::V4) == Some(ip)
        }))
    }

    fn subnets(&self) -> io::Result<Vec<Subnet>> {
        Ok(addresses()?
            .iter()
            .filter_map(|interface| {
                let network = interface.peer.unwrap_or(interface.address);
                Subnet::new(network, interface.prefix?)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback, with its prefix, is among the addresses, and the address that the route to
    /// another network leaves from is one of this Mac's.
    #[test]
    fn lists_loopback_and_the_address_of_the_default_route() {
        let all = addresses().unwrap();
        let loopback = all
            .iter()
            .find(|interface| interface.address == IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("127.0.0.1");
        assert_eq!(loopback.prefix, Some(8));
        assert!(Interfaces.is_host(Ipv4Addr::LOCALHOST.into()).unwrap());
        assert!(all.iter().any(|interface| interface.scope != 0));
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("192.0.2.1:9").is_ok() {
            let own = probe.local_addr().unwrap().ip();
            assert!(Interfaces.is_host(own).unwrap(), "{own}");
            let on_subnet = Interfaces
                .subnets()
                .unwrap()
                .iter()
                .any(|subnet| subnet.contains(own));
            assert!(on_subnet, "{own}");
        }
        assert!(!Interfaces.is_host("192.0.2.1".parse().unwrap()).unwrap());
    }
}
