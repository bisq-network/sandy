//! The addresses of this Mac's interfaces (`getifaddrs`), for the holder binds of
//! `ip = "private"` and for the egress broker's answer about its host (`HostNetwork`), and the
//! routes of its routing table that reach their network without a router, for that answer too.
//!
//! `getifaddrs` reads the routing sysctl (`CTL_NET`, `PF_ROUTE`, `NET_RT_IFLIST2`), so a process
//! with a profile needs `(allow sysctl-read (sysctl-name-prefix "net.route"))`; neither the exact
//! name `net.route` nor a longer prefix matches it (measured on macOS 27.0.1). It lists every
//! address, also of an interface that is down. The routing table comes from the same sysctl
//! (`NET_RT_DUMP`), which the same rule allows.

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
    let mut found = Vec::new();
    each_interface(|interface| {
        // SAFETY: the pointers of an entry are null or point at socket addresses.
        let Some((address, scope)) = (unsafe { ip_of(interface.ifa_addr) }) else {
            return;
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
    })?;
    Ok(found)
}

/// The indexes of the point-to-point interfaces, such as `utun`, `gif`, `stf` and `ppp`, from
/// the link-layer entry that `getifaddrs` lists for every interface.
fn point_to_point_links() -> io::Result<Vec<u16>> {
    let mut found = Vec::new();
    each_interface(|interface| {
        // SAFETY: the address of an entry is null or points at a socket address.
        let link = unsafe { bytes_of(interface.ifa_addr) };
        let point_to_point = interface.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0;
        // A `sockaddr_dl`: its length, its family, then the interface index.
        if let Some([_, family, low, high, ..]) = link
            && i32::from(*family) == libc::AF_LINK
            && point_to_point
        {
            found.push(u16::from_ne_bytes([*low, *high]));
        }
    })?;
    Ok(found)
}

/// Calls `each` with every entry of the list that `getifaddrs` returns.
fn each_interface(mut each: impl FnMut(&libc::ifaddrs)) -> io::Result<()> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list, which freeifaddrs frees below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entry is an element of the list that getifaddrs returned.
        let interface = unsafe { &*entry };
        entry = interface.ifa_next;
        each(interface);
    }
    // SAFETY: the list came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(())
}

/// The IP address of the socket address `raw`, and the scope of an IPv6 link-local one. `None`
/// for a null pointer and for every other family.
///
/// # Safety
///
/// `raw` is null or points at a socket address of the length it names.
unsafe fn ip_of(raw: *const libc::sockaddr) -> Option<(IpAddr, u32)> {
    // SAFETY: the caller's promise.
    unsafe { bytes_of(raw) }.and_then(ip_in)
}

/// The prefix length of the netmask `raw` of `address`.
///
/// # Safety
///
/// `raw` is null or points at a socket address of the length it names.
unsafe fn prefix_of(raw: *const libc::sockaddr, address: IpAddr) -> Option<u8> {
    // SAFETY: the caller's promise.
    unsafe { bytes_of(raw) }.map(|mask| mask_length(mask, address))
}

/// The bytes of the socket address `raw`, as many as its length names.
///
/// # Safety
///
/// `raw` is null or points at a socket address of the length it names, which outlives `'a`.
unsafe fn bytes_of<'a>(raw: *const libc::sockaddr) -> Option<&'a [u8]> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: the caller's promise; the length is the first byte.
    Some(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), usize::from((*raw).sa_len)) })
}

/// The IP address of the socket address `bytes`, and the scope of an IPv6 link-local one. `None`
/// for every other family, and for an address shorter than its family's.
fn ip_in(bytes: &[u8]) -> Option<(IpAddr, u32)> {
    match i32::from(*bytes.get(1)?) {
        libc::AF_INET if bytes.len() >= size_of::<libc::sockaddr_in>() => {
            let octets: [u8; 4] = bytes[4..8].try_into().expect("4 bytes");
            Some((Ipv4Addr::from(octets).into(), 0))
        }
        libc::AF_INET6 if bytes.len() >= size_of::<libc::sockaddr_in6>() => {
            let mut octets: [u8; 16] = bytes[8..24].try_into().expect("16 bytes");
            let mut scope = u32::from_ne_bytes(bytes[24..28].try_into().expect("4 bytes"));
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

/// The prefix length of the netmask socket address `bytes` of `address`. The kernel shortens a
/// netmask to its last byte that is not zero, so the bytes it leaves out count as zero, and it
/// does not always set the netmask's family.
fn mask_length(bytes: &[u8], address: IpAddr) -> u8 {
    // Where the address starts in sockaddr_in and in sockaddr_in6.
    let (start, size) = if address.is_ipv4() { (4, 4) } else { (8, 16) };
    let ones: u32 = bytes
        .iter()
        .skip(start)
        .take(size)
        .map(|byte| byte.leading_ones())
        .sum();
    u8::try_from(ones).expect("at most 128 bits")
}

/// The routing table of every family, as the routing sysctl gives it (`NET_RT_DUMP`): one
/// `rt_msghdr` after another, each followed by its socket addresses.
pub fn routing_table() -> io::Result<Vec<u8>> {
    let mut name = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    // A table that grows between the call that measures it and the call that reads it fails
    // the read with ENOMEM, and the next round measures it again.
    for _ in 0..3 {
        let mut size = 0;
        // SAFETY: the name has the length passed, and a null buffer asks for the size alone.
        let measured = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if measured != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut table = vec![0u8; size];
        // SAFETY: the buffer holds `size` bytes, and the call writes at most that many.
        let read = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                table.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if read == 0 {
            table.truncate(size);
            return Ok(table);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("the routing table kept growing"))
}

const ROUTE_HEADER: usize = size_of::<libc::rt_msghdr>();

/// The networks that the routes of `table` (`routing_table`) reach without a router
/// (`on_link_route`), except through the interfaces `point_to_point`: what a route sends into a
/// tunnel goes to its other end, which takes it on as a router does. Every message is checked:
/// it must be a route of this version and fit its own lengths.
fn on_link_routes(table: &[u8], point_to_point: &[u16]) -> io::Result<Vec<Subnet>> {
    let mut subnets = Vec::new();
    let mut rest = table;
    while !rest.is_empty() {
        let length = rest
            .get(..2)
            .map(|length| usize::from(u16::from_ne_bytes([length[0], length[1]])))
            .filter(|length| (ROUTE_HEADER..=rest.len()).contains(length))
            .ok_or_else(|| invalid("a route message whose length does not fit"))?;
        let route = on_link_route(&rest[..length])?;
        subnets.extend(
            route
                .filter(|(_, link)| !point_to_point.contains(link))
                .map(|(subnet, _)| subnet),
        );
        rest = &rest[length..];
    }
    Ok(subnets)
}

/// The network of one route message, with the index of the interface the route leaves through,
/// when the route reaches it without a router: a route that is up, other than the default
/// route, that sends to no gateway or to a link-layer address,
/// such as the route of an interface's subnet and the on-link prefix of router advertisements.
/// `None` for the other routes: the Mac itself (local, broadcast, multicast), which `is_host`
/// answers or `check` refuses first, routes that reach nothing (reject, blackhole), and families
/// other than IPv4 and IPv6.
fn on_link_route(message: &[u8]) -> io::Result<Option<(Subnet, u16)>> {
    let Some(head) = message.get(..ROUTE_HEADER) else {
        return Err(invalid("a truncated route message"));
    };
    // SAFETY: rt_msghdr is plain data, which any bytes of its size are, read without alignment.
    let header: libc::rt_msghdr = unsafe { std::ptr::read_unaligned(head.as_ptr().cast()) };
    if i32::from(header.rtm_version) != libc::RTM_VERSION
        || i32::from(header.rtm_type) != libc::RTM_GET
    {
        return Err(invalid("a message that is not a route"));
    }
    // The socket addresses follow in the order of their bits in rtm_addrs. Each takes its length
    // rounded up to 4 bytes, and 4 bytes when its length is 0.
    let mut addresses: [Option<&[u8]>; libc::RTAX_MAX as usize] = Default::default();
    let mut rest = &message[ROUTE_HEADER..];
    for (index, slot) in addresses.iter_mut().enumerate() {
        if header.rtm_addrs & (1 << index) == 0 {
            continue;
        }
        let length = usize::from(*rest.first().ok_or_else(|| invalid("a truncated route"))?);
        let room = length.max(1).next_multiple_of(4);
        if room > rest.len() {
            return Err(invalid("a socket address whose length does not fit"));
        }
        *slot = Some(&rest[..length]);
        rest = &rest[room..];
    }
    let address = |index: libc::c_int| addresses[index as usize];
    let Some((destination, _)) = address(libc::RTAX_DST).and_then(ip_in) else {
        return Ok(None);
    };
    let flags = header.rtm_flags;
    let to_a_link = address(libc::RTAX_GATEWAY)
        .and_then(|gateway| gateway.get(1))
        .is_some_and(|&family| i32::from(family) == libc::AF_LINK);
    let not_on_link = libc::RTF_REJECT
        | libc::RTF_BLACKHOLE
        | libc::RTF_LOCAL
        | libc::RTF_BROADCAST
        | libc::RTF_MULTICAST;
    if flags & libc::RTF_UP == 0
        || flags & not_on_link != 0
        || (flags & libc::RTF_GATEWAY != 0 && !to_a_link)
    {
        return Ok(None);
    }
    // A route without a netmask is a host route.
    let prefix = match address(libc::RTAX_NETMASK) {
        Some(mask) => mask_length(mask, destination),
        None if destination.is_ipv4() => 32,
        None => 128,
    };
    let subnet = Subnet::new(destination, prefix).filter(|_| prefix > 0);
    Ok(subnet.map(|subnet| (subnet, header.rtm_index)))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

    /// The subnets of the interfaces' addresses, for a point-to-point link that of its peer, and
    /// every network that a route reaches without a router other than through a point-to-point
    /// interface (`on_link_routes`).
    fn subnets(&self) -> io::Result<Vec<Subnet>> {
        let mut subnets: Vec<Subnet> = addresses()?
            .iter()
            .filter_map(|interface| {
                let network = interface.peer.unwrap_or(interface.address);
                Subnet::new(network, interface.prefix?)
            })
            .collect();
        subnets.extend(on_link_routes(&routing_table()?, &point_to_point_links()?)?);
        Ok(subnets)
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

    /// The routing table names the subnet that the way out leaves through as a route without a
    /// router, and not the default route, and the broker's subnets hold every such route.
    #[test]
    fn the_routing_table_holds_the_subnet_of_the_way_out() {
        let routes =
            on_link_routes(&routing_table().unwrap(), &point_to_point_links().unwrap()).unwrap();
        let subnets = Interfaces.subnets().unwrap();
        for route in &routes {
            assert!(subnets.contains(route), "{route:?} in {subnets:?}");
        }
        let on_link = |ip: IpAddr| routes.iter().any(|subnet| subnet.contains(ip));
        assert!(on_link(Ipv4Addr::LOCALHOST.into()), "{routes:?}");
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("192.0.2.1:9").is_err() {
            eprintln!("skipped: no IPv4 route out");
            return;
        }
        let IpAddr::V4(own) = probe.local_addr().unwrap().ip() else {
            unreachable!("an IPv4 socket");
        };
        let prefix = addresses()
            .unwrap()
            .iter()
            .find(|interface| interface.address == IpAddr::V4(own))
            .and_then(|interface| interface.prefix)
            .expect("the address of the way out has a prefix");
        // The last address of the subnet before its broadcast address, or the one before it.
        let last = (own.to_bits() | u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)) - 1;
        let other = Ipv4Addr::from_bits(if last == own.to_bits() {
            last - 1
        } else {
            last
        });
        assert!(
            prefix < 31 && on_link(other.into()),
            "{other} in {routes:?}"
        );
        for elsewhere in ["192.0.2.1", "1.1.1.1"] {
            assert!(
                !on_link(elsewhere.parse().unwrap()),
                "{elsewhere} in {routes:?}"
            );
        }
    }

    fn inet(octets: [u8; 4]) -> Vec<u8> {
        let mut address = vec![16, libc::AF_INET as u8, 0, 0];
        address.extend(octets);
        address.resize(16, 0);
        address
    }

    fn inet6(ip: &str) -> Vec<u8> {
        let mut address = vec![28, libc::AF_INET6 as u8, 0, 0, 0, 0, 0, 0];
        address.extend(ip.parse::<Ipv6Addr>().unwrap().octets());
        address.resize(28, 0);
        address
    }

    /// A netmask as the kernel writes it: cut after its last byte that is not zero, without a
    /// family.
    fn netmask(prefix: u32, ipv4: bool) -> Vec<u8> {
        let (start, size) = if ipv4 { (4, 4) } else { (8, 16) };
        let mut mask = vec![0u8; start];
        mask.extend((0..size).map(|byte| {
            (u8::MAX.checked_shl(8 - prefix.saturating_sub(byte * 8).min(8))).unwrap_or(0)
        }));
        while mask.len() > start && mask.last() == Some(&0) {
            mask.pop();
        }
        if mask.len() == start {
            mask.clear();
        } else {
            mask[0] = mask.len() as u8;
        }
        mask
    }

    /// A `sockaddr_dl` of interface 6 without a link-layer address, as a route of a link names
    /// it.
    fn link() -> Vec<u8> {
        let mut address = vec![20, libc::AF_LINK as u8, 6, 0];
        address.resize(20, 0);
        address
    }

    /// One route message with `flags` and its socket addresses by index (`RTAX_*`).
    fn route(flags: libc::c_int, addresses: &[(libc::c_int, Vec<u8>)]) -> Vec<u8> {
        // SAFETY: rt_msghdr is plain data; zero is a valid value for every field.
        let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        header.rtm_version = libc::RTM_VERSION as u8;
        header.rtm_type = libc::RTM_GET as u8;
        header.rtm_flags = flags;
        header.rtm_index = 6;
        let mut body = Vec::new();
        for (index, address) in addresses {
            header.rtm_addrs |= 1 << index;
            body.extend(address);
            body.resize(
                body.len() + address.len().max(1).next_multiple_of(4) - address.len(),
                0,
            );
        }
        header.rtm_msglen = u16::try_from(ROUTE_HEADER + body.len()).unwrap();
        // SAFETY: the header is plain data of ROUTE_HEADER bytes.
        let mut message =
            unsafe { std::slice::from_raw_parts((&raw const header).cast::<u8>(), ROUTE_HEADER) }
                .to_vec();
        message.extend(body);
        message
    }

    use libc::{RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTF_GATEWAY, RTF_HOST, RTF_UP};

    #[test]
    fn routes_to_a_link_name_their_network() {
        let network = |dst: Vec<u8>, gateway: Vec<u8>, prefix, flags| {
            let ipv4 = dst[1] == libc::AF_INET as u8;
            route(
                RTF_UP | flags,
                &[
                    (RTAX_DST, dst),
                    (RTAX_GATEWAY, gateway),
                    (RTAX_NETMASK, netmask(prefix, ipv4)),
                ],
            )
        };
        let table = [
            // The subnet of an interface: `192.168.8/24 link#6 UCS en0`.
            network(
                inet([192, 168, 8, 0]),
                link(),
                24,
                libc::RTF_CLONING | libc::RTF_STATIC,
            ),
            // The on-link prefix of router advertisements beside a DHCPv6 /128 address.
            network(inet6("2a01:4f8:5::"), link(), 64, libc::RTF_CLONING),
            // A route to an interface named by its address (`route add -interface`).
            network(
                inet([203, 0, 113, 0]),
                inet([192, 168, 8, 21]),
                24,
                libc::RTF_STATIC,
            ),
            // A gateway that is a link-layer address.
            network(inet([198, 51, 100, 0]), link(), 24, RTF_GATEWAY),
            // A neighbour: a host route without a netmask.
            route(
                RTF_UP | RTF_HOST | libc::RTF_LLINFO,
                &[(RTAX_DST, inet([10, 9, 0, 1])), (RTAX_GATEWAY, link())],
            ),
        ]
        .concat();
        let subnets = on_link_routes(&table, &[]).unwrap();
        let on_link = |ip: &str| {
            subnets
                .iter()
                .any(|subnet| subnet.contains(ip.parse().unwrap()))
        };
        for ip in [
            "192.168.8.77",
            "2a01:4f8:5::99",
            "203.0.113.5",
            "198.51.100.5",
            "10.9.0.1",
        ] {
            assert!(on_link(ip), "{ip} in {subnets:?}");
        }
        for ip in ["192.168.9.77", "2a01:4f8:6::99", "10.9.0.2"] {
            assert!(!on_link(ip), "{ip} in {subnets:?}");
        }
    }

    /// What a route sends into a point-to-point interface, such as the `utun` of a VPN, goes to
    /// the other end of the tunnel, so it names no network, also when it covers half of IPv4.
    #[test]
    fn routes_into_a_tunnel_name_no_network() {
        let network = |octets, prefix| {
            route(
                RTF_UP | libc::RTF_STATIC,
                &[
                    (RTAX_DST, inet(octets)),
                    (RTAX_GATEWAY, link()),
                    (RTAX_NETMASK, netmask(prefix, true)),
                ],
            )
        };
        let mut half = network([0, 0, 0, 0], 1);
        half[4..6].copy_from_slice(&20u16.to_ne_bytes());
        let table = [half, network([192, 168, 8, 0], 24)].concat();
        assert_eq!(on_link_routes(&table, &[]).unwrap().len(), 2);
        let subnets = on_link_routes(&table, &[20]).unwrap();
        let reached = |ip: &str| {
            subnets
                .iter()
                .any(|subnet| subnet.contains(ip.parse().unwrap()))
        };
        assert!(reached("192.168.8.7") && !reached("1.1.1.1"), "{subnets:?}");
    }

    #[test]
    fn other_routes_name_no_network() {
        let router = inet([192, 168, 8, 1]);
        let network = |flags, gateway: &[u8], prefix| {
            route(
                flags,
                &[
                    (RTAX_DST, inet([10, 1, 0, 0])),
                    (RTAX_GATEWAY, gateway.to_vec()),
                    (RTAX_NETMASK, netmask(prefix, true)),
                ],
            )
        };
        let mut routes = vec![
            // Through a router: `10.1/16 192.168.8.1 UGS en0`.
            network(RTF_UP | RTF_GATEWAY | libc::RTF_STATIC, &router, 16),
            // The default route, through a router and into a tunnel without one.
            network(RTF_UP | RTF_GATEWAY, &router, 0),
            network(RTF_UP | libc::RTF_IFSCOPE, &link(), 0),
            route(
                RTF_UP,
                &[
                    (RTAX_DST, inet6("::")),
                    (RTAX_GATEWAY, link()),
                    (RTAX_NETMASK, Vec::new()),
                ],
            ),
            // A route that is not up.
            network(0, &link(), 16),
            // A destination that is no IP address.
            route(RTF_UP, &[(RTAX_DST, link()), (RTAX_GATEWAY, link())]),
        ];
        // The Mac itself, and routes that reach nothing.
        for flag in [
            libc::RTF_LOCAL,
            libc::RTF_BROADCAST,
            libc::RTF_MULTICAST,
            libc::RTF_REJECT,
            libc::RTF_BLACKHOLE,
        ] {
            routes.push(network(RTF_UP | flag, &link(), 16));
        }
        for message in routes {
            assert_eq!(on_link_route(&message).unwrap(), None, "{message:?}");
        }
    }

    #[test]
    fn malformed_route_messages_fail() {
        let good = route(
            RTF_UP,
            &[(RTAX_DST, inet([10, 1, 0, 0])), (RTAX_GATEWAY, link())],
        );
        let mut too_long = good.clone();
        too_long[0..2].copy_from_slice(&(good.len() as u16 + 4).to_ne_bytes());
        let mut too_short = good.clone();
        too_short[0..2].copy_from_slice(&8u16.to_ne_bytes());
        let mut other_version = good.clone();
        other_version[2] = libc::RTM_VERSION as u8 + 1;
        let mut other_type = good.clone();
        other_type[3] = libc::RTM_ADD as u8;
        // A socket address that runs past its message, and one that the bits name but that is
        // not there.
        let mut overrun = good.clone();
        overrun[ROUTE_HEADER] = 200;
        let mut missing = good.clone();
        missing[12..16].copy_from_slice(&(0b111 as libc::c_int).to_ne_bytes());
        for table in [
            &good[..ROUTE_HEADER - 1],
            &too_long,
            &too_short,
            &other_version,
            &other_type,
            &overrun,
            &missing,
            &[good.clone(), good[..10].to_vec()].concat(),
        ] {
            assert_eq!(
                on_link_routes(table, &[]).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{table:?}"
            );
        }
        assert_eq!(
            on_link_routes(&[good.clone(), good].concat(), &[])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn shortened_netmasks_count_their_missing_bytes_as_zero() {
        let v4: IpAddr = Ipv4Addr::LOCALHOST.into();
        let v6: IpAddr = Ipv6Addr::LOCALHOST.into();
        for prefix in [0, 8, 13, 24, 32] {
            assert_eq!(mask_length(&netmask(prefix, true), v4), prefix as u8);
        }
        for prefix in [0, 10, 64, 127, 128] {
            assert_eq!(mask_length(&netmask(prefix, false), v6), prefix as u8);
        }
        assert_eq!(netmask(24, true), [7, 0, 0, 0, 255, 255, 255]);
    }
}
