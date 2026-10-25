//! What only the host can tell the egress broker about a destination: whether an address is one
//! of this machine's own, and which networks it reaches without a router: the subnets of its
//! interfaces and the networks of its on-link routes (`sandy_core::destination`).
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
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetBestRoute2, GetIfTable2, GetIpForwardTable2,
    IF_TYPE_PPP, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_POINT_TO_POINT;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// The Windows answer to `sandy_core::destination::HostNetwork`.
#[derive(Debug, Clone, Copy)]
pub struct WindowsHost;

impl HostNetwork for WindowsHost {
    fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
        let addresses = adapters()?.addresses;
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
        let adapters = adapters()?;
        let mut subnets: Vec<Subnet> = adapters
            .addresses
            .iter()
            .filter_map(|address| Subnet::new(address.ip, address.prefix))
            .collect();
        let mut point_to_point = adapters.point_to_point;
        point_to_point.extend(point_to_point_access()?);
        subnets.extend(on_link_routes(&point_to_point)?);
        Ok(subnets)
    }
}

/// The LUIDs of the interfaces whose access type is point-to-point (`GetIfTable2`), which a
/// tunnel can have whatever type it declares.
fn point_to_point_access() -> io::Result<Vec<u64>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: the call writes a pointer to a table that FreeMibTable frees below.
    let error = unsafe { GetIfTable2(&mut table) };
    if error != NO_ERROR {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: the table holds `NumEntries` rows from its first one on.
    let interfaces = unsafe {
        std::slice::from_raw_parts(
            (&raw const (*table).Table).cast::<MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    let found = point_to_point_of(interfaces);
    // SAFETY: the table came from GetIfTable2 and nothing refers to it any more.
    unsafe { FreeMibTable(table.cast()) };
    Ok(found)
}

/// The LUIDs of the `interfaces` whose access type is point-to-point.
fn point_to_point_of(interfaces: &[MIB_IF_ROW2]) -> Vec<u64> {
    interfaces
        .iter()
        .filter(|interface| interface.AccessType == NET_IF_ACCESS_POINT_TO_POINT)
        // SAFETY: a LUID is a 64-bit value in either view of its union.
        .map(|interface| unsafe { interface.InterfaceLuid.Value })
        .collect()
}

/// Every network that a route of this machine reaches without a router (`on_link`), from the
/// routing table of both families.
fn on_link_routes(point_to_point: &[u64]) -> io::Result<Vec<Subnet>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the call writes a pointer to a table that FreeMibTable frees below.
    let error = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if error != NO_ERROR {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: the table holds `NumEntries` rows from its first one on.
    let routes = unsafe {
        std::slice::from_raw_parts(
            (&raw const (*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    let subnets = on_link(routes, point_to_point);
    // SAFETY: the table came from GetIpForwardTable2 and nothing refers to it any more.
    unsafe { FreeMibTable(table.cast()) };
    Ok(subnets)
}

/// The networks that `routes` reach without a router: every route whose next hop is the
/// unspecified address, which Windows calls on-link, except the default route and the routes
/// into the interfaces `point_to_point` (by LUID). The on-link routes of this machine itself
/// (its addresses, their broadcast addresses, multicast and loopback) are among them; `is_host`
/// answers for those, or `check` refuses them first.
fn on_link(routes: &[MIB_IPFORWARD_ROW2], point_to_point: &[u64]) -> Vec<Subnet> {
    routes
        .iter()
        .filter_map(|route| {
            // SAFETY: a LUID is a 64-bit value in either view of its union.
            if point_to_point.contains(&unsafe { route.InterfaceLuid.Value }) {
                return None;
            }
            let prefix = route.DestinationPrefix.PrefixLength;
            // SAFETY: both are SOCKADDR_INET of the routing table, whose family says which
            // address they hold.
            let (destination, next_hop) = unsafe {
                (
                    sockaddr_ip((&raw const route.DestinationPrefix.Prefix).cast())?,
                    sockaddr_ip((&raw const route.NextHop).cast())?,
                )
            };
            if prefix == 0 || !next_hop.is_unspecified() {
                return None;
            }
            Subnet::new(destination, prefix)
        })
        .collect()
}

/// What `GetAdaptersAddresses` tells about the interfaces.
struct Adapters {
    addresses: Vec<InterfaceAddress>,
    /// The LUIDs of the interfaces of a tunnel or PPP type. What a route sends into one goes to
    /// the other end, which takes it on as a router does, so it is not the local network. Not
    /// `IF_TYPE_PROP_VIRTUAL`, which virtual adapters with real neighbours declare too.
    point_to_point: Vec<u64>,
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
/// prefix length, and the tunnel and PPP interfaces. `GetAdaptersAddresses` returns them for
/// both address families.
fn adapters() -> io::Result<Adapters> {
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
        return Ok(collect_adapters(adapters));
    }
    Err(io::Error::other(
        "the list of network adapters kept growing",
    ))
}

/// Walks the adapter list and its unicast address lists into plain addresses.
fn collect_adapters(first: *const IP_ADAPTER_ADDRESSES_LH) -> Adapters {
    let mut addresses = Vec::new();
    let mut point_to_point = Vec::new();
    let mut adapter = first;
    while !adapter.is_null() {
        // SAFETY: the list is NUL-terminated by a null `Next`, and the call filled it.
        let current = unsafe { &*adapter };
        if matches!(current.IfType, IF_TYPE_TUNNEL | IF_TYPE_PPP) {
            // SAFETY: a LUID is a 64-bit value in either view of its union.
            point_to_point.push(unsafe { current.Luid.Value });
        }
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
    Adapters {
        addresses,
        point_to_point,
    }
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

    fn route(destination: &str, prefix: u8, next_hop: &str) -> MIB_IPFORWARD_ROW2 {
        let mut route = MIB_IPFORWARD_ROW2::default();
        route.InterfaceLuid.Value = ETHERNET;
        route.DestinationPrefix.Prefix = inet(destination.parse().unwrap());
        route.DestinationPrefix.PrefixLength = prefix;
        route.NextHop = inet(next_hop.parse().unwrap());
        route
    }

    /// Interface LUIDs of the crafted routes.
    const ETHERNET: u64 = 6;
    const TUNNEL: u64 = 7;

    #[test]
    fn on_link_routes_name_their_network() {
        let subnets = on_link(
            &[
                // The subnet of an interface, and the on-link prefix of router advertisements
                // beside a DHCPv6 address.
                route("192.168.122.0", 24, "0.0.0.0"),
                route("2a01:4f8:5::", 64, "::"),
                // A route into a link where this machine has no address of its prefix.
                route("203.0.113.0", 24, "0.0.0.0"),
                // Through a router.
                route("10.1.0.0", 16, "192.168.122.1"),
                route("2a01:4f8:7::", 48, "fe80::1"),
                route("198.51.100.0", 24, "fe80::1"),
                // The default route, also one into a tunnel without a router.
                route("0.0.0.0", 0, "192.168.122.1"),
                route("0.0.0.0", 0, "0.0.0.0"),
                route("::", 0, "::"),
            ],
            &[],
        );
        let reached = |ip: &str| {
            subnets
                .iter()
                .any(|subnet| subnet.contains(ip.parse().unwrap()))
        };
        for ip in ["192.168.122.77", "2a01:4f8:5::99", "203.0.113.5"] {
            assert!(reached(ip), "{ip} in {subnets:?}");
        }
        for ip in [
            "10.1.0.5",
            "2a01:4f8:7::5",
            "198.51.100.5",
            "1.1.1.1",
            "2606:4700::1111",
        ] {
            assert!(!reached(ip), "{ip} in {subnets:?}");
        }
        // A route of no address family names nothing.
        assert!(on_link(&[MIB_IPFORWARD_ROW2::default()], &[]).is_empty());
    }

    /// What a route sends into a tunnel or PPP interface goes to the other end, so it names no
    /// network, also when it covers half of IPv4 as a full tunnel's routes can.
    #[test]
    fn routes_into_a_tunnel_name_no_network() {
        let mut half = route("0.0.0.0", 1, "0.0.0.0");
        half.InterfaceLuid.Value = TUNNEL;
        let routes = [half, route("192.168.122.0", 24, "0.0.0.0")];
        assert_eq!(on_link(&routes, &[]).len(), 2);
        let subnets = on_link(&routes, &[TUNNEL]);
        let reached = |ip: &str| {
            subnets
                .iter()
                .any(|subnet| subnet.contains(ip.parse().unwrap()))
        };
        assert!(
            reached("192.168.122.7") && !reached("1.1.1.1"),
            "{subnets:?}"
        );
    }

    /// An interface whose access type is point-to-point is a tunnel whatever type it declares;
    /// a broadcast one is not.
    #[test]
    fn a_point_to_point_access_type_is_a_tunnel() {
        use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_BROADCAST;
        let interface = |luid, access| {
            let mut row = MIB_IF_ROW2::default();
            row.InterfaceLuid.Value = luid;
            row.AccessType = access;
            row
        };
        let interfaces = [
            interface(ETHERNET, NET_IF_ACCESS_BROADCAST),
            interface(TUNNEL, NET_IF_ACCESS_POINT_TO_POINT),
        ];
        assert_eq!(point_to_point_of(&interfaces), [TUNNEL]);
        assert!(point_to_point_access().is_ok());
    }

    /// The routing table of this machine reaches the gateway of its way out without a router,
    /// and the broker's subnets hold every on-link route.
    #[test]
    fn the_routing_table_reaches_the_gateway_on_link() {
        let mut point_to_point = adapters().unwrap().point_to_point;
        point_to_point.extend(point_to_point_access().unwrap());
        let routes = on_link_routes(&point_to_point).unwrap();
        let subnets = WindowsHost.subnets().unwrap();
        for route in &routes {
            assert!(subnets.contains(route), "{route:?} in {subnets:?}");
        }
        let on_link = |ip: IpAddr| routes.iter().any(|subnet| subnet.contains(ip));
        assert!(on_link(Ipv4Addr::LOCALHOST.into()), "{routes:?}");
        let Some(out) = best_route("1.1.1.1".parse().unwrap()).unwrap() else {
            eprintln!("skipped: no IPv4 route out");
            return;
        };
        // SAFETY: a SOCKADDR_INET of the call, whose family says which address it holds.
        let gateway = unsafe { sockaddr_ip((&raw const out.NextHop).cast()) }.unwrap();
        assert!(!gateway.is_unspecified(), "the way out has no gateway");
        assert!(on_link(gateway), "{gateway} in {routes:?}");
        assert!(!on_link("1.1.1.1".parse().unwrap()), "{routes:?}");
    }
}
