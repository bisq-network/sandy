//! What only the host can tell the egress broker about a destination: whether an address is one
//! of this machine's own, and which networks it reaches without a router: the subnets of its
//! interfaces and the networks of its on-link routes (`sandy_core::destination`).
//!
//! The broker runs in its own AppContainer with the internetClient capability. It asks these
//! questions for every connection, so a destination that is this machine never leaves through
//! the broker even when the program picked it. The addresses, the point-to-point links and the
//! on-link networks are kept until Windows reports a change of an address, an IP interface or a
//! route (`NotifyUnicastIpAddressChange`, `NotifyIpInterfaceChange`, `NotifyRouteChange2`); the
//! best route of a destination is asked for every connection. The AppContainer's own loopback isolation stops
//! it from reaching this machine at the kernel level as well (docs/windows.md, "Egress broker").

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sandy_core::destination::{HostNetwork, Subnet};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NETWORK_UNREACHABLE, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetBestRoute2,
    GetIfTable2, GetIpForwardTable2, IF_TYPE_PPP, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::{NET_IF_ACCESS_POINT_TO_POINT, NdisMediumIP};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// The Windows answer to `sandy_core::destination::HostNetwork`. Without a watch (`default`) it
/// reads everything again for every question; with one (`watching`) it keeps what it read until
/// Windows reports a change.
#[derive(Default)]
pub struct WindowsHost {
    watch: Option<Watch>,
    held: Mutex<Held>,
}

#[derive(Default)]
struct Held {
    adapters: Option<Arc<Adapters>>,
    on_link: Option<Arc<Vec<Subnet>>>,
}

/// The change notifications and the flag their callbacks set.
struct Watch {
    changed: Arc<AtomicBool>,
    handles: Vec<HANDLE>,
}

// SAFETY: the handles are only passed to CancelMibChangeNotify2, which any thread may call, and
// the flag is atomic.
unsafe impl Send for Watch {}
// SAFETY: as above; nothing reads through the handles.
unsafe impl Sync for Watch {}

impl Drop for Watch {
    fn drop(&mut self) {
        for handle in &self.handles {
            // SAFETY: the handle came from a Notify* call and is cancelled once; the call waits
            // for a callback in progress, so the flag outlives every callback.
            if unsafe { CancelMibChangeNotify2(*handle) } != NO_ERROR {
                // The registration may still call back: the flag then lives on.
                std::mem::forget(Arc::clone(&self.changed));
            }
        }
    }
}

/// Sets the flag at `context` for a change notification of any kind.
unsafe extern "system" fn note_change<Row>(
    context: *const core::ffi::c_void,
    _row: *const Row,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: the context is the flag of a `Watch`, which outlives its registrations.
    unsafe { &*context.cast::<AtomicBool>() }.store(true, Ordering::SeqCst);
}

impl std::fmt::Debug for WindowsHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsHost")
            .field("watching", &self.watch.is_some())
            .finish_non_exhaustive()
    }
}

impl WindowsHost {
    /// Registers for the changes of addresses, IP interfaces and routes of both families. The
    /// broker calls this before it serves; where a registration fails it uses `default`, which
    /// reads everything for every question, as before.
    pub fn watching() -> io::Result<WindowsHost> {
        let changed = Arc::new(AtomicBool::new(false));
        let context = Arc::as_ptr(&changed).cast::<core::ffi::c_void>();
        let mut watch = Watch {
            changed: Arc::clone(&changed),
            handles: Vec::new(),
        };
        let registrations: [&dyn Fn(&mut HANDLE) -> u32; 3] = [
            // SAFETY: the callback matches the row type, the context outlives the registration
            // (`Watch::drop`), and the handle pointer is valid.
            &|handle| unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(note_change::<MIB_UNICASTIPADDRESS_ROW>),
                    context,
                    false,
                    handle,
                )
            },
            // SAFETY: as above.
            &|handle| unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(note_change::<MIB_IPINTERFACE_ROW>),
                    context,
                    false,
                    handle,
                )
            },
            // SAFETY: as above.
            &|handle| unsafe {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(note_change::<MIB_IPFORWARD_ROW2>),
                    context,
                    false,
                    handle,
                )
            },
        ];
        for register in registrations {
            let mut handle: HANDLE = std::ptr::null_mut();
            let error = register(&mut handle);
            if error != NO_ERROR {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            watch.handles.push(handle);
        }
        Ok(WindowsHost {
            watch: Some(watch),
            held: Mutex::default(),
        })
    }

    /// What is kept, after it dropped it if Windows reported a change since the last call.
    fn held(&self) -> MutexGuard<'_, Held> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = match &self.watch {
            Some(watch) => watch.changed.swap(false, Ordering::SeqCst),
            None => true,
        };
        if changed {
            *held = Held::default();
        }
        held
    }
}

impl Held {
    fn adapters(&mut self) -> io::Result<Arc<Adapters>> {
        if let Some(adapters) = &self.adapters {
            return Ok(Arc::clone(adapters));
        }
        let adapters = Arc::new(adapters()?);
        self.adapters = Some(Arc::clone(&adapters));
        Ok(adapters)
    }
}

impl HostNetwork for WindowsHost {
    fn is_host(&self, destination: SocketAddr) -> io::Result<bool> {
        let ip = destination.ip();
        let adapters = self.held().adapters()?;
        let addresses = &adapters.addresses;
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
        let mut held = self.held();
        let adapters = held.adapters()?;
        let mut subnets: Vec<Subnet> = adapters
            .addresses
            .iter()
            .filter_map(|address| Subnet::new(address.ip, address.prefix))
            .collect();
        let on_link = match &held.on_link {
            Some(on_link) => Arc::clone(on_link),
            None => {
                let mut point_to_point = adapters.point_to_point.clone();
                point_to_point.extend(point_to_point_links()?);
                let on_link = Arc::new(on_link_routes(&point_to_point)?);
                held.on_link = Some(Arc::clone(&on_link));
                on_link
            }
        };
        subnets.extend(on_link.iter().copied());
        Ok(subnets)
    }
}

/// The LUIDs of the interfaces whose link has one other end whatever type they declare
/// (`GetIfTable2`, `point_to_point_of`).
fn point_to_point_links() -> io::Result<Vec<u64>> {
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

/// The LUIDs of the `interfaces` whose access type is point-to-point, or whose medium is IP
/// itself (`NdisMediumIP`). A link without a link layer has no neighbours to address: the
/// adapter hands every packet to one other end. Wintun, the adapter of WireGuard and of the
/// TUN mode of many proxies, declares `IF_TYPE_PROP_VIRTUAL` with broadcast access and only
/// its medium tells.
fn point_to_point_of(interfaces: &[MIB_IF_ROW2]) -> Vec<u64> {
    interfaces
        .iter()
        .filter(|interface| {
            interface.AccessType == NET_IF_ACCESS_POINT_TO_POINT
                || interface.MediaType == NdisMediumIP
        })
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
        assert!(point_to_point_links().is_ok());
    }

    /// Wintun declares a virtual type with broadcast access, but its medium is IP. A VPN or proxy
    /// in TUN mode that splits the default route into it leaves the internet public, and the
    /// prefix of its own address stays the local network.
    #[test]
    fn an_ip_medium_is_a_tunnel() {
        use windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_PROP_VIRTUAL;
        use windows_sys::Win32::NetworkManagement::Ndis::{
            NET_IF_ACCESS_BROADCAST, NdisMedium802_3,
        };
        let interface = |luid, medium| {
            let mut row = MIB_IF_ROW2::default();
            row.InterfaceLuid.Value = luid;
            row.Type = IF_TYPE_PROP_VIRTUAL;
            row.AccessType = NET_IF_ACCESS_BROADCAST;
            row.MediaType = medium;
            row
        };
        let interfaces = [
            interface(ETHERNET, NdisMedium802_3),
            interface(TUNNEL, NdisMediumIP),
        ];
        let tunnels = point_to_point_of(&interfaces);
        assert_eq!(tunnels, [TUNNEL]);
        let into_tunnel = |destination, prefix| {
            let mut route = route(destination, prefix, "0.0.0.0");
            route.InterfaceLuid.Value = TUNNEL;
            route
        };
        let routes = [
            into_tunnel("0.0.0.0", 1),
            into_tunnel("128.0.0.0", 1),
            route("192.168.122.0", 24, "0.0.0.0"),
        ];
        let mut subnets = on_link(&routes, &tunnels);
        subnets.extend(Subnet::new("198.18.0.1".parse().unwrap(), 16));
        let reached = |ip: &str| {
            subnets
                .iter()
                .any(|subnet| subnet.contains(ip.parse().unwrap()))
        };
        for ip in ["1.1.1.1", "94.237.8.19", "185.220.101.105"] {
            assert!(!reached(ip), "{ip} in {subnets:?}");
        }
        assert!(
            reached("192.168.122.7") && reached("198.18.4.4"),
            "{subnets:?}"
        );
    }

    /// The routing table of this machine reaches the gateway of its way out without a router,
    /// and the broker's subnets hold every on-link route.
    #[test]
    fn the_routing_table_reaches_the_gateway_on_link() {
        let mut point_to_point = adapters().unwrap().point_to_point;
        point_to_point.extend(point_to_point_links().unwrap());
        let routes = on_link_routes(&point_to_point).unwrap();
        let subnets = WindowsHost::default().subnets().unwrap();
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

    /// With a watch, what was read is kept, and a change of the routing table drops it: an
    /// active route added on the loopback interface stands in for a change of the network.
    /// Adding a route needs administrator rights; without them the test skips.
    #[test]
    fn a_route_change_drops_what_is_kept() {
        let host = WindowsHost::watching().unwrap();
        let route = |verb: &str| {
            std::process::Command::new("netsh")
                .args(["interface", "ipv4", verb, "route", "198.51.100.0/24"])
                .arg("interface=Loopback Pseudo-Interface 1")
                .arg("store=active")
                .output()
                .unwrap()
        };
        // Control: a quiet network keeps what was read; a change elsewhere can drop it in
        // between, so the read is tried a few times.
        let kept = (0..5).any(|_| {
            host.subnets().unwrap();
            host.held().adapters.is_some()
        });
        assert!(kept, "nothing is kept");
        let added = route("add");
        if !added.status.success() {
            eprintln!("skipped: cannot add a route: {added:?}");
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut dropped = false;
        while !dropped && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            dropped = host.held().adapters.is_none();
        }
        let removed = route("delete");
        assert!(removed.status.success(), "{removed:?}");
        assert!(dropped, "the route change kept the old view");
    }
}
