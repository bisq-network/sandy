//! Where the egress broker may connect (docs/DESIGN.md, "Private network and egress", rule 6).
//!
//! The check has a static part, `check_ip`, which needs nothing but the address, and a part only
//! the host can answer, `HostNetwork`, which each backend implements. `check` combines both, so
//! every platform decides the same way.
//!
//! The static part follows the IANA special-purpose address registries. Copies of both are in
//! `data/`, a test pins the tables below to them, and a scheduled workflow
//! (`.github/workflows/iana.yml`) fails when IANA changes them. IPv4 is a denylist: every address
//! is public except the registry's blocks. IPv6 is an allowlist: only global unicast space,
//! `2000::/3`, can be public, minus the registry's blocks inside it, so a block that IANA adds
//! elsewhere is refused before anyone updates the tables.
//!
//! An IPv4-mapped IPv6 address is judged as the IPv4 address it maps, because a dual-stack socket
//! connects to exactly that address. The other forms that embed an IPv4 address (IPv4-compatible,
//! NAT64, 6to4 and Teredo) are refused as whole prefixes: whether a translator or a tunnel takes
//! them to the embedded address depends on the host and its network, which the broker cannot see.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::policy::EgressReach;

/// How a special-purpose block counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Never a destination, whatever `reach` says and whatever subnets the host has: the host
    /// itself, its link, groups of hosts, and the forms that embed an IPv4 address.
    Never,
    /// The local network, which `reach = "public-and-local"` allows.
    Local,
    /// Not globally reachable. With `public-and-local` a subnet of the host's interfaces in such
    /// a block is the local network too.
    Special,
}

use Kind::{Local, Never, Special};

/// The IPv4 blocks of the registry, and the ones every check refuses first. The first match
/// counts, so `Never` comes first.
const IPV4: &[(Ipv4Addr, u8, Kind, &str)] = &[
    (
        Ipv4Addr::new(0, 0, 0, 0),
        8,
        Never,
        "\"this network\" (0.0.0.0/8), which reaches the host itself",
    ),
    (
        Ipv4Addr::new(127, 0, 0, 0),
        8,
        Never,
        "loopback (127.0.0.0/8)",
    ),
    (
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        Never,
        "link-local (169.254.0.0/16)",
    ),
    (
        Ipv4Addr::new(224, 0, 0, 0),
        4,
        Never,
        "multicast (224.0.0.0/4)",
    ),
    (
        Ipv4Addr::new(255, 255, 255, 255),
        32,
        Never,
        "limited broadcast (255.255.255.255)",
    ),
    (
        Ipv4Addr::new(10, 0, 0, 0),
        8,
        Local,
        "private use (10.0.0.0/8)",
    ),
    (
        Ipv4Addr::new(100, 64, 0, 0),
        10,
        Local,
        "shared address space (100.64.0.0/10)",
    ),
    (
        Ipv4Addr::new(172, 16, 0, 0),
        12,
        Local,
        "private use (172.16.0.0/12)",
    ),
    (
        Ipv4Addr::new(192, 168, 0, 0),
        16,
        Local,
        "private use (192.168.0.0/16)",
    ),
    // Refused as a whole, with the two anycast addresses in it that no program needs.
    (
        Ipv4Addr::new(192, 0, 0, 0),
        24,
        Special,
        "IETF protocol assignments (192.0.0.0/24)",
    ),
    (
        Ipv4Addr::new(192, 0, 2, 0),
        24,
        Special,
        "documentation (192.0.2.0/24)",
    ),
    (
        Ipv4Addr::new(192, 88, 99, 0),
        24,
        Special,
        "deprecated 6to4 relay anycast (192.88.99.0/24)",
    ),
    (
        Ipv4Addr::new(198, 18, 0, 0),
        15,
        Special,
        "benchmarking (198.18.0.0/15)",
    ),
    (
        Ipv4Addr::new(198, 51, 100, 0),
        24,
        Special,
        "documentation (198.51.100.0/24)",
    ),
    (
        Ipv4Addr::new(203, 0, 113, 0),
        24,
        Special,
        "documentation (203.0.113.0/24)",
    ),
    (
        Ipv4Addr::new(240, 0, 0, 0),
        4,
        Special,
        "reserved (240.0.0.0/4)",
    ),
];

/// The IPv6 blocks that need a name of their own. Every address outside `GLOBAL_UNICAST` that
/// none of them names is `Special`.
const IPV6: &[(Ipv6Addr, u8, Kind, &str)] = &[
    (Ipv6Addr::UNSPECIFIED, 128, Never, "unspecified (::)"),
    (Ipv6Addr::LOCALHOST, 128, Never, "loopback (::1)"),
    (
        Ipv6Addr::UNSPECIFIED,
        96,
        Never,
        "IPv4-compatible (::/96), which embeds an IPv4 address",
    ),
    (
        Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        96,
        Never,
        "NAT64 (64:ff9b::/96), which embeds an IPv4 address",
    ),
    (
        Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
        48,
        Never,
        "local-use NAT64 (64:ff9b:1::/48), which embeds an IPv4 address",
    ),
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        32,
        Never,
        "Teredo (2001::/32), which embeds an IPv4 address",
    ),
    (
        Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
        16,
        Never,
        "6to4 (2002::/16), which embeds an IPv4 address",
    ),
    (
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
        Never,
        "link-local (fe80::/10)",
    ),
    (
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        8,
        Never,
        "multicast (ff00::/8)",
    ),
    (
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        7,
        Local,
        "unique local (fc00::/7)",
    ),
    // Refused as a whole, with the anycast, overlay and AS112 blocks in it that no program needs.
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        23,
        Special,
        "IETF protocol assignments (2001::/23)",
    ),
    (
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        32,
        Special,
        "documentation (2001:db8::/32)",
    ),
    (
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        20,
        Special,
        "documentation (3fff::/20)",
    ),
];

const GLOBAL_UNICAST: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);
const NOT_GLOBAL_UNICAST: &str = "not global unicast (outside 2000::/3)";

/// Why the broker does not connect to a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Port 0, which no server listens on.
    PortZero,
    /// A special-purpose block that `reach` does not allow, or that nothing allows; the text
    /// names it.
    Block(&'static str),
    /// An address of this host (`HostNetwork::is_host`).
    Host,
    /// An address on a subnet of the host's interfaces, which is the local network that
    /// `reach = "public"` excludes.
    HostSubnet,
    /// The host could not tell whether the address is its own, so it counts as its own.
    HostUnknown,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::PortZero => write!(f, "port 0"),
            Refusal::Block(name) => write!(f, "{name}"),
            Refusal::Host => write!(f, "an address of this host"),
            Refusal::HostSubnet => write!(
                f,
                "on a subnet of this host's interfaces, which is the local network"
            ),
            Refusal::HostUnknown => {
                write!(f, "this host could not tell whether the address is its own")
            }
        }
    }
}

/// A subnet of one of the host's interfaces: an address and the length of its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    address: IpAddr,
    prefix: u8,
}

impl Subnet {
    /// `None` when `prefix` is longer than the address.
    pub fn new(address: IpAddr, prefix: u8) -> Option<Subnet> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        (prefix <= bits).then_some(Subnet { address, prefix })
    }

    /// Whether `ip` is on this subnet. An address of the other family never is.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => v4_contains(network, self.prefix, ip),
            (IpAddr::V6(network), IpAddr::V6(ip)) => v6_contains(network, self.prefix, ip),
            _ => false,
        }
    }
}

/// What only the host can tell about a destination. Every backend that runs the egress broker
/// implements it, and `check` asks it for every connection, because the host's addresses can
/// change while the program runs.
///
/// `check` passes canonical addresses only, never IPv4-mapped ones, and never one that no reach
/// allows (loopback, multicast and the like); an implementation still answers for every
/// address. An error means that the host cannot tell, and the destination is refused. The broker
/// calls both methods from many connection threads at once, after it has confined itself, so
/// whatever they need from the system (a socket, a handle) is opened before that. Its threads
/// have small stacks (`sandy_relay::broker`), so large buffers belong on the heap.
pub trait HostNetwork {
    /// Whether `ip` is this host itself, which the broker never connects to. True for:
    /// - every address of every interface, also of one that is down, but not the peer address of
    ///   a point-to-point link;
    /// - the broadcast address of every IPv4 subnet of an interface;
    /// - every other address the host delivers to itself: what its routing table holds as a
    ///   local, broadcast, anycast or multicast route, also when no interface shows it (on Linux,
    ///   `ip route add local ...`).
    fn is_host(&self, ip: IpAddr) -> io::Result<bool>;

    /// The subnets of the host's interfaces: for each interface address, the subnet the host
    /// reaches without a router (the address and its prefix length, and for a point-to-point
    /// link the peer's address and prefix). They are the local network, which
    /// `reach = "public"` refuses and `"public-and-local"` allows.
    fn subnets(&self) -> io::Result<Vec<Subnet>>;
}

/// The static part of the check: whether `reach` allows `ip`, judged by the address alone,
/// without the host's own addresses and subnets that `check` adds.
pub fn check_ip(ip: IpAddr, reach: EgressReach) -> Result<(), Refusal> {
    match special(ip.to_canonical()) {
        None => Ok(()),
        Some((Local, _)) if reach == EgressReach::PublicAndLocal => Ok(()),
        Some((_, name)) => Err(Refusal::Block(name)),
    }
}

/// The whole check of a destination that the program asked the broker for: the static part,
/// then the host's own addresses and subnets. Returns the address to connect to, which is the
/// address that was checked: `destination` with an IPv4-mapped address written as the IPv4
/// address it maps.
pub fn check(
    destination: SocketAddr,
    reach: EgressReach,
    host: &dyn HostNetwork,
) -> Result<SocketAddr, Refusal> {
    let ip = destination.ip().to_canonical();
    if destination.port() == 0 {
        return Err(Refusal::PortZero);
    }
    // With `public-and-local` a block that is not globally reachable can still be the local
    // network, when the host has a subnet in it; it waits for the host's answer.
    let block = match (special(ip), reach) {
        (None, _) | (Some((Local, _)), EgressReach::PublicAndLocal) => None,
        (Some((Special, name)), EgressReach::PublicAndLocal) => Some(name),
        (Some((_, name)), _) => return Err(Refusal::Block(name)),
    };
    let unknown = |_| Refusal::HostUnknown;
    if host.is_host(ip).map_err(unknown)? {
        return Err(Refusal::Host);
    }
    let on_subnet = || {
        host.subnets()
            .map(|subnets| subnets.iter().any(|subnet| subnet.contains(ip)))
            .map_err(unknown)
    };
    let allowed = match (block, reach) {
        (None, EgressReach::Public) if on_subnet()? => Err(Refusal::HostSubnet),
        (None, _) => Ok(()),
        (Some(_), _) if on_subnet()? => Ok(()),
        (Some(name), _) => Err(Refusal::Block(name)),
    };
    allowed.map(|()| SocketAddr::new(ip, destination.port()))
}

/// The special-purpose block that the canonical address `ip` is in, if any.
fn special(ip: IpAddr) -> Option<(Kind, &'static str)> {
    match ip {
        IpAddr::V4(ip) => IPV4
            .iter()
            .find(|&&(network, prefix, ..)| v4_contains(network, prefix, ip))
            .map(|&(_, _, kind, name)| (kind, name)),
        IpAddr::V6(ip) => IPV6
            .iter()
            .find(|&&(network, prefix, ..)| v6_contains(network, prefix, ip))
            .map(|&(_, _, kind, name)| (kind, name))
            .or_else(|| {
                let (network, prefix) = GLOBAL_UNICAST;
                (!v6_contains(network, prefix, ip)).then_some((Special, NOT_GLOBAL_UNICAST))
            }),
    }
}

fn v4_contains(network: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    (network.to_bits() ^ ip.to_bits()) & mask == 0
}

fn v6_contains(network: Ipv6Addr, prefix: u8, ip: Ipv6Addr) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    (network.to_bits() ^ ip.to_bits()) & mask == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use EgressReach::{Public, PublicAndLocal};

    const IPV4_REGISTRY: &str = include_str!("../data/iana-ipv4-special-registry-1.csv");
    const IPV6_REGISTRY: &str = include_str!("../data/iana-ipv6-special-registry-1.csv");

    /// Registry entries that are not globally reachable but that `public` allows on purpose,
    /// with the reason.
    const ALLOWED_ON_PURPOSE: &[(&str, &str)] = &[(
        "::ffff:0:0/96",
        "an IPv4-mapped address is judged as the IPv4 address it maps",
    )];

    /// Blocks that `public` refuses as a whole although the registry marks entries in them
    /// globally reachable, with the reason.
    const REFUSED_ON_PURPOSE: &[(&str, &str)] = &[
        (
            "192.0.0.0/24",
            "the anycast addresses there serve no program, and the rest of the block is not \
             globally reachable",
        ),
        (
            "2001::/23",
            "the anycast, overlay and AS112 blocks there serve no program, and the rest of the \
             block is not globally reachable",
        ),
        (
            "64:ff9b::/96",
            "a NAT64 address embeds an IPv4 address, which a translator may connect to",
        ),
    ];

    /// One block of a registry entry, and whether the registry marks it globally reachable.
    #[derive(Debug)]
    struct Entry {
        block: String,
        network: IpAddr,
        prefix: u8,
        globally_reachable: bool,
    }

    /// The blocks of a registry CSV file. A row can name several blocks, and both the blocks and
    /// the values carry footnote marks such as " [1]".
    fn entries(csv: &str) -> Vec<Entry> {
        let mut lines = csv.lines();
        let header = fields(lines.next().unwrap());
        assert_eq!(header[0], "Address Block");
        assert_eq!(header[8], "Globally Reachable");
        let mut entries = Vec::new();
        for line in lines.filter(|line| !line.trim().is_empty()) {
            let row = fields(line);
            assert_eq!(row.len(), header.len(), "{line}");
            let reachable = without_footnote(&row[8]);
            assert!(
                ["True", "False", "N/A", ""].contains(&reachable),
                "{line}: {reachable}"
            );
            for block in row[0].split(',') {
                let block = without_footnote(block);
                let (network, prefix) = block.split_once('/').unwrap();
                entries.push(Entry {
                    block: block.to_string(),
                    network: network.parse().unwrap(),
                    prefix: prefix.parse().unwrap(),
                    globally_reachable: reachable == "True",
                });
            }
        }
        entries
    }

    fn without_footnote(text: &str) -> &str {
        let text = text.trim();
        text.split_once(" [").map_or(text, |(value, _)| value)
    }

    /// The fields of one CSV line, with quoted fields and doubled quotes.
    fn fields(line: &str) -> Vec<String> {
        let mut fields = vec![String::new()];
        let mut quoted = false;
        let mut chars = line.trim_end_matches('\r').chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                    fields.last_mut().unwrap().push('"');
                }
                '"' => quoted = !quoted,
                ',' if !quoted => fields.push(String::new()),
                c => fields.last_mut().unwrap().push(c),
            }
        }
        assert!(!quoted, "{line}");
        fields
    }

    fn registry() -> Vec<Entry> {
        let mut all = entries(IPV4_REGISTRY);
        let v4 = all.len();
        all.extend(entries(IPV6_REGISTRY));
        // As downloaded on 2026-10-25; a parser that loses rows would pass everything.
        assert_eq!((v4, all.len() - v4), (26, 25));
        all
    }

    fn block(text: &str) -> (IpAddr, u8) {
        let (network, prefix) = text.split_once('/').unwrap();
        (network.parse().unwrap(), prefix.parse().unwrap())
    }

    /// The first, a middle and the last address of a block.
    fn samples(network: IpAddr, prefix: u8) -> [IpAddr; 3] {
        let (bits, value) = match network {
            IpAddr::V4(ip) => (32, u128::from(ip.to_bits())),
            IpAddr::V6(ip) => (128, ip.to_bits()),
        };
        let size = 1u128.checked_shl(bits - u32::from(prefix)).unwrap_or(0);
        let host_bits = size.wrapping_sub(1);
        let first = value & !host_bits;
        let at = |value: u128| match network {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from_bits(value as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from_bits(value)),
        };
        [at(first), at(first | (size / 2)), at(first | host_bits)]
    }

    fn inside(entry: &Entry, outer: &str) -> bool {
        let (network, prefix) = block(outer);
        entry.prefix >= prefix
            && Subnet::new(network, prefix)
                .unwrap()
                .contains(entry.network)
    }

    #[test]
    fn public_refuses_every_block_the_registry_marks_not_globally_reachable() {
        for entry in registry().iter().filter(|entry| !entry.globally_reachable) {
            if let Some((_, why)) = ALLOWED_ON_PURPOSE
                .iter()
                .find(|(block, _)| *block == entry.block)
            {
                eprintln!("allowed on purpose: {}: {why}", entry.block);
                continue;
            }
            for ip in samples(entry.network, entry.prefix) {
                assert!(
                    check_ip(ip, Public).is_err(),
                    "{ip} of {} passed",
                    entry.block
                );
            }
        }
    }

    #[test]
    fn public_allows_every_block_the_registry_marks_globally_reachable() {
        for entry in registry().iter().filter(|entry| entry.globally_reachable) {
            let refused = REFUSED_ON_PURPOSE
                .iter()
                .find(|(outer, _)| inside(entry, outer));
            for ip in samples(entry.network, entry.prefix) {
                match refused {
                    Some((outer, why)) => assert!(
                        check_ip(ip, Public).is_err(),
                        "{ip} of {} passed, but {outer} is refused: {why}",
                        entry.block
                    ),
                    None => assert_eq!(check_ip(ip, Public), Ok(()), "{ip} of {}", entry.block),
                }
            }
        }
    }

    /// The blocks that `public-and-local` adds (docs/DESIGN.md, "Private network and egress",
    /// rule 6).
    const LOCAL: [&str; 5] = [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ];

    /// `public-and-local` allows exactly the local blocks more, and still refuses the forms
    /// that embed an IPv4 address.
    #[test]
    fn public_and_local_adds_only_the_local_blocks() {
        for entry in registry() {
            if ALLOWED_ON_PURPOSE
                .iter()
                .any(|(block, _)| *block == entry.block)
            {
                continue;
            }
            for ip in samples(entry.network, entry.prefix) {
                assert_eq!(
                    check_ip(ip, PublicAndLocal).is_ok(),
                    check_ip(ip, Public).is_ok() || LOCAL.contains(&entry.block.as_str()),
                    "{ip} of {}",
                    entry.block
                );
            }
        }
        for ip in [
            "10.1.2.3",
            "100.100.1.1",
            "172.31.255.254",
            "192.168.8.21",
            "fd42::1",
        ] {
            assert_eq!(
                check_ip(ip.parse().unwrap(), PublicAndLocal),
                Ok(()),
                "{ip}"
            );
        }
    }

    #[test]
    fn a_mapped_address_is_judged_as_the_address_it_maps() {
        for entry in entries(IPV4_REGISTRY) {
            for ip in samples(entry.network, entry.prefix) {
                let IpAddr::V4(v4) = ip else { unreachable!() };
                let mapped = IpAddr::V6(v4.to_ipv6_mapped());
                for reach in [Public, PublicAndLocal] {
                    assert_eq!(check_ip(mapped, reach), check_ip(ip, reach), "{mapped}");
                }
            }
        }
        assert_eq!(
            check_ip("::ffff:127.0.0.1".parse().unwrap(), Public),
            Err(Refusal::Block("loopback (127.0.0.0/8)"))
        );
        assert_eq!(check_ip("::ffff:1.1.1.1".parse().unwrap(), Public), Ok(()));
    }

    #[test]
    fn public_addresses_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "192.31.196.1",
            "223.255.255.255",
            "2a00:1450:4001::1",
            "2606:4700::1111",
            "2620:4f:8000::1",
            "3fff:1000::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(check_ip(ip, Public), Ok(()), "{ip}");
            assert_eq!(check_ip(ip, PublicAndLocal), Ok(()), "{ip}");
        }
    }

    /// Never allowed, whatever `reach` says, the embedded forms included.
    #[test]
    fn the_host_its_link_groups_and_embedded_forms_are_never_allowed() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::1.1.1.1",
            "64:ff9b::7f00:1",
            "64:ff9b::101:101",
            "64:ff9b:1::7f00:1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2002:7f00:1::1",
            "2002:101:101::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "ff0e::1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.1.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            for reach in [Public, PublicAndLocal] {
                assert!(
                    matches!(check_ip(ip, reach), Err(Refusal::Block(_))),
                    "{ip} {reach:?}"
                );
            }
        }
    }

    #[test]
    fn ipv6_outside_global_unicast_is_refused() {
        for ip in [
            "100::1",
            "100:0:0:1::1",
            "5f00::1",
            "fec0::1",
            "4000::1",
            "e000::1",
        ] {
            assert_eq!(
                check_ip(ip.parse().unwrap(), Public),
                Err(Refusal::Block(NOT_GLOBAL_UNICAST)),
                "{ip}"
            );
        }
    }

    /// Whether `text`, a block such as "10.0.0.0/8" or a single address, holds `ip`.
    fn holds(text: &str, ip: IpAddr) -> bool {
        let (network, prefix) = match text.split_once('/') {
            Some(_) => block(text),
            None => {
                let ip: IpAddr = text.parse().unwrap();
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        Subnet::new(network, prefix).unwrap().contains(ip)
    }

    /// What docs/DESIGN.md says `reach` allows, built from the registry copies and the
    /// decisions it names ("Egress broker", rule 2), without the tables above: no registry
    /// block that is not globally reachable, apart from `ALLOWED_ON_PURPOSE`, none of
    /// `REFUSED_ON_PURPOSE`, no IPv4 multicast (outside the registry), IPv6 only in global
    /// unicast space, and with `public-and-local` also the local blocks.
    struct Documented {
        refused: Vec<Subnet>,
        local: Vec<Subnet>,
        global_unicast: Subnet,
    }

    impl Documented {
        fn new(registry: &[Entry]) -> Documented {
            let parse = |text: &str| {
                let (network, prefix) = block(text);
                Subnet::new(network, prefix).unwrap()
            };
            let not_reachable = registry.iter().filter(|entry| {
                !entry.globally_reachable
                    && !ALLOWED_ON_PURPOSE
                        .iter()
                        .any(|(block, _)| *block == entry.block)
            });
            Documented {
                refused: not_reachable
                    .map(|entry| Subnet::new(entry.network, entry.prefix).unwrap())
                    .chain(REFUSED_ON_PURPOSE.iter().map(|(outer, _)| parse(outer)))
                    .chain([parse("224.0.0.0/4")])
                    .collect(),
                local: LOCAL.iter().map(|local| parse(local)).collect(),
                global_unicast: parse("2000::/3"),
            }
        }

        fn allows(&self, ip: IpAddr, reach: EgressReach) -> bool {
            let ip = ip.to_canonical();
            let public = !self.refused.iter().any(|block| block.contains(ip))
                && (ip.is_ipv4() || self.global_unicast.contains(ip));
            public || (reach == PublicAndLocal && self.local.iter().any(|block| block.contains(ip)))
        }
    }

    /// A deterministic source of numbers (xorshift64*), so that a failure always reproduces.
    struct Numbers(u64);

    impl Numbers {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn wide(&mut self) -> u128 {
            (u128::from(self.next()) << 64) | u128::from(self.next())
        }
    }

    /// The addresses at both edges of a block, inside and just outside it, and `count` random
    /// ones inside it.
    fn around(network: IpAddr, prefix: u8, count: usize, numbers: &mut Numbers) -> Vec<IpAddr> {
        let (bits, value) = match network {
            IpAddr::V4(ip) => (32, u128::from(ip.to_bits())),
            IpAddr::V6(ip) => (128, ip.to_bits()),
        };
        let width = u128::MAX >> (128 - bits);
        let host_bits = width.checked_shr(u32::from(prefix)).unwrap_or(0);
        let first = value & !host_bits & width;
        let last = first | host_bits;
        let at = |value: u128| match network {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from_bits((value & width) as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from_bits(value)),
        };
        let mut addresses: Vec<IpAddr> = [
            first.wrapping_sub(1),
            first,
            first.wrapping_add(1),
            last.wrapping_sub(1),
            last,
            last.wrapping_add(1),
        ]
        .into_iter()
        .map(at)
        .collect();
        addresses.extend((0..count).map(|_| at(first | (numbers.wide() & host_bits))));
        addresses
    }

    /// Fuzz-style: the tables decide as the documentation says at the edges of every block that
    /// the tables, the registry or the documentation name, where a prefix one bit off shows
    /// first, at random addresses inside each, and at random addresses of both families; and a
    /// refusal names a block that holds the address. The existing tests sample three addresses
    /// inside each registry block, which sees neither a block that is too wide nor one that the
    /// tables add.
    #[test]
    fn the_tables_decide_as_documented_everywhere() {
        let registry = registry();
        let documented = Documented::new(&registry);
        let mut numbers = Numbers(0x5eed_2026_1025_0001);
        let named = LOCAL
            .iter()
            .chain(REFUSED_ON_PURPOSE.iter().map(|(outer, _)| outer))
            .chain(&["224.0.0.0/4", "2000::/3"])
            .map(|text| block(text));
        let blocks: Vec<(IpAddr, u8)> = registry
            .iter()
            .map(|entry| (entry.network, entry.prefix))
            .chain(
                IPV4.iter()
                    .map(|&(network, prefix, ..)| (network.into(), prefix)),
            )
            .chain(
                IPV6.iter()
                    .map(|&(network, prefix, ..)| (network.into(), prefix)),
            )
            .chain(named)
            .collect();
        let mut addresses: Vec<IpAddr> = blocks
            .iter()
            .flat_map(|&(network, prefix)| around(network, prefix, 32, &mut numbers))
            .collect();
        for _ in 0..20_000 {
            addresses.push(Ipv4Addr::from_bits(numbers.next() as u32).into());
            addresses.push(Ipv6Addr::from_bits(numbers.wide()).into());
            // Global unicast space, where most of the IPv6 decisions are.
            addresses.push(Ipv6Addr::from_bits((numbers.wide() >> 3) | (1 << 125)).into());
        }
        let mapped: Vec<IpAddr> = addresses
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(IpAddr::V6(v4.to_ipv6_mapped())),
                IpAddr::V6(_) => None,
            })
            .collect();
        addresses.extend(mapped);
        for ip in addresses {
            for reach in [Public, PublicAndLocal] {
                let verdict = check_ip(ip, reach);
                assert_eq!(
                    verdict.is_ok(),
                    documented.allows(ip, reach),
                    "{ip} {reach:?}: {verdict:?}"
                );
                if let Err(Refusal::Block(name)) = verdict {
                    let inner = name
                        .split_once('(')
                        .and_then(|(_, rest)| rest.split_once(')'))
                        .map(|(inner, _)| inner)
                        .unwrap();
                    let canonical = ip.to_canonical();
                    let right = match inner.strip_prefix("outside ") {
                        Some(outer) => !holds(outer, canonical),
                        None => holds(inner, canonical),
                    };
                    assert!(right, "{ip} is refused as {name}");
                }
            }
        }
    }

    /// A host check that answers from fixed lists and counts its calls.
    #[derive(Default)]
    struct FakeHost {
        own: Vec<IpAddr>,
        subnets: Vec<Subnet>,
        fails: bool,
        asked: Cell<usize>,
    }

    impl FakeHost {
        fn with(own: &[&str], subnets: &[&str]) -> FakeHost {
            FakeHost {
                own: own.iter().map(|ip| ip.parse().unwrap()).collect(),
                subnets: subnets
                    .iter()
                    .map(|text| {
                        let (network, prefix) = block(text);
                        Subnet::new(network, prefix).unwrap()
                    })
                    .collect(),
                ..FakeHost::default()
            }
        }
    }

    impl HostNetwork for FakeHost {
        fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
            self.asked.set(self.asked.get() + 1);
            assert!(!matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()));
            if self.fails {
                return Err(io::Error::other("no answer"));
            }
            Ok(self.own.contains(&ip))
        }

        fn subnets(&self) -> io::Result<Vec<Subnet>> {
            self.asked.set(self.asked.get() + 1);
            if self.fails {
                return Err(io::Error::other("no answer"));
            }
            Ok(self.subnets.clone())
        }
    }

    fn at(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn the_host_itself_is_never_allowed() {
        let host = FakeHost::with(&["2a01:4f8::10", "192.168.8.21"], &[]);
        for ip in ["2a01:4f8::10", "192.168.8.21", "::ffff:192.168.8.21"] {
            for reach in [Public, PublicAndLocal] {
                let expected = match (ip, reach) {
                    (_, PublicAndLocal) | ("2a01:4f8::10", _) => Refusal::Host,
                    _ => Refusal::Block("private use (192.168.0.0/16)"),
                };
                assert_eq!(check(at(ip, 80), reach, &host), Err(expected), "{ip}");
            }
        }
    }

    /// On IPv6 a local network often has a global prefix, so the private ranges alone do not
    /// describe it: the host's own subnets are the local network too.
    #[test]
    fn the_host_subnets_are_the_local_network() {
        let host = FakeHost::with(
            &["2a01:4f8::10", "198.18.0.1"],
            &[
                "2a01:4f8::10/64",
                "198.18.0.1/15",
                "127.0.0.1/8",
                "fe80::1/64",
                "224.0.0.0/4",
            ],
        );
        let lan = at("2a01:4f8::99", 443);
        assert_eq!(check(lan, Public, &host), Err(Refusal::HostSubnet));
        assert_eq!(check(lan, PublicAndLocal, &host), Ok(lan));
        // A subnet in a block that is not globally reachable is the local network as well.
        let bench = at("198.18.7.7", 443);
        assert_eq!(
            check(bench, Public, &host),
            Err(Refusal::Block("benchmarking (198.18.0.0/15)"))
        );
        assert_eq!(check(bench, PublicAndLocal, &host), Ok(bench));
        // A subnet never opens what no reach allows.
        for ip in ["127.0.0.2", "fe80::2", "224.0.0.1"] {
            assert!(
                matches!(
                    check(at(ip, 443), PublicAndLocal, &host),
                    Err(Refusal::Block(_))
                ),
                "{ip}"
            );
        }
        // Outside the host's subnets, `public` allows what is public.
        let elsewhere = at("2a01:4f8:1::99", 443);
        assert_eq!(check(elsewhere, Public, &host), Ok(elsewhere));
    }

    #[test]
    fn a_host_that_cannot_tell_refuses() {
        let host = FakeHost {
            fails: true,
            ..FakeHost::default()
        };
        assert_eq!(
            check(at("1.1.1.1", 443), Public, &host),
            Err(Refusal::HostUnknown)
        );
        assert_eq!(
            check(at("10.0.0.1", 443), PublicAndLocal, &host),
            Err(Refusal::HostUnknown)
        );
    }

    /// The static refusals come first, so the host is not asked about them.
    #[test]
    fn static_refusals_do_not_ask_the_host() {
        let host = FakeHost::default();
        assert_eq!(
            check(at("1.1.1.1", 0), Public, &host),
            Err(Refusal::PortZero)
        );
        assert!(check(at("127.0.0.1", 80), PublicAndLocal, &host).is_err());
        assert!(check(at("10.0.0.1", 80), Public, &host).is_err());
        assert_eq!(host.asked.get(), 0);
    }

    #[test]
    fn the_checked_address_is_the_one_to_connect_to() {
        let host = FakeHost::default();
        assert_eq!(
            check(at("::ffff:1.1.1.1", 443), Public, &host),
            Ok(at("1.1.1.1", 443))
        );
        assert_eq!(
            check(at("2606:4700::1111", 443), Public, &host),
            Ok(at("2606:4700::1111", 443))
        );
    }

    #[test]
    fn subnets_contain_their_addresses_only() {
        let subnet = |text| {
            let (network, prefix) = block(text);
            Subnet::new(network, prefix)
        };
        let lan = subnet("192.168.8.21/24").unwrap();
        assert!(lan.contains("192.168.8.0".parse().unwrap()));
        assert!(lan.contains("192.168.8.255".parse().unwrap()));
        assert!(!lan.contains("192.168.9.1".parse().unwrap()));
        assert!(!lan.contains("::ffff:192.168.8.1".parse().unwrap()));
        assert!(
            subnet("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(
            subnet("::/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        let single = subnet("2a01:4f8::10/128").unwrap();
        assert!(single.contains("2a01:4f8::10".parse().unwrap()));
        assert!(!single.contains("2a01:4f8::11".parse().unwrap()));
        assert_eq!(subnet("10.0.0.1/33"), None);
        assert_eq!(subnet("::1/129"), None);
    }
}
