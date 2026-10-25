//! The host part of the egress broker's destination check (`HostNetwork`), answered by the kernel
//! over a NETLINK_ROUTE socket.
//!
//! `is_host` asks for the route to the address (RTM_GETROUTE, which `ip route get` shows): a
//! local, broadcast, anycast or multicast route is the host itself. That covers every interface
//! address, the broadcast address of every subnet, and local routes that no interface shows
//! (`ip route add local ...`). It also compares the address with every interface address and
//! subnet broadcast address (RTM_GETADDR), which does not depend on the routing rules that the
//! lookup follows. `subnets` comes from the same list of addresses.
//!
//! The socket is opened before the broker confines itself, so the broker needs no rule beyond
//! `sendto` and `recvfrom` for it, as for the relay's peer check (`peer`); Landlock does not
//! mediate netlink. Every answer is checked: it must come from the kernel, carry the sequence
//! number of its request and fit its own lengths. A lookup that fails refuses the destination.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use sandy_core::SandboxError;
use sandy_core::destination::{HostNetwork, Subnet};

/// How long a lookup waits for the kernel's answer. The kernel answers while the request is sent,
/// and a dump continues with each read, so this only bounds a lookup that went wrong.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(1);
/// The largest datagram a netlink dump sends (`netlink_dump` allocates at most 32 KiB).
const DATAGRAM: usize = 32 * 1024;

const HEADER: usize = size_of::<libc::nlmsghdr>();
/// `struct rtmsg`: family, the lengths of destination and source, tos, table, protocol, scope,
/// type, flags.
const ROUTE_MESSAGE: usize = 12;
/// `struct ifaddrmsg`: family, prefix length, flags, scope, interface index.
const ADDRESS_MESSAGE: usize = 8;
const ATTRIBUTE_HEADER: usize = 4;

const ERROR: u16 = libc::NLMSG_ERROR as u16;
const DONE: u16 = libc::NLMSG_DONE as u16;
const MULTIPART: u16 = libc::NLM_F_MULTI as u16;

/// The kernel's routing tables, asked over one socket that the broker's threads share.
pub(crate) struct Routes {
    socket: Mutex<Socket>,
}

struct Socket {
    fd: OwnedFd,
    sequence: u32,
    buffer: Vec<u8>,
}

/// One address of an interface, from RTM_GETADDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceAddress {
    /// The host's own address on the interface.
    own: IpAddr,
    broadcast: Option<IpAddr>,
    /// The address the prefix belongs to: the host's own, or the peer's on a point-to-point
    /// link, as the kernel's prefix route has it.
    subnet: Subnet,
}

impl Routes {
    /// Opens the socket and checks that the kernel answers both lookups. sandy calls this before
    /// it starts the broker, so a kernel that cannot answer refuses the run instead of every
    /// connection later.
    pub(crate) fn open() -> Result<Routes, SandboxError> {
        let failed = |error| {
            SandboxError::io(
                "cannot open a netlink socket to tell this host's addresses from others",
                error,
            )
        };
        // SAFETY: socket takes no pointers and returns a new descriptor.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(failed(io::Error::last_os_error()));
        }
        // SAFETY: the descriptor was just created and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval {
            tv_sec: ANSWER_TIMEOUT.as_secs() as _,
            tv_usec: 0,
        };
        // SAFETY: the option value is a valid timeval of the size passed.
        let set = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if set != 0 {
            return Err(failed(io::Error::last_os_error()));
        }
        let routes = Routes {
            socket: Mutex::new(Socket {
                fd,
                sequence: 0,
                buffer: vec![0; DATAGRAM],
            }),
        };
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let answers = routes
            .route_type(loopback)
            .map(|kind| kind == Some(libc::RTN_LOCAL))
            .and_then(|local| routes.addresses().map(|_| local));
        match answers {
            Ok(true) => Ok(routes),
            Ok(false) => Err(SandboxError::new(
                "the kernel does not report 127.0.0.1 as a local address, so the egress broker \
                 cannot tell this host's addresses from others",
            )),
            Err(error) => Err(failed(error)),
        }
    }

    /// The netlink socket, which the broker keeps when it closes its other descriptors.
    pub(crate) fn fd(&mut self) -> RawFd {
        let socket = self
            .socket
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        socket.fd.as_raw_fd()
    }

    /// The type of the route to `ip` (`RTN_*`), or `None` when the kernel has no route there,
    /// which a connect would fail on too.
    fn route_type(&self, ip: IpAddr) -> io::Result<Option<u8>> {
        let (family, length, bytes) = match ip {
            IpAddr::V4(ip) => (libc::AF_INET, 32, ip.octets().to_vec()),
            IpAddr::V6(ip) => (libc::AF_INET6, 128, ip.octets().to_vec()),
        };
        let mut payload = vec![0u8; ROUTE_MESSAGE];
        payload[0] = family as u8;
        payload[1] = length;
        push_attribute(&mut payload, libc::RTA_DST, &bytes);
        let mut kind = None;
        let asked = self.ask(libc::RTM_GETROUTE, 0, &payload, |message_type, message| {
            if message_type != libc::RTM_NEWROUTE || message.len() < ROUTE_MESSAGE {
                return Err(invalid("an answer that is not a route"));
            }
            kind = Some(message[7]);
            Ok(())
        });
        match asked {
            Ok(()) if kind.is_some() => Ok(kind),
            Ok(()) => Err(invalid("no route in the answer")),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENETUNREACH | libc::EHOSTUNREACH)
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Every address of every interface, IPv4 and IPv6.
    fn addresses(&self) -> io::Result<Vec<InterfaceAddress>> {
        // AF_UNSPEC asks for every family.
        let payload = [0u8; ADDRESS_MESSAGE];
        let mut addresses = Vec::new();
        self.ask(
            libc::RTM_GETADDR,
            libc::NLM_F_DUMP as u16,
            &payload,
            |message_type, message| {
                if message_type != libc::RTM_NEWADDR {
                    return Err(invalid("an answer that is not an address"));
                }
                addresses.extend(interface_address(message)?);
                Ok(())
            },
        )?;
        Ok(addresses)
    }

    /// Sends one request and calls `each` with the type and payload of every message of its
    /// answer, until the answer is complete.
    fn ask(
        &self,
        kind: u16,
        flags: u16,
        payload: &[u8],
        mut each: impl FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut socket = self
            .socket
            .lock()
            .map_err(|_| io::Error::other("a lookup panicked"))?;
        let Socket {
            fd,
            sequence,
            buffer,
        } = &mut *socket;
        *sequence = sequence.wrapping_add(1);
        let sequence = *sequence;
        let request = request(kind, flags, sequence, payload);
        // SAFETY: the request is a buffer of its own length, and the kernel is the destination of
        // an unbound netlink socket.
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                std::ptr::null(),
                0,
            )
        };
        if sent != request.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let Some(datagram) = receive(fd, buffer)? else {
                continue;
            };
            if let Progress::Done = read_messages(datagram, sequence, &mut each)? {
                return Ok(());
            }
        }
    }
}

impl HostNetwork for Routes {
    fn is_host(&self, ip: IpAddr) -> io::Result<bool> {
        // Every type but unicast counts as the host. Those that are not the host's own
        // (blackhole, unreachable, prohibit) reach nothing anyway.
        let routed_here = self
            .route_type(ip)?
            .is_some_and(|kind| kind != libc::RTN_UNICAST);
        Ok(routed_here
            || self
                .addresses()?
                .iter()
                .any(|address| address.own == ip || address.broadcast == Some(ip)))
    }

    fn subnets(&self) -> io::Result<Vec<Subnet>> {
        Ok(self
            .addresses()?
            .iter()
            .map(|address| address.subnet)
            .collect())
    }
}

/// A netlink request: the header, then `payload`.
fn request(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(HEADER + payload.len()).expect("a short request");
    let mut request = Vec::with_capacity(HEADER + payload.len());
    request.extend(length.to_ne_bytes());
    request.extend(kind.to_ne_bytes());
    request.extend((libc::NLM_F_REQUEST as u16 | flags).to_ne_bytes());
    request.extend(sequence.to_ne_bytes());
    // The port of the sender; 0 lets the kernel fill it in.
    request.extend(0u32.to_ne_bytes());
    request.extend(payload);
    request
}

fn push_attribute(payload: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = u16::try_from(ATTRIBUTE_HEADER + value.len()).expect("a short attribute");
    payload.extend(length.to_ne_bytes());
    payload.extend(kind.to_ne_bytes());
    payload.extend(value);
    payload.resize(align(payload.len()), 0);
}

/// Reads one datagram into `buffer`. `None` for a datagram that did not come from the kernel.
fn receive<'a>(fd: &OwnedFd, buffer: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
    loop {
        // SAFETY: sockaddr_nl is plain data; zero is a valid value for every field.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: the kernel writes at most `len` bytes into the buffer and at most
        // `sender_length` into `sender`. MSG_TRUNC makes it return the datagram's full length.
        let read = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&raw mut sender).cast(),
                &mut sender_length,
            )
        };
        let Ok(read) = usize::try_from(read) else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        };
        if read > buffer.len() {
            return Err(invalid("an answer longer than its buffer"));
        }
        // Only the kernel sends from port 0; another process cannot pose as it.
        if sender.nl_pid != 0 {
            return Ok(None);
        }
        return Ok(Some(&buffer[..read]));
    }
}

/// Whether a datagram ended the answer it belongs to.
enum Progress {
    More,
    Done,
}

/// Goes through the messages of `datagram` and calls `each` with the type and payload of every
/// message that answers the request with `sequence`. Messages of other requests, which can only
/// be late answers to earlier lookups, are skipped. The answer ends with a message that is not
/// part of a dump, with the end of a dump, or with an error, which is returned.
fn read_messages(
    datagram: &[u8],
    sequence: u32,
    each: &mut impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<Progress> {
    let mut rest = datagram;
    while !rest.is_empty() {
        let header = rest
            .get(..HEADER)
            .ok_or_else(|| invalid("a truncated message"))?;
        let length = u32_at(header, 0) as usize;
        if length < HEADER || length > rest.len() {
            return Err(invalid("a message whose length does not fit"));
        }
        let kind = u16_at(header, 4);
        let flags = u16_at(header, 6);
        let message = &rest[HEADER..length];
        rest = &rest[align(length).min(rest.len())..];
        if u32_at(header, 8) != sequence {
            continue;
        }
        match kind {
            ERROR => {
                let code = message
                    .get(..4)
                    .map(|code| i32::from_ne_bytes(code.try_into().expect("4 bytes")))
                    .ok_or_else(|| invalid("a truncated error"))?;
                return match code {
                    0 => Ok(Progress::Done),
                    code => Err(io::Error::from_raw_os_error(code.saturating_neg())),
                };
            }
            DONE => return Ok(Progress::Done),
            _ => {
                each(kind, message)?;
                if flags & MULTIPART == 0 {
                    return Ok(Progress::Done);
                }
            }
        }
    }
    Ok(Progress::More)
}

/// The address an RTM_NEWADDR message describes, or `None` for a family other than IPv4 and
/// IPv6.
fn interface_address(message: &[u8]) -> io::Result<Option<InterfaceAddress>> {
    let head = message
        .get(..ADDRESS_MESSAGE)
        .ok_or_else(|| invalid("a truncated address"))?;
    let (family, prefix) = (i32::from(head[0]), head[1]);
    let size = match family {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => return Ok(None),
    };
    let (mut address, mut local, mut broadcast) = (None, None, None);
    let mut rest = &message[ADDRESS_MESSAGE..];
    while !rest.is_empty() {
        let header = rest
            .get(..ATTRIBUTE_HEADER)
            .ok_or_else(|| invalid("a truncated attribute"))?;
        let length = usize::from(u16_at(header, 0));
        if length < ATTRIBUTE_HEADER || length > rest.len() {
            return Err(invalid("an attribute whose length does not fit"));
        }
        let value = &rest[ATTRIBUTE_HEADER..length];
        let slot = match u16_at(header, 2) {
            libc::IFA_ADDRESS => Some(&mut address),
            libc::IFA_LOCAL => Some(&mut local),
            libc::IFA_BROADCAST => Some(&mut broadcast),
            _ => None,
        };
        if let Some(slot) = slot {
            if value.len() != size {
                return Err(invalid("an address of the wrong length"));
            }
            *slot = Some(ip_from(value));
        }
        rest = &rest[align(length).min(rest.len())..];
    }
    let address = address.ok_or_else(|| invalid("an interface address without an address"))?;
    let subnet =
        Subnet::new(address, prefix).ok_or_else(|| invalid("a prefix longer than its address"))?;
    Ok(Some(InterfaceAddress {
        own: local.unwrap_or(address),
        broadcast,
        subnet,
    }))
}

/// The address in `bytes`, which are 4 or 16 long.
fn ip_from(bytes: &[u8]) -> IpAddr {
    match <[u8; 4]>::try_from(bytes) {
        Ok(v4) => IpAddr::V4(Ipv4Addr::from(v4)),
        Err(_) => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).expect("16 bytes"),
        )),
    }
}

/// `length` rounded up to the 4-byte alignment of netlink messages and attributes.
fn align(length: usize) -> usize {
    length.div_ceil(4) * 4
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The addresses of this host's interfaces as getifaddrs lists them, independently of the
    /// netlink code: each address with its prefix length, and the IPv4 broadcast addresses.
    fn interfaces() -> (Vec<(IpAddr, u8)>, Vec<IpAddr>) {
        let ip_of = |address: *const libc::sockaddr| -> Option<IpAddr> {
            if address.is_null() {
                return None;
            }
            // SAFETY: getifaddrs gives sockaddrs of the size their family implies.
            unsafe {
                match i32::from((*address).sa_family) {
                    libc::AF_INET => {
                        let v4 = &*address.cast::<libc::sockaddr_in>();
                        Some(IpAddr::from(u32::from_be(v4.sin_addr.s_addr).to_be_bytes()))
                    }
                    libc::AF_INET6 => {
                        let v6 = &*address.cast::<libc::sockaddr_in6>();
                        Some(IpAddr::from(v6.sin6_addr.s6_addr))
                    }
                    _ => None,
                }
            }
        };
        let (mut addresses, mut broadcasts) = (Vec::new(), Vec::new());
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs writes a list that freeifaddrs releases below.
        assert_eq!(unsafe { libc::getifaddrs(&mut head) }, 0);
        let mut entry = head;
        while !entry.is_null() {
            // SAFETY: entry is a node of the list getifaddrs returned.
            let node = unsafe { &*entry };
            if let (Some(ip), Some(mask)) = (ip_of(node.ifa_addr), ip_of(node.ifa_netmask)) {
                let prefix = match mask {
                    IpAddr::V4(mask) => mask.to_bits().count_ones(),
                    IpAddr::V6(mask) => mask.to_bits().count_ones(),
                };
                addresses.push((ip, prefix as u8));
                if node.ifa_flags & libc::IFF_BROADCAST as libc::c_uint != 0 {
                    broadcasts.extend(ip_of(node.ifa_ifu).filter(IpAddr::is_ipv4));
                }
            }
            entry = node.ifa_next;
        }
        // SAFETY: head came from getifaddrs.
        unsafe { libc::freeifaddrs(head) };
        (addresses, broadcasts)
    }

    #[test]
    fn the_kernel_knows_this_host() {
        let routes = Routes::open().unwrap();
        let (addresses, broadcasts) = interfaces();
        assert!(!broadcasts.is_empty(), "no subnet with a broadcast address");
        let fixed = [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
        ];
        let all = fixed
            .iter()
            .map(|ip| ip.parse().unwrap())
            .chain(addresses.iter().map(|(ip, _)| *ip))
            .chain(broadcasts.iter().copied());
        for ip in all {
            assert!(routes.is_host(ip).unwrap(), "{ip}");
        }
        // The address list alone knows them too, whatever the routes say.
        let listed = routes.addresses().unwrap();
        for (ip, _) in &addresses {
            assert!(listed.iter().any(|address| address.own == *ip), "{ip}");
        }
        for broadcast in &broadcasts {
            assert!(
                listed
                    .iter()
                    .any(|address| address.broadcast == Some(*broadcast)),
                "{broadcast}"
            );
        }
        assert_eq!(
            routes.route_type("127.0.0.1".parse().unwrap()).unwrap(),
            Some(libc::RTN_LOCAL)
        );
        assert_eq!(
            routes.route_type("224.0.0.1".parse().unwrap()).unwrap(),
            Some(libc::RTN_MULTICAST)
        );
        for broadcast in broadcasts {
            assert_eq!(
                routes.route_type(broadcast).unwrap(),
                Some(libc::RTN_BROADCAST),
                "{broadcast}"
            );
        }
    }

    /// An address elsewhere is no address of the host, whether the kernel routes it out or has
    /// no route for it.
    #[test]
    fn an_address_elsewhere_is_not_the_host() {
        let routes = Routes::open().unwrap();
        for ip in ["198.51.100.1", "8.8.8.8", "2001:db8::1", "2606:4700::1111"] {
            assert!(!routes.is_host(ip.parse().unwrap()).unwrap(), "{ip}");
        }
    }

    #[test]
    fn the_subnets_are_the_prefixes_of_the_interface_addresses() {
        let routes = Routes::open().unwrap();
        let subnets = routes.subnets().unwrap();
        let (addresses, _) = interfaces();
        for (ip, prefix) in addresses {
            assert!(
                subnets.contains(&Subnet::new(ip, prefix).unwrap()),
                "{ip}/{prefix} in {subnets:?}"
            );
        }
    }

    /// An answer that an earlier lookup left unread, for example after a timeout, is never taken
    /// for the answer to a later one. The broker's threads take turns on the socket, so this is
    /// what keeps their answers apart.
    #[test]
    fn a_late_answer_is_not_taken_for_the_current_one() {
        let routes = Routes::open().unwrap();
        {
            let mut socket = routes.socket.lock().unwrap();
            socket.sequence = socket.sequence.wrapping_add(1);
            let mut payload = vec![libc::AF_INET as u8, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            push_attribute(&mut payload, libc::RTA_DST, &[127, 0, 0, 1]);
            let stale = request(libc::RTM_GETROUTE, 0, socket.sequence, &payload);
            // SAFETY: the request is a buffer of its own length, and the kernel is the
            // destination of an unbound netlink socket.
            let sent = unsafe {
                libc::sendto(
                    socket.fd.as_raw_fd(),
                    stale.as_ptr().cast(),
                    stale.len(),
                    0,
                    std::ptr::null(),
                    0,
                )
            };
            assert_eq!(sent, stale.len() as isize);
        }
        // The answer about 127.0.0.1 waits in the socket, ahead of this one.
        let elsewhere = routes.route_type("198.51.100.1".parse().unwrap()).unwrap();
        assert_ne!(elsewhere, Some(libc::RTN_LOCAL));
        assert!(!routes.is_host("198.51.100.1".parse().unwrap()).unwrap());
    }

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut message = request(kind, 0, sequence, payload);
        message[6..8].copy_from_slice(&flags.to_ne_bytes());
        message.resize(align(message.len()), 0);
        message
    }

    /// The type and payload of each message of an answer.
    type Seen = Vec<(u16, Vec<u8>)>;

    fn collect(datagram: &[u8], sequence: u32) -> io::Result<(Seen, bool)> {
        let mut seen = Vec::new();
        let progress = read_messages(datagram, sequence, &mut |kind, payload| {
            seen.push((kind, payload.to_vec()));
            Ok(())
        })?;
        Ok((seen, matches!(progress, Progress::Done)))
    }

    #[test]
    fn answers_are_read_by_their_sequence_and_their_end() {
        // A late answer to another request is skipped; a single message ends the answer.
        let mut datagram = message(24, 0, 6, &[1, 2, 3]);
        datagram.extend(message(24, 0, 7, &[4; 12]));
        let (seen, done) = collect(&datagram, 7).unwrap();
        assert_eq!(seen, [(24, vec![4; 12])]);
        assert!(done);
        // A dump goes on until its end.
        let mut dump = message(20, MULTIPART, 7, &[1; 8]);
        dump.extend(message(20, MULTIPART, 7, &[2; 8]));
        let (seen, done) = collect(&dump, 7).unwrap();
        assert_eq!(seen.len(), 2);
        assert!(!done);
        let (seen, done) = collect(&message(DONE, MULTIPART, 7, &[0; 4]), 7).unwrap();
        assert!(seen.is_empty() && done);
        // An error ends it with that error, an acknowledgement without one.
        let error = collect(&message(ERROR, 0, 7, &(-libc::EACCES).to_ne_bytes()), 7);
        assert_eq!(error.unwrap_err().raw_os_error(), Some(libc::EACCES));
        assert!(
            collect(&message(ERROR, 0, 7, &0i32.to_ne_bytes()), 7)
                .unwrap()
                .1
        );
    }

    #[test]
    fn malformed_answers_fail() {
        let good = message(24, 0, 7, &[0; 12]);
        let mut too_long = good.clone();
        too_long[0..4].copy_from_slice(&(good.len() as u32 + 4).to_ne_bytes());
        let mut too_short = good.clone();
        too_short[0..4].copy_from_slice(&4u32.to_ne_bytes());
        for datagram in [
            &good[..10],
            &too_long,
            &too_short,
            &message(ERROR, 0, 7, &[1]),
        ] {
            assert_eq!(
                collect(datagram, 7).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{datagram:?}"
            );
        }
    }

    fn address_message(family: u8, prefix: u8, attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut payload = vec![family, prefix, 0, 0, 1, 0, 0, 0];
        for (kind, value) in attributes {
            push_attribute(&mut payload, *kind, value);
        }
        payload
    }

    #[test]
    fn an_interface_address_names_the_host_and_its_subnet() {
        let lan = address_message(
            libc::AF_INET as u8,
            24,
            &[
                (libc::IFA_ADDRESS, &[192, 168, 8, 21]),
                (libc::IFA_LOCAL, &[192, 168, 8, 21]),
                (libc::IFA_BROADCAST, &[192, 168, 8, 255]),
            ],
        );
        let lan = interface_address(&lan).unwrap().unwrap();
        assert_eq!(lan.own, "192.168.8.21".parse::<IpAddr>().unwrap());
        assert_eq!(lan.broadcast, Some("192.168.8.255".parse().unwrap()));
        assert!(lan.subnet.contains("192.168.8.77".parse().unwrap()));
        // On a point-to-point link the address is the peer's, and the prefix is the peer's.
        let link = address_message(
            libc::AF_INET as u8,
            32,
            &[
                (libc::IFA_ADDRESS, &[10, 1, 0, 2]),
                (libc::IFA_LOCAL, &[10, 1, 0, 1]),
            ],
        );
        let link = interface_address(&link).unwrap().unwrap();
        assert_eq!(link.own, "10.1.0.1".parse::<IpAddr>().unwrap());
        assert!(link.subnet.contains("10.1.0.2".parse().unwrap()));
        assert!(!link.subnet.contains("10.1.0.1".parse().unwrap()));
        let v6 = "2a01:4f8::10".parse::<Ipv6Addr>().unwrap().octets();
        let global = address_message(libc::AF_INET6 as u8, 64, &[(libc::IFA_ADDRESS, &v6)]);
        let global = interface_address(&global).unwrap().unwrap();
        assert_eq!(global.own, IpAddr::V6(Ipv6Addr::from(v6)));
        assert!(global.subnet.contains("2a01:4f8::99".parse().unwrap()));
        // Other families are not IP addresses.
        let other = address_message(35, 0, &[(1, &[7])]);
        assert_eq!(interface_address(&other).unwrap(), None);
    }

    #[test]
    fn malformed_interface_addresses_fail() {
        let inet = libc::AF_INET as u8;
        let wrong_length = address_message(inet, 24, &[(libc::IFA_ADDRESS, &[1, 2, 3])]);
        let no_address = address_message(inet, 24, &[(libc::IFA_BROADCAST, &[1, 2, 3, 255])]);
        let long_prefix = address_message(inet, 33, &[(libc::IFA_ADDRESS, &[1, 2, 3, 4])]);
        let mut bad_attribute = address_message(inet, 24, &[(libc::IFA_ADDRESS, &[1, 2, 3, 4])]);
        bad_attribute[8..10].copy_from_slice(&64u16.to_ne_bytes());
        for message in [
            &wrong_length[..],
            &no_address,
            &long_prefix,
            &bad_attribute,
            &[inet, 24, 0],
        ] {
            assert_eq!(
                interface_address(message).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{message:?}"
            );
        }
    }
}
