//! Who connected to a relay listener. A forwarded port exists for the program alone, but a
//! loopback listener carries no credentials: without a check, any local user could connect to it
//! and reach the service outside as sandy's user, which defeats an owner rule of a packet filter
//! or a peer credential check in that service.
//!
//! TCP has no `SO_PEERCRED`, so the relay asks the kernel instead. `NETLINK_SOCK_DIAG` answers an
//! exact lookup of one connection with the owner of the socket on the other end. The socket is
//! opened before the relay confines itself, so its filter needs no rule beyond `sendto` and
//! `recvfrom`, which it already allows; Landlock does not mediate netlink. An answer about
//! another connection, an answer with another owner and every failure mean that the connection
//! is refused, and a kernel that cannot answer at all is found by a self test before the relay
//! starts. The kernel answers a lookup in the call that sends it, so the relay's watchdog bounds
//! the wait for an answer that never comes.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use sandy_core::SandboxError;

/// `SOCK_DIAG_BY_FAMILY`, the only netlink message the relay sends.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `INET_DIAG_NOCOOKIE`: match the socket by its addresses, not by a cookie of an earlier answer.
const NO_COOKIE: [u32; 2] = [u32::MAX, u32::MAX];
/// Every TCP state, so that the lookup also finds the socket of a peer that has closed its side
/// already, which is the normal case for a program that connects, writes and exits.
const ALL_STATES: u32 = u32::MAX;

/// The owner of the other end of a connection, as the kernel reports it.
pub(crate) struct PeerCheck {
    diag: OwnedFd,
    uid: u32,
}

impl PeerCheck {
    /// Opens the netlink socket and checks that the kernel answers for a connection of this
    /// process. sandy calls this before it starts the relay, so a kernel without `inet_diag`
    /// refuses the run instead of silently refusing every connection later.
    pub(crate) fn open() -> Result<PeerCheck, SandboxError> {
        // SAFETY: socket takes no pointers and returns a new descriptor.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(SandboxError::io(
                "cannot open a netlink socket to check who connects to a forwarded port",
                io::Error::last_os_error(),
            ));
        }
        let check = PeerCheck {
            // SAFETY: the descriptor was just created and nothing else owns it.
            diag: unsafe { OwnedFd::from_raw_fd(fd) },
            // SAFETY: getuid has no preconditions. The relay's filter does not allow it, so the
            // answer is kept here.
            uid: unsafe { libc::getuid() },
        };
        check.self_test()?;
        Ok(check)
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.diag.as_raw_fd()
    }

    /// Whether the connection from `peer` to `local` belongs to sandy's user. False for every
    /// failure, so a connection the kernel cannot account for is refused.
    pub(crate) fn owned_by_us(&self, peer: SocketAddr, local: SocketAddr) -> bool {
        let Some(request) = Request::new(peer, local) else {
            return false;
        };
        let mut answer = [0u8; 4096];
        match self.ask(&request, &mut answer) {
            // A lookup that matches no connection falls back to a listening socket, and a socket
            // the kernel no longer accounts for (a peer in TIME_WAIT) reports no owner. Both are
            // caught by comparing the answer with what was asked.
            Some(message) => message.id.same_as(&request.id) && message.uid == self.uid,
            None => false,
        }
    }

    /// Sends one lookup and reads its answer. `None` when the kernel reports an error, the
    /// message is not the expected one, or the call fails.
    fn ask(&self, request: &Request, answer: &mut [u8]) -> Option<Message> {
        // SAFETY: the request is a packed message of its own size, and the kernel is the
        // destination of an unbound netlink socket.
        let sent = unsafe {
            libc::sendto(
                self.fd(),
                (request as *const Request).cast(),
                size_of::<Request>(),
                0,
                std::ptr::null(),
                0,
            )
        };
        if sent != size_of::<Request>() as isize {
            return None;
        }
        // SAFETY: the kernel writes at most `len` bytes into the buffer.
        let read = unsafe {
            libc::recvfrom(
                self.fd(),
                answer.as_mut_ptr().cast(),
                answer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let read = usize::try_from(read).ok()?;
        if read < size_of::<libc::nlmsghdr>() + size_of::<Message>() {
            return None;
        }
        // SAFETY: the buffer holds at least a header and a message, and both are plain data.
        let (header, message) = unsafe {
            (
                std::ptr::read_unaligned(answer.as_ptr().cast::<libc::nlmsghdr>()),
                std::ptr::read_unaligned(
                    answer
                        .as_ptr()
                        .add(size_of::<libc::nlmsghdr>())
                        .cast::<Message>(),
                ),
            )
        };
        if header.nlmsg_type != SOCK_DIAG_BY_FAMILY || header.nlmsg_seq != request.header.nlmsg_seq
        {
            return None;
        }
        Some(message)
    }

    /// Checks the lookup on a connection of this process, which must report this user.
    fn self_test(&self) -> Result<(), SandboxError> {
        let failed = |error| SandboxError::io("cannot check who owns a loopback connection", error);
        let listener = TcpListener::bind("127.0.0.1:0").map_err(failed)?;
        let address = listener.local_addr().map_err(failed)?;
        let client = TcpStream::connect(address).map_err(failed)?;
        let (accepted, peer) = listener.accept().map_err(failed)?;
        let local = accepted.local_addr().map_err(failed)?;
        let ours = self.owned_by_us(peer, local);
        drop((client, accepted, listener));
        if !ours {
            return Err(SandboxError::new(
                "this kernel does not report who owns a loopback connection, so a forwarded port \
                 cannot refuse other users (it needs inet_diag with TCP support)",
            ));
        }
        Ok(())
    }
}

/// `struct inet_diag_sockid` of linux/inet_diag.h. The ports are in network byte order and the
/// addresses are the first four or sixteen bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockId {
    source_port: u16,
    destination_port: u16,
    source: [u8; 16],
    destination: [u8; 16],
    interface: u32,
    cookie: [u32; 2],
}

impl SockId {
    /// Whether the kernel answered about the connection that was asked about. The cookie is not
    /// compared: the request carries `INET_DIAG_NOCOOKIE`, the answer the socket's own cookie.
    fn same_as(&self, asked: &SockId) -> bool {
        (
            self.source_port,
            self.destination_port,
            self.source,
            self.destination,
        ) == (
            asked.source_port,
            asked.destination_port,
            asked.source,
            asked.destination,
        )
    }
}

/// A netlink header followed by `struct inet_diag_req_v2`.
#[repr(C)]
struct Request {
    header: libc::nlmsghdr,
    family: u8,
    protocol: u8,
    extensions: u8,
    padding: u8,
    states: u32,
    id: SockId,
}

/// `struct inet_diag_msg`, the kernel's answer. The fields after the owner are not used.
#[repr(C)]
#[derive(Clone, Copy)]
struct Message {
    family: u8,
    state: u8,
    timer: u8,
    retransmits: u8,
    id: SockId,
    expires: u32,
    receive_queue: u32,
    send_queue: u32,
    uid: u32,
    inode: u32,
}

const _: () = assert!(size_of::<SockId>() == 48);
const _: () = assert!(size_of::<Request>() == 72);
const _: () = assert!(size_of::<Message>() == 72);

impl Request {
    /// The lookup for the socket whose own address is `source` and whose peer is `destination`,
    /// which is the socket of the process that connected. `None` when the two addresses are not
    /// of the same family, which no accepted connection is.
    fn new(source: SocketAddr, destination: SocketAddr) -> Option<Request> {
        let family = match (source.ip(), destination.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET,
            (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6,
            _ => return None,
        };
        let address = |ip: IpAddr| {
            let mut bytes = [0u8; 16];
            match ip {
                IpAddr::V4(ip) => bytes[..4].copy_from_slice(&ip.octets()),
                IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
            }
            bytes
        };
        Some(Request {
            header: libc::nlmsghdr {
                nlmsg_len: size_of::<Request>() as u32,
                nlmsg_type: SOCK_DIAG_BY_FAMILY,
                nlmsg_flags: libc::NLM_F_REQUEST as u16,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
            family: family as u8,
            protocol: libc::IPPROTO_TCP as u8,
            extensions: 0,
            padding: 0,
            states: ALL_STATES,
            id: SockId {
                source_port: source.port().to_be(),
                destination_port: destination.port().to_be(),
                source: address(source.ip()),
                destination: address(destination.ip()),
                // Loopback sockets are not bound to a device, and a lookup that names one would
                // not find them.
                interface: 0,
                cookie: NO_COOKIE,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection of this process belongs to this user, also when the peer has closed its
    /// side already, and the same lookup with another user's ID rejects it. The rejection is
    /// what a forward listener does with a connection of another user, which a test cannot make
    /// without a second account.
    #[test]
    fn a_loopback_connection_reports_its_owner() {
        let check = PeerCheck::open().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        let local = accepted.local_addr().unwrap();
        assert!(check.owned_by_us(peer, local));

        let other = PeerCheck {
            diag: check.diag.try_clone().unwrap(),
            uid: check.uid + 1,
        };
        assert!(!other.owned_by_us(peer, local));

        // A program that connects, writes and exits at once leaves its side closed before the
        // relay accepts. Its socket still names its owner.
        drop(client);
        assert!(check.owned_by_us(peer, local));

        // A connection that is gone has no owner to report, and is refused.
        drop(accepted);
        drop(listener);
        assert!(!check.owned_by_us(peer, local));
    }
}
