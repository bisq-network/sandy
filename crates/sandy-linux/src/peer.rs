//! Who connected to a relay listener. A forwarded port exists for the program alone, but a
//! loopback listener carries no credentials: without a check, any local user could connect to it
//! and reach the service outside as sandy's user, which defeats an owner rule of a packet filter
//! or a peer credential check in that service.
//!
//! TCP has no `SO_PEERCRED`, so the relay asks the kernel instead. `NETLINK_SOCK_DIAG` answers an
//! exact lookup of one connection with the owner of the socket on the other end. The socket is
//! opened before the relay confines itself, so its filter needs no rule beyond `sendto` and
//! `recvfrom`, which it already allows; Landlock does not mediate netlink. An answer about
//! another connection and every failure mean that the connection is refused, and a kernel that
//! cannot answer at all is found by a self test before the relay starts. The kernel answers a
//! lookup in the call that sends it, so the relay reads the answer without waiting, and a
//! missing answer refuses the connection instead of holding up the relay.
//!
//! One peer the kernel cannot name: one that closed its socket. The owner it reports comes from
//! the socket's file (`sock_i_uid`), and closing the socket takes that file away, so from the
//! close onwards the lookup answers with no owner for a connection of any user. It says so in
//! the inode of the answer, which is zero exactly then, and that is the field the relay reads.
//! The user in such an answer cannot name the owner on its own: kernels up to 6.8 report user 0
//! from the close, and 6.17 and later keep the user until they replace the socket with a
//! timewait record, which reports user 0, after about a millisecond, or about 40 milliseconds
//! when the peer wrote before it closed (measured on 6.8, 6.17 and 7.2). Requiring sandy's user
//! therefore refused nearly every connection of a program that connects and exits on 6.8, and
//! between none and nine tenths of them on the newer kernels, depending on what the program does
//! and how busy the host is (docs/linux.md, "Exposed and forwarded ports").
//!
//! The relay serves a connection no owner can be found for. It is the program's own in every
//! ordinary run: the kernel completes a handshake by itself, so a program that connects and
//! exits is always ahead of the relay's accept, and refusing these answers is refusing what a
//! forwarded port exists to carry. A user the answer does name still counts, though: user 0 says
//! nothing on any kernel and sandy's own user is the program's, but any other user is someone
//! else's closed socket, which the relay refuses. What remains is that another local user can
//! deliver a blind write when its socket no longer carries its user: on 6.8 always, usually on
//! the first attempt, because a peer that connects, writes and closes at once is usually closed
//! before the relay asks; on 6.17 and later only when the relay asks after the timewait record
//! has replaced the socket.
//!
//! The one thing that keeps the straightforward attack closed is that only a peer which can no
//! longer read is ever unnamed. Losing the file is what loses the owner, and it also gives up
//! the answer. A peer that only shuts down its sending side keeps its socket and its file, so
//! it keeps its owner and is checked like any other: half closing is no way to proxy through a
//! forwarded port. A change here that read the state instead of the inode would open exactly
//! that, because a half closed peer and a closed one are both in FIN_WAIT2.

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
/// Who the socket on the other end of a connection belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Owner {
    /// sandy's own user.
    Us,
    /// Another user, or an answer the relay cannot trust.
    AnotherUser,
    /// Nobody the kernel still knows: the peer closed its socket, and the record left behind
    /// carries no owner.
    Nobody,
}

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

    /// Whether the connection from `peer` to `local` may be relayed on a forwarded port. False
    /// when the kernel names another user as the owner of the other end, and false for every
    /// failure, so an answer the relay cannot trust refuses the connection.
    pub(crate) fn may_relay(&self, peer: SocketAddr, local: SocketAddr) -> bool {
        self.owner(peer, local) != Owner::AnotherUser
    }

    /// Who the kernel says the socket on the other end belongs to. `Nobody` when the answer
    /// carries no inode, which is how the kernel reports a socket that has no file any more.
    fn owner(&self, peer: SocketAddr, local: SocketAddr) -> Owner {
        let Some(request) = Request::new(peer, local) else {
            return Owner::AnotherUser;
        };
        let mut answer = [0u8; 4096];
        let Some(message) = self.ask(&request, &mut answer) else {
            return Owner::AnotherUser;
        };
        // A lookup that matches no connection falls back to a listening socket, which comparing
        // the answer with what was asked catches.
        if message.connection() != Some((canonical(peer), canonical(local))) {
            return Owner::AnotherUser;
        }
        owner_of(message.uid, message.inode, self.uid)
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
                libc::MSG_DONTWAIT,
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
        let ours = self.owner(peer, local) == Owner::Us;
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

/// Who an answer with `uid` and `inode` names, for a relay that runs as `own`. Only a peer that
/// closed its socket is unnamed, and such a peer can no longer read. A half closed peer keeps its
/// file, so it keeps its inode and its owner. Both reach FIN_WAIT2, so this must stay a test of
/// the inode and never of `idiag_state`. Without an inode, user 0 and sandy's user are served,
/// and any other user is refused (see the module documentation).
fn owner_of(uid: u32, inode: u32, own: u32) -> Owner {
    match (inode, uid) {
        (0, 0) => Owner::Nobody,
        (0, uid) if uid == own => Owner::Nobody,
        (_, uid) if uid == own => Owner::Us,
        _ => Owner::AnotherUser,
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

impl Message {
    /// The connection the kernel answered about: the socket's own address and its peer's, in the
    /// family of the socket, which need not be the family that was asked in. A dual-stack IPv6
    /// socket that connected to an IPv4 listener (Java's default, for one) has IPv4-mapped
    /// addresses, and the IPv4 lookup finds it under the plain IPv4 ones. The cookie is not part
    /// of it: the request carries `INET_DIAG_NOCOOKIE`, the answer the socket's own cookie.
    fn connection(&self) -> Option<(SocketAddr, SocketAddr)> {
        let ip = |bytes: [u8; 16]| match i32::from(self.family) {
            libc::AF_INET => Some(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])),
            libc::AF_INET6 => Some(IpAddr::from(bytes)),
            _ => None,
        };
        let address = |bytes, port: u16| {
            ip(bytes).map(|ip| canonical(SocketAddr::new(ip, u16::from_be(port))))
        };
        Some((
            address(self.id.source, self.id.source_port)?,
            address(self.id.destination, self.id.destination_port)?,
        ))
    }
}

/// `address` with an IPv4-mapped IPv6 address written as the IPv4 address it maps.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

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

    use std::net::{Ipv4Addr, Shutdown};
    use std::time::{Duration, Instant};

    /// The same lookup with another user's ID, which is what a forward listener answers for a
    /// connection of another user. A test cannot make one without a second account.
    fn as_another_user(check: &PeerCheck) -> PeerCheck {
        PeerCheck {
            diag: check.diag.try_clone().unwrap(),
            uid: check.uid + 1,
        }
    }

    /// A connection of this process belongs to this user and is refused for any other, also
    /// when the peer has stopped sending. Half closing keeps the socket and its owner, so it is
    /// no way around the check: a peer that can still read is always named.
    #[test]
    fn a_loopback_connection_reports_its_owner() {
        let check = PeerCheck::open().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        let local = accepted.local_addr().unwrap();
        let other = as_another_user(&check);
        assert_eq!(check.owner(peer, local), Owner::Us);
        assert!(!other.may_relay(peer, local));

        client.shutdown(Shutdown::Write).unwrap();
        // Long enough to pass the few milliseconds in which a peer that closed loses its owner.
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            assert_eq!(check.owner(peer, local), Owner::Us);
            assert!(!other.may_relay(peer, local));
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A dual-stack IPv6 socket reaches an IPv4 listener through an IPv4-mapped address, and the
    /// kernel answers about it in its own family. It is the same connection and the same owner.
    #[test]
    fn a_dual_stack_peer_reports_its_owner() {
        let check = PeerCheck::open().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), port));
        let client = TcpStream::connect(mapped).unwrap();
        assert!(
            client.local_addr().unwrap().is_ipv6(),
            "not a dual-stack socket"
        );
        let (accepted, peer) = listener.accept().unwrap();
        let local = accepted.local_addr().unwrap();
        assert_eq!(check.owner(peer, local), Owner::Us);
        assert!(!as_another_user(&check).may_relay(peer, local));
    }

    /// A peer that closed its socket has no file for the kernel to read an owner from, so the
    /// answer carries no inode, and the relay serves it for its own user from the close onwards.
    /// That keeps the program's own connection. For another user it is served only once the
    /// answer no longer carries a user: on 6.8 from the close, on 6.17 and later once a timewait
    /// record has replaced the socket. Until then the user it still carries refuses it. The
    /// decision is taken from the answer itself, because the kernel replaces the socket at a
    /// moment of its own. In a process of its own (`alone`): a child that another test starts
    /// meanwhile holds a copy of the socket until it executes, and the file with it.
    #[test]
    fn a_peer_that_closed_its_socket_has_no_owner() {
        if !crate::alone::in_own_process() {
            return;
        }
        let check = PeerCheck::open().unwrap();
        let other = as_another_user(&check);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        let local = accepted.local_addr().unwrap();
        drop(client);
        let request = Request::new(peer, local).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut answer = [0u8; 4096];
            let message = check
                .ask(&request, &mut answer)
                .expect("the kernel answered");
            assert_eq!(message.inode, 0, "the closed peer kept its file");
            assert!(check.may_relay(peer, local));
            if message.uid == 0 {
                break;
            }
            assert_eq!(message.uid, check.uid);
            let seen_by_other = owner_of(message.uid, message.inode, other.uid);
            assert_eq!(seen_by_other, Owner::AnotherUser);
            assert!(
                Instant::now() < deadline,
                "the closed socket was never replaced"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // A record that carries no user stays so until it expires.
        assert!(other.may_relay(peer, local));
        drop(accepted);
    }

    /// The rule for an answer, apart from the kernel: an answer with an inode names its owner.
    /// One without is a closed socket, served for user 0, which says nothing on any kernel, and
    /// for the relay's own user, and refused for any other user the kernel still names.
    #[test]
    fn an_answer_is_judged_by_the_user_it_carries() {
        const OWN: u32 = 1000;
        assert_eq!(owner_of(OWN, 7, OWN), Owner::Us);
        assert_eq!(owner_of(0, 7, OWN), Owner::AnotherUser);
        assert_eq!(owner_of(OWN + 1, 7, OWN), Owner::AnotherUser);
        assert_eq!(owner_of(0, 0, OWN), Owner::Nobody);
        assert_eq!(owner_of(OWN, 0, OWN), Owner::Nobody);
        assert_eq!(owner_of(OWN + 1, 0, OWN), Owner::AnotherUser);
    }

    /// A lookup the relay cannot trust refuses the connection: an answer about another socket
    /// is the one such answer a test can produce, by asking about a connection that never
    /// existed, where the kernel falls back to the listening socket.
    #[test]
    fn an_answer_about_another_socket_is_refused() {
        let check = PeerCheck::open().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let never_connected = SocketAddr::from(([127, 0, 0, 1], 1));
        assert_eq!(check.owner(never_connected, local), Owner::AnotherUser);
        assert!(!check.may_relay(never_connected, local));
    }
}
