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
//! lookup in the call that sends it, so the relay's watchdog bounds the wait for an answer that
//! never comes.
//!
//! One peer the kernel cannot name: one that closed its socket. The owner it reports comes from
//! the socket's file (`sock_i_uid`), and closing the socket takes that file away, so from the
//! close onwards the lookup answers with no owner for a connection of any user. It says so in
//! the inode of the answer, which is zero exactly then, and that is the field the relay reads.
//! The user in such an answer cannot be used: kernels up to 6.8 report user 0 from the close,
//! and 6.17 and later keep the user until they replace the socket with a timewait record a few
//! milliseconds afterwards. Reading the user therefore refused nearly every connection of a
//! program that connects and exits on 6.8, and between none and two thirds of them on the
//! newer kernels, depending on what the program does and how busy the host is (docs/linux.md,
//! "Exposed and forwarded ports").
//!
//! The relay serves a connection no owner can be found for. It is the program's own in every
//! ordinary run: the kernel completes a handshake by itself, so a program that connects and
//! exits is always ahead of the relay's accept, and refusing these answers is refusing what a
//! forwarded port exists to carry. What it costs is that another local user can land a write by
//! connecting, writing, closing and retrying until one attempt hits the window.
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
        if !message.id.same_as(&request.id) {
            return Owner::AnotherUser;
        }
        // Only a peer that closed its socket is unnamed, and such a peer can no longer read.
        // A half closed peer keeps its file, so it keeps its inode and its owner. Both reach
        // FIN_WAIT2, so this must stay a test of the inode and never of `idiag_state`.
        if message.inode == 0 {
            return Owner::Nobody;
        }
        if message.uid == self.uid {
            Owner::Us
        } else {
            Owner::AnotherUser
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

    use std::net::Shutdown;
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

    /// A peer that closed its socket has no file for the kernel to read an owner from, so no
    /// lookup can attribute it to anybody and the relay serves it whoever asks. That is what
    /// keeps the program's own connection, and what another local user can reach for (see the
    /// module documentation). The kernel answers this way from the close onwards, before it
    /// replaces the socket with a timewait record.
    #[test]
    fn a_peer_that_closed_its_socket_has_no_owner() {
        let check = PeerCheck::open().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        let local = accepted.local_addr().unwrap();
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(20);
        while check.owner(peer, local) != Owner::Nobody {
            assert!(Instant::now() < deadline, "the peer kept an owner");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(check.may_relay(peer, local));
        assert!(as_another_user(&check).may_relay(peer, local));
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
