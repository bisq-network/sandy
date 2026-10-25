//! The sockets a caller hands the program on its standard streams.
//!
//! sandy passes descriptors 0, 1 and 2 on as it received them, because that is how a program
//! reads its input and writes its output. No sandbox can take rights away from a socket that is
//! already open: it was created outside, so the policy that denies networking inside never sees
//! it. A socket on a standard stream therefore keeps working, and the program can send, receive
//! or accept through it.
//!
//! `run` looks at the three streams before it applies the sandbox and accepts a socket only when
//! the policy lets the program create one like it, so that the socket gives the program nothing
//! the policy denies. `check` cannot do this: it does not see the streams of a later `run`.

use crate::policy::NetworkAccess;
use crate::resolve::ResolvedPolicy;

/// One of the three streams every program starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardStream {
    Input,
    Output,
    Error,
}

impl StandardStream {
    pub const ALL: [StandardStream; 3] = [
        StandardStream::Input,
        StandardStream::Output,
        StandardStream::Error,
    ];
}

impl std::fmt::Display for StandardStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StandardStream::Input => "standard input",
            StandardStream::Output => "standard output",
            StandardStream::Error => "standard error",
        })
    }
}

/// The address family of a socket, as far as a policy tells families apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Unix,
    /// AF_INET or AF_INET6.
    Ip,
    /// Any other family, by its number on this platform and, where sandy knows it, its name.
    Other {
        number: i32,
        name: Option<&'static str>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stream,
    Seqpacket,
    Datagram,
    /// SOCK_RAW, and on Linux SOCK_PACKET.
    Raw,
    Other,
}

/// A socket that a caller passed on a standard stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socket {
    pub family: Family,
    pub kind: Kind,
    /// The protocol within the family, as the kernel reports it.
    pub protocol: i32,
    /// It has a peer, so `getpeername` answers.
    pub connected: bool,
    pub listening: bool,
}

impl Socket {
    /// Whether the socket gives no more than a pipe gives. A connected Unix stream or seqpacket
    /// socket talks to the peer it already has and to nobody else: it cannot connect again,
    /// listen, or send to another address. Parents pass pipes this way (libuv for the standard
    /// streams of a child, journald, `ssh` without a terminal), so sandy accepts it like a pipe.
    /// What the peer is remains the caller's choice, as with a file on a standard stream.
    fn is_a_pipe(self) -> bool {
        self.family == Family::Unix
            && self.connected
            && !self.listening
            && matches!(self.kind, Kind::Stream | Kind::Seqpacket)
    }

    /// The entry of `ip_also_allows` that this socket is like, if any.
    fn creatable_with_ip(self, ip_also_allows: &[CreatableSocket]) -> Option<CreatableSocket> {
        let Family::Other { number, .. } = self.family else {
            return None;
        };
        ip_also_allows
            .iter()
            .copied()
            .find(|allowed| allowed.family == number && allowed.protocol == self.protocol)
    }

    /// How a message names this socket, with its article.
    fn description(self, ip_also_allows: &[CreatableSocket]) -> String {
        let state = if self.listening {
            "a listening"
        } else if self.connected {
            "a connected"
        } else {
            "an unconnected"
        };
        let kind = match self.kind {
            Kind::Stream => " stream",
            Kind::Seqpacket => " seqpacket",
            Kind::Datagram => " datagram",
            Kind::Raw => " raw",
            Kind::Other => "",
        };
        match self.family {
            Family::Unix => format!("{state} Unix{kind} socket"),
            Family::Ip => format!("{state} IP{kind} socket"),
            Family::Other { number, name } => {
                if let Some(allowed) = self.creatable_with_ip(ip_also_allows) {
                    return format!("{state} {}{kind} socket", allowed.name);
                }
                let mut description = format!("{state}{kind} socket of family {number}");
                if let Some(name) = name {
                    description += &format!(" ({name})");
                }
                if self.protocol != 0 {
                    description += &format!(", protocol {}", self.protocol);
                }
                description
            }
        }
    }
}

/// A socket of a family other than Unix and IP that `ip = "all"` lets the program create on this
/// platform, as the backend enforces it (`Backend::ip_also_allows`), such as route netlink on
/// Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatableSocket {
    /// How a message names such a socket.
    pub name: &'static str,
    pub family: i32,
    /// The one protocol of the family that the backend allows.
    pub protocol: i32,
}

/// Why the policy cannot hold for the socket on `stream`, or `None` when it can. A socket is
/// accepted only when the policy lets the program create one like it; `ip_also_allows` names
/// what `ip = "all"` allows on this platform besides IP sockets.
pub fn refusal(
    policy: &ResolvedPolicy,
    stream: StandardStream,
    socket: Socket,
    ip_also_allows: &[CreatableSocket],
) -> Option<String> {
    let description = socket.description(ip_also_allows);
    let (access, setting, hint) = match socket.family {
        Family::Unix => (
            policy.unix_sockets,
            "unix_sockets",
            Some(
                "only a connected Unix stream or seqpacket socket, which is how a parent passes \
                 a pipe, needs neither",
            ),
        ),
        // An ICMP datagram socket (IPPROTO_ICMP or IPPROTO_ICMPV6) follows `ip` like any other
        // IP datagram socket: an unprivileged program can create one where the kernel allows
        // it, on Linux within net.ipv4.ping_group_range.
        Family::Ip if matches!(socket.kind, Kind::Stream | Kind::Seqpacket | Kind::Datagram) => (
            policy.ip,
            "ip",
            Some(
                "a service that is handed its connection on standard input, inetd-style or with \
                 systemd Accept=yes, needs that",
            ),
        ),
        Family::Other { .. } if socket.creatable_with_ip(ip_also_allows).is_some() => {
            (policy.ip, "ip", None)
        }
        // A raw IP socket needs privileges: CAP_NET_RAW on Linux, which sandy refuses to start
        // with, root on macOS and administrator rights on Windows. It is refused also where the
        // caller has them, so that a policy means the same on every platform.
        Family::Ip | Family::Other { .. } => {
            return Some(format!(
                "{stream} carries {description}; a socket that is open before the sandbox starts \
                 keeps working inside it, and no policy lets the program create one like it. \
                 Pass a pipe, a file or a connected Unix stream socket instead"
            ));
        }
    };
    if access != NetworkAccess::None || socket.is_a_pipe() {
        return None;
    }
    let mut message = format!(
        "{stream} carries {description}; a socket that is open before the sandbox starts keeps \
         working inside it, so {setting} = \"none\" cannot hold for it. Redirect the stream, or \
         allow what the socket gives with {setting} = \"all\""
    );
    if let Some(hint) = hint {
        message += &format!(": {hint}");
    }
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    /// Route netlink as the Linux backend allows it with `ip = "all"`.
    const ROUTE_NETLINK: CreatableSocket = CreatableSocket {
        name: "route netlink",
        family: 16,
        protocol: 0,
    };

    fn policy(ip: NetworkAccess, unix_sockets: NetworkAccess) -> ResolvedPolicy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.unix_sockets = unix_sockets;
        ResolvedPolicy::resolve(&policy, None).unwrap()
    }

    fn every_policy() -> Vec<ResolvedPolicy> {
        let settings = [NetworkAccess::None, NetworkAccess::All];
        settings
            .iter()
            .flat_map(|&ip| settings.iter().map(move |&unix| policy(ip, unix)))
            .collect()
    }

    fn socket(family: Family, kind: Kind, connected: bool, listening: bool) -> Socket {
        Socket {
            family,
            kind,
            protocol: 0,
            connected,
            listening,
        }
    }

    fn other(number: i32, name: Option<&'static str>, kind: Kind, protocol: i32) -> Socket {
        Socket {
            family: Family::Other { number, name },
            kind,
            protocol,
            connected: true,
            listening: false,
        }
    }

    #[test]
    fn a_connected_unix_stream_is_a_pipe_and_stays_allowed() {
        let denied = policy(NetworkAccess::None, NetworkAccess::None);
        for kind in [Kind::Stream, Kind::Seqpacket] {
            let pipe = socket(Family::Unix, kind, true, false);
            for stream in StandardStream::ALL {
                assert_eq!(refusal(&denied, stream, pipe, &[]), None, "{kind:?}");
            }
        }
    }

    #[test]
    fn other_unix_sockets_need_unix_sockets_all() {
        let denied = policy(NetworkAccess::None, NetworkAccess::None);
        let allowed = policy(NetworkAccess::None, NetworkAccess::All);
        let cases = [
            socket(Family::Unix, Kind::Stream, false, false),
            socket(Family::Unix, Kind::Stream, false, true),
            socket(Family::Unix, Kind::Datagram, true, false),
            socket(Family::Unix, Kind::Datagram, false, false),
        ];
        for case in cases {
            let message = refusal(&denied, StandardStream::Input, case, &[]).expect("refused");
            assert!(message.contains("standard input carries"), "{message}");
            assert!(message.contains("unix_sockets = \"none\""), "{message}");
            assert_eq!(refusal(&allowed, StandardStream::Input, case, &[]), None);
        }
    }

    #[test]
    fn ip_sockets_need_ip_all() {
        let denied = policy(NetworkAccess::None, NetworkAccess::All);
        let allowed = policy(NetworkAccess::All, NetworkAccess::None);
        // ICMP datagram sockets of IPv4 and IPv6, which an unprivileged program can create.
        let icmp = |protocol| Socket {
            protocol,
            ..socket(Family::Ip, Kind::Datagram, false, false)
        };
        let cases = [
            socket(Family::Ip, Kind::Stream, true, false),
            socket(Family::Ip, Kind::Stream, false, true),
            socket(Family::Ip, Kind::Seqpacket, true, false),
            socket(Family::Ip, Kind::Datagram, false, false),
            icmp(1),
            icmp(58),
        ];
        for case in cases {
            let message = refusal(&denied, StandardStream::Error, case, &[]).expect("refused");
            assert!(message.contains("standard error carries"), "{message}");
            assert!(message.contains("ip = \"none\""), "{message}");
            assert!(message.contains("inetd-style"), "{message}");
            assert_eq!(refusal(&allowed, StandardStream::Error, case, &[]), None);
        }
    }

    /// Creating a raw IP socket needs privileges the program does not have, so `ip = "all"` does
    /// not let it create one, and an inherited one is refused under every policy.
    #[test]
    fn raw_ip_sockets_are_refused_under_every_policy() {
        let raw = |protocol| Socket {
            protocol,
            ..socket(Family::Ip, Kind::Raw, false, false)
        };
        for policy in every_policy() {
            for case in [
                raw(1),
                raw(255),
                socket(Family::Ip, Kind::Other, false, false),
            ] {
                let message = refusal(&policy, StandardStream::Input, case, &[]).expect("refused");
                assert!(
                    message.contains("no policy lets the program create one like it"),
                    "{message}"
                );
                assert!(!message.contains("\"all\""), "{message}");
            }
            let message = refusal(&policy, StandardStream::Input, raw(1), &[]).unwrap();
            assert!(
                message.starts_with("standard input carries an unconnected IP raw socket;"),
                "{message}"
            );
        }
    }

    /// The program cannot create a socket of another family under any policy, so an inherited
    /// one would give it what no setting grants, and naming a setting would not help.
    #[test]
    fn other_families_are_refused_under_every_policy() {
        let cases = [
            other(40, Some("AF_VSOCK"), Kind::Stream, 0),
            other(38, None, Kind::Seqpacket, 0),
            // The family of route netlink, but sock_diag, which lists every socket of the host.
            other(16, Some("AF_NETLINK"), Kind::Raw, 4),
        ];
        for policy in every_policy() {
            for case in cases {
                let message = refusal(&policy, StandardStream::Input, case, &[ROUTE_NETLINK])
                    .expect("refused");
                assert!(
                    message.contains("no policy lets the program create one like it"),
                    "{message}"
                );
                assert!(message.contains("Pass a pipe"), "{message}");
                assert!(!message.contains("\"all\""), "{message}");
            }
        }
    }

    /// What `ip = "all"` lets the program create besides IP sockets follows `ip` like an IP
    /// socket, with no hint about inetd-style services.
    #[test]
    fn a_socket_that_ip_allows_follows_ip() {
        let route = other(16, Some("AF_NETLINK"), Kind::Raw, 0);
        let allows = [ROUTE_NETLINK];
        let allowed = policy(NetworkAccess::All, NetworkAccess::None);
        assert_eq!(
            refusal(&allowed, StandardStream::Input, route, &allows),
            None
        );
        let denied = policy(NetworkAccess::None, NetworkAccess::All);
        let message = refusal(&denied, StandardStream::Input, route, &allows).expect("refused");
        assert_eq!(
            message,
            "standard input carries a connected route netlink raw socket; a socket that is open \
             before the sandbox starts keeps working inside it, so ip = \"none\" cannot hold for \
             it. Redirect the stream, or allow what the socket gives with ip = \"all\""
        );
        // Without the entry, which is the case on every platform but Linux, it is a family like
        // any other.
        let message = refusal(&allowed, StandardStream::Input, route, &[]).expect("refused");
        assert!(message.contains("no policy lets"), "{message}");
    }

    #[test]
    fn the_message_names_the_socket() {
        let denied = policy(NetworkAccess::None, NetworkAccess::None);
        let listening = socket(Family::Ip, Kind::Stream, false, true);
        let message = refusal(&denied, StandardStream::Output, listening, &[]).unwrap();
        assert!(
            message.starts_with("standard output carries a listening IP stream socket;"),
            "{message}"
        );
        let datagram = socket(Family::Unix, Kind::Datagram, false, false);
        let message = refusal(&denied, StandardStream::Input, datagram, &[]).unwrap();
        assert!(
            message.starts_with("standard input carries an unconnected Unix datagram socket;"),
            "{message}"
        );
        let unnamed = Socket {
            connected: false,
            ..other(38, None, Kind::Datagram, 0)
        };
        let message = refusal(&denied, StandardStream::Input, unnamed, &[]).unwrap();
        assert!(
            message
                .starts_with("standard input carries an unconnected datagram socket of family 38;"),
            "{message}"
        );
        let diag = other(16, Some("AF_NETLINK"), Kind::Raw, 4);
        let message = refusal(&denied, StandardStream::Input, diag, &[ROUTE_NETLINK]).unwrap();
        assert!(
            message.starts_with(
                "standard input carries a connected raw socket of family 16 (AF_NETLINK), protocol \
                 4;"
            ),
            "{message}"
        );
    }
}
