//! The sockets a caller hands the program on its standard streams.
//!
//! sandy passes descriptors 0, 1 and 2 on as it received them, because that is how a program
//! reads its input and writes its output. No sandbox can take rights away from a socket that is
//! already open: it was created outside, so the policy that denies networking inside never sees
//! it. A socket on a standard stream therefore keeps working, and the program can send, receive
//! or accept through it.
//!
//! `run` looks at the three streams before it applies the sandbox and refuses the sockets whose
//! access the policy promises to deny. `check` cannot do this: it does not see the streams of a
//! later `run`.

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
    /// Any other family, by its number on this platform. No policy lets the program create such
    /// a socket, so an inherited one counts as network access like an IP socket.
    Other(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stream,
    Seqpacket,
    Datagram,
    /// Raw sockets and anything else.
    Other,
}

/// A socket that a caller passed on a standard stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socket {
    pub family: Family,
    pub kind: Kind,
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

    /// How a message names this socket, with its article.
    fn description(self) -> String {
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
            Kind::Other => "",
        };
        match self.family {
            Family::Unix => format!("{state} Unix{kind} socket"),
            Family::Ip => format!("{state} IP{kind} socket"),
            Family::Other(number) => format!("{state}{kind} socket of family {number}"),
        }
    }
}

/// Why the policy cannot hold for the socket on `stream`, or `None` when it can.
pub fn refusal(policy: &ResolvedPolicy, stream: StandardStream, socket: Socket) -> Option<String> {
    let (denied, setting, hint) = if socket.family == Family::Unix {
        (
            policy.unix_sockets,
            "unix_sockets",
            "only a connected Unix stream or seqpacket socket, which is how a parent passes a \
             pipe, needs neither",
        )
    } else {
        (
            policy.ip,
            "ip",
            "a service that is handed its connection on standard input, inetd-style or with \
             systemd Accept=yes, needs that",
        )
    };
    if denied != NetworkAccess::None || socket.is_a_pipe() {
        return None;
    }
    Some(format!(
        "{stream} carries {}; a socket that is open before the sandbox starts keeps working \
         inside it, so {setting} = \"none\" cannot hold for it. Redirect the stream, or allow \
         what the socket gives with {setting} = \"all\": {hint}",
        socket.description()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn policy(ip: NetworkAccess, unix_sockets: NetworkAccess) -> ResolvedPolicy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.unix_sockets = unix_sockets;
        ResolvedPolicy::resolve(&policy, None).unwrap()
    }

    fn socket(family: Family, kind: Kind, connected: bool, listening: bool) -> Socket {
        Socket {
            family,
            kind,
            connected,
            listening,
        }
    }

    #[test]
    fn a_connected_unix_stream_is_a_pipe_and_stays_allowed() {
        let denied = policy(NetworkAccess::None, NetworkAccess::None);
        for kind in [Kind::Stream, Kind::Seqpacket] {
            let pipe = socket(Family::Unix, kind, true, false);
            for stream in StandardStream::ALL {
                assert_eq!(refusal(&denied, stream, pipe), None, "{kind:?}");
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
            let message = refusal(&denied, StandardStream::Input, case).expect("refused");
            assert!(message.contains("standard input carries"), "{message}");
            assert!(message.contains("unix_sockets = \"none\""), "{message}");
            assert_eq!(refusal(&allowed, StandardStream::Input, case), None);
        }
    }

    #[test]
    fn ip_and_unknown_families_need_ip_all() {
        let denied = policy(NetworkAccess::None, NetworkAccess::All);
        let allowed = policy(NetworkAccess::All, NetworkAccess::None);
        let cases = [
            socket(Family::Ip, Kind::Stream, true, false),
            socket(Family::Ip, Kind::Stream, false, true),
            socket(Family::Ip, Kind::Datagram, false, false),
            socket(Family::Other(16), Kind::Other, false, false),
        ];
        for case in cases {
            let message = refusal(&denied, StandardStream::Error, case).expect("refused");
            assert!(message.contains("standard error carries"), "{message}");
            assert!(message.contains("ip = \"none\""), "{message}");
            assert_eq!(refusal(&allowed, StandardStream::Error, case), None);
        }
    }

    #[test]
    fn the_message_names_the_socket() {
        let denied = policy(NetworkAccess::None, NetworkAccess::None);
        let listening = socket(Family::Ip, Kind::Stream, false, true);
        let message = refusal(&denied, StandardStream::Output, listening).unwrap();
        assert!(
            message.starts_with("standard output carries a listening IP stream socket;"),
            "{message}"
        );
        let datagram = socket(Family::Unix, Kind::Datagram, false, false);
        let message = refusal(&denied, StandardStream::Input, datagram).unwrap();
        assert!(
            message.starts_with("standard input carries an unconnected Unix datagram socket;"),
            "{message}"
        );
        let other = socket(Family::Other(16), Kind::Datagram, false, false);
        let message = refusal(&denied, StandardStream::Input, other).unwrap();
        assert!(
            message
                .starts_with("standard input carries an unconnected datagram socket of family 16;"),
            "{message}"
        );
    }
}
