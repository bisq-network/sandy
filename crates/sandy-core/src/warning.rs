//! The warnings of `sandy check` and `sandy run`: advice that changes neither what sandy enforces
//! nor its exit status. Each has a stable ID, so a caller that has read a warning and accepted
//! what it says can hide it (`--hide-warning`) and still see every other one.

use std::fmt;

macro_rules! warning_ids {
    ($($(#[$doc:meta])* $variant:ident => $id:literal,)*) => {
        /// The kind of finding a warning reports. The IDs are part of sandy's interface: a
        /// caller names them in `--hide-warning`, so an ID never changes its meaning, and one
        /// that sandy no longer reports stays accepted.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum WarningId {
            $($(#[$doc])* $variant,)*
        }

        impl WarningId {
            /// Every ID, on every platform: a caller passes the same `--hide-warning` options
            /// to sandy on each of them.
            pub const ALL: &[WarningId] = &[$(WarningId::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(WarningId::$variant => $id,)*
                }
            }
        }
    };
}

warning_ids! {
    /// `unix_sockets = "all"`.
    UnixSocketsAll => "unix-sockets-all",
    /// `signals = "any"`.
    SignalsAny => "signals-any",
    /// What the egress broker's answers tell the program about this host's addresses.
    EgressProbing => "egress-probing",
    /// `path_metadata = "allow"`.
    PathMetadataAllow => "path-metadata-allow",
    /// A writable path that holds the home directory.
    WritableHome => "writable-home",
    /// A path that holds /dev/pts, with the terminals of this user.
    TerminalsReachable => "terminals-reachable",
    /// A writable path that reaches a directory on `PATH`.
    WritablePathDirectory => "writable-path-directory",
    /// `macos.mach_services` on a platform without Mach services.
    MachServicesIgnored => "mach-services-ignored",
    /// What the Mach services the policy allows give the program besides their purpose.
    MachServiceReach => "mach-service-reach",
    /// A command line option that replaced a stricter value of the policy file.
    OptionWidensPolicy => "option-widens-policy",
    /// `run` takes a fallback level.
    FallbackLevel => "fallback-level",
    /// `ip = "client"` receives datagrams from every sender on a socket that is not connected.
    IpClientUdp => "ip-client-udp",
    /// `ip = "client"` cannot listen on a Unix socket on Linux.
    IpClientUnixListen => "ip-client-unix-listen",
    /// `ip = "client"` reaches no host of a private or domain network on Windows.
    IpClientPrivateNetworks => "ip-client-private-networks",
    /// `ip = "private"` lets a process of this user enter the network namespace on Linux.
    IpPrivateSameUser => "ip-private-same-user",
    /// `ip = "private"` lets exposed ports listen at every address of this Mac.
    IpPrivateExposedAddresses => "ip-private-exposed-addresses",
    /// `ip = "private"` and an address this Mac gains after the relay started.
    IpPrivateLaterAddresses => "ip-private-later-addresses",
    /// `ip = "private"` and IPv6 link-local addresses on macOS.
    IpPrivateLinkLocal => "ip-private-link-local",
    /// `macos.relays = "ipv4"` refuses IPv6 sockets to the relayed ports.
    RelaysIpv4Only => "relays-ipv4-only",
    /// The program's own processes reach each other over loopback in one AppContainer.
    LoopbackWithinAppcontainer => "loopback-within-appcontainer",
    /// `signals = "isolated"` and the process group of the terminal.
    SignalsIsolatedTerminal => "signals-isolated-terminal",
    /// `signals = "isolated"` leaves SIGIO and SIGURG open on macOS.
    SignalsIsolatedSigio => "signals-isolated-sigio",
    /// Another local user can use a forwarded port.
    ForwardOtherUsers => "forward-other-users",
    /// Another local user can use the egress broker on macOS.
    EgressOtherUsers => "egress-other-users",
    /// The relay can outlive the program on macOS with `signals = "any"`.
    RelayOutlivesProgram => "relay-outlives-program",
    /// `path_metadata = "deny"` and descriptors opened for reading on Linux.
    PathMetadataOpenFiles => "path-metadata-open-files",
    /// `unix_sockets = "all"` tells existing paths from missing ones on macOS.
    UnixSocketsExistence => "unix-sockets-existence",
    /// `view = "policy"` with / readable hides nothing.
    ViewHoldsRoot => "view-holds-root",
    /// What `view = "policy"` leaves visible of the host.
    ViewPartial => "view-partial",
    /// `children = "contained"` denies posix_spawn on macOS.
    ContainedPosixSpawn => "contained-posix-spawn",
    /// An OpenSSL include the policy does not let the program read.
    OpensslInclude => "openssl-include",
    /// A cgroup limit the program cannot see.
    CgroupLimit => "cgroup-limit",
    /// A named AppContainer is shared with every user of the machine.
    AppcontainerShared => "appcontainer-shared",
    /// A grant on Windows follows the file, not the path.
    GrantFollowsFile => "grant-follows-file",
    /// sandy runs in session 0 on Windows.
    SessionZero => "session-zero",
}

impl fmt::Display for WarningId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for WarningId {
    type Err = String;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        WarningId::ALL
            .iter()
            .copied()
            .find(|known| known.as_str() == id)
            .ok_or_else(|| format!("unknown warning ID {id:?}"))
    }
}

/// One warning: its kind and the text for people, which may change between releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub id: WarningId,
    pub text: String,
}

impl Warning {
    pub fn new(id: WarningId, text: impl Into<String>) -> Self {
        Self {
            id,
            text: text.into(),
        }
    }
}

/// `[ID] text`, the form of the `warning:` lines.
impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.id, self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_kebab_case_and_parse_back() {
        let mut seen = HashSet::new();
        for &id in WarningId::ALL {
            let text = id.as_str();
            assert!(seen.insert(text), "{text} twice");
            assert!(
                text.split('-').all(|word| !word.is_empty()
                    && word
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
                "{text}"
            );
            assert_eq!(text.parse::<WarningId>(), Ok(id));
        }
        assert!("signals_any".parse::<WarningId>().is_err());
    }

    #[test]
    fn displays_the_id_before_the_text() {
        let warning = Warning::new(WarningId::SignalsAny, "text");
        assert_eq!(warning.to_string(), "[signals-any] text");
    }
}
