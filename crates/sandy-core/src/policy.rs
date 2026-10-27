use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

pub const POLICY_VERSION: u32 = 1;

/// The longest policy sandy reads, from a file or from standard input. Real policies are a few
/// KiB; this leaves room for thousands of paths.
pub const MAX_POLICY_LEN: usize = 1024 * 1024;

/// The deepest nesting of arrays and inline tables a policy may use; a policy needs a few
/// levels. The TOML parser recurses once per level, and input it rejects can get past its own
/// limit (its error recovery closes brackets it never opened), so deeper input overflowed the
/// stack before the parse failed: on a 1 MiB stack, from about 3 KiB of input.
pub const MAX_POLICY_NESTING: usize = 32;

/// A sandbox policy as written by the user. Everything that is not allowed is denied.
///
/// Unknown fields are rejected, so a misspelled key never turns into a silent default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub process: ProcessPolicy,
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    #[serde(default)]
    pub linux: LinuxPolicy,
    #[serde(default)]
    pub macos: MacosPolicy,
    #[serde(default)]
    pub windows: WindowsPolicy,
    /// Weaker variants of this policy, strongest first (`[[fallback]]`). `check` and `run` take
    /// the first of the base and these levels that the host can enforce (DESIGN.md, "Fallback
    /// levels").
    #[serde(default)]
    pub fallback: Vec<Fallback>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: POLICY_VERSION,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            process: ProcessPolicy::default(),
            environment: EnvironmentPolicy::default(),
            linux: LinuxPolicy::default(),
            macos: MacosPolicy::default(),
            windows: WindowsPolicy::default(),
            fallback: Vec::new(),
        }
    }
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Policy, PolicyError> {
        if text.len() > MAX_POLICY_LEN {
            return Err(PolicyError::TooLong(text.len()));
        }
        check_nesting(text)?;
        let policy: Policy =
            toml::from_str(text).map_err(|error| PolicyError::Parse(error.to_string()))?;
        if policy.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(policy.version));
        }
        policy.check_level_names()?;
        Ok(policy)
    }

    /// The base and then every fallback level, each as a whole policy without levels: the base
    /// with the keys that level sets. Levels do not build on each other.
    pub fn levels(&self) -> Vec<Level> {
        let mut base = self.clone();
        base.fallback.clear();
        let mut levels = vec![Level {
            name: BASE_LEVEL.to_string(),
            policy: base.clone(),
        }];
        for fallback in &self.fallback {
            let mut policy = base.clone();
            fallback.apply(&mut policy);
            levels.push(Level {
                name: fallback.name.clone(),
                policy,
            });
        }
        levels
    }

    fn check_level_names(&self) -> Result<(), PolicyError> {
        let mut names = vec![BASE_LEVEL];
        for fallback in &self.fallback {
            let name = fallback.name.as_str();
            let valid = !name.is_empty()
                && name.len() <= MAX_LEVEL_NAME
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !valid {
                return Err(PolicyError::InvalidLevelName(name.to_string()));
            }
            if names.contains(&name) {
                return Err(PolicyError::DuplicateLevelName(name.to_string()));
            }
            names.push(name);
        }
        Ok(())
    }
}

/// Refuses a policy nested deeper than `MAX_POLICY_NESTING`, counted on the tokens of the TOML
/// lexer before the parser sees them, so a bracket inside a string or a comment does not count.
/// The parser opens a level only on a `[` or `{` and closes it only on the matching `]` or `}`;
/// this count closes its innermost level only on that same token, so it never has fewer levels
/// open than the parser.
fn check_nesting(text: &str) -> Result<(), PolicyError> {
    use toml_parser::lexer::TokenKind;

    let mut open = Vec::with_capacity(MAX_POLICY_NESTING);
    for token in toml_parser::Source::new(text).lex() {
        match token.kind() {
            TokenKind::LeftSquareBracket | TokenKind::LeftCurlyBracket => {
                if open.len() == MAX_POLICY_NESTING {
                    return Err(PolicyError::TooDeep);
                }
                open.push(token.kind());
            }
            TokenKind::RightSquareBracket if open.last() == Some(&TokenKind::LeftSquareBracket) => {
                open.pop();
            }
            TokenKind::RightCurlyBracket if open.last() == Some(&TokenKind::LeftCurlyBracket) => {
                open.pop();
            }
            _ => {}
        }
    }
    Ok(())
}

/// The name of the policy's own settings among its levels.
pub const BASE_LEVEL: &str = "base";

/// The longest name a fallback level may have.
pub const MAX_LEVEL_NAME: usize = 32;

/// One level of a policy, as `Policy::levels` gives it: a whole policy without levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    pub name: String,
    pub policy: Policy,
}

/// A fallback level: the base policy with some of its hardening keys replaced. Only the keys
/// that choose how strongly the program is isolated may differ between levels; its files,
/// environment and ports stay the same, so the program finds the same things in every level and
/// the path rules, checked once, cover all of them. Any other key in a level is an error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fallback {
    pub name: String,
    #[serde(default)]
    pub filesystem: FallbackFilesystem,
    #[serde(default)]
    pub network: FallbackNetwork,
    #[serde(default)]
    pub process: FallbackProcess,
    #[serde(default)]
    pub linux: FallbackLinux,
    #[serde(default)]
    pub macos: FallbackMacos,
    #[serde(default)]
    pub windows: FallbackWindows,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackFilesystem {
    pub view: Option<FileView>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackNetwork {
    pub ip: Option<IpAccess>,
    pub unix_sockets: Option<NetworkAccess>,
    /// A broker of its own, or `"none"` for no broker.
    pub egress: Option<FallbackEgress>,
}

/// `network.egress` in a fallback level: a broker table as in the base, or the string `"none"`,
/// which removes the base's broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackEgress {
    None,
    Broker(Egress),
}

impl<'de> Deserialize<'de> for FallbackEgress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = FallbackEgress;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an egress table or \"none\"")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<FallbackEgress, E> {
                match value {
                    "none" => Ok(FallbackEgress::None),
                    other => Err(E::invalid_value(serde::de::Unexpected::Str(other), &self)),
                }
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<FallbackEgress, A::Error> {
                Egress::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(FallbackEgress::Broker)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackProcess {
    pub signals: Option<SignalScope>,
    pub children: Option<ChildProcesses>,
    pub end_with_parent: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackLinux {
    pub path_metadata: Option<PathMetadata>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackMacos {
    pub relays: Option<Relays>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackWindows {
    pub win32k: Option<Win32k>,
    pub appcontainer_name: Option<String>,
}

impl Fallback {
    /// Whether this level sets `key`, written as in the policy (`network.ip`).
    pub fn sets(&self, key: &str) -> bool {
        self.keys().contains(&key)
    }

    /// The keys this level sets, written as in the policy.
    pub fn keys(&self) -> Vec<&'static str> {
        [
            ("filesystem.view", self.filesystem.view.is_some()),
            ("network.ip", self.network.ip.is_some()),
            ("network.unix_sockets", self.network.unix_sockets.is_some()),
            ("network.egress", self.network.egress.is_some()),
            ("process.signals", self.process.signals.is_some()),
            ("process.children", self.process.children.is_some()),
            (
                "process.end_with_parent",
                self.process.end_with_parent.is_some(),
            ),
            ("linux.path_metadata", self.linux.path_metadata.is_some()),
            ("macos.relays", self.macos.relays.is_some()),
            ("windows.win32k", self.windows.win32k.is_some()),
            (
                "windows.appcontainer_name",
                self.windows.appcontainer_name.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(key, set)| set.then_some(key))
        .collect()
    }

    fn apply(&self, policy: &mut Policy) {
        if let Some(view) = self.filesystem.view {
            policy.filesystem.view = view;
        }
        if let Some(ip) = self.network.ip {
            policy.network.ip = ip;
        }
        if let Some(unix_sockets) = self.network.unix_sockets {
            policy.network.unix_sockets = unix_sockets;
        }
        match self.network.egress {
            Some(FallbackEgress::None) => policy.network.egress = None,
            Some(FallbackEgress::Broker(egress)) => policy.network.egress = Some(egress),
            None => {}
        }
        if let Some(signals) = self.process.signals {
            policy.process.signals = signals;
        }
        if let Some(children) = self.process.children {
            policy.process.children = children;
        }
        if let Some(end_with_parent) = self.process.end_with_parent {
            policy.process.end_with_parent = end_with_parent;
        }
        if let Some(path_metadata) = self.linux.path_metadata {
            policy.linux.path_metadata = path_metadata;
        }
        if let Some(relays) = self.macos.relays {
            policy.macos.relays = relays;
        }
        if let Some(win32k) = self.windows.win32k {
            policy.windows.win32k = win32k;
        }
        if let Some(name) = &self.windows.appcontainer_name {
            policy.windows.appcontainer_name = Some(name.clone());
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub system: SystemAccess,
    /// Read files and list directories.
    #[serde(default)]
    pub read: Vec<PathBuf>,
    /// Read, list and execute.
    #[serde(default)]
    pub read_exec: Vec<PathBuf>,
    /// Read, list, create, modify and delete. Never execute.
    #[serde(default)]
    pub read_write: Vec<PathBuf>,
    /// Whether paths outside the policy are visible to the target.
    #[serde(default)]
    pub view: FileView,
}

/// What the target sees of the paths outside the policy (and the system set).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileView {
    /// They exist for the target as on the host; the sandbox denies access to them.
    #[default]
    All,
    /// They look missing: every call that names one answers as for a path that does not exist.
    Policy,
}

impl FileView {
    /// The value as the policy writes it.
    pub fn name(self) -> &'static str {
        match self {
            FileView::All => "all",
            FileView::Policy => "policy",
        }
    }
}

/// Which operating system files the target may use in addition to the policy paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemAccess {
    /// The backend adds the minimal read-only set of system paths that typical programs need to
    /// start (shared libraries, loader configuration, time zone data, random devices).
    #[default]
    Minimal,
    /// Only the policy paths. Useful for static programs.
    None,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// IPv4 and IPv6 networking, including loopback.
    #[serde(default)]
    pub ip: IpAccess,
    /// Connecting to Unix domain sockets (pathname and abstract). With `all`, the target can
    /// reach every Unix socket the user can reach, independent of the filesystem rules.
    #[serde(default)]
    pub unix_sockets: NetworkAccess,
    /// Loopback ports of the target that clients outside the sandbox can reach through a relay.
    #[serde(default)]
    pub expose: Vec<ExposedPort>,
    /// Loopback services outside the sandbox that the target can reach through a relay.
    #[serde(default)]
    pub forward: Vec<ForwardedPort>,
    /// A SOCKS5 broker through which a target with `ip = "private"` connects out.
    #[serde(default)]
    pub egress: Option<Egress>,
}

/// A broker that lets a target with `ip = "private"` connect out to the destinations `reach`
/// allows, and nowhere else.
///
/// The target connects to `port` on 127.0.0.1 and asks for a destination with SOCKS5 CONNECT
/// (RFC 1928), as an IPv4 or IPv6 address. sandy checks the destination outside the sandbox,
/// connects to it and relays the bytes. Names are refused, so the broker resolves nothing for the
/// target. Only TCP goes out this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub port: u16,
    #[serde(default)]
    pub reach: EgressReach,
}

impl Egress {
    /// The address inside the sandbox that the target connects to.
    pub fn listen(&self) -> SocketAddr {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), self.port)
    }
}

/// Which destinations the egress broker connects to. The host itself, under any of its
/// addresses, is never one of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressReach {
    /// Globally reachable unicast addresses only (`sandy_core::destination`).
    #[default]
    Public,
    /// Public addresses and the local network: the private, shared and unique local ranges and
    /// every network the host reaches without a router (`destination::HostNetwork::subnets`).
    PublicAndLocal,
}

impl EgressReach {
    /// The value as the policy writes it.
    pub fn name(self) -> &'static str {
        match self {
            EgressReach::Public => "public",
            EgressReach::PublicAndLocal => "public-and-local",
        }
    }
}

/// A relay that makes a loopback port of the target reachable from outside the sandbox.
///
/// sandy accepts connections on `listen` and forwards each one to `port` on the loopback address
/// of the same family (127.0.0.1 or ::1), where the target listens. Windows blocks every inbound
/// loopback connection into an AppContainer, so this is the only way to reach a sandboxed server
/// there; the other platforms relay the same way, so a policy means the same everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposedPort {
    pub listen: SocketAddr,
    pub port: u16,
}

impl ExposedPort {
    /// The address the relay connects to inside the sandbox.
    pub fn target(&self) -> SocketAddr {
        let ip: std::net::IpAddr = if self.listen.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        };
        SocketAddr::new(ip, self.port)
    }
}

/// A relay that lets the target reach a loopback service outside the sandbox.
///
/// The target connects to `port` on the loopback address of the same family as `to`, and sandy
/// relays each connection to `to` outside the sandbox. Windows blocks loopback connections from an
/// AppContainer to processes outside it unless an administrator installs an exemption; the relay
/// needs no exemption. The other platforms relay the same way, so a policy means the same
/// everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedPort {
    pub port: u16,
    pub to: SocketAddr,
}

impl ForwardedPort {
    /// The address inside the sandbox that the target connects to.
    pub fn listen(&self) -> SocketAddr {
        let ip: std::net::IpAddr = if self.to.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        };
        SocketAddr::new(ip, self.port)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAccess {
    #[default]
    None,
    All,
}

/// What the target may do over IPv4 and IPv6, loopback included.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpAccess {
    #[default]
    None,
    /// IP only among the target's own processes, on a loopback that belongs to the sandbox. The
    /// host, the local network and the internet are reachable only through `expose`, `forward`
    /// and `egress`.
    Private,
    /// Connections and datagrams the target starts, name resolution included, but no listening
    /// socket and no accepted connection. What a datagram socket receives differs per platform
    /// (DESIGN.md, "Requirements and the enforcement plan").
    Client,
    All,
}

impl IpAccess {
    /// The value as the policy writes it.
    pub fn name(self) -> &'static str {
        match self {
            IpAccess::None => "none",
            IpAccess::Private => "private",
            IpAccess::Client => "client",
            IpAccess::All => "all",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub signals: SignalScope,
    #[serde(default)]
    pub children: ChildProcesses,
    /// End the target when the process that started sandy ends.
    #[serde(default)]
    pub end_with_parent: bool,
}

/// Whether the target may start other processes. Threads are always allowed, and so is replacing
/// the target's own program image with `execve`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChildProcesses {
    /// Children are allowed; they inherit the sandbox. Whether they can outlive the target
    /// depends on the platform.
    #[default]
    Allowed,
    /// The target cannot create processes. Nothing it starts can outlive it in the sandbox.
    None,
    /// Children are allowed and inherit the sandbox. When the target ends, sandy ends every
    /// process the target started, directly or through its children.
    Contained,
}

impl ChildProcesses {
    /// The value as the policy writes it.
    pub fn name(self) -> &'static str {
        match self {
            ChildProcesses::Allowed => "allowed",
            ChildProcesses::None => "none",
            ChildProcesses::Contained => "contained",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalScope {
    /// The target may signal every process of the user. Some platforms cannot restrict this.
    #[default]
    Any,
    /// The target may signal only processes inside the same sandbox.
    Isolated,
}

/// The target starts with an empty environment plus these variables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    /// Names of variables copied from the environment of sandy, if present.
    #[serde(default)]
    pub pass: Vec<String>,
    /// Variables set to fixed values. They override `pass`.
    #[serde(default)]
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicy {
    #[serde(default)]
    pub path_metadata: PathMetadata,
}

/// Whether the target may change permissions, owner, timestamps and extended attributes through
/// calls that take a path (`chmod`, `chown`, `utimensat`, `setxattr`).
///
/// Landlock does not control these calls, so on Linux sandy can protect files outside the
/// policy only by denying the path-based calls everywhere, also inside writable paths. The calls
/// on an open file (`fchmod`, `fchown`, `futimens`, `fsetxattr`) keep working. Programs that
/// change metadata by path (`tar`, `cp -p`, `install`) need `allow`. Other platforms protect
/// metadata outside the writable paths in every case; there `allow` only drops the requirement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathMetadata {
    #[default]
    Deny,
    /// The target can change the metadata of every file the user owns, also outside the
    /// policy paths.
    Allow,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosPolicy {
    #[serde(default)]
    pub relays: Relays,
}

/// How the target reaches its forwarded ports and the egress broker under `ip = "private"`.
///
/// A Seatbelt rule can name a port only at every address of the Mac, and for an IPv6 link-local
/// address it ignores the scope, so with `dual-stack` the program can connect to those ports at a
/// link-local address of the Mac on another link, where another host may have it (docs/macos.md,
/// "The private network"). `ipv4` allows the ports over IPv4 only, which closes that route and
/// costs the program its IPv6 sockets there: one that connects to 127.0.0.1 as
/// `::ffff:127.0.0.1`, as Java and .NET do by default, is denied. Other platforms have no such
/// route, so there the requirement holds without a mechanism.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Relays {
    #[default]
    DualStack,
    Ipv4,
}

impl Relays {
    /// The value as the policy writes it.
    pub fn name(self) -> &'static str {
        match self {
            Relays::DualStack => "dual-stack",
            Relays::Ipv4 => "ipv4",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPolicy {
    /// Stable name of the AppContainer profile. Required on Windows. Access grants and the
    /// loopback exemption are bound to this name.
    #[serde(default)]
    pub appcontainer_name: Option<String>,
    #[serde(default)]
    pub win32k: Win32k,
}

/// Whether the target may make the system calls of win32k, the part of the Windows kernel that
/// serves windows, input and drawing (`user32.dll` and `gdi32.dll` call it).
///
/// A command-line program needs none of them, but many load `user32.dll`, which calls win32k
/// when it loads, and these end at startup under `deny` (docs/windows.md, "Win32k"). `deny`
/// takes this part of the kernel out of the program's reach. Other platforms have no win32k, so
/// there the requirement holds without a mechanism.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Win32k {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug)]
pub enum PolicyError {
    /// The length of the text, longer than `MAX_POLICY_LEN`.
    TooLong(usize),
    TooDeep,
    Parse(String),
    UnsupportedVersion(u32),
    RelativePath(PathBuf),
    PathNotFound {
        path: PathBuf,
        source: io::Error,
    },
    WritableAndExecutable {
        writable: PathBuf,
        executable: PathBuf,
        /// How the two paths lead to one file: nesting, or a second name of the file.
        relation: &'static str,
    },
    ResolvedThroughWritable {
        path: PathBuf,
        entry: PathBuf,
        writable: PathBuf,
    },
    InsideWritable {
        path: PathBuf,
        writable: PathBuf,
    },
    TrustedFileWritable {
        path: PathBuf,
        /// The name through which a writable path reaches the file: the file itself, an entry
        /// on the way to it, or a second name of it.
        through: PathBuf,
        writable: PathBuf,
    },
    Unreadable {
        path: PathBuf,
        source: io::Error,
    },
    InvalidExpose {
        expose: ExposedPort,
        reason: &'static str,
    },
    InvalidForward {
        forward: ForwardedPort,
        reason: &'static str,
    },
    InvalidEgress {
        egress: Egress,
        reason: &'static str,
    },
    ChildrenNeedUnixSocketsDenied(ChildProcesses),
    Ipv4RelaysNeedPrivateNetwork,
    ContainedChildrenNeedIsolatedSignals,
    EndWithParentNeedsIsolatedSignals,
    ProgramNotAFile(PathBuf),
    InvalidEnvironmentName(String),
    InvalidEnvironmentValue(String),
    InvalidLevelName(String),
    DuplicateLevelName(String),
    /// Two levels would run in one AppContainer.
    SharedAppContainerName {
        first: String,
        second: String,
        name: String,
    },
    /// One level names an AppContainer and another names none.
    MissingAppContainerName {
        level: String,
        named: String,
    },
    /// A level is not valid as a policy of its own.
    InvalidLevel {
        level: String,
        error: Box<PolicyError>,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::TooLong(len) => write!(
                f,
                "the policy is {len} bytes long, more than the {} KiB a policy may have",
                MAX_POLICY_LEN / 1024
            ),
            PolicyError::TooDeep => write!(
                f,
                "the policy nests arrays and inline tables deeper than {MAX_POLICY_NESTING} levels"
            ),
            PolicyError::Parse(message) => write!(f, "invalid policy: {message}"),
            PolicyError::UnsupportedVersion(version) => write!(
                f,
                "unsupported policy version {version}, expected {POLICY_VERSION}"
            ),
            PolicyError::RelativePath(path) => {
                write!(f, "path must be absolute: {}", path.display())
            }
            PolicyError::PathNotFound { path, source } => {
                write!(f, "cannot resolve path {}: {source}", path.display())
            }
            PolicyError::WritableAndExecutable {
                writable,
                executable,
                relation,
            } => write!(
                f,
                "writable path {} {relation} executable path {}; a path must not be both writable and executable",
                writable.display(),
                executable.display()
            ),
            PolicyError::ResolvedThroughWritable {
                path,
                entry,
                writable,
            } => write!(
                f,
                "policy path {} is resolved through {}, which lies inside writable path {}; the \
                 program could change where it leads before the next start",
                path.display(),
                entry.display(),
                writable.display()
            ),
            PolicyError::InsideWritable { path, writable } => write!(
                f,
                "policy path {} lies inside writable path {}; the program could replace it with a symbolic link before the next start",
                path.display(),
                writable.display()
            ),
            PolicyError::TrustedFileWritable {
                path,
                through,
                writable,
            } if through == path => write!(
                f,
                "{} lies inside writable path {}; the program could change it before the next \
                 start",
                path.display(),
                writable.display()
            ),
            PolicyError::TrustedFileWritable {
                path,
                through,
                writable,
            } => write!(
                f,
                "{} is reachable as {}, inside writable path {}; the program could change it \
                 before the next start",
                path.display(),
                through.display(),
                writable.display()
            ),
            PolicyError::Unreadable { path, source } => write!(
                f,
                "cannot read {}, which sandy checks before it starts the program: {source}",
                path.display()
            ),
            PolicyError::ChildrenNeedUnixSocketsDenied(children) => write!(
                f,
                "children = \"{}\" needs unix_sockets = \"none\": through a Unix socket the program could ask a service of the user to start a process that outlives it",
                children.name()
            ),
            PolicyError::EndWithParentNeedsIsolatedSignals => f.write_str(
                "end_with_parent needs signals = \"isolated\": otherwise the program could kill the process that ends it",
            ),
            PolicyError::ContainedChildrenNeedIsolatedSignals => f.write_str(
                "children = \"contained\" needs signals = \"isolated\": otherwise the program could kill sandy, and the processes it started would outlive it",
            ),
            PolicyError::InvalidForward { forward, reason } => write!(
                f,
                "invalid forward port {} -> {}: {reason}",
                forward.port, forward.to
            ),
            PolicyError::InvalidEgress { egress, reason } => {
                write!(f, "invalid egress port {}: {reason}", egress.port)
            }
            PolicyError::Ipv4RelaysNeedPrivateNetwork => f.write_str(
                "macos.relays = \"ipv4\" needs ip = \"private\": it closes a route of the private \
                 network on macOS, and with any other value the program either has no network or \
                 reaches every address without the relays",
            ),
            PolicyError::InvalidExpose { expose, reason } => write!(
                f,
                "invalid expose {} -> port {}: {reason}",
                expose.listen, expose.port
            ),
            PolicyError::ProgramNotAFile(path) => {
                write!(f, "program is a directory: {}", path.display())
            }
            PolicyError::InvalidEnvironmentName(name) => {
                write!(f, "invalid environment variable name: {name:?}")
            }
            PolicyError::InvalidEnvironmentValue(name) => {
                write!(f, "invalid value for environment variable {name}")
            }
            PolicyError::InvalidLevelName(name) => write!(
                f,
                "invalid fallback level name {name:?}: use 1 to {MAX_LEVEL_NAME} characters of \
                 a-z, 0-9 and '-'"
            ),
            PolicyError::DuplicateLevelName(name) => write!(
                f,
                "fallback level name {name:?} is used twice; every level needs a name of its \
                 own, and {BASE_LEVEL:?} names the base"
            ),
            PolicyError::SharedAppContainerName {
                first,
                second,
                name,
            } => write!(
                f,
                "levels {first} and {second} share the AppContainer name {name:?}; give each \
                 level a windows.appcontainer_name of its own, because on Windows levels that \
                 share one share the loopback exemption, the running instance and the profile \
                 folder"
            ),
            PolicyError::MissingAppContainerName { level, named } => write!(
                f,
                "level {level} names no AppContainer while level {named} does; give each level a \
                 windows.appcontainer_name of its own"
            ),
            PolicyError::InvalidLevel { level, error } => write!(f, "level {level}: {error}"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyError::PathNotFound { source, .. } | PolicyError::Unreadable { source, .. } => {
                Some(source)
            }
            PolicyError::InvalidLevel { error, .. } => Some(error.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_nested_deeper_than_the_limit_is_refused() {
        let nested = |levels| {
            format!(
                "version = 1\nx = {}{}",
                "[".repeat(levels),
                "]".repeat(levels)
            )
        };
        assert!(matches!(
            Policy::from_toml(&nested(MAX_POLICY_NESTING + 1)),
            Err(PolicyError::TooDeep)
        ));
        // At the limit the parser decides, and `x` is no key of a policy.
        assert!(matches!(
            Policy::from_toml(&nested(MAX_POLICY_NESTING)),
            Err(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn brackets_the_parser_does_not_open_do_not_lower_the_count() {
        // The parser's error recovery closes a `{}` in the key position of an inline table that
        // it never opened, which took input past toml's own limit and overflowed the stack.
        let recovery = format!("a = {{{}b = {}", "{}".repeat(1000), "[".repeat(1100));
        assert!(matches!(
            Policy::from_toml(&recovery),
            Err(PolicyError::TooDeep)
        ));
        // A bracket of the other kind closes nothing.
        let mismatched = format!("a = {}", "[}".repeat(MAX_POLICY_NESTING + 1));
        assert!(matches!(
            Policy::from_toml(&mismatched),
            Err(PolicyError::TooDeep)
        ));
    }

    #[test]
    fn brackets_in_strings_and_comments_do_not_count() {
        let text = format!(
            "version = 1\n# {}\n[filesystem]\nread = [\"/a{}\", '/b{}', \"\"\"/c{}\"\"\"]\n",
            "[".repeat(100),
            "[".repeat(100),
            "{".repeat(100),
            "[".repeat(100),
        );
        let policy = Policy::from_toml(&text).unwrap();
        assert_eq!(policy.filesystem.read.len(), 3);
    }

    #[test]
    fn a_policy_longer_than_the_limit_is_refused() {
        let start = "version = 1\n#";
        let longest = format!("{start}{}", "x".repeat(MAX_POLICY_LEN - start.len()));
        assert!(Policy::from_toml(&longest).is_ok());
        let longer = format!("{longest}x");
        assert!(matches!(
            Policy::from_toml(&longer),
            Err(PolicyError::TooLong(len)) if len == MAX_POLICY_LEN + 1
        ));
    }

    #[test]
    fn empty_policy_denies_everything_optional() {
        let policy = Policy::from_toml("version = 1").unwrap();
        assert_eq!(policy, Policy::default());
        assert_eq!(policy.network.ip, IpAccess::None);
        assert_eq!(policy.network.unix_sockets, NetworkAccess::None);
        assert_eq!(policy.filesystem.system, SystemAccess::Minimal);
        assert_eq!(policy.linux.path_metadata, PathMetadata::Deny);
        assert_eq!(policy.process.children, ChildProcesses::Allowed);
        assert_eq!(policy.windows.win32k, Win32k::Allow);
        assert_eq!(policy.macos.relays, Relays::DualStack);
        assert_eq!(policy.filesystem.view, FileView::All);
        assert_eq!(policy.network.egress, None);
    }

    #[test]
    fn parses_all_sections() {
        let policy = Policy::from_toml(
            r#"
            version = 1
            [filesystem]
            system = "none"
            read = ["/a"]
            read_exec = ["/b"]
            read_write = ["/c"]
            [network]
            ip = "all"
            unix_sockets = "none"
            expose = [{ listen = "127.0.0.1:18080", port = 8080 }]
            forward = [{ port = 18081, to = "127.0.0.1:8081" }]
            [process]
            signals = "isolated"
            children = "none"
            [environment]
            pass = ["LANG"]
            set = { HOME = "/c" }
            [linux]
            path_metadata = "allow"
            [macos]
            relays = "ipv4"
            [windows]
            appcontainer_name = "example"
            win32k = "deny"
            "#,
        )
        .unwrap();
        assert_eq!(policy.filesystem.system, SystemAccess::None);
        assert_eq!(policy.filesystem.read_write, vec![PathBuf::from("/c")]);
        assert_eq!(policy.network.ip, IpAccess::All);
        assert_eq!(
            policy.network.expose,
            vec![ExposedPort {
                listen: "127.0.0.1:18080".parse().unwrap(),
                port: 8080,
            }]
        );
        assert_eq!(
            policy.network.expose[0].target(),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            policy.network.forward,
            vec![ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap(),
            }]
        );
        assert_eq!(
            policy.network.forward[0].listen(),
            "127.0.0.1:18081".parse().unwrap()
        );
        assert_eq!(policy.process.signals, SignalScope::Isolated);
        assert_eq!(policy.process.children, ChildProcesses::None);
        assert_eq!(policy.environment.set["HOME"], "/c");
        assert_eq!(policy.linux.path_metadata, PathMetadata::Allow);
        assert_eq!(policy.macos.relays, Relays::Ipv4);
        assert_eq!(policy.windows.appcontainer_name.as_deref(), Some("example"));
        assert_eq!(policy.windows.win32k, Win32k::Deny);
    }

    #[test]
    fn ip_takes_client_and_unix_sockets_does_not() {
        let policy = Policy::from_toml("version = 1\n[network]\nip = \"client\"").unwrap();
        assert_eq!(policy.network.ip, IpAccess::Client);
        let error =
            Policy::from_toml("version = 1\n[network]\nunix_sockets = \"client\"").unwrap_err();
        assert!(matches!(error, PolicyError::Parse(_)), "{error}");
    }

    #[test]
    fn parses_the_private_network_and_the_view() {
        let policy = Policy::from_toml(
            r#"
            version = 1
            [filesystem]
            view = "policy"
            [network]
            ip = "private"
            egress = { port = 1080 }
            "#,
        )
        .unwrap();
        assert_eq!(policy.filesystem.view, FileView::Policy);
        assert_eq!(policy.network.ip, IpAccess::Private);
        let egress = policy.network.egress.unwrap();
        assert_eq!(egress.reach, EgressReach::Public);
        assert_eq!(egress.listen(), "127.0.0.1:1080".parse().unwrap());
        let local = Policy::from_toml(
            "version = 1\n[network]\negress = { port = 1, reach = \"public-and-local\" }",
        )
        .unwrap();
        assert_eq!(
            local.network.egress.unwrap().reach,
            EgressReach::PublicAndLocal
        );
        for bad in [
            "version = 1\n[network]\negress = { port = 1, reach = \"local\" }",
            "version = 1\n[network]\negress = { port = 1, host = \"x\" }",
            "version = 1\n[filesystem]\nview = \"none\"",
        ] {
            assert!(
                matches!(Policy::from_toml(bad), Err(PolicyError::Parse(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn relays_take_dual_stack_and_ipv4_only() {
        let policy = Policy::from_toml("version = 1\n[macos]\nrelays = \"dual-stack\"").unwrap();
        assert_eq!(policy.macos.relays, Relays::DualStack);
        for bad in [
            "version = 1\n[macos]\nrelays = \"ipv6\"",
            "version = 1\n[macos]\nrelays = \"dual_stack\"",
            "version = 1\n[macos]\nrelay = \"ipv4\"",
        ] {
            assert!(
                matches!(Policy::from_toml(bad), Err(PolicyError::Parse(_))),
                "{bad}"
            );
        }
    }

    const LEVELS: &str = r#"
        version = 1
        [filesystem]
        read = ["/a"]
        view = "policy"
        [network]
        ip = "private"
        egress = { port = 1080 }
        [process]
        signals = "isolated"
        end_with_parent = true

        [[fallback]]
        name = "contained"
        filesystem.view = "all"
        process.children = "contained"

        [[fallback]]
        name = "host-network"
        network.ip = "all"
        network.egress = "none"
        filesystem.view = "all"
        process.signals = "any"
        process.end_with_parent = false
    "#;

    /// Each level is the base plus its own keys; levels do not build on each other, and they
    /// keep their order.
    #[test]
    fn a_level_is_the_base_with_its_own_keys() {
        let policy = Policy::from_toml(LEVELS).unwrap();
        let levels = policy.levels();
        let names: Vec<&str> = levels.iter().map(|level| level.name.as_str()).collect();
        assert_eq!(names, ["base", "contained", "host-network"]);
        assert!(levels.iter().all(|level| level.policy.fallback.is_empty()));

        let base = &levels[0].policy;
        let mut expected = policy.clone();
        expected.fallback.clear();
        assert_eq!(base, &expected);

        let contained = &levels[1].policy;
        assert_eq!(contained.filesystem.view, FileView::All);
        assert_eq!(contained.process.children, ChildProcesses::Contained);
        assert_eq!(contained.network.ip, IpAccess::Private);
        assert_eq!(contained.network.egress, base.network.egress);
        assert!(contained.process.end_with_parent);

        let host = &levels[2].policy;
        assert_eq!(host.network.ip, IpAccess::All);
        assert_eq!(host.network.egress, None);
        assert_eq!(host.process.signals, SignalScope::Any);
        assert!(!host.process.end_with_parent);
        // Not inherited from "contained".
        assert_eq!(host.process.children, ChildProcesses::Allowed);
        assert_eq!(host.filesystem.read, base.filesystem.read);
    }

    #[test]
    fn a_level_sets_every_hardening_key() {
        let policy = Policy::from_toml(
            r#"
            version = 1
            [[fallback]]
            name = "all-keys"
            filesystem.view = "policy"
            network.ip = "client"
            network.unix_sockets = "all"
            network.egress = { port = 1, reach = "public-and-local" }
            process.signals = "isolated"
            process.children = "none"
            process.end_with_parent = true
            linux.path_metadata = "allow"
            macos.relays = "ipv4"
            windows.win32k = "deny"
            windows.appcontainer_name = "example-level"
            "#,
        )
        .unwrap();
        let fallback = &policy.fallback[0];
        assert_eq!(fallback.keys().len(), 11, "{:?}", fallback.keys());
        assert!(fallback.sets("network.egress"));
        let level = &policy.levels()[1].policy;
        assert_eq!(level.filesystem.view, FileView::Policy);
        assert_eq!(level.network.ip, IpAccess::Client);
        assert_eq!(level.network.unix_sockets, NetworkAccess::All);
        assert_eq!(
            level.network.egress,
            Some(Egress {
                port: 1,
                reach: EgressReach::PublicAndLocal
            })
        );
        assert_eq!(level.process.signals, SignalScope::Isolated);
        assert_eq!(level.process.children, ChildProcesses::None);
        assert!(level.process.end_with_parent);
        assert_eq!(level.linux.path_metadata, PathMetadata::Allow);
        assert_eq!(level.macos.relays, Relays::Ipv4);
        assert_eq!(level.windows.win32k, Win32k::Deny);
        assert_eq!(
            level.windows.appcontainer_name.as_deref(),
            Some("example-level")
        );
        let none = Policy::from_toml("version = 1\n[[fallback]]\nname = \"a\"").unwrap();
        assert!(none.fallback[0].keys().is_empty());
        assert_eq!(none.levels()[1].policy, none.levels()[0].policy);
    }

    /// Paths, `system`, the environment and the relays are the same in every level, so a level
    /// that sets one is an error, as is a misspelled key.
    #[test]
    fn a_level_sets_no_other_key() {
        for key in [
            "filesystem.read = [\"/a\"]",
            "filesystem.read_exec = [\"/a\"]",
            "filesystem.read_write = [\"/a\"]",
            "filesystem.system = \"none\"",
            "network.expose = []",
            "network.forward = []",
            "environment.pass = [\"A\"]",
            "environment.set = { A = \"b\" }",
            "version = 1",
            "fallback = []",
            "network.ipp = \"all\"",
            "network.egress = \"public\"",
            "network.egress = { port = 1, host = \"x\" }",
            "process.end_with_parent = \"yes\"",
        ] {
            let text = format!("version = 1\n[[fallback]]\nname = \"a\"\n{key}");
            assert!(
                matches!(Policy::from_toml(&text), Err(PolicyError::Parse(_))),
                "{key}"
            );
        }
        let nameless = "version = 1\n[[fallback]]\nnetwork.ip = \"all\"";
        assert!(matches!(
            Policy::from_toml(nameless),
            Err(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn level_names_are_short_distinct_and_simple() {
        let named = |names: &[&str]| {
            let mut text = String::from("version = 1\n");
            for name in names {
                text.push_str(&format!("[[fallback]]\nname = {name:?}\n"));
            }
            Policy::from_toml(&text)
        };
        assert!(named(&["a", "b-2", &"x".repeat(MAX_LEVEL_NAME)]).is_ok());
        for bad in [
            "",
            "A",
            "a b",
            "a_b",
            "a.b",
            "\u{e9}",
            &"x".repeat(MAX_LEVEL_NAME + 1),
        ] {
            assert!(
                matches!(named(&[bad]), Err(PolicyError::InvalidLevelName(_))),
                "{bad:?}"
            );
        }
        for names in [&["base"][..], &["a", "a"]] {
            assert!(
                matches!(named(names), Err(PolicyError::DuplicateLevelName(_))),
                "{names:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_field() {
        let error = Policy::from_toml("version = 1\n[network]\nipp = \"all\"").unwrap_err();
        assert!(matches!(error, PolicyError::Parse(_)));
    }

    #[test]
    fn rejects_other_version() {
        let error = Policy::from_toml("version = 2").unwrap_err();
        assert!(matches!(error, PolicyError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_missing_version() {
        assert!(Policy::from_toml("").is_err());
    }
}
