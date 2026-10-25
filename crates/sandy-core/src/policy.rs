use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

pub const POLICY_VERSION: u32 = 1;

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
    pub windows: WindowsPolicy,
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
            windows: WindowsPolicy::default(),
        }
    }
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Policy, PolicyError> {
        let policy: Policy =
            toml::from_str(text).map_err(|error| PolicyError::Parse(error.to_string()))?;
        if policy.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(policy.version));
        }
        Ok(policy)
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
    /// the subnets of the host's interfaces.
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
    ContainedChildrenNeedIsolatedSignals,
    EndWithParentNeedsIsolatedSignals,
    ProgramNotAFile(PathBuf),
    InvalidEnvironmentName(String),
    InvalidEnvironmentValue(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyError::PathNotFound { source, .. } | PolicyError::Unreadable { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
