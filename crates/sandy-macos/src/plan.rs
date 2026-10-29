//! The enforcement plan for a host with known capabilities. Pure, so it runs and is tested on
//! every platform.

use std::path::Path;

use sandy_core::{
    ChildProcesses, FileView, IpAccess, MachService, NetworkAccess, PathAccess, PathIdentity,
    PlanItem, ProtectedPath, Relays, Requirement, ResolvedPolicy, SignalScope, Status,
    SystemAccess,
};

use crate::system::{self, SystemAccess as Grant};

/// What the host offers. `MacosBackend` detects it (`detect::Detected`); tests use fixed values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    /// `Ok` when the Seatbelt functions could be loaded, otherwise the reason.
    pub seatbelt: Result<(), String>,
    /// `Ok` when the Seatbelt compiler of this host accepts the generated profiles (the
    /// program's, and the relay's and the watcher's when the policy needs them), otherwise why
    /// not.
    pub profile: Result<(), ProfileError>,
    /// sandy itself already runs in a Seatbelt sandbox. macOS then refuses another profile.
    pub already_sandboxed: bool,
    /// Why the program would run as x86_64 code through Rosetta, if it would. Rosetta cannot load
    /// its runtime inside the sandbox, so such a program never starts.
    pub rosetta: Option<String>,
    /// Why the kernel could not execute the program, if it could not: it is a script whose
    /// interpreter no `read_exec` path covers (`executable_paths`).
    pub interpreter: Option<String>,
    /// The locations of this user that programs outside the sandbox read or execute later
    /// (`trust::locations`), or why sandy cannot name them: no source names the home directory,
    /// or the password database cannot be read.
    pub trusted_locations: Result<Vec<ProtectedPath>, String>,
}

/// Why this macOS did not compile a generated profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The compiler's message: this macOS lacks an operation or a filter that the profile uses.
    /// The profile text depends only on the policy, so that lasts until macOS changes.
    Rejected(String),
    /// The compiler gave no verdict: the library could not create the parameters or the
    /// compiled profile and said nothing, as when memory runs out, which can pass.
    Failed(String),
}

impl ProfileError {
    /// The same error with `name` before its message, for a profile other than the program's.
    pub fn of(self, name: &str) -> ProfileError {
        match self {
            ProfileError::Rejected(message) => ProfileError::Rejected(format!("{name}: {message}")),
            ProfileError::Failed(message) => ProfileError::Failed(format!("{name}: {message}")),
        }
    }
}

/// How many `#!` lines sandy follows when it checks whether the program can be executed. XNU
/// follows more (measured on macOS 26: a script whose interpreter is a script runs), so this
/// never names a level the kernel would not reach, and no real program nests more than one.
pub const SHEBANG_LEVELS: usize = 1;

/// The paths the profile lets the target execute, for `ResolvedPolicy::interpreter_problem`. The
/// system set grants `file-map-executable` for the dynamic loader but no `process-exec*`, so only
/// the policy's `read_exec` paths execute.
pub fn executable_paths(policy: &ResolvedPolicy) -> Vec<std::path::PathBuf> {
    policy
        .paths
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadExec)
        .map(|rule| rule.path.clone())
        .collect()
}

/// Reports every requirement of `policy` exactly once, as enforced (with its mechanism) or not
/// (with the reason). A missing Seatbelt, a sandbox around sandy, code that needs Rosetta and a
/// profile that this macOS rejects are shortfalls of the host that every later run meets too; a
/// writable path that reaches what the sandbox must protect and an interpreter that the policy
/// does not let the program execute are conflicts of the policy; a lookup that failed is
/// indeterminate (`sandy_core::Status`).
pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<PlanItem> {
    let unavailable = |reason| Status::Unavailable { reason };
    let profile = match (
        &host.seatbelt,
        host.already_sandboxed,
        &host.rosetta,
        &host.profile,
    ) {
        (Err(reason), _, _, _) => Err(unavailable(format!("Seatbelt is not available: {reason}"))),
        (Ok(()), true, _, _) => Err(unavailable(
            "sandy already runs in a Seatbelt sandbox, and macOS refuses a second profile"
                .to_string(),
        )),
        (Ok(()), false, Some(reason), _) => Err(unavailable(reason.clone())),
        (Ok(()), false, None, Err(ProfileError::Rejected(message))) => Err(unavailable(format!(
            "this macOS rejects the generated Seatbelt profile: {message}"
        ))),
        (Ok(()), false, None, Err(ProfileError::Failed(message))) => Err(Status::Indeterminate {
            reason: format!("cannot compile the generated Seatbelt profile: {message}"),
        }),
        (Ok(()), false, None, Ok(())) => Ok(()),
    };
    // What ends the selection comes first, so that a shortfall cannot hide it.
    let filesystem = system_conflict(policy)
        .or_else(|| trust_conflict(policy, &host.trusted_locations))
        .or_else(|| {
            let reason = host.interpreter.clone()?;
            Some(Status::Conflict { reason })
        })
        .or_else(|| root_directory_missing(policy).map(unavailable));
    policy
        .requirements()
        .into_iter()
        .map(|requirement| {
            if let (Requirement::FilesystemConfined, Some(status)) = (requirement, &filesystem) {
                return PlanItem {
                    requirement,
                    status: status.clone(),
                };
            }
            match mechanism(requirement, policy) {
                Mechanism::Profile(text) => match &profile {
                    Ok(()) => PlanItem::enforced(requirement, format!("Seatbelt profile: {text}")),
                    Err(status) => PlanItem {
                        requirement,
                        status: status.clone(),
                    },
                },
                Mechanism::Exec(text) => PlanItem::enforced(requirement, text),
                Mechanism::Missing(reason) => PlanItem::unavailable(requirement, reason),
            }
        })
        .collect()
}

/// The policy checks for writable paths (never executable, nothing inside a writable path) see
/// only the policy paths; the minimal system set is added by the profile. Its entries are code
/// (dyld, system libraries) and configuration that programs trust (time zone and locale data, the
/// name resolver files). A writable policy path that contains an entry, or lies inside a directory
/// entry, would let the program change them for the next start and for programs outside the
/// sandbox, as far as the user may write there. /dev/null is writable in the set itself, and the
/// entries for /etc, /tmp and /var allow only reading the links.
///
/// The comparison is the one of rules 3 and 4 (`PathIdentity`), so a second name of a directory
/// of the set, a firmlink spelling for example, counts as that directory.
///
/// The set is fixed for this macOS, and the policy asks to write it, so this is a conflict of
/// the policy: no weaker level helps, because every level has the same paths.
fn system_conflict(policy: &ResolvedPolicy) -> Option<Status> {
    if policy.system == SystemAccess::None {
        return None;
    }
    let protected: Vec<ProtectedPath> = system::MINIMAL
        .iter()
        .filter(|entry| {
            !matches!(
                entry.access,
                Grant::ReadWriteDevice | Grant::ReadWriteDeviceTree | Grant::Symlink
            )
        })
        .map(|entry| {
            if matches!(entry.access, Grant::ReadTree | Grant::CodeTree) {
                ProtectedPath::tree(entry.path)
            } else {
                ProtectedPath::entry(entry.path)
            }
        })
        .chain([
            ProtectedPath::entry(system::HOSTS_FILE),
            ProtectedPath::entry(system::DNS_RESOLVER_SOCKET),
        ])
        .collect();
    let identity = match path_identity() {
        Ok(identity) => identity,
        Err(status) => return Some(status),
    };
    let (rule, entry) = policy.writable_conflict(&protected, &identity)?;
    Some(Status::Conflict {
        reason: format!(
            "writable path {} overlaps {} of the minimal system set; the program could change \
             code or configuration that the next start and programs outside the sandbox use",
            rule.path.display(),
            entry.path.display()
        ),
    })
}

/// The locations of this user that programs outside the sandbox read or execute later (see
/// `trust`). They are no policy paths, so rules 3 and 4 do not cover them. Unlike the system set
/// this applies with `system = "none"` as well: the locations belong to the user, not to the set.
/// A writable path that reaches one is a conflict of the policy, like one over the system set.
///
/// When sandy cannot name the home directory, it cannot tell whether a writable path reaches
/// the locations below it, so a policy with a writable path is indeterminate: the password
/// database may answer on the next try, and `HOME` names the directory once it is set. A policy
/// without one reaches no location.
fn trust_conflict(
    policy: &ResolvedPolicy,
    trusted: &Result<Vec<ProtectedPath>, String>,
) -> Option<Status> {
    let trusted = match trusted {
        Ok(trusted) => trusted,
        Err(reason) => {
            let writable = |rule: &sandy_core::PathRule| rule.access == PathAccess::ReadWrite;
            return policy
                .paths
                .iter()
                .any(writable)
                .then(|| Status::Indeterminate {
                    reason: reason.clone(),
                });
        }
    };
    let identity = match path_identity() {
        Ok(identity) => identity,
        Err(status) => return Some(status),
    };
    let (rule, location) = policy.writable_conflict(trusted, &identity)?;
    Some(Status::Conflict {
        reason: format!(
            "writable path {} overlaps {}, which programs outside the sandbox read or execute \
             later; a file the program leaves there runs outside the sandbox",
            rule.path.display(),
            location.path.display()
        ),
    })
}

/// What the comparisons with the protected locations need. It cannot fail on macOS; elsewhere a
/// mount table that cannot be read now says nothing about the host.
fn path_identity() -> Result<PathIdentity, Status> {
    PathIdentity::read().map_err(|error| Status::Indeterminate {
        reason: error.to_string(),
    })
}

/// What makes the program behave differently inside the sandbox than outside, beyond the
/// requirements: a directory on sandy's PATH inside a writable path (rule 12), from the
/// `path_locations` of `trust`. Before it come the `shortfalls` of the policy. `sandy check`
/// prints these as warnings; they change nothing sandy enforces.
pub fn notes(policy: &ResolvedPolicy, path_locations: &[ProtectedPath]) -> Vec<String> {
    let mut notes = shortfalls(policy);
    notes.extend(mach_service_notes(policy));
    notes.extend(policy.path_directory_notes(path_locations));
    notes
}

/// What each service of `macos.mach_services` lets the program do besides its purpose, as
/// assessed from the published source of the service (docs/macos.md, "Mach services and other
/// IPC").
fn mach_service_notes(policy: &ResolvedPolicy) -> Vec<String> {
    policy
        .macos
        .allowed_mach_services()
        .map(|service| match service {
            MachService::TrustdAgent => format!(
                "macos.mach_services allows {}, the trust agent of this user, which verifies \
                 certificates for the program. Through it the program can also have the agent \
                 fetch the CA issuer and OCSP URLs that a certificate names, from outside the \
                 sandbox (ip = \"client\" or \"all\" reaches those hosts anyway), flush this \
                 user's OCSP and CA issuer caches, read the trust settings of this user and of \
                 the administrator, and learn whether a keychain of the user holds the issuer of \
                 a certificate it sends. It cannot make a certificate trusted: trust settings \
                 change only with an authorization from the user, through a service that stays \
                 denied, and the trust store only for a program signed with the entitlement \
                 modify-anchor-certificates, so keep such programs out of read_exec paths \
                 (docs/macos.md, \"Mach services and other IPC\")",
                service.name()
            ),
        })
        .collect()
}

/// What the policy asks for and macOS gives only in part, although the plan reports it as
/// enforced (DESIGN.md, "Requirements and the enforcement plan"), each with the section of
/// docs/macos.md that explains it.
fn shortfalls(policy: &ResolvedPolicy) -> Vec<String> {
    let mut shortfalls = Vec::new();
    let contained = policy.children == ChildProcesses::Contained;
    if policy.signals == SignalScope::Isolated {
        // SIGURG needs urgent data on a TCP socket, which only IP networking gives.
        let signals = if policy.ip != IpAccess::None {
            "SIGIO and SIGURG"
        } else {
            "SIGIO"
        };
        shortfalls.push(format!(
            "signals = \"isolated\" is enforced only in part on macOS: the program can still \
             have the kernel send {signals} to a process outside the sandbox, including one of \
             another user, by making that process the owner of a socket or a pipe with an ioctl \
             (FIOSETOWN, SIOCSPGRP, TIOCSPGRP) that no profile rule reaches; the macOS kernel \
             sends it with no owner check, so this is outside sandy's reach, and a process that \
             does not handle the signal discards it (docs/macos.md, \"Signals the profile does \
             not cover\")"
        ));
        if !contained {
            shortfalls.push(
                "signals = \"isolated\" is enforced only in part on macOS: the program can join \
                 the process group of another job of its terminal session (setpgid, or \
                 posix_spawn with POSIX_SPAWN_SETPGROUP) and have the kernel stop that job by \
                 reading from the terminal; children = \"contained\" closes this (docs/macos.md, \
                 \"Signals the profile does not cover\")"
                    .to_string(),
            );
        }
    }
    if policy.ip == IpAccess::Client {
        shortfalls.push(
            "ip = \"client\" keeps datagrams out only in part on macOS: a UDP socket that is not \
             connected receives datagrams from every sender, not only from the addresses it sent \
             to, at any port the program binds it to; Seatbelt checks each such datagram as \
             network-inbound and cannot tell a reply from any other, and programs that receive on \
             a socket that is not connected (QUIC, DNS and NTP clients) need it, so the profile \
             allows it for UDP (docs/macos.md, \"Networking\")"
                .to_string(),
        );
    }
    if policy.ip == IpAccess::Private && !policy.expose.is_empty() {
        shortfalls.push(
            "ip = \"private\" keeps the program's exposed ports off the network only in part on \
             macOS: Seatbelt's localhost matches every address of this Mac, so the program can \
             listen on its exposed ports at the local network address and every other address \
             of this Mac too, where other hosts and every local process reach it without the \
             relay (docs/macos.md, \"The private network\")"
                .to_string(),
        );
    }
    let held = !policy.forward.is_empty() || policy.egress.is_some();
    let ipv4 = policy.macos.relays == Relays::Ipv4;
    if policy.ip == IpAccess::Private && held {
        // The guard ends a contained program with its helpers.
        let ended = if contained {
            ""
        } else {
            ", and once the relay or the broker has ended, also when something outside the \
             sandbox ends it, any process that binds the port does"
        };
        let (addresses, gained) = if ipv4 {
            (
                "each of its IPv4 addresses",
                "a new VPN or local network address",
            )
        } else {
            ("each of them", "a new temporary IPv6 or VPN address")
        };
        shortfalls.push(format!(
            "ip = \"private\" keeps the program off this Mac's other addresses only in part on \
             macOS: Seatbelt's localhost matches every address of this Mac, so the program may \
             connect to its forwarded and egress ports at {addresses}; the relay and the \
             broker hold those ports at every address the Mac had when they started, but a \
             process of sandy's own user that listens on one at an address the Mac gains later, \
             such as {gained}, receives the program's connections there{ended} (docs/macos.md, \
             \"The private network\")"
        ));
        if ipv4 {
            shortfalls.push(
                "macos.relays = \"ipv4\" lets the program reach its forwarded and egress ports \
                 only from IPv4 sockets on macOS: an IPv6 socket gets EPERM there, also one that \
                 connects to 127.0.0.1 as ::ffff:127.0.0.1, which is how Java and .NET connect to \
                 an IPv4 address by default, so start Java with \
                 -Djava.net.preferIPv4Stack=true and .NET with DOTNET_SYSTEM_NET_DISABLEIPV6=1 \
                 (docs/macos.md, \"The private network\")"
                    .to_string(),
            );
        } else {
            shortfalls.push(
                "ip = \"private\" keeps the program off the local network only in part on \
                 macOS: Seatbelt's localhost matches an IPv6 link-local address of this Mac with \
                 any interface as its scope, so the program may connect to its forwarded and \
                 egress ports at a link-local address that is this Mac's on one link and another \
                 host's on another, such as fe80::1, which every Mac has on its loopback and many \
                 routers use, and no socket of sandy's can hold an address of another host; \
                 macos.relays = \"ipv4\" closes this, at the cost of IPv6 sockets to those ports \
                 (docs/macos.md, \"The private network\")"
                    .to_string(),
            );
        }
    }
    if policy.egress.is_some() {
        shortfalls.push(
            "the egress broker serves every local user on macOS: macOS cannot tell the broker \
             which user holds the other end of a TCP connection, so another user can connect out \
             through it, as sandy's user, to every destination the policy's reach allows \
             (docs/macos.md, \"The egress broker\")"
                .to_string(),
        );
    }
    if policy.unix_sockets == NetworkAccess::All {
        shortfalls.push(
            "unix_sockets = \"all\" lets the program tell existing paths outside the policy \
             from missing ones on macOS: a connect to a socket needs the existence check for \
             every path, so access, statfs, chdir and the path from getattrlist answer again, \
             also by inode number through /.vol (docs/macos.md, \"Information the target can \
             still read\")"
                .to_string(),
        );
    }
    if policy.view == FileView::Policy && policy.unix_sockets == NetworkAccess::None {
        shortfalls.push(
            "view = \"policy\" hides paths outside the policy only in part on macOS: the names \
             in the root directory stay listable, because dyld reads that directory, and a bulk \
             listing of it (getattrlistbulk) that asks for the type of each entry also returns \
             their metadata; the directories above each policy path exist, with their metadata, \
             which realpath and getcwd need; and statfs of a policy path names its volume and \
             where that is mounted (docs/macos.md, \"The file system view\")"
                .to_string(),
        );
    }
    if contained {
        shortfalls.push(
            "children = \"contained\" denies posix_spawn on macOS, because its flags can move a \
             new process out of the program's process group where no profile rule sees them: \
             programs that start processes with it get EPERM, among them Rust's \
             std::process::Command without pre_exec, Java's ProcessBuilder, Node.js and other \
             libuv programs, and system() and popen(); fork and exec keep working \
             (docs/macos.md, \"Contained child processes\")"
                .to_string(),
        );
    }
    if !policy.forward.is_empty() {
        shortfalls.push(
            "a forwarded port serves every local user on macOS: macOS cannot tell the relay \
             which user holds the other end of a TCP connection, so another user can reach the \
             forwarded service through the relay, as sandy's user; forward only to services \
             that authenticate their clients (docs/macos.md, \"Who may connect, and who may \
             stop the relay\")"
                .to_string(),
        );
    }
    let relayed = !policy.expose.is_empty() || !policy.forward.is_empty();
    if relayed && policy.signals == SignalScope::Any {
        shortfalls.push(
            "the relay of exposed and forwarded ports can outlive the program without limit on \
             macOS with signals = \"any\": the program can stop the relay with SIGSTOP, and \
             macOS has no timer that ends a stopped process, so the relay keeps its ports until \
             something continues or kills it, and once continued it can relay a connection made \
             after the program ended; signals = \"isolated\" keeps the program from stopping \
             it (docs/macos.md, \"Who may connect, and who may stop the relay\")"
                .to_string(),
        );
    }
    shortfalls
}

/// Reports every requirement that the Seatbelt profile enforces as indeterminate with `reason`.
/// For `verify`, which learns in a helper process whether the profile can be applied at all. Like
/// every finding of `verify` this decides no level: a process of the same user can stop the
/// helper, and a process limit can keep it from starting.
pub fn profile_indeterminate(policy: &ResolvedPolicy, reason: &str) -> Vec<PlanItem> {
    policy
        .requirements()
        .into_iter()
        .filter(|requirement| matches!(mechanism(*requirement, policy), Mechanism::Profile(_)))
        .map(|requirement| PlanItem::indeterminate(requirement, reason))
        .collect()
}

/// Why `system = "none"` cannot start a program, unless a policy path covers the root directory.
/// Every program on macOS is linked dynamically: dyld opens the root directory to locate the
/// shared cache, and it maps the cache and its own code from /usr/lib. `system = "none"` adds
/// none of that, and a rule on "/" is the only way a policy can, because dyld needs the root
/// directory itself. Without this, `check` reported such a policy as enforced and the program
/// then died at its start.
fn root_directory_missing(policy: &ResolvedPolicy) -> Option<String> {
    let covered = policy.system != SystemAccess::None
        || policy.paths.iter().any(|rule| rule.path == Path::new("/"));
    (!covered).then(|| {
        "system = \"none\" adds none of the paths that every program on macOS needs to start: \
         dyld opens the root directory to locate the dyld shared cache and maps its own code \
         from /usr/lib. Use system = \"minimal\", or add a read rule for \"/\""
            .to_string()
    })
}

enum Mechanism {
    /// Enforced by the Seatbelt profile.
    Profile(String),
    /// Enforced by how sandy starts the target, or by macOS itself. Needs no host capability
    /// beyond posix_spawn and execve.
    Exec(String),
    /// Not enforced by this backend.
    Missing(&'static str),
}

/// The Mach services that `macos.mach_services` allows, as the mechanisms name them: empty when
/// it allows none.
fn mach_exceptions(policy: &ResolvedPolicy) -> String {
    let names: Vec<&str> = policy
        .macos
        .allowed_mach_services()
        .map(MachService::name)
        .collect();
    if names.is_empty() {
        String::new()
    } else {
        format!(" except {} (macos.mach_services)", names.join(", "))
    }
}

fn mechanism(requirement: Requirement, policy: &ResolvedPolicy) -> Mechanism {
    let contained = policy.children == ChildProcesses::Contained;
    let text = match requirement {
        Requirement::FilesystemConfined => {
            let hidden = if policy.unix_sockets == NetworkAccess::All {
                "paths outside the policy answer ENOENT except to existence checks, which Unix \
                 sockets need (unix_sockets = \"all\")"
            } else {
                "paths outside the policy answer ENOENT"
            };
            return Mechanism::Profile(format!(
                "deny by default; read, write and execute only policy paths and the system set; \
                 {hidden}; no Mach or XPC services (LaunchServices, Apple events, launchd, \
                 pasteboard){}; policy paths cannot be replaced",
                mach_exceptions(policy)
            ));
        }
        Requirement::NoPrivilegeEscalation => {
            return Mechanism::Profile(format!(
                "only policy paths execute; setuid and setgid files never do (process-exec* \
                 denied by file mode, and Sandbox.kext refuses them in any sandbox); no Mach \
                 services (authorization, privileged helpers, launchd jobs){}",
                mach_exceptions(policy)
            ));
        }
        Requirement::ProcessMemoryIsolated => {
            "no task ports of other processes (mach-priv*, mach-task-name, mach-task-read, \
             mach-task-inspect); process-info* only for the target itself, ESRCH for others"
        }
        Requirement::InheritedHandlesClosed => {
            return Mechanism::Exec(if contained {
                "the forked target, a single thread, marks every descriptor except 0, 1 and 2 \
                 close-on-exec (PROC_PIDLISTFDS) right before execve"
                    .to_string()
            } else {
                "posix_spawn with POSIX_SPAWN_SETEXEC and POSIX_SPAWN_CLOEXEC_DEFAULT; the \
                 kernel closes every descriptor except 0, 1 and 2"
                    .to_string()
            });
        }
        Requirement::EnvironmentControlled => {
            let call = if contained { "execve" } else { "posix_spawn" };
            return Mechanism::Exec(format!("{call} with exactly the policy environment"));
        }
        Requirement::IpNetworkDenied => {
            if policy.unix_sockets == NetworkAccess::All {
                "no IP network-bind, network-inbound or network-outbound, no NECP calls; the name \
                 resolver (mDNSResponder) stays reachable like every Unix socket \
                 (unix_sockets = \"all\")"
            } else {
                "no IP network-bind, network-inbound or network-outbound, no NECP calls; the name \
                 resolver (mDNSResponder) is unreachable"
            }
        }
        Requirement::InboundIpDenied => {
            "network-outbound and network-bind for IP sockets, network-inbound only for UDP \
             sockets, so no TCP socket can listen or accept"
        }
        Requirement::UnixSocketsDenied => {
            if matches!(policy.ip, IpAccess::Client | IpAccess::All) {
                "no Unix socket network-bind or network-outbound, except the socket of the name \
                 resolver (mDNSResponder), which is part of IP networking"
            } else {
                "no Unix socket network-bind or network-outbound"
            }
        }
        Requirement::SignalsIsolated => "signals only to the target and its sandboxed children",
        Requirement::MetadataConfined => {
            "file-write* (mode, owner, flags, times, extended attributes, ACLs) only on read_write \
             paths, by path and through open descriptors alike"
        }
        Requirement::EndsWithParent => {
            "a watcher process that is not a child of the target (forked twice, so launchd \
             adopts it), in a session of its own with every signal but the faults blocked, \
             confined by its own profile (no files, no network, no Mach services); it watches \
             sandy's parent and the target with kqueue (NOTE_EXIT) and, when the parent ends, \
             sends SIGTERM and SIGCONT, and SIGKILL 5 seconds later"
        }
        Requirement::ChildProcessesContained => {
            "sandy stays the target's parent and runs it in a process group led by a guard \
             process; setpgid, setsid and posix_spawn denied (syscall-unix), so no process the \
             target starts can leave the group (fork, vfork and execve work); the guard kills the \
             group when the target or sandy ends, and sandy kills it when the target exits"
        }
        Requirement::ChildProcessesDenied => {
            "process-fork denied, so fork, vfork and posix_spawn fail; threads and replacing the \
             program's own image (execve) stay allowed"
        }
        Requirement::ForwardedPortsRelayed => {
            "the relay process of the exposed ports with the direction mirrored: it listens on \
             the target's loopback port outside the sandbox and connects only to the forwarded \
             addresses; not a child of the target (forked twice), its own profile without files \
             or Mach services, ends when the target ends (kqueue NOTE_EXIT)"
        }
        Requirement::IpNetworkPrivate => {
            let held = !policy.forward.is_empty() || policy.egress.is_some();
            if held && policy.signals == SignalScope::Any {
                return Mechanism::Missing(
                    "with signals = \"any\" the program can end its relay or its egress broker, \
                     and on macOS its forwarded or egress port then reaches whatever binds that \
                     port next, at any address of this Mac; set signals = \"isolated\" \
                     (docs/macos.md, \"The private network\")",
                );
            }
            let ports = match policy.macos.relays {
                Relays::DualStack => {
                    "network-outbound only to the forwarded and egress ports, network-bind and \
                     network-inbound only on the exposed ports, both at every address of this \
                     Mac"
                }
                Relays::Ipv4 => {
                    "network-outbound only to the forwarded and egress ports at every IPv4 \
                     address of this Mac, network-bind and network-inbound only on the exposed \
                     ports at every address of this Mac"
                }
            };
            let resolver = if policy.unix_sockets == NetworkAccess::All {
                "the name resolver (mDNSResponder) stays reachable like every Unix socket \
                 (unix_sockets = \"all\")"
            } else {
                "names resolve only from /etc/hosts, the name resolver (mDNSResponder) is \
                 unreachable"
            };
            return Mechanism::Profile(format!(
                "TCP only: {ports}, which is what Seatbelt's localhost matches; the relay and the \
                 broker bind their ports without listening at the wildcard addresses and at \
                 every current address of this Mac; no UDP, no NECP calls; {resolver}"
            ));
        }
        Requirement::PathsHidden => {
            if policy.unix_sockets == NetworkAccess::All {
                return Mechanism::Missing(
                    "unix_sockets = \"all\" allows the existence check for every path, which a \
                     connect to a socket outside the policy needs, so access, statfs, chdir and \
                     the path from getattrlist answer outside the policy (docs/macos.md, \
                     \"Information the target can still read\")",
                );
            }
            "every path outside the policy and the system set answers ENOENT to every call, as a \
             missing path does: (deny file-read* file-test-existence (with errno ENOENT)) before \
             every allow"
        }
        Requirement::EgressBrokered => {
            "a broker process on the program's 127.0.0.1 egress port that is not a child of the \
             target (forked twice, so launchd adopts it) and checks every destination \
             (sandy_core::destination, with the addresses and subnets of this Mac's interfaces \
             from getifaddrs and its on-link routes from the routing sysctl); confined by its \
             own profile: accept on its port, TCP out, no connection to an address of this Mac \
             (localhost denied), the routing sysctl, no files, no Mach services; it ends when \
             the target ends (kqueue NOTE_EXIT)"
        }
        Requirement::RelaysIpv4Only => {
            "network-outbound to the forwarded and egress ports only from IPv4 sockets (tcp4), \
             so the program cannot connect to them at an IPv6 address, also not at a link-local \
             address of this Mac at the scope of another link"
        }
        Requirement::Win32kDenied => {
            return Mechanism::Exec(
                "nothing to deny: win32k is the GUI part of the Windows kernel, and macOS has \
                 none"
                    .to_string(),
            );
        }
        Requirement::ExposedPortsRelayed => {
            "a relay process that is not a child of the target (forked twice, so launchd \
             adopts it), confined by its own profile: deny by default, accept on the exposed \
             listeners and connect only to the target's loopback ports, no files, no Mach \
             services; it ends when the target ends (kqueue NOTE_EXIT)"
        }
    };
    Mechanism::Profile(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{
        EnforcementPlan, EnvironmentPolicy, PathMetadata, SignalScope, Status, SystemAccess,
        WindowsPolicy,
    };

    fn policy(ip: IpAccess, unix_sockets: NetworkAccess, signals: SignalScope) -> ResolvedPolicy {
        ResolvedPolicy {
            paths: Vec::new(),
            program: None,
            links: Vec::new(),
            system: SystemAccess::Minimal,
            ip,
            unix_sockets,
            expose: Vec::new(),
            forward: Vec::new(),
            egress: None,
            view: sandy_core::FileView::All,
            signals,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            macos: sandy_core::MacosPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }

    fn strictest() -> ResolvedPolicy {
        policy(IpAccess::None, NetworkAccess::None, SignalScope::Isolated)
    }

    fn capable() -> HostCapabilities {
        HostCapabilities {
            seatbelt: Ok(()),
            profile: Ok(()),
            already_sandboxed: false,
            rosetta: None,
            interpreter: None,
            trusted_locations: Ok(Vec::new()),
        }
    }

    #[test]
    fn reports_every_requirement_once_in_order() {
        let policy = strictest();
        let items = plan_for(&policy, &capable());
        let reported: Vec<Requirement> = items.iter().map(|item| item.requirement).collect();
        assert_eq!(reported, policy.requirements());
    }

    /// The class of a report that is not enforced.
    fn class(status: &Status) -> &'static str {
        match status {
            Status::Enforced { .. } => "enforced",
            Status::NeedsSetup { .. } => "needs setup",
            Status::Unavailable { .. } => "unavailable",
            Status::Indeterminate { .. } => "indeterminate",
            Status::Conflict { .. } => "conflict",
        }
    }

    /// A writable path over the minimal system set conflicts with the fixed layout of macOS:
    /// every level has the same paths, so a weaker level would not help.
    #[test]
    fn a_writable_path_must_not_overlap_the_system_set() {
        let refused_with = |path: &str, system: SystemAccess| {
            let mut policy = strictest();
            policy.system = system;
            policy.paths.push(sandy_core::PathRule {
                path: path.into(),
                access: PathAccess::ReadWrite,
                is_dir: true,
            });
            plan_for(&policy, &capable())
                .into_iter()
                .filter(|item| !item.is_enforced())
                .map(|item| (item.requirement, class(&item.status)))
                .collect::<Vec<_>>()
        };
        let conflict = vec![(Requirement::FilesystemConfined, "conflict")];
        // Contains a tree or a file of the set.
        assert_eq!(
            refused_with("/private/var/db", SystemAccess::Minimal),
            conflict
        );
        assert_eq!(
            refused_with("/private/etc", SystemAccess::Minimal),
            conflict
        );
        // Lies inside a tree of the set.
        assert_eq!(
            refused_with("/usr/lib/app", SystemAccess::Minimal),
            conflict
        );
        assert_eq!(
            refused_with("/usr/share/locale/x", SystemAccess::Minimal),
            conflict
        );
        // Not part of the set, or the set itself allows writing.
        assert!(refused_with("/Users/someone/data", SystemAccess::Minimal).is_empty());
        assert!(refused_with("/dev/null", SystemAccess::Minimal).is_empty());
        // Without the system set there is nothing to overlap, but then no program starts
        // (`system_none_needs_the_root_directory`), which this macOS cannot change.
        assert_eq!(
            refused_with("/private/var/db", SystemAccess::None),
            vec![(Requirement::FilesystemConfined, "unavailable")]
        );
    }

    /// A writable path that reaches one of the user's trusted locations is refused. The set of
    /// this host is in `trust`; this checks the rule with a fixed set, so it runs everywhere.
    #[test]
    fn a_writable_path_over_a_trusted_location_is_refused() {
        let home = Path::new("/Users/someone");
        let trusted = vec![
            ProtectedPath::entry(home.join(".zshrc")),
            ProtectedPath::tree(home.join("Library/LaunchAgents")),
            ProtectedPath::entry(home),
        ];
        let conflict = |path: &str| {
            let mut policy = strictest();
            policy.paths.push(sandy_core::PathRule {
                path: path.into(),
                access: PathAccess::ReadWrite,
                is_dir: true,
            });
            trust_conflict(&policy, &Ok(trusted.clone()))
        };
        // Holds the startup file, holds the home directory, lies inside a protected tree. Each
        // is a conflict of the policy, which every level shares.
        for path in [
            "/Users/someone",
            "/Users",
            "/Users/someone/Library/LaunchAgents/sub",
        ] {
            let status = conflict(path);
            assert_eq!(status.as_ref().map(class), Some("conflict"), "{status:?}");
        }
        // A directory below the home directory stays writable.
        assert!(conflict("/Users/someone/data").is_none());
    }

    /// When sandy cannot name the home directory, it cannot check the locations below it, so a
    /// policy with a writable path is indeterminate, with the reason: a lookup in the password
    /// database that failed may pass on the next try, and must not make a weaker level run. One
    /// without a writable path stays enforceable.
    #[test]
    fn an_unknown_home_directory_refuses_a_writable_path() {
        let host = HostCapabilities {
            trusted_locations: Err("cannot find the home directory of this user".into()),
            ..capable()
        };
        let plan_of = |policy: &ResolvedPolicy| {
            EnforcementPlan::new(&policy.requirements(), plan_for(policy, &host))
        };
        let mut policy = strictest();
        assert!(plan_of(&policy).is_enforceable());

        policy.paths.push(sandy_core::PathRule {
            path: "/Users/someone/data".into(),
            access: PathAccess::ReadWrite,
            is_dir: true,
        });
        let plan = plan_of(&policy);
        let reports: Vec<_> = plan.final_reports().collect();
        assert_eq!(reports.len(), 1, "{plan}");
        assert_eq!(class(&reports[0].status), "indeterminate", "{plan}");
        assert!(plan.to_string().contains("home directory"), "{plan}");
    }

    /// `system = "none"` leaves out what dyld needs, so no program starts with it. A policy that
    /// reads the root directory brings its own.
    #[test]
    fn system_none_needs_the_root_directory() {
        let plan_of = |root: Option<PathAccess>| {
            let mut policy = strictest();
            policy.system = SystemAccess::None;
            if let Some(access) = root {
                policy.paths.push(sandy_core::PathRule {
                    path: "/".into(),
                    access,
                    is_dir: true,
                });
            }
            EnforcementPlan::new(&policy.requirements(), plan_for(&policy, &capable()))
        };
        let plan = plan_of(None);
        assert!(!plan.is_enforceable(), "{plan}");
        assert!(plan.to_string().contains("dyld"), "{plan}");
        assert!(plan_of(Some(PathAccess::Read)).is_enforceable());
        assert!(plan_of(Some(PathAccess::ReadExec)).is_enforceable());
    }

    #[test]
    fn capable_host_enforces_everything() {
        let policy = strictest();
        let plan = EnforcementPlan::new(&policy.requirements(), plan_for(&policy, &capable()));
        assert!(plan.is_enforceable(), "{plan}");
    }

    /// An allowed Mach service is named where the plan says that no service is reachable, and
    /// `check` warns what else the service gives the program.
    #[test]
    fn allowed_mach_services_are_named_in_the_plan_and_warned_about() {
        let mut policy = strictest();
        policy.ip = IpAccess::All;
        let mechanism = |policy: &ResolvedPolicy, requirement| {
            format!(
                "{:?}",
                plan_for(policy, &capable())
                    .into_iter()
                    .find(|item| item.requirement == requirement)
                    .unwrap()
                    .status
            )
        };
        for requirement in [
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
        ] {
            assert!(!mechanism(&policy, requirement).contains("except"));
        }
        assert!(mach_service_notes(&policy).is_empty());
        policy.macos.mach_services = vec![MachService::TrustdAgent];
        for requirement in [
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
        ] {
            assert!(
                mechanism(&policy, requirement)
                    .contains("except com.apple.trustd.agent (macos.mach_services)"),
                "{requirement:?}"
            );
        }
        let notes = mach_service_notes(&policy);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("cannot make a certificate trusted"),
            "{}",
            notes[0]
        );
        assert_eq!(
            policy.mach_services_notes("Linux"),
            [
                "macos.mach_services allows com.apple.trustd.agent on macOS only; Linux has no \
              Mach services, so it allows nothing here"
            ]
        );
    }

    #[test]
    fn contained_and_end_with_parent_are_enforced_on_a_capable_host() {
        let mut policy = strictest();
        policy.children = ChildProcesses::Contained;
        policy.end_with_parent = true;
        let items = plan_for(&policy, &capable());
        let plan = EnforcementPlan::new(&policy.requirements(), items.clone());
        assert!(plan.is_enforceable(), "{plan}");
        let mechanism = |requirement| {
            format!(
                "{:?}",
                items
                    .iter()
                    .find(|item| item.requirement == requirement)
                    .unwrap()
                    .status
            )
        };
        assert!(mechanism(Requirement::ChildProcessesContained).contains("posix_spawn"));
        assert!(mechanism(Requirement::EndsWithParent).contains("NOTE_EXIT"));
        // The forked target starts with execve, not posix_spawn.
        assert!(mechanism(Requirement::InheritedHandlesClosed).contains("execve"));
        assert!(mechanism(Requirement::EnvironmentControlled).contains("execve"));
    }

    #[test]
    fn missing_sandbox_function_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            seatbelt: Err("dlsym(sandbox_init_with_parameters): symbol not found".into()),
            profile: Err(ProfileError::Failed("not compiled".into())),
            already_sandboxed: false,
            rosetta: None,
            interpreter: None,
            trusted_locations: Ok(Vec::new()),
        };
        let items = plan_for(&policy, &host);
        let plan = EnforcementPlan::new(&policy.requirements(), items.clone());
        assert!(!plan.is_enforceable());
        for item in &items {
            let exec_only = matches!(
                item.requirement,
                Requirement::InheritedHandlesClosed | Requirement::EnvironmentControlled
            );
            assert_eq!(item.is_enforced(), exec_only, "{item:?}");
            if let Status::Unavailable { reason } = &item.status {
                assert!(reason.contains("sandbox_init_with_parameters"), "{reason}");
            }
        }
    }

    #[test]
    fn rejected_profile_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            seatbelt: Ok(()),
            profile: Err(ProfileError::Rejected(
                "unbound variable: file-test-existence".into(),
            )),
            already_sandboxed: false,
            rosetta: None,
            interpreter: None,
            trusted_locations: Ok(Vec::new()),
        };
        let items = plan_for(&policy, &host);
        let filesystem = items
            .iter()
            .find(|item| item.requirement == Requirement::FilesystemConfined)
            .unwrap();
        assert_eq!(
            filesystem.status,
            Status::Unavailable {
                reason: "this macOS rejects the generated Seatbelt profile: unbound variable: \
                         file-test-existence"
                    .into()
            }
        );
        let plan = EnforcementPlan::new(&policy.requirements(), items);
        assert!(!plan.is_enforceable());
    }

    #[test]
    fn names_the_resolver_exception_only_when_ip_is_allowed() {
        let mechanism_of = |policy: &ResolvedPolicy| {
            plan_for(policy, &capable())
                .into_iter()
                .find(|item| item.requirement == Requirement::UnixSocketsDenied)
                .map(|item| item.status)
        };
        let with_ip = policy(IpAccess::All, NetworkAccess::None, SignalScope::Any);
        let without_ip = policy(IpAccess::None, NetworkAccess::None, SignalScope::Any);
        let with = format!("{:?}", mechanism_of(&with_ip));
        let without = format!("{:?}", mechanism_of(&without_ip));
        assert!(with.contains("mDNSResponder"), "{with}");
        assert!(!without.contains("mDNSResponder"), "{without}");
    }

    /// `check` names what the program sees outside the policy, and what `unix_sockets = "all"`
    /// gives back.
    #[test]
    fn names_what_looks_missing_outside_the_policy() {
        let mechanism_of = |policy: &ResolvedPolicy, requirement| {
            let item = plan_for(policy, &capable())
                .into_iter()
                .find(|item| item.requirement == requirement)
                .unwrap();
            format!("{:?}", item.status)
        };
        let strict = strictest();
        let files = mechanism_of(&strict, Requirement::FilesystemConfined);
        assert!(files.contains("answer ENOENT;"), "{files}");
        let processes = mechanism_of(&strict, Requirement::ProcessMemoryIsolated);
        assert!(processes.contains("ESRCH for others"), "{processes}");
        let ip = mechanism_of(&strict, Requirement::IpNetworkDenied);
        assert!(ip.contains("no NECP calls"), "{ip}");
        let unix = policy(IpAccess::None, NetworkAccess::All, SignalScope::Isolated);
        let files = mechanism_of(&unix, Requirement::FilesystemConfined);
        assert!(files.contains("except to existence checks"), "{files}");
    }

    /// `ip = "client"` is the profile's, and the UDP route it leaves open is named, as is
    /// SIGURG, which urgent data on its TCP connections can raise.
    #[test]
    fn client_is_enforced_by_the_profile_and_names_what_stays_open() {
        let client = policy(IpAccess::Client, NetworkAccess::None, SignalScope::Isolated);
        let item = plan_for(&client, &capable())
            .into_iter()
            .find(|item| item.requirement == Requirement::InboundIpDenied)
            .expect("reported");
        let Status::Enforced { mechanism } = item.status else {
            panic!("{item:?}");
        };
        assert!(
            mechanism.contains("network-inbound only for UDP"),
            "{mechanism}"
        );
        let udp = |policy: &ResolvedPolicy| {
            notes(policy, &[])
                .iter()
                .any(|note| note.starts_with("ip = \"client\" keeps datagrams out only in part"))
        };
        assert!(udp(&client));
        assert!(
            notes(&client, &[])
                .iter()
                .any(|note| note.contains("SIGIO and SIGURG"))
        );
        let all = policy(IpAccess::All, NetworkAccess::None, SignalScope::Isolated);
        assert!(!udp(&all));
    }

    fn status_of(policy: &ResolvedPolicy, requirement: Requirement) -> Status {
        plan_for(policy, &capable())
            .into_iter()
            .find(|item| item.requirement == requirement)
            .expect("reported")
            .status
    }

    fn private_network() -> ResolvedPolicy {
        let mut private = policy(
            IpAccess::Private,
            NetworkAccess::None,
            SignalScope::Isolated,
        );
        private.forward = vec![sandy_core::ForwardedPort {
            port: 18081,
            to: "127.0.0.1:8081".parse().unwrap(),
        }];
        private.expose = vec![sandy_core::ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        private.egress = Some(sandy_core::Egress {
            port: 1080,
            reach: sandy_core::EgressReach::Public,
        });
        private
    }

    /// The profiles give the private network and the egress broker.
    #[test]
    fn a_private_network_and_its_broker_are_enforced_by_the_profiles() {
        let private = private_network();
        let Status::Enforced { mechanism } = status_of(&private, Requirement::IpNetworkPrivate)
        else {
            panic!("not enforced");
        };
        assert!(
            mechanism.starts_with("Seatbelt profile: TCP only"),
            "{mechanism}"
        );
        assert!(mechanism.contains("every current address"), "{mechanism}");
        assert!(mechanism.contains("only from /etc/hosts"), "{mechanism}");
        let Status::Enforced { mechanism } = status_of(&private, Requirement::EgressBrokered)
        else {
            panic!("not enforced");
        };
        assert!(mechanism.contains("localhost denied"), "{mechanism}");
        let unix = format!("{:?}", status_of(&private, Requirement::UnixSocketsDenied));
        assert!(!unix.contains("mDNSResponder"), "{unix}");
        let plan = EnforcementPlan::new(&private.requirements(), plan_for(&private, &capable()));
        assert!(plan.is_enforceable(), "{plan}");

        let mut all_unix = private;
        all_unix.unix_sockets = NetworkAccess::All;
        let mechanism = format!("{:?}", status_of(&all_unix, Requirement::IpNetworkPrivate));
        assert!(mechanism.contains("stays reachable"), "{mechanism}");
    }

    /// With signals = "any" the program could end its relay or broker and leave the port to
    /// whatever binds it next, at any address of the Mac, so the plan refuses; a private network
    /// without forwarded or egress ports holds nothing and needs no such rule.
    #[test]
    fn a_held_port_of_a_private_network_needs_isolated_signals() {
        for (forward, egress) in [(true, false), (false, true)] {
            let mut private = private_network();
            private.signals = SignalScope::Any;
            if !forward {
                private.forward.clear();
            }
            if !egress {
                private.egress = None;
            }
            let Status::Unavailable { reason } = status_of(&private, Requirement::IpNetworkPrivate)
            else {
                panic!("enforced with signals = \"any\"");
            };
            assert!(reason.contains("set signals = \"isolated\""), "{reason}");
        }
        let mut exposed = private_network();
        exposed.signals = SignalScope::Any;
        exposed.forward.clear();
        exposed.egress = None;
        assert!(matches!(
            status_of(&exposed, Requirement::IpNetworkPrivate),
            Status::Enforced { .. }
        ));
    }

    /// The ENOENT rule hides every path outside the policy, unless `unix_sockets = "all"` allows
    /// the existence check everywhere again.
    #[test]
    fn the_view_holds_unless_unix_sockets_test_every_path() {
        let mut view = strictest();
        view.view = FileView::Policy;
        let Status::Enforced { mechanism } = status_of(&view, Requirement::PathsHidden) else {
            panic!("not enforced");
        };
        assert!(
            mechanism.contains("(deny file-read* file-test-existence (with errno ENOENT))"),
            "{mechanism}"
        );
        view.unix_sockets = NetworkAccess::All;
        let Status::Unavailable { reason } = status_of(&view, Requirement::PathsHidden) else {
            panic!("enforced with unix_sockets = \"all\"");
        };
        assert!(reason.starts_with("unix_sockets = \"all\""), "{reason}");
        let plan = EnforcementPlan::new(&view.requirements(), plan_for(&view, &capable()));
        assert!(!plan.is_enforceable(), "{plan}");
    }

    /// Seatbelt's localhost is every address of the Mac, so check names what a private network
    /// leaves open there: listening on the exposed ports, the forwarded and egress ports at
    /// addresses the Mac gains later and at its link-local addresses on other links; and that
    /// every local user reaches the broker.
    #[test]
    fn warns_where_a_private_network_reaches_other_addresses() {
        let count = |policy: &ResolvedPolicy, start: &str| {
            notes(policy, &[])
                .iter()
                .filter(|note| note.starts_with(start))
                .count()
        };
        let exposed = "ip = \"private\" keeps the program's exposed ports off the network";
        let held = "ip = \"private\" keeps the program off this Mac's other addresses";
        let scoped = "ip = \"private\" keeps the program off the local network only in part";
        let broker = "the egress broker serves every local user";
        let mut private = private_network();
        assert_eq!(count(&private, exposed), 1);
        assert_eq!(count(&private, held), 1);
        assert_eq!(count(&private, scoped), 1);
        assert_eq!(count(&private, broker), 1);
        let held_note = |policy: &ResolvedPolicy| {
            notes(policy, &[])
                .into_iter()
                .find(|note| note.starts_with(held))
                .unwrap()
        };
        let isolated = held_note(&private);
        assert!(
            isolated.contains("an address the Mac gains later"),
            "{isolated}"
        );
        assert!(
            isolated.contains("once the relay or the broker has ended"),
            "{isolated}"
        );
        // The guard ends a contained program with its helpers.
        private.children = ChildProcesses::Contained;
        assert!(!held_note(&private).contains("has ended"));
        let mut forward_only = private_network();
        forward_only.egress = None;
        assert_eq!(count(&forward_only, held), 1);
        assert_eq!(count(&forward_only, scoped), 1);
        assert_eq!(count(&forward_only, broker), 0);

        let mut alone = private_network();
        alone.expose.clear();
        alone.forward.clear();
        alone.egress = None;
        assert_eq!(
            count(&alone, exposed) + count(&alone, held) + count(&alone, scoped),
            0
        );
        let mut all = private_network();
        all.ip = IpAccess::All;
        all.egress = None;
        assert_eq!(
            count(&all, exposed) + count(&all, held) + count(&all, scoped),
            0
        );
    }

    /// `macos.relays = "ipv4"` is the profile's. It takes the link-local route out of the
    /// warnings, which name what the program pays instead: its IPv6 sockets to the forwarded
    /// and egress ports. Without such ports there is nothing to pay.
    #[test]
    fn ipv4_relays_close_the_link_local_route_and_name_the_cost() {
        let notes_starting = |policy: &ResolvedPolicy, start: &str| -> Vec<String> {
            notes(policy, &[])
                .into_iter()
                .filter(|note| note.starts_with(start))
                .collect()
        };
        let scoped = "ip = \"private\" keeps the program off the local network only in part";
        let cost = "macos.relays = \"ipv4\" lets the program reach its forwarded and egress \
                    ports only from IPv4 sockets";
        let held = "ip = \"private\" keeps the program off this Mac's other addresses";

        let dual_stack = private_network();
        let scoped_note = notes_starting(&dual_stack, scoped);
        assert_eq!(scoped_note.len(), 1);
        assert!(
            scoped_note[0].contains("macos.relays = \"ipv4\" closes this"),
            "{scoped_note:?}"
        );
        assert!(notes_starting(&dual_stack, cost).is_empty());

        let mut ipv4 = private_network();
        ipv4.macos.relays = Relays::Ipv4;
        let Status::Enforced { mechanism } = status_of(&ipv4, Requirement::RelaysIpv4Only) else {
            panic!("not enforced");
        };
        assert!(
            mechanism.starts_with(
                "Seatbelt profile: network-outbound to the forwarded and egress ports only from \
                 IPv4 sockets (tcp4)"
            ),
            "{mechanism}"
        );
        let private = format!("{:?}", status_of(&ipv4, Requirement::IpNetworkPrivate));
        assert!(private.contains("at every IPv4 address"), "{private}");
        let plan = EnforcementPlan::new(&ipv4.requirements(), plan_for(&ipv4, &capable()));
        assert!(plan.is_enforceable(), "{plan}");
        assert!(notes_starting(&ipv4, scoped).is_empty());
        let cost_note = notes_starting(&ipv4, cost);
        assert_eq!(cost_note.len(), 1);
        for advice in [
            "::ffff:127.0.0.1",
            "-Djava.net.preferIPv4Stack=true",
            "DOTNET_SYSTEM_NET_DISABLEIPV6=1",
        ] {
            assert!(cost_note[0].contains(advice), "{cost_note:?}");
        }
        let held_note = notes_starting(&ipv4, held);
        assert_eq!(held_note.len(), 1);
        assert!(
            held_note[0].contains("each of its IPv4 addresses") && !held_note[0].contains("IPv6"),
            "{held_note:?}"
        );

        let mut alone = ipv4;
        alone.forward.clear();
        alone.egress = None;
        assert!(notes_starting(&alone, cost).is_empty());
        assert!(matches!(
            status_of(&alone, Requirement::RelaysIpv4Only),
            Status::Enforced { .. }
        ));
    }

    #[test]
    fn warns_what_the_view_leaves_visible() {
        let warned = |view, unix_sockets| {
            let mut policy = policy(IpAccess::None, unix_sockets, SignalScope::Isolated);
            policy.view = view;
            notes(&policy, &[])
                .iter()
                .filter(|note| note.starts_with("view = \"policy\" hides paths"))
                .count()
        };
        assert_eq!(warned(FileView::Policy, NetworkAccess::None), 1);
        assert_eq!(warned(FileView::All, NetworkAccess::None), 0);
        // Refused there, so nothing to warn about.
        assert_eq!(warned(FileView::Policy, NetworkAccess::All), 0);
    }

    #[test]
    fn warns_that_unix_sockets_all_shows_which_paths_exist() {
        let warned = |unix_sockets| {
            let policy = policy(IpAccess::None, unix_sockets, SignalScope::Isolated);
            notes(&policy, &[])
                .iter()
                .filter(|note| note.starts_with("unix_sockets = \"all\" lets the program tell"))
                .count()
        };
        assert_eq!(warned(NetworkAccess::All), 1);
        assert_eq!(warned(NetworkAccess::None), 0);
    }

    #[test]
    fn code_that_needs_rosetta_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            rosetta: Some("the program has no arm64 code".into()),
            ..capable()
        };
        let items = plan_for(&policy, &host);
        let plan = EnforcementPlan::new(&policy.requirements(), items.clone());
        assert!(!plan.is_enforceable());
        let filesystem = items
            .iter()
            .find(|item| item.requirement == Requirement::FilesystemConfined)
            .unwrap();
        assert_eq!(
            filesystem.status,
            Status::Unavailable {
                reason: "the program has no arm64 code".into()
            }
        );
    }

    /// XNU executes the interpreter of a script, so a script whose interpreter no `read_exec`
    /// path covers cannot start. The plan reports it instead of letting the `execve` fail with
    /// the profile already applied, as a conflict between the program and the policy: whoever
    /// can change a link on the way to the interpreter must not make sandy pick a level whose
    /// `read_exec` paths cover the new target.
    #[test]
    fn a_script_without_an_executable_interpreter_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            interpreter: Some("/tmp/s is a script and the kernel executes its interpreter".into()),
            ..capable()
        };
        let items = plan_for(&policy, &host);
        let plan = EnforcementPlan::new(&policy.requirements(), items.clone());
        assert!(!plan.is_enforceable());
        let filesystem = items
            .iter()
            .find(|item| item.requirement == Requirement::FilesystemConfined)
            .unwrap();
        assert_eq!(
            filesystem.status,
            Status::Conflict {
                reason: host.interpreter.clone().unwrap()
            }
        );
        assert_eq!(plan.final_reports().count(), 1, "{plan}");
    }

    /// The trial apply of `verify` never decides a level: whatever stops its helper, every
    /// requirement of the profile is reported indeterminate, and only those.
    #[test]
    fn a_failed_trial_is_indeterminate_for_every_profile_requirement() {
        let mut policy = private_network();
        policy.children = ChildProcesses::Contained;
        let items = profile_indeterminate(&policy, "the trial sandbox did not report");
        let profile: Vec<Requirement> = plan_for(&policy, &capable())
            .into_iter()
            .filter(|item| {
                matches!(&item.status, Status::Enforced { mechanism } if mechanism.starts_with("Seatbelt profile"))
            })
            .map(|item| item.requirement)
            .collect();
        assert_eq!(
            items
                .iter()
                .map(|item| item.requirement)
                .collect::<Vec<_>>(),
            profile
        );
        assert!(
            items
                .iter()
                .all(|item| class(&item.status) == "indeterminate"),
            "{items:?}"
        );
    }

    #[test]
    fn only_read_exec_paths_execute() {
        let mut policy = strictest();
        for (path, access) in [
            ("/bin/tool", PathAccess::ReadExec),
            ("/data", PathAccess::ReadWrite),
            ("/etc/app", PathAccess::Read),
        ] {
            policy.paths.push(sandy_core::PathRule {
                path: path.into(),
                access,
                is_dir: false,
            });
        }
        assert_eq!(
            executable_paths(&policy),
            vec![std::path::PathBuf::from("/bin/tool")]
        );
    }

    #[test]
    fn nested_sandbox_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            already_sandboxed: true,
            ..capable()
        };
        let plan = EnforcementPlan::new(&policy.requirements(), plan_for(&policy, &host));
        assert!(!plan.is_enforceable());
        assert!(
            plan.to_string()
                .contains("already runs in a Seatbelt sandbox"),
            "{plan}"
        );
    }
}
