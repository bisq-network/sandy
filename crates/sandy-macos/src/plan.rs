//! The enforcement plan for a host with known capabilities. Pure, so it runs and is tested on
//! every platform.

use std::path::Path;

use sandy_core::{
    ChildProcesses, IpAccess, NetworkAccess, PathAccess, PathIdentity, PlanItem, ProtectedPath,
    Requirement, ResolvedPolicy, SignalScope, SystemAccess,
};

use crate::system::{self, SystemAccess as Grant};
use crate::trust;

/// What the host offers. `MacosBackend` detects it; tests use fixed values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    /// `Ok` when the Seatbelt functions could be loaded, otherwise the reason.
    pub seatbelt: Result<(), String>,
    /// `Ok` when the Seatbelt compiler of this host accepts the generated profiles (the
    /// program's, and the relay's and the watcher's when the policy needs them), otherwise its
    /// message.
    pub profile: Result<(), String>,
    /// sandy itself already runs in a Seatbelt sandbox. macOS then refuses another profile.
    pub already_sandboxed: bool,
    /// Why the program would run as x86_64 code through Rosetta, if it would. Rosetta cannot load
    /// its runtime inside the sandbox, so such a program never starts.
    pub rosetta: Option<String>,
    /// Why the kernel could not execute the program, if it could not: it is a script whose
    /// interpreter no `read_exec` path covers (`executable_paths`).
    pub interpreter: Option<String>,
    /// The locations of this user that programs outside the sandbox read or execute later
    /// (`trust::locations`), or why sandy cannot name them: no source names the home directory.
    pub trusted_locations: Result<Vec<ProtectedPath>, String>,
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

/// Reports every requirement of `policy` exactly once, as enforced (with its mechanism) or
/// unavailable (with the reason).
pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<PlanItem> {
    let profile = match (
        &host.seatbelt,
        host.already_sandboxed,
        &host.rosetta,
        &host.profile,
    ) {
        (Err(reason), _, _, _) => Err(format!("Seatbelt is not available: {reason}")),
        (Ok(()), true, _, _) => Err(
            "sandy already runs in a Seatbelt sandbox, and macOS refuses a second profile"
                .to_string(),
        ),
        (Ok(()), false, Some(reason), _) => Err(reason.clone()),
        (Ok(()), false, None, Err(message)) => Err(format!(
            "this macOS rejects the generated Seatbelt profile: {message}"
        )),
        (Ok(()), false, None, Ok(())) => Ok(()),
    };
    let conflict = system_conflict(policy)
        .or_else(|| trust_conflict(policy, &host.trusted_locations))
        .or_else(|| host.interpreter.clone());
    policy
        .requirements()
        .into_iter()
        .map(|requirement| match mechanism(requirement, policy) {
            _ if requirement == Requirement::FilesystemConfined && conflict.is_some() => {
                PlanItem::unavailable(requirement, conflict.clone().unwrap_or_default())
            }
            Mechanism::Profile(text) => match &profile {
                Ok(()) => PlanItem::enforced(requirement, format!("Seatbelt profile: {text}")),
                Err(reason) => PlanItem::unavailable(requirement, reason.clone()),
            },
            Mechanism::Exec(text) => PlanItem::enforced(requirement, text),
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
fn system_conflict(policy: &ResolvedPolicy) -> Option<String> {
    if policy.system == SystemAccess::None {
        return root_directory_missing(policy);
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
    let identity = match PathIdentity::read() {
        Ok(identity) => identity,
        Err(error) => return Some(error.to_string()),
    };
    let (rule, entry) = policy.writable_conflict(&protected, &identity)?;
    Some(format!(
        "writable path {} overlaps {} of the minimal system set; the program could change code \
         or configuration that the next start and programs outside the sandbox use",
        rule.path.display(),
        entry.path.display()
    ))
}

/// The locations of this user that programs outside the sandbox read or execute later (see
/// `trust`). They are no policy paths, so rules 3 and 4 do not cover them. Unlike the system set
/// this applies with `system = "none"` as well: the locations belong to the user, not to the set.
///
/// When no source names the home directory, sandy cannot tell whether a writable path reaches
/// the locations below it, so a policy with a writable path is refused. A policy without one
/// reaches no location.
fn trust_conflict(
    policy: &ResolvedPolicy,
    trusted: &Result<Vec<ProtectedPath>, String>,
) -> Option<String> {
    let trusted = match trusted {
        Ok(trusted) => trusted,
        Err(reason) => {
            let writable = |rule: &sandy_core::PathRule| rule.access == PathAccess::ReadWrite;
            return policy.paths.iter().any(writable).then(|| reason.clone());
        }
    };
    let identity = match PathIdentity::read() {
        Ok(identity) => identity,
        Err(error) => return Some(error.to_string()),
    };
    let (rule, location) = policy.writable_conflict(trusted, &identity)?;
    Some(format!(
        "writable path {} overlaps {}, which programs outside the sandbox read or execute \
         later; a file the program leaves there runs outside the sandbox",
        rule.path.display(),
        location.path.display()
    ))
}

/// What makes the program behave differently inside the sandbox than outside, beyond the
/// requirements: a directory on sandy's PATH inside a writable path (rule 12). Before it come
/// the `shortfalls` of the policy. `sandy check` prints these as warnings; they change nothing
/// sandy enforces.
pub fn notes(policy: &ResolvedPolicy) -> Vec<String> {
    let mut notes = shortfalls(policy);
    notes.extend(policy.path_directory_notes(&trust::path_locations()));
    notes
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

/// Reports every requirement that the Seatbelt profile enforces as unavailable with `reason`. For
/// `verify`, which learns in a helper process whether the profile can be applied at all.
pub fn profile_unavailable(policy: &ResolvedPolicy, reason: &str) -> Vec<PlanItem> {
    policy
        .requirements()
        .into_iter()
        .filter(|requirement| matches!(mechanism(*requirement, policy), Mechanism::Profile(_)))
        .map(|requirement| PlanItem::unavailable(requirement, reason))
        .collect()
}

/// Why `system = "none"` cannot start a program, unless a policy path covers the root directory.
/// Every program on macOS is linked dynamically: dyld opens the root directory to locate the
/// shared cache, and it maps the cache and its own code from /usr/lib. `system = "none"` adds
/// none of that, and a rule on "/" is the only way a policy can, because dyld needs the root
/// directory itself. Without this, `check` reported such a policy as enforced and the program
/// then died at its start.
fn root_directory_missing(policy: &ResolvedPolicy) -> Option<String> {
    let covered = policy.paths.iter().any(|rule| rule.path == Path::new("/"));
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
}

fn mechanism(requirement: Requirement, policy: &ResolvedPolicy) -> Mechanism {
    let contained = policy.children == ChildProcesses::Contained;
    let text = match requirement {
        Requirement::FilesystemConfined => {
            "deny by default; read, write and execute only policy paths and the system set; \
             no Mach or XPC services (LaunchServices, Apple events, launchd, pasteboard); \
             policy paths cannot be replaced"
        }
        Requirement::NoPrivilegeEscalation => {
            "only policy paths execute; setuid and setgid files never do (process-exec* denied \
             by file mode, and Sandbox.kext refuses them in any sandbox); no Mach services \
             (authorization, privileged helpers, launchd jobs)"
        }
        Requirement::ProcessMemoryIsolated => {
            "no task ports of other processes (mach-priv*, mach-task-name, mach-task-read, \
             mach-task-inspect); process-info* only for the target itself"
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
                "no IP network-bind, network-inbound or network-outbound; the name resolver \
                 (mDNSResponder) stays reachable like every Unix socket (unix_sockets = \"all\")"
            } else {
                "no IP network-bind, network-inbound or network-outbound; the name resolver \
                 (mDNSResponder) is unreachable"
            }
        }
        Requirement::InboundIpDenied => {
            "network-outbound and network-bind for IP sockets, network-inbound only for UDP \
             sockets, so no TCP socket can listen or accept"
        }
        Requirement::UnixSocketsDenied => {
            if policy.ip != IpAccess::None {
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
            system: SystemAccess::Minimal,
            ip,
            unix_sockets,
            expose: Vec::new(),
            forward: Vec::new(),
            signals,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
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

    #[test]
    fn a_writable_path_must_not_overlap_the_system_set() {
        let unavailable_with = |path: &str, system: SystemAccess| {
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
                .map(|item| item.requirement)
                .collect::<Vec<_>>()
        };
        let refused = vec![Requirement::FilesystemConfined];
        // Contains a tree or a file of the set.
        assert_eq!(
            unavailable_with("/private/var/db", SystemAccess::Minimal),
            refused
        );
        assert_eq!(
            unavailable_with("/private/etc", SystemAccess::Minimal),
            refused
        );
        // Lies inside a tree of the set.
        assert_eq!(
            unavailable_with("/usr/lib/app", SystemAccess::Minimal),
            refused
        );
        assert_eq!(
            unavailable_with("/usr/share/locale/x", SystemAccess::Minimal),
            refused
        );
        // Not part of the set, or the set itself allows writing.
        assert!(unavailable_with("/Users/someone/data", SystemAccess::Minimal).is_empty());
        assert!(unavailable_with("/dev/null", SystemAccess::Minimal).is_empty());
        // Without the system set there is nothing to overlap, but then no program starts
        // (`system_none_needs_the_root_directory`).
        assert_eq!(
            unavailable_with("/private/var/db", SystemAccess::None),
            refused
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
        // Holds the startup file, holds the home directory, lies inside a protected tree.
        assert!(conflict("/Users/someone").is_some());
        assert!(conflict("/Users").is_some());
        assert!(conflict("/Users/someone/Library/LaunchAgents/sub").is_some());
        // A directory below the home directory stays writable.
        assert!(conflict("/Users/someone/data").is_none());
    }

    /// When no source names the home directory, sandy cannot check the locations below it, so a
    /// policy with a writable path is refused with the reason, and one without stays
    /// enforceable.
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
        assert!(!plan.is_enforceable(), "{plan}");
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
            profile: Err("not compiled".into()),
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
            profile: Err("unbound variable: file-test-existence".into()),
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
            notes(policy)
                .iter()
                .any(|note| note.starts_with("ip = \"client\" keeps datagrams out only in part"))
        };
        assert!(udp(&client));
        assert!(
            notes(&client)
                .iter()
                .any(|note| note.contains("SIGIO and SIGURG"))
        );
        let all = policy(IpAccess::All, NetworkAccess::None, SignalScope::Isolated);
        assert!(!udp(&all));
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
    /// the profile already applied.
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
            Status::Unavailable {
                reason: host.interpreter.clone().unwrap()
            }
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
