//! The planning step. From a policy and the host capabilities it derives the plan items and the
//! exact configuration that `run` applies. Both come from the same function, so `run` applies
//! what the plan names. The only state it reads besides the host capabilities is the `#!` line
//! and the ELF interpreter of the program, which tell whether the kernel could execute it at
//! all, and the identity of every rule path; both depend on the policy, so no detection step
//! can answer them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use landlock::{ABI, Access, AccessFs, AccessNet, BitFlags, Scope, make_bitflags};
use sandy_core::{
    ChildProcesses, FileView, IpAccess, NetworkAccess, PathAccess, PathIdentity, PathMetadata,
    PathRule, PlanItem, ProtectedPath, Requirement, ResolvedPolicy, SignalScope, SystemAccess,
};

use crate::broker::BrokerConfig;
use crate::cgroup;
use crate::filter::FilterConfig;
use crate::host::HostCapabilities;
use crate::launch;
use crate::loader;
use crate::namespace::{Missing, Namespaces};
use crate::openssl;
use crate::relay::RelayConfig;
use crate::system::{self, Needed, SystemPath, SystemUse};
use crate::view::{Bind, Link, View};

#[derive(Debug)]
pub struct LinuxPlan {
    pub items: Vec<PlanItem>,
    /// What `run` applies. `None` unless every requirement is enforced.
    pub sandbox: Option<Sandbox>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sandbox {
    pub landlock: LandlockConfig,
    /// `ip = "client"`: the Landlock network rights that a socket may use only on port 0, so
    /// that it binds only to a port the kernel chooses (`client_binds`). Zero for no ruleset.
    pub client_binds: u64,
    pub filter: FilterConfig,
    /// The relay for exposed ports, when the policy has any.
    pub relay: Option<RelayConfig>,
    /// The egress broker, when the policy has one.
    pub broker: Option<BrokerConfig>,
    /// The namespaces the program runs in, `None` for the host's own (see `namespace`).
    pub namespaces: Option<Namespaces>,
    /// `filesystem.view = "policy"`: what the program's mount namespace shows (see `view`).
    pub view: Option<View>,
    /// `process.children = "contained"`: sandy stays the program's parent and ends its process
    /// group when the program ends, instead of replacing itself with the program.
    pub contain: bool,
    /// `process.end_with_parent`: a watcher ends the program when sandy's parent ends.
    pub end_with_parent: bool,
    /// The file each Landlock rule path named when sandy planned the run, before the checks of
    /// this module. The launch binds a rule only to that file (`launch::open_rule`).
    pub identities: BTreeMap<PathBuf, FileIdentity>,
}

/// The device and inode number of a file.
pub type FileIdentity = (u64, u64);

/// `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_BIND_UDP` of linux/landlock.h, from
/// ABI 4 and ABI 10. The landlock crate does not know the UDP right yet.
pub const BIND_TCP: u64 = 1 << 0;
pub const BIND_UDP: u64 = 1 << 2;

#[derive(Debug, Clone, PartialEq)]
pub struct LandlockConfig {
    pub abi: ABI,
    pub handled_fs: BitFlags<AccessFs>,
    pub handled_net: BitFlags<AccessNet>,
    pub scopes: BitFlags<Scope>,
    pub rules: Vec<PathRights>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathRights {
    pub path: PathBuf,
    pub is_dir: bool,
    pub access: BitFlags<AccessFs>,
}

const FILTER_BASELINE: &str = "seccomp denies namespaces, mounts and their listing (statmount, \
    listmount, listns), bpf, perf_event_open, io_uring, \
    keyrings, userfaultfd, calls and arguments that need capabilities, setuid and setgid mode \
    bits, and unknown or foreign system calls";
const FILTER_METADATA: &str = "seccomp denies chmod, chown, utime and xattr calls that take a \
    path, and fchmodat, fchmodat2 and fchownat";
const FILTER_PROCESSES: &str = "seccomp denies ptrace, process_vm_readv, process_vm_writev, \
    pidfd_getfd, kcmp, process_madvise, System V IPC and POSIX message queues, and changes of the \
    limits, priority and CPU affinity of other processes";
const PRIVATE_NETWORK: &str = "a user and a network namespace of the sandbox's own, created \
    before the sandbox is applied: only lo, up; the user's own user and group ID mapped to \
    themselves and setgroups denied, so root is not mapped; every capability in the namespace \
    dropped, the bounding set included; the relays and the egress broker are the only ways in \
    and out; seccomp denies the program new namespaces";
const CONTAINED_GROUP: &str = "sandy stays the program's parent and puts it in a process group of \
    its own, whose leader is a guard process of sandy; seccomp denies setsid and setpgid, so every \
    process the program starts stays in that group; the guard kills the group when the program \
    ends (pidfd) or sandy dies, and sandy kills it with SIGKILL when the program ends and reaps it \
    as child subreaper";
const CONTAINED_PID_NAMESPACE: &str = "a PID namespace of the sandbox's own, whose PID 1 is an \
    init of sandy and whose PID 2 is the program; the kernel ends every process of the namespace \
    when the init ends, and the init ends when the program or sandy ends (pidfd) and when a guard \
    process of sandy, which watches the program and sandy, kills it; the program leads a process \
    group of its own, and seccomp denies setsid and setpgid, so every process it starts stays in \
    that group, which sandy kills with SIGKILL when the program ends; sandy stays the program's \
    parent and reaps it as child subreaper";
const SIGNALS_PID_NAMESPACE: &str = "a PID namespace of the sandbox's own: kill, pidfd_open, \
    F_SETOWN, setpriority, ioprio_set and sched_setaffinity reach no process outside it by ID \
    (ESRCH), the program's process group holds only its own processes, and seccomp denies setsid, \
    setpgid and the terminal ioctls TIOCSPGRP, TIOCSWINSZ and TIOCSIG";
const VIEW: &str = "a user and a mount namespace of the sandbox's own, created before the sandbox \
    is applied: a read-only tmpfs root that holds only the paths the Landlock rules name, each \
    bound at its own path through descriptors (open_tree, mount_setattr, move_mount), nosuid and \
    nodev, read-only unless a writable path holds it and without execute unless the policy makes \
    it executable; the symbolic links on the way to them; a /dev with null, zero, full, random and \
    urandom; the old root detached (pivot_root); every capability in the namespace dropped; \
    Landlock decides access as without the view, on a kernel with the fix of Landlock erratum 3; \
    seccomp denies the program mounts and namespaces";
/// Landlock erratum 3 (bit 2 of the errata bitmask): rights could widen through a directory that a
/// bind mount disconnected, which the file system view creates.
const ERRATUM_3: u64 = 1 << 2;
const NO_WIN32K: &str =
    "nothing to deny: win32k is the GUI part of the Windows kernel, and Linux has none";

/// How many `#!` lines sandy follows when it checks whether the program can be executed. The
/// kernel follows more (measured on Linux 7.2: a chain of five scripts runs, six fails with
/// ELOOP), so this never names a level the kernel would not reach, and no real program nests
/// more than one.
const SHEBANG_LEVELS: usize = 4;

pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> LinuxPlan {
    // Landlock restricts only the calling thread, so it is only usable when sandy can verify
    // that it is single-threaded.
    let abi = match (&host.landlock, &host.thread_count) {
        (Err(reason), _) | (Ok(_), Err(reason)) => Err(reason.as_str()),
        (Ok(version), Ok(())) => Ok(ABI::from(*version)),
    };
    let loader = program_loader(policy);
    let landlock = abi
        .ok()
        .map(|abi| landlock_config(policy, &host.system_paths, loader.as_deref(), abi));
    // Before the checks below, so that a file swapped in while they run is not the one bound.
    let identities: BTreeMap<PathBuf, FileIdentity> = landlock
        .iter()
        .flat_map(|landlock| &landlock.rules)
        .filter_map(|rule| Some((rule.path.clone(), launch::identity(&rule.path)?)))
        .collect();
    let conflict = system_conflict(policy, &host.system_locations)
        .or_else(|| trust_conflict(policy, &host.trusted_locations))
        .or_else(|| loader_problem(loader.as_deref(), &executable_paths(landlock.as_ref()?)))
        .or_else(|| {
            policy.interpreter_problem(SHEBANG_LEVELS, &executable_paths(landlock.as_ref()?))
        });
    let items: Vec<PlanItem> = policy
        .requirements()
        .into_iter()
        .map(|requirement| plan_item(requirement, policy, host, abi, conflict.as_deref()))
        .collect();
    let enforceable = items.iter().all(PlanItem::is_enforced);
    let private = policy.ip == IpAccess::Private;
    let hidden = policy.view == FileView::Policy;
    let pid = pid_namespace(policy, host);
    let sandbox = match (abi, landlock) {
        (Ok(abi), Some(landlock)) if enforceable => Some(Sandbox {
            view: hidden.then(|| view_config(policy, &landlock, &host.system_paths)),
            landlock,
            client_binds: match policy.ip {
                IpAccess::Client => port_zero_binds(host),
                IpAccess::None | IpAccess::Private | IpAccess::All => 0,
            },
            filter: FilterConfig {
                allow_ip: policy.ip != IpAccess::None,
                allow_unix: policy.unix_sockets == NetworkAccess::All,
                deny_inbound: policy.ip == IpAccess::Client,
                restrict_truncate: abi < ABI::V3,
                deny_path_metadata: policy.path_metadata == PathMetadata::Deny,
                deny_children: policy.children == ChildProcesses::None,
                keep_process_group: policy.children == ChildProcesses::Contained,
                isolate_signals: policy.signals == SignalScope::Isolated,
            },
            relay: RelayConfig::new(
                &policy.expose,
                &policy.forward,
                policy.signals,
                abi,
                private,
            ),
            broker: BrokerConfig::new(policy.egress, policy.signals, abi),
            namespaces: (private || hidden || pid).then_some(Namespaces {
                network: private,
                mount: hidden,
                pid,
            }),
            contain: policy.children == ChildProcesses::Contained,
            end_with_parent: policy.end_with_parent,
            identities,
        }),
        _ => None,
    };
    LinuxPlan { items, sandbox }
}

/// Whether the program of `children = "contained"` runs in a PID namespace of its own. Only where
/// the host gives one, and not where the policy grants a path of `/proc`, with or without a file
/// system view: the host's `/proc` names processes by their IDs outside the namespace, so a
/// program that reads `/proc/<getpid()>` would read another process, and a `/proc` of the
/// namespace (`subset=pid`) would hide the host's files the policy grants, such as `meminfo`.
fn pid_namespace(policy: &ResolvedPolicy, host: &HostCapabilities) -> bool {
    wants_pid_namespace(policy) && host.pid_namespace.is_ok()
}

/// Whether the program of `children = "contained"` runs in a PID namespace where the host gives
/// one (`pid_namespace`), for the trial of `check`.
pub(crate) fn wants_pid_namespace(policy: &ResolvedPolicy) -> bool {
    policy.children == ChildProcesses::Contained && !sees_proc(policy, "/proc")
}

/// Whether a policy path holds `path` or lies below it.
fn sees_proc(policy: &ResolvedPolicy, path: &str) -> bool {
    policy
        .paths
        .iter()
        .any(|rule| rule.path.starts_with(path) || Path::new(path).starts_with(&rule.path))
}

/// The bind rights of `Sandbox::client_binds` on this host: TCP from Landlock ABI 4, UDP from
/// ABI 10. With them a socket binds only to port 0, which the kernel turns into a free port of
/// its choice, so a client that names its local address keeps working while no socket takes a
/// port that others know. The seccomp filter denies listening, so this does not decide whether
/// the program can take connections; it narrows where datagrams reach it.
fn port_zero_binds(host: &HostCapabilities) -> u64 {
    let version = *host.landlock.as_ref().unwrap_or(&0);
    let mut rights = 0;
    if version >= 4 {
        rights |= BIND_TCP;
    }
    if version >= 10 {
        rights |= BIND_UDP;
    }
    rights
}

/// What makes the program behave differently inside the sandbox than outside, beyond the
/// requirements: a directory on sandy's PATH inside a writable path, an OpenSSL include the
/// policy does not cover, and a cgroup limit the program cannot see. Before them come the
/// `shortfalls` of the policy. `sandy check` prints these as warnings; they change nothing sandy
/// enforces, and a program that uses neither TLS nor the limits runs as it is.
pub fn notes(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<String> {
    let mut notes = shortfalls(policy, host);
    if policy.ip == IpAccess::Client && policy.unix_sockets == NetworkAccess::All {
        notes.push(
            "with ip = \"client\" the program cannot listen on a Unix socket either on Linux: \
             seccomp denies listen and accept for every socket, because it cannot tell a Unix \
             socket from an IP socket; a program that serves on a Unix socket needs ip = \"all\" \
             there (docs/linux.md, \"Client networking\")"
                .to_string(),
        );
    }
    notes.extend(policy.path_directory_notes(&host.path_locations));
    let Some(rules) = landlock_for(policy, host).map(|landlock| landlock.rules) else {
        // Without Landlock the policy is refused anyway, and there are no rules to compare with.
        return notes;
    };
    let readable = |path: &Path| {
        let covers = |rule: &PathRights| {
            rule.access.contains(AccessFs::ReadFile) && path.starts_with(&rule.path)
        };
        rules.iter().any(covers)
    };
    notes.extend(
        openssl::missing_includes(&system::openssl_configs(), &readable)
            .into_iter()
            .map(|missing| {
                format!(
                    "the OpenSSL configuration {} includes {}, which this policy does not let \
                     the program read: OpenSSL drops an include it cannot read without an error \
                     and then runs with weaker built-in defaults, for example other TLS cipher \
                     suites. Add --read {} unless the program needs no cryptography",
                    missing.config.display(),
                    missing.target.display(),
                    missing.target.display()
                )
            }),
    );
    let sees_own_cgroup =
        readable(Path::new("/proc/self/cgroup")) && readable(Path::new("/sys/fs/cgroup"));
    if !sees_own_cgroup {
        notes.extend(cgroup::note(cgroup::limits()));
    }
    notes
}

/// What the policy asks for and Linux gives only in part, although the plan reports it as
/// enforced (DESIGN.md, "Requirements and the enforcement plan"), each with the section of
/// docs/linux.md that explains it.
fn shortfalls(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<String> {
    let mut shortfalls = Vec::new();
    if policy.ip == IpAccess::Client {
        let any_port = "at any port the program binds it to, because only Landlock ABI 10 \
            limits UDP binds";
        let ports = match &host.landlock {
            _ if port_zero_binds(host) & BIND_UDP != 0 => {
                "at the port the kernel chose for it".to_string()
            }
            Ok(version) => format!("{any_port} and this kernel has ABI {version}"),
            Err(_) => any_port.to_string(),
        };
        shortfalls.push(format!(
            "ip = \"client\" keeps datagrams out only in part on Linux: a UDP socket that is not \
             connected receives datagrams from every sender, not only from the addresses it sent \
             to, {ports}; no seccomp or Landlock rule tells a reply from any other datagram \
             (docs/linux.md, \"Client networking\")"
        ));
    }
    if policy.signals == SignalScope::Isolated && policy.children != ChildProcesses::Contained {
        shortfalls.push(
            "signals = \"isolated\" is enforced only in part on Linux: when the program reads \
             from the terminal while its process group is in the background, the kernel stops \
             the whole group, and without children = \"contained\" that is the group sandy was \
             started in, so the processes outside the sandbox in it stop as well, for example \
             the shell that ran sandy from a script; children = \"contained\" gives the program \
             a group of its own (docs/linux.md, \"Signals and the terminal\")"
                .to_string(),
        );
    }
    if policy.ip == IpAccess::Private {
        let ports = match policy.egress {
            Some(_) => "the program's ports, forwarded ports and egress port",
            None => "the program's ports and forwarded ports",
        };
        shortfalls.push(format!(
            "ip = \"private\" keeps out other users, but not this user, on Linux: the sandbox's \
             network namespace belongs to the user that runs sandy, so a process of this user \
             outside the sandbox can enter it (nsenter) and reach {ports} there without a \
             relay, as it reaches them directly with ip = \"all\"; no process of another user \
             can (docs/linux.md, \"Private network\")"
        ));
    }
    // With ip = "private" the forward listener is in the sandbox's network namespace, which no
    // other user reaches.
    if !policy.forward.is_empty() && policy.ip != IpAccess::Private {
        shortfalls.push(
            "a forwarded port keeps other users out only in part on Linux: the relay refuses a \
             connection that the kernel names as another user's, but once the client has closed \
             its socket the kernel names no owner, at once on Linux 6.8 and after a moment on \
             newer kernels, and the relay serves such a connection, so another local user can \
             deliver a write to the forwarded service, though it cannot read the answer; \
             forward only to services that are safe against such a write or authenticate their \
             clients (docs/linux.md, \"Exposed and forwarded ports\")"
                .to_string(),
        );
    }
    // In a file system view these paths are read-only binds, where the calls fail with EROFS.
    let read_only = |rule: &PathRule| rule.access != PathAccess::ReadWrite;
    if policy.path_metadata == PathMetadata::Deny
        && policy.view == FileView::All
        && policy.paths.iter().any(read_only)
    {
        shortfalls.push(
            "path_metadata = \"deny\" is enforced only in part on Linux: through a descriptor it \
             opened for reading, the program can still change the mode, except the setuid and \
             setgid bits, and the times of a file or directory it may only read (fchmod, \
             futimens), for example make a file of a read path writable for other local users, \
             because seccomp cannot tell such a descriptor from one opened for writing and cp, \
             touch and many runtimes need both calls on the files they write; the content, the \
             owner and the extended attributes stay protected (docs/linux.md, \"Metadata \
             through open files\")"
                .to_string(),
        );
    }
    if policy.view == FileView::Policy {
        shortfalls.extend(view_shortfalls(policy));
    }
    shortfalls
}

/// What a file system view leaves visible of the host (docs/linux.md, "File system view").
fn view_shortfalls(policy: &ResolvedPolicy) -> Vec<String> {
    let hides = "filesystem.view = \"policy\" hides paths only in part on Linux";
    if policy.paths.iter().any(|rule| rule.path == Path::new("/")) {
        return vec![
            "filesystem.view = \"policy\" hides nothing here: the policy makes / readable, so the \
             view holds the whole file system of the host; grant the directories the program \
             needs instead of / (docs/linux.md, \"File system view\")"
                .to_string(),
        ];
    }
    let mut shortfalls = vec![
        format!(
            "{hides}: statfs on a path of the view reports the host's file system there, its \
             type, size, free space and number of files, because the view binds the host's own \
             file systems (docs/linux.md, \"File system view\")"
        ),
        format!(
            "{hides}: the directories above a granted path exist in the view with their names, \
             for example /home and /home/user above a granted /home/user/project, though the \
             program cannot list them (docs/linux.md, \"File system view\")"
        ),
        format!(
            "{hides}: the link count of a granted file still counts its names outside the view, \
             so the program learns that a file has another name, though not where \
             (docs/linux.md, \"File system view\")"
        ),
    ];
    let proc_granted = policy
        .paths
        .iter()
        .any(|rule| rule.path.starts_with("/proc") || Path::new("/proc").starts_with(&rule.path));
    if proc_granted {
        shortfalls.push(format!(
            "{hides}: with /proc granted, /proc/self/mountinfo lists every mount of the view with \
             the host's device and file system and their mount options, for example the name of \
             an encrypted volume, and the mount table of a process outside the sandbox lists the \
             host's mounts with their paths (docs/linux.md, \"File system view\")"
        ));
    }
    shortfalls
}

/// The Landlock rules this policy gets on this host, for the callers that need the rules alone:
/// the notes above and the diagnostic mode. `None` when the host has no Landlock, where sandy
/// refuses to start the program anyway.
pub fn landlock_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> Option<LandlockConfig> {
    let &version = host.landlock.as_ref().ok()?;
    let loader = program_loader(policy);
    Some(landlock_config(
        policy,
        &host.system_paths,
        loader.as_deref(),
        ABI::from(version),
    ))
}

fn plan_item(
    requirement: Requirement,
    policy: &ResolvedPolicy,
    host: &HostCapabilities,
    abi: Result<ABI, &str>,
    conflict: Option<&str>,
) -> PlanItem {
    let enforced = |mechanism: String| PlanItem::enforced(requirement, mechanism);
    let unavailable = |reason: &str| PlanItem::unavailable(requirement, reason);
    let abi = match abi {
        Ok(abi) => abi,
        Err(reason) => match requirement {
            Requirement::FilesystemConfined
            | Requirement::ProcessMemoryIsolated
            | Requirement::SignalsIsolated => return unavailable(reason),
            _ => ABI::Unsupported,
        },
    };
    match requirement {
        Requirement::FilesystemConfined => {
            if let Some(conflict) = conflict {
                unavailable(conflict)
            } else if let Err(reason) = &host.seccomp {
                unavailable(&format!(
                    "without the seccomp filter, opening a file with access mode 3 bypasses \
                     Landlock: {reason}"
                ))
            } else {
                let mut mechanism = format!(
                    "Landlock ABI {abi}; seccomp denies opening with access mode 3 and openat2"
                );
                if abi < ABI::V3 {
                    mechanism.push_str(&format!(
                        ", and truncate and O_TRUNC on read-only opens, which Landlock ABI {abi} \
                         cannot restrict"
                    ));
                }
                enforced(mechanism)
            }
        }
        Requirement::NoPrivilegeEscalation => {
            match (&host.unprivileged, &host.no_new_privs, &host.seccomp) {
                (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
                    unavailable(reason)
                }
                _ => enforced(format!("no_new_privs; {FILTER_BASELINE}")),
            }
        }
        Requirement::ProcessMemoryIsolated => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => enforced(format!("Landlock ptrace scope; {FILTER_PROCESSES}")),
        },
        Requirement::InheritedHandlesClosed => enforced(
            "close-on-exec on every descriptor above 2 (close_range, or /proc/self/fd before \
             Linux 5.11)"
                .to_string(),
        ),
        Requirement::EnvironmentControlled => {
            enforced("execve with only the policy environment".to_string())
        }
        Requirement::InboundIpDenied => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => {
                let mut mechanism =
                    "seccomp denies listen, accept and accept4 for every socket".to_string();
                let binds = port_zero_binds(host);
                if binds & BIND_UDP != 0 {
                    mechanism.push_str(
                        "; Landlock ABI 10 lets TCP and UDP sockets bind only to a port the \
                         kernel chooses",
                    );
                } else if binds & BIND_TCP != 0 {
                    mechanism.push_str(
                        "; Landlock ABI 4 lets TCP sockets bind only to a port the kernel chooses",
                    );
                }
                enforced(mechanism)
            }
        },
        Requirement::IpNetworkDenied => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => {
                let mut mechanism =
                    "seccomp socket family allowlist without AF_INET, AF_INET6 and AF_NETLINK; \
                     io_uring denied"
                        .to_string();
                if abi >= ABI::V4 {
                    mechanism.push_str("; Landlock ABI 4 denies TCP bind and connect");
                }
                enforced(mechanism)
            }
        },
        Requirement::UnixSocketsDenied => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => {
                let mut mechanism =
                    "seccomp denies AF_UNIX sockets and datagram socket pairs".to_string();
                if abi >= ABI::V6 {
                    mechanism.push_str("; Landlock ABI 6 abstract socket scope");
                }
                if abi >= ABI::V9 {
                    mechanism.push_str("; Landlock ABI 9 denies pathname socket connections");
                }
                enforced(mechanism)
            }
        },
        Requirement::ChildProcessesDenied => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => enforced(
                "seccomp denies fork, vfork and clone without CLONE_THREAD (clone3 fails with \
                 ENOSYS); threads and execve stay allowed"
                    .to_string(),
            ),
        },
        Requirement::ChildProcessesContained => {
            match (&host.seccomp, &host.pidfd, &host.process_group) {
                (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
                    unavailable(reason)
                }
                (Ok(()), Ok(()), Ok(())) if pid_namespace(policy, host) => {
                    enforced(CONTAINED_PID_NAMESPACE.to_string())
                }
                (Ok(()), Ok(()), Ok(())) => enforced(CONTAINED_GROUP.to_string()),
            }
        }
        Requirement::EndsWithParent => match (&host.landlock, &host.seccomp, &host.pidfd) {
            (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => unavailable(reason),
            _ => enforced(format!(
                "a watcher process outside the sandbox, not a child of the program, polls pidfds \
                 for sandy's parent and the program; when the parent ends it sends SIGTERM to the \
                 program (with children = \"contained\": to the supervising sandy) and SIGKILL \
                 {} s later; in a session of its own with its signals blocked; confined by \
                 no_new_privs, Landlock ABI {abi} without file access or TCP, and a seccomp \
                 filter that allows only polling, pidfd_send_signal, ending and memory calls",
                crate::watch::GRACE.as_secs()
            )),
        },
        Requirement::ExposedPortsRelayed | Requirement::ForwardedPortsRelayed => {
            match (&host.landlock, &host.seccomp, &host.pidfd) {
                (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
                    unavailable(reason)
                }
                _ => enforced(relay_mechanism(abi, policy.ip == IpAccess::Private)),
            }
        }
        Requirement::MetadataConfined => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => enforced(FILTER_METADATA.to_string()),
        },
        Requirement::Win32kDenied => enforced(NO_WIN32K.to_string()),
        Requirement::IpNetworkPrivate => match (&host.user_namespaces, &host.seccomp) {
            (Err(Missing::Unavailable(reason)), _) | (_, Err(reason)) => unavailable(reason),
            (Err(Missing::NeedsSetup(reason)), _) => PlanItem::needs_setup(requirement, reason),
            (Ok(()), Ok(())) => enforced(PRIVATE_NETWORK.to_string()),
        },
        // The broker serves a listener in the sandbox's network namespace, so it needs what the
        // private network needs, and what the relay needs to confine itself and watch the program.
        // What setup cannot fix comes first, so that the item needs setup only when setup is all
        // that is missing.
        Requirement::EgressBrokered => {
            match (
                &host.user_namespaces,
                &host.landlock,
                &host.seccomp,
                &host.pidfd,
            ) {
                (Err(Missing::Unavailable(reason)), ..)
                | (_, Err(reason), _, _)
                | (_, _, Err(reason), _)
                | (_, _, _, Err(reason)) => unavailable(reason),
                (Err(Missing::NeedsSetup(reason)), ..) => {
                    PlanItem::needs_setup(requirement, reason)
                }
                _ => enforced(broker_mechanism(abi)),
            }
        }
        Requirement::PathsHidden => {
            let erratum = match &host.landlock_errata {
                Ok(errata) if errata & ERRATUM_3 != 0 => Ok(()),
                Ok(errata) => Err(format!(
                    "the file system view needs the fix of Landlock erratum 3, which this kernel \
                     lacks (errata {errata:#x}): Landlock rights could widen through a directory \
                     that a bind mount disconnected"
                )),
                Err(reason) => Err(format!(
                    "the file system view needs the fix of Landlock erratum 3, and {reason}"
                )),
            };
            match (&host.user_namespaces, &host.seccomp, erratum) {
                (_, Err(reason), _) | (Err(Missing::Unavailable(reason)), _, _) => {
                    unavailable(reason)
                }
                (_, _, Err(reason)) => unavailable(&reason),
                (Err(Missing::NeedsSetup(reason)), _, _) => {
                    PlanItem::needs_setup(requirement, reason)
                }
                (Ok(()), Ok(()), Ok(())) => enforced(VIEW.to_string()),
            }
        }
        // The kernel sends the job control signals of a terminal without the check that the
        // Landlock scope hooks, so the scope alone does not isolate signals.
        Requirement::SignalsIsolated => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) if abi >= ABI::V6 => enforced(
                "Landlock ABI 6 signal scope; seccomp denies setpgid into a process group that \
                 exists and the terminal ioctls TIOCSPGRP, TIOCSWINSZ and TIOCSIG"
                    .to_string(),
            ),
            Ok(()) if pid_namespace(policy, host) => enforced(SIGNALS_PID_NAMESPACE.to_string()),
            Ok(()) => {
                let without = match (&host.pid_namespace, policy.children) {
                    (Err(reason), ChildProcesses::Contained) => {
                        format!(", and no PID namespace for children = \"contained\": {reason}")
                    }
                    (Ok(()), ChildProcesses::Contained) => {
                        ", and children = \"contained\" gets no PID namespace while the policy \
                         grants a path of /proc"
                            .to_string()
                    }
                    _ => ", or with children = \"contained\" a PID namespace".to_string(),
                };
                unavailable(&format!(
                    "signal isolation needs Landlock ABI 6 (Linux 6.12){without}; this kernel has \
                     ABI {abi}"
                ))
            }
        },
    }
}

/// The file system view of `filesystem.view = "policy"`: a bind for every path a Landlock rule
/// names, so the view shows what the rules grant and nothing else, and the symbolic links on the
/// way to them. A bind gets the rights of every path that holds it, as Landlock grants them: it
/// is writable inside a writable path, and executable inside a path with an execute rule or a
/// library directory of the system set, which the loader maps as code.
fn view_config(policy: &ResolvedPolicy, landlock: &LandlockConfig, system: &[SystemPath]) -> View {
    let writable = |path: &Path| {
        policy
            .paths
            .iter()
            .any(|rule| rule.access == PathAccess::ReadWrite && path.starts_with(&rule.path))
    };
    let executable = |path: &Path| {
        let library = system
            .iter()
            .any(|entry| entry.usage == SystemUse::Library && path.starts_with(&entry.path));
        library
            || landlock
                .rules
                .iter()
                .any(|rule| rule.access.contains(AccessFs::Execute) && path.starts_with(&rule.path))
    };
    let mut binds: Vec<Bind> = landlock
        .rules
        .iter()
        .map(|rule| Bind {
            path: rule.path.clone(),
            is_dir: rule.is_dir,
            writable: writable(&rule.path),
            executable: executable(&rule.path),
        })
        .collect();
    binds.sort_by(|a, b| a.path.cmp(&b.path));
    binds.dedup_by(|later, kept| later.path == kept.path);

    let bound = |path: &Path| landlock.rules.iter().any(|rule| rule.path == path);
    let mut names: Vec<PathBuf> = policy.links.clone();
    names.extend(
        system
            .iter()
            .filter(|entry| bound(&entry.path))
            .flat_map(|entry| entry.links.iter().cloned()),
    );
    names.extend(executed_names(policy));
    names.sort();
    names.dedup();
    let links = names
        .into_iter()
        .filter(|name| !binds.iter().any(|bind| name.starts_with(&bind.path)))
        .filter_map(|name| {
            let target = std::fs::read_link(&name).ok()?;
            Some(Link { path: name, target })
        })
        .collect();
    View { binds, links }
}

/// The symbolic links that the kernel passes when it executes the program: the names of its
/// interpreters as their `#!` lines write them, and of each loader as its ELF header writes it,
/// up to `SHEBANG_LEVELS` scripts deep.
fn executed_names(policy: &ResolvedPolicy) -> Vec<PathBuf> {
    let mut links = Vec::new();
    let Some(mut file) = policy.program.clone() else {
        return links;
    };
    for _ in 0..=SHEBANG_LEVELS {
        if let Some(loader) = loader::interpreter(&file) {
            links.extend(system::links_on_the_way(&loader));
        }
        let Some(interpreter) = sandy_core::shebang(&file) else {
            break;
        };
        links.extend(system::links_on_the_way(&interpreter));
        let Ok(next) = interpreter.canonicalize() else {
            break;
        };
        file = next;
    }
    links
}

/// One relay process serves exposed and forwarded ports, so both requirements name it.
fn relay_mechanism(abi: ABI, private: bool) -> String {
    let mut mechanism = format!(
        "relay process outside the sandbox, not a child of the program, that ends with it \
         (pidfd); confined by no_new_privs, Landlock ABI {abi} without file access"
    );
    if abi >= ABI::V4 {
        mechanism.push_str(", TCP connect only to the relay targets and no bind");
    }
    mechanism.push_str(", and a seccomp filter that allows only TCP, copying bytes and threads");
    if private {
        mechanism.push_str(
            "; the forward listeners are bound inside the sandbox's network namespace and handed \
             to the relay, and an exposed connection starts inside it with a socket from a \
             factory process there that can create TCP sockets and nothing else",
        );
    }
    mechanism
}

fn broker_mechanism(abi: ABI) -> String {
    let mut mechanism = format!(
        "a broker process in the host's network namespace, not a child of the program, that ends \
         with it (pidfd); its listener is bound inside the sandbox's network namespace and handed \
         to it; it takes one SOCKS5 CONNECT to an IP address per connection, checks the \
         destination against the IANA special-purpose registries and asks the kernel's routing \
         tables (NETLINK_ROUTE) whether it is this host or its local network, refuses a \
         connection that reached this host after all, and copies bytes; confined by \
         no_new_privs, Landlock ABI {abi} without file access"
    );
    if abi >= ABI::V4 {
        mechanism.push_str(" and without TCP bind");
    }
    mechanism.push_str(
        ", and a seccomp filter that allows only TCP sockets, the route lookups, copying bytes \
         and threads",
    );
    mechanism
}

/// The policy checks for writable paths (never executable, nothing inside a writable path) see
/// only the policy paths; the minimal system set is added here. Its entries are code and
/// configuration that programs trust: the dynamic loader, shared libraries, /etc/ld.so.cache and
/// /etc/ld.so.preload, which decide which code runs, and files such as /etc/hosts. A writable policy path that contains an entry, or lies
/// inside a directory entry, would let the program change them for the next start and for
/// programs outside the sandbox. Missing entries count, because the program could create them.
/// /dev/null is writable in the set itself.
///
/// The comparison is the one of rules 3 and 4 (`PathIdentity`), so an alias of a directory of
/// the set counts as that directory. Without the mount table sandy cannot see such an alias, so
/// it refuses the policy, as the resolver does.
fn system_conflict(policy: &ResolvedPolicy, system: &[SystemPath]) -> Option<String> {
    if policy.system != SystemAccess::Minimal {
        return None;
    }
    let protected: Vec<ProtectedPath> = system
        .iter()
        .filter(|entry| entry.usage != SystemUse::Discard)
        .map(|entry| {
            if entry.is_dir {
                ProtectedPath::tree(&entry.path)
            } else {
                ProtectedPath::entry(&entry.path)
            }
        })
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
/// `trust`). They are no policy paths, so rules 3 and 4 do not cover them, and Landlock cannot
/// carve one file out of a writable tree, so the only way to keep what the policy promises is to
/// refuse it. Unlike the system set this applies with `system = "none"` as well: the locations
/// belong to the user, not to the set.
///
/// When no source names the home directory, sandy cannot tell whether a writable path reaches
/// the locations below it, so a policy with a writable path is refused, as without the mount
/// table. A policy without one reaches no location.
fn trust_conflict(
    policy: &ResolvedPolicy,
    trusted: &Result<Vec<ProtectedPath>, String>,
) -> Option<String> {
    let trusted = match trusted {
        Ok(trusted) => trusted,
        Err(reason) => {
            let writable = |rule: &PathRule| rule.access == PathAccess::ReadWrite;
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

/// Where the loader of the program is, with symbolic links resolved. A program that names none,
/// or one that does not exist, is left to `execve` and its own error.
fn program_loader(policy: &ResolvedPolicy) -> Option<PathBuf> {
    loader::interpreter(policy.program.as_ref()?)?
        .canonicalize()
        .ok()
}

/// Why the kernel could not execute the program: the loader it names in its ELF header lies
/// outside every path this configuration executes. Without this, `execve` would fail with
/// "Permission denied" after the sandbox is in place, which looks like a broken program. It
/// happens on a host whose loader the minimal system set does not name and that `loader_rule`
/// does not grant either, or with `system = "none"` and no `read_exec` path for the loader.
fn loader_problem(loader: Option<&Path>, executable: &[PathBuf]) -> Option<String> {
    let loader = loader?;
    if executable.iter().any(|allowed| loader.starts_with(allowed)) {
        return None;
    }
    Some(format!(
        "the kernel executes the loader {} of the program, which no read_exec path and no entry \
         of the minimal system set covers; grant it with --read-exec",
        loader.display()
    ))
}

/// An execute rule for the program's loader, when no rule covers it yet. Only for a loader in a
/// system location (`loader::is_system_loader`) and never inside a writable path, where the
/// program could replace what it executes: the loader comes from the header of the program file,
/// which is untrusted input. Every other case becomes the refusal of `loader_problem`.
fn loader_rule(
    policy: &ResolvedPolicy,
    loader: Option<&Path>,
    rules: &[PathRights],
) -> Option<PathRights> {
    let loader = loader?;
    if policy.system != SystemAccess::Minimal || !loader::is_system_loader(loader) {
        return None;
    }
    let covered = |rule: &PathRights| {
        rule.access.contains(AccessFs::Execute) && loader.starts_with(&rule.path)
    };
    if rules.iter().any(covered) {
        return None;
    }
    // Without the mount table an alias of a writable path is indistinguishable from any other
    // directory, so sandy grants nothing; `loader_problem` then refuses the policy.
    let identity = PathIdentity::read().ok()?;
    let inside_writable = |rule: &PathRule| {
        rule.access == PathAccess::ReadWrite && identity.within(loader, &rule.path)
    };
    if policy.paths.iter().any(inside_writable) {
        return None;
    }
    Some(PathRights {
        path: loader.to_path_buf(),
        is_dir: false,
        access: system_rights(SystemUse::Execute),
    })
}

/// The paths this configuration executes, for `ResolvedPolicy::interpreter_problem`: the policy's
/// `read_exec` paths and the entries of the system set that hold code, as the Landlock rules
/// carry them.
fn executable_paths(landlock: &LandlockConfig) -> Vec<PathBuf> {
    landlock
        .rules
        .iter()
        .filter(|rule| rule.access.contains(AccessFs::Execute))
        .map(|rule| rule.path.clone())
        .collect()
}

fn landlock_config(
    policy: &ResolvedPolicy,
    system: &[SystemPath],
    loader: Option<&Path>,
    abi: ABI,
) -> LandlockConfig {
    let unix_all = policy.unix_sockets == NetworkAccess::All;
    let mut handled_fs = AccessFs::from_all(abi);
    if unix_all {
        // `unix_sockets = "all"` allows every socket, independent of the filesystem rules.
        handled_fs.remove(AccessFs::ResolveUnix);
    }
    let handled_net = if policy.ip == IpAccess::None && abi >= ABI::V4 {
        AccessNet::BindTcp | AccessNet::ConnectTcp
    } else {
        BitFlags::empty()
    };
    let mut scopes = BitFlags::empty();
    if abi >= ABI::V6 {
        if policy.signals == SignalScope::Isolated {
            scopes |= Scope::Signal;
        }
        if !unix_all {
            scopes |= Scope::AbstractUnixSocket;
        }
    }

    let fit = |access: BitFlags<AccessFs>, is_dir: bool| {
        let access = access & handled_fs;
        if is_dir {
            access
        } else {
            access & AccessFs::from_file(abi)
        }
    };
    let mut rules: Vec<PathRights> = policy
        .paths
        .iter()
        .map(|rule| PathRights {
            path: rule.path.clone(),
            is_dir: rule.is_dir,
            access: fit(policy_rights(rule.access, unix_all), rule.is_dir),
        })
        .collect();
    if policy.system == SystemAccess::Minimal {
        let ip = policy.ip != IpAccess::None;
        let needed = system
            .iter()
            .filter(|entry| entry.needed == Needed::Always || ip);
        rules.extend(needed.map(|entry| PathRights {
            path: entry.path.clone(),
            is_dir: entry.is_dir,
            access: fit(system_rights(entry.usage), entry.is_dir),
        }));
    }
    if let Some(mut rule) = loader_rule(policy, loader, &rules) {
        rule.access = fit(rule.access, rule.is_dir);
        rules.push(rule);
    }
    rules.retain(|rule| !rule.access.is_empty());

    LandlockConfig {
        abi,
        handled_fs,
        handled_net,
        scopes,
        rules,
    }
}

const READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ReadFile | ReadDir});

/// Writable paths never get execute, symbolic links, named pipes or device nodes. A symbolic
/// link or a named pipe in a directory that a process outside the sandbox also uses could
/// redirect or block that process.
fn policy_rights(access: PathAccess, unix_all: bool) -> BitFlags<AccessFs> {
    match access {
        PathAccess::Read => READ,
        PathAccess::ReadExec => READ | AccessFs::Execute,
        PathAccess::ReadWrite => {
            let mut rights = READ
                | make_bitflags!(AccessFs::{
                    WriteFile | Truncate | RemoveDir | RemoveFile | MakeDir | MakeReg | Refer
                        | IoctlDev
                });
            if unix_all {
                rights |= AccessFs::MakeSock;
            }
            rights
        }
    }
}

fn system_rights(usage: SystemUse) -> BitFlags<AccessFs> {
    match usage {
        SystemUse::Read | SystemUse::Library => READ,
        SystemUse::Execute => AccessFs::ReadFile | AccessFs::Execute,
        SystemUse::Discard => AccessFs::ReadFile | AccessFs::WriteFile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::RelayPair;
    use sandy_core::{
        EgressReach, EnvironmentPolicy, ExposedPort, ForwardedPort, Status, WindowsPolicy,
    };

    fn host(abi: Option<i32>) -> HostCapabilities {
        let system = |path: &str, is_dir, usage, needed| SystemPath {
            path: PathBuf::from(path),
            is_dir,
            usage,
            needed,
            links: Vec::new(),
        };
        let existing = vec![
            system("/usr/lib", true, SystemUse::Library, Needed::Always),
            system(
                "/usr/lib64/ld-linux-x86-64.so.2",
                false,
                SystemUse::Execute,
                Needed::Always,
            ),
            system("/dev/null", false, SystemUse::Discard, Needed::Always),
            system("/etc/hosts", false, SystemUse::Read, Needed::WithIpNetwork),
        ];
        // A candidate that does not exist on this host still has a location.
        let missing = system("/etc/ld.so.preload", false, SystemUse::Read, Needed::Always);
        HostCapabilities {
            landlock: abi.ok_or_else(|| "no Landlock here".to_string()),
            landlock_errata: Ok(0xf),
            thread_count: Ok(()),
            process_group: Ok(()),
            user_namespaces: Ok(()),
            pid_namespace: Ok(()),
            seccomp: Ok(()),
            no_new_privs: Ok(()),
            unprivileged: Ok(()),
            pidfd: Ok(()),
            system_locations: [existing.clone(), vec![missing]].concat(),
            system_paths: existing,
            trusted_locations: Ok(vec![sandy_core::ProtectedPath::entry("/home/someone")]),
            path_locations: vec![sandy_core::ProtectedPath::entry("/data/bin")],
        }
    }

    fn rule(path: &str, access: PathAccess, is_dir: bool) -> PathRule {
        PathRule {
            path: PathBuf::from(path),
            access,
            is_dir,
        }
    }

    fn policy() -> ResolvedPolicy {
        ResolvedPolicy {
            paths: vec![
                rule("/data", PathAccess::ReadWrite, true),
                rule("/opt/app", PathAccess::ReadExec, true),
                rule("/opt/app/bin/app", PathAccess::ReadExec, false),
                rule("/srv/share", PathAccess::Read, true),
            ],
            program: Some(PathBuf::from("/opt/app/bin/app")),
            links: Vec::new(),
            system: SystemAccess::Minimal,
            ip: IpAccess::None,
            unix_sockets: NetworkAccess::None,
            expose: Vec::new(),
            forward: Vec::new(),
            egress: None,
            view: sandy_core::FileView::All,
            signals: SignalScope::Isolated,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }

    fn status(plan: &LinuxPlan, requirement: Requirement) -> &Status {
        let mut matching = plan.items.iter().filter(|i| i.requirement == requirement);
        let item = matching.next().expect("requirement not reported");
        assert!(matching.next().is_none(), "requirement reported twice");
        &item.status
    }

    fn unavailable(plan: &LinuxPlan) -> Vec<Requirement> {
        plan.items
            .iter()
            .filter(|item| !item.is_enforced())
            .map(|item| item.requirement)
            .collect()
    }

    fn rights(plan: &LinuxPlan, path: &str) -> BitFlags<AccessFs> {
        let landlock = &plan.sandbox.as_ref().unwrap().landlock;
        let rule = landlock.rules.iter().find(|r| r.path == Path::new(path));
        rule.unwrap_or_else(|| panic!("no rule for {path}")).access
    }

    #[test]
    fn a_current_kernel_enforces_every_requirement() {
        let policy = policy();
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        for requirement in policy.requirements() {
            status(&plan, requirement);
        }
        assert_eq!(plan.items.len(), policy.requirements().len());
        assert!(plan.sandbox.is_some());
    }

    #[test]
    fn without_landlock_the_filesystem_is_not_confined() {
        let plan = plan_for(&policy(), &host(None));
        assert_eq!(
            unavailable(&plan),
            vec![
                Requirement::FilesystemConfined,
                Requirement::ProcessMemoryIsolated,
                Requirement::SignalsIsolated,
            ]
        );
        assert_eq!(
            status(&plan, Requirement::FilesystemConfined),
            &Status::Unavailable {
                reason: "no Landlock here".to_string()
            }
        );
        assert!(plan.sandbox.is_none());
    }

    #[test]
    fn signal_isolation_needs_abi_6() {
        let plan = plan_for(&policy(), &host(Some(5)));
        assert_eq!(unavailable(&plan), vec![Requirement::SignalsIsolated]);
        assert!(plan.sandbox.is_none());

        let mut any_signals = policy();
        any_signals.signals = SignalScope::Any;
        let plan = plan_for(&any_signals, &host(Some(5)));
        assert_eq!(unavailable(&plan), vec![]);
        let sandbox = plan.sandbox.unwrap();
        assert!(sandbox.landlock.scopes.is_empty());
        assert!(!sandbox.filter.isolate_signals);

        let sandbox = plan_for(&policy(), &host(Some(6))).sandbox.unwrap();
        assert!(sandbox.landlock.scopes.contains(Scope::Signal));
        assert!(sandbox.filter.isolate_signals);
    }

    #[test]
    fn without_seccomp_the_filter_requirements_are_unavailable() {
        let mut host = host(Some(9));
        host.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy(), &host);
        assert_eq!(
            unavailable(&plan),
            vec![
                Requirement::FilesystemConfined,
                Requirement::NoPrivilegeEscalation,
                Requirement::ProcessMemoryIsolated,
                Requirement::IpNetworkDenied,
                Requirement::UnixSocketsDenied,
                Requirement::SignalsIsolated,
                Requirement::MetadataConfined,
            ]
        );
        assert!(plan.sandbox.is_none());
    }

    #[test]
    fn metadata_rules_follow_the_policy() {
        let plan = plan_for(&policy(), &host(Some(9)));
        assert!(plan.sandbox.unwrap().filter.deny_path_metadata);
        let mut allow = policy();
        allow.path_metadata = PathMetadata::Allow;
        let plan = plan_for(&allow, &host(Some(9)));
        assert!(
            plan.items
                .iter()
                .all(|i| i.requirement != Requirement::MetadataConfined)
        );
        assert!(!plan.sandbox.unwrap().filter.deny_path_metadata);
    }

    #[test]
    fn landlock_needs_a_way_to_count_threads() {
        let mut host = host(Some(9));
        host.thread_count = Err("no /proc".to_string());
        let plan = plan_for(&policy(), &host);
        assert_eq!(
            unavailable(&plan),
            vec![
                Requirement::FilesystemConfined,
                Requirement::ProcessMemoryIsolated,
                Requirement::SignalsIsolated,
            ]
        );
        assert!(plan.sandbox.is_none());
    }

    #[test]
    fn relayed_ports_need_pidfd_landlock_and_seccomp() {
        let mut policy = policy();
        policy.ip = IpAccess::All;
        policy.expose = vec![ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        policy.forward = vec![ForwardedPort {
            port: 18082,
            to: "127.0.0.1:8082".parse().unwrap(),
        }];
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        let relay = plan.sandbox.unwrap().relay.unwrap();
        let pair = |listen: &str, target: &str| RelayPair {
            listen: listen.parse().unwrap(),
            target: target.parse().unwrap(),
        };
        // One relay serves both directions: exposed ports listen outside and connect to the
        // program, forwarded ports listen on the program's port and connect outside.
        assert_eq!(
            relay.pairs,
            vec![
                pair("127.0.0.1:18080", "127.0.0.1:8080"),
                pair("127.0.0.1:18082", "127.0.0.1:8082"),
            ]
        );
        assert_eq!(relay.abi, ABI::V9);
        // Signals are isolated, so the program cannot stop the relay, and it has no watchdog.
        assert!(!relay.watchdog);
        let mut any_signals = policy.clone();
        any_signals.signals = SignalScope::Any;
        let plan = plan_for(&any_signals, &host(Some(9)));
        assert!(plan.sandbox.unwrap().relay.unwrap().watchdog);

        let mut no_pidfd = host(Some(9));
        no_pidfd.pidfd = Err("old kernel".to_string());
        let plan = plan_for(&policy, &no_pidfd);
        assert_eq!(
            unavailable(&plan),
            vec![
                Requirement::ExposedPortsRelayed,
                Requirement::ForwardedPortsRelayed
            ]
        );
        assert!(plan.sandbox.is_none());

        policy.expose.clear();
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(plan.sandbox.unwrap().relay.unwrap().pairs.len(), 1);

        policy.forward.clear();
        let plan = plan_for(&policy, &host(Some(9)));
        assert!(plan.sandbox.unwrap().relay.is_none());
    }

    /// `ip = "private"` runs the program in namespaces of its own, with the filter of
    /// `ip = "all"` as a second layer, and both relays know the namespace.
    #[test]
    fn a_private_network_enters_namespaces_and_allows_ip_inside() {
        let mut policy = policy();
        policy.ip = IpAccess::Private;
        policy.expose = vec![ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        policy.forward = vec![ForwardedPort {
            port: 18082,
            to: "127.0.0.1:8082".parse().unwrap(),
        }];
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        let Status::Enforced { mechanism } = status(&plan, Requirement::IpNetworkPrivate) else {
            panic!("{plan:?}");
        };
        assert!(mechanism.contains("network namespace"), "{mechanism}");
        let Status::Enforced { mechanism } = status(&plan, Requirement::ForwardedPortsRelayed)
        else {
            panic!("{plan:?}");
        };
        assert!(mechanism.contains("handed to the relay"), "{mechanism}");
        let sandbox = plan.sandbox.unwrap();
        assert_eq!(
            sandbox.namespaces,
            Some(Namespaces {
                network: true,
                mount: false,
                pid: false,
            })
        );
        assert!(sandbox.relay.unwrap().private);
        assert!(sandbox.filter.allow_ip && !sandbox.filter.deny_inbound);
        assert!(sandbox.landlock.handled_net.is_empty());
        assert_eq!(sandbox.client_binds, 0);

        for ip in [IpAccess::None, IpAccess::Client, IpAccess::All] {
            let mut other = policy.clone();
            other.ip = ip;
            other.expose.clear();
            other.forward.clear();
            let sandbox = plan_for(&other, &host(Some(9))).sandbox.unwrap();
            assert_eq!(sandbox.namespaces, None, "{ip:?}");
        }
    }

    /// What the host says against user namespaces becomes the requirement's status: a matter of
    /// `sandy setup` only for the AppArmor restriction.
    #[test]
    fn a_private_network_follows_what_the_host_says() {
        let mut policy = policy();
        policy.ip = IpAccess::Private;
        let mut restricted = host(Some(9));
        restricted.user_namespaces = Err(Missing::NeedsSetup("restricted".to_string()));
        let plan = plan_for(&policy, &restricted);
        assert_eq!(
            status(&plan, Requirement::IpNetworkPrivate),
            &Status::NeedsSetup {
                reason: "restricted".to_string()
            }
        );
        assert!(plan.sandbox.is_none());

        let mut disabled = host(Some(9));
        disabled.user_namespaces = Err(Missing::Unavailable("disabled".to_string()));
        let plan = plan_for(&policy, &disabled);
        assert_eq!(
            status(&plan, Requirement::IpNetworkPrivate),
            &Status::Unavailable {
                reason: "disabled".to_string()
            }
        );

        let mut no_seccomp = host(Some(9));
        no_seccomp.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy, &no_seccomp);
        assert!(unavailable(&plan).contains(&Requirement::IpNetworkPrivate));
        no_seccomp.user_namespaces = Err(Missing::NeedsSetup("restricted".to_string()));
        let plan = plan_for(&policy, &no_seccomp);
        assert_eq!(
            status(&plan, Requirement::IpNetworkPrivate),
            &Status::Unavailable {
                reason: "no seccomp".to_string()
            }
        );
    }

    /// The egress broker serves a listener in the sandbox's network namespace, so it is
    /// enforced where the private network is, and needs setup or is unavailable where that is.
    /// Its watchdog follows `signals` as the relay's does.
    #[test]
    fn the_egress_broker_follows_the_private_network() {
        let mut policy = policy();
        policy.ip = IpAccess::Private;
        policy.egress = Some(sandy_core::Egress {
            port: 1080,
            reach: EgressReach::PublicAndLocal,
        });
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        let Status::Enforced { mechanism } = status(&plan, Requirement::EgressBrokered) else {
            panic!("{plan:?}");
        };
        assert!(
            mechanism.contains("host's network namespace"),
            "{mechanism}"
        );
        assert!(mechanism.contains("without TCP bind"), "{mechanism}");
        let broker = plan.sandbox.unwrap().broker.unwrap();
        assert_eq!(broker.listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(broker.reach, EgressReach::PublicAndLocal);
        assert!(!broker.watchdog);
        policy.signals = SignalScope::Any;
        let broker = plan_for(&policy, &host(Some(9))).sandbox.unwrap().broker;
        assert!(broker.unwrap().watchdog);

        let mut restricted = host(Some(9));
        restricted.user_namespaces = Err(Missing::NeedsSetup("restricted".to_string()));
        let plan = plan_for(&policy, &restricted);
        for requirement in [Requirement::IpNetworkPrivate, Requirement::EgressBrokered] {
            assert_eq!(
                status(&plan, requirement),
                &Status::NeedsSetup {
                    reason: "restricted".to_string()
                },
                "{requirement:?}"
            );
        }
        let mut disabled = host(Some(9));
        disabled.user_namespaces = Err(Missing::Unavailable("disabled".to_string()));
        let plan = plan_for(&policy, &disabled);
        assert_eq!(
            status(&plan, Requirement::EgressBrokered),
            &Status::Unavailable {
                reason: "disabled".to_string()
            }
        );
        for broken in [
            HostCapabilities {
                landlock: Err("no Landlock".to_string()),
                ..host(Some(9))
            },
            HostCapabilities {
                pidfd: Err("no pidfd".to_string()),
                ..host(Some(9))
            },
        ] {
            let plan = plan_for(&policy, &broken);
            assert!(unavailable(&plan).contains(&Requirement::EgressBrokered));
            // What setup cannot fix wins over what it fixes, so check never exits with 2 here.
            let restricted = HostCapabilities {
                user_namespaces: Err(Missing::NeedsSetup("restricted".to_string())),
                ..broken
            };
            let plan = plan_for(&policy, &restricted);
            assert!(
                matches!(
                    status(&plan, Requirement::EgressBrokered),
                    Status::Unavailable { .. }
                ),
                "{plan:?}"
            );
        }
        policy.egress = None;
        assert_eq!(
            plan_for(&policy, &host(Some(9))).sandbox.unwrap().broker,
            None
        );
    }

    /// The forward warning of the other `ip` values does not apply in a namespace no other user
    /// reaches; the one of `ip = "private"` names the user's own processes instead.
    #[test]
    fn private_notes_name_what_stays_open() {
        let mut policy = policy();
        policy.forward = vec![ForwardedPort {
            port: 18082,
            to: "127.0.0.1:8082".parse().unwrap(),
        }];
        let warned = |policy: &ResolvedPolicy, text: &str| {
            notes(policy, &host(Some(9)))
                .iter()
                .any(|note| note.contains(text))
        };
        let forward = "another local user can deliver a write";
        let own_user = "a process of this user outside the sandbox can enter it";
        for ip in [IpAccess::Client, IpAccess::All] {
            policy.ip = ip;
            assert!(warned(&policy, forward), "{ip:?}");
            assert!(!warned(&policy, own_user), "{ip:?}");
        }
        policy.ip = IpAccess::Private;
        assert!(!warned(&policy, forward));
        assert!(warned(&policy, own_user));
        let egress_port = "and egress port there";
        assert!(!warned(&policy, egress_port));
        policy.egress = Some(sandy_core::Egress {
            port: 1080,
            reach: EgressReach::Public,
        });
        assert!(warned(&policy, egress_port));
    }

    /// `view = "policy"` enters a mount namespace and binds every rule path once: writable only
    /// inside a writable path, executable inside a path with an execute rule or a library
    /// directory of the system set.
    #[test]
    fn a_view_binds_the_rule_paths_with_their_rights() {
        let mut policy = policy();
        policy.view = FileView::Policy;
        policy
            .paths
            .push(rule("/srv/share/doc", PathAccess::Read, true));
        policy
            .paths
            .push(rule("/opt/app/data", PathAccess::Read, true));
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        let Status::Enforced { mechanism } = status(&plan, Requirement::PathsHidden) else {
            panic!("{plan:?}");
        };
        assert!(mechanism.contains("pivot_root"), "{mechanism}");
        let sandbox = plan.sandbox.unwrap();
        assert_eq!(
            sandbox.namespaces,
            Some(Namespaces {
                network: false,
                mount: true,
                pid: false,
            })
        );
        let view = sandbox.view.unwrap();
        let bind = |path: &str| {
            view.binds
                .iter()
                .find(|bind| bind.path == Path::new(path))
                .map(|bind| (bind.writable, bind.executable))
                .unwrap_or_else(|| panic!("no bind for {path}"))
        };
        assert_eq!(bind("/data"), (true, false));
        assert_eq!(bind("/srv/share"), (false, false));
        assert_eq!(bind("/srv/share/doc"), (false, false));
        assert_eq!(bind("/opt/app"), (false, true));
        // A `read` path inside a `read_exec` path keeps the execute right Landlock grants there.
        assert_eq!(bind("/opt/app/data"), (false, true));
        assert_eq!(bind("/opt/app/bin/app"), (false, true));
        assert_eq!(bind("/usr/lib"), (false, true));
        assert_eq!(bind("/usr/lib64/ld-linux-x86-64.so.2"), (false, true));
        assert_eq!(bind("/dev/null"), (false, false));
        // One bind per path, sorted, so a path follows the paths that hold it.
        let paths: Vec<&Path> = view.binds.iter().map(|bind| bind.path.as_path()).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(paths, sorted);
        assert_eq!(paths.len(), sandbox.landlock.rules.len());

        policy.view = FileView::All;
        let sandbox = plan_for(&policy, &host(Some(9))).sandbox.unwrap();
        assert_eq!(sandbox.namespaces, None);
        assert_eq!(sandbox.view, None);
    }

    /// The links the policy paths and the system entries pass are recreated where they lie
    /// outside every bind, with their text, and not where a bind already shows them.
    #[test]
    fn a_view_recreates_the_links_outside_the_binds() {
        let dir = std::env::temp_dir().join(format!("sandy-plan-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::create_dir_all(dir.join("granted")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("outside")).unwrap();
        std::os::unix::fs::symlink("../real", dir.join("granted/inside")).unwrap();
        let mut policy = policy();
        policy.view = FileView::Policy;
        policy.paths.push(rule(
            dir.join("real").to_str().unwrap(),
            PathAccess::Read,
            true,
        ));
        policy.paths.push(rule(
            dir.join("granted").to_str().unwrap(),
            PathAccess::Read,
            true,
        ));
        policy.links = vec![dir.join("granted/inside"), dir.join("outside")];
        let mut host = host(Some(9));
        host.system_paths[0].links = vec![dir.join("outside")];
        let view = plan_for(&policy, &host).sandbox.unwrap().view.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            view.links,
            vec![Link {
                path: dir.join("outside"),
                target: PathBuf::from("real"),
            }]
        );
    }

    /// The view needs user namespaces as the private network does, and a kernel with the fix of
    /// Landlock erratum 3; an unknown errata mask counts as missing.
    #[test]
    fn a_view_follows_what_the_host_says() {
        let mut policy = policy();
        policy.view = FileView::Policy;
        let mut restricted = host(Some(9));
        restricted.user_namespaces = Err(Missing::NeedsSetup("restricted".to_string()));
        let plan = plan_for(&policy, &restricted);
        assert_eq!(
            status(&plan, Requirement::PathsHidden),
            &Status::NeedsSetup {
                reason: "restricted".to_string()
            }
        );
        assert!(plan.sandbox.is_none());

        for errata in [Ok(0x3), Err("no errata here".to_string())] {
            let mut old = restricted.clone();
            old.landlock_errata = errata.clone();
            // A kernel without the fix is unavailable, which setup cannot change.
            match status(&plan_for(&policy, &old), Requirement::PathsHidden) {
                Status::Unavailable { reason } => assert!(reason.contains("erratum 3"), "{reason}"),
                other => panic!("{errata:?}: {other:?}"),
            }
        }

        let mut no_seccomp = host(Some(9));
        no_seccomp.seccomp = Err("no seccomp".to_string());
        assert!(unavailable(&plan_for(&policy, &no_seccomp)).contains(&Requirement::PathsHidden));
    }

    /// A view of a policy that makes / readable holds the whole host, which the notes say instead
    /// of what a narrower view leaves visible.
    #[test]
    fn a_view_of_the_whole_root_is_warned_about() {
        let mut policy = policy();
        policy.view = FileView::Policy;
        let hides_nothing = |policy: &ResolvedPolicy| {
            notes(policy, &host(Some(9)))
                .iter()
                .any(|note| note.contains("hides nothing here"))
        };
        assert!(!hides_nothing(&policy));
        policy.paths.push(rule("/", PathAccess::Read, true));
        assert!(hides_nothing(&policy));
        let notes = notes(&policy, &host(Some(9)));
        assert!(
            !notes.iter().any(|note| note.contains("statfs on a path")),
            "{notes:?}"
        );
        policy.view = FileView::All;
        assert!(!hides_nothing(&policy));
    }

    /// The view closes the metadata exception of `read` paths and adds its own, the mount table
    /// one only with /proc in the policy.
    #[test]
    fn view_notes_name_what_stays_visible() {
        let warned = |policy: &ResolvedPolicy, text: &str| {
            notes(policy, &host(Some(9)))
                .iter()
                .any(|note| note.contains(text))
        };
        let metadata = "path_metadata = \"deny\" is enforced only in part";
        let view_notes = [
            "statfs on a path",
            "the directories above",
            "the link count",
        ];
        let mut policy = policy();
        assert!(warned(&policy, metadata));
        assert!(!warned(&policy, view_notes[0]));
        policy.view = FileView::Policy;
        assert!(!warned(&policy, metadata));
        for note in view_notes {
            assert!(warned(&policy, note), "{note}");
        }
        assert!(!warned(&policy, "mountinfo"));
        policy.paths.push(rule("/proc", PathAccess::Read, true));
        assert!(warned(&policy, "mountinfo"));
    }

    #[test]
    fn denying_children_needs_seccomp() {
        let mut policy = policy();
        policy.children = ChildProcesses::None;
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        status(&plan, Requirement::ChildProcessesDenied);
        assert!(plan.sandbox.unwrap().filter.deny_children);

        let mut no_seccomp = host(Some(9));
        no_seccomp.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy, &no_seccomp);
        assert!(unavailable(&plan).contains(&Requirement::ChildProcessesDenied));

        policy.children = ChildProcesses::Allowed;
        let plan = plan_for(&policy, &host(Some(9)));
        assert!(!plan.sandbox.unwrap().filter.deny_children);
    }

    #[test]
    fn containing_children_needs_seccomp_and_pidfd() {
        let mut policy = policy();
        policy.children = ChildProcesses::Contained;
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        status(&plan, Requirement::ChildProcessesContained);
        let sandbox = plan.sandbox.unwrap();
        assert!(sandbox.contain);
        assert!(sandbox.filter.keep_process_group);
        assert!(!sandbox.filter.deny_children);

        let mut no_seccomp = host(Some(9));
        no_seccomp.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy, &no_seccomp);
        assert!(unavailable(&plan).contains(&Requirement::ChildProcessesContained));

        let mut no_pidfd = host(Some(9));
        no_pidfd.pidfd = Err("no pidfd_open".to_string());
        let plan = plan_for(&policy, &no_pidfd);
        assert!(unavailable(&plan).contains(&Requirement::ChildProcessesContained));

        for children in [ChildProcesses::Allowed, ChildProcesses::None] {
            policy.children = children;
            let sandbox = plan_for(&policy, &host(Some(9))).sandbox.unwrap();
            assert!(!sandbox.contain);
            assert!(!sandbox.filter.keep_process_group);
        }
    }

    /// `contained` runs the program in a PID namespace where the host gives one, keeps its process
    /// group and the denial of setsid and setpgid, and gets none where the program would see the
    /// host's /proc without a view.
    #[test]
    fn contained_uses_a_pid_namespace_where_the_host_gives_one() {
        let mut policy = policy();
        policy.children = ChildProcesses::Contained;
        let mechanism = |policy: &ResolvedPolicy, host: &HostCapabilities| {
            let plan = plan_for(policy, host);
            match status(&plan, Requirement::ChildProcessesContained) {
                Status::Enforced { mechanism } => mechanism.clone(),
                other => panic!("{other:?}"),
            }
        };
        let plan = plan_for(&policy, &host(Some(9)));
        let sandbox = plan.sandbox.unwrap();
        assert_eq!(
            sandbox.namespaces,
            Some(Namespaces {
                network: false,
                mount: false,
                pid: true,
            })
        );
        assert!(sandbox.filter.keep_process_group);
        assert!(mechanism(&policy, &host(Some(9))).contains("PID namespace"));

        let mut no_namespace = host(Some(9));
        no_namespace.pid_namespace = Err("no user namespaces".to_string());
        assert_eq!(
            plan_for(&policy, &no_namespace).sandbox.unwrap().namespaces,
            None
        );
        assert!(mechanism(&policy, &no_namespace).contains("whose leader is a guard"));

        // The host's /proc names processes by their IDs outside the namespace, and a /proc of the
        // namespace would hide the host's files of the grant; also with a view.
        for path in ["/proc", "/proc/meminfo", "/"] {
            let mut with_proc = policy.clone();
            with_proc.paths.push(rule(path, PathAccess::Read, true));
            assert_eq!(
                plan_for(&with_proc, &host(Some(9)))
                    .sandbox
                    .unwrap()
                    .namespaces,
                None
            );
            with_proc.view = FileView::Policy;
            let namespaces = plan_for(&with_proc, &host(Some(9)))
                .sandbox
                .unwrap()
                .namespaces;
            assert!(!namespaces.unwrap().pid, "{path}");
        }

        for children in [ChildProcesses::Allowed, ChildProcesses::None] {
            policy.children = children;
            assert_eq!(
                plan_for(&policy, &host(Some(9)))
                    .sandbox
                    .unwrap()
                    .namespaces,
                None
            );
        }
    }

    /// Below Landlock ABI 6 the PID namespace of `contained` isolates signals, and nothing else
    /// does: without it, or without `contained`, the requirement stays unavailable, with the
    /// reason.
    #[test]
    fn a_pid_namespace_isolates_signals_below_abi_6() {
        let mut policy = policy();
        policy.children = ChildProcesses::Contained;
        let plan = plan_for(&policy, &host(Some(4)));
        assert_eq!(unavailable(&plan), vec![]);
        let Status::Enforced { mechanism } = status(&plan, Requirement::SignalsIsolated) else {
            panic!("{plan:?}");
        };
        assert!(mechanism.contains("PID namespace"), "{mechanism}");
        let sandbox = plan.sandbox.unwrap();
        assert!(sandbox.filter.isolate_signals && sandbox.landlock.scopes.is_empty());

        let mut no_namespace = host(Some(4));
        no_namespace.pid_namespace = Err("no user namespaces".to_string());
        match status(
            &plan_for(&policy, &no_namespace),
            Requirement::SignalsIsolated,
        ) {
            Status::Unavailable { reason } => {
                assert!(reason.contains("no user namespaces"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        policy.children = ChildProcesses::Allowed;
        assert_eq!(
            unavailable(&plan_for(&policy, &host(Some(4)))),
            vec![Requirement::SignalsIsolated]
        );
        // From ABI 6 the Landlock scope isolates signals, with or without the namespace.
        policy.children = ChildProcesses::Contained;
        let plan = plan_for(&policy, &host(Some(6)));
        let Status::Enforced { mechanism } = status(&plan, Requirement::SignalsIsolated) else {
            panic!("{plan:?}");
        };
        assert!(mechanism.contains("Landlock ABI 6"), "{mechanism}");
    }

    #[test]
    fn ending_with_the_parent_needs_landlock_seccomp_and_pidfd() {
        let mut policy = policy();
        policy.end_with_parent = true;
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        status(&plan, Requirement::EndsWithParent);
        assert!(plan.sandbox.unwrap().end_with_parent);

        let mut no_pidfd = host(Some(9));
        no_pidfd.pidfd = Err("no pidfd_open".to_string());
        let plan = plan_for(&policy, &no_pidfd);
        assert!(unavailable(&plan).contains(&Requirement::EndsWithParent));

        policy.end_with_parent = false;
        assert!(
            !plan_for(&policy, &host(Some(9)))
                .sandbox
                .unwrap()
                .end_with_parent
        );
    }

    #[test]
    fn root_and_capabilities_are_refused() {
        let mut host = host(Some(9));
        host.unprivileged = Err("root".to_string());
        let plan = plan_for(&policy(), &host);
        assert_eq!(unavailable(&plan), vec![Requirement::NoPrivilegeEscalation]);
        assert!(plan.sandbox.is_none());
    }

    #[test]
    fn missing_no_new_privs_is_refused() {
        let mut host = host(Some(9));
        host.no_new_privs = Err("old kernel".to_string());
        let plan = plan_for(&policy(), &host);
        assert_eq!(unavailable(&plan), vec![Requirement::NoPrivilegeEscalation]);
    }

    #[test]
    fn landlock_without_truncation_control_gets_the_seccomp_rules() {
        for (abi, restrict) in [(1, true), (2, true), (3, false), (9, false)] {
            let mut policy = policy();
            policy.signals = SignalScope::Any;
            let plan = plan_for(&policy, &host(Some(abi)));
            assert_eq!(unavailable(&plan), vec![], "ABI {abi}");
            let sandbox = plan.sandbox.unwrap();
            assert_eq!(sandbox.filter.restrict_truncate, restrict, "ABI {abi}");
        }
        let mut host = host(Some(2));
        host.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy(), &host);
        assert!(unavailable(&plan).contains(&Requirement::FilesystemConfined));
    }

    #[test]
    fn writable_paths_never_execute_or_create_special_files() {
        for unix_sockets in [NetworkAccess::None, NetworkAccess::All] {
            let mut policy = policy();
            policy.unix_sockets = unix_sockets;
            let plan = plan_for(&policy, &host(Some(9)));
            let data = rights(&plan, "/data");
            let forbidden = make_bitflags!(AccessFs::{
                Execute | MakeChar | MakeBlock | MakeSym | MakeFifo | ResolveUnix
            });
            assert!((data & forbidden).is_empty(), "{data:?}");
            assert!(data.contains(AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::Refer));
            assert_eq!(
                data.contains(AccessFs::MakeSock),
                unix_sockets == NetworkAccess::All
            );
        }
    }

    #[test]
    fn read_and_execute_rights_match_the_policy() {
        let plan = plan_for(&policy(), &host(Some(9)));
        assert_eq!(rights(&plan, "/srv/share"), READ);
        assert_eq!(rights(&plan, "/opt/app"), READ | AccessFs::Execute);
        assert_eq!(
            rights(&plan, "/opt/app/bin/app"),
            AccessFs::ReadFile | AccessFs::Execute
        );
    }

    #[test]
    fn every_known_right_is_handled() {
        for abi in 1..=9 {
            let mut policy = policy();
            policy.signals = SignalScope::Any;
            let plan = plan_for(&policy, &host(Some(abi)));
            let landlock = plan.sandbox.unwrap().landlock;
            assert_eq!(landlock.handled_fs, AccessFs::from_all(ABI::from(abi)));
        }
    }

    #[test]
    fn unix_socket_layers_follow_the_policy() {
        let plan = plan_for(&policy(), &host(Some(9)));
        let landlock = plan.sandbox.unwrap().landlock;
        assert!(landlock.handled_fs.contains(AccessFs::ResolveUnix));
        assert!(landlock.scopes.contains(Scope::AbstractUnixSocket));

        let mut policy = policy();
        policy.unix_sockets = NetworkAccess::All;
        let plan = plan_for(&policy, &host(Some(9)));
        let sandbox = plan.sandbox.unwrap();
        assert!(!sandbox.landlock.handled_fs.contains(AccessFs::ResolveUnix));
        assert!(!sandbox.landlock.scopes.contains(Scope::AbstractUnixSocket));
        assert!(sandbox.filter.allow_unix);
    }

    #[test]
    fn tcp_rules_need_denied_ip_and_abi_4() {
        let mut policy = policy();
        policy.signals = SignalScope::Any;
        let plan = plan_for(&policy, &host(Some(4)));
        let handled = plan.sandbox.unwrap().landlock.handled_net;
        assert_eq!(handled, AccessNet::BindTcp | AccessNet::ConnectTcp);

        let plan = plan_for(&policy, &host(Some(3)));
        assert!(plan.sandbox.unwrap().landlock.handled_net.is_empty());

        policy.ip = IpAccess::All;
        let plan = plan_for(&policy, &host(Some(9)));
        let sandbox = plan.sandbox.unwrap();
        assert!(sandbox.landlock.handled_net.is_empty());
        assert!(sandbox.filter.allow_ip);
    }

    /// `ip = "client"` lets the program create IP sockets and denies listening with seccomp on
    /// every kernel; Landlock adds what each ABI can: binds only to port 0, for TCP from ABI 4
    /// and for UDP from ABI 10. The TCP rights of `ip = "none"` stay off, so it can connect.
    #[test]
    fn client_denies_listening_and_limits_binds_per_abi() {
        let mut policy = policy();
        policy.ip = IpAccess::Client;
        policy.signals = SignalScope::Any;
        for (abi, binds) in [
            (3, 0),
            (4, BIND_TCP),
            (9, BIND_TCP),
            (10, BIND_TCP | BIND_UDP),
        ] {
            let plan = plan_for(&policy, &host(Some(abi)));
            let Status::Enforced { mechanism } = status(&plan, Requirement::InboundIpDenied) else {
                panic!("ABI {abi}: {plan:?}");
            };
            assert!(
                mechanism.starts_with("seccomp denies listen"),
                "{mechanism}"
            );
            assert_eq!(
                mechanism.contains("Landlock ABI 10"),
                abi >= 10,
                "{mechanism}"
            );
            assert!(
                !plan
                    .items
                    .iter()
                    .any(|item| item.requirement == Requirement::IpNetworkDenied)
            );
            let sandbox = plan.sandbox.unwrap();
            assert_eq!(sandbox.client_binds, binds, "ABI {abi}");
            assert!(sandbox.landlock.handled_net.is_empty(), "ABI {abi}");
            assert!(sandbox.filter.allow_ip && sandbox.filter.deny_inbound);
        }
        let mut no_seccomp = host(Some(10));
        no_seccomp.seccomp = Err("no seccomp".to_string());
        let plan = plan_for(&policy, &no_seccomp);
        assert!(unavailable(&plan).contains(&Requirement::InboundIpDenied));

        // The other values neither deny listening nor add the bind rules.
        for ip in [IpAccess::None, IpAccess::All] {
            policy.ip = ip;
            let sandbox = plan_for(&policy, &host(Some(10))).sandbox.unwrap();
            assert_eq!(sandbox.client_binds, 0);
            assert!(!sandbox.filter.deny_inbound);
        }
    }

    /// The UDP route that stays open is named in a warning, with the ports this kernel leaves
    /// to the program, and so is the listen denial that also hits Unix sockets.
    #[test]
    fn client_notes_name_what_stays_open() {
        let mut policy = policy();
        policy.ip = IpAccess::Client;
        let udp = |abi| {
            notes(&policy, &host(Some(abi)))
                .into_iter()
                .find(|note| note.starts_with("ip = \"client\" keeps datagrams out only in part"))
                .unwrap_or_else(|| panic!("ABI {abi}: no UDP note"))
        };
        assert!(
            udp(10).contains("at the port the kernel chose for it"),
            "{}",
            udp(10)
        );
        assert!(udp(9).contains("this kernel has ABI 9"), "{}", udp(9));
        let unix = |policy: &ResolvedPolicy| {
            notes(policy, &host(Some(10)))
                .iter()
                .any(|note| note.contains("cannot listen on a Unix socket either"))
        };
        assert!(!unix(&policy));
        policy.unix_sockets = NetworkAccess::All;
        assert!(unix(&policy));
        policy.ip = IpAccess::All;
        assert!(!unix(&policy));
        assert!(
            !notes(&policy, &host(Some(10)))
                .iter()
                .any(|note| note.contains("keeps datagrams out"))
        );
    }

    #[test]
    fn system_set_follows_the_policy() {
        let plan = plan_for(&policy(), &host(Some(9)));
        assert_eq!(rights(&plan, "/usr/lib"), READ);
        assert_eq!(
            rights(&plan, "/usr/lib64/ld-linux-x86-64.so.2"),
            AccessFs::ReadFile | AccessFs::Execute
        );
        assert_eq!(
            rights(&plan, "/dev/null"),
            AccessFs::ReadFile | AccessFs::WriteFile
        );
        let landlock = plan.sandbox.unwrap().landlock;
        assert!(!landlock.rules.iter().any(|r| r.path.starts_with("/etc")));

        for ip in [IpAccess::Client, IpAccess::All] {
            let mut with_ip = policy();
            with_ip.ip = ip;
            let plan = plan_for(&with_ip, &host(Some(9)));
            assert_eq!(rights(&plan, "/etc/hosts"), AccessFs::ReadFile, "{ip:?}");
        }

        let mut no_system = policy();
        no_system.system = SystemAccess::None;
        let plan = plan_for(&no_system, &host(Some(9)));
        let landlock = plan.sandbox.unwrap().landlock;
        assert_eq!(landlock.rules.len(), no_system.paths.len());
    }

    #[test]
    fn a_writable_path_must_not_overlap_the_system_set() {
        let conflicts = |path: &str, is_dir: bool| {
            let mut policy = policy();
            policy.paths.push(rule(path, PathAccess::ReadWrite, is_dir));
            let plan = plan_for(&policy, &host(Some(9)));
            unavailable(&plan) == vec![Requirement::FilesystemConfined]
        };
        // Contains a library directory, a configuration file, or a missing candidate.
        assert!(conflicts("/usr", true));
        assert!(conflicts("/etc", true));
        // Lies inside a directory of the set.
        assert!(conflicts("/usr/lib/app/state", true));
        // The set itself makes /dev/null writable.
        assert!(!conflicts("/dev/null", false));
        assert!(!conflicts("/srv/state", true));

        // A candidate that does not exist counts: the program could create it.
        let mut policy = policy();
        policy.paths.push(rule("/etc", PathAccess::ReadWrite, true));
        let mut without_hosts = host(Some(9));
        without_hosts
            .system_locations
            .retain(|entry| entry.path != Path::new("/etc/hosts"));
        let plan = plan_for(&policy, &without_hosts);
        match status(&plan, Requirement::FilesystemConfined) {
            Status::Unavailable { reason } => {
                assert!(reason.contains("/etc/ld.so.preload"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A writable path that reaches one of the user's trusted locations is refused, whatever the
    /// system access, and a path below a location that protects only itself is not.
    #[test]
    fn a_writable_path_over_a_trusted_location_is_refused() {
        let refused = |path: &str, system: SystemAccess| {
            let mut policy = policy();
            policy.system = system;
            policy.paths.push(rule(path, PathAccess::ReadWrite, true));
            let plan = plan_for(&policy, &host(Some(9)));
            unavailable(&plan) == vec![Requirement::FilesystemConfined]
        };
        assert!(refused("/home", SystemAccess::Minimal));
        assert!(refused("/home", SystemAccess::None));
        assert!(!refused("/home/someone/data", SystemAccess::Minimal));
    }

    /// When no source names the home directory, sandy cannot check the locations below it, so a
    /// policy with a writable path is refused with the reason, and one without stays
    /// enforceable.
    #[test]
    fn an_unknown_home_directory_refuses_a_writable_path() {
        let mut host = host(Some(9));
        host.trusted_locations = Err("cannot find the home directory of this user".into());
        let plan = plan_for(&policy(), &host);
        assert_eq!(unavailable(&plan), vec![Requirement::FilesystemConfined]);
        match status(&plan, Requirement::FilesystemConfined) {
            Status::Unavailable { reason } => assert!(reason.contains("home directory")),
            other => panic!("{other:?}"),
        }

        let mut policy = policy();
        policy
            .paths
            .retain(|rule| rule.access != PathAccess::ReadWrite);
        assert_eq!(unavailable(&plan_for(&policy, &host)), vec![]);
    }

    /// A writable path that holds a directory on PATH is enforced and warned about (rule 12),
    /// and a writable path that holds a refused location as well stays refused: the warning
    /// never replaces the refusal. `/data` of the test policy holds `/data/bin` of the host.
    #[test]
    fn a_writable_path_over_a_directory_on_path_is_warned_about() {
        let host = host(Some(9));
        let plan = plan_for(&policy(), &host);
        assert_eq!(unavailable(&plan), vec![]);
        let notes = notes(&policy(), &host);
        assert!(
            notes.iter().any(|note| note.contains("/data/bin")),
            "{notes:?}"
        );

        let mut policy = policy();
        policy
            .paths
            .push(rule("/home", PathAccess::ReadWrite, true));
        let plan = plan_for(&policy, &host);
        assert_eq!(unavailable(&plan), vec![Requirement::FilesystemConfined]);
    }

    #[test]
    fn a_writable_path_must_not_contain_the_loader() {
        let mut policy = policy();
        policy.paths.push(rule("/usr", PathAccess::ReadWrite, true));
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![Requirement::FilesystemConfined]);

        policy.system = SystemAccess::None;
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
    }

    fn loader_rights(config: &LandlockConfig, path: &str) -> Option<BitFlags<AccessFs>> {
        let rule = config.rules.iter().find(|r| r.path == Path::new(path));
        rule.map(|rule| rule.access)
    }

    /// A loader the minimal system set does not name, as a distribution outside the FHS layout
    /// has, gets an execute rule of its own when it lies in a system location. One somewhere
    /// else is refused instead of granted, because it comes from the header of the program file.
    #[test]
    fn the_programs_loader_is_granted_only_in_a_system_location() {
        let policy = policy();
        let system = host(Some(9)).system_paths;
        let config =
            |loader: &str| landlock_config(&policy, &system, Some(Path::new(loader)), ABI::V9);
        let problem = |loader: &str, config: &LandlockConfig| {
            loader_problem(Some(Path::new(loader)), &executable_paths(config))
        };

        let store = "/nix/store/abc-glibc/lib/ld-linux-x86-64.so.2";
        let granted = config(store);
        assert_eq!(
            loader_rights(&granted, store),
            Some(AccessFs::ReadFile | AccessFs::Execute)
        );
        assert_eq!(problem(store, &granted), None);

        let home = "/home/user/toolchain/lib/ld-linux-x86-64.so.2";
        let refused = config(home);
        assert_eq!(loader_rights(&refused, home), None);
        assert!(problem(home, &refused).unwrap().contains(home));

        // A loader a read_exec path of the policy already covers needs no rule of its own.
        let inside = "/opt/app/lib/ld-linux-x86-64.so.2";
        let covered = config(inside);
        assert_eq!(loader_rights(&covered, inside), None);
        assert_eq!(problem(inside, &covered), None);

        // Without the system set, sandy adds no path of its own.
        let mut no_system = policy.clone();
        no_system.system = SystemAccess::None;
        let config = landlock_config(&no_system, &system, Some(Path::new(store)), ABI::V9);
        assert_eq!(loader_rights(&config, store), None);
        assert!(problem(store, &config).is_some());
    }

    /// A writable path never becomes executable, whatever the program's header names.
    #[test]
    fn a_loader_inside_a_writable_path_is_refused() {
        let mut policy = policy();
        policy
            .paths
            .push(rule("/nix/store/abc", PathAccess::ReadWrite, true));
        let loader = "/nix/store/abc/lib/ld-linux-x86-64.so.2";
        let system = host(Some(9)).system_paths;
        let config = landlock_config(&policy, &system, Some(Path::new(loader)), ABI::V9);
        assert_eq!(loader_rights(&config, loader), None);
        let problem = loader_problem(Some(Path::new(loader)), &executable_paths(&config));
        assert!(problem.unwrap().contains(loader));
    }
}
