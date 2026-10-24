//! The planning step. From a policy and the host capabilities it derives the plan items and the
//! exact configuration that `run` applies. Both come from the same function, so `run` applies
//! what the plan names. The only state it reads besides the host capabilities is the `#!` line
//! and the ELF interpreter of the program, which tell whether the kernel could execute it at
//! all; that depends on the policy, so no detection step can answer it.

use std::path::{Path, PathBuf};

use landlock::{ABI, Access, AccessFs, AccessNet, BitFlags, Scope, make_bitflags};
use sandy_core::{
    ChildProcesses, NetworkAccess, PathAccess, PathIdentity, PathMetadata, PathRule, PlanItem,
    ProtectedPath, Requirement, ResolvedPolicy, SignalScope, SystemAccess,
};

use crate::cgroup;
use crate::filter::FilterConfig;
use crate::host::HostCapabilities;
use crate::loader;
use crate::openssl;
use crate::relay::RelayConfig;
use crate::system::{self, Needed, SystemPath, SystemUse};

#[derive(Debug)]
pub struct LinuxPlan {
    pub items: Vec<PlanItem>,
    /// What `run` applies. `None` unless every requirement is enforced.
    pub sandbox: Option<Sandbox>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sandbox {
    pub landlock: LandlockConfig,
    pub filter: FilterConfig,
    /// The relay for exposed ports, when the policy has any.
    pub relay: Option<RelayConfig>,
    /// `process.children = "contained"`: sandy stays the program's parent and ends its process
    /// group when the program ends, instead of replacing itself with the program.
    pub contain: bool,
    /// `process.end_with_parent`: a watcher ends the program when sandy's parent ends.
    pub end_with_parent: bool,
}

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
    keyrings, userfaultfd, calls that need capabilities, setuid and setgid mode bits, and unknown \
    or foreign system calls";
const FILTER_METADATA: &str = "seccomp denies chmod, chown, utime and xattr calls that take a \
    path, and fchmodat, fchmodat2 and fchownat";
const FILTER_PROCESSES: &str = "seccomp denies ptrace, process_vm_readv, process_vm_writev, \
    pidfd_getfd, kcmp, process_madvise, System V IPC and POSIX message queues, and changes of the \
    limits, priority and CPU affinity of other processes";

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
    let conflict = system_conflict(policy, &host.system_locations)
        .or_else(|| trust_conflict(policy, &host.trusted_locations))
        .or_else(|| loader_problem(loader.as_deref(), &executable_paths(landlock.as_ref()?)))
        .or_else(|| {
            policy.interpreter_problem(SHEBANG_LEVELS, &executable_paths(landlock.as_ref()?))
        });
    let items: Vec<PlanItem> = policy
        .requirements()
        .into_iter()
        .map(|requirement| plan_item(requirement, host, abi, conflict.as_deref()))
        .collect();
    let enforceable = items.iter().all(PlanItem::is_enforced);
    let sandbox = match (abi, landlock) {
        (Ok(abi), Some(landlock)) if enforceable => Some(Sandbox {
            landlock,
            filter: FilterConfig {
                allow_ip: policy.ip == NetworkAccess::All,
                allow_unix: policy.unix_sockets == NetworkAccess::All,
                restrict_truncate: abi < ABI::V3,
                deny_path_metadata: policy.path_metadata == PathMetadata::Deny,
                deny_children: policy.children == ChildProcesses::None,
                keep_process_group: policy.children == ChildProcesses::Contained,
                isolate_signals: policy.signals == SignalScope::Isolated,
            },
            relay: RelayConfig::new(&policy.expose, &policy.forward, abi),
            contain: policy.children == ChildProcesses::Contained,
            end_with_parent: policy.end_with_parent,
        }),
        _ => None,
    };
    LinuxPlan { items, sandbox }
}

/// What makes the program behave differently inside the sandbox than outside, beyond the
/// requirements: a directory on sandy's PATH inside a writable path, an OpenSSL include the
/// policy does not cover, and a cgroup limit the program cannot see. `sandy check` prints these
/// as warnings; they change nothing sandy enforces, and a program that uses neither TLS nor the
/// limits runs as it is.
pub fn notes(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<String> {
    let mut notes = policy.path_directory_notes(&host.path_locations);
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
                (Ok(()), Ok(()), Ok(())) => enforced(
                    "sandy stays the program's parent and puts it in a process group of its own, \
                     whose leader is a guard process of sandy; seccomp denies setsid and setpgid, \
                     so every process the program starts stays in that group; the guard kills \
                     the group when the program ends (pidfd) or sandy dies, and sandy kills it \
                     with SIGKILL when the program ends and reaps it as child subreaper"
                        .to_string(),
                ),
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
                _ => enforced(relay_mechanism(abi)),
            }
        }
        Requirement::MetadataConfined => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => enforced(FILTER_METADATA.to_string()),
        },
        // The kernel sends the job control signals of a terminal without the check that the
        // Landlock scope hooks, so the scope alone does not isolate signals.
        Requirement::SignalsIsolated => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) if abi >= ABI::V6 => enforced(
                "Landlock ABI 6 signal scope; seccomp denies setpgid into a process group that \
                 exists and the terminal ioctls TIOCSPGRP and TIOCSWINSZ"
                    .to_string(),
            ),
            Ok(()) => unavailable(&format!(
                "signal isolation needs Landlock ABI 6 (Linux 6.12); this kernel has ABI {abi}"
            )),
        },
    }
}

/// One relay process serves exposed and forwarded ports, so both requirements name it.
fn relay_mechanism(abi: ABI) -> String {
    let mut mechanism = format!(
        "relay process outside the sandbox, not a child of the program, that ends with it \
         (pidfd); confined by no_new_privs, Landlock ABI {abi} without file access"
    );
    if abi >= ABI::V4 {
        mechanism.push_str(", TCP connect only to the relay targets and no bind");
    }
    mechanism.push_str(", and a seccomp filter that allows only TCP, copying bytes and threads");
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
fn trust_conflict(policy: &ResolvedPolicy, trusted: &[ProtectedPath]) -> Option<String> {
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
    let handled_net = if policy.ip == NetworkAccess::None && abi >= ABI::V4 {
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
        let ip_all = policy.ip == NetworkAccess::All;
        let needed = system
            .iter()
            .filter(|entry| entry.needed == Needed::Always || ip_all);
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
        SystemUse::Read => READ,
        SystemUse::Execute => AccessFs::ReadFile | AccessFs::Execute,
        SystemUse::Discard => AccessFs::ReadFile | AccessFs::WriteFile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::RelayPair;
    use sandy_core::{EnvironmentPolicy, ExposedPort, ForwardedPort, Status, WindowsPolicy};

    fn host(abi: Option<i32>) -> HostCapabilities {
        let system = |path: &str, is_dir, usage, needed| SystemPath {
            path: PathBuf::from(path),
            is_dir,
            usage,
            needed,
        };
        let existing = vec![
            system("/usr/lib", true, SystemUse::Read, Needed::Always),
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
            thread_count: Ok(()),
            process_group: Ok(()),
            seccomp: Ok(()),
            no_new_privs: Ok(()),
            unprivileged: Ok(()),
            pidfd: Ok(()),
            system_locations: [existing.clone(), vec![missing]].concat(),
            system_paths: existing,
            trusted_locations: vec![sandy_core::ProtectedPath::entry("/home/someone")],
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
            system: SystemAccess::Minimal,
            ip: NetworkAccess::None,
            unix_sockets: NetworkAccess::None,
            expose: Vec::new(),
            forward: Vec::new(),
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
        policy.ip = NetworkAccess::All;
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

        policy.ip = NetworkAccess::All;
        let plan = plan_for(&policy, &host(Some(9)));
        let sandbox = plan.sandbox.unwrap();
        assert!(sandbox.landlock.handled_net.is_empty());
        assert!(sandbox.filter.allow_ip);
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

        let mut with_ip = policy();
        with_ip.ip = NetworkAccess::All;
        let plan = plan_for(&with_ip, &host(Some(9)));
        assert_eq!(rights(&plan, "/etc/hosts"), AccessFs::ReadFile);

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
