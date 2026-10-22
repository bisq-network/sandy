//! The planning step. It is pure: from a policy and the host capabilities it derives the plan
//! items and the exact configuration that `run` applies. Both come from the same function, so
//! `run` applies what the plan names.

use std::path::PathBuf;

use landlock::{ABI, Access, AccessFs, AccessNet, BitFlags, Scope, make_bitflags};
use sandy_core::{
    NetworkAccess, PathAccess, PathMetadata, PlanItem, Requirement, ResolvedPolicy, SignalScope,
    SystemAccess,
};

use crate::filter::FilterConfig;
use crate::host::HostCapabilities;
use crate::relay::RelayConfig;
use crate::system::{Needed, SystemPath, SystemUse};

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

pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> LinuxPlan {
    // Landlock restricts only the calling thread, so it is only usable when sandy can verify
    // that it is single-threaded.
    let abi = match (&host.landlock, &host.thread_count) {
        (Err(reason), _) | (Ok(_), Err(reason)) => Err(reason.as_str()),
        (Ok(version), Ok(())) => Ok(ABI::from(*version)),
    };
    let conflict = executable_conflict(policy, &host.system_paths);
    let items: Vec<PlanItem> = policy
        .requirements()
        .into_iter()
        .map(|requirement| plan_item(requirement, host, abi, conflict.as_deref()))
        .collect();
    let enforceable = items.iter().all(PlanItem::is_enforced);
    let sandbox = match abi {
        Ok(abi) if enforceable => Some(Sandbox {
            landlock: landlock_config(policy, &host.system_paths, abi),
            filter: FilterConfig {
                allow_ip: policy.ip == NetworkAccess::All,
                allow_unix: policy.unix_sockets == NetworkAccess::All,
                restrict_truncate: abi < ABI::V3,
                deny_path_metadata: policy.path_metadata == PathMetadata::Deny,
            },
            relay: (!policy.expose.is_empty()).then(|| RelayConfig {
                expose: policy.expose.clone(),
                abi,
            }),
        }),
        _ => None,
    };
    LinuxPlan { items, sandbox }
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
        Requirement::ExposedPortsRelayed => match (&host.landlock, &host.seccomp, &host.pidfd) {
            (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => unavailable(reason),
            _ => {
                let mut mechanism = format!(
                    "relay process outside the sandbox, not a child of the program, that \
                         ends with it (pidfd); confined by no_new_privs, Landlock ABI {abi} \
                         without file access"
                );
                if abi >= ABI::V4 {
                    mechanism.push_str(", TCP connect only to the exposed ports and no bind");
                }
                mechanism.push_str(
                    ", and a seccomp filter that allows only TCP, copying bytes and threads",
                );
                enforced(mechanism)
            }
        },
        Requirement::MetadataConfined => match &host.seccomp {
            Err(reason) => unavailable(reason),
            Ok(()) => enforced(FILTER_METADATA.to_string()),
        },
        Requirement::SignalsIsolated => {
            if abi >= ABI::V6 {
                enforced("Landlock ABI 6 signal scope".to_string())
            } else {
                unavailable(&format!(
                    "signal isolation needs Landlock ABI 6 (Linux 6.12); this kernel has ABI \
                     {abi}"
                ))
            }
        }
    }
}

/// The policy check for writable and executable paths does not see the system set. A writable
/// policy path that contains the dynamic loader would make the loader writable and executable.
fn executable_conflict(policy: &ResolvedPolicy, system: &[SystemPath]) -> Option<String> {
    if policy.system != SystemAccess::Minimal {
        return None;
    }
    let writable = policy
        .paths
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadWrite);
    for rule in writable {
        let executable = system.iter().filter(|s| s.usage == SystemUse::Execute);
        for entry in executable {
            if entry.path.starts_with(&rule.path) {
                return Some(format!(
                    "writable path {} contains the dynamic loader {}, which the minimal system \
                     set makes executable",
                    rule.path.display(),
                    entry.path.display()
                ));
            }
        }
    }
    None
}

fn landlock_config(policy: &ResolvedPolicy, system: &[SystemPath], abi: ABI) -> LandlockConfig {
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
    use sandy_core::{EnvironmentPolicy, ExposedPort, PathRule, Status, WindowsPolicy};
    use std::path::Path;

    fn host(abi: Option<i32>) -> HostCapabilities {
        let system = |path: &str, is_dir, usage, needed| SystemPath {
            path: PathBuf::from(path),
            is_dir,
            usage,
            needed,
        };
        HostCapabilities {
            landlock: abi.ok_or_else(|| "no Landlock here".to_string()),
            thread_count: Ok(()),
            seccomp: Ok(()),
            no_new_privs: Ok(()),
            unprivileged: Ok(()),
            pidfd: Ok(()),
            system_paths: vec![
                system("/usr/lib", true, SystemUse::Read, Needed::Always),
                system(
                    "/usr/lib64/ld-linux-x86-64.so.2",
                    false,
                    SystemUse::Execute,
                    Needed::Always,
                ),
                system("/dev/null", false, SystemUse::Discard, Needed::Always),
                system("/etc/hosts", false, SystemUse::Read, Needed::WithIpNetwork),
            ],
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
            signals: SignalScope::Isolated,
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
        let landlock = plan.sandbox.unwrap().landlock;
        assert!(landlock.scopes.is_empty());
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
    fn exposed_ports_need_pidfd_landlock_and_seccomp() {
        let mut policy = policy();
        policy.ip = NetworkAccess::All;
        policy.expose = vec![ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
        let relay = plan.sandbox.unwrap().relay.unwrap();
        assert_eq!(relay.expose, policy.expose);
        assert_eq!(relay.abi, ABI::V9);

        let mut no_pidfd = host(Some(9));
        no_pidfd.pidfd = Err("old kernel".to_string());
        let plan = plan_for(&policy, &no_pidfd);
        assert_eq!(unavailable(&plan), vec![Requirement::ExposedPortsRelayed]);
        assert!(plan.sandbox.is_none());

        policy.expose.clear();
        let plan = plan_for(&policy, &host(Some(9)));
        assert!(plan.sandbox.unwrap().relay.is_none());
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
    fn a_writable_path_must_not_contain_the_loader() {
        let mut policy = policy();
        policy.paths.push(rule("/usr", PathAccess::ReadWrite, true));
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![Requirement::FilesystemConfined]);

        policy.system = SystemAccess::None;
        let plan = plan_for(&policy, &host(Some(9)));
        assert_eq!(unavailable(&plan), vec![]);
    }
}
