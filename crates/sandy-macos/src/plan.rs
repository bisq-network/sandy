//! The enforcement plan for a host with known capabilities. Pure code, so it runs and is tested on
//! every platform.

use sandy_core::{NetworkAccess, PlanItem, Requirement, ResolvedPolicy};

/// What the host offers. `MacosBackend` detects it; tests use fixed values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    /// `Ok` when the Seatbelt functions could be loaded, otherwise the reason.
    pub seatbelt: Result<(), String>,
    /// `Ok` when the Seatbelt compiler of this host accepts the generated profile, otherwise its
    /// message.
    pub profile: Result<(), String>,
    /// sandy itself already runs in a Seatbelt sandbox. macOS then refuses another profile.
    pub already_sandboxed: bool,
}

/// Reports every requirement of `policy` exactly once, as enforced (with its mechanism) or
/// unavailable (with the reason).
pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<PlanItem> {
    let profile = match (&host.seatbelt, host.already_sandboxed, &host.profile) {
        (Err(reason), _, _) => Err(format!("Seatbelt is not available: {reason}")),
        (Ok(()), true, _) => Err(
            "sandy already runs in a Seatbelt sandbox, and macOS refuses a second profile"
                .to_string(),
        ),
        (Ok(()), false, Err(message)) => Err(format!(
            "this macOS rejects the generated Seatbelt profile: {message}"
        )),
        (Ok(()), false, Ok(())) => Ok(()),
    };
    policy
        .requirements()
        .into_iter()
        .map(|requirement| match mechanism(requirement, policy) {
            Mechanism::Profile(text) => match &profile {
                Ok(()) => PlanItem::enforced(requirement, format!("Seatbelt profile: {text}")),
                Err(reason) => PlanItem::unavailable(requirement, reason.clone()),
            },
            Mechanism::Exec(text) => PlanItem::enforced(requirement, text),
        })
        .collect()
}

enum Mechanism {
    /// Enforced by the Seatbelt profile.
    Profile(String),
    /// Enforced by how sandy starts the target. Needs no host capability beyond posix_spawn.
    Exec(String),
}

fn mechanism(requirement: Requirement, policy: &ResolvedPolicy) -> Mechanism {
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
            return Mechanism::Exec(
                "posix_spawn with POSIX_SPAWN_SETEXEC and POSIX_SPAWN_CLOEXEC_DEFAULT; the \
                 kernel closes every descriptor except 0, 1 and 2"
                    .to_string(),
            );
        }
        Requirement::EnvironmentControlled => {
            return Mechanism::Exec("posix_spawn with exactly the policy environment".to_string());
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
        Requirement::UnixSocketsDenied => {
            if policy.ip == NetworkAccess::All {
                "no Unix socket network-bind or network-outbound, except the socket of the name \
                 resolver (mDNSResponder), which is part of ip = \"all\""
            } else {
                "no Unix socket network-bind or network-outbound"
            }
        }
        Requirement::SignalsIsolated => "signals only to the target and its sandboxed children",
        Requirement::MetadataConfined => {
            "file-write* (mode, owner, flags, times, extended attributes, ACLs) only on read_write \
             paths, by path and through open descriptors alike"
        }
        Requirement::ForwardedPortsRelayed => {
            "the relay process of the exposed ports with the direction mirrored: it listens on \
             the target's loopback port outside the sandbox and connects only to the forwarded \
             addresses; not a child of the target (forked twice), its own profile without files \
             or Mach services, ends when the target ends (kqueue NOTE_EXIT)"
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

    fn policy(
        ip: NetworkAccess,
        unix_sockets: NetworkAccess,
        signals: SignalScope,
    ) -> ResolvedPolicy {
        ResolvedPolicy {
            paths: Vec::new(),
            program: None,
            system: SystemAccess::Minimal,
            ip,
            unix_sockets,
            expose: Vec::new(),
            forward: Vec::new(),
            signals,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }

    fn strictest() -> ResolvedPolicy {
        policy(
            NetworkAccess::None,
            NetworkAccess::None,
            SignalScope::Isolated,
        )
    }

    fn capable() -> HostCapabilities {
        HostCapabilities {
            seatbelt: Ok(()),
            profile: Ok(()),
            already_sandboxed: false,
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
    fn capable_host_enforces_everything() {
        let policy = strictest();
        let plan = EnforcementPlan::new(&policy.requirements(), plan_for(&policy, &capable()));
        assert!(plan.is_enforceable(), "{plan}");
    }

    #[test]
    fn missing_sandbox_function_refuses() {
        let policy = strictest();
        let host = HostCapabilities {
            seatbelt: Err("dlsym(sandbox_init_with_parameters): symbol not found".into()),
            profile: Err("not compiled".into()),
            already_sandboxed: false,
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
        let with_ip = policy(NetworkAccess::All, NetworkAccess::None, SignalScope::Any);
        let without_ip = policy(NetworkAccess::None, NetworkAccess::None, SignalScope::Any);
        let with = format!("{:?}", mechanism_of(&with_ip));
        let without = format!("{:?}", mechanism_of(&without_ip));
        assert!(with.contains("mDNSResponder"), "{with}");
        assert!(!without.contains("mDNSResponder"), "{without}");
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
