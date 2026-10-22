//! The enforcement plan: how this backend enforces each requirement of a policy on a given host.
//! `plan_for` is pure; `sys` detects the host capabilities.

use std::path::{Path, PathBuf};

use sandy_core::{NetworkAccess, PathAccess, PlanItem, Requirement, ResolvedPolicy, SystemAccess};

use crate::name::validate_appcontainer_name;
use crate::version::{WindowsVersion, below_minimum, firewall_bypass};

/// What the host offers. Each field is `Err(reason)` when it could not be determined or the
/// mechanism is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    /// The AppContainer API works on this host.
    pub appcontainer: Result<(), String>,
    /// Build and update revision of Windows.
    pub windows: Result<WindowsVersion, String>,
    /// `DeriveCapabilitySidsFromName` exists. sandy resolves it at run time, so `sandy.exe`
    /// still starts and can explain the problem on builds that lack it.
    pub capability_sids: Result<(), String>,
    /// The UI restrictions of the job sandy runs in, or `None` outside a job.
    pub outer_job_ui: Result<Option<u32>, String>,
    /// The Windows Firewall service runs. It installs the filters that isolate AppContainers
    /// from the network.
    pub firewall: Result<(), String>,
    /// Whether the AppContainer of the policy is exempt from loopback isolation.
    pub loopback_exempt: Result<bool, String>,
    /// sandy's own executable, which runs the relays of exposed ports, if sandy can allow the
    /// AppContainer to run it.
    pub relay_program: Result<PathBuf, String>,
}

const SYSTEM_NONE: &str = "Windows grants every AppContainer read and execute access to the \
     system directories (C:\\Windows, C:\\Program Files) through the ALL APPLICATION PACKAGES \
     group, and a Less Privileged AppContainer keeps it through ALL RESTRICTED APPLICATION \
     PACKAGES; sandy cannot remove these grants, so system = \"none\" cannot be enforced";

/// Reports every requirement of `policy` as enforced or unavailable on `host`.
pub fn plan_for(policy: &ResolvedPolicy, host: &HostCapabilities) -> Vec<PlanItem> {
    let container = appcontainer(policy, host);
    policy
        .requirements()
        .into_iter()
        .map(|requirement| match (requirement, &container) {
            (Requirement::InheritedHandlesClosed, _) => PlanItem::enforced(
                requirement,
                "PROC_THREAD_ATTRIBUTE_HANDLE_LIST with only the three standard handles; a \
                 console is relayed through a pipe",
            ),
            (Requirement::EnvironmentControlled, _) => PlanItem::enforced(
                requirement,
                "Unicode environment block built from the policy, plus SystemRoot and \
                 LOCALAPPDATA",
            ),
            (_, Err(reason)) => PlanItem::unavailable(requirement, reason.clone()),
            (_, Ok(name)) => contained(requirement, policy, host, name),
        })
        .collect()
}

/// The validated AppContainer name, or why there is no usable AppContainer.
fn appcontainer(policy: &ResolvedPolicy, host: &HostCapabilities) -> Result<String, String> {
    let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
        "the policy names no AppContainer; set windows.appcontainer_name or pass --appcontainer \
         NAME"
            .to_string()
    })?;
    validate_appcontainer_name(name)?;
    host.appcontainer
        .clone()
        .map_err(|reason| format!("AppContainers are not available: {reason}"))?;
    let version = host
        .windows
        .clone()
        .map_err(|reason| format!("cannot read the Windows version: {reason}"))?;
    if let Some(reason) = below_minimum(version) {
        return Err(reason);
    }
    Ok(name.to_string())
}

/// Why sandy cannot put the program into its job, or `None`. Measured on Windows 11 build 26200:
/// a process already in a job with UI restrictions cannot join a second job with UI
/// restrictions (`ERROR_NOT_SUPPORTED`); an outer job without UI restrictions nests, with or
/// without breakaway. sandy does not break away from the outer job: that would escape the limits
/// its owner set.
fn job_problem(host: &HostCapabilities) -> Option<String> {
    match &host.outer_job_ui {
        Err(reason) => Some(format!("cannot read the job sandy runs in: {reason}")),
        Ok(Some(ui)) if *ui != 0 => Some(format!(
            "sandy runs inside a job with UI restrictions ({ui:#x}); Windows does not nest \
             sandy's job, which sets UI restrictions too, so the program cannot be put into \
             it; start sandy outside that job"
        )),
        Ok(_) => None,
    }
}

/// Requirements that the AppContainer enforces.
fn contained(
    requirement: Requirement,
    policy: &ResolvedPolicy,
    host: &HostCapabilities,
    name: &str,
) -> PlanItem {
    let enforced = |mechanism: String| PlanItem::enforced(requirement, mechanism);
    let unavailable = |reason: String| PlanItem::unavailable(requirement, reason);
    // The job carries the no-breakaway rule and the UI restrictions, and ends the relays.
    if let (
        Requirement::NoPrivilegeEscalation
        | Requirement::SignalsIsolated
        | Requirement::ExposedPortsRelayed,
        Some(reason),
    ) = (requirement, job_problem(host))
    {
        return unavailable(reason);
    }
    let bypass = host
        .windows
        .as_ref()
        .ok()
        .copied()
        .and_then(firewall_bypass);
    if let (Requirement::IpNetworkDenied, Some(reason)) = (requirement, bypass) {
        return unavailable(reason);
    }
    match requirement {
        Requirement::FilesystemConfined => match (policy.system, &host.capability_sids) {
            (SystemAccess::None, _) => unavailable(SYSTEM_NONE.into()),
            (SystemAccess::Minimal, Err(reason)) => unavailable(reason.clone()),
            (SystemAccess::Minimal, Ok(())) => enforced(format!(
                "AppContainer {name:?}: one capability per policy path with an access control \
                 entry on the path (no FILE_EXECUTE on read and read-write paths); besides, what \
                 Windows grants all AppContainers and the AppContainer profile folder"
            )),
        },
        Requirement::ExposedPortsRelayed => match &host.relay_program {
            Err(reason) => unavailable(reason.clone()),
            Ok(sandy) => match writable_parent(policy, sandy) {
                Some(writable) => unavailable(format!(
                    "the relays run sandy's executable {}, which lies in the read-write path {}; \
                     the program could replace it",
                    sandy.display(),
                    writable.display()
                )),
                None => enforced(format!(
                    "`sandy __relay` in AppContainer {name:?} and the program's job, on a \
                     listening socket that sandy creates outside the AppContainer; the relay \
                     has no network capability and only read and execute access to {}",
                    sandy.display()
                )),
            },
        },
        Requirement::MetadataConfined => enforced(format!(
            "AppContainer {name:?} holds no WRITE_DAC, WRITE_OWNER, FILE_WRITE_ATTRIBUTES or \
             FILE_WRITE_EA outside read-write paths, and the AppContainer access check grants \
             no implicit owner rights"
        )),
        Requirement::NoPrivilegeEscalation => enforced(format!(
            "AppContainer {name:?} token at low integrity, inherited by every child; job object \
             without breakaway"
        )),
        Requirement::ProcessMemoryIsolated => enforced(format!(
            "AppContainer {name:?}: processes outside it grant its SID no access"
        )),
        Requirement::IpNetworkDenied => match (&host.firewall, &host.loopback_exempt) {
            (Err(reason), _) => unavailable(format!(
                "AppContainer network isolation depends on the Windows Firewall service: {reason}"
            )),
            (_, Err(reason)) => unavailable(format!(
                "cannot read the loopback exemptions of AppContainers: {reason}"
            )),
            (_, Ok(true)) => unavailable(format!(
                "AppContainer {name:?} is exempt from loopback isolation and could reach \
                 127.0.0.1 without network capabilities; run `sandy setup --appcontainer \
                 {name}` without --ip all as administrator to remove the exemption, or use \
                 another name for policies without IP networking"
            )),
            (Ok(()), Ok(false)) => enforced(format!(
                "AppContainer {name:?} without network capabilities and without loopback \
                 exemption"
            )),
        },
        Requirement::UnixSocketsDenied => enforced(format!(
            "connecting to an AF_UNIX socket needs write access to the socket file; \
             AppContainer {name:?} can write only in read-write paths and in its profile folder, \
             where Windows also puts TEMP"
        )),
        Requirement::SignalsIsolated => enforced(format!(
            "own console for the program; AppContainer {name:?} cannot open processes outside \
             it; job UI restrictions and low integrity block window messages"
        )),
        Requirement::InheritedHandlesClosed | Requirement::EnvironmentControlled => {
            unreachable!("reported in plan_for")
        }
    }
}

/// The read-write path of `policy` that contains `path`. The relays get read and execute access
/// to sandy's executable, so it must not be writable (writable-and-executable rule), and sandy
/// itself must stay out of the program's reach.
fn writable_parent<'a>(policy: &'a ResolvedPolicy, path: &Path) -> Option<&'a Path> {
    policy
        .paths
        .iter()
        .find(|rule| rule.access == PathAccess::ReadWrite && path.starts_with(&rule.path))
        .map(|rule| rule.path.as_path())
}

/// The network capabilities the target gets. The policy allows IP networking completely or not
/// at all. `internetClientServer` includes `internetClient`.
pub fn network_capabilities(ip: NetworkAccess) -> &'static [NetworkCapability] {
    match ip {
        NetworkAccess::None => &[],
        NetworkAccess::All => &[
            NetworkCapability::InternetClientServer,
            NetworkCapability::PrivateNetworkClientServer,
        ],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCapability {
    /// Inbound and outbound connections to the internet.
    InternetClientServer,
    /// Inbound and outbound connections to home and work networks.
    PrivateNetworkClientServer,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sandy_core::{
        EnforcementPlan, ExposedPort, PathAccess, PathMetadata, PathRule, Policy, SignalScope,
        Status, WindowsPolicy,
    };

    use super::*;

    fn host() -> HostCapabilities {
        HostCapabilities {
            appcontainer: Ok(()),
            windows: Ok(WindowsVersion {
                build: 26200,
                revision: Some(7000),
            }),
            capability_sids: Ok(()),
            outer_job_ui: Ok(None),
            firewall: Ok(()),
            loopback_exempt: Ok(false),
            relay_program: Ok(sandy_exe(Path::new(r"C:\Program Files\sandy"))),
        }
    }

    /// `dir.join` keeps the path splittable into components on every host the tests run on.
    fn sandy_exe(dir: &Path) -> PathBuf {
        dir.join("sandy.exe")
    }

    fn exposing(mut policy: ResolvedPolicy) -> ResolvedPolicy {
        policy.ip = NetworkAccess::All;
        policy.expose = vec![ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        policy
    }

    fn policy() -> ResolvedPolicy {
        let mut policy = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        policy.windows = WindowsPolicy {
            appcontainer_name: Some("example.app".into()),
        };
        policy
    }

    fn with_rule(mut policy: ResolvedPolicy, access: PathAccess) -> ResolvedPolicy {
        policy.paths.push(PathRule {
            path: PathBuf::from(r"C:\data"),
            access,
            is_dir: true,
        });
        policy
    }

    fn plan(policy: &ResolvedPolicy, host: &HostCapabilities) -> EnforcementPlan {
        EnforcementPlan::new(&policy.requirements(), plan_for(policy, host))
    }

    fn status(
        policy: &ResolvedPolicy,
        host: &HostCapabilities,
        requirement: Requirement,
    ) -> Status {
        plan_for(policy, host)
            .into_iter()
            .find(|item| item.requirement == requirement)
            .expect("reported")
            .status
    }

    fn unavailable(status: Status) -> String {
        match status {
            Status::Unavailable { reason } => reason,
            Status::Enforced { mechanism } => panic!("enforced: {mechanism}"),
        }
    }

    #[test]
    fn reports_every_requirement_once() {
        let mut policy = policy();
        policy.signals = SignalScope::Isolated;
        let items = plan_for(&policy, &host());
        let mut reported: Vec<_> = items.iter().map(|item| item.requirement).collect();
        reported.sort();
        let mut required = policy.requirements();
        required.sort();
        assert_eq!(reported, required);
    }

    #[test]
    fn default_policy_is_enforceable() {
        assert!(plan(&policy(), &host()).is_enforceable());
        assert!(plan(&with_rule(policy(), PathAccess::Read), &host()).is_enforceable());
    }

    #[test]
    fn needs_a_valid_appcontainer_name() {
        let mut policy = policy();
        policy.windows.appcontainer_name = None;
        let plan = plan(&policy, &host());
        assert!(!plan.is_enforceable());
        let reason = unavailable(status(&policy, &host(), Requirement::FilesystemConfined));
        assert!(reason.contains("appcontainer"), "{reason}");

        policy.windows.appcontainer_name = Some("bad/name".into());
        assert!(
            !plan_for(&policy, &host())
                .iter()
                .any(|item| item.requirement == Requirement::FilesystemConfined
                    && item.is_enforced())
        );
    }

    #[test]
    fn without_appcontainers_nothing_contained_is_enforced() {
        let host = HostCapabilities {
            appcontainer: Err("old Windows".into()),
            ..host()
        };
        for item in plan_for(&policy(), &host) {
            let contained = !matches!(
                item.requirement,
                Requirement::InheritedHandlesClosed | Requirement::EnvironmentControlled
            );
            assert_eq!(item.is_enforced(), !contained, "{item:?}");
        }
    }

    #[test]
    fn system_none_is_unavailable() {
        let mut policy = policy();
        policy.system = SystemAccess::None;
        let reason = unavailable(status(&policy, &host(), Requirement::FilesystemConfined));
        assert!(reason.contains("ALL APPLICATION PACKAGES"), "{reason}");
    }

    #[test]
    fn exempt_appcontainer_cannot_deny_ip() {
        let host = HostCapabilities {
            loopback_exempt: Ok(true),
            ..host()
        };
        let reason = unavailable(status(&policy(), &host, Requirement::IpNetworkDenied));
        assert!(reason.contains("exempt"), "{reason}");

        let mut allowed = policy();
        allowed.ip = NetworkAccess::All;
        assert!(plan(&allowed, &host).is_enforceable());
    }

    #[test]
    fn unknown_network_state_fails_closed() {
        for host in [
            HostCapabilities {
                firewall: Err("MpsSvc stopped".into()),
                ..host()
            },
            HostCapabilities {
                loopback_exempt: Err("access denied".into()),
                ..host()
            },
        ] {
            assert!(!plan(&policy(), &host).is_enforceable());
        }
    }

    #[test]
    fn unix_sockets_are_enforced_with_writable_paths() {
        let writable = with_rule(policy(), PathAccess::ReadWrite);
        assert!(matches!(
            status(&writable, &host(), Requirement::UnixSocketsDenied),
            Status::Enforced { .. }
        ));
    }

    #[test]
    fn metadata_requirement_follows_the_policy() {
        let mut policy = policy();
        assert!(matches!(
            status(&policy, &host(), Requirement::MetadataConfined),
            Status::Enforced { .. }
        ));
        policy.path_metadata = PathMetadata::Allow;
        assert!(
            !plan_for(&policy, &host())
                .iter()
                .any(|item| item.requirement == Requirement::MetadataConfined)
        );
    }

    fn enforceable_on(host: &HostCapabilities) -> bool {
        plan(&policy(), host).is_enforceable()
    }

    #[test]
    fn old_windows_enforces_nothing_contained() {
        let old = HostCapabilities {
            windows: Ok(WindowsVersion {
                build: 17134,
                revision: Some(2208),
            }),
            ..host()
        };
        let reason = unavailable(status(&policy(), &old, Requirement::FilesystemConfined));
        assert!(reason.contains("1809"), "{reason}");
        let unknown = HostCapabilities {
            windows: Err("RtlGetVersion failed".into()),
            ..host()
        };
        assert!(!enforceable_on(&unknown));
    }

    #[test]
    fn unpatched_windows_cannot_deny_ip() {
        let unpatched = HostCapabilities {
            windows: Ok(WindowsVersion {
                build: 19043,
                revision: Some(1287),
            }),
            ..host()
        };
        let reason = unavailable(status(&policy(), &unpatched, Requirement::IpNetworkDenied));
        assert!(reason.contains("CVE-2021-41338"), "{reason}");

        let mut allowed = policy();
        allowed.ip = NetworkAccess::All;
        assert!(plan(&allowed, &unpatched).is_enforceable());
    }

    #[test]
    fn missing_capability_sids_block_the_filesystem_only() {
        let host = HostCapabilities {
            capability_sids: Err("DeriveCapabilitySidsFromName is missing".into()),
            ..host()
        };
        let reason = unavailable(status(&policy(), &host, Requirement::FilesystemConfined));
        assert!(reason.contains("DeriveCapabilitySidsFromName"), "{reason}");
        assert!(matches!(
            status(&policy(), &host, Requirement::ProcessMemoryIsolated),
            Status::Enforced { .. }
        ));
    }

    #[test]
    fn an_outer_job_with_ui_restrictions_blocks_the_job() {
        let nested = HostCapabilities {
            outer_job_ui: Ok(Some(0x1)),
            ..host()
        };
        let reason = unavailable(status(
            &policy(),
            &nested,
            Requirement::NoPrivilegeEscalation,
        ));
        assert!(reason.contains("UI restrictions"), "{reason}");
        let mut isolated = policy();
        isolated.signals = SignalScope::Isolated;
        assert!(matches!(
            status(&isolated, &nested, Requirement::SignalsIsolated),
            Status::Unavailable { .. }
        ));
        assert!(matches!(
            status(&policy(), &nested, Requirement::FilesystemConfined),
            Status::Enforced { .. }
        ));
    }

    #[test]
    fn an_outer_job_without_ui_restrictions_nests() {
        for outer in [Ok(None), Ok(Some(0))] {
            let host = HostCapabilities {
                outer_job_ui: outer,
                ..host()
            };
            assert!(enforceable_on(&host));
        }
        let unreadable = HostCapabilities {
            outer_job_ui: Err("access denied".into()),
            ..host()
        };
        assert!(!enforceable_on(&unreadable));
    }

    #[test]
    fn exposed_ports_are_relayed_by_sandy() {
        let policy = exposing(policy());
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::ExposedPortsRelayed) {
            Status::Enforced { mechanism } => {
                assert!(mechanism.contains("sandy __relay"), "{mechanism}");
                assert!(mechanism.contains("sandy.exe"), "{mechanism}");
            }
            Status::Unavailable { reason } => panic!("unavailable: {reason}"),
        }
    }

    #[test]
    fn relays_need_an_executable_sandy() {
        let host = HostCapabilities {
            relay_program: Err("the current user may not change its permissions".into()),
            ..host()
        };
        let reason = unavailable(status(
            &exposing(policy()),
            &host,
            Requirement::ExposedPortsRelayed,
        ));
        assert!(reason.contains("permissions"), "{reason}");
        // Policies without exposed ports do not need it.
        assert!(plan(&policy(), &host).is_enforceable());
    }

    #[test]
    fn relays_refuse_a_writable_sandy() {
        let data = Path::new(r"C:\data");
        let host = HostCapabilities {
            relay_program: Ok(sandy_exe(&data.join("bin"))),
            ..host()
        };
        let writable = exposing(with_rule(policy(), PathAccess::ReadWrite));
        let reason = unavailable(status(&writable, &host, Requirement::ExposedPortsRelayed));
        assert!(reason.contains("read-write"), "{reason}");
        // Read access to the directory gives the program nothing it could replace sandy with.
        let readable = exposing(with_rule(policy(), PathAccess::Read));
        assert!(plan(&readable, &host).is_enforceable());
    }

    #[test]
    fn relays_need_sandys_job() {
        let nested = HostCapabilities {
            outer_job_ui: Ok(Some(0x1)),
            ..host()
        };
        let reason = unavailable(status(
            &exposing(policy()),
            &nested,
            Requirement::ExposedPortsRelayed,
        ));
        assert!(reason.contains("UI restrictions"), "{reason}");
    }

    #[test]
    fn network_capabilities_are_all_or_nothing() {
        assert!(network_capabilities(NetworkAccess::None).is_empty());
        assert_eq!(network_capabilities(NetworkAccess::All).len(), 2);
    }
}
