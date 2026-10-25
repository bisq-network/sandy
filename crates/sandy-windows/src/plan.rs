//! The enforcement plan: how this backend enforces each requirement of a policy on a given host.
//! `plan_for` is pure; `sys` detects the host capabilities.

use std::path::{Path, PathBuf};

use sandy_core::{
    EgressReach, IpAccess, PathAccess, PlanItem, Requirement, ResolvedPolicy, SystemAccess,
};

use crate::name::{EGRESS_BROKER_SUFFIX, validate_appcontainer_name};
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
    /// No writable path overlaps a system directory, and Windows does not let every
    /// AppContainer execute files in one (rules 3 and 6).
    pub writable_paths: Result<(), String>,
    /// sandy can give the AppContainer access to every policy path: the entry is in place, or
    /// the current user may change the path's access control list.
    pub grants: Result<(), String>,
    /// The UI restrictions of the job sandy runs in, or `None` outside a job.
    pub outer_job_ui: Result<Option<u32>, String>,
    /// The Windows Firewall service runs. It installs the filters that isolate AppContainers
    /// from the network.
    pub firewall: Result<(), String>,
    /// Whether the AppContainer of the policy is exempt from loopback isolation.
    pub loopback_exempt: Result<bool, String>,
    /// Whether the egress broker's AppContainer is exempt from loopback isolation; `Ok(false)`
    /// without `network.egress`.
    pub broker_loopback_exempt: Result<bool, String>,
    /// sandy's own executable, which runs the relays of exposed and forwarded ports and the egress
    /// broker, if sandy can allow the AppContainer, and with egress the broker's, to run it.
    pub relay_program: Result<PathBuf, String>,
    /// AF_UNIX sockets work and the socket paths of forwarded ports fit into `sun_path`.
    pub forward_sockets: Result<(), String>,
}

const SYSTEM_NONE: &str = "Windows grants every AppContainer read and execute access to the \
     system directories (C:\\Windows, C:\\Program Files) through the ALL APPLICATION PACKAGES \
     group, and a Less Privileged AppContainer keeps it through ALL RESTRICTED APPLICATION \
     PACKAGES; sandy cannot remove these grants, so system = \"none\" cannot be enforced";

const PATHS_HIDDEN: &str = "Windows cannot hide paths from an AppContainer without \
     administrator rights: the AppContainer denies a path outside the policy with \
     ERROR_ACCESS_DENIED instead of answering that it does not exist, and the mechanisms that \
     change what a process sees of the file system (bind links, silos) need administrator rights \
     and act on the whole machine or a container (docs/windows.md, \"What the program can see\")";

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
            (Requirement::PathsHidden, _) => PlanItem::unavailable(requirement, PATHS_HIDDEN),
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

/// Whether sandy's job objects carry this requirement: they hold the no-breakaway rule and the UI
/// restrictions, and they end the relays.
fn needs_job(requirement: Requirement) -> bool {
    matches!(
        requirement,
        Requirement::NoPrivilegeEscalation
            | Requirement::SignalsIsolated
            | Requirement::ExposedPortsRelayed
            | Requirement::ForwardedPortsRelayed
            | Requirement::ChildProcessesDenied
            | Requirement::ChildProcessesContained
            | Requirement::EndsWithParent
    )
}

/// Reports every requirement that sandy's job objects carry as unavailable with `reason`. For
/// `verify`, which learns in a trial whether the program's job can be nested here.
pub fn job_unavailable(policy: &ResolvedPolicy, reason: &str) -> Vec<PlanItem> {
    policy
        .requirements()
        .into_iter()
        .filter(|requirement| needs_job(*requirement))
        .map(|requirement| PlanItem::unavailable(requirement, reason))
        .collect()
}

/// What the policy asks for and this backend gives only in part, although the plan reports it
/// as enforced (DESIGN.md, "Requirements and the enforcement plan"), each with the section of
/// docs/windows.md that explains it. `sandy check` prints these as warnings.
pub fn shortfalls(policy: &ResolvedPolicy) -> Vec<String> {
    let mut shortfalls = Vec::new();
    if policy.paths.iter().any(|rule| rule.is_dir) {
        shortfalls.push(
            "a grant on Windows follows the file, not the path: a file moved out of a granted \
             directory on the same volume keeps the access it inherited there, so the program \
             can still open it at its new place by its full path for as long as the directory \
             is in the policy (docs/windows.md, \"Links and identity\")"
                .to_string(),
        );
    }
    shortfalls
}

/// What makes the program behave differently inside the sandbox than outside with this policy,
/// beyond what it denies by design. `sandy check` prints these as warnings.
pub fn notes(policy: &ResolvedPolicy) -> Vec<String> {
    let mut notes = Vec::new();
    if policy.ip == IpAccess::Client {
        notes.push(
            "ip = \"client\" reaches no host of a network that Windows counts as private or \
             domain network, such as a printer or a server on the local network: Windows has no \
             capability for connections out into such a network alone, and \
             privateNetworkClientServer lets its hosts connect in too; names still resolve, \
             through the DNS Client service, and ip = \"all\" reaches those hosts \
             (docs/windows.md, \"Client networking\")"
                .to_string(),
        );
    }
    if matches!(policy.ip, IpAccess::None | IpAccess::Private) {
        notes.push(
            "the program's own processes in its AppContainer reach each other over loopback, \
             also with ip = \"none\" and ip = \"private\": Windows isolates loopback between the \
             AppContainer and the rest of the machine, not within one AppContainer, so a program \
             that starts helper processes (or a relay of expose, forward or egress) can talk to \
             them on 127.0.0.1 and ::1 (docs/windows.md, \"Private network\")"
                .to_string(),
        );
    }
    notes
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
    // `sandy setup`, run once as administrator, would make this enforceable; `check` exits 2.
    let needs_setup = |reason: String| PlanItem::needs_setup(requirement, reason);
    let relay = |policy, host, sandy: &dyn Fn(&Path) -> PlanItem| match relay_program(policy, host)
    {
        Err(RelayProblem::NeedsSetup(reason)) => needs_setup(reason),
        Err(RelayProblem::Fixed(reason)) => unavailable(reason),
        Ok(path) => sandy(path),
    };
    if needs_job(requirement)
        && let Some(reason) = job_problem(host)
    {
        return unavailable(reason);
    }
    let bypass = host
        .windows
        .as_ref()
        .ok()
        .copied()
        .and_then(firewall_bypass);
    if let (
        Requirement::IpNetworkDenied
        | Requirement::IpNetworkPrivate
        | Requirement::InboundIpDenied
        | Requirement::EgressBrokered,
        Some(reason),
    ) = (requirement, bypass)
    {
        return unavailable(reason);
    }
    let network = network_path_problem(policy);
    match requirement {
        Requirement::FilesystemConfined if policy.system == SystemAccess::None => {
            unavailable(SYSTEM_NONE.into())
        }
        Requirement::FilesystemConfined if network.is_some() => {
            unavailable(network.unwrap_or_default())
        }
        Requirement::FilesystemConfined => {
            match (&host.capability_sids, &host.writable_paths, &host.grants) {
                (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
                    unavailable(reason.clone())
                }
                (Ok(()), Ok(()), Ok(())) => enforced(format!(
                    "AppContainer {name:?}: one capability per policy path with an access control \
                 entry on the path (no FILE_EXECUTE on read and read-write paths); besides, what \
                 Windows grants all AppContainers and the AppContainer profile folder"
                )),
            }
        }
        Requirement::ChildProcessesDenied => enforced(
            "the program's job admits one active process (JOB_OBJECT_LIMIT_ACTIVE_PROCESS = \
             1), so Windows refuses every process that would join it, and every child of the \
             program joins it because the job allows no breakaway; the program holds no handle to \
             the job and cannot change the limit; the relays run without a console and with \
             PROCESS_CREATION_CHILD_PROCESS_RESTRICTED, so the program cannot start processes \
             through them either"
                .to_string(),
        ),
        Requirement::EndsWithParent => enforced(
            "sandy waits for the process that started it (found in a process snapshot and \
             checked by its creation time) and ends the program's job when that process ends; \
             the AppContainer cannot open sandy"
                .to_string(),
        ),
        Requirement::ChildProcessesContained => enforced(
            "every child of the program joins the program's job, which allows no breakaway; \
             sandy ends the job when the program exits, and the job's kill-on-close ends it when \
             sandy dies; the program holds no handle to the job"
                .to_string(),
        ),
        Requirement::ExposedPortsRelayed => relay(policy, host, &|sandy| {
            enforced(format!(
                "`sandy __relay` in AppContainer {name:?} and a job of its own, on a listening \
                 socket that sandy creates outside the AppContainer; the relay has no network \
                 capability and only read and execute access to {}; {RELAY_END}",
                sandy.display()
            ))
        }),
        Requirement::ForwardedPortsRelayed => {
            relay(policy, host, &|sandy| match &host.forward_sockets {
                Err(reason) => unavailable(reason.clone()),
                Ok(()) => enforced(format!(
                    "`sandy __forward` in AppContainer {name:?} and a job of its own listens on \
                     the program's loopback port and passes each connection over an AF_UNIX \
                     socket that only the relays may open to sandy outside, which connects to \
                     the target; no loopback exemption is needed; the relay has no network \
                     capability and only read and execute access to {}; {RELAY_END}",
                    sandy.display()
                )),
            })
        }
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
            (_, Ok(true)) => needs_setup(format!(
                "AppContainer {name:?} is exempt from loopback isolation and could reach \
                 127.0.0.1 without network capabilities; run `sandy setup --appcontainer \
                 {name}` without --ip as administrator to remove the exemption, or use another \
                 name for policies without IP networking"
            )),
            (Ok(()), Ok(false)) => enforced(format!(
                "AppContainer {name:?} without network capabilities and without loopback \
                 exemption"
            )),
        },
        Requirement::IpNetworkPrivate => match (&host.firewall, &host.loopback_exempt) {
            (Err(reason), _) => unavailable(format!(
                "AppContainer network isolation depends on the Windows Firewall service: {reason}"
            )),
            (_, Err(reason)) => unavailable(format!(
                "cannot read the loopback exemptions of AppContainers: {reason}"
            )),
            (_, Ok(true)) => needs_setup(format!(
                "AppContainer {name:?} is exempt from loopback isolation and could reach \
                 127.0.0.1 outside the sandbox without network capabilities; run `sandy setup \
                 --appcontainer {name} --ip private` as administrator to remove the exemption, \
                 or use another name for this policy"
            )),
            (Ok(()), Ok(false)) => enforced(format!(
                "AppContainer {name:?} without network capabilities and without loopback \
                 exemption: its processes and the relays in it reach each other over loopback; \
                 Windows Firewall denies connections and datagrams to other hosts, loopback \
                 isolation drops the traffic between the AppContainer and the rest of this \
                 machine, and the DNS Client service resolves no name for it"
            )),
        },
        Requirement::InboundIpDenied => match &host.firewall {
            Err(reason) => unavailable(format!(
                "AppContainer network isolation depends on the Windows Firewall service: {reason}"
            )),
            Ok(()) => enforced(format!(
                "AppContainer {name:?} with the internetClient capability only: Windows Firewall \
                 drops the connections and datagrams of other hosts that the program did not \
                 start, also with its profiles off, and loopback isolation all that processes of \
                 this machine outside the AppContainer send"
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
        Requirement::Win32kDenied => enforced(WIN32K_LOCKDOWN.to_string()),
        Requirement::EgressBrokered => match (
            &host.firewall,
            &host.loopback_exempt,
            &host.broker_loopback_exempt,
        ) {
            (Err(reason), _, _) => unavailable(format!(
                "AppContainer network isolation depends on the Windows Firewall service: {reason}"
            )),
            (_, Err(reason), _) | (_, _, Err(reason)) => unavailable(format!(
                "cannot read the loopback exemptions of AppContainers: {reason}"
            )),
            (_, Ok(true), _) => needs_setup(format!(
                "AppContainer {name:?} is exempt from loopback isolation and could reach \
                 127.0.0.1 outside the sandbox without network capabilities; run `sandy setup \
                 --appcontainer {name} --ip private` as administrator to remove the exemption, \
                 or use another name for this policy"
            )),
            (_, _, Ok(true)) => needs_setup(format!(
                "the egress broker's AppContainer \"{name}{EGRESS_BROKER_SUFFIX}\" is exempt from \
                 loopback isolation, so nothing below the destination check keeps the broker off \
                 this machine; run `sandy setup` with this policy as administrator to remove the \
                 exemption"
            )),
            (Ok(()), Ok(false), Ok(false)) => match crate::name::egress_broker_name(name) {
                Err(reason) => unavailable(reason),
                Ok(broker) => relay(policy, host, &|sandy| match &host.forward_sockets {
                    Err(reason) => unavailable(reason.clone()),
                    Ok(()) => enforced(format!(
                        "`sandy __broker` in AppContainer {broker:?}, its own sandbox with the \
                         internetClient capability{capabilities}, in the relay job, serves SOCKS5 \
                         on an AF_UNIX socket that a `sandy __forward` relay in AppContainer \
                         {name:?} passes the program's connections to; it connects out only to \
                         {reach} destinations (sandy_core::destination) and never to this host, \
                         which its own loopback isolation also denies at the kernel; the broker \
                         has only read and execute access to {}; {RELAY_END}",
                        sandy.display(),
                        reach = policy
                            .egress
                            .map(|egress| egress.reach.name())
                            .unwrap_or("public"),
                        capabilities = match policy.egress.map(|egress| egress.reach) {
                            Some(EgressReach::PublicAndLocal) => {
                                " and privateNetworkClientServer, which also admits connections \
                                 from hosts of a private network to a socket it listens on, \
                                 although it listens on none"
                            }
                            _ => "",
                        },
                    )),
                }),
            },
        },
        Requirement::InheritedHandlesClosed
        | Requirement::EnvironmentControlled
        | Requirement::PathsHidden => {
            unreachable!("reported in plan_for")
        }
    }
}

/// `windows.win32k = "deny"`. The relays get it too: the program can open them, because they
/// run in its AppContainer, and would otherwise make the calls through them.
const WIN32K_LOCKDOWN: &str = "PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY with \
     PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON for the program and \
     the relays, checked with GetProcessMitigationPolicy before they run";

/// How the relays end, docs/DESIGN.md "Forwarded ports" rule 5.
const RELAY_END: &str = "when the program ends, the relay takes no new connection, lets \
     accepted ones finish, and ends within one second";

/// Why the relays and the egress broker cannot run sandy's executable, and whether `sandy setup`
/// would fix it.
enum RelayProblem {
    /// The current user cannot grant the AppContainer read and execute on sandy's executable;
    /// `sandy setup`, run as administrator, adds the grant.
    NeedsSetup(String),
    /// sandy's executable lies in a read-write path; setup does not help.
    Fixed(String),
}

/// sandy's executable for the relays, unless sandy cannot let the AppContainer run it (which
/// setup fixes) or it lies in a read-write path (which it does not).
fn relay_program<'a>(
    policy: &ResolvedPolicy,
    host: &'a HostCapabilities,
) -> Result<&'a Path, RelayProblem> {
    let sandy = host
        .relay_program
        .as_ref()
        .map_err(|reason| RelayProblem::NeedsSetup(reason.clone()))?;
    match writable_parent(policy, sandy) {
        Some(writable) => Err(RelayProblem::Fixed(format!(
            "the relays run sandy's executable {}, which lies in the read-write path {}; the \
             program could replace it",
            sandy.display(),
            writable.display()
        ))),
        None => Ok(sandy),
    }
}

/// Why a policy path that names a network share is refused. The program cannot open a share in
/// its AppContainer with the capabilities sandy grants (docs/windows.md, "Network and share
/// paths"), but the entry sandy adds through the share lands on the folder behind it, which the
/// program then opens by its local path.
fn network_path_problem(policy: &ResolvedPolicy) -> Option<String> {
    let rule = policy
        .paths
        .iter()
        .find(|rule| is_network_path(&rule.path))?;
    Some(format!(
        "policy path {} is a network or share path, which sandy does not support: the program \
         cannot open it, and the access sandy grants would land on the folder behind the share; \
         name the local path instead",
        rule.path.display()
    ))
}

/// Whether `path` reaches its file through a network share: `\\server\share`, or
/// `\\?\UNC\server\share`, which `canonicalize` returns for a share and for a mapped network
/// drive. The other forms that start with two backslashes, `\\?\` and `\\.\`, are local.
pub(crate) fn is_network_path(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    let verbatim = text
        .get(..8)
        .is_some_and(|start| start.eq_ignore_ascii_case(r"\\?\UNC\"));
    let plain = text.starts_with(r"\\") && !text.starts_with(r"\\?\") && !text.starts_with(r"\\.\");
    verbatim || plain
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

/// Whether `sandy setup` gives the policy's AppContainer the loopback exemption. Only the values
/// that let the program connect to other hosts get it: an exempt AppContainer reaches 127.0.0.1
/// outside the sandbox without any network capability, which `ip = "none"` and
/// `ip = "private"` deny.
pub fn loopback_exemption(ip: IpAccess) -> bool {
    match ip {
        IpAccess::None | IpAccess::Private => false,
        IpAccess::Client | IpAccess::All => true,
    }
}

/// The network capabilities the target gets. `internetClientServer` includes `internetClient`.
/// Windows has no capability for outbound connections into home and work networks alone, so
/// `ip = "client"` reaches the internet only (docs/windows.md, "Client networking").
pub fn network_capabilities(ip: IpAccess) -> &'static [NetworkCapability] {
    match ip {
        IpAccess::None | IpAccess::Private => &[],
        IpAccess::Client => &[NetworkCapability::InternetClient],
        IpAccess::All => &[
            NetworkCapability::InternetClientServer,
            NetworkCapability::PrivateNetworkClientServer,
        ],
    }
}

/// The network capabilities the egress broker gets. It only ever connects out, so it needs
/// `internetClient`, not `internetClientServer`; `reach = "public-and-local"` adds
/// `privateNetworkClientServer` so it may reach the local network the broker's destination check
/// allows. The broker's own loopback isolation still stops it from reaching this machine
/// (docs/windows.md, "Egress broker").
pub fn broker_network_capabilities(reach: EgressReach) -> &'static [NetworkCapability] {
    match reach {
        EgressReach::Public => &[NetworkCapability::InternetClient],
        EgressReach::PublicAndLocal => &[
            NetworkCapability::InternetClient,
            NetworkCapability::PrivateNetworkClientServer,
        ],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCapability {
    /// Outbound connections to the internet.
    InternetClient,
    /// Inbound and outbound connections to the internet.
    InternetClientServer,
    /// Inbound and outbound connections to home and work networks.
    PrivateNetworkClientServer,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sandy_core::{
        ChildProcesses, EnforcementPlan, ExposedPort, ForwardedPort, PathAccess, PathMetadata,
        PathRule, Policy, SignalScope, Status, Win32k, WindowsPolicy,
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
            writable_paths: Ok(()),
            grants: Ok(()),
            outer_job_ui: Ok(None),
            firewall: Ok(()),
            loopback_exempt: Ok(false),
            broker_loopback_exempt: Ok(false),
            relay_program: Ok(sandy_exe(Path::new(r"C:\Program Files\sandy"))),
            forward_sockets: Ok(()),
        }
    }

    fn forwarding(mut policy: ResolvedPolicy) -> ResolvedPolicy {
        policy.ip = IpAccess::All;
        policy.forward = vec![ForwardedPort {
            port: 18081,
            to: "127.0.0.1:8081".parse().unwrap(),
        }];
        policy
    }

    /// `dir.join` keeps the path splittable into components on every host the tests run on.
    fn sandy_exe(dir: &Path) -> PathBuf {
        dir.join("sandy.exe")
    }

    fn exposing(mut policy: ResolvedPolicy) -> ResolvedPolicy {
        policy.ip = IpAccess::All;
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
            ..WindowsPolicy::default()
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
            Status::NeedsSetup { reason } => panic!("needs setup: {reason}"),
            Status::Enforced { mechanism } => panic!("enforced: {mechanism}"),
        }
    }

    fn needs_setup(status: Status) -> String {
        match status {
            Status::NeedsSetup { reason } => reason,
            Status::Unavailable { reason } => panic!("unavailable: {reason}"),
            Status::Enforced { mechanism } => panic!("enforced: {mechanism}"),
        }
    }

    #[test]
    fn reports_every_requirement_once() {
        let mut policy = policy();
        policy.signals = SignalScope::Isolated;
        policy.children = ChildProcesses::None;
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

    /// sandy grants access by adding an entry to the access control list of each policy path, so
    /// a path whose list the user may not change makes the run fail. The plan reports it.
    #[test]
    fn a_policy_path_that_cannot_be_granted_refuses() {
        let host = HostCapabilities {
            grants: Err(
                r#"cannot give AppContainer "example.app" access to C:\data: the grant is missing, and the current user may not change the permissions"#
                    .into(),
            ),
            ..host()
        };
        let policy = with_rule(policy(), PathAccess::Read);
        assert!(!plan(&policy, &host).is_enforceable());
        let reason = unavailable(status(&policy, &host, Requirement::FilesystemConfined));
        assert!(reason.contains(r"C:\data"), "{reason}");
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
    fn network_paths_are_refused_at_every_access_level() {
        for path in [
            r"\\?\UNC\localhost\C$\data",
            r"\\?\unc\server\share",
            r"\\server\share\data",
        ] {
            for access in [
                PathAccess::Read,
                PathAccess::ReadExec,
                PathAccess::ReadWrite,
            ] {
                let mut policy = policy();
                policy.paths.push(PathRule {
                    path: PathBuf::from(path),
                    access,
                    is_dir: true,
                });
                let reason = unavailable(status(&policy, &host(), Requirement::FilesystemConfined));
                assert!(reason.contains("network or share path"), "{path}: {reason}");
                assert!(reason.contains(path), "{path}: {reason}");
            }
        }
        // Control: local paths, also in the verbatim and the device form.
        for path in [
            r"C:\data",
            r"\\?\C:\data",
            r"\\?\Volume{0}\data",
            r"\\.\C:\data",
        ] {
            let mut policy = policy();
            policy.paths.push(PathRule {
                path: PathBuf::from(path),
                access: PathAccess::ReadWrite,
                is_dir: true,
            });
            assert!(plan(&policy, &host()).is_enforceable(), "{path}");
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
        // `sandy setup` removes the exemption, so it is NeedsSetup, not plain Unavailable.
        let reason = needs_setup(status(&policy(), &host, Requirement::IpNetworkDenied));
        assert!(reason.contains("exempt"), "{reason}");
        assert!(plan(&policy(), &host).needs_only_setup());

        let mut allowed = policy();
        allowed.ip = IpAccess::All;
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

    #[test]
    fn win32k_requirement_follows_the_policy() {
        let mut policy = policy();
        assert!(
            !plan_for(&policy, &host())
                .iter()
                .any(|item| item.requirement == Requirement::Win32kDenied)
        );
        policy.windows.win32k = Win32k::Deny;
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::Win32kDenied) {
            Status::Enforced { mechanism } => {
                assert!(
                    mechanism.contains("WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON"),
                    "{mechanism}"
                );
                assert!(mechanism.contains("relays"), "{mechanism}");
            }
            Status::Unavailable { reason } | Status::NeedsSetup { reason } => {
                panic!("unavailable: {reason}")
            }
        }
        // The program never starts without an AppContainer, so nothing is enforced.
        policy.windows.appcontainer_name = None;
        assert!(matches!(
            status(&policy, &host(), Requirement::Win32kDenied),
            Status::Unavailable { .. }
        ));
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
        allowed.ip = IpAccess::All;
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
    fn a_writable_path_problem_blocks_the_filesystem_only() {
        let host = HostCapabilities {
            writable_paths: Err("writable path C:\\Program Files\\App overlaps".into()),
            ..host()
        };
        let reason = unavailable(status(&policy(), &host, Requirement::FilesystemConfined));
        assert!(reason.contains("overlaps"), "{reason}");
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
            Status::Unavailable { reason } | Status::NeedsSetup { reason } => {
                panic!("unavailable: {reason}")
            }
        }
    }

    #[test]
    fn relays_need_an_executable_sandy() {
        let host = HostCapabilities {
            relay_program: Err("the current user may not change its permissions".into()),
            ..host()
        };
        // `sandy setup` adds the grant, so the relay grant is NeedsSetup.
        let reason = needs_setup(status(
            &exposing(policy()),
            &host,
            Requirement::ExposedPortsRelayed,
        ));
        assert!(reason.contains("permissions"), "{reason}");
        assert!(plan(&exposing(policy()), &host).needs_only_setup());
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
    fn child_processes_are_denied_by_the_job() {
        let mut policy = policy();
        policy.children = ChildProcesses::None;
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::ChildProcessesDenied) {
            Status::Enforced { mechanism } => {
                assert!(
                    mechanism.contains("JOB_OBJECT_LIMIT_ACTIVE_PROCESS"),
                    "{mechanism}"
                );
                assert!(
                    mechanism.contains("CHILD_PROCESS_RESTRICTED"),
                    "{mechanism}"
                );
            }
            Status::Unavailable { reason } | Status::NeedsSetup { reason } => {
                panic!("unavailable: {reason}")
            }
        }
        // The limit lives in sandy's job, which an outer job with UI restrictions prevents.
        let nested = HostCapabilities {
            outer_job_ui: Ok(Some(0x1)),
            ..host()
        };
        let reason = unavailable(status(&policy, &nested, Requirement::ChildProcessesDenied));
        assert!(reason.contains("UI restrictions"), "{reason}");
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
        let reason = unavailable(status(
            &forwarding(policy()),
            &nested,
            Requirement::ForwardedPortsRelayed,
        ));
        assert!(reason.contains("UI restrictions"), "{reason}");
    }

    #[test]
    fn forwarded_ports_are_relayed_through_af_unix() {
        let policy = forwarding(policy());
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::ForwardedPortsRelayed) {
            Status::Enforced { mechanism } => {
                assert!(mechanism.contains("sandy __forward"), "{mechanism}");
                assert!(mechanism.contains("AF_UNIX"), "{mechanism}");
                assert!(mechanism.contains("no loopback exemption"), "{mechanism}");
            }
            Status::Unavailable { reason } | Status::NeedsSetup { reason } => {
                panic!("unavailable: {reason}")
            }
        }
    }

    #[test]
    fn forwarding_needs_af_unix_sockets_and_an_executable_sandy() {
        let no_sockets = HostCapabilities {
            forward_sockets: Err("AF_UNIX sockets are not available".into()),
            ..host()
        };
        let reason = unavailable(status(
            &forwarding(policy()),
            &no_sockets,
            Requirement::ForwardedPortsRelayed,
        ));
        assert!(reason.contains("AF_UNIX"), "{reason}");
        // Exposed ports do not need AF_UNIX.
        assert!(plan(&exposing(policy()), &no_sockets).is_enforceable());

        let data = Path::new(r"C:\data");
        let writable_sandy = HostCapabilities {
            relay_program: Ok(sandy_exe(&data.join("bin"))),
            ..host()
        };
        let writable = forwarding(with_rule(policy(), PathAccess::ReadWrite));
        let reason = unavailable(status(
            &writable,
            &writable_sandy,
            Requirement::ForwardedPortsRelayed,
        ));
        assert!(reason.contains("read-write"), "{reason}");
    }

    #[test]
    fn client_notes_that_private_networks_are_out_of_reach() {
        let mut client = policy();
        client.ip = IpAccess::Client;
        let notes = notes(&client);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("private or domain network"), "{notes:?}");
        let mut all = policy();
        all.ip = IpAccess::All;
        assert!(super::notes(&all).is_empty());
    }

    #[test]
    fn none_and_private_note_the_loopback_within_the_appcontainer() {
        for ip in [IpAccess::None, IpAccess::Private] {
            let mut policy = policy();
            policy.ip = ip;
            let notes = notes(&policy);
            assert_eq!(notes.len(), 1, "{ip:?}: {notes:?}");
            assert!(
                notes[0].contains("reach each other over loopback"),
                "{notes:?}"
            );
        }
    }

    fn private(mut policy: ResolvedPolicy) -> ResolvedPolicy {
        policy.ip = IpAccess::Private;
        policy
    }

    /// `ip = "private"` is the AppContainer of `ip = "none"`: no network capability and no
    /// loopback exemption, so its processes reach each other over loopback and nothing else.
    #[test]
    fn private_network_is_an_appcontainer_without_capabilities() {
        let policy = private(policy());
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::IpNetworkPrivate) {
            Status::Enforced { mechanism } => {
                assert!(
                    mechanism.contains("without network capabilities"),
                    "{mechanism}"
                );
                assert!(mechanism.contains("loopback isolation"), "{mechanism}");
            }
            Status::Unavailable { reason } | Status::NeedsSetup { reason } => {
                panic!("unavailable: {reason}")
            }
        }
        assert!(network_capabilities(IpAccess::Private).is_empty());
        let relayed = private(forwarding(exposing(self::policy())));
        assert!(plan(&relayed, &host()).is_enforceable());
    }

    #[test]
    fn private_network_needs_the_firewall_no_exemption_and_the_fix() {
        let policy = private(policy());
        let exempt = HostCapabilities {
            loopback_exempt: Ok(true),
            ..host()
        };
        let reason = needs_setup(status(&policy, &exempt, Requirement::IpNetworkPrivate));
        assert!(reason.contains("exempt"), "{reason}");
        assert!(reason.contains("--ip private"), "{reason}");
        assert!(plan(&policy, &exempt).needs_only_setup());
        let stopped = HostCapabilities {
            firewall: Err("MpsSvc stopped".into()),
            ..host()
        };
        let reason = unavailable(status(&policy, &stopped, Requirement::IpNetworkPrivate));
        assert!(reason.contains("Windows Firewall"), "{reason}");
        let unreadable = HostCapabilities {
            loopback_exempt: Err("access denied".into()),
            ..host()
        };
        assert!(!plan(&policy, &unreadable).is_enforceable());
        let unpatched = HostCapabilities {
            windows: Ok(WindowsVersion {
                build: 19043,
                revision: Some(1287),
            }),
            ..host()
        };
        let reason = unavailable(status(&policy, &unpatched, Requirement::IpNetworkPrivate));
        assert!(reason.contains("CVE-2021-41338"), "{reason}");
    }

    /// `sandy setup` gives the exemption to the values that connect to other hosts, and takes it
    /// from the two that must not reach 127.0.0.1 outside the sandbox.
    #[test]
    fn setup_exempts_only_the_values_that_connect_out() {
        assert!(!loopback_exemption(IpAccess::None));
        assert!(!loopback_exemption(IpAccess::Private));
        assert!(loopback_exemption(IpAccess::Client));
        assert!(loopback_exemption(IpAccess::All));
    }

    /// Windows has nothing that hides paths from an AppContainer without administrator rights,
    /// so the view is refused, also when the policy is otherwise not enforceable here.
    #[test]
    fn the_policy_view_is_unavailable() {
        let mut policy = policy();
        policy.view = sandy_core::FileView::Policy;
        assert!(!plan(&policy, &host()).is_enforceable());
        let reason = unavailable(status(&policy, &host(), Requirement::PathsHidden));
        assert!(reason.contains("administrator rights"), "{reason}");
        assert!(reason.contains("What the program can see"), "{reason}");
        policy.windows.appcontainer_name = None;
        let reason = unavailable(status(&policy, &host(), Requirement::PathsHidden));
        assert!(reason.contains("administrator rights"), "{reason}");
    }

    fn with_egress(reach: sandy_core::EgressReach) -> ResolvedPolicy {
        let mut policy = private(policy());
        policy.egress = Some(sandy_core::Egress { port: 1080, reach });
        policy
    }

    /// The broker runs as `sandy __broker` in a sandbox of its own, reached over AF_UNIX.
    #[test]
    fn egress_is_enforced_by_a_broker_in_its_own_sandbox() {
        let policy = with_egress(sandy_core::EgressReach::Public);
        assert!(plan(&policy, &host()).is_enforceable());
        match status(&policy, &host(), Requirement::EgressBrokered) {
            Status::Enforced { mechanism } => {
                assert!(mechanism.contains("sandy __broker"), "{mechanism}");
                assert!(mechanism.contains("AF_UNIX"), "{mechanism}");
                assert!(mechanism.contains("public"), "{mechanism}");
                assert!(mechanism.contains("loopback isolation"), "{mechanism}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            broker_network_capabilities(sandy_core::EgressReach::Public),
            &[NetworkCapability::InternetClient]
        );
        assert_eq!(
            broker_network_capabilities(sandy_core::EgressReach::PublicAndLocal),
            &[
                NetworkCapability::InternetClient,
                NetworkCapability::PrivateNetworkClientServer
            ]
        );
    }

    /// The broker needs the firewall, no exemption and the CVE fix, like `ip = "private"`, no
    /// exemption for its own AppContainer, and an AppContainer name that leaves room for the
    /// broker's reserved suffix.
    #[test]
    fn egress_is_unavailable_under_the_same_conditions_as_private() {
        let policy = with_egress(sandy_core::EgressReach::Public);
        let exempt = HostCapabilities {
            loopback_exempt: Ok(true),
            ..host()
        };
        assert!(
            needs_setup(status(&policy, &exempt, Requirement::EgressBrokered)).contains("exempt")
        );
        let stopped = HostCapabilities {
            firewall: Err("MpsSvc stopped".into()),
            ..host()
        };
        assert!(
            unavailable(status(&policy, &stopped, Requirement::EgressBrokered))
                .contains("Windows Firewall")
        );
        let unpatched = HostCapabilities {
            windows: Ok(WindowsVersion {
                build: 19043,
                revision: Some(1287),
            }),
            ..host()
        };
        assert!(
            unavailable(status(&policy, &unpatched, Requirement::EgressBrokered))
                .contains("CVE-2021-41338")
        );
        // The relay grant on sandy.exe that the broker's AppContainer also needs: setup adds it.
        let ungrantable = HostCapabilities {
            relay_program: Err("the current user may not change its permissions".into()),
            ..host()
        };
        assert!(
            needs_setup(status(&policy, &ungrantable, Requirement::EgressBrokered))
                .contains("permissions")
        );
        // The broker's own AppContainer must not be exempt either; `sandy setup` removes it.
        let broker_exempt = HostCapabilities {
            broker_loopback_exempt: Ok(true),
            ..host()
        };
        let reason = needs_setup(status(&policy, &broker_exempt, Requirement::EgressBrokered));
        assert!(reason.contains("example.app.sandy-egress"), "{reason}");
        assert!(reason.contains("exempt"), "{reason}");
        assert!(plan(&policy, &broker_exempt).needs_only_setup());
        let broker_unreadable = HostCapabilities {
            broker_loopback_exempt: Err("access denied".into()),
            ..host()
        };
        assert!(
            unavailable(status(
                &policy,
                &broker_unreadable,
                Requirement::EgressBrokered
            ))
            .contains("loopback exemptions")
        );
        // A name with no room for the broker suffix.
        let mut long = with_egress(sandy_core::EgressReach::Public);
        long.windows.appcontainer_name = Some("a".repeat(60));
        assert!(
            unavailable(status(&long, &host(), Requirement::EgressBrokered)).contains("longer")
        );
    }

    #[test]
    fn network_capabilities_follow_ip() {
        assert!(network_capabilities(IpAccess::None).is_empty());
        assert_eq!(
            network_capabilities(IpAccess::Client),
            &[NetworkCapability::InternetClient]
        );
        assert_eq!(network_capabilities(IpAccess::All).len(), 2);
    }

    /// `ip = "client"` relies on the firewall like `ip = "none"`, and on the fix of
    /// CVE-2021-41338, but an exempt AppContainer is what it needs to reach loopback services.
    #[test]
    fn client_needs_the_firewall_and_may_be_exempt() {
        let mut client = policy();
        client.ip = IpAccess::Client;
        let exempt = HostCapabilities {
            loopback_exempt: Ok(true),
            ..host()
        };
        assert!(matches!(
            status(&client, &exempt, Requirement::InboundIpDenied),
            Status::Enforced { .. }
        ));
        let stopped = HostCapabilities {
            firewall: Err("MpsSvc stopped".into()),
            ..host()
        };
        let reason = unavailable(status(&client, &stopped, Requirement::InboundIpDenied));
        assert!(reason.contains("Windows Firewall"), "{reason}");
        let unpatched = HostCapabilities {
            windows: Ok(WindowsVersion {
                build: 19043,
                revision: Some(1287),
            }),
            ..host()
        };
        let reason = unavailable(status(&client, &unpatched, Requirement::InboundIpDenied));
        assert!(reason.contains("CVE-2021-41338"), "{reason}");
    }
}
