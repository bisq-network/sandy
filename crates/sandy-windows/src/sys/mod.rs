mod acl;
mod appcontainer;
mod elevate;
mod forward;
mod host;
mod host_network;
mod lockfile;
mod network;
mod parent;
mod process;
mod relay;
mod singleton;
mod util;

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawSocket;
use std::path::Path;

use sandy_core::{
    Backend, ChildProcesses, Junctions, ParentProcess, PathRule, PlanItem, ProtectedPath,
    Requirement, ResolvedLevel, ResolvedPolicy, SandboxError, SetupOptions, SetupOutcome,
    StatusReport, TargetCommand, Warning, WarningId, Win32k, path_directories,
};
use windows_sys::Win32::Security::{
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Profile,
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData,
    FOLDERID_Startup, KF_FLAG_DONT_VERIFY,
};

use crate::cmdline::{command_line, refused_program, without_verbatim_prefix};
use crate::detect::{Detection, Probes};
use crate::envblock::{LOCAL_APP_DATA, SYSTEM_ROOT, environment_block};
use crate::name::validate_appcontainer_name;
use crate::plan::{NetworkCapability, Problem, loopback_exemption, network_capabilities, worst};
use crate::version::WindowsVersion;
use util::{Sid, wide, wide_nul};

pub use host_network::WindowsHost;
pub use parent::recorded_parent;

/// Refuses a program that Windows does not start as named (`cmdline::refused_program`).
fn refuse_program(program: &Path) -> Result<(), SandboxError> {
    match refused_program(&wide(program.as_os_str())) {
        Some(reason) => Err(SandboxError::new(reason)),
        None => Ok(()),
    }
}

/// The ports the one relay of a run serves, for its messages, such as "the exposed ports and the
/// egress port".
fn relay_serves(exposed: usize, forwarded: usize, egress: bool) -> String {
    let ports = |count: usize, kind: &str| match count {
        0 => None,
        1 => Some(format!("the {kind} port")),
        _ => Some(format!("the {kind} ports")),
    };
    let served: Vec<String> = [
        ports(exposed, "exposed"),
        ports(forwarded, "forwarded"),
        ports(usize::from(egress), "egress"),
    ]
    .into_iter()
    .flatten()
    .collect();
    match served.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => "no port".to_string(),
    }
}

/// Why a run fails when its relay, which serves the ports of `relay_serves`, ends while the
/// program runs, as on Linux and macOS.
fn relay_ended_first(exposed: usize, forwarded: usize, egress: bool) -> String {
    let serves = relay_serves(exposed, forwarded, egress);
    let gone = if exposed + forwarded + usize::from(egress) == 1 {
        "the port it served is gone"
    } else {
        "the ports it served are gone"
    };
    format!(
        "the relay of {serves} ended before the program; {gone} and the program has been ended \
         with it"
    )
}

/// Why a run fails when its egress broker ends while the program runs, as on Linux and macOS.
const BROKER_ENDED_FIRST: &str = "the egress broker ended before the program; the program can no \
    longer connect out and has been ended with it";

/// The Windows backend. It keeps what it learns of the host (`Detection`), so one value serves
/// one invocation of sandy.
#[derive(Debug)]
pub struct WindowsBackend {
    detection: Detection<WindowsProbes>,
}

impl WindowsBackend {
    pub fn new() -> Self {
        WindowsBackend {
            detection: Detection::new(WindowsProbes),
        }
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for WindowsBackend {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        self.detection.plan(policy)
    }

    /// The trials that the plan cannot make without touching the host: the listeners of the
    /// relays, the nesting of sandy's job and the win32k lockdown. Every finding is
    /// indeterminate (`Backend::verify`).
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let mut items = sandy_core::verify::relay_listeners(policy);
        // The relay listens on the program's egress port inside the AppContainer, which shares the
        // host's ports, as it does on a forwarded port.
        if let Some(egress) = policy.egress {
            let address = egress.listen();
            if let Err(error) = std::net::TcpListener::bind(address) {
                items.push(PlanItem::indeterminate(
                    Requirement::EgressBrokered,
                    format!("cannot listen on {address}: {error}"),
                ));
            }
        }
        if let Err(reason) = host::job_nests(self.detection.outer_job_ui()) {
            items.extend(crate::plan::job_indeterminate(policy, &reason));
        }
        if policy.windows.win32k == Win32k::Deny
            && let Err(reason) = host::win32k_lockdown()
        {
            items.push(PlanItem::indeterminate(Requirement::Win32kDenied, reason));
        }
        items
    }

    /// What makes the program behave differently inside the sandbox than outside, beyond the
    /// requirements: the networks `ip = "client"` cannot reach (`plan::notes`) and a directory on
    /// sandy's PATH inside a writable path (rule 12). Before them come the shortfalls of the
    /// policy (`plan::shortfalls`).
    fn notes(&self, policy: &ResolvedPolicy) -> Vec<Warning> {
        let mut notes = crate::plan::shortfalls(policy);
        notes.extend(crate::plan::notes(policy));
        notes.extend(policy.mach_services_notes("Windows"));
        notes.extend(policy.path_directory_notes(&path_locations()));
        notes.extend(session_note());
        notes.extend(junction_notes(policy));
        notes
    }

    /// A batch file program and, with `end_with_parent`, a parent that has ended, which `run`
    /// refuses before it changes anything.
    fn refuse(
        &self,
        policy: &ResolvedPolicy,
        parent: Option<ParentProcess>,
    ) -> Result<(), SandboxError> {
        if let Some(program) = &policy.program {
            refuse_program(program)?;
        }
        if policy.end_with_parent {
            parent::open_parent(parent)?;
        }
        Ok(())
    }

    fn run(
        &self,
        policy: &ResolvedPolicy,
        command: &TargetCommand,
        status: &StatusReport,
    ) -> Result<i32, SandboxError> {
        // The plan of the selection, kept with the answers it saw: the caller checked it, and
        // every mechanism below is one it named. A step that finds the host changed fails.
        if let Some(item) = self.plan(policy).into_iter().find(|i| !i.is_enforced()) {
            return Err(SandboxError::new(format!(
                "{}: {}",
                item.requirement.description(),
                item.status.reason().unwrap_or_default()
            )));
        }
        let name = policy
            .windows
            .appcontainer_name
            .as_deref()
            .ok_or_else(|| SandboxError::new("the policy names no AppContainer"))?;
        if policy.program.as_deref() != Some(command.program.as_path()) {
            return Err(SandboxError::new(
                "the policy was resolved for another program",
            ));
        }
        // Opened first, so a parent that has already ended stops the run before anything starts.
        let parent = if policy.end_with_parent {
            Some(parent::open_parent(command.parent)?)
        } else {
            None
        };

        // Refuse a concurrent run that shares this AppContainer with a different policy. Held
        // until the program exits, so an overlapping weaker policy cannot join the sandbox. The
        // SID is the identity, not the name: names that differ only in case give one SID.
        let _singleton = singleton::hold(&appcontainer::sid(name)?, policy)?;

        let container = appcontainer::ensure_profile(name)?;
        // Windows gives the AppContainer a private, persistent, writable folder (its profile,
        // which holds TEMP). sandy removes execute there so the program cannot run what it
        // writes, keeping the writable-never-executable rule.
        acl::deny_execute_in_profile(&container, &profile_folder(&container)?)?;
        let mut capabilities = Vec::new();
        for capability in network_capabilities(policy.ip) {
            capabilities.push(network_capability_sid(*capability)?);
        }
        let held = held_sids(policy, &container)?;
        for rule in &policy.paths {
            capabilities.push(acl::grant(name, rule, &held)?);
        }
        // A directory policy path named through a junction opens under that name only when the
        // junction itself lets the program in (docs/windows.md, "Links and identity").
        if policy.windows.junctions == Junctions::Grant {
            capabilities.extend(acl::grant_junctions(name, policy));
        }

        // The relays run sandy's own executable, the one the plan read, with one capability:
        // read and execute access to that file. The same capability opens the sockets of
        // forwarded ports, which the egress broker also reaches, so it is needed for `egress` too.
        let relay_rule =
            if policy.expose.is_empty() && policy.forward.is_empty() && policy.egress.is_none() {
                None
            } else {
                match self.detection.relay() {
                    Ok(target) => Some(target.rule().clone()),
                    Err(problem) => return Err(SandboxError::new(problem.to_string())),
                }
            };
        // The egress broker runs in a sandbox of its own, so prepare it before the relays that
        // name the AppContainer they belong to. Its profile stays like the program's: the runs
        // of one policy share it, and one that ends must not take it from one that starts.
        let broker = match (policy.egress, &relay_rule) {
            (Some(egress), Some(rule)) => Some(EgressBroker::prepare(name, egress, rule)?),
            _ => None,
        };
        let relay_capability = match relay_rule {
            Some(rule) => Some((acl::grant(name, &rule, &held)?, rule.path)),
            None => None,
        };
        let mut relays = Vec::new();
        let mut forwarding = None;
        if let Some((capability, sandy)) = &relay_capability {
            let capability = std::slice::from_ref(capability);
            // One `sandy __relay` in the program's AppContainer serves every exposed port, on the
            // listener that sandy creates outside, and every forwarded port, on a listener it
            // creates inside, and the egress port, on a listener it creates inside too, named
            // with `--egress`; the broker serves that port's AF_UNIX socket instead of sandy.
            let serves = relay_serves(
                policy.expose.len(),
                policy.forward.len(),
                policy.egress.is_some(),
            );
            let exposed = relay::listen(&policy.expose)?;
            let mut args = vec![wide(relay::RELAY_COMMAND.as_ref())];
            for (listener, target) in &exposed {
                args.push(wide("--expose".as_ref()));
                args.push(wide(listener.as_raw_socket().to_string().as_ref()));
                args.push(wide(target.to_string().as_ref()));
            }
            let egress_listen = policy.egress.map(|egress| egress.listen());
            let mut egress_listener = None;
            if !policy.forward.is_empty() || egress_listen.is_some() {
                let (started, listens, listener) =
                    forward::Forwarding::start(&policy.forward, egress_listen, &capability[0])?;
                args.push(wide("--sockets".as_ref()));
                args.push(wide(started.directory().as_os_str()));
                for listen in listens {
                    args.push(wide("--forward".as_ref()));
                    args.push(wide(listen.to_string().as_ref()));
                }
                if let Some(listen) = egress_listen {
                    args.push(wide("--egress".as_ref()));
                    args.push(wide(listen.to_string().as_ref()));
                }
                forwarding = Some(started);
                egress_listener = listener;
            }
            let process = process_for(
                sandy.as_os_str(),
                sandy.as_os_str(),
                &args,
                &[],
                None,
                capability,
            )
            .map_err(|error| {
                SandboxError::new(format!("cannot start the relay of {serves}: {error}"))
            })?;
            relays.push(process::Relay {
                process,
                appcontainer: &container,
                sockets: exposed
                    .into_iter()
                    .map(|(listener, _)| Box::new(listener) as Box<dyn process::InheritedSocket>)
                    .collect(),
                name: "the relay",
                ended_first: relay_ended_first(
                    policy.expose.len(),
                    policy.forward.len(),
                    policy.egress.is_some(),
                ),
            });
            // The broker itself: `sandy __broker` in its own AppContainer, serving the egress
            // AF_UNIX socket it inherits. It is in the relay job, so it ends with the program.
            if let (Some(broker), Some(listener)) = (&broker, egress_listener) {
                let reach = policy.egress.expect("egress set with a broker").reach;
                let args = [
                    wide(relay::BROKER_COMMAND.as_ref()),
                    wide(listener.as_raw_socket().to_string().as_ref()),
                    wide(reach.name().as_ref()),
                ];
                relays.push(process::Relay {
                    process: process_for(
                        sandy.as_os_str(),
                        sandy.as_os_str(),
                        &args,
                        &[],
                        None,
                        &broker.capabilities,
                    )?,
                    appcontainer: &broker.container,
                    sockets: vec![Box::new(listener)],
                    name: "the egress broker",
                    ended_first: BROKER_ENDED_FIRST.to_string(),
                });
            }
        }

        let args: Vec<Vec<u16>> = command.args.iter().map(|arg| wide(arg)).collect();
        let cwd = command.cwd.as_ref().map(|cwd| wide_nul(cwd.as_os_str()));
        let program = process_for(
            command.program.as_os_str(),
            &command.arg0,
            &args,
            &command.env,
            cwd,
            &capabilities,
        )?;
        let ended = process::run(
            process::Launch {
                appcontainer: &container,
                program,
                relays,
                deny_children: policy.children == ChildProcesses::None,
                deny_win32k: policy.windows.win32k == Win32k::Deny,
                parent,
            },
            status,
        )?;
        if let Some(forwarding) = forwarding {
            forwarding.stop(ended.deadline);
        }
        match ended.failure {
            Some(failure) => Err(SandboxError::new(failure)),
            None => Ok(ended.code),
        }
    }

    /// Makes the loopback exemption of the policy's AppContainer match the policy: present with
    /// `ip = "client"` and `ip = "all"`, absent with `ip = "none"` and `ip = "private"`
    /// (`plan::loopback_exemption`), and always absent for the egress broker's. With exposed or
    /// forwarded ports or egress, also lets the relays run sandy's executable, which a user
    /// without the right to change its permissions cannot do at run time. Without administrator
    /// rights it changes nothing (`elevate::needs_rights`).
    fn setup(
        &self,
        policy: &ResolvedPolicy,
        _options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
            SandboxError::new("the policy names no AppContainer; pass --appcontainer NAME")
        })?;
        validate_appcontainer_name(name).map_err(SandboxError::new)?;
        if !elevate::is_elevated()? {
            return Ok(elevate::needs_rights("setup"));
        }
        let container = appcontainer::sid(name)?;
        let exempt = loopback_exemption(policy.ip);
        network::set_loopback_exempt(&container, exempt)?;
        let mut done = format!(
            "the AppContainer {name} is {} the loopback exemption",
            if exempt { "in" } else { "not in" }
        );
        if !policy.expose.is_empty() || !policy.forward.is_empty() || policy.egress.is_some() {
            // The SIDs that run sandy.exe, so that setup refuses what check and run refuse.
            let rule = relay::relay_rule().map_err(SandboxError::new)?;
            acl::grant(name, &rule, &held_sids(policy, &container)?)?;
            done.push_str(", and its relays may run sandy.exe");
            // The egress broker runs sandy's executable from an AppContainer of its own, which
            // loopback isolation keeps off this machine only without the exemption.
            if let Some(egress) = policy.egress {
                let broker = crate::name::egress_broker_name(name).map_err(SandboxError::new)?;
                let broker_container = appcontainer::sid(&broker)?;
                network::set_loopback_exempt(&broker_container, false)?;
                acl::grant(
                    &broker,
                    &rule,
                    &broker_held_sids(&broker_container, egress.reach)?,
                )?;
                done.push_str(
                    ", and so may its egress broker, whose AppContainer is not in the loopback \
                     exemption",
                );
            }
        }
        Ok(SetupOutcome::Done(done))
    }

    /// Takes back what `setup` and the runs of this policy left behind: the loopback exemptions of
    /// its AppContainer and of the egress broker's, the access control entry of every policy path
    /// and of sandy's own executable, and the AppContainer profile with its folder. Only entries
    /// for the capability SIDs sandy derives for this AppContainer are removed; other software uses
    /// capability SIDs too.
    ///
    /// Entries on objects that have left the policy stay, because nothing says where they are.
    /// Without administrator rights it changes nothing (`elevate::needs_rights`).
    fn remove(
        &self,
        policy: &ResolvedPolicy,
        _options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
            SandboxError::new("the policy names no AppContainer; pass --appcontainer NAME")
        })?;
        validate_appcontainer_name(name).map_err(SandboxError::new)?;
        if !elevate::is_elevated()? {
            return Ok(elevate::needs_rights("setup --remove"));
        }
        let container = appcontainer::sid(name)?;
        // A run of this AppContainer would lose its access in the middle.
        let _idle = singleton::hold_idle(&container)?;
        network::set_loopback_exempt(&container, false)?;
        if let Ok(broker) = crate::name::egress_broker_name(name) {
            network::set_loopback_exempt(&appcontainer::sid(&broker)?, false)?;
        }
        // First, so that a path whose entry cannot be removed does not keep these.
        let kept = acl::revoke_junctions(name, policy);
        for rule in &policy.paths {
            acl::revoke(name, rule)?;
        }
        if let Ok(rule) = relay::relay_rule() {
            acl::revoke(name, &rule)?;
            // The egress broker's grant on sandy's executable and its profile, if any.
            if let Ok(broker) = crate::name::egress_broker_name(name) {
                acl::revoke(&broker, &rule)?;
                appcontainer::delete_profile(&broker)?;
            }
        }
        appcontainer::delete_profile(name)?;
        let mut done = format!("removed what sandy left for the AppContainer {name}");
        if !kept.is_empty() {
            let entries: Vec<String> = kept
                .iter()
                .map(|(path, error)| format!("{} ({error})", path.display()))
                .collect();
            done.push_str(&format!(
                ", except the entries on the junctions {}, which grant nothing without the \
                 AppContainer; remove one with icacls JUNCTION /L /remove:g *SID",
                entries.join(", ")
            ));
        }
        Ok(SetupOutcome::Done(done))
    }

    /// With administrator rights already, setup runs here; otherwise sandy runs again after the
    /// UAC prompt (`elevate`).
    fn elevate(
        &self,
        levels: &[ResolvedLevel],
        remove: bool,
        options: SetupOptions,
        args: &[OsString],
    ) -> Result<SetupOutcome, SandboxError> {
        if elevate::is_elevated()? {
            return sandy_core::setup_levels(levels, |policy| {
                if remove {
                    self.remove(policy, options)
                } else {
                    self.setup(policy, options)
                }
            });
        }
        elevate::run_elevated(args)
    }
}

/// The egress broker's sandbox: its own AppContainer with the internetClient capability (and
/// privateNetworkClientServer for `reach = "public-and-local"`) and read and execute access to
/// sandy's executable. Its loopback isolation stops it from reaching this machine at the kernel
/// level, and `sandy_core::destination` keeps it to the destinations `reach` allows.
struct EgressBroker {
    container: Sid,
    capabilities: Vec<Sid>,
}

impl EgressBroker {
    /// `relay` is the rule that lets it run sandy's executable.
    fn prepare(
        program_name: &str,
        egress: sandy_core::Egress,
        relay: &PathRule,
    ) -> Result<EgressBroker, SandboxError> {
        let name = crate::name::egress_broker_name(program_name).map_err(SandboxError::new)?;
        let container = appcontainer::ensure_profile(&name)?;
        // The broker can write its profile folder (its TEMP) but must not execute what it writes.
        acl::deny_execute_in_profile(&container, &profile_folder(&container)?)?;
        let network = broker_network_sids(egress.reach)?;
        let mut held = vec![container.clone()];
        held.extend(network.iter().cloned());
        let mut capabilities = vec![acl::grant(&name, relay, &held)?];
        capabilities.extend(network);
        Ok(EgressBroker {
            container,
            capabilities,
        })
    }
}

/// A process of `program` with `arg0` as the first token of its command line, then `args`, the
/// policy environment `env` plus the variables sandy sets, and `capabilities`.
fn process_for<'a>(
    program: &OsStr,
    arg0: &OsStr,
    args: &[Vec<u16>],
    env: &[(OsString, OsString)],
    cwd: Option<Vec<u16>>,
    capabilities: &'a [Sid],
) -> Result<process::Process<'a>, SandboxError> {
    let program = wide(program);
    let program = without_verbatim_prefix(&program);
    let arg0 = wide(arg0);
    let command_line = command_line(without_verbatim_prefix(&arg0), args)
        .map_err(|error| SandboxError::new(format!("invalid command line: {error}")))?;
    let mut application = program.to_vec();
    application.push(0);
    Ok(process::Process {
        application,
        command_line,
        environment: environment(env)?,
        cwd,
        capabilities,
    })
}

/// The answers of this host to the probes of the plan (`detect::Probes`). Each changes nothing.
/// A probe that fails is indeterminate, unless it read a lasting state (`probe`).
#[derive(Debug)]
struct WindowsProbes;

impl Probes for WindowsProbes {
    type Sid = Sid;
    type Relay = acl::GrantTarget;
    type Layout = Layout;

    fn windows_version(&self) -> Result<WindowsVersion, Problem> {
        host::windows_version().map_err(Problem::Indeterminate)
    }

    fn capability_sids(&self) -> Result<(), Problem> {
        host::derive_capability_sids()
            .map(|_| ())
            .map_err(Problem::Unavailable)
    }

    fn outer_job_ui(&self) -> Result<Option<u32>, Problem> {
        host::outer_job_ui().map_err(Problem::Indeterminate)
    }

    fn firewall(&self) -> Result<(), Problem> {
        network::firewall_running()
    }

    fn loopback_exemptions(&self) -> Result<Vec<Sid>, Problem> {
        network::loopback_exemptions()
    }

    fn forward_sockets(&self) -> Result<(), Problem> {
        forward::check()
    }

    fn relay(&self) -> Result<acl::GrantTarget, Problem> {
        relay::relay_target()
    }

    fn layout(&self) -> Result<Layout, Problem> {
        Layout::read().map_err(|error| Problem::Indeterminate(error.to_string()))
    }

    fn appcontainer_sid(&self, name: &str) -> Result<Sid, Problem> {
        appcontainer::sid(name).map_err(|error| Problem::Indeterminate(error.to_string()))
    }

    fn relay_path<'relay>(&self, relay: &'relay acl::GrantTarget) -> &'relay std::path::Path {
        &relay.rule().path
    }

    fn relay_grantable(&self, relay: &acl::GrantTarget, name: &str) -> Result<(), Problem> {
        relay::grantable(relay, name)
    }

    fn relay_rights(
        &self,
        relay: &acl::GrantTarget,
        name: &str,
        policy: &ResolvedPolicy,
    ) -> Result<(), Problem> {
        check_relay_rights(relay, name, policy)
    }

    fn writable_paths(
        &self,
        layout: Option<&Layout>,
        policy: &ResolvedPolicy,
        container: &Sid,
    ) -> Result<(), Problem> {
        check_writable_paths(layout, policy, container)
    }

    fn grants(&self, name: &str, policy: &ResolvedPolicy) -> Result<(), Problem> {
        check_grants(name, policy)
    }
}

fn environment(vars: &[(OsString, OsString)]) -> Result<Vec<u16>, SandboxError> {
    let vars: Vec<(Vec<u16>, Vec<u16>)> = vars
        .iter()
        .map(|(name, value)| (wide(name), wide(value)))
        .collect();
    let fixed = [
        (wide(SYSTEM_ROOT.as_ref()), windows_directory()?),
        (wide(LOCAL_APP_DATA.as_ref()), local_app_data()?),
    ];
    environment_block(&vars, &fixed).map_err(|error| SandboxError::new(error.to_string()))
}

fn windows_directory() -> Result<Vec<u16>, SandboxError> {
    let mut buffer = vec![0u16; 260];
    loop {
        // SAFETY: the buffer is writable for the length passed.
        let len = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) }
            as usize;
        if len == 0 {
            return Err(util::last_error("cannot find the Windows directory"));
        }
        if len < buffer.len() {
            buffer.truncate(len);
            return Ok(buffer);
        }
        buffer.resize(len, 0);
    }
}

/// The AppContainer's profile folder, `<LOCALAPPDATA>\Packages\<name>\AC`. Windows redirects
/// the program's `LOCALAPPDATA`, `TEMP` and `TMP` here [Implementing an AppContainer].
///
/// Asked of Windows rather than built from the name: the name and the folder it reaches are not
/// the same function of the name, because Win32 normalizes a path component and
/// `GetAppContainerFolderPath` takes the SID, which is what the access check uses. Building the
/// path would change the permissions of another container's folder for a name Windows reads
/// differently, and leave the real one executable.
fn profile_folder(container: &Sid) -> Result<std::path::PathBuf, SandboxError> {
    use windows_sys::Win32::Security::Isolation::GetAppContainerFolderPath;

    let sid = wide_nul(container.to_string().as_ref());
    let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the SID string is NUL-terminated and path is a valid out pointer.
    let hresult = unsafe { GetAppContainerFolderPath(sid.as_ptr(), &mut path) };
    let result = if hresult < 0 {
        Err(util::hresult_error(
            format!("cannot find the profile folder of AppContainer {container}"),
            hresult,
        ))
    } else {
        // SAFETY: on success path is a NUL-terminated string from the function.
        let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        // SAFETY: path holds `len` units before its NUL.
        let wide = unsafe { std::slice::from_raw_parts(path, len) };
        Ok(std::path::PathBuf::from(OsString::from_wide(wide)))
    };
    // SAFETY: the function allocated path with the COM allocator; it is freed exactly once and
    // CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

fn local_app_data() -> Result<Vec<u16>, SandboxError> {
    known_folder(
        &FOLDERID_LocalAppData,
        "cannot find the local application data folder",
    )
}

/// sandy's own folder, `%LOCALAPPDATA%\sandy`: the lock files that coordinate its runs
/// (`lockfile`) and the socket directories of forwarded ports (`forward`).
fn state_directory() -> Result<std::path::PathBuf, SandboxError> {
    Ok(std::path::PathBuf::from(OsString::from_wide(&local_app_data()?)).join("sandy"))
}

/// The directories of the system set that a writable path may neither contain nor lie in: the
/// Windows directory and the program files directories, where Windows grants every
/// AppContainer read and execute access (rule 6 in DESIGN.md).
fn system_directories() -> Result<Vec<ProtectedPath>, SandboxError> {
    let mut directories = vec![windows_directory()?];
    directories.push(known_folder(
        &FOLDERID_ProgramFiles,
        "cannot find the program files folder",
    )?);
    directories.push(known_folder(
        &FOLDERID_ProgramFilesX86,
        "cannot find the x86 program files folder",
    )?);
    Ok(directories
        .into_iter()
        .map(|directory| {
            ProtectedPath::tree(std::path::PathBuf::from(OsString::from_wide(&directory)))
        })
        .collect())
}

/// The SIDs the program's token will hold that could carry rights on a policy path: its
/// AppContainer and its network capabilities. `acl::check_rights` says why the grant
/// capabilities are not among them.
fn held_sids(policy: &ResolvedPolicy, container: &Sid) -> Result<Vec<Sid>, SandboxError> {
    let mut held = vec![container.clone()];
    for capability in network_capabilities(policy.ip) {
        held.push(network_capability_sid(*capability)?);
    }
    Ok(held)
}

/// The SIDs the egress broker's token holds that could carry rights on sandy's executable: its
/// AppContainer `container` and the network capabilities of `reach`.
fn broker_held_sids(
    container: &Sid,
    reach: sandy_core::EgressReach,
) -> Result<Vec<Sid>, SandboxError> {
    let mut held = vec![container.clone()];
    held.extend(broker_network_sids(reach)?);
    Ok(held)
}

/// The network capabilities the egress broker holds for `reach`.
fn broker_network_sids(reach: sandy_core::EgressReach) -> Result<Vec<Sid>, SandboxError> {
    crate::plan::broker_network_capabilities(reach)
        .iter()
        .map(|capability| network_capability_sid(*capability))
        .collect()
}

/// Rule 3 for sandy's executable, which the relays run in the program's AppContainer and the
/// egress broker in its own: neither may be able to write it, as `run` and `setup` refuse in
/// `acl::grant`. Changes nothing.
fn check_relay_rights(
    relay: &acl::GrantTarget,
    name: &str,
    policy: &ResolvedPolicy,
) -> Result<(), Problem> {
    let indeterminate = |error: SandboxError| Problem::Indeterminate(error.to_string());
    let rule = relay.rule();
    let container = appcontainer::sid(name).map_err(indeterminate)?;
    acl::check_rights(rule, &held_sids(policy, &container).map_err(indeterminate)?).map_err(
        |problem| problem.map(|reason| format!("the relays run sandy's executable: {reason}")),
    )?;
    // A name with no room for the broker's suffix is the plan's own conflict.
    let (Some(egress), Ok(broker)) = (policy.egress, crate::name::egress_broker_name(name)) else {
        return Ok(());
    };
    let container = appcontainer::sid(&broker).map_err(indeterminate)?;
    let held = broker_held_sids(&container, egress.reach).map_err(indeterminate)?;
    acl::check_rights(rule, &held).map_err(|problem| {
        problem.map(|reason| format!("the egress broker runs sandy's executable: {reason}"))
    })
}

/// Locations of this user that programs outside the sandbox read or execute later: the folders
/// Windows runs programs from at logon, the PowerShell profile folders, the app execution
/// aliases, the configuration of git, SSH, GnuPG and cargo (shared with the Unix backends,
/// `sandy_core::trust::tool_configs`), libgit2's `%PROGRAMDATA%\Git`, Gpg4win's GnuPG folder
/// and sandy's own state. A writable path that reaches one of them lets the program leave a file
/// there that runs outside the sandbox at the next logon or the next build, and a file the
/// program creates keeps the user's own rights on it, including the right to execute it (see
/// "Trusted user locations" in docs/windows.md). Such a path is refused; the directories on
/// sandy's PATH only warn (`path_locations`).
///
/// The list is a heuristic and can never be complete: no list knows which files the programs of
/// this user trust. The user profile is protected only against a writable path that contains it,
/// so an ordinary writable folder below the profile keeps working.
fn trusted_locations() -> Result<Vec<ProtectedPath>, SandboxError> {
    let folder = |id, error| -> Result<std::path::PathBuf, SandboxError> {
        Ok(std::path::PathBuf::from(OsString::from_wide(
            &known_folder(id, error)?,
        )))
    };
    let documents = folder(&FOLDERID_Documents, "cannot find the documents folder")?;
    let local = folder(
        &FOLDERID_LocalAppData,
        "cannot find the local application data folder",
    )?;
    let mut locations = vec![
        ProtectedPath::tree(folder(&FOLDERID_Startup, "cannot find the startup folder")?),
        ProtectedPath::tree(folder(
            &FOLDERID_CommonStartup,
            "cannot find the common startup folder",
        )?),
        // Where PowerShell 5 and PowerShell 7 read their profile scripts from.
        ProtectedPath::tree(documents.join("WindowsPowerShell")),
        ProtectedPath::tree(documents.join("PowerShell")),
        // The app execution aliases, which the default PATH holds.
        ProtectedPath::tree(local.join("Microsoft").join("WindowsApps")),
        // The state that decides which policy may join a running AppContainer.
        ProtectedPath::tree(state_directory()?),
    ];
    // Where Gpg4win keeps the GnuPG configuration; GnuPG of MSYS2 and Git for Windows reads
    // `.gnupg` below HOME.
    locations.push(ProtectedPath::tree(
        folder(
            &FOLDERID_RoamingAppData,
            "cannot find the roaming application data folder",
        )?
        .join("gnupg"),
    ));
    // libgit2 reads `Git\config` below the folder that PROGRAMDATA names, as a level below the
    // system configuration (measured with libgit2 1.9.7); every user may create folders in
    // `C:\ProgramData`. Git for Windows 2.54 no longer reads it.
    let drives = drives()?;
    let program_data = folder(&FOLDERID_ProgramData, "cannot find the program data folder")?;
    locations.extend(
        known_and_named(program_data, std::env::var_os("PROGRAMDATA"), &drives)
            .into_iter()
            .map(|folder| ProtectedPath::tree(folder.join("Git"))),
    );
    let profiles = user_profiles(&drives)?;
    let named_homes: Vec<OsString> = [std::env::var_os("HOME"), home_drive_path()]
        .into_iter()
        .flatten()
        .collect();
    locations.extend(sandy_core::trust::tool_configs(
        &tool_homes(&profiles, &named_homes, &drives),
        &drives,
    ));
    // After the folders in it, so that a writable profile is reported with the folder that makes
    // it dangerous.
    locations.extend(profiles.into_iter().map(ProtectedPath::entry));
    Ok(locations)
}

/// The home directories the tools of `sandy_core::trust::tool_configs` read their configuration
/// below: the profile folders and the `named` homes, HOME and the one of `home_drive_path`. Git
/// for Windows reads `.gitconfig` and `.config\git` below HOME when it is set, and without HOME
/// below HOMEDRIVE followed by HOMEPATH (measured on Windows 11 with Git for Windows 2.54); a
/// tool that does not only makes the list longer. A home without a drive, `\Users\x`, which
/// git resolves on its current drive, counts on each of `drives`. A relative home, which git
/// resolves against its working directory, names no one place and is left out.
fn tool_homes(
    profiles: &[std::path::PathBuf],
    named: &[OsString],
    drives: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    let mut homes = profiles.to_vec();
    for home in named {
        homes.extend(sandy_core::trust::named_directories(
            Some(home.clone()),
            drives,
        ));
    }
    homes.sort();
    homes.dedup();
    homes
}

/// Where Git for Windows and libgit2 look for the home without HOME: HOMEDRIVE followed by
/// HOMEPATH, and HOMEPATH alone without HOMEDRIVE.
fn home_drive_path() -> Option<OsString> {
    let mut home = std::env::var_os("HOMEDRIVE").unwrap_or_default();
    home.push(std::env::var_os("HOMEPATH")?);
    Some(home)
}

/// The drives a path without one may mean to a program outside the sandbox: the drive of
/// sandy's working directory and the system drive. A program started on another drive is not
/// covered.
fn drives() -> Result<Vec<std::path::PathBuf>, SandboxError> {
    let windows = std::path::PathBuf::from(OsString::from_wide(&windows_directory()?));
    let current = std::env::current_dir().ok();
    let mut drives: Vec<std::path::PathBuf> = [Some(windows), current]
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let std::path::Component::Prefix(prefix) = path.components().next()? else {
                return None;
            };
            let mut drive = std::path::PathBuf::from(prefix.as_os_str());
            drive.push(std::path::Component::RootDir);
            Some(drive)
        })
        .collect();
    drives.sort();
    drives.dedup();
    Ok(drives)
}

/// The directories on sandy's PATH, which only warn. A program the sandboxed one leaves in one
/// of them runs outside the sandbox when the user next types its name, but a writable path that
/// holds such a directory is ordinary work, a package cache whose `bin` folder is on PATH for
/// example, so refusing it would turn away the common case (rule 12).
fn path_locations() -> Vec<ProtectedPath> {
    path_directories(std::env::var_os("PATH").as_deref())
}

/// The junctions on the way to directory policy paths that `run` would leave closed: the
/// program then opens what lies below such a junction, but not the directory under the
/// junction's name (docs/windows.md, "Links and identity"). A note, because `run` goes on.
fn junction_notes(policy: &ResolvedPolicy) -> Vec<Warning> {
    // Under "refuse" such a junction is a conflict of the plan, not a note.
    let Some(name) = policy.windows.appcontainer_name.as_deref() else {
        return Vec::new();
    };
    if policy.windows.junctions == Junctions::Refuse {
        return Vec::new();
    }
    acl::closed_junctions(name, policy)
        .into_iter()
        .map(|closed| {
            Warning::new(
                WarningId::JunctionClosed,
                format!(
                    "sandy does not open the junction {} itself for the program ({}), so the \
                     program can open what lies below it but cannot list or open the directory \
                     under that name; {}",
                    closed.junction.display(),
                    closed.reason,
                    closed.remedy
                ),
            )
        })
        .collect()
}

/// The warning for a run in session 0, where services and SSH sessions run. Its window stations
/// admit no AppContainer, so `user32.dll` cannot initialize in the program (docs/windows.md,
/// limitation 13). Interactive users have sessions of their own since Windows Vista. A note,
/// not a requirement: a program without `user32.dll` runs there.
fn session_note() -> Option<Warning> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

    let mut session = u32::MAX;
    // SAFETY: session is a valid out pointer.
    let found = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0;
    (found && session == 0).then(|| {
        Warning::new(
            WarningId::SessionZero,
            "sandy runs in session 0, where services and SSH sessions run, and its window stations \
         admit no AppContainer: a program that loads user32.dll ends there with \
         STATUS_DLL_INIT_FAILED (0xC0000142) before it runs; run it from a desktop session \
         (docs/windows.md, \"Known limitations\")",
        )
    })
}

/// The profile folder of this user, from the known folder and from USERPROFILE. The known
/// folder, because a service that starts sandy with a minimal environment sets no USERPROFILE;
/// the variable as well, because a user who moves their profile with it keeps their files there.
fn user_profiles(drives: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>, SandboxError> {
    let known = std::path::PathBuf::from(OsString::from_wide(&known_folder(
        &FOLDERID_Profile,
        "cannot find the user profile folder",
    )?));
    Ok(known_and_named(
        known,
        std::env::var_os("USERPROFILE"),
        drives,
    ))
}

/// A known folder and the place its variable names, each once. The variable names a place with a
/// drive directly, and one rooted without a drive on each of `drives`, the same expansion
/// `tool_homes` does for a home directory; a relative value names no one place and is left out.
fn known_and_named(
    known: std::path::PathBuf,
    named: Option<OsString>,
    drives: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    let mut folders: Vec<std::path::PathBuf> = std::iter::once(known)
        .chain(sandy_core::trust::named_directories(named, drives))
        .collect();
    folders.sort();
    folders.dedup();
    folders
}

/// The locations of this host that a writable path must not reach (rules 3 and 6), and how to
/// compare paths with them. A known folder that Windows does not name makes the policy
/// indeterminate (`WindowsProbes::layout`).
struct Layout {
    identity: sandy_core::PathIdentity,
    system: Vec<ProtectedPath>,
    trusted: Vec<ProtectedPath>,
    state: std::path::PathBuf,
}

impl Layout {
    fn read() -> Result<Layout, SandboxError> {
        Ok(Layout {
            identity: sandy_core::PathIdentity::read()
                .map_err(|error| SandboxError::new(error.to_string()))?,
            system: system_directories()?,
            trusted: trusted_locations()?,
            state: state_directory()?,
        })
    }
}

/// Rules 3 and 6 for the policy paths of `policy`: no writable path may overlap a system
/// directory or one of the user's trusted locations in `layout`, and nobody the program's token
/// carries may execute files in a writable path or write files in an executable one
/// (`acl::check_rights`). `container` is the policy's AppContainer. Changes nothing.
///
/// Paths are compared as rules 3 and 4 compare them (`PathIdentity`): by the identity of the
/// directories on the way, so a junction or another spelling of a directory counts as that
/// directory ("Links and identity" in docs/windows.md). An overlap is a conflict of the policy
/// with the layout of this host; one that sandy only assumes because it cannot read the
/// identity of a directory on the way is indeterminate.
fn check_writable_paths(
    layout: Option<&Layout>,
    policy: &ResolvedPolicy,
    container: &Sid,
) -> Result<(), Problem> {
    let held =
        held_sids(policy, container).map_err(|error| Problem::Indeterminate(error.to_string()))?;
    let mut problems = Vec::new();
    // The overlap checks read the layout, so they run only when the policy has a writable path.
    if let Some(Layout {
        identity,
        system,
        trusted,
        state,
    }) = layout
    {
        if let Some((rule, directory)) = policy.known_writable_conflict(system, identity) {
            problems.push(Problem::Conflict(format!(
                "writable path {} overlaps the system directory {}, where Windows lets every \
                 AppContainer read and execute files",
                rule.path.display(),
                directory.path.display()
            )));
        }
        if let Some((rule, location)) = policy.known_writable_conflict(trusted, identity) {
            let why = if location.path == *state {
                "where sandy keeps the state of its runs; the program could let a run with \
                 another policy join its AppContainer, or make every later run wait"
            } else {
                "which programs outside the sandbox read or execute later; a file the program \
                 leaves there runs outside the sandbox"
            };
            problems.push(Problem::Conflict(format!(
                "writable path {} overlaps {}, {why}",
                rule.path.display(),
                location.describe()
            )));
        }
        for protected in [system, trusted] {
            if let Some((rule, location)) = policy.writable_conflict(protected, identity) {
                problems.push(Problem::Indeterminate(format!(
                    "cannot tell whether writable path {} overlaps {}: sandy cannot read the \
                     identity of a directory on the way",
                    rule.path.display(),
                    location.describe()
                )));
            }
        }
    }
    problems.extend(
        policy
            .paths
            .iter()
            .filter_map(|rule| acl::check_rights(rule, &held).err()),
    );
    worst(problems).map_or(Ok(()), Err)
}

/// Whether sandy can give the AppContainer access to every policy path. `run` adds an entry for
/// the path's capability to the path's access control list, which needs the right to change that
/// list, and refuses when it cannot. A path whose list is already right needs no change. Changes
/// nothing.
fn check_grants(appcontainer: &str, policy: &ResolvedPolicy) -> Result<(), Problem> {
    let problems = policy.paths.iter().filter_map(|rule| {
        let problem = acl::grantable(appcontainer, rule).err()?;
        Some(crate::probe::path_grant(problem).map(|reason| {
            format!(
                "cannot give AppContainer {appcontainer:?} access to {}: {reason}",
                rule.path.display()
            )
        }))
    });
    worst(problems.chain(junction_refusals(policy))).map_or(Ok(()), Err)
}

/// Under `windows.junctions = "refuse"`, each junction that the program could open under its
/// name only with an entry of sandy's, which this setting forbids: a conflict of the policy with
/// this host, like a policy path whose permissions sandy may not change.
fn junction_refusals(policy: &ResolvedPolicy) -> Vec<Problem> {
    if policy.windows.junctions != Junctions::Refuse {
        return Vec::new();
    }
    acl::junctions_needing_entries(policy)
        .into_iter()
        .map(|junction| {
            Problem::Conflict(format!(
                "{} is a junction on the way to a directory policy path, and the program could \
                 open that directory under the junction's name only if sandy changed the \
                 junction's permissions, which windows.junctions = \"refuse\" forbids; name the \
                 directory by its own path, or set junctions = \"grant\"",
                junction.display()
            ))
        })
        .collect()
}

/// Where Windows puts a known folder. `KF_FLAG_DONT_VERIFY`, because the default verifies that
/// the folder exists and fails when it does not: an account without a Documents folder would
/// make every policy unenforceable, and a location that does not exist counts anyway, because
/// the program could create it.
fn known_folder(
    id: &windows_sys::core::GUID,
    error: &'static str,
) -> Result<Vec<u16>, SandboxError> {
    let known_folder_path = sh_get_known_folder_path()?;
    let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the folder ID is a valid GUID, a null token selects the current user, and path is
    // a valid out pointer.
    let hresult = unsafe {
        known_folder_path(
            id,
            KF_FLAG_DONT_VERIFY as u32,
            std::ptr::null_mut(),
            &mut path,
        )
    };
    let result = if hresult < 0 {
        Err(util::hresult_error(error, hresult))
    } else {
        // SAFETY: on success path is a NUL-terminated string from the function.
        let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        // SAFETY: path holds `len` units before its NUL.
        Ok(unsafe { std::slice::from_raw_parts(path, len) }.to_vec())
    };
    // SAFETY: the function allocated path with the COM allocator, also on failure, and it is
    // freed exactly once; CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

type ShGetKnownFolderPath = unsafe extern "system" fn(
    *const windows_sys::core::GUID,
    u32,
    windows_sys::Win32::Foundation::HANDLE,
    *mut windows_sys::core::PWSTR,
) -> windows_sys::core::HRESULT;

/// `SHGetKnownFolderPath`, loaded at run time (`util::system_function`): shell32.dll must not be
/// imported at load time.
fn sh_get_known_folder_path() -> Result<ShGetKnownFolderPath, SandboxError> {
    let address = util::system_function("shell32.dll", c"SHGetKnownFolderPath")?;
    // SAFETY: the export has the documented signature of SHGetKnownFolderPath.
    Ok(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, ShGetKnownFolderPath>(address)
    })
}

fn network_capability_sid(capability: NetworkCapability) -> Result<Sid, SandboxError> {
    let kind: WELL_KNOWN_SID_TYPE = match capability {
        NetworkCapability::InternetClient => WinCapabilityInternetClientSid,
        NetworkCapability::InternetClientServer => WinCapabilityInternetClientServerSid,
        NetworkCapability::PrivateNetworkClientServer => WinCapabilityPrivateNetworkClientServerSid,
    };
    Sid::well_known(kind).map_err(|error| {
        SandboxError::io(
            format!("cannot create the {capability:?} capability SID"),
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    use sandy_core::ProtectedPath;

    use std::ffi::OsString;

    use super::{
        FOLDERID_ProgramData, FOLDERID_RoamingAppData, drives, known_and_named, known_folder,
        relay_ended_first, relay_serves, tool_homes, trusted_locations, user_profiles,
        windows_directory,
    };
    use crate::{access, probe};
    use windows_sys::Win32::Foundation as f;
    use windows_sys::Win32::Security as ss;
    use windows_sys::Win32::Storage::FileSystem as fs;

    /// `refuse`, which the command line calls for `check` and before `run`, refuses a batch
    /// file. Nothing of the host is touched before.
    #[test]
    fn refuse_names_a_batch_file() {
        use sandy_core::{Backend, Policy, ResolvedPolicy};

        let mut policy = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        policy.program = Some(std::path::PathBuf::from("C:\\nowhere\\run.cmd"));
        let error = super::WindowsBackend::new()
            .refuse(&policy, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("batch files run in cmd.exe"), "{error}");
    }

    #[test]
    fn the_relay_names_the_ports_it_serves() {
        assert_eq!(relay_serves(0, 0, true), "the egress port");
        assert_eq!(relay_serves(1, 0, false), "the exposed port");
        assert_eq!(
            relay_serves(2, 1, false),
            "the exposed ports and the forwarded port"
        );
        assert_eq!(
            relay_serves(1, 3, true),
            "the exposed port, the forwarded ports and the egress port"
        );
        assert_eq!(
            relay_ended_first(0, 0, true),
            "the relay of the egress port ended before the program; the port it served is gone \
             and the program has been ended with it"
        );
        assert!(relay_ended_first(2, 0, false).contains("; the ports it served are gone "));
    }

    /// The configuration of git and GnuPG is protected below the profile as it is below the
    /// home directory on Linux and macOS, and Gpg4win's GnuPG folder with it.
    #[test]
    fn trusted_locations_cover_git_and_gnupg() {
        let locations = trusted_locations().unwrap();
        let profile = user_profiles(&drives().unwrap()).unwrap().remove(0);
        let known = |id, error| {
            PathBuf::from(std::ffi::OsString::from_wide(
                &known_folder(id, error).unwrap(),
            ))
        };
        let roaming = known(&FOLDERID_RoamingAppData, "no roaming folder");
        let program_data = known(&FOLDERID_ProgramData, "no program data folder");
        for expected in [
            ProtectedPath::entry(profile.join(".gitconfig")),
            ProtectedPath::tree(profile.join(".config").join("git")),
            ProtectedPath::tree(profile.join(".gnupg")),
            ProtectedPath::tree(profile.join(".ssh")),
            ProtectedPath::entry(profile.join(".cargo").join("config.toml")),
            ProtectedPath::tree(roaming.join("gnupg")),
            ProtectedPath::tree(program_data.join("Git")),
        ] {
            assert!(locations.contains(&expected), "{expected:?}: {locations:?}");
        }
        assert!(
            locations
                .iter()
                .position(|l| *l == ProtectedPath::entry(&profile))
                > locations
                    .iter()
                    .position(|l| *l == ProtectedPath::tree(profile.join(".gnupg")))
        );
    }

    /// A named home adds a home directory for the tools when it is absolute, on each drive when
    /// it has a root but no drive, never when it is relative, and each once.
    #[test]
    fn tool_homes_add_the_named_homes() {
        let profile = PathBuf::from(r"C:\Users\someone");
        let moved = PathBuf::from(r"D:\home");
        let profiles = std::slice::from_ref(&profile);
        let drives = [PathBuf::from(r"C:\"), PathBuf::from(r"E:\")];
        let homes = |named: &[&str]| {
            let named: Vec<OsString> = named.iter().map(OsString::from).collect();
            tool_homes(profiles, &named, &drives)
        };
        assert_eq!(homes(&[]), vec![profile.clone()]);
        assert_eq!(homes(&["relative", r"C:relative"]), vec![profile.clone()]);
        assert_eq!(homes(&[r"C:\Users\someone"]), vec![profile.clone()]);
        assert_eq!(
            homes(&[r"D:\home", r"D:\home"]),
            vec![profile.clone(), moved.clone()]
        );
        assert_eq!(
            homes(&[r"\Users\someone", r"D:\home"]),
            vec![profile.clone(), moved, PathBuf::from(r"E:\Users\someone")]
        );
        assert_eq!(
            homes(&[r"\\server\share\home"]),
            vec![PathBuf::from(r"\\server\share\home"), profile]
        );
    }

    /// USERPROFILE and PROGRAMDATA, like the tool homes, name a place with a drive directly and
    /// one rooted without a drive on each drive; a relative value is left out.
    #[test]
    fn known_and_named_expands_a_rooted_variable() {
        let known = PathBuf::from(r"C:\Users\someone");
        let drives = [PathBuf::from(r"C:\"), PathBuf::from(r"D:\")];
        let folders = |named: &str| known_and_named(known.clone(), Some(named.into()), &drives);
        assert_eq!(
            known_and_named(known.clone(), None, &drives),
            vec![known.clone()]
        );
        assert_eq!(folders("relative"), vec![known.clone()]);
        assert_eq!(
            folders(r"E:\profiles\x"),
            vec![known.clone(), PathBuf::from(r"E:\profiles\x")]
        );
        assert_eq!(
            folders(r"\profiles\x"),
            vec![
                PathBuf::from(r"C:\Users\someone"),
                PathBuf::from(r"C:\profiles\x"),
                PathBuf::from(r"D:\profiles\x"),
            ]
        );
    }

    /// The drives are drive roots, the system drive among them.
    #[test]
    fn drives_hold_the_system_drive() {
        let drives = drives().unwrap();
        let windows = PathBuf::from(std::ffi::OsString::from_wide(&windows_directory().unwrap()));
        assert!(
            drives.iter().any(|drive| windows.starts_with(drive)),
            "{drives:?}"
        );
        for drive in &drives {
            assert_eq!(drive.parent(), None, "{drive:?}");
        }
    }

    #[test]
    fn probe_constants_match_windows_sys() {
        use windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT;
        use windows_sys::Win32::System::Services as sv;
        assert_eq!(probe::ERROR_ACCESS_DENIED as u32, f::ERROR_ACCESS_DENIED);
        assert_eq!(probe::WSAEAFNOSUPPORT, WSAEAFNOSUPPORT);
        assert_eq!(probe::SERVICE_STOPPED, sv::SERVICE_STOPPED);
        assert_eq!(probe::SERVICE_START_PENDING, sv::SERVICE_START_PENDING);
        assert_eq!(probe::SERVICE_STOP_PENDING, sv::SERVICE_STOP_PENDING);
        assert_eq!(probe::SERVICE_RUNNING, sv::SERVICE_RUNNING);
    }

    #[test]
    fn access_constants_match_windows_sys() {
        assert_eq!(access::FILE_READ_DATA, fs::FILE_READ_DATA);
        assert_eq!(access::FILE_WRITE_DATA, fs::FILE_WRITE_DATA);
        assert_eq!(access::FILE_APPEND_DATA, fs::FILE_APPEND_DATA);
        assert_eq!(access::FILE_READ_EA, fs::FILE_READ_EA);
        assert_eq!(access::FILE_WRITE_EA, fs::FILE_WRITE_EA);
        assert_eq!(access::FILE_EXECUTE, fs::FILE_EXECUTE);
        assert_eq!(access::FILE_DELETE_CHILD, fs::FILE_DELETE_CHILD);
        assert_eq!(access::FILE_READ_ATTRIBUTES, fs::FILE_READ_ATTRIBUTES);
        assert_eq!(access::FILE_WRITE_ATTRIBUTES, fs::FILE_WRITE_ATTRIBUTES);
        assert_eq!(access::DELETE, fs::DELETE);
        assert_eq!(access::READ_CONTROL, fs::READ_CONTROL);
        assert_eq!(access::WRITE_DAC, fs::WRITE_DAC);
        assert_eq!(access::WRITE_OWNER, fs::WRITE_OWNER);
        assert_eq!(access::SYNCHRONIZE, fs::SYNCHRONIZE);
        assert_eq!(access::GENERIC_READ, f::GENERIC_READ);
        assert_eq!(access::GENERIC_WRITE, f::GENERIC_WRITE);
        assert_eq!(access::GENERIC_EXECUTE, f::GENERIC_EXECUTE);
        assert_eq!(access::GENERIC_ALL, f::GENERIC_ALL);
        assert_eq!(access::FILE_GENERIC_READ, fs::FILE_GENERIC_READ);
        assert_eq!(access::FILE_GENERIC_WRITE, fs::FILE_GENERIC_WRITE);
        assert_eq!(access::FILE_GENERIC_EXECUTE, fs::FILE_GENERIC_EXECUTE);
        assert_eq!(access::FILE_ALL_ACCESS, fs::FILE_ALL_ACCESS);
        assert_eq!(
            u32::from(access::OBJECT_INHERIT_ACE),
            ss::OBJECT_INHERIT_ACE
        );
        assert_eq!(
            u32::from(access::CONTAINER_INHERIT_ACE),
            ss::CONTAINER_INHERIT_ACE
        );
        assert_eq!(
            u32::from(access::NO_PROPAGATE_INHERIT_ACE),
            ss::NO_PROPAGATE_INHERIT_ACE
        );
        assert_eq!(u32::from(access::INHERIT_ONLY_ACE), ss::INHERIT_ONLY_ACE);
        assert_eq!(u32::from(access::INHERITED_ACE), ss::INHERITED_ACE);
    }
}
