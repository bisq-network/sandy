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

use sandy_core::{
    Backend, ChildProcesses, PlanItem, ProtectedPath, Requirement, ResolvedPolicy, SandboxError,
    SetupOptions, SetupOutcome, Status, StatusReport, TargetCommand, Win32k, path_directories,
};
use windows_sys::Win32::Security::{
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Profile,
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_Startup, KF_FLAG_DONT_VERIFY,
};

use crate::cmdline::{command_line, is_batch_file, without_verbatim_prefix};
use crate::envblock::{LOCAL_APP_DATA, SYSTEM_ROOT, environment_block};
use crate::name::validate_appcontainer_name;
use crate::plan::{
    HostCapabilities, NetworkCapability, loopback_exemption, network_capabilities, plan_for,
};
use util::{Sid, wide, wide_nul};

pub use host_network::WindowsHost;

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsBackend;

impl Backend for WindowsBackend {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan_for(policy, &detect(policy))
    }

    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let mut items = sandy_core::verify::relay_listeners(policy);
        if let Err(reason) = host::job_nests() {
            items.extend(crate::plan::job_unavailable(policy, &reason));
        }
        if policy.windows.win32k == Win32k::Deny
            && let Err(reason) = host::win32k_lockdown()
        {
            items.push(PlanItem::unavailable(Requirement::Win32kDenied, reason));
        }
        items
    }

    /// What makes the program behave differently inside the sandbox than outside, beyond the
    /// requirements: the networks `ip = "client"` cannot reach (`plan::notes`) and a directory on
    /// sandy's PATH inside a writable path (rule 12). Before them come the shortfalls of the
    /// policy (`plan::shortfalls`).
    fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        let mut notes = crate::plan::shortfalls(policy);
        notes.extend(crate::plan::notes(policy));
        notes.extend(policy.path_directory_notes(&path_locations()));
        notes
    }

    fn run(
        &self,
        policy: &ResolvedPolicy,
        command: &TargetCommand,
        status: &StatusReport,
    ) -> Result<i32, SandboxError> {
        // The caller checked the plan, but the host may have changed since. Every mechanism
        // below is one the plan named.
        if let Some(item) = self.plan(policy).into_iter().find(|i| !i.is_enforced()) {
            let reason = match item.status {
                Status::Unavailable { reason } | Status::NeedsSetup { reason } => reason,
                Status::Enforced { .. } => unreachable!(),
            };
            return Err(SandboxError::new(format!(
                "{}: {reason}",
                item.requirement.description()
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
        if is_batch_file(&command.program) {
            return Err(SandboxError::new(
                "batch files run in cmd.exe with other argument rules; run cmd.exe /c explicitly",
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

        // The egress broker runs in a sandbox of its own, so prepare it before the relays that
        // name the AppContainer they belong to. Its container and capabilities outlive the run.
        let broker = match policy.egress {
            None => None,
            Some(egress) => Some(EgressBroker::prepare(name, egress, &held)?),
        };

        // The relays run sandy's own executable with one capability: read and execute access to
        // that file. The same capability opens the sockets of forwarded ports, which the egress
        // broker also reaches, so it is needed for `egress` too.
        let relay_capability =
            if policy.expose.is_empty() && policy.forward.is_empty() && policy.egress.is_none() {
                None
            } else {
                let rule = relay::relay_program(name).map_err(SandboxError::new)?;
                Some((acl::grant(name, &rule, &held)?, rule.path))
            };
        let mut relays = Vec::new();
        let mut forwarding = None;
        if let Some((capability, sandy)) = &relay_capability {
            let capability = std::slice::from_ref(capability);
            for (listener, target) in relay::listen(&policy.expose)? {
                let args = [
                    wide(relay::RELAY_COMMAND.as_ref()),
                    wide(listener.as_raw_socket().to_string().as_ref()),
                    wide(target.to_string().as_ref()),
                ];
                relays.push(process::Relay {
                    process: process_for(
                        sandy.as_os_str(),
                        sandy.as_os_str(),
                        &args,
                        &[],
                        None,
                        capability,
                    )?,
                    appcontainer: &container,
                    socket: Some(Box::new(listener)),
                    reports_ready: false,
                });
            }
            // The egress broker reaches the program through a forward relay like any other, whose
            // target is the broker's AF_UNIX socket instead of a loopback service.
            let egress_listen = policy.egress.map(|egress| egress.listen());
            if !policy.forward.is_empty() || egress_listen.is_some() {
                let (started, routes, egress_listener) =
                    forward::Forwarding::start(&policy.forward, egress_listen, &capability[0])?;
                forwarding = Some(started);
                for route in routes {
                    let args = [
                        wide(relay::FORWARD_COMMAND.as_ref()),
                        wide(route.listen.to_string().as_ref()),
                        wide(route.socket.as_os_str()),
                    ];
                    relays.push(process::Relay {
                        process: process_for(
                            sandy.as_os_str(),
                            sandy.as_os_str(),
                            &args,
                            &[],
                            None,
                            capability,
                        )?,
                        appcontainer: &container,
                        socket: None,
                        reports_ready: true,
                    });
                }
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
                        socket: Some(Box::new(listener)),
                        reports_ready: false,
                    });
                }
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
        // The broker's AppContainer profile is this run's alone; its folder holds no user data.
        if let Some(broker) = &broker {
            let _ = appcontainer::delete_profile(&broker.name);
        }
        Ok(ended.code)
    }

    /// Makes the loopback exemption of the policy's AppContainer match the policy: present with
    /// `ip = "client"` and `ip = "all"`, absent with `ip = "none"` and `ip = "private"`
    /// (`plan::loopback_exemption`). With exposed or forwarded ports, also lets the relays run
    /// sandy's executable, which a user without the right to change its permissions cannot do at
    /// run time. Needs administrator rights when it changes something.
    fn setup(
        &self,
        policy: &ResolvedPolicy,
        _options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
            SandboxError::new("the policy names no AppContainer; pass --appcontainer NAME")
        })?;
        validate_appcontainer_name(name).map_err(SandboxError::new)?;
        let container = appcontainer::sid(name)?;
        let exempt = loopback_exemption(policy.ip);
        network::set_loopback_exempt(&container, exempt)?;
        let mut done = format!(
            "the AppContainer {name} is {} the loopback exemption",
            if exempt { "in" } else { "not in" }
        );
        if !policy.expose.is_empty() || !policy.forward.is_empty() || policy.egress.is_some() {
            // The relay rule is read and execute, so no writable-path check reads `held`.
            let rule = relay::relay_rule().map_err(SandboxError::new)?;
            acl::grant(name, &rule, &[])?;
            done.push_str(", and its relays may run sandy.exe");
            // The egress broker runs sandy's executable from an AppContainer of its own.
            if policy.egress.is_some() {
                let broker = crate::name::egress_broker_name(name).map_err(SandboxError::new)?;
                acl::grant(&broker, &rule, &[])?;
                done.push_str(", and so may its egress broker");
            }
        }
        Ok(SetupOutcome::Done(done))
    }

    /// Takes back what `setup` and the runs of this policy left behind: the loopback exemption,
    /// the access control entry of every policy path and of sandy's own executable, and the
    /// AppContainer profile with its folder. Only entries for the capability SIDs sandy derives
    /// for this AppContainer are removed; other software uses capability SIDs too.
    ///
    /// Entries on objects that have left the policy stay, because nothing says where they are.
    /// Needs administrator rights only where it changes the loopback exemption.
    fn remove(
        &self,
        policy: &ResolvedPolicy,
        _options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
            SandboxError::new("the policy names no AppContainer; pass --appcontainer NAME")
        })?;
        validate_appcontainer_name(name).map_err(SandboxError::new)?;
        let container = appcontainer::sid(name)?;
        // A run of this AppContainer would lose its access in the middle.
        let _idle = singleton::hold_idle(&container)?;
        network::set_loopback_exempt(&container, false)?;
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
        Ok(SetupOutcome::Done(format!(
            "removed what sandy left for the AppContainer {name}"
        )))
    }

    /// With administrator rights already, setup runs here; otherwise sandy runs again after the
    /// UAC prompt (`elevate`).
    fn elevate(
        &self,
        policy: &ResolvedPolicy,
        remove: bool,
        options: SetupOptions,
        args: &[OsString],
    ) -> Result<SetupOutcome, SandboxError> {
        if elevate::is_elevated()? {
            return if remove {
                self.remove(policy, options)
            } else {
                self.setup(policy, options)
            };
        }
        elevate::run_elevated(args)
    }
}

/// The egress broker's sandbox: its own AppContainer with the internetClient capability (and
/// privateNetworkClientServer for `reach = "public-and-local"`) and read and execute access to
/// sandy's executable. Its loopback isolation stops it from reaching this machine at the kernel
/// level, and `sandy_core::destination` keeps it to the destinations `reach` allows.
struct EgressBroker {
    name: String,
    container: Sid,
    capabilities: Vec<Sid>,
}

impl EgressBroker {
    fn prepare(
        program_name: &str,
        egress: sandy_core::Egress,
        held: &[Sid],
    ) -> Result<EgressBroker, SandboxError> {
        let name = crate::name::egress_broker_name(program_name).map_err(SandboxError::new)?;
        let container = appcontainer::ensure_profile(&name)?;
        // The broker can write its profile folder (its TEMP) but must not execute what it writes.
        acl::deny_execute_in_profile(&container, &profile_folder(&container)?)?;
        let rule = relay::relay_program(&name).map_err(SandboxError::new)?;
        let mut capabilities = vec![acl::grant(&name, &rule, held)?];
        for capability in crate::plan::broker_network_capabilities(egress.reach) {
            capabilities.push(network_capability_sid(*capability)?);
        }
        Ok(EgressBroker {
            name,
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

/// Reads the host state the plan depends on. Changes nothing.
fn detect(policy: &ResolvedPolicy) -> HostCapabilities {
    let container = policy
        .windows
        .appcontainer_name
        .as_deref()
        .ok_or_else(|| "no AppContainer name".to_string())
        .and_then(|name| appcontainer::sid(name).map_err(|error| error.to_string()));
    HostCapabilities {
        appcontainer: container.as_ref().map(|_| ()).map_err(Clone::clone),
        windows: host::windows_version(),
        capability_sids: host::derive_capability_sids().map(|_| ()),
        writable_paths: check_writable_paths(policy),
        // Only `FilesystemConfined` reads this, and only with an AppContainer name.
        grants: match policy.windows.appcontainer_name.as_deref() {
            Some(name) => check_grants(name, policy),
            None => Ok(()),
        },
        outer_job_ui: host::outer_job_ui(),
        firewall: network::firewall_running(),
        loopback_exempt: container.and_then(|sid| network::is_loopback_exempt(&sid)),
        // The relay requirements and the egress broker read these; the broker runs sandy's
        // executable too, and reaches the program over an AF_UNIX socket like a forwarded port.
        relay_program: match policy.windows.appcontainer_name.as_deref() {
            Some(name)
                if !policy.expose.is_empty()
                    || !policy.forward.is_empty()
                    || policy.egress.is_some() =>
            {
                relay::relay_program(name).map(|rule| rule.path)
            }
            _ => Err("no relay is needed".into()),
        },
        forward_sockets: if policy.forward.is_empty() && policy.egress.is_none() {
            Err("no forwarded port".into())
        } else {
            forward::check()
        },
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
/// AppContainer and its network capabilities. `acl::check_writable` says why the grant
/// capabilities are not among them.
fn held_sids(policy: &ResolvedPolicy, container: &Sid) -> Result<Vec<Sid>, SandboxError> {
    let mut held = vec![container.clone()];
    for capability in network_capabilities(policy.ip) {
        held.push(network_capability_sid(*capability)?);
    }
    Ok(held)
}

/// Locations of this user that programs outside the sandbox read or execute later: the folders
/// Windows runs programs from at logon, the PowerShell profile folders, the app execution
/// aliases, the SSH configuration, cargo's configuration (shared with the Unix backends,
/// `sandy_core::trust::cargo_configs`) and sandy's own state. A writable path that reaches one of
/// them lets the program leave a file there that runs outside the sandbox at the next logon or
/// the next build, and a file the program creates keeps the user's own rights on it, including
/// the right to execute it (see "Trusted user locations" in docs/windows.md). Such a path is
/// refused; the directories on sandy's PATH only warn (`path_locations`).
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
    let profiles = user_profiles()?;
    locations.extend(sandy_core::trust::cargo_configs(&profiles));
    for profile in profiles {
        locations.push(ProtectedPath::tree(profile.join(".ssh")));
        // After the folders in it, so that a writable profile is reported with the folder that
        // makes it dangerous.
        locations.push(ProtectedPath::entry(profile));
    }
    Ok(locations)
}

/// The directories on sandy's PATH, which only warn. A program the sandboxed one leaves in one
/// of them runs outside the sandbox when the user next types its name, but a writable path that
/// holds such a directory is ordinary work, a package cache whose `bin` folder is on PATH for
/// example, so refusing it would turn away the common case (rule 12).
fn path_locations() -> Vec<ProtectedPath> {
    path_directories(std::env::var_os("PATH").as_deref())
}

/// The profile folder of this user, from the known folder and from USERPROFILE. The known
/// folder, because a service that starts sandy with a minimal environment sets no USERPROFILE;
/// the variable as well, because a user who moves their profile with it keeps their files there.
fn user_profiles() -> Result<Vec<std::path::PathBuf>, SandboxError> {
    let known = std::path::PathBuf::from(OsString::from_wide(&known_folder(
        &FOLDERID_Profile,
        "cannot find the user profile folder",
    )?));
    let named = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute());
    let mut profiles: Vec<std::path::PathBuf> = std::iter::once(known).chain(named).collect();
    profiles.sort();
    profiles.dedup();
    Ok(profiles)
}

/// Rules 3 and 6 for the writable paths of `policy`: none may overlap a system directory or one
/// of the user's trusted locations, and nobody the program's token carries may execute files in
/// one. Changes nothing.
///
/// Paths are compared as rules 3 and 4 compare them (`PathIdentity`): by the identity of the
/// directories on the way, so a junction or another spelling of a directory counts as that
/// directory ("Links and identity" in docs/windows.md).
fn check_writable_paths(policy: &ResolvedPolicy) -> Result<(), String> {
    let identity = sandy_core::PathIdentity::read().map_err(|error| error.to_string())?;
    let system = system_directories().map_err(|error| error.to_string())?;
    if let Some((rule, directory)) = policy.writable_conflict(&system, &identity) {
        return Err(format!(
            "writable path {} overlaps the system directory {}, where Windows lets every \
             AppContainer read and execute files",
            rule.path.display(),
            directory.path.display()
        ));
    }
    let trusted = trusted_locations().map_err(|error| error.to_string())?;
    if let Some((rule, location)) = policy.writable_conflict(&trusted, &identity) {
        let state = state_directory().map_err(|error| error.to_string())?;
        let why = if location.path == state {
            "where sandy keeps the state of its runs; the program could let a run with another \
             policy join its AppContainer, or make every later run wait"
        } else {
            "which programs outside the sandbox read or execute later; a file the program leaves \
             there runs outside the sandbox"
        };
        return Err(format!(
            "writable path {} overlaps {}, {why}",
            rule.path.display(),
            location.path.display()
        ));
    }
    let held = match policy.windows.appcontainer_name.as_deref() {
        Some(name) => {
            let container = appcontainer::sid(name).map_err(|error| error.to_string())?;
            held_sids(policy, &container).map_err(|error| error.to_string())?
        }
        None => Vec::new(),
    };
    let writable = policy
        .paths
        .iter()
        .filter(|rule| rule.access == sandy_core::PathAccess::ReadWrite);
    for rule in writable {
        acl::check_writable(rule, &held)?;
    }
    Ok(())
}

/// Whether sandy can give the AppContainer access to every policy path. `run` adds an entry for
/// the path's capability to the path's access control list, which needs the right to change that
/// list, and refuses when it cannot. A path whose list is already right needs no change. Changes
/// nothing.
fn check_grants(appcontainer: &str, policy: &ResolvedPolicy) -> Result<(), String> {
    for rule in &policy.paths {
        acl::grantable(appcontainer, rule).map_err(|reason| {
            format!(
                "cannot give AppContainer {appcontainer:?} access to {}: {reason}",
                rule.path.display()
            )
        })?;
    }
    Ok(())
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
    use crate::access;
    use windows_sys::Win32::Foundation as f;
    use windows_sys::Win32::Security as ss;
    use windows_sys::Win32::Storage::FileSystem as fs;

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
