mod acl;
mod appcontainer;
mod network;
mod process;
mod util;

use std::ffi::OsString;

use sandy_core::{
    Backend, NetworkAccess, PlanItem, ResolvedPolicy, SandboxError, Status, TargetCommand,
};
use windows_sys::Win32::Security::{
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

use crate::cmdline::{command_line, is_batch_file, without_verbatim_prefix};
use crate::envblock::{LOCAL_APP_DATA, SYSTEM_ROOT, environment_block};
use crate::name::validate_appcontainer_name;
use crate::plan::{HostCapabilities, NetworkCapability, network_capabilities, plan_for};
use util::{Sid, wide, wide_nul};

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsBackend;

impl Backend for WindowsBackend {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan_for(policy, &detect(policy))
    }

    fn run(&self, policy: &ResolvedPolicy, command: &TargetCommand) -> Result<i32, SandboxError> {
        // The caller checked the plan, but the host may have changed since. Every mechanism
        // below is one the plan named.
        if let Some(item) = self.plan(policy).into_iter().find(|i| !i.is_enforced()) {
            let reason = match item.status {
                Status::Unavailable { reason } => reason,
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

        let container = appcontainer::ensure_profile(name)?;
        let mut capabilities = Vec::new();
        for capability in network_capabilities(policy.ip) {
            capabilities.push(network_capability_sid(*capability)?);
        }
        for rule in &policy.paths {
            capabilities.push(acl::grant(name, rule)?);
        }

        let program = wide(command.program.as_os_str());
        let program = without_verbatim_prefix(&program);
        let args: Vec<Vec<u16>> = command.args.iter().map(|arg| wide(arg)).collect();
        let command_line = command_line(program, &args)
            .map_err(|error| SandboxError::new(format!("invalid command line: {error}")))?;
        let mut application = program.to_vec();
        application.push(0);

        process::run(process::Launch {
            application,
            command_line,
            environment: environment(&command.env)?,
            cwd: command.cwd.as_ref().map(|cwd| wide_nul(cwd.as_os_str())),
            appcontainer: &container,
            capabilities: &capabilities,
        })
    }

    /// Makes the loopback exemption of the policy's AppContainer match the policy: present with
    /// `ip = "all"`, absent otherwise. Needs administrator rights when it changes something.
    fn setup(&self, policy: &ResolvedPolicy) -> Result<(), SandboxError> {
        let name = policy.windows.appcontainer_name.as_deref().ok_or_else(|| {
            SandboxError::new("the policy names no AppContainer; pass --appcontainer NAME")
        })?;
        validate_appcontainer_name(name).map_err(SandboxError::new)?;
        let container = appcontainer::sid(name)?;
        network::set_loopback_exempt(&container, policy.ip == NetworkAccess::All)
    }
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
        firewall: network::firewall_running(),
        loopback_exempt: container.and_then(|sid| network::is_loopback_exempt(&sid)),
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

fn local_app_data() -> Result<Vec<u16>, SandboxError> {
    let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the folder ID is a valid GUID, a null token selects the current user, and path is
    // a valid out pointer.
    let hresult = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut path,
        )
    };
    let result = if hresult < 0 {
        Err(util::hresult_error(
            "cannot find the local application data folder",
            hresult,
        ))
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

fn network_capability_sid(capability: NetworkCapability) -> Result<Sid, SandboxError> {
    let kind: WELL_KNOWN_SID_TYPE = match capability {
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
