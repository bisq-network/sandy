//! `setup --elevate` on Windows: setup with administrator rights, asked for with the "runas"
//! verb of `ShellExecuteExW`, which shows the UAC prompt. Administrator rights never run a file
//! that someone else can change, so sandy asks only when no one but administrators can change
//! its own file (`acl::administrators_only`). The elevated sandy gets a console of its own, so
//! its messages do not reach the caller; its exit status does.

use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr;

use sandy_core::{SandboxError, SetupOutcome};
use windows_sys::Win32::Foundation::{ERROR_CANCELLED, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::core::{BOOL, HRESULT};

use super::acl;
use super::util::{last_error, system_function, wide, wide_nul, win32_error};
use crate::cmdline::parameters;

/// `SW_HIDE`: the elevated sandy's console stays out of sight.
const HIDE: i32 = 0;

type ShellExecuteExW = unsafe extern "system" fn(*mut SHELLEXECUTEINFOW) -> BOOL;
type CoInitializeEx = unsafe extern "system" fn(*const core::ffi::c_void, u32) -> HRESULT;

/// What every refusal of `--elevate` ends with, so a caller knows what to do instead.
const FALLBACK: &str = "nothing changed; until setup is done, run policies that need no setup \
    on this host";

/// The refusal of `command` in a process without administrator rights, with status 3 as on
/// Linux. Whether a step would change anything shows only once it is tried, so it refuses also
/// where nothing would change: the status then means the same on every host.
pub fn needs_rights(command: &str) -> SetupOutcome {
    SetupOutcome::Refused(format!(
        "{command} needs administrator rights; `sandy {command} --elevate` asks for them with \
         the UAC prompt, or run it from an elevated prompt; {FALLBACK}"
    ))
}

/// Whether this process runs with administrator rights that UAC does not hold back.
pub fn is_elevated() -> Result<bool, SandboxError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo handle of this process needs no closing; token is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("cannot open this process's token"));
    }
    // SAFETY: OpenProcessToken returned a handle that nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0;
    // SAFETY: elevation is a writable TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            std::os::windows::io::AsRawHandle::as_raw_handle(&token),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    if ok == 0 {
        return Err(last_error("cannot read whether this process is elevated"));
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// Runs this sandy again with `args` and administrator rights, after the user agreed at the UAC
/// prompt, and waits for it.
pub fn run_elevated(args: &[OsString]) -> Result<SetupOutcome, SandboxError> {
    let own = std::env::current_exe()
        .map_err(|error| SandboxError::io("cannot find the file of this sandy", error))?;
    if let Err(reason) = acl::administrators_only(&own) {
        return Ok(SetupOutcome::Refused(format!(
            "--elevate runs sandy with administrator rights only from a file that only \
             administrators can change, and {reason}; install sandy where only administrators \
             can write, such as below Program Files, or run setup from an elevated prompt; \
             {FALLBACK}"
        )));
    }
    let arguments: Vec<Vec<u16>> = args.iter().map(|arg| wide(arg)).collect();
    let parameters = parameters(&arguments)
        .map_err(|error| SandboxError::new(format!("invalid arguments: {error}")))?;
    let program = wide_nul(own.as_os_str());
    let directory = std::env::current_dir()
        .map_err(|error| SandboxError::io("cannot read the current directory", error))?;
    let directory = wide_nul(directory.as_os_str());
    let verb = wide_nul("runas".as_ref());
    // Both libraries load user32.dll, so they are loaded only here (`system_function`).
    // SAFETY: the exports have the documented signatures.
    let (shell_execute, co_initialize) = unsafe {
        (
            std::mem::transmute::<unsafe extern "system" fn() -> isize, ShellExecuteExW>(
                system_function("shell32.dll", c"ShellExecuteExW")?,
            ),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, CoInitializeEx>(
                system_function("ole32.dll", c"CoInitializeEx")?,
            ),
        )
    };
    // ShellExecuteExW may hand the request to shell extensions, which expect COM. A second
    // initialization on this thread only reports that COM is there already.
    // SAFETY: no reserved pointer; the flags are valid.
    unsafe {
        co_initialize(
            ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    // SAFETY: SHELLEXECUTEINFOW is plain data; all zeros means no optional field is set.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = program.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.lpDirectory = directory.as_ptr();
    info.nShow = HIDE;
    // SAFETY: info is initialized, and every string it points to is NUL-terminated and lives
    // until the call returns.
    if unsafe { shell_execute(&mut info) } == 0 {
        // SAFETY: GetLastError has no preconditions.
        let error = unsafe { GetLastError() };
        let reason = if error == ERROR_CANCELLED {
            "the UAC prompt was dismissed".to_string()
        } else {
            format!(
                "Windows did not start sandy with administrator rights ({})",
                std::io::Error::from_raw_os_error(error as i32)
            )
        };
        return Ok(SetupOutcome::Refused(format!(
            "{reason}; {FALLBACK}; run the same command from an elevated prompt instead"
        )));
    }
    if info.hProcess.is_null() {
        return Err(SandboxError::new(
            "Windows started sandy with administrator rights but gave no handle to wait for",
        ));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS gives the caller the process handle to close.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let handle = std::os::windows::io::AsRawHandle::as_raw_handle(&process);
    // SAFETY: handle is the process handle above.
    if unsafe { WaitForSingleObject(handle, INFINITE) } != WAIT_OBJECT_0 {
        return Err(last_error("cannot wait for the elevated sandy"));
    }
    let mut code = 0u32;
    // SAFETY: handle is the process handle above and code a writable u32.
    if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
        return Err(win32_error(
            "cannot read the exit status of the elevated sandy",
            // SAFETY: GetLastError has no preconditions.
            unsafe { GetLastError() },
        ));
    }
    match code {
        0 => Ok(SetupOutcome::Done(String::new())),
        // Its console closed with it, so only the status arrives here.
        3 => Ok(SetupOutcome::Refused(format!(
            "the elevated sandy did not do it (status 3); {FALLBACK}; run the same command from              an elevated prompt to see why"
        ))),
        code => Err(SandboxError::new(format!(
            "the elevated sandy ended with status {code}; run the same command from an elevated              prompt to see why"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use windows_sys::Win32::Security::{
        WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinLocalSystemSid,
    };

    use super::*;
    use crate::access;
    use crate::sys::util::Sid;

    #[test]
    fn the_administrative_sids_are_the_well_known_ones() {
        for (bytes, kind) in [
            (access::LOCAL_SYSTEM, WinLocalSystemSid),
            (access::ADMINISTRATORS, WinBuiltinAdministratorsSid),
            (access::OWNER_RIGHTS, WinCreatorOwnerRightsSid),
        ] {
            assert_eq!(Sid::well_known(kind).unwrap().bytes(), bytes);
        }
    }

    /// TrustedInstaller owns the programs of Windows, and only administrators can change them
    /// and the directories above; the user that runs the tests owns a file it writes.
    #[test]
    fn only_administrators_can_change_the_programs_of_windows() {
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap();
        acl::administrators_only(&root.join(r"System32\cmd.exe")).unwrap();
        let file = std::env::temp_dir().join(format!("sandy-elevate-{}.exe", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let refused = acl::administrators_only(&file);
        std::fs::remove_file(&file).unwrap();
        let reason = refused.unwrap_err();
        assert!(reason.contains("can change"), "{reason}");
        assert!(is_elevated().is_ok());
    }
}
