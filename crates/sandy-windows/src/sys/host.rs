//! Host facts the plan depends on: the Windows version, the job sandy runs in, and the
//! `DeriveCapabilitySidsFromName` export.

use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JobObjectBasicUIRestrictions, QueryInformationJobObject, SetInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, GetCurrentProcess, PROCESS_INFORMATION,
    STARTUPINFOW, TerminateProcess,
};
use windows_sys::core::{BOOL, PCWSTR};

use super::util::wide_nul;
use crate::version::WindowsVersion;

/// The real build number. `GetVersionExW` reports Windows 8 to programs without a
/// compatibility manifest; `RtlGetVersion` does not.
pub fn windows_version() -> Result<WindowsVersion, String> {
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut info: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;
    // SAFETY: info is a writable OSVERSIONINFOW with its size set.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status < 0 {
        return Err(format!("RtlGetVersion failed with {status:#x}"));
    }
    Ok(WindowsVersion {
        build: info.dwBuildNumber,
        revision: update_revision(),
    })
}

/// The update build revision (UBR) that cumulative updates raise. Windows documents no API for
/// it; the registry value is what `winver` shows.
fn update_revision() -> Option<u32> {
    let key = wide_nul(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion".as_ref());
    let name = wide_nul("UBR".as_ref());
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: key and name are NUL-terminated; value is a writable DWORD of `size` bytes.
    let error = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    (error == 0).then_some(value)
}

/// The UI restrictions of the job sandy runs in, or `None` outside a job. For nested jobs this
/// is the immediate job of sandy.
pub fn outer_job_ui() -> Result<Option<u32>, String> {
    let mut in_job = 0;
    // SAFETY: the pseudo handle of this process and a null job handle ask whether this process
    // is in any job; in_job is a valid out pointer.
    if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut in_job) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if in_job == 0 {
        return Ok(None);
    }
    let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: 0,
    };
    // SAFETY: a null job handle selects the job of this process; ui is a writable structure of
    // the size passed.
    let ok = unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectBasicUIRestrictions,
            (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(Some(ui.UIRestrictionsClass))
}

/// Whether a job with sandy's UI restrictions can hold a process of sandy's job chain. sandy puts
/// the program into a job of its own with UI restrictions, and Windows refuses that when a job
/// sandy runs in has UI restrictions too. `outer_job_ui` reads the immediate job only, so in a
/// chain of jobs nothing but a trial answers it (measured on Windows 11 build 26200: with an
/// outer job that has UI restrictions and an immediate job without, the immediate job's
/// restrictions read as 0, `sandy check` reported the policy as enforced and `sandy run` then
/// failed with status 125).
///
/// The trial creates a process and ends it again, so only `verify` calls it. The process starts
/// suspended and is terminated before it runs an instruction. `Ok` when there is nothing to try:
/// outside a job there is no chain, and an immediate job with UI restrictions is in the plan
/// already.
pub fn job_nests() -> Result<(), String> {
    if !matches!(outer_job_ui(), Ok(Some(0))) {
        return Ok(());
    }
    let job = ui_restricted_job()?;
    let process = suspended_process()?;
    // SAFETY: both handles are open and owned here.
    let assigned =
        unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) };
    let error = io::Error::last_os_error();
    // SAFETY: the process is still suspended, so it ends without running anything.
    unsafe { TerminateProcess(process.as_raw_handle(), 1) };
    if assigned == 0 {
        return Err(format!(
            "sandy runs in a chain of job objects and one of them has UI restrictions, so \
             Windows does not nest sandy's job, which sets UI restrictions too, and the program \
             cannot be put into it: {error}. Start sandy outside that job"
        ));
    }
    Ok(())
}

/// An unnamed job object with the UI restrictions of the program's job, for `job_nests`.
fn ui_restricted_job() -> Result<OwnedHandle, String> {
    // SAFETY: null attributes and name create an unnamed job with a handle that is not
    // inheritable.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(format!(
            "cannot create a job object to test whether sandy's job can be nested: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a new handle that nothing else owns.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: super::process::UI_RESTRICTIONS,
    };
    // SAFETY: the structure matches the information class and outlives the call.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicUIRestrictions,
            (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "cannot set the UI restrictions of the job object that tests whether sandy's job can \
             be nested: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(job)
}

/// A suspended process of sandy's own executable, which joins sandy's job chain like the program
/// would. It runs nothing: `job_nests` terminates it while it is still suspended.
fn suspended_process() -> Result<OwnedHandle, String> {
    let sandy = std::env::current_exe()
        .map_err(|error| format!("cannot find the path of sandy: {error}"))?;
    // Passed as the application too: from the command line alone, Windows splits a path with a
    // space and starts the first file its words name, `C:\Program.exe` for
    // `C:\Program Files\sandy\sandy.exe` for example.
    let application = wide_nul(sandy.as_os_str());
    let mut line = application.clone();
    // SAFETY: the structures are plain data; zero is a valid value for every field.
    let (mut startup, mut info): (STARTUPINFOW, PROCESS_INFORMATION) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    // SAFETY: application and line are NUL-terminated and line is writable; startup and info
    // outlive the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    };
    if created == 0 {
        return Err(format!(
            "cannot start a suspended process to test whether sandy's job can be nested: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: CreateProcessW returned two new handles that nothing else owns. The thread handle
    // is closed at once: the process stays suspended until it is terminated.
    unsafe {
        drop(OwnedHandle::from_raw_handle(info.hThread));
        Ok(OwnedHandle::from_raw_handle(info.hProcess))
    }
}

pub type DeriveCapabilitySidsFromName =
    unsafe extern "system" fn(PCWSTR, *mut *mut PSID, *mut u32, *mut *mut PSID, *mut u32) -> BOOL;

/// `DeriveCapabilitySidsFromName` from KernelBase, resolved at run time. Builds before Windows
/// 10 1809 do not export it; a load-time import would stop `sandy.exe` before `main`, without
/// any explanation.
pub fn derive_capability_sids() -> Result<DeriveCapabilitySidsFromName, String> {
    static FUNCTION: OnceLock<Option<DeriveCapabilitySidsFromName>> = OnceLock::new();
    let function =
        *FUNCTION.get_or_init(|| {
            let module = wide_nul("kernelbase.dll".as_ref());
            // SAFETY: KernelBase is loaded in every Win32 process; the name is NUL-terminated.
            let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
            if handle.is_null() {
                return None;
            }
            // SAFETY: the module handle is valid and the export name is NUL-terminated.
            let address =
                unsafe { GetProcAddress(handle, c"DeriveCapabilitySidsFromName".as_ptr().cast()) }?;
            // SAFETY: the export has the signature documented for DeriveCapabilitySidsFromName.
            Some(unsafe {
                std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    DeriveCapabilitySidsFromName,
                >(address)
            })
        });
    function.ok_or_else(|| {
        "this Windows lacks DeriveCapabilitySidsFromName (Windows 10 1809 or later has it), \
         which sandy needs to grant file access"
            .to_string()
    })
}
