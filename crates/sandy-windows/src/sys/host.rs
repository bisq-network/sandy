//! Host facts the plan depends on: the Windows version, the job sandy runs in, and the
//! `DeriveCapabilitySidsFromName` export.

use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_BASIC_UI_RESTRICTIONS, JobObjectBasicUIRestrictions,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
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
