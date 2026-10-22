//! The AppContainer identity of the target.

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{FreeSid, PSID};

use super::util::{Sid, hresult_error, wide_nul};

/// The AppContainer SID for `name`. Deriving it is a computation; it registers nothing.
pub fn sid(name: &str) -> Result<Sid, SandboxError> {
    let wide = wide_nul(name.as_ref());
    let mut psid: PSID = std::ptr::null_mut();
    // SAFETY: wide is NUL-terminated and psid is a valid out pointer.
    let hresult = unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut psid) };
    if hresult < 0 {
        return Err(hresult_error(
            format!("cannot derive the SID of AppContainer {name:?}"),
            hresult,
        ));
    }
    take_sid(psid, name)
}

/// Registers the AppContainer profile of `name` for the current user, unless it exists, and
/// returns its SID. Microsoft documents a profile as the precondition for creating a process in
/// an AppContainer. The profile also creates a folder for the AppContainer below
/// `%LOCALAPPDATA%\Packages`.
pub fn ensure_profile(name: &str) -> Result<Sid, SandboxError> {
    let wide = wide_nul(name.as_ref());
    let description = wide_nul("Created by sandy".as_ref());
    let mut psid: PSID = std::ptr::null_mut();
    // SAFETY: all strings are NUL-terminated; no capabilities are passed (null, 0); psid is a
    // valid out pointer.
    let hresult = unsafe {
        CreateAppContainerProfile(
            wide.as_ptr(),
            wide.as_ptr(),
            description.as_ptr(),
            std::ptr::null(),
            0,
            &mut psid,
        )
    };
    const ALREADY_EXISTS: i32 = (0x8007_0000 | ERROR_ALREADY_EXISTS) as i32;
    if hresult == ALREADY_EXISTS {
        return sid(name);
    }
    if hresult < 0 {
        return Err(hresult_error(
            format!("cannot create the profile of AppContainer {name:?}"),
            hresult,
        ));
    }
    take_sid(psid, name)
}

/// Copies a SID that an AppContainer function returned and frees the original.
fn take_sid(psid: PSID, name: &str) -> Result<Sid, SandboxError> {
    // SAFETY: on success the function stored a SID it allocated in psid.
    let sid = unsafe { Sid::copy_from(psid) };
    // SAFETY: "This buffer must be freed using the FreeSid function." It is freed exactly once.
    unsafe { FreeSid(psid) };
    sid.map_err(|error| SandboxError::io(format!("AppContainer {name:?}"), error))
}
