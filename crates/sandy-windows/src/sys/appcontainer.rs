//! The AppContainer identity of the target.

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{FreeSid, PSID};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, RegCloseKey, RegOpenKeyExW,
};

use super::lockfile::{LOCKS, SERIALIZE, UserLock};
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

/// Registers the AppContainer profile of `name` for the current user, unless it is registered,
/// and returns its SID. Microsoft documents a profile as the precondition for creating a process
/// in an AppContainer. The profile also creates a folder for the AppContainer below
/// `%LOCALAPPDATA%\Packages`.
///
/// `CreateAppContainerProfile` is called only when the profile is missing, under a lock. On
/// Windows 11, calling it for an existing profile while other runs started processes in the
/// same AppContainer made it fail with E_UNEXPECTED and made a concurrent `CreateProcessW` fail
/// with ERROR_FILE_NOT_FOUND.
pub fn ensure_profile(name: &str) -> Result<Sid, SandboxError> {
    let container = sid(name)?;
    if is_registered(&container) {
        return Ok(container);
    }
    let _lock = UserLock::wait_for(LOCKS, "appcontainer-profiles", SERIALIZE, true)?;
    if is_registered(&container) {
        return Ok(container);
    }
    create_profile(name)
}

/// Whether the profile of `container` is registered for the current user. Windows records the
/// registration under this key. Microsoft does not document the location; if it changes, this
/// returns false and sandy calls `CreateAppContainerProfile`, which reports an existing profile.
fn is_registered(container: &Sid) -> bool {
    let key = wide_nul(
        format!(
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{container}"
        )
        .as_ref(),
    );
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: the key name is NUL-terminated and handle is a valid out pointer.
    let status =
        unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, key.as_ptr(), 0, KEY_READ, &mut handle) };
    if status != 0 {
        return false;
    }
    // SAFETY: the key is open and closed exactly once.
    unsafe { RegCloseKey(handle) };
    true
}

/// Removes the profile of `name` and its folder. Does nothing when there is no profile.
pub fn delete_profile(name: &str) -> Result<(), SandboxError> {
    if !is_registered(&sid(name)?) {
        return Ok(());
    }
    let wide = wide_nul(name.as_ref());
    // SAFETY: the name is NUL-terminated.
    let hresult = unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    if hresult < 0 {
        return Err(hresult_error(
            format!("cannot remove the profile of AppContainer {name:?}"),
            hresult,
        ));
    }
    Ok(())
}

fn create_profile(name: &str) -> Result<Sid, SandboxError> {
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
