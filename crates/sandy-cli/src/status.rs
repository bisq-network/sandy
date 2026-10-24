//! `--status-fd`: the descriptor sandy writes the status record to (see
//! `sandy_core::StatusReport`). Only `run` takes it over, because the descriptors of a `check`
//! are not the descriptors the later `run` gets.

use sandy_core::StatusReport;

/// Takes over the descriptor the caller named, after checking that it is open and is none of
/// the standard streams, which belong to the program. The descriptor is made close-on-exec, so
/// the program never sees it, and sandy owns it from here.
#[cfg(unix)]
pub fn open(number: Option<u64>) -> Result<StatusReport, String> {
    use std::os::fd::{FromRawFd, RawFd};

    let Some(number) = number else {
        return Ok(StatusReport::none());
    };
    let fd = RawFd::try_from(number)
        .ok()
        .filter(|&fd| fd > 2)
        .ok_or_else(|| format!("--status-fd {number} is not a descriptor above 2"))?;
    // SAFETY: F_SETFD only changes the flags of the descriptor, and reports a closed one.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(format!(
            "cannot use --status-fd {number}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor is open, and the caller passed it to sandy to write the record to,
    // so nothing else in this process owns it.
    Ok(StatusReport::to(unsafe { std::fs::File::from_raw_fd(fd) }))
}

/// Takes over the handle the caller inherited to sandy, after checking that it is a handle sandy
/// can write to. sandy names every handle the program inherits, and this one is not among them
/// (see `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` in the Windows backend), so the program never sees
/// it. Clearing the inherit flag keeps it out of every other process sandy starts as well.
#[cfg(windows)]
pub fn open(number: Option<u64>) -> Result<StatusReport, String> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_UNKNOWN, GetFileType};

    let Some(number) = number else {
        return Ok(StatusReport::none());
    };
    let handle = usize::try_from(number)
        .map(|handle| handle as RawHandle)
        .map_err(|_| format!("--status-fd {number} is not a handle"))?;
    // SAFETY: GetFileType reports an invalid handle instead of failing.
    if unsafe { GetFileType(handle) } == FILE_TYPE_UNKNOWN {
        return Err(format!(
            "cannot use --status-fd {number}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the handle is valid; the call only clears its inherit flag.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(format!(
            "cannot keep --status-fd {number} from being inherited: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the handle is valid, and the caller passed it to sandy to write the record to, so
    // nothing else in this process owns it.
    Ok(StatusReport::to(unsafe {
        std::fs::File::from_raw_handle(handle)
    }))
}

#[cfg(not(any(unix, windows)))]
pub fn open(number: Option<u64>) -> Result<StatusReport, String> {
    match number {
        None => Ok(StatusReport::none()),
        Some(_) => Err("--status-fd is not supported on this operating system".to_string()),
    }
}
