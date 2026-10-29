//! `--status-fd` and `--status-file`: where sandy writes the status record (see
//! `sandy_core::StatusReport`). Only `run` takes them, because the descriptors of a `check` are
//! not the descriptors the later `run` gets.

use std::path::Path;

use sandy_core::StatusReport;

use crate::args::StatusTarget;

/// The status record of `run`, or none.
pub fn open(target: Option<&StatusTarget>) -> Result<StatusReport, String> {
    match target {
        None => Ok(StatusReport::none()),
        Some(StatusTarget::Inherited(number)) => inherited(*number),
        Some(StatusTarget::File(path)) => create(path),
    }
}

/// Creates the file of `--status-file`. It must not exist yet, so that sandy follows no link
/// and overwrites no file that someone left there, the program of an earlier run for example;
/// the caller removes it once it has read the record. The file is close-on-exec, and on Windows
/// not inheritable, so the program never has it, and `run` refuses a file the program could
/// open for writing (`refuse_writable_status_file`).
fn create(path: &Path) -> Result<StatusReport, String> {
    if !path.is_absolute() {
        return Err(format!(
            "--status-file needs an absolute path, not {}",
            path.display()
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .map(StatusReport::to)
        .map_err(|error| format!("cannot create --status-file {}: {error}", path.display()))
}

/// Takes over the descriptor the caller named, after checking that it is open and is none of
/// the standard streams, which belong to the program. The descriptor is made close-on-exec, so
/// the program never sees it, and sandy owns it from here.
#[cfg(unix)]
fn inherited(number: u64) -> Result<StatusReport, String> {
    use std::os::fd::{FromRawFd, RawFd};

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
fn inherited(number: u64) -> Result<StatusReport, String> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_UNKNOWN, GetFileType};

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
fn inherited(_number: u64) -> Result<StatusReport, String> {
    Err("--status-fd is not supported on this operating system".to_string())
}
