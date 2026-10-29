//! `process.end_with_parent`: sandy finds the process that started it, so that it can wait for it
//! next to the program and end the program's job when it ends.

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use sandy_core::{ParentProcess, SandboxError};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, FALSE, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use super::util::last_error;

/// Opens the process that started sandy, for waiting. `named` is what the caller gave with
/// `--parent-pid` and `--parent-start`. Windows records only the parent's process ID, which
/// another process can have once the parent has ended.
///
/// Without a start token sandy compares creation times: a process created after sandy cannot be
/// its parent. That is an ordering test on the wall clock, so a clock set back between the start
/// of the parent and the start of sandy makes sandy refuse a running parent, and an early death,
/// a clock set back and a reused process ID together could let an unrelated process pass. With
/// `--parent-start`, the caller's own creation time, sandy requires that exact time instead,
/// which no clock change can alter and which a reused process ID cannot have; the named process
/// then need not be the one Windows recorded as sandy's parent, so a wrapper between the caller
/// and sandy is allowed.
pub fn open_parent(named: Option<ParentProcess>) -> Result<OwnedHandle, SandboxError> {
    let ended = || SandboxError::new("the process that started sandy has already ended");
    let recorded = parent_id()?;
    let token = named.and_then(|named| named.start);
    let parent_id = match named {
        Some(named) if token.is_none() && named.id != recorded => {
            return Err(SandboxError::new(format!(
                "the process that started sandy is {recorded}, not {} (--parent-pid); sandy may \
                 have been started through a wrapper; --parent-start says which process {} is",
                named.id, named.id
            )));
        }
        Some(named) => named.id,
        None => recorded,
    };
    // SAFETY: OpenProcess takes access rights, an inheritance flag and a process ID.
    let raw = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            parent_id,
        )
    };
    if raw.is_null() {
        // SAFETY: GetLastError has no preconditions.
        return Err(match unsafe { GetLastError() } {
            // OpenProcess reports a process ID that names no process this way.
            ERROR_INVALID_PARAMETER => ended(),
            _ => last_error("cannot open the process that started sandy"),
        });
    }
    // SAFETY: raw is a new handle that nothing else owns.
    let parent = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
    let own = created(unsafe { GetCurrentProcess() })?;
    // SAFETY: parent is a valid process handle with SYNCHRONIZE access.
    let running = unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } == WAIT_TIMEOUT;
    let parent_created = created(parent.as_raw_handle())?;
    if !running {
        return Err(ended());
    }
    if !is_the_caller(parent_created, own, token) {
        return Err(match token {
            Some(token) => SandboxError::new(format!(
                "process {parent_id} was created at {parent_created}, not at {token} \
                 (--parent-start); the process that started sandy may have ended already"
            )),
            None => ended(),
        });
    }
    Ok(parent)
}

/// Whether the opened process can be the one the caller means. `created` and `own` are creation
/// times in 100 ns units; an equal time counts as older, because Windows 11 records them finely
/// enough to tell processes apart (40 processes started in a row had 40 distinct times).
fn is_the_caller(created: u64, own: u64, token: Option<u64>) -> bool {
    match token {
        Some(token) => created == token,
        None => created <= own,
    }
}

/// The process ID that Windows recorded as sandy's parent.
fn parent_id() -> Result<u32, SandboxError> {
    // SAFETY: a process snapshot needs no process ID.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error("cannot list the processes"));
    }
    // SAFETY: raw is a new handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: GetCurrentProcessId has no preconditions.
    let own_id = unsafe { GetCurrentProcessId() };
    // SAFETY: the structure is plain data; zero is valid for every field.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: snapshot is a valid snapshot handle and entry has its size set.
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
    while found {
        if entry.th32ProcessID == own_id {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: as above.
        found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    Err(SandboxError::new(
        "sandy is missing from the list of processes",
    ))
}

/// The creation time of `process`, in 100 ns units.
fn created(process: HANDLE) -> Result<u64, SandboxError> {
    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: process is a valid process handle and every pointer is writable.
    if unsafe { GetProcessTimes(process, creation, exit, kernel, user) } == 0 {
        return Err(last_error("cannot read the creation time of a process"));
    }
    Ok(u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_token_asks_for_the_exact_creation_time() {
        // Without a token, every process created no later than sandy passes.
        assert!(is_the_caller(10, 20, None));
        assert!(is_the_caller(20, 20, None));
        assert!(!is_the_caller(21, 20, None));
        // With one, only that creation time does, whichever side of sandy's it is on.
        assert!(is_the_caller(10, 20, Some(10)));
        assert!(is_the_caller(21, 20, Some(21)));
        assert!(!is_the_caller(10, 20, Some(11)));
    }
}
