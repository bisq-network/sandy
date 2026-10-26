//! Host state that AppContainer network isolation depends on: the firewall service and the
//! loopback exemptions.

use std::io;
use std::ptr;

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
};
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS,
};

use super::util::{Sid, wide_nul, win32_error};
use crate::plan::Problem;
use crate::probe;

/// Whether the Windows Firewall service runs. It turns the AppContainer network rules into
/// filters of the Windows Filtering Platform; Microsoft does not support stopping it.
pub fn firewall_running() -> Result<(), Problem> {
    probe::firewall(firewall_state())
}

/// The current state of the Windows Firewall service, or the step that failed and its error.
fn firewall_state() -> Result<u32, (&'static str, io::Error)> {
    let service = wide_nul("MpsSvc".as_ref());
    let manager = ServiceHandle::open(
        // SAFETY: null machine and database names select the local service database.
        unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) },
        "open the service control manager",
    )?;
    let firewall = ServiceHandle::open(
        // SAFETY: manager is open and the service name is NUL-terminated.
        unsafe { OpenServiceW(manager.0, service.as_ptr(), SERVICE_QUERY_STATUS) },
        "open the Windows Firewall service (MpsSvc)",
    )?;
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: firewall is open with SERVICE_QUERY_STATUS and status is writable.
    if unsafe { QueryServiceStatus(firewall.0, &mut status) } == 0 {
        return Err((
            "query the Windows Firewall service (MpsSvc)",
            io::Error::last_os_error(),
        ));
    }
    Ok(status.dwCurrentState)
}

struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn open(
        handle: SC_HANDLE,
        step: &'static str,
    ) -> Result<ServiceHandle, (&'static str, io::Error)> {
        if handle.is_null() {
            return Err((step, io::Error::last_os_error()));
        }
        Ok(ServiceHandle(handle))
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed exactly once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// The AppContainer SIDs that are exempt from loopback isolation, with their attributes.
fn exemptions() -> io::Result<Vec<(Sid, u32)>> {
    let mut count = 0u32;
    let mut entries: *mut SID_AND_ATTRIBUTES = ptr::null_mut();
    // SAFETY: both out pointers are valid.
    let error = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: GetProcessHeap has no preconditions.
    let heap: HANDLE = unsafe { GetProcessHeap() };
    let mut list = Vec::with_capacity(count as usize);
    let mut failure = None;
    for index in 0..count as usize {
        // SAFETY: the function returned `count` entries.
        let entry = unsafe { entries.add(index).read() };
        // SAFETY: each entry holds a SID from the function.
        match unsafe { Sid::copy_from(entry.Sid) } {
            Ok(sid) => list.push((sid, entry.Attributes)),
            Err(error) => failure = Some(error),
        }
        // The documentation frees each SID and the array with HeapFree on the process heap.
        // SAFETY: the SID was allocated on the process heap and is freed exactly once.
        unsafe { HeapFree(heap, 0, entry.Sid) };
    }
    if !entries.is_null() {
        // SAFETY: the array was allocated on the process heap and is freed exactly once.
        unsafe { HeapFree(heap, 0, entries.cast()) };
    }
    failure.map_or(Ok(list), Err)
}

/// The AppContainer SIDs that are exempt from loopback isolation. Any error can pass, so it is
/// indeterminate.
pub fn loopback_exemptions() -> Result<Vec<Sid>, Problem> {
    exemptions()
        .map(|list| list.into_iter().map(|(sid, _)| sid).collect())
        .map_err(|error| Problem::Indeterminate(error.to_string()))
}

/// Adds or removes the loopback exemption of `appcontainer`. The call replaces the whole list,
/// so the other entries are read first and written back. Needs administrator rights.
pub fn set_loopback_exempt(appcontainer: &Sid, exempt: bool) -> Result<(), SandboxError> {
    let mut list = exemptions()
        .map_err(|error| SandboxError::io("cannot read the loopback exemptions", error))?;
    if list.iter().any(|(sid, _)| sid == appcontainer) == exempt {
        return Ok(());
    }
    if exempt {
        list.push((appcontainer.clone(), 0));
    } else {
        list.retain(|(sid, _)| sid != appcontainer);
    }
    let entries: Vec<SID_AND_ATTRIBUTES> = list
        .iter()
        .map(|(sid, attributes)| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: *attributes,
        })
        .collect();
    // SAFETY: entries holds list.len() valid SIDs that outlive the call.
    let error =
        unsafe { NetworkIsolationSetAppContainerConfig(entries.len() as u32, entries.as_ptr()) };
    if error == ERROR_ACCESS_DENIED {
        return Err(SandboxError::new(
            "changing the loopback exemptions needs administrator rights",
        ));
    }
    if error != 0 {
        return Err(win32_error("cannot change the loopback exemptions", error));
    }
    Ok(())
}
