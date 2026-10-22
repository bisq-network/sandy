//! One AppContainer name per resolved policy, enforced while runs overlap in time.
//!
//! Processes in one AppContainer reach each other over loopback and can open each other's
//! processes (same package SID). So two concurrent runs under the same AppContainer name share a
//! sandbox: a weaker policy could take over a stronger one that runs at the same time. sandy
//! refuses a second run with the same name but a different resolved policy while the first is
//! active. The same policy may run concurrently; sequential runs with different policies stay
//! allowed.
//!
//! The coordination state is a named file mapping in the `Local\` namespace, which an
//! AppContainer process cannot open (it is redirected to its own AppContainer object namespace),
//! so the sandboxed program cannot tamper with it. The mapping holds the active policy's
//! fingerprint. Each active run holds a handle to it; the kernel frees the mapping when the last
//! handle closes, so a crashed run leaves no stale state and cannot block a later run forever.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use sandy_core::{PathAccess, ResolvedPolicy, SandboxError};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
};

use super::util::{SessionLock, last_error, wide_nul};

/// The shared region: a 4-byte little-endian length, then that many fingerprint bytes. Backed by
/// the pagefile and committed lazily, so the generous size costs almost nothing until written.
const REGION_SIZE: usize = 128 * 1024;
const MAX_FINGERPRINT: usize = REGION_SIZE - 4;

/// Held for the lifetime of a run. Dropping it closes the mapping handle; when the last run's
/// handle closes, the kernel frees the mapping and the name becomes free for a different policy.
pub struct RunGuard {
    _mapping: OwnedHandle,
}

/// Refuses the run when another run with the same AppContainer name but a different resolved
/// policy is active. Returns a guard the caller holds until the program exits.
pub fn hold(name: &str, policy: &ResolvedPolicy) -> Result<RunGuard, SandboxError> {
    let fingerprint = fingerprint(policy)?;
    // Serialize the check so two first runs do not both create the mapping.
    let _lock = SessionLock::acquire(&format!(r"Local\sandy.singleton.{name}"))?;

    let mapping_name = wide_nul(format!(r"Local\sandy.state.{name}").as_ref());
    // SAFETY: INVALID_HANDLE_VALUE backs the mapping by the pagefile; the name is NUL-terminated.
    // A zero size high word with REGION_SIZE as the low word sizes it.
    let raw = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            ptr::null(),
            PAGE_READWRITE,
            0,
            REGION_SIZE as u32,
            mapping_name.as_ptr(),
        )
    };
    if raw.is_null() {
        return Err(last_error("cannot create the run coordination object"));
    }
    // GetLastError is read before any other call can overwrite it.
    let existed =
        std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32);
    // SAFETY: CreateFileMappingW returned a new handle this process owns.
    let mapping = unsafe { OwnedHandle::from_raw_handle(raw) };

    let view = MappedView::map(&mapping)?;
    if existed {
        let active = view.read();
        if active != fingerprint {
            return Err(SandboxError::new(format!(
                "another sandy run uses the AppContainer {name:?} with a different policy; \
                 processes in one AppContainer can reach and control each other, so sandy does \
                 not run a different policy under the same name at the same time; wait for the \
                 other run to end, or use a different --appcontainer name"
            )));
        }
    } else {
        view.write(&fingerprint);
    }
    // The view is only needed for the check; the mapping stays alive through its handle.
    drop(view);
    Ok(RunGuard { _mapping: mapping })
}

/// A mapped view of the coordination region, unmapped on drop.
struct MappedView(*mut c_void);

impl MappedView {
    fn map(mapping: &OwnedHandle) -> Result<MappedView, SandboxError> {
        // SAFETY: the handle is a valid file mapping; mapping the whole region for read and write.
        let address =
            unsafe { MapViewOfFile(mapping.as_raw_handle(), FILE_MAP_WRITE, 0, 0, REGION_SIZE) };
        if address.Value.is_null() {
            return Err(last_error("cannot map the run coordination object"));
        }
        Ok(MappedView(address.Value))
    }

    fn read(&self) -> Vec<u8> {
        // SAFETY: the view is REGION_SIZE bytes; the first four hold the length, written under the
        // same mutex before any reader runs. A fresh mapping is zero, so a reader that somehow
        // raced creation would see length 0, never a valid fingerprint.
        let len = unsafe { ptr::read_unaligned(self.0.cast::<u32>()) } as usize;
        let len = len.min(MAX_FINGERPRINT);
        // SAFETY: len is at most MAX_FINGERPRINT, so the slice stays inside the view.
        unsafe { std::slice::from_raw_parts(self.0.cast::<u8>().add(4), len) }.to_vec()
    }

    fn write(&self, fingerprint: &[u8]) {
        // SAFETY: the caller guarantees fingerprint fits in MAX_FINGERPRINT (checked in
        // `fingerprint`); the view has room for the length word and the bytes.
        unsafe {
            ptr::write_unaligned(self.0.cast::<u32>(), fingerprint.len() as u32);
            ptr::copy_nonoverlapping(
                fingerprint.as_ptr(),
                self.0.cast::<u8>().add(4),
                fingerprint.len(),
            );
        }
    }
}

impl Drop for MappedView {
    fn drop(&mut self) {
        // SAFETY: self.0 came from MapViewOfFile and is unmapped once.
        unsafe {
            UnmapViewOfFile(
                windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS { Value: self.0 },
            )
        };
    }
}

/// A deterministic encoding of everything in `policy` that affects confinement. Two resolved
/// policies produce equal bytes exactly when they confine the program the same way. The program,
/// its arguments, the working directory and the environment do not change the sandbox boundary
/// and are excluded; the program's own read-and-execute rule is part of `paths` and is included.
fn fingerprint(policy: &ResolvedPolicy) -> Result<Vec<u8>, SandboxError> {
    use std::os::windows::ffi::OsStrExt;

    let mut out = vec![
        1u8, // format version
        match policy.system {
            sandy_core::SystemAccess::Minimal => 0,
            sandy_core::SystemAccess::None => 1,
        },
        net(policy.ip),
        net(policy.unix_sockets),
        match policy.signals {
            sandy_core::SignalScope::Any => 0,
            sandy_core::SignalScope::Isolated => 1,
        },
        match policy.path_metadata {
            sandy_core::PathMetadata::Deny => 0,
            sandy_core::PathMetadata::Allow => 1,
        },
    ];

    // `paths` is sorted by path when the policy is resolved, so the order is deterministic.
    out.extend((policy.paths.len() as u32).to_le_bytes());
    for rule in &policy.paths {
        out.push(match rule.access {
            PathAccess::Read => 0,
            PathAccess::ReadExec => 1,
            PathAccess::ReadWrite => 2,
        });
        out.push(u8::from(rule.is_dir));
        let wide: Vec<u16> = rule.path.as_os_str().encode_wide().collect();
        out.extend((wide.len() as u32).to_le_bytes());
        for unit in wide {
            out.extend(unit.to_le_bytes());
        }
    }

    // Exposed and forwarded ports are order independent; sort their encodings for a stable
    // result. The prefixes keep an exposed and a forwarded port with the same numbers apart.
    let mut ports: Vec<String> = policy
        .expose
        .iter()
        .map(|port| format!("expose {}={}", port.listen, port.port))
        .chain(
            policy
                .forward
                .iter()
                .map(|port| format!("forward {}={}", port.port, port.to)),
        )
        .collect();
    ports.sort();
    out.extend((ports.len() as u32).to_le_bytes());
    for port in ports {
        out.extend((port.len() as u32).to_le_bytes());
        out.extend(port.as_bytes());
    }

    if out.len() > MAX_FINGERPRINT {
        return Err(SandboxError::new(
            "the policy is too large to coordinate concurrent runs under one AppContainer name",
        ));
    }
    Ok(out)
}

fn net(access: sandy_core::NetworkAccess) -> u8 {
    match access {
        sandy_core::NetworkAccess::None => 0,
        sandy_core::NetworkAccess::All => 1,
    }
}
