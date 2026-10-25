//! One AppContainer per resolved policy, enforced while runs overlap in time.
//!
//! Processes in one AppContainer reach each other over loopback and can open each other's
//! processes (same package SID). So two concurrent runs in the same AppContainer share a
//! sandbox: a weaker policy could take over a stronger one that runs at the same time. sandy
//! refuses a second run in the same AppContainer with a different resolved policy while the
//! first is active. The same policy may run concurrently; sequential runs with different
//! policies stay allowed.
//!
//! The identity is the AppContainer SID, not the name from the policy. Windows derives the SID
//! from the name without regard to case, and so do the capability names and the profile folder,
//! so `sandy.X` and `SANDY.x` are one sandbox and must be one policy.
//!
//! The coordination state is a file below `%LOCALAPPDATA%\sandy\runs`, which the sandboxed
//! program cannot reach (see `lockfile`). It holds the active policy's fingerprint. Each active
//! run holds a shared byte range lock on the file; the kernel releases the lock when the run
//! ends or dies, so a crashed run leaves no state that blocks a later run.

use sandy_core::{PathAccess, ResolvedPolicy, SandboxError};

use super::lockfile::{ACTIVE, RUNS, SERIALIZE, UserLock};
use super::util::Sid;

/// Held for the lifetime of a run. Dropping it releases the lock that marks the AppContainer as
/// in use, so the next run may set a different policy.
pub struct RunGuard {
    _active: UserLock,
}

/// Refuses the run when another run in the same AppContainer with a different resolved policy is
/// active. Returns a guard the caller holds until the program exits.
pub fn hold(container: &Sid, policy: &ResolvedPolicy) -> Result<RunGuard, SandboxError> {
    let fingerprint = fingerprint(policy);
    let key = container.to_string();
    // Serialize the check, so two first runs do not both set the policy.
    let serialize = UserLock::wait_for(RUNS, &key, SERIALIZE, true)?;

    // An exclusive lock on ACTIVE succeeds exactly while no run holds the shared one.
    match UserLock::take(RUNS, &key, ACTIVE, true, false)? {
        Some(exclusive) => {
            // No run is active, so this one sets the policy. Dropping the exclusive lock lets
            // the shared one below take the byte; no other run can slip in between, because
            // this one holds the serializing lock.
            drop(exclusive);
            serialize.write(&fingerprint)?;
        }
        None => {
            if serialize.read()? != fingerprint {
                return Err(SandboxError::new(format!(
                    "another sandy run uses the AppContainer {container} with a different \
                     policy; processes in one AppContainer can reach and control each other, so \
                     sandy does not run a different policy in the same AppContainer at the same \
                     time; wait for the other run to end, or use a different --appcontainer name"
                )));
            }
        }
    }
    Ok(RunGuard {
        _active: UserLock::wait_for(RUNS, &key, ACTIVE, false)?,
    })
}

/// Takes the AppContainer for a step that must not overlap a run, and refuses while one is
/// active. The caller holds the lock until it is done.
pub fn hold_idle(container: &Sid) -> Result<UserLock, SandboxError> {
    let key = container.to_string();
    let _serialize = UserLock::wait_for(RUNS, &key, SERIALIZE, true)?;
    UserLock::take(RUNS, &key, ACTIVE, true, false)?.ok_or_else(|| {
        SandboxError::new(format!(
            "a sandy run is using the AppContainer {container}; wait for it to end"
        ))
    })
}

/// A deterministic encoding of everything in `policy` that affects confinement. Two resolved
/// policies produce equal bytes exactly when they confine the program the same way. The program,
/// its arguments, the working directory and the environment do not change the sandbox boundary
/// and are excluded; the program's own read-and-execute rule is part of `paths` and is included.
fn fingerprint(policy: &ResolvedPolicy) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    let mut out = vec![
        // Format version. 2 adds forwarded ports and `children`, 3 adds `end_with_parent` and
        // keys the state on the SID, 4 adds `win32k`; a run of another sandy version that reads
        // this file then never matches by accident and is refused, which is the safe outcome.
        // sandy 1.3.2 (version 2) kept the state in a named kernel object, which this version
        // does not read.
        4u8,
        match policy.system {
            sandy_core::SystemAccess::Minimal => 0,
            sandy_core::SystemAccess::None => 1,
        },
        match policy.ip {
            sandy_core::IpAccess::None => 0,
            sandy_core::IpAccess::All => 1,
            sandy_core::IpAccess::Client => 2,
        },
        net(policy.unix_sockets),
        match policy.signals {
            sandy_core::SignalScope::Any => 0,
            sandy_core::SignalScope::Isolated => 1,
        },
        match policy.path_metadata {
            sandy_core::PathMetadata::Deny => 0,
            sandy_core::PathMetadata::Allow => 1,
        },
        // A program that may start processes could use a sibling that may not, and the reverse.
        match policy.children {
            sandy_core::ChildProcesses::Allowed => 0,
            sandy_core::ChildProcesses::None => 1,
            sandy_core::ChildProcesses::Contained => 2,
        },
        // A run that ends with its parent could be kept alive by a sibling that does not, which
        // can open its processes because they share the AppContainer.
        u8::from(policy.end_with_parent),
        // A program without win32k could make the calls through a sibling that has it.
        match policy.windows.win32k {
            sandy_core::Win32k::Allow => 0,
            sandy_core::Win32k::Deny => 1,
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
    out
}

fn net(access: sandy_core::NetworkAccess) -> u8 {
    match access {
        sandy_core::NetworkAccess::None => 0,
        sandy_core::NetworkAccess::All => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ResolvedPolicy {
        ResolvedPolicy::resolve(&sandy_core::Policy::default(), None).unwrap()
    }

    /// Every field that changes the sandbox must change the fingerprint, or a run with the field
    /// set the other way could join the sandbox of a run that has it set.
    #[test]
    fn end_with_parent_changes_the_fingerprint() {
        let mut ends = policy();
        ends.end_with_parent = true;
        assert_ne!(fingerprint(&policy()), fingerprint(&ends));
    }

    #[test]
    fn every_ip_value_has_its_own_fingerprint() {
        let with = |ip| {
            let mut policy = policy();
            policy.ip = ip;
            fingerprint(&policy)
        };
        let none = with(sandy_core::IpAccess::None);
        let client = with(sandy_core::IpAccess::Client);
        let all = with(sandy_core::IpAccess::All);
        assert!(none != client && client != all && none != all);
    }

    #[test]
    fn win32k_changes_the_fingerprint() {
        let mut denied = policy();
        denied.windows.win32k = sandy_core::Win32k::Deny;
        assert_ne!(fingerprint(&policy()), fingerprint(&denied));
    }
}
