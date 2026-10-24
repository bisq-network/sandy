//! Detection of the kernel features and process state the backend depends on. Every function
//! here only reads state, so `plan` can call it.

use std::io;
use std::ptr;

use sandy_core::{ChildProcesses, ResolvedPolicy};

use crate::filter;
use crate::system::{self, SystemPath};

/// `Ok` when a feature can be used, otherwise the reason why it cannot.
pub type Support = Result<(), String>;

/// What this host and this process offer. `plan_for` turns it into a plan without further I/O,
/// so tests can describe any host.
#[derive(Debug, Clone)]
pub struct HostCapabilities {
    /// The Landlock ABI version the kernel reports.
    pub landlock: Result<i32, String>,
    /// Whether sandy can count its threads, which it must do before Landlock restricts it.
    pub thread_count: Support,
    /// Seccomp filters with the actions the filter uses, for this CPU architecture.
    pub seccomp: Support,
    pub no_new_privs: Support,
    /// `Err` when the process runs as root or holds capabilities.
    pub unprivileged: Support,
    /// pidfd_open, which the relay uses to watch the program and the guard of
    /// `children = "contained"` uses to watch the program.
    pub pidfd: Support,
    /// Whether sandy may put a process into a process group, which `children = "contained"`
    /// needs. Only probed for a policy that needs it (`detect_for`).
    pub process_group: Support,
    /// The candidates of the minimal system set that exist on this host.
    pub system_paths: Vec<SystemPath>,
    /// Where every candidate of the minimal system set is or would be, also missing ones.
    pub system_locations: Vec<SystemPath>,
}

impl HostCapabilities {
    /// What this host offers whatever the policy asks for.
    pub fn detect() -> Self {
        HostCapabilities {
            landlock: landlock_abi(),
            thread_count: thread_count_support(),
            pidfd: pidfd_support(),
            process_group: Ok(()),
            seccomp: seccomp_support(),
            no_new_privs: no_new_privs_support(),
            unprivileged: unprivileged(),
            system_paths: system::detect(),
            system_locations: system::locations(),
        }
    }

    /// `detect` plus the probes that only some policies need. A probe is a system call that an
    /// outer sandbox can answer with SIGSYS instead of an error, so it runs only for a policy
    /// whose run would make the call anyway.
    pub fn detect_for(policy: &ResolvedPolicy) -> Self {
        let mut host = Self::detect();
        if policy.children == ChildProcesses::Contained {
            host.process_group = process_group_support();
        }
        host
    }
}

/// Whether sandy may put a process into a process group. `children = "contained"` runs the
/// program in a group of its own, so a sandbox around sandy that denies `setpgid` makes the run
/// fail; sandy's own filter denies it inside `contained`, so one contained sandbox cannot hold
/// another.
fn process_group_support() -> Support {
    // SAFETY: getsid, getpid and getpgrp have no preconditions.
    unsafe {
        // A session leader cannot change its own process group, whatever a filter allows, and
        // that does not stop `contained`: the group is led by the guard, which is a child of
        // sandy and no session leader. Without this, sandy started with `setsid` would report a
        // problem it does not have.
        if libc::getsid(0) == libc::getpid() {
            return Ok(());
        }
        // Joining the group this process is already in changes nothing.
        if libc::setpgid(0, libc::getpgrp()) != 0 {
            return Err(format!(
                "sandy cannot put a process into a process group, which \
                 children = \"contained\" needs: {}. A sandbox around sandy denies setpgid; \
                 sandy's own filter does inside children = \"contained\", so one contained \
                 sandbox cannot hold another",
                io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

fn landlock_abi() -> Result<i32, String> {
    // SAFETY: with a null attribute, size 0 and the VERSION flag, the kernel only returns the ABI
    // version and creates nothing.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version >= 1 {
        return i32::try_from(version).map_err(|_| format!("invalid Landlock ABI {version}"));
    }
    let error = io::Error::last_os_error();
    Err(match error.raw_os_error() {
        Some(libc::EOPNOTSUPP) => "Landlock is built into this kernel but not enabled. On RHEL 9, \
             update to 9.6 or newer. On SLES 15 and openSUSE Leap 15, add landlock to the lsm= \
             boot parameter"
            .to_string(),
        Some(libc::ENOSYS) => "this kernel has no Landlock. Linux 5.13 or newer with Landlock is \
             required (RHEL 8 has none). In a container, the seccomp profile may block the \
             Landlock system calls"
            .to_string(),
        _ => format!("cannot query the Landlock ABI: {error}"),
    })
}

/// The directory that lists the threads of this process.
pub const THREADS_DIR: &str = "/proc/self/task";

fn thread_count_support() -> Support {
    std::fs::read_dir(THREADS_DIR).map(|_| ()).map_err(|error| {
        format!(
            "cannot list {THREADS_DIR}, which sandy needs to verify that it is single-threaded \
             before Landlock restricts it: {error}"
        )
    })
}

fn pidfd_support() -> Support {
    // SAFETY: process ID 0 is invalid, so a kernel with pidfd_open fails with EINVAL and creates
    // nothing.
    if unsafe { libc::syscall(libc::SYS_pidfd_open, 0, 0u32) } >= 0 {
        return Err("pidfd_open accepted process ID 0".to_string());
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::EINVAL) => Ok(()),
        _ => Err(format!(
            "pidfd_open is unavailable (Linux 5.3 or newer is required): {}",
            io::Error::last_os_error()
        )),
    }
}

fn seccomp_support() -> Support {
    if !filter::ARCH_SUPPORTED {
        return Err("sandy has no seccomp filter for this CPU architecture".to_string());
    }
    for action in [libc::SECCOMP_RET_ERRNO, libc::SECCOMP_RET_KILL_PROCESS] {
        // SAFETY: SECCOMP_GET_ACTION_AVAIL reads one u32 through the pointer and changes nothing.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_ACTION_AVAIL,
                0,
                &action as *const u32,
            )
        };
        if result != 0 {
            return Err(format!(
                "this kernel does not support the seccomp filter actions sandy uses (Linux 4.14 or \
                 newer is required): {}",
                io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn no_new_privs_support() -> Support {
    // SAFETY: PR_GET_NO_NEW_PRIVS only reads a process flag.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } < 0 {
        return Err(format!(
            "this kernel does not support no_new_privs: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// A program that starts with root or with capabilities keeps them under no_new_privs. Landlock
/// does not restrict chmod or chown, so root could, for example, add the setuid bit to a shell.
fn unprivileged() -> Support {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: getresuid writes three uid_t values through valid pointers.
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0 {
        return Err(format!(
            "cannot read the user IDs: {}",
            io::Error::last_os_error()
        ));
    }
    if real == 0 || effective == 0 || saved == 0 {
        return Err(
            "sandy runs as root (user ID 0); the program would keep root privileges".to_string(),
        );
    }
    let capabilities = capability_sets()?;
    if capabilities.effective != 0 || capabilities.permitted != 0 {
        return Err("sandy holds capabilities; the program could keep them".to_string());
    }
    if has_ambient_capability() {
        return Err("sandy holds ambient capabilities; the program would inherit them".to_string());
    }
    Ok(())
}

struct CapabilitySets {
    effective: u64,
    permitted: u64,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capability_sets() -> Result<CapabilitySets, String> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: version 3 of capget writes two CapData entries, which `data` provides.
    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if result != 0 {
        return Err(format!(
            "cannot read the capability sets: {}",
            io::Error::last_os_error()
        ));
    }
    let join = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
    Ok(CapabilitySets {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
    })
}

fn has_ambient_capability() -> bool {
    // Capability numbers the kernel does not know fail with EINVAL and count as not set.
    (0..64).any(|capability: libc::c_ulong| {
        // SAFETY: PR_CAP_AMBIENT_IS_SET only reads a process flag.
        let result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        if result < 0 {
            return false;
        }
        result == 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_does_not_fail_on_this_host() {
        let host = HostCapabilities::detect();
        // The test machine runs as an ordinary user with a Landlock kernel; detection must not
        // report spurious errors there.
        assert!(host.no_new_privs.is_ok(), "{host:?}");
        assert!(host.thread_count.is_ok(), "{host:?}");
        assert!(host.pidfd.is_ok(), "{host:?}");
        assert!(host.seccomp.is_ok(), "{host:?}");
    }
}
