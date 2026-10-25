//! The namespaces sandy puts the program in: a user namespace that owns the others, and with
//! `ip = "private"` a network namespace that holds only `lo`. The process that becomes the
//! program creates them, so in the exec model the program keeps sandy's process ID; with
//! `children = "contained"` and with `--explain` the forked child does, and the supervising sandy
//! stays outside. In that process, in this order:
//!
//! 1. The helpers that must stay in the host's namespaces are already running: the relay, which
//!    listens and connects on the host's loopback, and the watcher, which signals through pidfds.
//! 2. `enter`: one `unshare` creates every namespace of the run. Then the process denies
//!    `setgroups` and maps its own user and group ID to themselves, one ID each, and with a
//!    network namespace it brings `lo` up. Root is never mapped: a process that is root in its
//!    user namespace keeps its capabilities there across `execve`, and a mapped user keeps none.
//! 3. It binds the listeners that helpers outside serve inside the namespace and hands them over
//!    (`handover`). A port below 1024 needs the capability it still holds here.
//! 4. `drop_capabilities`: until here the process holds every capability of the new user
//!    namespace. It gives up all of them, the bounding set included.
//! 5. It starts the helpers that must run inside the namespace (the socket factory of exposed
//!    ports), which therefore hold no capability either.
//! 6. It confines itself as without namespaces. The filters read the user and group IDs after the
//!    maps: before them `getresuid` returns the overflow ID 65534.
//!
//! The program's seccomp filter still denies every namespace and mount call, so it cannot create
//! namespaces of its own or change these.
//!
//! A helper outside that serves a listener inside, such as a broker next to the relay, starts
//! before step 2 with the `Inbox` of a `handover::pair` and gives its `Handover` to step 3, as the
//! relay does with its forward listeners (`launch::enter`).
//!
//! A mount view (`CLONE_NEWNS`) and a PID namespace for `contained` (`CLONE_NEWPID`) belong in the
//! same `unshare` and in `Namespaces`. Their setup follows the maps, as `lo` does, and comes
//! before step 3. Two things to keep in mind there: a descriptor opened before a new mount
//! namespace refers to the host's mounts and cannot be bound, so the Landlock rule paths, which
//! `launch` opens before `enter` today, must then be opened after it; and a PID namespace takes
//! effect for the next process the entering process forks, which becomes its PID 1, so the init
//! must be forked before the helpers of step 5.
//!
//! `plan` reads what the host says about user namespaces without trying one (`support`), `check`
//! also tries the steps in a forked child (`probe`), and `run` stays the authoritative answer: a
//! step that fails refuses the run.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use sandy_core::SandboxError;

use crate::helper;
use crate::host::{CapData, CapHeader, LINUX_CAPABILITY_VERSION_3};
use crate::launch::ensure_single_thread;

/// The namespaces of a run. Each one is opt-in; the user namespace comes with any of them,
/// because without it an unprivileged process can create none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespaces {
    /// A network namespace with only `lo` (`ip = "private"`).
    pub network: bool,
}

impl Namespaces {
    /// The flags of the one `unshare` call.
    fn flags(self) -> libc::c_int {
        let mut flags = libc::CLONE_NEWUSER;
        if self.network {
            flags |= libc::CLONE_NEWNET;
        }
        flags
    }

    /// Moves this process into new namespaces and prepares them (step 2 of the module
    /// documentation). The process must have one thread, which `unshare` of a user namespace
    /// requires.
    pub fn enter(self) -> Result<(), SandboxError> {
        ensure_single_thread()?;
        // The maps are files of /proc/self, which belong to root while the process is
        // undumpable, as the forked child of `contained` is from sandy. The kernel makes the
        // program dumpable at execve in any case; sandy and the guard stay undumpable.
        // SAFETY: PR_SET_DUMPABLE only sets a process flag.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
            return Err(SandboxError::io(
                "cannot make the program's /proc files its own",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: geteuid and getegid have no preconditions.
        let (user, group) = unsafe { (libc::geteuid(), libc::getegid()) };
        // SAFETY: unshare takes flags and changes only this process.
        if unsafe { libc::unshare(self.flags()) } != 0 {
            return Err(SandboxError::io(
                "cannot create the sandbox's user namespace",
                io::Error::last_os_error(),
            ));
        }
        // An unprivileged process may map only its own IDs, and the group only once setgroups
        // is denied. Without the maps the process is user 65534 to itself.
        write_own("setgroups", "deny")?;
        write_own("uid_map", &format!("{user} {user} 1"))?;
        write_own("gid_map", &format!("{group} {group} 1"))?;
        if self.network {
            bring_up_loopback()?;
        }
        Ok(())
    }
}

/// Writes `content` to `/proc/self/NAME` in one write, which the kernel requires of the maps.
fn write_own(name: &str, content: &str) -> Result<(), SandboxError> {
    let path = format!("/proc/self/{name}");
    let failed = |error| SandboxError::io(format!("cannot write {path}"), error);
    let mut file = File::options().write(true).open(&path).map_err(failed)?;
    let written = file.write(content.as_bytes()).map_err(failed)?;
    if written != content.len() {
        return Err(SandboxError::new(format!(
            "cannot write {path}: the kernel took {written} of {} bytes",
            content.len()
        )));
    }
    Ok(())
}

/// A new network namespace has `lo`, but down. Bringing it up needs `CAP_NET_ADMIN` in the user
/// namespace that owns the network namespace, which this process holds before step 4.
fn bring_up_loopback() -> Result<(), SandboxError> {
    let failed =
        |error| SandboxError::io("cannot bring up the sandbox's loopback interface", error);
    // SAFETY: socket returns a new descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain data; all zeros is an empty name and no flags.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, from) in request.ifr_name.iter_mut().zip(b"lo") {
        *to = *from as libc::c_char;
    }
    // SAFETY: both ioctls read and write the ifreq above, whose name is NUL-terminated.
    unsafe {
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) != 0 {
            return Err(failed(io::Error::last_os_error()));
        }
        request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) != 0 {
            return Err(failed(io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Gives up every capability this process holds in its user namespace: the bounding set, the
/// ambient set, and the effective, permitted and inheritable sets (step 4 of the module
/// documentation). Only in a namespace `enter` created: dropping from the bounding set needs
/// `CAP_SETPCAP`.
pub fn drop_capabilities() -> Result<(), SandboxError> {
    let failed =
        |what: &str| SandboxError::io(format!("cannot {what}"), io::Error::last_os_error());
    // The bounding set first, while CAP_SETPCAP is still effective. The kernel answers EINVAL for
    // the first number it does not know.
    for capability in 0..64_u8 {
        let capability = libc::c_ulong::from(capability);
        // SAFETY: PR_CAPBSET_DROP changes only this process's bounding set.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(failed("empty the capability bounding set"));
        }
    }
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL changes only this process's ambient set.
    let cleared = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if cleared != 0 {
        return Err(failed("clear the ambient capabilities"));
    }
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: version 3 of capset reads two CapData entries, which `data` provides.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0 {
        return Err(failed(
            "drop the capabilities of the sandbox's user namespace",
        ));
    }
    Ok(())
}

/// Why the namespaces are unusable on this host, as far as the host says without a trial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// Nothing `sandy setup` installs changes it.
    Unavailable(String),
    /// An AppArmor profile that `sandy setup` installs lifts it.
    NeedsSetup(String),
}

/// `Ok` when nothing the host says rules user namespaces out.
pub type Support = Result<(), Missing>;

const MAX_USER_NAMESPACES: &str = "/proc/sys/user/max_user_namespaces";
const UNPRIVILEGED_USERNS_CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";
pub(crate) const APPARMOR_RESTRICTION: &str =
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
pub(crate) const APPARMOR_LABEL: &str = "/proc/self/attr/apparmor/current";

/// What `plan` reads, and none of it is a trial: the two sysctls that disable user namespaces
/// (`kernel.unprivileged_userns_clone` exists on Debian and Ubuntu kernels only), Ubuntu's
/// AppArmor restriction, and sandy's own AppArmor label. A host that passes can still refuse, for
/// example inside a container whose seccomp profile denies `unshare`, or under an AppArmor profile
/// without `userns`; `probe` and the run find those.
pub fn support() -> Support {
    let read = |path: &str| {
        std::fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
    };
    judge(&HostFacts {
        max_user_namespaces: read(MAX_USER_NAMESPACES),
        unprivileged_userns_clone: read(UNPRIVILEGED_USERNS_CLONE),
        apparmor_restriction: read(APPARMOR_RESTRICTION),
        label: read(APPARMOR_LABEL),
    })
}

/// The values `support` reads, `None` for a file that is missing or unreadable.
#[derive(Debug, Default)]
struct HostFacts {
    max_user_namespaces: Option<String>,
    unprivileged_userns_clone: Option<String>,
    apparmor_restriction: Option<String>,
    label: Option<String>,
}

/// The reason `plan` gives on Ubuntu 23.10 and newer, where the AppArmor restriction applies to
/// sandy. The plan adds that `sandy setup` prepares the host.
pub const APPARMOR_REASON: &str = "Ubuntu's AppArmor restriction of unprivileged user namespaces \
    (kernel.apparmor_restrict_unprivileged_userns = 1) applies to sandy, which runs unconfined: \
    the user namespace it creates gives it no rights, so it cannot set up the private network; an \
    AppArmor profile that allows sandy user namespaces lifts the restriction for sandy alone";

fn judge(facts: &HostFacts) -> Support {
    let disabled = |sysctl: &str| {
        Missing::Unavailable(format!(
            "user namespaces are disabled on this host ({sysctl} = 0), and ip = \"private\" needs \
             one to own the sandbox's network namespace"
        ))
    };
    if facts.max_user_namespaces.as_deref() == Some("0") {
        return Err(disabled("user.max_user_namespaces"));
    }
    if facts.unprivileged_userns_clone.as_deref() == Some("0") {
        return Err(disabled("kernel.unprivileged_userns_clone"));
    }
    // The restriction applies to unconfined processes. A confined one gets what its profile
    // says, which only a trial shows; the profile `sandy setup` installs is such a profile.
    if facts.apparmor_restriction.as_deref() == Some("1")
        && facts.label.as_deref() == Some("unconfined")
    {
        return Err(Missing::NeedsSetup(APPARMOR_REASON.to_string()));
    }
    Ok(())
}

/// Tries the steps of `enter` and `drop_capabilities` for `namespaces` in a forked child and
/// returns the first that fails. The namespaces end with the child, so the host keeps nothing of
/// it; on Ubuntu the kernel log keeps the AppArmor audit lines of the `unshare`. For `check`
/// (`Backend::verify`).
pub fn probe(namespaces: Namespaces) -> Result<(), String> {
    let (mut report, report_write) =
        helper::pipe("the namespace probe's pipe").map_err(|error| error.to_string())?;
    // SAFETY: the child has one thread, which `enter` checks, and the allocator stays usable after
    // fork in glibc and musl. It leaves only through `_exit`, never by returning into sandy's
    // code.
    let child = unsafe { libc::fork() };
    match child {
        -1 => {
            return Err(format!(
                "cannot fork the namespace probe: {}",
                io::Error::last_os_error()
            ));
        }
        0 => {
            drop(report);
            let tried = std::panic::catch_unwind(|| {
                namespaces
                    .enter()
                    .and_then(|()| drop_capabilities())
                    .map_err(|error| error.to_string())
            });
            let message = match tried {
                Ok(Ok(())) => String::new(),
                Ok(Err(message)) => message,
                Err(_) => "the namespace probe panicked".to_string(),
            };
            let mut report = report_write;
            let _ = report.write_all(message.as_bytes());
            // SAFETY: ends the child without running sandy's cleanup.
            unsafe { libc::_exit(i32::from(!message.is_empty())) }
        }
        _ => {}
    }
    drop(report_write);
    let mut message = String::new();
    let read = report.read_to_string(&mut message);
    let mut status = 0;
    // SAFETY: waits for the child forked above.
    unsafe { libc::waitpid(child, &mut status, 0) };
    if let Err(error) = read {
        return Err(format!("cannot read the namespace probe's report: {error}"));
    }
    match (
        message.is_empty(),
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
    ) {
        (true, true) => Ok(()),
        (false, _) => Err(message),
        (true, false) => Err(format!(
            "the namespace probe ended without a report (wait status {status})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        max: Option<&str>,
        clone: Option<&str>,
        restriction: Option<&str>,
        label: Option<&str>,
    ) -> HostFacts {
        HostFacts {
            max_user_namespaces: max.map(String::from),
            unprivileged_userns_clone: clone.map(String::from),
            apparmor_restriction: restriction.map(String::from),
            label: label.map(String::from),
        }
    }

    /// The hosts of the research: Fedora (no Ubuntu sysctls), Ubuntu 22.04 (restriction off) and
    /// Ubuntu 25.10 (restriction on, sandy unconfined).
    #[test]
    fn the_host_facts_decide_as_measured() {
        assert_eq!(judge(&facts(Some("255504"), None, None, None)), Ok(()));
        assert_eq!(
            judge(&facts(
                Some("15329"),
                Some("1"),
                Some("0"),
                Some("unconfined")
            )),
            Ok(())
        );
        assert_eq!(
            judge(&facts(
                Some("15275"),
                Some("1"),
                Some("1"),
                Some("unconfined")
            )),
            Err(Missing::NeedsSetup(APPARMOR_REASON.to_string()))
        );
        // A profile of sandy's own, as `sandy setup` installs it, leaves the answer to a trial.
        assert_eq!(
            judge(&facts(
                Some("15275"),
                Some("1"),
                Some("1"),
                Some("sandy (unconfined)")
            )),
            Ok(())
        );
    }

    #[test]
    fn disabled_user_namespaces_are_unavailable_not_a_matter_of_setup() {
        for (facts, sysctl) in [
            (
                facts(Some("0"), None, None, None),
                "user.max_user_namespaces",
            ),
            (
                facts(Some("100"), Some("0"), Some("1"), Some("unconfined")),
                "kernel.unprivileged_userns_clone",
            ),
        ] {
            match judge(&facts) {
                Err(Missing::Unavailable(reason)) => {
                    assert!(reason.contains(sysctl), "{reason}");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// What a host does not say rules nothing out; the trial of `check` and the run decide.
    #[test]
    fn missing_facts_rule_nothing_out() {
        assert_eq!(judge(&HostFacts::default()), Ok(()));
        assert_eq!(judge(&facts(None, None, Some("1"), None)), Ok(()));
    }

    /// The probe tries the real steps. On a host whose plan sees no obstacle they work, and on
    /// one with the AppArmor restriction they fail at the first map write.
    #[test]
    fn the_probe_agrees_with_the_host() {
        let tried = probe(Namespaces { network: true });
        match support() {
            Ok(()) if tried.is_err() => {
                // An outer sandbox can deny what the host allows; a trial is what finds that.
                eprintln!("skipped: the probe failed where the host allows it: {tried:?}");
            }
            Ok(()) => {}
            Err(Missing::NeedsSetup(_)) => {
                let error = tried.unwrap_err();
                assert!(error.contains("/proc/self/setgroups"), "{error}");
            }
            Err(Missing::Unavailable(_)) => assert!(tried.is_err()),
        }
    }

    /// After `enter` and `drop_capabilities` the process has the outside user and group IDs,
    /// no capability in any set, and an `lo` that takes a listener.
    #[test]
    fn the_namespace_maps_the_own_ids_and_leaves_no_capability() {
        if support().is_err() || probe(Namespaces { network: true }).is_err() {
            eprintln!("skipped: this host gives sandy no user namespace");
            return;
        }
        // SAFETY: getuid and getgid have no preconditions.
        let (user, group) = unsafe { (libc::getuid(), libc::getgid()) };
        // SAFETY: the child only runs the checks below and leaves through `_exit`.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let outcome = (|| {
                if (Namespaces { network: true }).enter().is_err() {
                    return 1;
                }
                if drop_capabilities().is_err() {
                    return 2;
                }
                let (mut real, mut effective, mut saved) = (0, 0, 0);
                // SAFETY: getresuid writes three IDs through valid pointers.
                unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) };
                // SAFETY: getgid has no preconditions.
                if [real, effective, saved] != [user; 3] || unsafe { libc::getgid() } != group {
                    return 3;
                }
                let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                let empty = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
                    .iter()
                    .all(|set| status.contains(&format!("{set}:\t0000000000000000")));
                if !empty {
                    return 4;
                }
                if std::net::TcpListener::bind("127.0.0.1:0").is_err() {
                    return 5;
                }
                0
            })();
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(outcome) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "step {}",
            libc::WEXITSTATUS(status)
        );
    }
}
