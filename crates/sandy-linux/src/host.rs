//! Detection of the kernel features and process state the backend depends on. Every function
//! here only reads state, so `plan` can call it.

use std::cell::{OnceCell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::ptr;

use sandy_core::{
    ChildProcesses, FileView, IpAccess, PlanItem, ProtectedPath, Requirement, ResolvedPolicy,
};

use crate::filter;
use crate::namespace::{self, Namespaces, TrialFailure};
use crate::plan;
use crate::system::{self, SystemPath};
use crate::trust;

/// `Ok` when a feature can be used, otherwise the reason why it cannot.
pub type Support = Result<(), String>;

/// Why a feature cannot be used here, by what it means for the choice of a fallback level
/// (`sandy_core::Status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// A lasting shortfall of this host that nothing `sandy setup` installs changes.
    Unavailable(String),
    /// A lasting shortfall that an AppArmor profile `sandy setup` installs lifts.
    NeedsSetup(String),
    /// A probe failed for a reason that can pass, so sandy cannot tell now.
    Indeterminate(String),
}

impl Missing {
    pub fn reason(&self) -> &str {
        match self {
            Missing::Unavailable(reason)
            | Missing::NeedsSetup(reason)
            | Missing::Indeterminate(reason) => reason,
        }
    }

    /// The same kind of shortfall, with another reason.
    pub fn because(&self, reason: String) -> Missing {
        match self {
            Missing::Unavailable(_) => Missing::Unavailable(reason),
            Missing::NeedsSetup(_) => Missing::NeedsSetup(reason),
            Missing::Indeterminate(_) => Missing::Indeterminate(reason),
        }
    }

    /// The plan item that reports it for `requirement`.
    pub fn item(&self, requirement: Requirement) -> PlanItem {
        match self {
            Missing::Unavailable(reason) => PlanItem::unavailable(requirement, reason),
            Missing::NeedsSetup(reason) => PlanItem::needs_setup(requirement, reason),
            Missing::Indeterminate(reason) => PlanItem::indeterminate(requirement, reason),
        }
    }

    /// The order of `EnforcementPlan::new`: what ends the selection before what lets sandy try
    /// the next level, and what setup cannot fix before what it can.
    fn rank(&self) -> u8 {
        match self {
            Missing::NeedsSetup(_) => 0,
            Missing::Unavailable(_) => 1,
            Missing::Indeterminate(_) => 2,
        }
    }
}

/// The worst of `missing` (`Missing::rank`), the first of them among equals, `None` when nothing
/// is missing.
pub fn worst(missing: impl IntoIterator<Item = Option<Missing>>) -> Option<Missing> {
    missing.into_iter().flatten().reduce(|worst, next| {
        if next.rank() > worst.rank() {
            next
        } else {
            worst
        }
    })
}

/// What this host and this process offer. `plan_for` turns it into a plan without further I/O,
/// so tests can describe any host.
#[derive(Debug, Clone)]
pub struct HostCapabilities {
    /// The Landlock ABI version the kernel reports.
    pub landlock: Result<i32, String>,
    /// The Landlock errata the kernel reports fixed, as the kernel's bitmask (erratum N is bit
    /// N - 1), or why it reports none.
    pub landlock_errata: Result<u64, String>,
    /// Whether sandy can count its threads, which it must do before Landlock restricts it.
    pub thread_count: Result<(), Missing>,
    /// Seccomp filters with the actions the filter uses, for this CPU architecture.
    pub seccomp: Support,
    pub no_new_privs: Support,
    /// `Err` when the process runs as root or holds capabilities.
    pub unprivileged: Support,
    /// pidfd_open, which the relay uses to watch the program and the guard of
    /// `children = "contained"` uses to watch the program.
    pub pidfd: Support,
    /// Whether sandy may put a process into a process group, which `children = "contained"`
    /// needs. Only probed for a policy that needs it (`Detected::for_policy`).
    pub process_group: Support,
    /// Whether the host rules out the namespaces of `ip = "private"` and `filesystem.view =
    /// "policy"`, as far as it says, and else whether a trial of them works. Only read for a
    /// policy that needs them (`Detected::for_policy`).
    pub user_namespaces: namespace::Support,
    /// Whether `children = "contained"` gets a PID namespace here, or why not. Only read for a
    /// policy whose run would use one (`Detected::for_policy`).
    pub pid_namespace: namespace::Support,
    /// Whether the kernel names the owner of the other end of a loopback connection
    /// (`inet_diag`), which the relay of a forwarded port asks to refuse other users wherever
    /// the program has no private network. Only probed for a policy that needs it
    /// (`Detected::for_policy`).
    pub peer_lookup: Result<(), Missing>,
    /// The candidates of the minimal system set that exist on this host.
    pub system_paths: Vec<SystemPath>,
    /// Where every candidate of the minimal system set is or would be, also missing ones.
    pub system_locations: Vec<SystemPath>,
    /// The locations of this user that programs outside the sandbox read or execute later, or
    /// why sandy cannot name them: no source names the home directory.
    pub trusted_locations: Result<Vec<ProtectedPath>, String>,
    /// The directories on sandy's PATH and the usual ones of the user's PATH, which only warn
    /// (rule 12).
    pub path_locations: Vec<ProtectedPath>,
}

impl HostCapabilities {
    /// What this host offers whatever the policy asks for.
    pub fn detect() -> Self {
        HostCapabilities {
            landlock: landlock_abi(),
            landlock_errata: landlock_errata(),
            thread_count: thread_count_support(),
            pidfd: pidfd_support(),
            process_group: Ok(()),
            user_namespaces: Ok(()),
            pid_namespace: Ok(()),
            peer_lookup: Ok(()),
            seccomp: seccomp_support(),
            no_new_privs: no_new_privs_support(),
            unprivileged: unprivileged(),
            system_paths: system::detect(),
            system_locations: system::locations(),
            trusted_locations: trust::locations(),
            path_locations: trust::path_locations(),
        }
    }
}

/// The probes behind `HostCapabilities`, as a trait so that a test can count them.
pub(crate) trait Probes: std::fmt::Debug {
    /// What this host offers whatever the policy asks for (`HostCapabilities::detect`).
    fn common(&self) -> HostCapabilities;
    /// Whether sandy may put a process into a process group (`process_group_support`).
    fn process_group(&self) -> Support;
    /// What the host says about user namespaces without a trial.
    fn namespace_facts(&self) -> namespace::HostFacts;
    /// A trial of `namespaces` in a forked child (`namespace::probe`).
    fn trial(&self, namespaces: Namespaces) -> Result<(), TrialFailure>;
    /// Whether the kernel names the owner of a loopback connection (`PeerCheck::probe`).
    fn peer_lookup(&self) -> Result<(), Missing>;
}

/// The probes of this host.
#[derive(Debug)]
pub(crate) struct ThisHost;

impl Probes for ThisHost {
    fn common(&self) -> HostCapabilities {
        HostCapabilities::detect()
    }

    fn process_group(&self) -> Support {
        process_group_support()
    }

    fn namespace_facts(&self) -> namespace::HostFacts {
        namespace::HostFacts::read()
    }

    fn trial(&self, namespaces: Namespaces) -> Result<(), TrialFailure> {
        namespace::probe(namespaces)
    }

    fn peer_lookup(&self) -> Result<(), Missing> {
        crate::peer::PeerCheck::probe()
    }
}

/// What one backend value has found out about this host. Each property is detected at most
/// once, the first time a policy needs it, and kept, so every level that one invocation plans,
/// the notes and explanations of the selected one, and its run see the same host (`Backend`): a
/// probe that fails for a moment cannot fail for one level and pass for the next. A probe that
/// only some policies need runs only for them: it is a system call that a sandbox around sandy
/// can answer with SIGSYS, so it must not run for a level that never makes it.
#[derive(Debug)]
pub(crate) struct Detected {
    probes: Box<dyn Probes>,
    common: OnceCell<HostCapabilities>,
    process_group: OnceCell<Support>,
    namespace_facts: OnceCell<namespace::HostFacts>,
    trials: RefCell<BTreeMap<Namespaces, Result<(), TrialFailure>>>,
    peer_lookup: OnceCell<Result<(), Missing>>,
}

impl Detected {
    pub(crate) fn new(probes: Box<dyn Probes>) -> Detected {
        Detected {
            probes,
            common: OnceCell::new(),
            process_group: OnceCell::new(),
            namespace_facts: OnceCell::new(),
            trials: RefCell::new(BTreeMap::new()),
            peer_lookup: OnceCell::new(),
        }
    }

    /// What this host offers whatever the policy asks for.
    pub(crate) fn common(&self) -> HostCapabilities {
        self.common.get_or_init(|| self.probes.common()).clone()
    }

    /// `common` plus the probes that `policy` needs.
    pub(crate) fn for_policy(&self, policy: &ResolvedPolicy) -> HostCapabilities {
        let mut host = self.common();
        if policy.children == ChildProcesses::Contained {
            host.process_group = self
                .process_group
                .get_or_init(|| self.probes.process_group())
                .clone();
        }
        let private = policy.ip == IpAccess::Private;
        let hidden = policy.view == FileView::Policy;
        let pid = plan::wants_pid_namespace(policy);
        if private || hidden {
            // The run asks for every namespace in one `unshare`, so the trial does too.
            let namespaces = Namespaces {
                network: private,
                mount: hidden,
                pid,
            };
            host.user_namespaces = namespace::judge(self.facts(), namespace::Purpose::of(policy))
                .and_then(|()| self.tried(namespaces, "a trial of the sandbox's namespaces"));
            if pid {
                host.pid_namespace = host.user_namespaces.clone();
            }
        } else if pid {
            host.pid_namespace = self.pid_namespace();
        }
        if !policy.forward.is_empty() && !private {
            host.peer_lookup = self
                .peer_lookup
                .get_or_init(|| self.probes.peer_lookup())
                .clone();
        }
        host
    }

    fn facts(&self) -> &namespace::HostFacts {
        self.namespace_facts
            .get_or_init(|| self.probes.namespace_facts())
    }

    /// The kept trial of `namespaces`, called `what` in the reason, by what it says about the
    /// host (`TrialFailure::missing`).
    fn tried(&self, namespaces: Namespaces, what: &str) -> namespace::Support {
        let known = self.trials.borrow().get(&namespaces).cloned();
        let tried = known.unwrap_or_else(|| {
            let tried = self.probes.trial(namespaces);
            self.trials.borrow_mut().insert(namespaces, tried.clone());
            tried
        });
        tried.map_err(|failure| failure.missing(what, self.facts().zero_limit(namespaces)))
    }

    /// Whether `children = "contained"` alone gets a PID namespace. It only adds to the process
    /// group, which holds the program's processes as before, so it is used only where a trial in
    /// a forked child works: a host that allows user namespaces and still denies them to sandy, a
    /// container whose seccomp profile denies `unshare` for one, keeps `contained` as it is.
    /// What can pass is indeterminate instead, so that it never swaps one mechanism for the other.
    fn pid_namespace(&self) -> namespace::Support {
        namespace::judge(self.facts(), namespace::Purpose::Processes)?;
        let namespaces = Namespaces {
            network: false,
            mount: false,
            pid: true,
        };
        self.tried(namespaces, "a trial of a PID namespace")
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
const LANDLOCK_CREATE_RULESET_ERRATA: libc::c_uint = 2;

/// The errata bitmask of `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ERRATA)`
/// (measured: 0x5 on Ubuntu 22.04's Linux 6.8, 0x7 on 6.17, 0xf on 7.2). A kernel without the
/// flag answers EINVAL, which says nothing about which fixes it has.
fn landlock_errata() -> Result<u64, String> {
    // SAFETY: with a null attribute, size 0 and the ERRATA flag, the kernel only returns the
    // bitmask and creates nothing.
    let errata = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_ERRATA,
        )
    };
    if errata >= 0 {
        return Ok(errata as u64);
    }
    Err(format!(
        "this kernel does not report which Landlock errata it has fixed ({})",
        io::Error::last_os_error()
    ))
}

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

fn thread_count_support() -> Result<(), Missing> {
    std::fs::read_dir(THREADS_DIR)
        .map(|_| ())
        .map_err(unlisted_threads)
}

/// Why sandy cannot count its threads. Without `/proc` that lasts; any other error, such as a
/// full descriptor table or no memory, can pass.
fn unlisted_threads(error: io::Error) -> Missing {
    let reason = format!(
        "cannot list {THREADS_DIR}, which sandy needs to verify that it is single-threaded \
         before Landlock restricts it: {error}"
    );
    match error.kind() {
        io::ErrorKind::NotFound => Missing::Unavailable(reason),
        _ => Missing::Indeterminate(reason),
    }
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

pub(crate) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
pub(crate) struct CapHeader {
    pub(crate) version: u32,
    pub(crate) pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CapData {
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

/// Probes that answer as a test says and record which of them ran.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct Recording {
    /// The probes that ran, in order, shared with the test that boxed these probes.
    pub(crate) ran: std::rc::Rc<RefCell<Vec<String>>>,
    /// What every trial answers.
    pub(crate) trial: Result<(), TrialFailure>,
    /// What the host says about user namespaces.
    pub(crate) facts: namespace::HostFacts,
    /// What the lookup of a loopback connection's owner answers.
    pub(crate) peer_lookup: Result<(), Missing>,
}

#[cfg(test)]
impl Recording {
    pub(crate) fn new() -> Recording {
        Recording {
            ran: Default::default(),
            trial: Ok(()),
            facts: namespace::HostFacts::default(),
            peer_lookup: Ok(()),
        }
    }

    pub(crate) fn ran(&self) -> Vec<String> {
        self.ran.borrow().clone()
    }

    fn record(&self, probe: String) {
        self.ran.borrow_mut().push(probe);
    }
}

#[cfg(test)]
impl Probes for Recording {
    fn common(&self) -> HostCapabilities {
        self.record("common".to_string());
        HostCapabilities::detect()
    }

    fn process_group(&self) -> Support {
        self.record("process group".to_string());
        Ok(())
    }

    fn namespace_facts(&self) -> namespace::HostFacts {
        self.record("namespace facts".to_string());
        self.facts.clone()
    }

    fn trial(&self, namespaces: Namespaces) -> Result<(), TrialFailure> {
        self.record(format!("trial {namespaces:?}"));
        self.trial.clone()
    }

    fn peer_lookup(&self) -> Result<(), Missing> {
        self.record("peer lookup".to_string());
        self.peer_lookup.clone()
    }
}

/// A resolved policy from the TOML `text`, without paths or a program, so it resolves on any
/// host.
#[cfg(test)]
pub(crate) fn resolved(text: &str) -> ResolvedPolicy {
    let policy = sandy_core::Policy::from_toml(&format!("version = 1\n{text}")).unwrap();
    ResolvedPolicy::resolve(&policy, None).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINED: &str = "[process]\nchildren = \"contained\"\nsignals = \"isolated\"";

    /// Each probe runs once, when the first policy needs it, and every later policy that needs
    /// it gets the kept answer.
    #[test]
    fn a_second_policy_reuses_the_answers() {
        let probes = Recording::new();
        let detected = Detected::new(Box::new(probes.clone()));
        let contained = resolved(CONTAINED);
        let private = resolved(&format!("{CONTAINED}\n[network]\nip = \"private\""));

        let first = detected.for_policy(&contained);
        assert_eq!(
            probes.ran(),
            [
                "common",
                "process group",
                "namespace facts",
                "trial Namespaces { network: false, mount: false, pid: true }",
            ]
        );
        let again = detected.for_policy(&contained);
        assert_eq!(format!("{first:?}"), format!("{again:?}"));
        // The private network tries its own set of namespaces, once.
        detected.for_policy(&private);
        detected.for_policy(&private);
        detected.for_policy(&contained);
        detected.common();
        assert_eq!(
            probes.ran()[4..],
            ["trial Namespaces { network: true, mount: false, pid: true }"]
        );
    }

    /// The owner lookup runs once, and only for a policy whose relay asks it: one with a
    /// forwarded port outside the private network, where nothing else keeps other users from
    /// the forward's listeners.
    #[test]
    fn only_a_forward_outside_the_private_network_looks_up_owners() {
        let probes = Recording::new();
        let detected = Detected::new(Box::new(probes.clone()));
        let forward = "forward = [{ port = 18082, to = \"127.0.0.1:8082\" }]";
        let lookups = || {
            probes
                .ran()
                .iter()
                .filter(|probe| *probe == "peer lookup")
                .count()
        };
        detected.for_policy(&resolved("[network]\nip = \"client\""));
        detected.for_policy(&resolved(&format!(
            "[network]\nip = \"private\"\n{forward}"
        )));
        assert_eq!(lookups(), 0, "{:?}", probes.ran());
        let client =
            detected.for_policy(&resolved(&format!("[network]\nip = \"client\"\n{forward}")));
        detected.for_policy(&resolved(&format!("[network]\nip = \"all\"\n{forward}")));
        assert_eq!(lookups(), 1, "{:?}", probes.ran());
        assert_eq!(client.peer_lookup, Ok(()));
    }

    /// The owner lookup works on this host, as the relay finds it.
    #[test]
    fn this_kernel_names_the_owner_of_a_loopback_connection() {
        crate::peer::PeerCheck::probe().unwrap();
    }

    /// A trial that fails for a reason that can pass makes the namespaces indeterminate, also
    /// the PID namespace of `contained` alone, and one that the kernel refuses for good makes
    /// them unavailable. What the host says comes first: under the AppArmor restriction no
    /// trial runs.
    #[test]
    fn a_trial_decides_by_what_it_says_about_the_host() {
        let failed = |errno| {
            Err(TrialFailure::Step {
                message: "cannot fork into the sandbox's PID namespace".to_string(),
                errno: Some(errno),
            })
        };
        let contained = resolved(CONTAINED);
        let private = resolved("[network]\nip = \"private\"");
        for (trial, lasting) in [(failed(libc::EAGAIN), false), (failed(libc::EPERM), true)] {
            let mut probes = Recording::new();
            probes.trial = trial;
            let detected = Detected::new(Box::new(probes));
            let pid = detected.for_policy(&contained).pid_namespace.unwrap_err();
            let user = detected.for_policy(&private).user_namespaces.unwrap_err();
            for (missing, what) in [
                (pid, "a trial of a PID namespace failed: cannot fork"),
                (
                    user,
                    "a trial of the sandbox's namespaces failed: cannot fork",
                ),
            ] {
                assert!(missing.reason().starts_with(what), "{missing:?}");
                assert_eq!(
                    matches!(missing, Missing::Unavailable(_)),
                    lasting,
                    "{missing:?}"
                );
                assert_eq!(matches!(missing, Missing::Indeterminate(_)), !lasting);
            }
        }

        let mut probes = Recording::new();
        probes.facts = namespace::HostFacts::under_apparmor_restriction();
        let detected = Detected::new(Box::new(probes.clone()));
        let missing = detected.for_policy(&private).user_namespaces.unwrap_err();
        assert!(matches!(missing, Missing::NeedsSetup(_)), "{missing:?}");
        let missing = detected.for_policy(&contained).pid_namespace.unwrap_err();
        assert!(matches!(missing, Missing::NeedsSetup(_)), "{missing:?}");
        assert!(!probes.ran().iter().any(|probe| probe.starts_with("trial")));
    }

    /// Without `/proc` the thread list is missing for good; any other error can pass.
    #[test]
    fn an_unreadable_thread_list_is_unavailable_only_without_proc() {
        let unlisted = |errno| unlisted_threads(io::Error::from_raw_os_error(errno));
        assert!(
            matches!(unlisted(libc::ENOENT), Missing::Unavailable(reason) if reason.contains(THREADS_DIR))
        );
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::EACCES] {
            assert!(
                matches!(unlisted(errno), Missing::Indeterminate(_)),
                "{errno}"
            );
        }
    }

    /// One requirement that misses several things reports the one that weighs most, as the
    /// core does: an indeterminate one before a lasting one, which comes before one that setup
    /// fixes; among equals the first.
    #[test]
    fn the_worst_missing_thing_wins() {
        let setup = || Some(Missing::NeedsSetup("setup".into()));
        let lasting = |reason: &str| Some(Missing::Unavailable(reason.into()));
        let passing = || Some(Missing::Indeterminate("passing".into()));
        assert_eq!(worst([None, None]), None);
        assert_eq!(worst([setup(), lasting("a"), None]), lasting("a"));
        assert_eq!(worst([lasting("a"), lasting("b")]), lasting("a"));
        assert_eq!(worst([lasting("a"), passing(), setup()]), passing());
        assert_eq!(worst([setup(), None]), setup());
    }

    /// A policy that needs no process group, user namespace or PID namespace makes none of
    /// their probes.
    #[test]
    fn probes_run_only_for_the_policies_that_need_them() {
        let probes = Recording::new();
        let detected = Detected::new(Box::new(probes.clone()));
        detected.for_policy(&resolved(""));
        detected.for_policy(&resolved("[process]\nsignals = \"isolated\""));
        assert_eq!(probes.ran(), ["common"]);
        // contained with /proc granted gets no PID namespace, so it tries none.
        let mut with_proc = resolved(CONTAINED);
        with_proc.paths.push(sandy_core::PathRule {
            path: "/proc".into(),
            access: sandy_core::PathAccess::Read,
            is_dir: true,
        });
        detected.for_policy(&with_proc);
        assert_eq!(probes.ran(), ["common", "process group"]);
    }

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
