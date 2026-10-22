//! The seccomp filters. sandy installs two filters; the kernel applies the stricter result:
//!
//! 1. The allowlist allows the system calls of the reviewed kernel table. Every other number,
//!    including x32 numbers and system calls of newer kernels, fails with ENOSYS. Programs treat
//!    that like an older kernel. A call of another CPU architecture kills the process.
//! 2. The denylist checks arguments and denies single system calls with EPERM.
//!
//! seccompiler compiles both. Numbers come from `libc::SYS_*`, so sandy controls the table.

use std::collections::BTreeMap;

use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterConfig {
    /// Allow AF_INET, AF_INET6 and route netlink sockets.
    pub allow_ip: bool,
    /// Allow AF_UNIX sockets and socket pairs of every type.
    pub allow_unix: bool,
    /// Deny the ways to truncate a file without write access. Landlock checks truncation only
    /// since ABI 3.
    pub restrict_truncate: bool,
    /// Deny the metadata calls that take a path.
    pub deny_path_metadata: bool,
    /// Deny creating processes; threads stay allowed.
    pub deny_children: bool,
}

#[cfg(target_arch = "x86_64")]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::x86_64);
    /// The x86_64 table of Linux 7.2 (arch/x86/entry/syscalls/syscall_64.tbl). Numbers 337 to
    /// 423 are not assigned.
    pub const REVIEWED: &[(i64, i64)] = &[(0, 336), (424, 471)];
    /// kexec_file_load, capability-gated port and segment access, and old exploit helpers.
    pub const DENIED: &[i64] = &[
        libc::SYS_kexec_file_load,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_modify_ldt,
        libc::SYS_uselib,
    ];
    /// Metadata calls by path that newer architectures only have as `*at` calls.
    pub const PATH_METADATA: &[i64] = &[
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ];
    /// System calls that open a path, with the index of their flags argument.
    pub const OPEN_CALLS: &[(i64, u8)] = &[(libc::SYS_open, 1), (libc::SYS_openat, 2)];
    /// chmod variants that only x86_64 has, with the index of their mode argument.
    pub const CHMOD_CALLS: &[(i64, u8)] = &[(libc::SYS_chmod, 1)];
    /// Calls the relay needs that only x86_64 has (arm64 has only ppoll).
    pub const RELAY_CALLS: &[i64] = &[libc::SYS_poll];
    /// System calls that create a process without arguments to check; arm64 has only clone.
    pub const FORK_CALLS: &[i64] = &[libc::SYS_fork, libc::SYS_vfork];
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::aarch64);
    /// The generic table (include/uapi/asm-generic/unistd.h) of Linux 7.2 for 64-bit arm64.
    /// 244 to 259 are reserved for architecture-specific calls, which arm64 does not have.
    /// 403 to 423 exist only for 32-bit ABIs.
    pub const REVIEWED: &[(i64, i64)] = &[(0, 243), (260, 294), (424, 471)];
    /// kexec_file_load, which the libc crate lacks for musl on arm64.
    pub const DENIED: &[i64] = &[294];
    pub const PATH_METADATA: &[i64] = &[];
    pub const OPEN_CALLS: &[(i64, u8)] = &[(libc::SYS_openat, 2)];
    pub const CHMOD_CALLS: &[(i64, u8)] = &[];
    pub const RELAY_CALLS: &[i64] = &[];
    pub const FORK_CALLS: &[i64] = &[];
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = None;
    pub const REVIEWED: &[(i64, i64)] = &[];
    pub const DENIED: &[i64] = &[];
    pub const PATH_METADATA: &[i64] = &[];
    pub const OPEN_CALLS: &[(i64, u8)] = &[];
    pub const CHMOD_CALLS: &[(i64, u8)] = &[];
    pub const RELAY_CALLS: &[i64] = &[];
    pub const FORK_CALLS: &[i64] = &[];
}

/// Whether sandy has a filter for the CPU architecture it was built for.
pub const ARCH_SUPPORTED: bool = arch::TARGET.is_some();

// Numbers from 424 upward are the same on every architecture. The libc crate does not have
// these yet for every target.
const SYS_FCHMODAT2: i64 = 452;
const SYS_SETXATTRAT: i64 = 463;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;
const SYS_OPEN_TREE_ATTR: i64 = 467;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_LISTNS: i64 = 470;

/// Denied with EPERM under every policy.
const DENIED: &[i64] = &[
    // io_uring operations do not pass through seccomp, so they would bypass the socket rules.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // Access to other processes. Landlock already limits these to the sandbox.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_getfd,
    libc::SYS_kcmp,
    libc::SYS_process_madvise,
    // System V IPC objects and POSIX message queues belong to all processes of the user, and
    // Landlock does not cover them. Shared memory would give access to the memory of processes
    // outside the sandbox.
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_shmdt,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semtimedop,
    libc::SYS_semctl,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    // Namespaces expose kernel interfaces that are otherwise reserved for root.
    libc::SYS_setns,
    // Mounts. Landlock denies most of them already.
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    SYS_OPEN_TREE_ATTR,
    libc::SYS_mount_setattr,
    // Mount and namespace topology of the host, which leaving out /proc otherwise hides
    // (/proc/self/mountinfo, /proc/*/ns).
    SYS_STATMOUNT,
    SYS_LISTMOUNT,
    SYS_LISTNS,
    // Kernel attack surface that exploits often use.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    // The keyrings of the user are shared by all processes of the user.
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    // These need capabilities, which sandy never passes on. A second layer.
    libc::SYS_kexec_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_quotactl,
    libc::SYS_quotactl_fd,
    libc::SYS_syslog,
    libc::SYS_open_by_handle_at,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
];

/// Landlock does not restrict metadata changes. The descriptor variants (fchmod, fchown,
/// fsetxattr, fremovexattr, futimens) stay allowed: they reject O_PATH descriptors, so they only
/// reach files that Landlock let the program open. fchmodat, fchmodat2 and fchownat accept
/// O_PATH descriptors with AT_EMPTY_PATH, so they are denied completely. utimensat has its own
/// rule.
const PATH_METADATA: &[i64] = &[
    libc::SYS_fchmodat,
    SYS_FCHMODAT2,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    SYS_SETXATTRAT,
    SYS_REMOVEXATTRAT,
    SYS_FILE_SETATTR,
];

/// Not in the allowlist, so they fail with ENOSYS. Their arguments are in memory, where seccomp
/// cannot check them, and programs fall back to another call on ENOSYS: glibc uses clone instead
/// of clone3, and openat2 callers use openat.
const ENOSYS_CALLS: &[i64] = &[libc::SYS_clone3, libc::SYS_openat2];

/// The namespace flags of clone. CLONE_NEWTIME shares its bit with the exit signal of clone, so
/// only unshare checks it.
const CLONE_NAMESPACES: &[i32] = &[
    libc::CLONE_NEWNS,
    libc::CLONE_NEWCGROUP,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWNET,
];

/// The personality values that Docker's default profile allows: PER_LINUX, PER_LINUX32,
/// UNAME26, PER_LINUX32 | UNAME26, and the query value.
const PERSONALITIES: &[u64] = &[0, 0x8, 0x2_0000, 0x2_0008, 0xffff_ffff];

/// System calls that change another process, with the index of their process ID argument.
/// Process ID 0 means the caller.
const PROCESS_CALLS: &[(i64, u8)] = &[
    (libc::SYS_prlimit64, 0),
    (libc::SYS_sched_setaffinity, 0),
    (libc::SYS_sched_setscheduler, 0),
    (libc::SYS_sched_setparam, 0),
    (libc::SYS_sched_setattr, 0),
];

/// System calls with a "which" and a "who" argument, with the "which" value that selects one
/// process. The other values select a process group or every process of a user.
const PROCESS_SELECTOR_CALLS: &[(i64, u64)] = &[
    (libc::SYS_setpriority, libc::PRIO_PROCESS as u64),
    (libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS),
];
const IOPRIO_WHO_PROCESS: u64 = 1;

const NETLINK_ROUTE: u64 = 0;
const SOCK_TYPE_MASK: u64 = 0xf;

/// The two compiled filters, in the order they are installed.
#[derive(Debug)]
pub struct Filters {
    pub allowlist: BpfProgram,
    pub denylist: BpfProgram,
}

/// Builds the filters for `config` and the CPU architecture sandy was built for. `own_pid` is
/// the process ID of sandy, which the target keeps after execve.
pub fn build(config: &FilterConfig, own_pid: u32) -> Result<Filters, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    Ok(Filters {
        allowlist: allowlist(target)?,
        denylist: denylist(config, own_pid, target)?,
    })
}

fn allowlist(target: TargetArch) -> Result<BpfProgram, BackendError> {
    let rules: BTreeMap<i64, Vec<SeccompRule>> = arch::REVIEWED
        .iter()
        .flat_map(|&(first, last)| first..=last)
        .filter(|call| !ENOSYS_CALLS.contains(call))
        .map(|call| (call, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        target,
    )?;
    filter.try_into()
}

/// A condition on the low 32 bits of an argument. The kernel reads int and unsigned int
/// arguments (socket family, ioctl command, clone flags, open flags) from these bits only, so a
/// check of all 64 bits could be bypassed by setting the high bits.
fn low(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, BackendError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, BackendError> {
    SeccompRule::new(conditions)
}

fn denylist(
    config: &FilterConfig,
    own_pid: u32,
    target: TargetArch,
) -> Result<BpfProgram, BackendError> {
    let mut rules = Rules::default();
    for &call in DENIED.iter().chain(arch::DENIED) {
        rules.add(call, Vec::new());
    }
    rules.add(libc::SYS_ioctl, ioctl_rules()?);
    rules.add(libc::SYS_socket, socket_rules(config)?);
    rules.add(libc::SYS_socketpair, socketpair_rules(config)?);
    let mut clone = namespace_rules(CLONE_NAMESPACES)?;
    if config.deny_children {
        // Only a thread (CLONE_THREAD) stays possible. The flags are the first argument of clone
        // on x86_64 and arm64. clone3 already fails with ENOSYS, so libc falls back to clone,
        // also for posix_spawn (CLONE_VM | CLONE_VFORK), which this denies.
        let thread = libc::CLONE_THREAD as u64;
        clone.push(rule(vec![low(0, SeccompCmpOp::MaskedEq(thread), 0)?])?);
        for &call in arch::FORK_CALLS {
            rules.add(call, Vec::new());
        }
    }
    rules.add(libc::SYS_clone, clone);
    let unshare: Vec<i32> = [CLONE_NAMESPACES, &[libc::CLONE_NEWTIME]].concat();
    rules.add(libc::SYS_unshare, namespace_rules(&unshare)?);
    let personality = PERSONALITIES
        .iter()
        .map(|&value| low(0, SeccompCmpOp::Ne, value))
        .collect::<Result<_, _>>()?;
    rules.add(libc::SYS_personality, vec![rule(personality)?]);
    if config.deny_path_metadata {
        for &call in PATH_METADATA.iter().chain(arch::PATH_METADATA) {
            rules.add(call, Vec::new());
        }
        // utimensat with a NULL path changes the descriptor itself (futimens).
        let path = SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Ne, 0)?;
        rules.add(libc::SYS_utimensat, vec![rule(vec![path])?]);
    }
    rules.add(libc::SYS_fchmod, setid_rules(1)?);
    if !config.deny_path_metadata {
        for &(call, mode) in [(libc::SYS_fchmodat, 2), (SYS_FCHMODAT2, 2)]
            .iter()
            .chain(arch::CHMOD_CALLS)
        {
            rules.add(call, setid_rules(mode)?);
        }
    }
    let own_pid = u64::from(own_pid);
    for &(call, pid) in PROCESS_CALLS {
        rules.add(call, vec![other_process(pid, own_pid)?]);
    }
    for &(call, one_process) in PROCESS_SELECTOR_CALLS {
        let group_or_user = rule(vec![low(0, SeccompCmpOp::Ne, one_process)?])?;
        rules.add(call, vec![group_or_user, other_process(1, own_pid)?]);
    }
    for &(call, flags) in arch::OPEN_CALLS {
        rules.add(call, open_rules(flags, config.restrict_truncate)?);
    }
    if config.restrict_truncate {
        rules.add(libc::SYS_truncate, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules.0,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target,
    )?;
    filter.try_into()
}

/// Rules keyed by system call. A rule list matches when any rule matches; an empty list matches
/// every call.
#[derive(Default)]
struct Rules(BTreeMap<i64, Vec<SeccompRule>>);

impl Rules {
    fn add(&mut self, call: i64, rules: Vec<SeccompRule>) {
        let previous = self.0.insert(call, rules);
        assert!(previous.is_none(), "system call {call} has two rule lists");
    }
}

/// TIOCSTI and TIOCLINUX can push input into the terminal of the user, where a shell outside the
/// sandbox would run it.
fn ioctl_rules() -> Result<Vec<SeccompRule>, BackendError> {
    [libc::TIOCSTI as u32, libc::TIOCLINUX as u32]
        .into_iter()
        .map(|command| rule(vec![low(1, SeccompCmpOp::Eq, u64::from(command))?]))
        .collect()
}

/// An allowlist of socket families. A denylist of AF_INET and AF_INET6 is not enough: other
/// families, for example AF_SMC, fall back to TCP.
fn socket_rules(config: &FilterConfig) -> Result<Vec<SeccompRule>, BackendError> {
    let mut allowed = Vec::new();
    if config.allow_unix {
        allowed.push(libc::AF_UNIX);
    }
    if config.allow_ip {
        allowed.extend([libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK]);
    }
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    let other_family = allowed
        .iter()
        .map(|&family| low(0, SeccompCmpOp::Ne, family as u64))
        .collect::<Result<_, _>>()?;
    let mut rules = vec![rule(other_family)?];
    if config.allow_ip {
        // Route netlink lets the C library list interfaces and addresses. Other netlink
        // protocols expose, for example, every socket of the host (sock_diag).
        rules.push(rule(vec![
            low(0, SeccompCmpOp::Eq, libc::AF_NETLINK as u64)?,
            low(2, SeccompCmpOp::Ne, NETLINK_ROUTE)?,
        ])?);
    }
    Ok(rules)
}

/// A connected stream or seqpacket pair cannot reach anything outside the sandbox. A datagram
/// socket can send to any address, also from a pair. AF_UNIX treats SOCK_RAW like SOCK_DGRAM
/// and rejects every other type.
fn socketpair_rules(config: &FilterConfig) -> Result<Vec<SeccompRule>, BackendError> {
    let other_family = low(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?;
    let mut rules = vec![rule(vec![other_family])?];
    if !config.allow_unix {
        for kind in [libc::SOCK_DGRAM, libc::SOCK_RAW] {
            let condition = low(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), kind as u64)?;
            rules.push(rule(vec![condition])?);
        }
    }
    Ok(rules)
}

/// A file with the setuid or setgid bit runs with the rights of this user when another local
/// user runs it. Writing to a file clears both bits, so only the chmod calls can set them on a
/// file with content.
fn setid_rules(mode: u8) -> Result<Vec<SeccompRule>, BackendError> {
    [libc::S_ISUID, libc::S_ISGID]
        .into_iter()
        .map(|bit| {
            let bit = u64::from(bit);
            rule(vec![low(mode, SeccompCmpOp::MaskedEq(bit), bit)?])
        })
        .collect()
}

/// Matches a process ID argument that names neither the caller (0) nor the target. Children of
/// the target therefore cannot use these calls on each other, and a thread ID other than the
/// main thread's counts as another process.
fn other_process(pid: u8, own_pid: u64) -> Result<SeccompRule, BackendError> {
    rule(vec![
        low(pid, SeccompCmpOp::Ne, 0)?,
        low(pid, SeccompCmpOp::Ne, own_pid)?,
    ])
}

/// One rule per flag, because a rule matches only when all its conditions match.
fn namespace_rules(flags: &[i32]) -> Result<Vec<SeccompRule>, BackendError> {
    flags
        .iter()
        .map(|&flag| {
            let flag = flag as u64;
            rule(vec![low(0, SeccompCmpOp::MaskedEq(flag), flag)?])
        })
        .collect()
}

/// Access mode 3 opens a file for ioctl only. Landlock requires no right for such an open, and
/// fchmod, fchown and fsetxattr work on the descriptor, so it would bypass both Landlock and the
/// metadata rules. Before Landlock ABI 3, O_TRUNC also truncates a file that is opened read-only,
/// without a Landlock check.
fn open_rules(flags: u8, restrict_truncate: bool) -> Result<Vec<SeccompRule>, BackendError> {
    let accmode = libc::O_ACCMODE as u64;
    let ioctl_only = low(flags, SeccompCmpOp::MaskedEq(accmode), accmode)?;
    let mut rules = vec![rule(vec![ioctl_only])?];
    if restrict_truncate {
        let trunc = libc::O_TRUNC as u64;
        let read_only_trunc = low(
            flags,
            SeccompCmpOp::MaskedEq(accmode | trunc),
            trunc | libc::O_RDONLY as u64,
        )?;
        rules.push(rule(vec![read_only_trunc])?);
    }
    Ok(rules)
}

/// What the relay for exposed ports needs: accept and connect TCP, copy bytes, start threads,
/// wait for the program to end, and report an error on standard error. Everything else fails with
/// EPERM. clone3 is listed so that the shared allowlist, installed with it, decides: ENOSYS.
const RELAY_CALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_shutdown,
    libc::SYS_getsockopt,
    libc::SYS_fcntl,
    libc::SYS_ppoll,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_clone3,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_getrandom,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// Builds the filters of the relay: the shared allowlist and the relay's own list, which allows
/// only `RELAY_CALLS`, TCP sockets, thread creation without namespaces, and FIONBIO.
pub fn relay() -> Result<Filters, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    let mut rules = Rules::default();
    for &call in RELAY_CALLS.iter().chain(arch::RELAY_CALLS) {
        rules.add(call, Vec::new());
    }
    let tcp = |family: i32| -> Result<SeccompRule, BackendError> {
        rule(vec![
            low(0, SeccompCmpOp::Eq, family as u64)?,
            low(
                1,
                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                libc::SOCK_STREAM as u64,
            )?,
        ])
    };
    rules.add(
        libc::SYS_socket,
        vec![tcp(libc::AF_INET)?, tcp(libc::AF_INET6)?],
    );
    let namespaces = CLONE_NAMESPACES
        .iter()
        .fold(0, |all, &flag| all | flag as u64);
    let no_namespace = low(0, SeccompCmpOp::MaskedEq(namespaces), 0)?;
    rules.add(libc::SYS_clone, vec![rule(vec![no_namespace])?]);
    let fionbio = low(1, SeccompCmpOp::Eq, u64::from(libc::FIONBIO as u32))?;
    rules.add(libc::SYS_ioctl, vec![rule(vec![fionbio])?]);
    let filter = SeccompFilter::new(
        rules.0,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target,
    )?;
    Ok(Filters {
        allowlist: allowlist(target)?,
        denylist: filter.try_into()?,
    })
}

/// Installs the allowlist and then the denylist on every thread of the process. Both stay in
/// force across execve and are inherited by every child.
pub fn install(filters: &Filters) -> Result<(), seccompiler::Error> {
    seccompiler::apply_filter_all_threads(&filters.allowlist)?;
    seccompiler::apply_filter_all_threads(&filters.denylist)
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    use seccompiler::sock_filter;

    const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    #[cfg(target_arch = "x86_64")]
    const NATIVE: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const NATIVE: u32 = 183 | 0x8000_0000 | 0x4000_0000;

    const fn code(parts: u32) -> u16 {
        parts as u16
    }
    const LD: u16 = code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
    const AND: u16 = code(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K);
    const JA: u16 = code(libc::BPF_JMP | libc::BPF_JA);
    const JEQ: u16 = code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
    const JGE: u16 = code(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K);
    const JGT: u16 = code(libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K);
    const RET: u16 = code(libc::BPF_RET | libc::BPF_K);

    /// A classic BPF interpreter for the instructions seccompiler emits.
    fn evaluate(program: &[sock_filter], arch: u32, nr: i64, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&(nr as i32).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, arg) in args.iter().enumerate() {
            let start = 16 + 8 * index;
            data[start..start + 8].copy_from_slice(&arg.to_le_bytes());
        }
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let insn = &program[pc];
            pc += 1;
            let condition = match insn.code {
                LD => {
                    let offset = insn.k as usize;
                    accumulator = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                    continue;
                }
                AND => {
                    accumulator &= insn.k;
                    continue;
                }
                JA => {
                    pc += insn.k as usize;
                    continue;
                }
                RET => return insn.k,
                JEQ => accumulator == insn.k,
                JGE => accumulator >= insn.k,
                JGT => accumulator > insn.k,
                other => panic!("unexpected instruction {other:#x}"),
            };
            pc += usize::from(if condition { insn.jt } else { insn.jf });
        }
    }

    /// Runs both filters like the kernel: the most restrictive action wins, and among equal
    /// actions the most recently installed filter.
    const OWN_PID: u32 = 4242;

    fn decide(config: &FilterConfig, arch: u32, nr: i64, args: [u64; 6]) -> u32 {
        decide_with(&build(config, OWN_PID).unwrap(), arch, nr, args)
    }

    fn decide_with(filters: &Filters, arch: u32, nr: i64, args: [u64; 6]) -> u32 {
        let rank = |action: u32| (action & libc::SECCOMP_RET_ACTION_FULL) as i32;
        let mut result = RET_ALLOW;
        for program in [&filters.denylist, &filters.allowlist] {
            let action = evaluate(program, arch, nr, args);
            if rank(action) < rank(result) {
                result = action;
            }
        }
        result
    }

    fn call(config: &FilterConfig, nr: i64, args: [u64; 6]) -> u32 {
        decide(config, NATIVE, nr, args)
    }

    fn strict() -> FilterConfig {
        FilterConfig {
            allow_ip: false,
            allow_unix: false,
            restrict_truncate: false,
            deny_path_metadata: true,
            deny_children: true,
        }
    }

    fn open() -> FilterConfig {
        FilterConfig {
            allow_ip: true,
            allow_unix: true,
            restrict_truncate: false,
            deny_path_metadata: false,
            deny_children: false,
        }
    }

    fn args(values: &[u64]) -> [u64; 6] {
        let mut args = [0; 6];
        args[..values.len()].copy_from_slice(values);
        args
    }

    fn socket(family: i32, kind: i32, protocol: i32) -> [u64; 6] {
        args(&[family as u64, kind as u64, protocol as u64])
    }

    #[test]
    fn programs_fit_the_kernel_limit() {
        for config in [strict(), open()] {
            let filters = build(&config, OWN_PID).unwrap();
            assert!(filters.allowlist.len() < 4096);
            assert!(filters.denylist.len() < 4096);
        }
    }

    #[test]
    fn foreign_architectures_are_killed_and_x32_fails() {
        const AUDIT_ARCH_I386: u32 = 3 | 0x4000_0000;
        assert_eq!(
            decide(&open(), AUDIT_ARCH_I386, 20, [0; 6]),
            RET_KILL_PROCESS
        );
        let x32_socket = 0x4000_0000 | libc::SYS_socket;
        assert_eq!(call(&open(), x32_socket, [0; 6]), RET_ENOSYS);
    }

    #[test]
    fn reviewed_calls_are_allowed_and_unknown_calls_fail_with_enosys() {
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_close_range,
            libc::SYS_rseq,
            libc::SYS_fchmod,
            libc::SYS_fchown,
            libc::SYS_fsetxattr,
        ] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        for nr in [472, 1000, -1] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_ENOSYS, "system call {nr}");
        }
        assert_eq!(call(&open(), libc::SYS_clone3, [0; 6]), RET_ENOSYS);
        assert_eq!(call(&open(), libc::SYS_openat2, [0; 6]), RET_ENOSYS);
    }

    #[test]
    fn socket_families_follow_the_policy() {
        for family in [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
        ] {
            let args = socket(family, 1, 0);
            assert_eq!(call(&strict(), libc::SYS_socket, args), RET_EPERM);
            assert_eq!(call(&open(), libc::SYS_socket, args), RET_ALLOW);
        }
        const AF_ALG: i32 = 38;
        const AF_VSOCK: i32 = 40;
        const AF_SMC: i32 = 43;
        for family in [libc::AF_PACKET, AF_VSOCK, AF_ALG, AF_SMC, 0] {
            let args = socket(family, 1, 0);
            assert_eq!(call(&open(), libc::SYS_socket, args), RET_EPERM);
        }
        const NETLINK_SOCK_DIAG: i32 = 4;
        let diag = socket(libc::AF_NETLINK, 2, NETLINK_SOCK_DIAG);
        assert_eq!(call(&open(), libc::SYS_socket, diag), RET_EPERM);
        let ip_only = FilterConfig {
            allow_unix: false,
            ..open()
        };
        let unix = socket(libc::AF_UNIX, 1, 0);
        assert_eq!(call(&ip_only, libc::SYS_socket, unix), RET_EPERM);
        let unix_only = FilterConfig {
            allow_ip: false,
            ..open()
        };
        assert_eq!(call(&unix_only, libc::SYS_socket, unix), RET_ALLOW);
        let inet = socket(libc::AF_INET, 1, 0);
        assert_eq!(call(&unix_only, libc::SYS_socket, inet), RET_EPERM);
    }

    #[test]
    fn socket_family_check_uses_the_low_32_bits() {
        let high_bits = (1u64 << 32) | libc::AF_UNIX as u64;
        let args = args(&[high_bits, 1]);
        assert_eq!(call(&strict(), libc::SYS_socket, args), RET_EPERM);
    }

    #[test]
    fn socketpair_allows_only_connected_types_when_unix_sockets_are_denied() {
        let flags = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        for kind in [libc::SOCK_STREAM, libc::SOCK_SEQPACKET] {
            let args = socket(libc::AF_UNIX, kind | flags, 0);
            assert_eq!(call(&strict(), libc::SYS_socketpair, args), RET_ALLOW);
        }
        for kind in [libc::SOCK_DGRAM, libc::SOCK_RAW] {
            let args = socket(libc::AF_UNIX, kind | flags, 0);
            assert_eq!(call(&strict(), libc::SYS_socketpair, args), RET_EPERM);
            assert_eq!(call(&open(), libc::SYS_socketpair, args), RET_ALLOW);
        }
        let inet = socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert_eq!(call(&open(), libc::SYS_socketpair, inet), RET_EPERM);
    }

    #[test]
    fn terminal_injection_is_denied_also_with_high_bits_set() {
        for command in [libc::TIOCSTI as u32, libc::TIOCLINUX as u32].map(u64::from) {
            for high in [0, 0xffff_ffff_0000_0000] {
                let args = args(&[0, high | command]);
                assert_eq!(call(&open(), libc::SYS_ioctl, args), RET_EPERM);
            }
        }
        let window_size = args(&[0, u64::from(libc::TIOCGWINSZ as u32)]);
        assert_eq!(call(&strict(), libc::SYS_ioctl, window_size), RET_ALLOW);
    }

    #[test]
    fn namespaces_are_denied() {
        let thread_flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let fork_flags = libc::SIGCHLD as u64;
        for flags in [thread_flags, fork_flags] {
            assert_eq!(call(&open(), libc::SYS_clone, args(&[flags])), RET_ALLOW);
        }
        for namespace in [libc::CLONE_NEWUSER, libc::CLONE_NEWNET, libc::CLONE_NEWNS] {
            let flags = fork_flags | namespace as u64;
            assert_eq!(call(&open(), libc::SYS_clone, args(&[flags])), RET_EPERM);
            let unshare = args(&[namespace as u64]);
            assert_eq!(call(&open(), libc::SYS_unshare, unshare), RET_EPERM);
        }
        let time = args(&[libc::CLONE_NEWTIME as u64]);
        assert_eq!(call(&open(), libc::SYS_unshare, time), RET_EPERM);
        let files = args(&[libc::CLONE_FILES as u64]);
        assert_eq!(call(&open(), libc::SYS_unshare, files), RET_ALLOW);
        assert_eq!(call(&open(), libc::SYS_setns, [0; 6]), RET_EPERM);
    }

    #[test]
    fn baseline_denials_apply_to_every_policy() {
        for config in [strict(), open()] {
            for nr in [
                libc::SYS_io_uring_setup,
                libc::SYS_ptrace,
                libc::SYS_process_vm_readv,
                libc::SYS_bpf,
                libc::SYS_keyctl,
                libc::SYS_userfaultfd,
                libc::SYS_mount,
                libc::SYS_shmat,
                libc::SYS_mq_open,
                libc::SYS_init_module,
                SYS_STATMOUNT,
                SYS_LISTMOUNT,
                SYS_LISTNS,
            ] {
                assert_eq!(call(&config, nr, [0; 6]), RET_EPERM, "system call {nr}");
            }
        }
    }

    #[test]
    fn path_metadata_calls_follow_the_policy() {
        let deny = strict();
        let allow = open();
        let mut calls = vec![
            libc::SYS_fchmodat,
            SYS_FCHMODAT2,
            libc::SYS_fchownat,
            libc::SYS_setxattr,
            libc::SYS_lremovexattr,
            SYS_SETXATTRAT,
            SYS_FILE_SETATTR,
        ];
        calls.extend(arch::PATH_METADATA);
        for nr in calls {
            assert_eq!(call(&deny, nr, [0; 6]), RET_EPERM, "system call {nr}");
            assert_eq!(call(&allow, nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        for nr in [libc::SYS_fchmod, libc::SYS_fchown, libc::SYS_fsetxattr] {
            assert_eq!(call(&deny, nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        let path = args(&[3, 0x7fff_0000_1000]);
        assert_eq!(call(&deny, libc::SYS_utimensat, path), RET_EPERM);
        assert_eq!(call(&allow, libc::SYS_utimensat, path), RET_ALLOW);
        let descriptor = args(&[3, 0]);
        assert_eq!(call(&deny, libc::SYS_utimensat, descriptor), RET_ALLOW);
    }

    #[test]
    fn setuid_and_setgid_bits_cannot_be_set() {
        let setid = [0o4755, 0o2755, 0o6755];
        let plain = [0o755, 0o644, 0o1777];
        for config in [strict(), open()] {
            for mode in setid {
                let args = args(&[3, mode]);
                assert_eq!(call(&config, libc::SYS_fchmod, args), RET_EPERM, "{mode:o}");
            }
            for mode in plain {
                let args = args(&[3, mode]);
                assert_eq!(call(&config, libc::SYS_fchmod, args), RET_ALLOW, "{mode:o}");
            }
        }
        // With path metadata allowed, the path variants get the same check.
        let mut calls = vec![(libc::SYS_fchmodat, 2), (SYS_FCHMODAT2, 2)];
        calls.extend(
            arch::CHMOD_CALLS
                .iter()
                .map(|&(call, mode)| (call, usize::from(mode))),
        );
        for (nr, mode_index) in calls {
            let with_mode = |mode: u64| {
                let mut args = [0; 6];
                args[mode_index] = mode;
                args
            };
            for mode in setid {
                assert_eq!(
                    call(&open(), nr, with_mode(mode)),
                    RET_EPERM,
                    "{nr} {mode:o}"
                );
            }
            for mode in plain {
                assert_eq!(
                    call(&open(), nr, with_mode(mode)),
                    RET_ALLOW,
                    "{nr} {mode:o}"
                );
            }
        }
    }

    #[test]
    fn other_processes_cannot_be_changed() {
        let own = u64::from(OWN_PID);
        let other = own + 1;
        for &(nr, pid_index) in PROCESS_CALLS {
            let with_pid = |pid: u64| {
                let mut args = [0; 6];
                args[usize::from(pid_index)] = pid;
                args
            };
            assert_eq!(call(&open(), nr, with_pid(0)), RET_ALLOW, "{nr}");
            assert_eq!(call(&open(), nr, with_pid(own)), RET_ALLOW, "{nr}");
            assert_eq!(call(&open(), nr, with_pid(other)), RET_EPERM, "{nr}");
        }
        let prio_pgrp = libc::PRIO_PGRP as u64;
        let prio_user = libc::PRIO_USER as u64;
        for (nr, one, groups) in [
            (
                libc::SYS_setpriority,
                libc::PRIO_PROCESS as u64,
                [prio_pgrp, prio_user],
            ),
            (libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, [2, 3]),
        ] {
            assert_eq!(call(&open(), nr, args(&[one, 0])), RET_ALLOW, "{nr}");
            assert_eq!(call(&open(), nr, args(&[one, own])), RET_ALLOW, "{nr}");
            assert_eq!(call(&open(), nr, args(&[one, other])), RET_EPERM, "{nr}");
            for which in groups {
                assert_eq!(call(&open(), nr, args(&[which, 0])), RET_EPERM, "{nr}");
            }
        }
    }

    #[test]
    fn the_relay_can_only_relay() {
        let filters = relay().unwrap();
        let relay = |nr: i64, args: [u64; 6]| decide_with(&filters, NATIVE, nr, args);
        let tcp = |family: i32| socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        for nr in [
            libc::SYS_accept4,
            libc::SYS_connect,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_recvfrom,
            libc::SYS_sendto,
            libc::SYS_shutdown,
            libc::SYS_close,
            libc::SYS_ppoll,
            libc::SYS_futex,
            libc::SYS_exit_group,
        ] {
            assert_eq!(relay(nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        assert_eq!(relay(libc::SYS_socket, tcp(libc::AF_INET)), RET_ALLOW);
        assert_eq!(relay(libc::SYS_socket, tcp(libc::AF_INET6)), RET_ALLOW);
        let thread = (libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u64;
        assert_eq!(relay(libc::SYS_clone, args(&[thread])), RET_ALLOW);
        let fionbio = args(&[3, u64::from(libc::FIONBIO as u32)]);
        assert_eq!(relay(libc::SYS_ioctl, fionbio), RET_ALLOW);
        // No files, no other sockets, no new listeners, no programs, no namespaces.
        for nr in [
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_kill,
            libc::SYS_ptrace,
            libc::SYS_fchmod,
        ] {
            assert_eq!(relay(nr, [0; 6]), RET_EPERM, "system call {nr}");
        }
        assert_eq!(relay(libc::SYS_socket, tcp(libc::AF_UNIX)), RET_EPERM);
        let udp = socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert_eq!(relay(libc::SYS_socket, udp), RET_EPERM);
        let user = thread | libc::CLONE_NEWUSER as u64;
        assert_eq!(relay(libc::SYS_clone, args(&[user])), RET_EPERM);
        let tiocsti = args(&[0, u64::from(libc::TIOCSTI as u32)]);
        assert_eq!(relay(libc::SYS_ioctl, tiocsti), RET_EPERM);
        // The shared allowlist still decides clone3, so threads fall back to clone.
        assert_eq!(relay(libc::SYS_clone3, [0; 6]), RET_ENOSYS);
    }

    #[test]
    fn children_none_allows_only_threads() {
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let fork = libc::SIGCHLD as u64;
        let spawn = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64;
        assert_eq!(call(&strict(), libc::SYS_clone, args(&[thread])), RET_ALLOW);
        for flags in [fork, spawn] {
            assert_eq!(call(&strict(), libc::SYS_clone, args(&[flags])), RET_EPERM);
            assert_eq!(call(&open(), libc::SYS_clone, args(&[flags])), RET_ALLOW);
        }
        // High bits do not hide a missing CLONE_THREAD: the kernel uses the low 32 bits.
        let high = args(&[(1 << 32) | fork]);
        assert_eq!(call(&strict(), libc::SYS_clone, high), RET_EPERM);
        for &nr in arch::FORK_CALLS {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_EPERM, "system call {nr}");
            assert_eq!(call(&open(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        assert_eq!(call(&strict(), libc::SYS_clone3, [0; 6]), RET_ENOSYS);
        assert_eq!(call(&strict(), libc::SYS_execve, [0; 6]), RET_ALLOW);
    }

    #[test]
    fn personality_allows_only_harmless_values() {
        assert_eq!(call(&open(), libc::SYS_personality, [0; 6]), RET_ALLOW);
        let query = args(&[0xffff_ffff]);
        assert_eq!(call(&open(), libc::SYS_personality, query), RET_ALLOW);
        const READ_IMPLIES_EXEC: u64 = 0x040_0000;
        let exec = args(&[READ_IMPLIES_EXEC]);
        assert_eq!(call(&open(), libc::SYS_personality, exec), RET_EPERM);
    }

    #[test]
    fn open_for_ioctl_only_is_denied() {
        for &(nr, flags_index) in arch::OPEN_CALLS {
            let mut ioctl_only = [0; 6];
            ioctl_only[usize::from(flags_index)] = libc::O_ACCMODE as u64;
            assert_eq!(call(&open(), nr, ioctl_only), RET_EPERM);
            let mut read = [0; 6];
            read[usize::from(flags_index)] = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
            assert_eq!(call(&open(), nr, read), RET_ALLOW);
        }
    }

    #[test]
    fn truncation_rules_apply_only_when_landlock_cannot_check_it() {
        let restricted = FilterConfig {
            restrict_truncate: true,
            ..open()
        };
        let trunc = libc::O_TRUNC as u64;
        for &(nr, flags_index) in arch::OPEN_CALLS {
            let with_flags = |flags: u64| {
                let mut args = [0; 6];
                args[usize::from(flags_index)] = flags;
                args
            };
            assert_eq!(call(&restricted, nr, with_flags(trunc)), RET_EPERM);
            assert_eq!(call(&open(), nr, with_flags(trunc)), RET_ALLOW);
            for flags in [
                trunc | libc::O_WRONLY as u64,
                trunc | (libc::O_RDWR | libc::O_CREAT) as u64,
                libc::O_RDONLY as u64,
            ] {
                assert_eq!(call(&restricted, nr, with_flags(flags)), RET_ALLOW);
            }
        }
        assert_eq!(call(&restricted, libc::SYS_truncate, [0; 6]), RET_EPERM);
        assert_eq!(call(&open(), libc::SYS_truncate, [0; 6]), RET_ALLOW);
    }
}
