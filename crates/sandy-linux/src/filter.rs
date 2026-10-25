//! The seccomp filters. sandy installs up to four filters; the kernel applies the stricter
//! result, and among equal results the one of the filter installed last:
//!
//! 1. The allowlist allows the system calls of the reviewed kernel table. Every other number,
//!    including x32 numbers and system calls of newer kernels, fails with ENOSYS. Programs treat
//!    that like an older kernel. A call of another CPU architecture kills the process.
//! 2. The denylist checks arguments and denies single system calls with EPERM.
//! 3. The extended attribute filter fails the reads that take a path, and the changes through a
//!    descriptor, with ENOTSUP. Programs treat that like a file system without extended
//!    attributes and skip them.
//! 4. The socket family filter fails `socket` with EAFNOSUPPORT for the families the policy
//!    denies. Programs treat that like a kernel without the family and fall back; EPERM reads
//!    like a temporary failure and often ends the program instead.
//!
//! seccompiler compiles all of them. Numbers come from `libc::SYS_*`, so sandy controls the
//! table.

use std::collections::{BTreeMap, BTreeSet};

use sandy_core::streams::{CreatableSocket, IP_PROTOCOLS};
use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch, sock_filter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterConfig {
    /// Allow AF_INET, AF_INET6 and the sockets of `IP_ALSO_ALLOWS`.
    pub allow_ip: bool,
    /// Allow AF_UNIX sockets and socket pairs of every type.
    pub allow_unix: bool,
    /// Deny listening and accepting (`ip = "client"`), for every socket: the filter sees only
    /// the descriptor, not the family of its socket.
    pub deny_inbound: bool,
    /// Deny the ways to truncate a file without write access. Landlock checks truncation only
    /// since ABI 3.
    pub restrict_truncate: bool,
    /// Deny the metadata calls that take a path.
    pub deny_path_metadata: bool,
    /// Deny creating processes; threads stay allowed.
    pub deny_children: bool,
    /// Deny setsid and setpgid, so every process the program starts stays in the process group
    /// that sandy ends as a whole (`process.children = "contained"`).
    pub keep_process_group: bool,
    /// Deny joining another process group and the terminal ioctls that make the kernel signal
    /// one (`signals = "isolated"`). The kernel sends the job control signals of a terminal to a
    /// whole process group without the check that the Landlock signal scope hooks.
    pub isolate_signals: bool,
}

#[cfg(target_arch = "x86_64")]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::x86_64);
    /// `AUDIT_ARCH_X86_64`: EM_X86_64 with the 64-bit and the little-endian bit. seccompiler
    /// keeps its own copy private, and the observer program needs it.
    pub const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
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
    /// chown variants that only x86_64 has, with the index of their user ID argument.
    pub const CHOWN_CALLS: &[(i64, u8)] = &[(libc::SYS_chown, 1), (libc::SYS_lchown, 1)];
    /// Calls the relay and the watcher need that only x86_64 has (arm64 has only ppoll).
    pub const RELAY_CALLS: &[i64] = &[libc::SYS_poll];
    /// Lookups by path that only x86_64 has besides their `*at` forms.
    pub const PATH_LOOKUP_CALLS: &[i64] = &[
        libc::SYS_readlink,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
    ];
    /// System calls that create a process without arguments to check; arm64 has only clone.
    pub const FORK_CALLS: &[i64] = &[libc::SYS_fork, libc::SYS_vfork];
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::aarch64);
    /// `AUDIT_ARCH_AARCH64`: EM_AARCH64 with the 64-bit and the little-endian bit.
    pub const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;
    /// The generic table (include/uapi/asm-generic/unistd.h) of Linux 7.2 for 64-bit arm64.
    /// 244 to 259 are reserved for architecture-specific calls, which arm64 does not have.
    /// 403 to 423 exist only for 32-bit ABIs.
    pub const REVIEWED: &[(i64, i64)] = &[(0, 243), (260, 294), (424, 471)];
    /// kexec_file_load, which the libc crate lacks for musl on arm64.
    pub const DENIED: &[i64] = &[294];
    pub const PATH_METADATA: &[i64] = &[];
    pub const OPEN_CALLS: &[(i64, u8)] = &[(libc::SYS_openat, 2)];
    pub const CHMOD_CALLS: &[(i64, u8)] = &[];
    pub const CHOWN_CALLS: &[(i64, u8)] = &[];
    pub const RELAY_CALLS: &[i64] = &[];
    pub const PATH_LOOKUP_CALLS: &[i64] = &[];
    pub const FORK_CALLS: &[i64] = &[];
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod arch {
    pub const TARGET: Option<seccompiler::TargetArch> = None;
    pub const AUDIT_ARCH: u32 = 0;
    pub const REVIEWED: &[(i64, i64)] = &[];
    pub const DENIED: &[i64] = &[];
    pub const PATH_METADATA: &[i64] = &[];
    pub const OPEN_CALLS: &[(i64, u8)] = &[];
    pub const CHMOD_CALLS: &[(i64, u8)] = &[];
    pub const CHOWN_CALLS: &[(i64, u8)] = &[];
    pub const RELAY_CALLS: &[i64] = &[];
    pub const PATH_LOOKUP_CALLS: &[i64] = &[];
    pub const FORK_CALLS: &[i64] = &[];
}

/// Whether sandy has a filter for the CPU architecture it was built for.
pub const ARCH_SUPPORTED: bool = arch::TARGET.is_some();

// Numbers from 424 upward are the same on every architecture. The libc crate does not have
// these yet for every target.
const SYS_FCHMODAT2: i64 = 452;
const SYS_SETXATTRAT: i64 = 463;
const SYS_GETXATTRAT: i64 = 464;
const SYS_LISTXATTRAT: i64 = 465;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_FILE_GETATTR: i64 = 468;
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;
const SYS_OPEN_TREE_ATTR: i64 = 467;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_LISTNS: i64 = 470;
const SYS_LSM_GET_SELF_ATTR: i64 = 459;
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
const SYS_LSM_LIST_MODULES: i64 = 461;

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
    // Which security modules the host runs and the program's own attributes, which
    // lsm_set_self_attr changes. Without /proc and /sys/kernel/security it sees neither.
    SYS_LSM_GET_SELF_ATTR,
    SYS_LSM_SET_SELF_ATTR,
    SYS_LSM_LIST_MODULES,
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
    libc::SYS_vhangup,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_setgroups,
];

/// prctl options that only work with a capability, which sandy never passes on. A second layer,
/// like the calls of `DENIED` that need one. The option is an int.
///
/// - PR_CAPBSET_DROP needs CAP_SETPCAP.
/// - PR_SET_MM needs CAP_SYS_RESOURCE. Its forms PR_SET_MM_MAP and PR_SET_MM_MAP_SIZE do not,
///   but the executable that PR_SET_MM_MAP can set needs CAP_CHECKPOINT_RESTORE and lies in
///   memory, where seccomp cannot read it. Only tools that restore checkpointed processes use
///   them, and those need ptrace, which the sandbox denies.
/// - PR_SET_IO_FLUSHER needs CAP_SYS_RESOURCE.
///
/// PR_CAP_AMBIENT has a rule of its own. PR_SET_SECUREBITS stays allowed: since Linux 6.14 a
/// process may set SECBIT_EXEC_RESTRICT_FILE and SECBIT_EXEC_DENY_INTERACTIVE without a
/// capability, so whether a call needs one depends on the bits the process already holds, and
/// the other bits change only how the kernel treats root and capabilities, which the program has
/// neither of.
const CAPABILITY_PRCTLS: &[i32] = &[libc::PR_CAPBSET_DROP, libc::PR_SET_MM, PR_SET_IO_FLUSHER];
/// PR_SET_IO_FLUSHER of Linux 5.6, which the libc crate does not have.
const PR_SET_IO_FLUSHER: i32 = 57;

/// The calls that set user or group IDs, with the number of IDs each takes. Without CAP_SETUID
/// or CAP_SETGID a process may only switch among its real, effective and saved IDs, and -1
/// leaves an ID as it is. setfsuid and setfsgid ignore any other ID instead of failing.
const UID_CALLS: &[(i64, u8)] = &[
    (libc::SYS_setuid, 1),
    (libc::SYS_setreuid, 2),
    (libc::SYS_setresuid, 3),
    (libc::SYS_setfsuid, 1),
];
const GID_CALLS: &[(i64, u8)] = &[
    (libc::SYS_setgid, 1),
    (libc::SYS_setregid, 2),
    (libc::SYS_setresgid, 3),
    (libc::SYS_setfsgid, 1),
];

/// The calls that change the owner of a file on every architecture, with the index of their user
/// ID argument. Without CAP_CHOWN a process may only keep the owner of its own file, which is its
/// file system user ID, one of the IDs it holds; -1 leaves the owner as it is.
const CHOWN_CALLS: &[(i64, u8)] = &[(libc::SYS_fchown, 1), (libc::SYS_fchownat, 2)];

/// The bits of the class in an I/O priority (an int, the class from bit 13), and the real-time
/// class, which needs CAP_SYS_ADMIN or CAP_SYS_NICE.
const IOPRIO_CLASS_MASK: u64 = 0x7 << 13;
const IOPRIO_CLASS_RT: u64 = 1 << 13;

/// Socket options that only work with a capability, as level and option, both ints. setsockopt
/// only; reading them needs none.
///
/// - SO_SNDBUFFORCE and SO_RCVBUFFORCE (CAP_NET_ADMIN) go past the buffer limits of the host,
///   and SO_MARK (CAP_NET_RAW or CAP_NET_ADMIN) selects routing tables and firewall rules.
/// - IP_IPSEC_POLICY, IP_XFRM_POLICY and their IPv6 forms (CAP_NET_ADMIN) set the IPsec policy
///   of a socket.
/// - TCP_REPAIR (CAP_NET_ADMIN) rewrites the state of a connection, and TCP_REPAIR_QUEUE,
///   TCP_QUEUE_SEQ, TCP_REPAIR_OPTIONS and TCP_REPAIR_WINDOW work only in repair mode.
const CAPABILITY_SOCKET_OPTIONS: &[(i32, i32)] = &[
    (libc::SOL_SOCKET, libc::SO_SNDBUFFORCE),
    (libc::SOL_SOCKET, libc::SO_RCVBUFFORCE),
    (libc::SOL_SOCKET, libc::SO_MARK),
    (libc::SOL_IP, libc::IP_IPSEC_POLICY),
    (libc::SOL_IP, libc::IP_XFRM_POLICY),
    (libc::SOL_IPV6, libc::IPV6_IPSEC_POLICY),
    (libc::SOL_IPV6, libc::IPV6_XFRM_POLICY),
    (libc::SOL_TCP, libc::TCP_REPAIR),
    (libc::SOL_TCP, libc::TCP_REPAIR_QUEUE),
    (libc::SOL_TCP, libc::TCP_QUEUE_SEQ),
    (libc::SOL_TCP, libc::TCP_REPAIR_OPTIONS),
    (libc::SOL_TCP, libc::TCP_REPAIR_WINDOW),
];

/// The options of the legacy firewall interfaces, as level and first and last option, for
/// setsockopt and getsockopt: iptables (64 to 67), ipset (83), arptables (96 to 99), ebtables
/// (128 to 132) and IPVS (1152 to 1167) on IPv4 sockets, ip6tables (64, 65, 68 and 69) on IPv6
/// sockets. Each needs CAP_NET_ADMIN before the module behind it parses the request. No other
/// IP option has these numbers; IPV6_RECVTCLASS (66), IPV6_TCLASS (67) and SO_ORIGINAL_DST (80),
/// which transparent proxies read without a capability, lie between them.
const FIREWALL_SOCKET_OPTIONS: &[(i32, u32, u32)] = &[
    (libc::SOL_IP, 64, 67),
    (libc::SOL_IP, 83, 83),
    (libc::SOL_IP, 96, 99),
    (libc::SOL_IP, 128, 132),
    (libc::SOL_IP, 1152, 1167),
    (libc::SOL_IPV6, 64, 65),
    (libc::SOL_IPV6, 68, 69),
];

/// Terminal and file system ioctls that only work with CAP_SYS_ADMIN. A second layer. The numbers
/// are the same on x86_64 and arm64.
///
/// - TIOCVHANGUP hangs up a terminal like `vhangup`, TIOCCONS sends the console messages of the
///   host to a terminal, and TIOCSLCKTRMIOS locks the settings of a terminal.
/// - FIFREEZE and FITHAW freeze and thaw the whole file system of a descriptor, FITRIM discards
///   its free blocks, FS_IOC_SHUTDOWN shuts it down, and FS_IOC_SETFSLABEL renames it.
///
/// The management ioctls of single file systems (resizing, devices, quotas) stay with the
/// kernel's check.
const CAPABILITY_IOCTLS: &[u32] = &[
    // TIOCVHANGUP, TIOCCONS, TIOCSLCKTRMIOS.
    0x5437,
    0x541d,
    0x5457,
    // FIFREEZE, FITHAW, FITRIM, FS_IOC_SHUTDOWN, FS_IOC_SETFSLABEL.
    0xc004_5877,
    0xc004_5878,
    0xc018_5879,
    0x8004_587d,
    0x4100_9432,
];

/// MPOL_MF_MOVE_ALL, which the libc crate does not have: mbind and move_pages then also move the
/// pages that other processes map, which needs CAP_SYS_NICE. The flags are the sixth argument of
/// both, an unsigned int and an int.
const MPOL_MF_MOVE_ALL: u64 = 1 << 2;

/// Landlock does not restrict metadata changes. fchmodat, fchmodat2 and fchownat accept O_PATH
/// descriptors with AT_EMPTY_PATH, so they are denied completely. utimensat has its own rule. The
/// descriptor variants reject O_PATH descriptors, so they only reach files that Landlock let the
/// program open, but also one it may only read: see `DESCRIPTOR_METADATA`.
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

/// Reads of extended attributes that take a path. Landlock has no hook for them, so they work on
/// every file the user can reach, outside the policy as well, and they return contents: ACLs,
/// SELinux labels and user attributes such as the download address of a file. The descriptor
/// variants (fgetxattr, flistxattr) stay allowed, like the other metadata calls on a descriptor:
/// they reject O_PATH descriptors (measured on Linux 7.2: EBADF), so they only reach files that
/// Landlock let the program open. `getxattrat`, `listxattrat` and `file_getattr` are denied
/// completely, because they read the descriptor itself with AT_EMPTY_PATH.
const PATH_XATTR_READS: &[i64] = &[
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    SYS_GETXATTRAT,
    SYS_LISTXATTRAT,
    SYS_FILE_GETATTR,
];

/// Metadata changes through a descriptor that sandy denies with the path metadata: fchown sets
/// the owner and group, fsetxattr and fremovexattr the ACLs, the security label and the user
/// attributes. seccomp cannot tell a descriptor opened for writing from one opened for reading,
/// so they would otherwise change a file of a `read` path or one the caller passed on a standard
/// stream. The programs that call them on the files they write (sed -i, gzip, xz, patch, Java's
/// Files.copy) carry on without them: fchown fails with EPERM as for any user who may not
/// change an owner, and the attribute calls fail with ENOTSUP, as on a file system without
/// extended attributes, because EPERM there makes sed and patch print a warning. fchmod and
/// futimens stay allowed: cp, touch and Rust's fs::copy need them on the files they write.
const DESCRIPTOR_METADATA: &[i64] = &[libc::SYS_fchown];
const DESCRIPTOR_XATTR_CHANGES: &[i64] = &[libc::SYS_fsetxattr, libc::SYS_fremovexattr];

/// Not in the allowlist, so they fail with ENOSYS. Programs fall back on ENOSYS: glibc uses
/// clone instead of clone3, openat2 callers use openat, a program that cannot create an fanotify
/// group uses inotify, and one without file handles works with paths, as on a kernel built
/// without them. The arguments of clone3 and openat2 are in memory, where seccomp cannot check
/// them; an unprivileged fanotify group needs no argument check, because it reports paths outside
/// the policy whatever its flags are, and name_to_handle_at gives the handle and the mount of any
/// path the user can reach, also outside the policy, while open_by_handle_at, its only use, needs
/// a capability.
const ENOSYS_CALLS: &[i64] = &[
    libc::SYS_clone3,
    libc::SYS_openat2,
    libc::SYS_fanotify_init,
    libc::SYS_name_to_handle_at,
];

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
/// UNAME26, PER_LINUX32 | UNAME26, and the query value. ADDR_NO_RANDOMIZE, alone and with those
/// two flags, is allowed as well: `setarch -R`, rr and the thread sanitizer need it, and it
/// weakens address space randomization only inside the sandbox.
const PERSONALITIES: &[u64] = &[
    0,
    0x8,
    0x2_0000,
    0x2_0008,
    0x4_0000,
    0x4_0008,
    0x6_0000,
    0x6_0008,
    0xffff_ffff,
];

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

/// What `ip = "all"` allows besides AF_INET and AF_INET6, one protocol per family. Route netlink
/// lets the C library list interfaces and addresses. Other netlink protocols expose, for example,
/// every socket of the host (sock_diag).
pub const IP_ALSO_ALLOWS: &[CreatableSocket] = &[CreatableSocket {
    name: "route netlink",
    family: libc::AF_NETLINK,
    protocol: libc::NETLINK_ROUTE,
}];
const SOCK_TYPE_MASK: u64 = 0xf;

/// F_SETDELEG of Linux 7, which the libc crate does not have yet.
const F_SETDELEG: u64 = 1040;

/// File system ioctls that change a file or a directory through a descriptor opened read-only.
/// Landlock checks ioctls only on device files, so they reach everything the program may open,
/// also in `read` paths. The libc crate has none of these numbers; they are the same on x86_64
/// and arm64.
///
/// - FS_IOC_SETFLAGS, its 32-bit form, and FS_IOC_FSSETXATTR change inode flags and attributes,
///   which is metadata like chmod (`chattr`).
/// - FS_IOC_SETVERSION, its 32-bit form, and EXT4_IOC_SETVERSION, which ext4 treats the same,
///   change the version a file carries, which is metadata the policy denies by path.
/// - FS_IOC_ENABLE_VERITY makes the content of a file permanently read-only.
/// - FS_IOC_SET_ENCRYPTION_POLICY encrypts what the user later writes into an empty directory,
///   with a key the program chose. FS_IOC_REMOVE_ENCRYPTION_KEY and its all-users form lock
///   encrypted directories the user has unlocked, outside the policy.
/// - The btrfs ioctls create, snapshot and delete subvolumes, or make them read-only, which
///   changes directories without the Landlock checks for creating and removing entries.
///   BTRFS_IOC_SET_RECEIVED_SUBVOL and its 32-bit form, which 64-bit kernels also take, change
///   the identity by which `btrfs receive` finds the parent of an incremental stream.
/// - FIDEDUPERANGE makes a file share blocks with another file of the same content. The kernel
///   takes a destination the user owns also when it was opened read-only, so it changes how a
///   file of a `read` path is stored, and its answer tells whether a guessed block equals a block
///   of the destination, which is what made access mode 3 a content oracle.
const FILE_SYSTEM_IOCTLS: &[u32] = &[
    0x4008_6602,
    0x4004_6602,
    0x401c_5820,
    0x4008_7602,
    0x4004_7602,
    0x4008_6604,
    0x4080_6685,
    0x800c_6613,
    0xc040_6618,
    0xc040_6619,
    0x5000_9401,
    0x5000_940e,
    0x5000_940f,
    0x5000_9417,
    0x5000_9418,
    0x5000_943f,
    0x4008_941a,
    0xc0c8_9425,
    0xc0c0_9425,
    0xc018_9436,
];

/// PIDFD_GET_INFO, `_IOWR(0xFF, 11, struct pidfd_info)`, which tells the parent, the user and
/// group IDs, the cgroup and the exit status of the process behind a pidfd, and pidfd_open takes
/// any process of the host. Leaving out `/proc` otherwise hides these, as it hides the mounts
/// that statmount shows. The structure grows with the kernel and its size is part of the number,
/// so the rule ignores the size bits. Only libsystemd uses the call, for the peers of a bus; it
/// does without when the call fails.
const PIDFD_GET_INFO: u64 = 0xc000_ff0b;
const PIDFD_GET_INFO_MASK: u64 = 0xc000_ffff;

/// Console ioctls that change a Linux virtual console, its keyboard or which console the screen
/// shows. The kernel allows them without privileges on the console that is the caller's
/// controlling terminal, which a program has when the user started it from a text console. The
/// key map, the strings of the function keys and the fonts belong to every console of the host,
/// and a key mapped to a string types that string when the user presses the key later, at the
/// shell, which is input injection like TIOCSTI. The calls that only read stay allowed: nano
/// asks VT_GETSTATE whether it runs on a console. KDFONTOP and KDKBDREP also read, which only
/// console tools do. The numbers are the same on x86_64 and arm64.
const CONSOLE_IOCTLS: &[u32] = &[
    // KIOCSOUND, KDMKTONE, KDSETLED, KDSKBLED: the speaker and the keyboard lights.
    0x4b2f, 0x4b30, 0x4b32, 0x4b65,
    // KDSETMODE, KDSKBMODE, KDSKBMETA, KDKBDREP: text or graphics, a raw or disabled keyboard,
    // the repeat rate.
    0x4b3a, 0x4b45, 0x4b63, 0x4b52,
    // KDSKBENT, KDSKBSENT, KDSKBDIACR, KDSKBDIACRUC, KDSETKEYCODE, KDSIGACCEPT: the key map, the
    // function key strings, the accent tables, the scan codes, and the signal of a key.
    0x4b47, 0x4b49, 0x4b4b, 0x4bfb, 0x4b4d, 0x4b4e,
    // PIO_FONT, PIO_FONTX, PIO_FONTRESET, KDFONTOP, PIO_CMAP, PIO_SCRNMAP, PIO_UNISCRNMAP,
    // PIO_UNIMAP, PIO_UNIMAPCLR: fonts, colors and character maps.
    0x4b61, 0x4b6c, 0x4b6d, 0x4b72, 0x4b71, 0x4b41, 0x4b6a, 0x4b67, 0x4b68,
    // VT_SETMODE, VT_RELDISP, VT_ACTIVATE, VT_SETACTIVATE, VT_DISALLOCATE, VT_RESIZE, VT_RESIZEX,
    // VT_LOCKSWITCH, VT_UNLOCKSWITCH: switching consoles, holding a switch back, and the size of
    // every console.
    0x5602, 0x5605, 0x5606, 0x560f, 0x5608, 0x5609, 0x560a, 0x560b, 0x560c,
];

/// The compiled filters, in the order they are installed. The relay and the watcher have no
/// extended attribute and no socket family filter: their denylist allows only the calls and the
/// sockets they need.
#[derive(Debug)]
pub struct Filters {
    pub allowlist: BpfProgram,
    pub denylist: BpfProgram,
    pub path_xattrs: Option<BpfProgram>,
    pub families: Option<BpfProgram>,
}

/// The process that executes the target. The target keeps its process ID after execve, and under
/// no_new_privs its user and group IDs too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetProcess {
    pub pid: u32,
    /// The real, effective and saved user IDs.
    pub uids: [u32; 3],
    /// The real, effective and saved group IDs.
    pub gids: [u32; 3],
}

/// Builds the filters for `config` and the CPU architecture sandy was built for, to be installed
/// by `process`.
pub fn build(config: &FilterConfig, process: &TargetProcess) -> Result<Filters, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    let path_xattrs = config
        .deny_path_metadata
        .then(|| xattr_filter(target))
        .transpose()?;
    Ok(Filters {
        allowlist: allowlist(target)?,
        denylist: denylist(config, process, target)?,
        path_xattrs,
        families: Some(family_filter(config, target)?),
    })
}

/// The third filter: the extended attribute reads that take a path, and the changes through a
/// descriptor, fail with ENOTSUP, the error of a file system without extended attributes, so
/// that `cp -a`, `rsync -X`, `tar --xattrs` and `sed -i` skip them instead of reporting a
/// failure. It follows `path_metadata`, which decides the same question for the calls that
/// change metadata by path.
fn xattr_filter(target: TargetArch) -> Result<BpfProgram, BackendError> {
    let rules = PATH_XATTR_READS
        .iter()
        .chain(DESCRIPTOR_XATTR_CHANGES)
        .map(|&call| (call, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOTSUP as u32),
        target,
    )?;
    filter.try_into()
}

/// The fourth filter: `socket` with a family the policy denies fails with EAFNOSUPPORT instead of
/// EPERM, so that a program which probes for a family falls back as it would on a kernel without
/// it. Installed last, because the kernel takes the newest filter's result among equal actions.
fn family_filter(config: &FilterConfig, target: TargetArch) -> Result<BpfProgram, BackendError> {
    let rules = BTreeMap::from([(libc::SYS_socket, socket_rules(config)?)]);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        target,
    )?;
    filter.try_into()
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
    process: &TargetProcess,
    target: TargetArch,
) -> Result<BpfProgram, BackendError> {
    let mut rules = Rules::default();
    for &call in DENIED.iter().chain(arch::DENIED) {
        rules.add(call, Vec::new());
    }
    rules.add(libc::SYS_ioctl, ioctl_rules(config)?);
    rules.add(libc::SYS_fcntl, lease_rules()?);
    rules.add(libc::SYS_socket, raw_ip_rules()?);
    rules.add(libc::SYS_setsockopt, socket_option_rules(true)?);
    rules.add(libc::SYS_getsockopt, socket_option_rules(false)?);
    for call in [libc::SYS_mbind, libc::SYS_move_pages] {
        let move_all = SeccompCmpOp::MaskedEq(MPOL_MF_MOVE_ALL);
        rules.add(call, vec![rule(vec![low(5, move_all, MPOL_MF_MOVE_ALL)?])?]);
    }
    for (calls, held) in [(UID_CALLS, &process.uids), (GID_CALLS, &process.gids)] {
        for &(call, count) in calls {
            rules.add(call, unheld_id_rules(0..count, held)?);
        }
    }
    // Where an administrator enabled KSM, the kernel shares mergeable pages of the program with
    // identical pages of other processes, and the time a write to such a page takes tells the
    // program whether another process holds the same content. PR_SET_MEMORY_MERGE makes every
    // page of the process mergeable, without a capability; turning it off (0, compared on all
    // 64 bits like the kernel) stays allowed.
    let mergeable = low(2, SeccompCmpOp::Eq, libc::MADV_MERGEABLE as u64)?;
    rules.add(libc::SYS_madvise, vec![rule(vec![mergeable])?]);
    let merge_all = rule(vec![
        low(0, SeccompCmpOp::Eq, libc::PR_SET_MEMORY_MERGE as u64)?,
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Ne, 0)?,
    ])?;
    let mut prctl = prctl_rules()?;
    prctl.push(merge_all);
    rules.add(libc::SYS_prctl, prctl);
    rules.add(libc::SYS_socketpair, socketpair_rules(config)?);
    if !config.allow_ip && !config.allow_unix {
        // The only sockets left are connected pairs, which need none of these. bind would let
        // one end take an abstract name that a service outside binds later; the Landlock scope
        // checks connect and send, not bind.
        for call in [
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
        ] {
            rules.add(call, Vec::new());
        }
    } else if config.deny_inbound {
        // Landlock does not check the port that listen gives an unbound TCP socket (measured on
        // Linux 7.2), so only this keeps the program from listening.
        for call in [libc::SYS_listen, libc::SYS_accept, libc::SYS_accept4] {
            rules.add(call, Vec::new());
        }
    }
    let mut clone = namespace_rules(CLONE_NAMESPACES)?;
    // CLONE_PARENT makes the new process a child of the program's parent, a process outside the
    // sandbox, which then receives its SIGCHLD and has to reap it.
    let parent = libc::CLONE_PARENT as u64;
    clone.push(rule(vec![low(0, SeccompCmpOp::MaskedEq(parent), parent)?])?);
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
    if config.keep_process_group {
        rules.add(libc::SYS_setsid, Vec::new());
        rules.add(libc::SYS_setpgid, Vec::new());
    } else if config.isolate_signals {
        // Group 0 makes the process a group leader. Every other group ID joins a group that
        // exists, and a terminal then stops or signals that whole group with the program in it.
        rules.add(
            libc::SYS_setpgid,
            vec![rule(vec![low(1, SeccompCmpOp::Ne, 0)?])?],
        );
    }
    let unshare: Vec<i32> = [CLONE_NAMESPACES, &[libc::CLONE_NEWTIME]].concat();
    rules.add(libc::SYS_unshare, namespace_rules(&unshare)?);
    let personality = PERSONALITIES
        .iter()
        .map(|&value| low(0, SeccompCmpOp::Ne, value))
        .collect::<Result<_, _>>()?;
    rules.add(libc::SYS_personality, vec![rule(personality)?]);
    if config.deny_path_metadata {
        for &call in PATH_METADATA
            .iter()
            .chain(arch::PATH_METADATA)
            .chain(DESCRIPTOR_METADATA)
        {
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
        // Under "deny" these calls are denied completely. The group stays with the kernel: a
        // process may give its file any of its supplementary groups, which the filter does not
        // know.
        for &(call, uid) in CHOWN_CALLS.iter().chain(arch::CHOWN_CALLS) {
            rules.add(call, unheld_id_rules([uid], &process.uids)?);
        }
    }
    // With children = "allowed", a process the program started can outlive it, and once the
    // program's ID belongs to another process of the user, the exemption would cover that one.
    let own_pid =
        (config.deny_children || config.keep_process_group).then_some(u64::from(process.pid));
    for &(call, pid) in PROCESS_CALLS {
        rules.add(call, vec![other_process(pid, own_pid)?]);
    }
    for &(call, one_process) in PROCESS_SELECTOR_CALLS {
        let group_or_user = rule(vec![low(0, SeccompCmpOp::Ne, one_process)?])?;
        let mut selector_rules = vec![group_or_user, other_process(1, own_pid)?];
        if call == libc::SYS_ioprio_set {
            let class = SeccompCmpOp::MaskedEq(IOPRIO_CLASS_MASK);
            selector_rules.push(rule(vec![low(2, class, IOPRIO_CLASS_RT)?])?);
        }
        rules.add(call, selector_rules);
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
/// sandbox would run it. TIOCSETD changes the line discipline of the terminal, and the kernel
/// loads the module of a discipline on demand (dev.tty.ldisc_autoload). TIOCEXCL makes every
/// later open of the terminal fail with EBUSY for processes without CAP_SYS_ADMIN, also after the
/// program has ended, so that a pager or a password prompt outside cannot open /dev/tty. The
/// console ioctls change a virtual console and its keyboard for the whole host. The file system
/// ioctls change files through descriptors that Landlock opened for reading. With isolated
/// signals, TIOCSPGRP, TIOCSWINSZ and TIOCSIG are denied too: the first gives the terminal to
/// another job of the session, which then stops at its next read, the second makes the kernel
/// send SIGWINCH to the foreground group, and the third, on the master side of a pseudo-terminal,
/// sends SIGINT, SIGQUIT or SIGTSTP to the foreground group of the other side. Writing the
/// interrupt, quit or suspend character into the master does the same and stays possible, because
/// a write cannot be told from any other. `CAPABILITY_IOCTLS` need a capability.
fn ioctl_rules(config: &FilterConfig) -> Result<Vec<SeccompRule>, BackendError> {
    let mut commands = vec![
        libc::TIOCSTI as u32,
        libc::TIOCLINUX as u32,
        libc::TIOCSETD as u32,
        libc::TIOCEXCL as u32,
    ];
    commands.extend(CONSOLE_IOCTLS);
    commands.extend(FILE_SYSTEM_IOCTLS);
    commands.extend(CAPABILITY_IOCTLS);
    if config.isolate_signals {
        commands.extend([
            libc::TIOCSPGRP as u32,
            libc::TIOCSWINSZ as u32,
            libc::TIOCSIG as u32,
        ]);
    }
    let mut rules: Vec<SeccompRule> = commands
        .into_iter()
        .map(|command| rule(vec![low(1, SeccompCmpOp::Eq, u64::from(command))?]))
        .collect::<Result<_, _>>()?;
    let pidfd_info = low(
        1,
        SeccompCmpOp::MaskedEq(PIDFD_GET_INFO_MASK),
        PIDFD_GET_INFO,
    )?;
    rules.push(rule(vec![pidfd_info])?);
    Ok(rules)
}

/// A lease or a delegation needs only a read descriptor of a file the user owns, and Landlock
/// does not cover fcntl. While the program holds one, a process outside that opens the file for
/// writing, or changes the directory of a delegation, waits until the program gives it up or
/// /proc/sys/fs/lease-break-time passes (45 seconds by default). Giving one up (F_UNLCK) stays
/// allowed; the argument of F_SETDELEG is a pointer, so that command is denied as a whole.
fn lease_rules() -> Result<Vec<SeccompRule>, BackendError> {
    let lease = rule(vec![
        low(1, SeccompCmpOp::Eq, libc::F_SETLEASE as u64)?,
        low(2, SeccompCmpOp::Ne, libc::F_UNLCK as u64)?,
    ])?;
    let delegation = rule(vec![low(1, SeccompCmpOp::Eq, F_SETDELEG)?])?;
    Ok(vec![lease, delegation])
}

/// `CAPABILITY_PRCTLS`, and raising an ambient capability, which needs the capability in the
/// permitted and inheritable sets, both empty for the program. Lowering, clearing and asking stay
/// allowed. The kernel compares the subcommand, an unsigned long, on all 64 bits.
fn prctl_rules() -> Result<Vec<SeccompRule>, BackendError> {
    let option = |option: i32| low(0, SeccompCmpOp::Eq, option as u64);
    let mut rules: Vec<SeccompRule> = CAPABILITY_PRCTLS
        .iter()
        .map(|&denied| rule(vec![option(denied)?]))
        .collect::<Result<_, _>>()?;
    let raise = SeccompCondition::new(
        1,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        libc::PR_CAP_AMBIENT_RAISE as u64,
    )?;
    rules.push(rule(vec![option(libc::PR_CAP_AMBIENT)?, raise])?);
    Ok(rules)
}

/// Raw IP sockets need CAP_NET_RAW. A second layer; ping uses ICMP datagram sockets, which need
/// none. Where the policy denies IP, the EAFNOSUPPORT of the family filter wins.
fn raw_ip_rules() -> Result<Vec<SeccompRule>, BackendError> {
    [libc::AF_INET, libc::AF_INET6]
        .into_iter()
        .map(|family| {
            rule(vec![
                low(0, SeccompCmpOp::Eq, family as u64)?,
                low(
                    1,
                    SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                    libc::SOCK_RAW as u64,
                )?,
            ])
        })
        .collect()
}

/// `CAPABILITY_SOCKET_OPTIONS` when `set`, and `FIREWALL_SOCKET_OPTIONS` for both calls. A
/// second layer.
fn socket_option_rules(set: bool) -> Result<Vec<SeccompRule>, BackendError> {
    let level = |level: i32| low(1, SeccompCmpOp::Eq, level as u64);
    let mut rules = Vec::new();
    if set {
        for &(at, option) in CAPABILITY_SOCKET_OPTIONS {
            let option = low(2, SeccompCmpOp::Eq, option as u64)?;
            rules.push(rule(vec![level(at)?, option])?);
        }
    }
    for &(at, first, last) in FIREWALL_SOCKET_OPTIONS {
        rules.push(rule(vec![
            level(at)?,
            low(2, SeccompCmpOp::Ge, u64::from(first))?,
            low(2, SeccompCmpOp::Le, u64::from(last))?,
        ])?);
    }
    Ok(rules)
}

/// An allowlist of socket families. A denylist of AF_INET and AF_INET6 is not enough: other
/// families, for example AF_SMC, fall back to TCP. Within AF_INET and AF_INET6 an allowlist of
/// protocols, because the kernel loads the module of a protocol such as SCTP, L2TP or SMC when a
/// program asks for a socket of it (`IP_PROTOCOLS`).
fn socket_rules(config: &FilterConfig) -> Result<Vec<SeccompRule>, BackendError> {
    let mut allowed = Vec::new();
    if config.allow_unix {
        allowed.push(libc::AF_UNIX);
    }
    if config.allow_ip {
        allowed.extend([libc::AF_INET, libc::AF_INET6]);
        allowed.extend(IP_ALSO_ALLOWS.iter().map(|socket| socket.family));
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
        for family in [libc::AF_INET, libc::AF_INET6] {
            let mut other_protocol = vec![low(0, SeccompCmpOp::Eq, family as u64)?];
            for &protocol in IP_PROTOCOLS {
                other_protocol.push(low(2, SeccompCmpOp::Ne, protocol as u64)?);
            }
            rules.push(rule(other_protocol)?);
        }
        for socket in IP_ALSO_ALLOWS {
            rules.push(rule(vec![
                low(0, SeccompCmpOp::Eq, socket.family as u64)?,
                low(2, SeccompCmpOp::Ne, socket.protocol as u64)?,
            ])?);
        }
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

/// One rule per ID argument at `args`: it matches an ID that is neither one of `held` nor -1. A
/// second layer, like the calls of `DENIED` that need a capability. The kernel reads the IDs as
/// 32-bit values.
fn unheld_id_rules(
    args: impl IntoIterator<Item = u8>,
    held: &[u32; 3],
) -> Result<Vec<SeccompRule>, BackendError> {
    let allowed: BTreeSet<u32> = held.iter().copied().chain([u32::MAX]).collect();
    args.into_iter()
        .map(|arg| {
            let unheld = allowed
                .iter()
                .map(|&id| low(arg, SeccompCmpOp::Ne, u64::from(id)))
                .collect::<Result<_, _>>()?;
            rule(unheld)
        })
        .collect()
}

/// Matches a process ID argument that names neither the caller (0) nor the target (`own_pid`,
/// when given). Children of the target therefore cannot use these calls on each other, and a
/// thread ID other than the main thread's counts as another process.
fn other_process(pid: u8, own_pid: Option<u64>) -> Result<SeccompRule, BackendError> {
    let mut conditions = vec![low(pid, SeccompCmpOp::Ne, 0)?];
    if let Some(own_pid) = own_pid {
        conditions.push(low(pid, SeccompCmpOp::Ne, own_pid)?);
    }
    rule(conditions)
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

/// The access mode bits of the open flags, as the kernel reads them. Not `libc::O_ACCMODE`: musl
/// adds O_PATH to it, and the rules below then matched only opens with O_PATH set.
const O_ACCMODE: u64 = 3;

/// Access mode 3 opens a file for ioctl only. Landlock requires no right for such an open, and
/// fchmod, fchown and fsetxattr work on the descriptor, so it would bypass both Landlock and the
/// metadata rules. Before Landlock ABI 3, O_TRUNC also truncates a file that is opened read-only,
/// without a Landlock check.
fn open_rules(flags: u8, restrict_truncate: bool) -> Result<Vec<SeccompRule>, BackendError> {
    let ioctl_only = low(flags, SeccompCmpOp::MaskedEq(O_ACCMODE), O_ACCMODE)?;
    let mut rules = vec![rule(vec![ioctl_only])?];
    if restrict_truncate {
        let trunc = libc::O_TRUNC as u64;
        let read_only_trunc = low(
            flags,
            SeccompCmpOp::MaskedEq(O_ACCMODE | trunc),
            trunc | libc::O_RDONLY as u64,
        )?;
        rules.push(rule(vec![read_only_trunc])?);
    }
    Ok(rules)
}

/// What the relay for exposed ports needs: accept and connect TCP, copy bytes, start threads,
/// wait for the program to end, and keep its watchdog armed. Everything else fails with EPERM.
/// clone3 is listed so that the shared allowlist, installed with it, decides: ENOSYS.
const RELAY_CALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    // With ip = "private", the forward listeners and the sockets of the factory arrive over a
    // socket pair (`handover`, `factory`).
    libc::SYS_recvmsg,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_shutdown,
    libc::SYS_getsockopt,
    // SO_LINGER, so that a cut connection ends with a reset; SO_RCVTIMEO for the read tick.
    libc::SYS_setsockopt,
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
    // Takes a pending SIGCONT, which is how the relay sees that it was stopped.
    libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    // With signals = "any" the relay re-arms its watchdog timer on every turn of the poll loop.
    // The timer itself is created before the filter is installed, so timer_create is not allowed
    // here.
    libc::SYS_timer_settime,
    libc::SYS_getrandom,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// What the watcher of `end_with_parent` needs: poll two pidfds, signal the program through its
/// pidfd, write the readiness report with its process ID, and end. The memory calls cover allocations of the Rust
/// runtime. Everything else fails with EPERM. `pidfd_send_signal` has rules of its own.
const WATCHER_CALLS: &[i64] = &[
    libc::SYS_ppoll,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_getpid,
    libc::SYS_clock_gettime,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_mprotect,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// What the socket factory of exposed ports needs once it is confined: read a request, send a
/// socket back, write the readiness report with its process ID, and end. The memory calls cover
/// allocations of the Rust runtime. `socket` has a rule of its own; everything else fails with
/// EPERM, `connect`, `bind` and `listen` among them.
const FACTORY_CALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_sendmsg,
    libc::SYS_close,
    libc::SYS_getpid,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_mprotect,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// The signals the watcher sends to end the program: the request, a continue so that a stopped
/// program receives the request, and the kill after the grace period.
const WATCHER_SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGCONT, libc::SIGKILL];

/// Builds the filters of the watcher: the shared allowlist and a list that allows only
/// `WATCHER_CALLS`, and `pidfd_send_signal` only with one of `WATCHER_SIGNALS` through
/// `program`, the number of the program's pidfd. The watcher also holds a pidfd for the process
/// that started sandy, which it must never signal.
pub fn watcher(program: i32) -> Result<Filters, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    let mut rules = Rules::default();
    for &call in WATCHER_CALLS.iter().chain(arch::RELAY_CALLS) {
        rules.add(call, Vec::new());
    }
    let send = WATCHER_SIGNALS
        .into_iter()
        .map(|signal| {
            rule(vec![
                low(0, SeccompCmpOp::Eq, program as u64)?,
                low(1, SeccompCmpOp::Eq, signal as u64)?,
                // No siginfo, so that the kernel fills it in, and no flags. The siginfo is a
                // pointer, so all 64 bits must be zero.
                SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)?,
                low(3, SeccompCmpOp::Eq, 0)?,
            ])
        })
        .collect::<Result<Vec<SeccompRule>, BackendError>>()?;
    rules.add(libc::SYS_pidfd_send_signal, send);
    let filter = SeccompFilter::new(
        rules.0,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target,
    )?;
    Ok(Filters {
        allowlist: allowlist(target)?,
        denylist: filter.try_into()?,
        path_xattrs: None,
        families: None,
    })
}

/// Builds the filters of the relay: the shared allowlist and the relay's own list, which allows
/// only `RELAY_CALLS`, TCP sockets, threads without namespaces, and FIONBIO. The relay serves
/// each connection in a thread and never starts a process, so clone needs CLONE_THREAD. A
/// socket must use protocol 0, which is TCP: another stream protocol, such as SCTP or MPTCP,
/// would make the kernel load its module.
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
            low(2, SeccompCmpOp::Eq, 0)?,
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
    let thread = libc::CLONE_THREAD as u64;
    let a_thread = low(0, SeccompCmpOp::MaskedEq(thread), thread)?;
    rules.add(libc::SYS_clone, vec![rule(vec![no_namespace, a_thread])?]);
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
        path_xattrs: None,
        families: None,
    })
}

/// Builds the filters of the socket factory: the shared allowlist and a list that allows only
/// `FACTORY_CALLS` and `socket` for TCP over IPv4 and IPv6 with protocol 0, which is TCP.
pub fn factory() -> Result<Filters, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    let mut rules = Rules::default();
    for &call in FACTORY_CALLS {
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
            low(2, SeccompCmpOp::Eq, 0)?,
        ])
    };
    rules.add(
        libc::SYS_socket,
        vec![tcp(libc::AF_INET)?, tcp(libc::AF_INET6)?],
    );
    let filter = SeccompFilter::new(
        rules.0,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target,
    )?;
    Ok(Filters {
        allowlist: allowlist(target)?,
        denylist: filter.try_into()?,
        path_xattrs: None,
        families: None,
    })
}

/// What the watcher thread of the diagnostic mode needs once it holds the notification
/// descriptor: wait for a notification, read the path out of the calling process, resolve it
/// with the stat, access and readlink family, and end. The memory calls cover the allocator and the
/// futex the lock of standard error. `ioctl`, `write`, `writev`, `mmap` and `mprotect` have
/// rules of their own.
const EXPLAIN_WATCHER_CALLS: &[i64] = &[
    libc::SYS_ppoll,
    libc::SYS_process_vm_readv,
    libc::SYS_readlinkat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_fstat,
    libc::SYS_getcwd,
    libc::SYS_close,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_clock_gettime,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// The filter of the diagnostic mode's watcher thread, which parses bytes the program controls
/// outside the sandbox. It is installed on that thread alone. ioctl is allowed only on
/// `listener`, the notification descriptor, and only with `requests`, the notification
/// interface; write only to standard error; mmap and mprotect only without PROT_EXEC, so the
/// thread cannot make code of its own. Any other call ends sandy with SIGSYS: a watcher that
/// went on after a denied call would report what it did not see, and the program keeps its
/// sandbox, with its watched calls failing with ENOSYS from then on.
pub fn explain_watcher(listener: i32, requests: &[u32]) -> Result<BpfProgram, BackendError> {
    let target = arch::TARGET
        .ok_or_else(|| BackendError::InvalidTargetArch(std::env::consts::ARCH.to_string()))?;
    let mut rules = Rules::default();
    for &call in EXPLAIN_WATCHER_CALLS
        .iter()
        .chain(arch::RELAY_CALLS)
        .chain(arch::PATH_LOOKUP_CALLS)
    {
        rules.add(call, Vec::new());
    }
    let notify = requests
        .iter()
        .map(|&request| {
            rule(vec![
                low(0, SeccompCmpOp::Eq, listener as u64)?,
                low(1, SeccompCmpOp::Eq, u64::from(request))?,
            ])
        })
        .collect::<Result<_, _>>()?;
    rules.add(libc::SYS_ioctl, notify);
    let standard_error = libc::STDERR_FILENO as u64;
    for call in [libc::SYS_write, libc::SYS_writev] {
        rules.add(
            call,
            vec![rule(vec![low(0, SeccompCmpOp::Eq, standard_error)?])?],
        );
    }
    // Rust's standard library asks whether a descriptor is still open before it closes it.
    let descriptor_flags = low(1, SeccompCmpOp::Eq, libc::F_GETFD as u64)?;
    rules.add(libc::SYS_fcntl, vec![rule(vec![descriptor_flags])?]);
    let executable = libc::PROT_EXEC as u64;
    for call in [libc::SYS_mmap, libc::SYS_mprotect] {
        let no_code = low(2, SeccompCmpOp::MaskedEq(executable), 0)?;
        rules.add(call, vec![rule(vec![no_code])?]);
    }
    let filter = SeccompFilter::new(
        rules.0,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        target,
    )?;
    filter.try_into()
}

/// The program of the diagnostic mode (`explain`): `calls` return SECCOMP_RET_USER_NOTIF, every
/// other call and every other CPU architecture is allowed. It is written by hand, because
/// seccompiler has no notification action.
///
/// The program cannot change what the sandbox allows. USER_NOTIF is less restrictive than every
/// action the other filters use, so a call they deny keeps their answer and never reaches the
/// watcher (measured on Linux 7.2), and ALLOW is what they would have returned anyway. Only a
/// call that all filters allow notifies, and the watcher answers with
/// SECCOMP_USER_NOTIF_FLAG_CONTINUE, which leaves the decision to Landlock. See `explain.rs`.
pub fn observer(calls: &[i64]) -> BpfProgram {
    const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JUMP_EQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    /// Offsets of `nr` and `arch` in `struct seccomp_data`.
    const CALL: u32 = 0;
    const ARCHITECTURE: u32 = 4;

    let insn = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    // Every jump leads to one of the two return instructions at the end: the comparison of call
    // number `index` jumps over the `count - index - 1` comparisons after it and over the allow,
    // and the architecture check jumps over every comparison and lands on the allow.
    let count = calls.len();
    let to_allow =
        u8::try_from(count + 1).expect("the observer watches few enough calls for one jump");
    let mut program = vec![
        insn(LOAD, 0, 0, ARCHITECTURE),
        insn(JUMP_EQ, 0, to_allow, arch::AUDIT_ARCH),
        insn(LOAD, 0, 0, CALL),
    ];
    for (index, &call) in calls.iter().enumerate() {
        let to_notify = (count - index) as u8;
        program.push(insn(JUMP_EQ, to_notify, 0, call as u32));
    }
    program.push(insn(RETURN, 0, 0, libc::SECCOMP_RET_ALLOW));
    program.push(insn(RETURN, 0, 0, libc::SECCOMP_RET_USER_NOTIF));
    program
}

/// Installs the filters on every thread of the process, in order. They stay in force across
/// execve and are inherited by every child.
pub fn install(filters: &Filters) -> Result<(), seccompiler::Error> {
    let programs = [
        Some(&filters.allowlist),
        Some(&filters.denylist),
        filters.path_xattrs.as_ref(),
        filters.families.as_ref(),
    ];
    for program in programs.into_iter().flatten() {
        seccompiler::apply_filter_all_threads(program)?;
    }
    Ok(())
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    use seccompiler::sock_filter;

    const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    const RET_NO_FAMILY: u32 = libc::SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32;
    const RET_NO_XATTRS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOTSUP as u32;
    const RET_USER_NOTIF: u32 = libc::SECCOMP_RET_USER_NOTIF;

    /// The highest system call number the tests and the snapshot look at. Above the reviewed
    /// table, so they also record what the programs do with the numbers of a newer kernel.
    const LAST_CALL: i64 = 511;

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

    /// Runs every filter like the kernel: the most restrictive action wins, and among equal
    /// actions the most recently installed filter.
    const OWN_PID: u32 = 4242;
    const OWN_UID: u32 = 1000;
    const OWN_GID: u32 = 100;
    const OWN: TargetProcess = TargetProcess {
        pid: OWN_PID,
        uids: [OWN_UID; 3],
        gids: [OWN_GID; 3],
    };

    fn decide(config: &FilterConfig, arch: u32, nr: i64, args: [u64; 6]) -> u32 {
        decide_with(&build(config, &OWN).unwrap(), arch, nr, args)
    }

    fn decide_with(filters: &Filters, arch: u32, nr: i64, args: [u64; 6]) -> u32 {
        let rank = |action: u32| (action & libc::SECCOMP_RET_ACTION_FULL) as i32;
        let mut result = RET_ALLOW;
        // Newest first, as the kernel walks the list.
        let installed = filters
            .families
            .iter()
            .chain(&filters.path_xattrs)
            .chain([&filters.denylist, &filters.allowlist]);
        for program in installed {
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
            deny_inbound: false,
            restrict_truncate: false,
            deny_path_metadata: true,
            deny_children: true,
            keep_process_group: true,
            isolate_signals: true,
        }
    }

    fn open() -> FilterConfig {
        FilterConfig {
            allow_ip: true,
            allow_unix: true,
            deny_inbound: false,
            restrict_truncate: false,
            deny_path_metadata: false,
            deny_children: false,
            keep_process_group: false,
            isolate_signals: false,
        }
    }

    /// `children = "contained"` requires `signals = "isolated"`.
    fn contained() -> FilterConfig {
        FilterConfig {
            keep_process_group: true,
            isolate_signals: true,
            ..open()
        }
    }

    fn isolated() -> FilterConfig {
        FilterConfig {
            isolate_signals: true,
            ..open()
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
            let filters = build(&config, &OWN).unwrap();
            let programs = filters
                .families
                .iter()
                .chain(&filters.path_xattrs)
                .chain([&filters.allowlist, &filters.denylist]);
            for program in programs {
                assert!(program.len() < 4096);
            }
        }
    }

    /// The golden snapshot of the compiled programs. x86_64 only: arm64 has its own system
    /// call numbers, so its snapshot would have to be written on an arm64 Linux host.
    #[cfg(target_arch = "x86_64")]
    mod snapshot {
        use super::*;

        /// The pidfd of the program in the watcher's snapshot, which its rules compare against.
        const WATCHED_PROGRAM: i32 = 4;

        /// Repeated at the top of the snapshot file, so the file says what it is.
        const SNAPSHOT_HEADER: &str = "\
# The compiled seccomp programs of sandy's configurations on x86_64, written by
# compiled_programs_match_the_snapshot in crates/sandy-linux/src/filter.rs.
#
# Every section names one program, how many instructions it has, a checksum of them, and the
# action it returns for each system call number with all arguments zero. Rules that look at
# arguments do not show in that table, because their call is allowed with zero arguments; the
# checksum covers them, and the tests next to the snapshot check what they decide.
#
# A diff here means a filter, the reviewed table or seccompiler's code generation changed.
";

        /// A checksum over the compiled instructions. It has to make a change visible, not resist
        /// one, so FNV-1a is enough and needs no dependency.
        fn checksum(program: &[sock_filter]) -> u64 {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            let bytes = program.iter().flat_map(|insn| {
                insn.code
                    .to_le_bytes()
                    .into_iter()
                    .chain([insn.jt, insn.jf])
                    .chain(insn.k.to_le_bytes())
            });
            for byte in bytes {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            hash
        }

        fn action_name(action: u32) -> String {
            let errno = (action & libc::SECCOMP_RET_DATA) as i32;
            match action {
                RET_ALLOW => "allow".to_string(),
                RET_USER_NOTIF => "notify".to_string(),
                RET_KILL_PROCESS => "kill process".to_string(),
                _ if action & libc::SECCOMP_RET_ACTION_FULL == libc::SECCOMP_RET_ERRNO => {
                    match errno {
                        libc::EPERM => "EPERM".to_string(),
                        libc::ENOSYS => "ENOSYS".to_string(),
                        libc::ENOTSUP => "ENOTSUP".to_string(),
                        libc::EAFNOSUPPORT => "EAFNOSUPPORT".to_string(),
                        other => format!("errno {other}"),
                    }
                }
                other => format!("action {other:#010x}"),
            }
        }

        /// One section of the snapshot: the size and checksum of `program`, then its decision per
        /// system call number, with numbers that decide the same way collapsed into a range.
        fn render(name: &str, program: &[sock_filter], out: &mut String) {
            out.push_str(&format!(
                "\n[{name}]\ninstructions {}\nchecksum {:#018x}\n",
                program.len(),
                checksum(program)
            ));
            let mut first = 0;
            let mut action = evaluate(program, NATIVE, 0, [0; 6]);
            for nr in 1..=LAST_CALL + 1 {
                let next = (nr <= LAST_CALL).then(|| evaluate(program, NATIVE, nr, [0; 6]));
                if next == Some(action) {
                    continue;
                }
                let last = nr - 1;
                let calls = if first == last {
                    format!("{first}")
                } else {
                    format!("{first}-{last}")
                };
                out.push_str(&format!("{calls} {}\n", action_name(action)));
                first = nr;
                if let Some(next) = next {
                    action = next;
                }
            }
        }

        fn snapshot() -> String {
            let strict = build(&strict(), &OWN).unwrap();
            let open = build(&open(), &OWN).unwrap();
            let watcher = watcher(WATCHED_PROGRAM).unwrap();
            let relay = relay().unwrap();
            let factory = factory().unwrap();
            let mut out = SNAPSHOT_HEADER.to_string();
            for (name, filters) in [
                ("strict", &strict),
                ("open", &open),
                ("watcher", &watcher),
                ("relay", &relay),
                ("factory", &factory),
            ] {
                assert_eq!(
                    checksum(&filters.allowlist),
                    checksum(&strict.allowlist),
                    "the allowlist of {name} differs from the shared one"
                );
                render(&format!("{name} denylist"), &filters.denylist, &mut out);
                if let Some(program) = &filters.path_xattrs {
                    render(&format!("{name} path xattrs"), program, &mut out);
                }
                if let Some(program) = &filters.families {
                    render(&format!("{name} socket families"), program, &mut out);
                }
            }
            render("allowlist", &strict.allowlist, &mut out);
            render(
                "observer",
                &observer(&crate::explain::watched_calls()),
                &mut out,
            );
            let requests = crate::explain::NOTIFICATION_REQUESTS;
            let explain_watcher = explain_watcher(WATCHED_PROGRAM, &requests).unwrap();
            render("explain watcher", &explain_watcher, &mut out);
            out
        }

        /// Pins the compiled programs, so that a change to a rule, to the reviewed table or to
        /// seccompiler shows up as a diff of a committed file instead of passing unnoticed.
        /// Update that file deliberately: write the text the failure prints to it, then read
        /// its diff and check that every line that changed is one you meant to change.
        #[test]
        fn compiled_programs_match_the_snapshot() {
            let expected = include_str!("../snapshots/x86_64.txt");
            let actual = snapshot();
            // Trailing whitespace only: an editor that adds or drops the last newline is no change.
            if actual.trim_end() == expected.trim_end() {
                return;
            }
            // Only the first difference: a changed call shifts the ranges after it, so a line by
            // line report would list every later line as well. The diff of the committed file,
            // once it is updated, names the calls that changed instead.
            let committed: Vec<&str> = expected.lines().collect();
            let now: Vec<&str> = actual.lines().collect();
            let index = (0..committed.len().max(now.len()))
                .find(|&index| committed.get(index) != now.get(index))
                .expect("the texts differ, so one of their lines differs");
            let end = "<end of file>";
            panic!(
                "the compiled programs differ from crates/sandy-linux/snapshots/x86_64.txt, from \
                 line {}:\n  committed: {}\n  now:       {}\n\nWrite the text below to that file \
                 and review its diff. Every difference must be one you meant to make.\n{actual}",
                index + 1,
                committed.get(index).unwrap_or(&end),
                now.get(index).unwrap_or(&end)
            );
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
            libc::SYS_fgetxattr,
        ] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        for nr in [472, 1000, -1] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_ENOSYS, "system call {nr}");
        }
        assert_eq!(call(&open(), libc::SYS_clone3, [0; 6]), RET_ENOSYS);
        assert_eq!(call(&open(), libc::SYS_openat2, [0; 6]), RET_ENOSYS);
    }

    /// A denied family fails with EAFNOSUPPORT, which programs treat as "this kernel does not
    /// have it".
    #[test]
    fn socket_families_follow_the_policy() {
        for family in [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
        ] {
            let args = socket(family, 1, 0);
            assert_eq!(call(&strict(), libc::SYS_socket, args), RET_NO_FAMILY);
            assert_eq!(call(&open(), libc::SYS_socket, args), RET_ALLOW);
        }
        const AF_ALG: i32 = 38;
        const AF_VSOCK: i32 = 40;
        const AF_SMC: i32 = 43;
        for family in [libc::AF_PACKET, AF_VSOCK, AF_ALG, AF_SMC, 0] {
            let args = socket(family, 1, 0);
            assert_eq!(call(&open(), libc::SYS_socket, args), RET_NO_FAMILY);
        }
        const NETLINK_SOCK_DIAG: i32 = 4;
        let diag = socket(libc::AF_NETLINK, 2, NETLINK_SOCK_DIAG);
        assert_eq!(call(&open(), libc::SYS_socket, diag), RET_NO_FAMILY);
        // The usual IP protocols, and not those whose module the kernel would load: SCTP, L2TP
        // over IP, SMC and UDP-Lite. High bits change neither.
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        for family in [libc::AF_INET, libc::AF_INET6] {
            for (kind, protocol) in [(1, 0), (1, 6), (1, 262), (2, 17), (2, 1), (2, 58)] {
                let mut args = socket(family, kind, protocol);
                args[2] |= HIGH;
                assert_eq!(
                    call(&open(), libc::SYS_socket, args),
                    RET_ALLOW,
                    "{protocol}"
                );
            }
            for (kind, protocol) in [(5, 132), (1, 132), (2, 115), (1, 256), (2, 136)] {
                let mut args = socket(family, kind, protocol);
                assert_eq!(
                    call(&open(), libc::SYS_socket, args),
                    RET_NO_FAMILY,
                    "{protocol}"
                );
                args[2] |= HIGH;
                assert_eq!(
                    call(&open(), libc::SYS_socket, args),
                    RET_NO_FAMILY,
                    "{protocol}"
                );
            }
        }
        let ip_only = FilterConfig {
            allow_unix: false,
            ..open()
        };
        let unix = socket(libc::AF_UNIX, 1, 0);
        assert_eq!(call(&ip_only, libc::SYS_socket, unix), RET_NO_FAMILY);
        let unix_only = FilterConfig {
            allow_ip: false,
            ..open()
        };
        assert_eq!(call(&unix_only, libc::SYS_socket, unix), RET_ALLOW);
        let inet = socket(libc::AF_INET, 1, 0);
        assert_eq!(call(&unix_only, libc::SYS_socket, inet), RET_NO_FAMILY);
    }

    #[test]
    fn socket_family_check_uses_the_low_32_bits() {
        let high_bits = (1u64 << 32) | libc::AF_UNIX as u64;
        let args = args(&[high_bits, 1]);
        assert_eq!(call(&strict(), libc::SYS_socket, args), RET_NO_FAMILY);
    }

    /// Without IP and Unix sockets the program has only connected socket pairs, which need no
    /// name, connection or listener; bind could take an abstract name.
    #[test]
    fn sockets_cannot_be_named_without_network_access() {
        for nr in [
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
        ] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_EPERM, "{nr}");
            assert_eq!(call(&open(), nr, [0; 6]), RET_ALLOW, "{nr}");
        }
    }

    /// `ip = "client"`: sockets connect and bind, but none listens or accepts, also not a Unix
    /// socket with `unix_sockets = "all"`. The socket families are those of `ip = "all"`.
    #[test]
    fn client_sockets_neither_listen_nor_accept() {
        for unix in [false, true] {
            let client = FilterConfig {
                allow_unix: unix,
                deny_inbound: true,
                ..open()
            };
            for nr in [libc::SYS_listen, libc::SYS_accept, libc::SYS_accept4] {
                assert_eq!(call(&client, nr, [0; 6]), RET_EPERM, "{nr}");
            }
            for nr in [libc::SYS_bind, libc::SYS_connect, libc::SYS_sendto] {
                assert_eq!(call(&client, nr, [0; 6]), RET_ALLOW, "{nr}");
            }
            for family in [libc::AF_INET, libc::AF_INET6] {
                let args = socket(family, libc::SOCK_STREAM, 0);
                assert_eq!(call(&client, libc::SYS_socket, args), RET_ALLOW);
            }
        }
    }

    /// Every int argument the denylist checks is read by the kernel from its low 32 bits (umode_t
    /// from its low 16), so set high bits must change neither a denial nor an allowance.
    #[test]
    fn argument_rules_decide_on_the_bits_the_kernel_reads() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let own = u64::from(OWN_PID);
        for &(nr, pid_index) in PROCESS_CALLS {
            let with_pid = |pid: u64| {
                let mut args = [0; 6];
                args[usize::from(pid_index)] = pid;
                args
            };
            assert_eq!(call(&open(), nr, with_pid(HIGH)), RET_ALLOW, "{nr}");
            assert_eq!(
                call(&contained(), nr, with_pid(HIGH | own)),
                RET_ALLOW,
                "{nr}"
            );
            assert_eq!(
                call(&contained(), nr, with_pid(HIGH | (own + 1))),
                RET_EPERM,
                "{nr}"
            );
        }
        for &(nr, one_process) in PROCESS_SELECTOR_CALLS {
            let group = args(&[HIGH | (one_process + 1), 0]);
            assert_eq!(call(&open(), nr, group), RET_EPERM, "{nr}");
            let own_process = args(&[HIGH | one_process, HIGH]);
            assert_eq!(call(&open(), nr, own_process), RET_ALLOW, "{nr}");
        }
        for &(nr, flags_index) in arch::OPEN_CALLS {
            let mut ioctl_only = [0; 6];
            ioctl_only[usize::from(flags_index)] = HIGH | 3;
            assert_eq!(call(&open(), nr, ioctl_only), RET_EPERM, "{nr}");
        }
        let setuid = args(&[3, HIGH | 0o4755]);
        assert_eq!(call(&open(), libc::SYS_fchmod, setuid), RET_EPERM);
        let dgram = socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0);
        let dgram = args(&[dgram[0] | HIGH, dgram[1] | HIGH]);
        assert_eq!(call(&strict(), libc::SYS_socketpair, dgram), RET_EPERM);
        let user = args(&[HIGH | libc::CLONE_NEWUSER as u64]);
        assert_eq!(call(&open(), libc::SYS_unshare, user), RET_EPERM);
        const READ_IMPLIES_EXEC: u64 = 0x040_0000;
        let exec = args(&[HIGH | READ_IMPLIES_EXEC]);
        assert_eq!(call(&open(), libc::SYS_personality, exec), RET_EPERM);
        assert_eq!(
            call(&open(), libc::SYS_personality, args(&[HIGH])),
            RET_ALLOW
        );
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
    fn terminal_ioctls_are_denied_also_with_high_bits_set() {
        let denied = [
            libc::TIOCSTI,
            libc::TIOCLINUX,
            libc::TIOCSETD,
            libc::TIOCEXCL,
        ];
        for command in denied.map(|command| u64::from(command as u32)) {
            for high in [0, 0xffff_ffff_0000_0000] {
                let args = args(&[0, high | command]);
                assert_eq!(call(&open(), libc::SYS_ioctl, args), RET_EPERM);
            }
        }
        // Giving up exclusive mode, and asking for it, stay allowed.
        let allowed = [
            libc::TIOCGWINSZ,
            libc::TIOCGETD,
            libc::TIOCNXCL,
            libc::TIOCGEXCL,
        ];
        for command in allowed.map(|c| u64::from(c as u32)) {
            let args = args(&[0, command]);
            assert_eq!(call(&strict(), libc::SYS_ioctl, args), RET_ALLOW);
        }
    }

    #[test]
    fn file_system_ioctls_that_change_files_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        // FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR, FS_IOC_SETVERSION, ext4's own number for it, both
        // forms of BTRFS_IOC_SET_RECEIVED_SUBVOL, and FIDEDUPERANGE.
        for command in [
            0x4008_6602,
            0x401c_5820,
            0x4008_7602,
            0x4008_6604,
            0xc0c8_9425,
            0xc0c0_9425,
            0xc018_9436,
        ] {
            assert!(FILE_SYSTEM_IOCTLS.contains(&command), "{command:#x}");
        }
        for &command in FILE_SYSTEM_IOCTLS {
            let args = args(&[3, HIGH | u64::from(command)]);
            for config in [strict(), open()] {
                assert_eq!(
                    call(&config, libc::SYS_ioctl, args),
                    RET_EPERM,
                    "{command:#x}"
                );
            }
        }
        // The forms that only read stay allowed: FS_IOC_GETFLAGS and FS_IOC_FSGETXATTR. So does
        // FICLONE, which `cp` uses and which needs a destination opened for writing.
        for command in [0x8008_6601u32, 0x801c_581f, 0x4004_9409] {
            let args = args(&[3, u64::from(command)]);
            assert_eq!(
                call(&open(), libc::SYS_ioctl, args),
                RET_ALLOW,
                "{command:#x}"
            );
        }
    }

    #[test]
    fn memory_cannot_be_offered_for_merging() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let advice = |advice: i32| args(&[0x7fff_0000_0000, 4096, HIGH | advice as u64]);
        let merge_all = |on: u64| args(&[HIGH | libc::PR_SET_MEMORY_MERGE as u64, on]);
        for config in [strict(), open()] {
            // The whole process at once, with any value the kernel reads as "on".
            for on in [1, 2, 1 << 32] {
                let decision = call(&config, libc::SYS_prctl, merge_all(on));
                assert_eq!(decision, RET_EPERM, "{on:#x}");
            }
            assert_eq!(call(&config, libc::SYS_prctl, merge_all(0)), RET_ALLOW);
            let ask = args(&[libc::PR_GET_MEMORY_MERGE as u64]);
            assert_eq!(call(&config, libc::SYS_prctl, ask), RET_ALLOW);
            let merge = advice(libc::MADV_MERGEABLE);
            assert_eq!(call(&config, libc::SYS_madvise, merge), RET_EPERM);
            for other in [
                libc::MADV_UNMERGEABLE,
                libc::MADV_DONTNEED,
                libc::MADV_HUGEPAGE,
            ] {
                let args = advice(other);
                assert_eq!(call(&config, libc::SYS_madvise, args), RET_ALLOW, "{other}");
            }
        }
    }

    #[test]
    fn process_details_through_a_pidfd_are_denied() {
        // The sizes of Linux 6.13, of libsystemd, and of a larger structure, also with high bits.
        for command in [
            0xc040_ff0bu64,
            0xc048_ff0b,
            0xc050_ff0b,
            0xffff_ffff_c040_ff0b,
        ] {
            for config in [strict(), open()] {
                let args = args(&[3, command]);
                assert_eq!(
                    call(&config, libc::SYS_ioctl, args),
                    RET_EPERM,
                    "{command:#x}"
                );
            }
        }
        // PIDFD_GET_NET_NAMESPACE, which needs ptrace access that Landlock gives only inside the
        // sandbox, and another call of the same number without the read-write direction.
        for command in [0xff06u64, 0x8040_ff0b] {
            let args = args(&[3, command]);
            assert_eq!(
                call(&open(), libc::SYS_ioctl, args),
                RET_ALLOW,
                "{command:#x}"
            );
        }
    }

    #[test]
    fn console_ioctls_that_change_the_console_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        // KDSKBENT, KDSKBSENT, KDSKBMODE and VT_ACTIVATE.
        for command in [0x4b47, 0x4b49, 0x4b45, 0x5606] {
            assert!(CONSOLE_IOCTLS.contains(&command), "{command:#x}");
        }
        for &command in CONSOLE_IOCTLS {
            let args = args(&[0, HIGH | u64::from(command)]);
            for config in [strict(), open()] {
                assert_eq!(
                    call(&config, libc::SYS_ioctl, args),
                    RET_EPERM,
                    "{command:#x}"
                );
            }
        }
        // The forms that only read stay allowed: KDGKBTYPE, KDGKBMODE, KDGKBENT, KDGKBSENT,
        // VT_GETMODE and VT_GETSTATE.
        for command in [0x4b33u32, 0x4b44, 0x4b46, 0x4b48, 0x5601, 0x5603] {
            let args = args(&[0, u64::from(command)]);
            assert_eq!(
                call(&open(), libc::SYS_ioctl, args),
                RET_ALLOW,
                "{command:#x}"
            );
        }
    }

    #[test]
    fn ioctls_that_need_a_capability_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let named = [libc::TIOCVHANGUP, libc::TIOCCONS, libc::TIOCSLCKTRMIOS];
        for command in named.map(|command| command as u32) {
            assert!(CAPABILITY_IOCTLS.contains(&command), "{command:#x}");
        }
        for &command in CAPABILITY_IOCTLS {
            let args = args(&[0, HIGH | u64::from(command)]);
            for config in [strict(), open()] {
                let decision = call(&config, libc::SYS_ioctl, args);
                assert_eq!(decision, RET_EPERM, "{command:#x}");
            }
        }
        // The forms that only read stay allowed: TIOCGLCKTRMIOS and FS_IOC_GETFSLABEL. So does
        // TIOCSCTTY, which needs a capability only to take a terminal from another session.
        let allowed = [
            libc::TIOCGLCKTRMIOS as u32,
            0x8100_9431,
            libc::TIOCSCTTY as u32,
        ];
        for command in allowed {
            let args = args(&[0, u64::from(command), 1]);
            let decision = call(&open(), libc::SYS_ioctl, args);
            assert_eq!(decision, RET_ALLOW, "{command:#x}");
        }
    }

    /// MPOL_MF_MOVE_ALL moves the pages that other processes map as well. MPOL_MF_MOVE, which
    /// moves only the caller's own pages, stays allowed.
    #[test]
    fn pages_that_other_processes_map_cannot_be_moved() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        const MPOL_MF_MOVE: u64 = 1 << 1;
        for config in [strict(), open()] {
            for nr in [libc::SYS_mbind, libc::SYS_move_pages] {
                let with_flags = |flags: u64| args(&[0, 0, 0, 0, 0, flags]);
                for flags in [MPOL_MF_MOVE_ALL, MPOL_MF_MOVE_ALL | MPOL_MF_MOVE] {
                    let decision = call(&config, nr, with_flags(HIGH | flags));
                    assert_eq!(decision, RET_EPERM, "{nr} {flags:#x}");
                }
                for flags in [0, MPOL_MF_MOVE, HIGH] {
                    let decision = call(&config, nr, with_flags(flags));
                    assert_eq!(decision, RET_ALLOW, "{nr} {flags:#x}");
                }
            }
        }
    }

    /// The program of the diagnostic mode has only these two answers, so it can never be the
    /// filter that decides a call: every other action is more restrictive than USER_NOTIF, and
    /// the kernel takes ALLOW only when every other filter allows the call too.
    #[test]
    fn the_observer_only_allows_or_notifies() {
        let watched = crate::explain::watched_calls();
        let program = observer(&watched);
        for nr in -1..=LAST_CALL {
            let action = evaluate(&program, NATIVE, nr, [0; 6]);
            let expected = if watched.contains(&nr) {
                RET_USER_NOTIF
            } else {
                RET_ALLOW
            };
            assert_eq!(action, expected, "system call {nr}");
        }
        // Another architecture is the allowlist's business, which kills the process.
        const AUDIT_ARCH_I386: u32 = 3 | 0x4000_0000;
        let foreign = evaluate(&program, AUDIT_ARCH_I386, watched[0], [0; 6]);
        assert_eq!(foreign, RET_ALLOW);
    }

    /// The diagnostic mode must not be a way around the sandbox. With the observer installed,
    /// every call keeps the answer it had; only a watched call that was allowed becomes a
    /// notification, which the watcher always continues (`explain::answer_continue`).
    #[test]
    fn the_observer_changes_no_decision() {
        let watched = crate::explain::watched_calls();
        let program = observer(&watched);
        let rank = |action: u32| (action & libc::SECCOMP_RET_ACTION_FULL) as i32;
        for config in [strict(), open()] {
            let filters = build(&config, &OWN).unwrap();
            for nr in -1..=LAST_CALL {
                let without = decide_with(&filters, NATIVE, nr, [0; 6]);
                let observed = evaluate(&program, NATIVE, nr, [0; 6]);
                let with = if rank(observed) < rank(without) {
                    observed
                } else {
                    without
                };
                let notified = watched.contains(&nr) && without == RET_ALLOW;
                let expected = if notified { RET_USER_NOTIF } else { without };
                assert_eq!(with, expected, "system call {nr}");
            }
        }
    }

    #[test]
    fn leases_and_delegations_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let fcntl = |command: u64, argument: u64| args(&[3, HIGH | command, HIGH | argument]);
        for config in [strict(), open()] {
            for kind in [libc::F_RDLCK, libc::F_WRLCK].map(|kind| kind as u64) {
                let lease = fcntl(libc::F_SETLEASE as u64, kind);
                assert_eq!(call(&config, libc::SYS_fcntl, lease), RET_EPERM);
            }
            let delegation = fcntl(F_SETDELEG, 0);
            assert_eq!(call(&config, libc::SYS_fcntl, delegation), RET_EPERM);
            // Giving a lease up, reading one, and the locks that readers need.
            let unlock = fcntl(libc::F_SETLEASE as u64, libc::F_UNLCK as u64);
            assert_eq!(call(&config, libc::SYS_fcntl, unlock), RET_ALLOW);
            for command in [libc::F_GETLEASE, libc::F_OFD_SETLK, libc::F_SETLK] {
                let args = fcntl(command as u64, 0);
                assert_eq!(call(&config, libc::SYS_fcntl, args), RET_ALLOW, "{command}");
            }
        }
    }

    /// The prctl options that only work with a capability, also with high bits in the option,
    /// which the kernel reads as an int. The options a program uses without one stay allowed.
    #[test]
    fn prctl_options_that_need_a_capability_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let prctl = |option: i32, subcommand: u64| args(&[HIGH | option as u64, subcommand]);
        for config in [strict(), open()] {
            let decide = |args| call(&config, libc::SYS_prctl, args);
            for option in CAPABILITY_PRCTLS.iter().copied() {
                assert_eq!(decide(prctl(option, 0)), RET_EPERM, "{option}");
            }
            assert!(CAPABILITY_PRCTLS.contains(&libc::PR_CAPBSET_DROP));
            assert!(CAPABILITY_PRCTLS.contains(&PR_SET_IO_FLUSHER));
            for form in [
                libc::PR_SET_MM_START_CODE,
                libc::PR_SET_MM_EXE_FILE,
                libc::PR_SET_MM_MAP,
                libc::PR_SET_MM_MAP_SIZE,
            ] {
                let set_mm = prctl(libc::PR_SET_MM, form as u64);
                assert_eq!(decide(set_mm), RET_EPERM, "{form}");
            }
            let ambient = |subcommand: i32| prctl(libc::PR_CAP_AMBIENT, subcommand as u64);
            assert_eq!(decide(ambient(libc::PR_CAP_AMBIENT_RAISE)), RET_EPERM);
            for subcommand in [
                libc::PR_CAP_AMBIENT_LOWER,
                libc::PR_CAP_AMBIENT_IS_SET,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
            ] {
                assert_eq!(decide(ambient(subcommand)), RET_ALLOW, "{subcommand}");
            }
            // The kernel compares the subcommand on all 64 bits, so this is no raise for it.
            let not_a_raise = args(&[
                libc::PR_CAP_AMBIENT as u64,
                HIGH | libc::PR_CAP_AMBIENT_RAISE as u64,
            ]);
            assert_eq!(decide(not_a_raise), RET_ALLOW);
            for option in [
                libc::PR_SET_NAME,
                libc::PR_SET_PDEATHSIG,
                libc::PR_SET_DUMPABLE,
                libc::PR_SET_NO_NEW_PRIVS,
                libc::PR_SET_CHILD_SUBREAPER,
                libc::PR_SET_KEEPCAPS,
                libc::PR_CAPBSET_READ,
                libc::PR_GET_SECUREBITS,
                libc::PR_SET_SECUREBITS,
                libc::PR_SET_TIMERSLACK,
                libc::PR_SET_VMA,
            ] {
                assert_eq!(decide(prctl(option, 1)), RET_ALLOW, "{option}");
            }
        }
    }

    /// The real-time I/O class needs a capability, also for the program itself. The class is in
    /// bits 13 to 15 of an int; the bits above it do not change it.
    #[test]
    fn realtime_io_priority_is_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let class = |class: u64| (class << 13) | 4;
        let own = |ioprio: u64| args(&[IOPRIO_WHO_PROCESS, 0, ioprio]);
        for config in [strict(), open()] {
            let decide = |args| call(&config, libc::SYS_ioprio_set, args);
            for realtime in [class(1), class(1) | 1 << 16, HIGH | class(1)] {
                assert_eq!(decide(own(realtime)), RET_EPERM, "{realtime:#x}");
            }
            // None, best effort, idle, and the invalid class 7, which the kernel rejects.
            for other in [0, class(2), class(3), class(2) | 1 << 16, class(7)] {
                assert_eq!(decide(own(other)), RET_ALLOW, "{other:#x}");
            }
        }
    }

    /// Another user or group ID needs CAP_SETUID or CAP_SETGID. Each ID argument is checked on
    /// its own and on 32 bits; -1 leaves an ID as it is.
    #[test]
    fn ids_the_process_does_not_hold_cannot_be_set() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        const UNCHANGED: u64 = 0xffff_ffff;
        for config in [strict(), open()] {
            for (calls, own) in [(UID_CALLS, OWN_UID), (GID_CALLS, OWN_GID)] {
                let own = u64::from(own);
                for &(nr, count) in calls {
                    assert_eq!(call(&config, nr, [own; 6]), RET_ALLOW, "{nr}");
                    for index in 0..usize::from(count) {
                        for (id, expected) in [
                            (0, RET_EPERM),
                            (own + 1, RET_EPERM),
                            (HIGH, RET_EPERM),
                            (HIGH | own, RET_ALLOW),
                            (UNCHANGED, RET_ALLOW),
                        ] {
                            let mut ids = [own; 6];
                            ids[index] = id;
                            let decision = call(&config, nr, ids);
                            assert_eq!(decision, expected, "{nr} argument {index}: {id:#x}");
                        }
                    }
                }
            }
        }
        assert!(UID_CALLS.contains(&(libc::SYS_setresuid, 3)));
        assert!(GID_CALLS.contains(&(libc::SYS_setresgid, 3)));
        // A process whose real, effective and saved IDs differ may switch among them.
        let switching = TargetProcess {
            uids: [1000, 1001, 1002],
            gids: [100, 101, 102],
            ..OWN
        };
        let filters = build(&open(), &switching).unwrap();
        let set = |nr: i64, id: u64| decide_with(&filters, NATIVE, nr, args(&[id]));
        for id in [1000, 1001, 1002] {
            assert_eq!(set(libc::SYS_setuid, id), RET_ALLOW, "{id}");
            assert_eq!(set(libc::SYS_setgid, id - 900), RET_ALLOW, "{id}");
        }
        assert_eq!(set(libc::SYS_setuid, 1003), RET_EPERM);
        assert_eq!(set(libc::SYS_setgid, 103), RET_EPERM);
    }

    /// Raw IPv4 and IPv6 sockets need CAP_NET_RAW. The type is an int with flags above the low
    /// four bits.
    #[test]
    fn raw_ip_sockets_are_denied() {
        let flags = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        for (family, icmp) in [
            (libc::AF_INET, libc::IPPROTO_ICMP),
            (libc::AF_INET6, libc::IPPROTO_ICMPV6),
        ] {
            for kind in [libc::SOCK_RAW, libc::SOCK_RAW | flags] {
                for protocol in [icmp, 0] {
                    let mut args = socket(family, kind, protocol);
                    assert_eq!(call(&open(), libc::SYS_socket, args), RET_EPERM);
                    args[1] |= 1 << 32;
                    assert_eq!(call(&open(), libc::SYS_socket, args), RET_EPERM);
                }
            }
            // The ICMP datagram sockets of ping.
            let ping = socket(family, libc::SOCK_DGRAM | flags, icmp);
            assert_eq!(call(&open(), libc::SYS_socket, ping), RET_ALLOW);
        }
        // Raw netlink and Unix sockets need no capability.
        for (family, protocol) in [(libc::AF_NETLINK, libc::NETLINK_ROUTE), (libc::AF_UNIX, 0)] {
            let raw = socket(family, libc::SOCK_RAW, protocol);
            assert_eq!(call(&open(), libc::SYS_socket, raw), RET_ALLOW, "{family}");
        }
    }

    /// The socket options that only work with a capability, also with high bits in the level and
    /// the option, which are ints. The neighbours of the firewall ranges, and the same numbers at
    /// another level, stay allowed.
    #[test]
    fn socket_options_that_need_a_capability_are_denied() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let option =
            |level: i32, name: u32| args(&[3, HIGH | level as u64, HIGH | u64::from(name)]);
        for config in [strict(), open()] {
            let set = |args| call(&config, libc::SYS_setsockopt, args);
            let get = |args| call(&config, libc::SYS_getsockopt, args);
            for &(level, name) in CAPABILITY_SOCKET_OPTIONS {
                assert_eq!(set(option(level, name as u32)), RET_EPERM, "{level} {name}");
                assert_eq!(get(option(level, name as u32)), RET_ALLOW, "{level} {name}");
            }
            for (level, name) in [
                (libc::SOL_SOCKET, libc::SO_MARK),
                (libc::SOL_IP, libc::IP_XFRM_POLICY),
                (libc::SOL_TCP, libc::TCP_REPAIR),
            ] {
                assert!(CAPABILITY_SOCKET_OPTIONS.contains(&(level, name)));
            }
            for &(level, first, last) in FIREWALL_SOCKET_OPTIONS {
                for name in [first, last] {
                    assert_eq!(set(option(level, name)), RET_EPERM, "{level} {name}");
                    assert_eq!(get(option(level, name)), RET_EPERM, "{level} {name}");
                }
            }
            for name in [63, 68, 80, 82, 84, 95, 100, 127, 133, 1151, 1168] {
                assert_eq!(get(option(libc::SOL_IP, name)), RET_ALLOW, "{name}");
            }
            for name in [63, 66, 67, 70, 80] {
                assert_eq!(get(option(libc::SOL_IPV6, name)), RET_ALLOW, "{name}");
                assert_eq!(set(option(libc::SOL_IPV6, name)), RET_ALLOW, "{name}");
            }
            for (level, name) in [
                (libc::SOL_SOCKET, libc::SO_RCVBUF),
                (libc::SOL_SOCKET, libc::SO_PRIORITY),
                (libc::SOL_TCP, libc::TCP_NODELAY),
                (libc::SOL_IP, libc::IP_TOS),
                // IP_DROP_MEMBERSHIP, which has the number of SO_MARK.
                (libc::SOL_IP, libc::SO_MARK),
            ] {
                assert_eq!(set(option(level, name as u32)), RET_ALLOW, "{level} {name}");
            }
        }
    }

    /// With path metadata allowed, a file can only keep its owner without CAP_CHOWN, so a user ID
    /// the process does not hold is denied, on 32 bits. The group is the kernel's to check.
    /// Under "deny" the calls are denied completely (`path_metadata_calls_follow_the_policy`).
    #[test]
    fn files_cannot_be_given_to_another_user() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        const UNCHANGED: u64 = 0xffff_ffff;
        let own = u64::from(OWN_UID);
        let mut calls = CHOWN_CALLS.to_vec();
        calls.extend(arch::CHOWN_CALLS);
        assert!(calls.contains(&(libc::SYS_fchownat, 2)));
        for (nr, uid_index) in calls {
            let chown = |uid: u64, gid: u64| {
                let mut args = [3, 0x7fff_0000_1000, 0, 0, 0, 0];
                args[usize::from(uid_index)] = uid;
                args[usize::from(uid_index) + 1] = gid;
                args
            };
            for uid in [0, own + 1, HIGH] {
                assert_eq!(call(&open(), nr, chown(uid, 0)), RET_EPERM, "{nr} {uid:#x}");
            }
            for (uid, gid) in [(own, 0), (HIGH | own, 0), (UNCHANGED, 0), (UNCHANGED, 1234)] {
                let decision = call(&open(), nr, chown(uid, gid));
                assert_eq!(decision, RET_ALLOW, "{nr} {uid:#x} {gid}");
            }
            assert_eq!(call(&strict(), nr, chown(own, 0)), RET_EPERM, "{nr}");
        }
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
        // A process whose parent would be the program's parent, also with high bits set.
        let parent = libc::CLONE_PARENT as u64;
        for flags in [
            fork_flags | parent,
            (1 << 32) | parent,
            thread_flags | parent,
        ] {
            assert_eq!(call(&open(), libc::SYS_clone, args(&[flags])), RET_EPERM);
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
                SYS_LSM_GET_SELF_ATTR,
                SYS_LSM_SET_SELF_ATTR,
                SYS_LSM_LIST_MODULES,
                libc::SYS_vhangup,
                libc::SYS_sethostname,
                libc::SYS_setdomainname,
                libc::SYS_setgroups,
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
        // The program's own user ID in every argument, which the chown calls may keep under
        // "allow" (`files_cannot_be_given_to_another_user`), and a mode without setuid bits.
        let own = [u64::from(OWN_UID); 6];
        for nr in calls {
            assert_eq!(call(&deny, nr, own), RET_EPERM, "system call {nr}");
            assert_eq!(call(&allow, nr, own), RET_ALLOW, "system call {nr}");
        }
        // Through a descriptor, the owner and the extended attributes follow the policy too;
        // the attributes fail like on a file system without them. The mode stays allowed.
        assert_eq!(call(&deny, libc::SYS_fchown, [0; 6]), RET_EPERM);
        for nr in [libc::SYS_fsetxattr, libc::SYS_fremovexattr] {
            assert_eq!(call(&deny, nr, [0; 6]), RET_NO_XATTRS, "system call {nr}");
        }
        for nr in [
            libc::SYS_fchown,
            libc::SYS_fsetxattr,
            libc::SYS_fremovexattr,
        ] {
            assert_eq!(call(&allow, nr, own), RET_ALLOW, "system call {nr}");
        }
        assert_eq!(call(&deny, libc::SYS_fchmod, [0; 6]), RET_ALLOW);
        let path = args(&[3, 0x7fff_0000_1000]);
        assert_eq!(call(&deny, libc::SYS_utimensat, path), RET_EPERM);
        assert_eq!(call(&allow, libc::SYS_utimensat, path), RET_ALLOW);
        let descriptor = args(&[3, 0]);
        assert_eq!(call(&deny, libc::SYS_utimensat, descriptor), RET_ALLOW);
    }

    /// Reading extended attributes by path follows the same setting as changing metadata by
    /// path, and fails with ENOTSUP, which programs read as "this file system has none". The
    /// descriptor variants stay allowed: they reject O_PATH descriptors, so they only reach
    /// files Landlock let the program open.
    #[test]
    fn extended_attribute_reads_by_path_follow_the_policy() {
        for &nr in PATH_XATTR_READS {
            assert_eq!(
                call(&strict(), nr, [0; 6]),
                RET_NO_XATTRS,
                "system call {nr}"
            );
            assert_eq!(call(&open(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        for nr in [libc::SYS_fgetxattr, libc::SYS_flistxattr] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        assert!(build(&open(), &OWN).unwrap().path_xattrs.is_none());
    }

    /// An unprivileged fanotify group reports events on every path the user can reach, which
    /// Landlock cannot restrict. ENOSYS, so a program falls back to inotify.
    #[test]
    fn fanotify_groups_cannot_be_created() {
        for config in [strict(), open()] {
            assert_eq!(call(&config, libc::SYS_fanotify_init, [0; 6]), RET_ENOSYS);
        }
        assert_eq!(call(&open(), libc::SYS_inotify_init1, [0; 6]), RET_ALLOW);
    }

    /// A file handle names a file of any path the user can reach, with its mount, and only
    /// open_by_handle_at, which needs a capability, takes it. ENOSYS, as on a kernel without
    /// file handles.
    #[test]
    fn file_handles_cannot_be_made() {
        for config in [strict(), open()] {
            assert_eq!(
                call(&config, libc::SYS_name_to_handle_at, [0; 6]),
                RET_ENOSYS
            );
            assert_eq!(
                call(&config, libc::SYS_open_by_handle_at, [0; 6]),
                RET_EPERM
            );
        }
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
            assert_eq!(call(&open(), nr, with_pid(other)), RET_EPERM, "{nr}");
            // The own ID only where no process the program started can outlive it.
            assert_eq!(call(&open(), nr, with_pid(own)), RET_EPERM, "{nr}");
            assert_eq!(call(&contained(), nr, with_pid(own)), RET_ALLOW, "{nr}");
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
            assert_eq!(call(&open(), nr, args(&[one, own])), RET_EPERM, "{nr}");
            assert_eq!(call(&contained(), nr, args(&[one, own])), RET_ALLOW, "{nr}");
            assert_eq!(call(&open(), nr, args(&[one, other])), RET_EPERM, "{nr}");
            for which in groups {
                assert_eq!(call(&open(), nr, args(&[which, 0])), RET_EPERM, "{nr}");
            }
        }
    }

    #[test]
    fn the_watcher_can_only_watch_and_signal() {
        const PROGRAM: i32 = 4;
        const PARENT: i32 = 3;
        let filters = watcher(PROGRAM).unwrap();
        let watcher = |nr: i64| decide_with(&filters, NATIVE, nr, [0; 6]);
        for nr in [
            libc::SYS_ppoll,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_getpid,
            libc::SYS_exit_group,
        ] {
            assert_eq!(watcher(nr), RET_ALLOW, "system call {nr}");
        }
        // Only the program may be signalled, and only with the signals that end it. The watcher
        // also holds a pidfd for the process that started sandy.
        let send = |fd: i32, signal: i32| {
            let args = args(&[fd as u64, signal as u64]);
            decide_with(&filters, NATIVE, libc::SYS_pidfd_send_signal, args)
        };
        for signal in [libc::SIGTERM, libc::SIGCONT, libc::SIGKILL] {
            assert_eq!(send(PROGRAM, signal), RET_ALLOW, "signal {signal}");
            assert_eq!(send(PARENT, signal), RET_EPERM, "signal {signal}");
        }
        for signal in [0, libc::SIGSTOP, libc::SIGUSR1] {
            assert_eq!(send(PROGRAM, signal), RET_EPERM, "signal {signal}");
        }
        // A siginfo of the watcher's own, also one at an address whose low 32 bits are zero.
        for info in [0x7fff_0000_1000, 1 << 32] {
            let args = args(&[PROGRAM as u64, libc::SIGTERM as u64, info]);
            let decision = decide_with(&filters, NATIVE, libc::SYS_pidfd_send_signal, args);
            assert_eq!(decision, RET_EPERM, "siginfo {info:#x}");
        }
        for nr in [
            libc::SYS_openat,
            libc::SYS_socket,
            libc::SYS_kill,
            libc::SYS_clone,
            libc::SYS_execve,
            libc::SYS_pidfd_open,
            libc::SYS_read,
        ] {
            assert_eq!(watcher(nr), RET_EPERM, "system call {nr}");
        }
        assert_eq!(watcher(libc::SYS_pidfd_send_signal), RET_EPERM);
    }

    #[test]
    fn the_explain_watcher_can_only_watch_and_report() {
        const LISTENER: i32 = 5;
        let requests = crate::explain::NOTIFICATION_REQUESTS;
        let program = explain_watcher(LISTENER, &requests).unwrap();
        let decide = |nr: i64, values: &[u64]| evaluate(&program, NATIVE, nr, args(values));
        for nr in [
            libc::SYS_ppoll,
            libc::SYS_process_vm_readv,
            libc::SYS_readlinkat,
            libc::SYS_statx,
            libc::SYS_faccessat2,
            libc::SYS_futex,
            libc::SYS_munmap,
            libc::SYS_exit,
        ] {
            assert_eq!(decide(nr, &[]), RET_ALLOW, "system call {nr}");
        }
        // The notification interface on the notification descriptor, and nothing else on any.
        let listener = LISTENER as u64;
        for request in requests.map(u64::from) {
            assert_eq!(decide(libc::SYS_ioctl, &[listener, request]), RET_ALLOW);
            assert_eq!(decide(libc::SYS_ioctl, &[2, request]), RET_KILL_PROCESS);
        }
        let tiocsti = u64::from(libc::TIOCSTI as u32);
        assert_eq!(
            decide(libc::SYS_ioctl, &[listener, tiocsti]),
            RET_KILL_PROCESS
        );
        // The report goes to standard error only.
        assert_eq!(decide(libc::SYS_write, &[2]), RET_ALLOW);
        for fd in [0, 1, 3] {
            assert_eq!(decide(libc::SYS_write, &[fd]), RET_KILL_PROCESS, "fd {fd}");
        }
        // Memory, but no code of its own.
        let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        let executable = (libc::PROT_READ | libc::PROT_EXEC) as u64;
        for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
            assert_eq!(decide(nr, &[0, 4096, read_write]), RET_ALLOW, "{nr}");
            assert_eq!(decide(nr, &[0, 4096, executable]), RET_KILL_PROCESS, "{nr}");
        }
        assert_eq!(
            decide(libc::SYS_fcntl, &[3, libc::F_GETFD as u64]),
            RET_ALLOW
        );
        assert_eq!(
            decide(libc::SYS_fcntl, &[3, libc::F_SETFL as u64]),
            RET_KILL_PROCESS
        );
        for nr in [
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_kill,
            libc::SYS_clone,
            libc::SYS_ptrace,
            libc::SYS_process_vm_writev,
            libc::SYS_unlinkat,
            libc::SYS_pidfd_send_signal,
        ] {
            assert_eq!(decide(nr, &[]), RET_KILL_PROCESS, "system call {nr}");
        }
        const AUDIT_ARCH_I386: u32 = 3 | 0x4000_0000;
        let foreign = evaluate(&program, AUDIT_ARCH_I386, 3, [0; 6]);
        assert_eq!(foreign, RET_KILL_PROCESS);
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
            libc::SYS_recvmsg,
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
        // Stream sockets of another protocol, whose module the kernel would load.
        for protocol in [libc::IPPROTO_SCTP, libc::IPPROTO_MPTCP, libc::IPPROTO_TCP] {
            let other = socket(libc::AF_INET, libc::SOCK_STREAM, protocol);
            assert_eq!(relay(libc::SYS_socket, other), RET_EPERM, "{protocol}");
        }
        let user = thread | libc::CLONE_NEWUSER as u64;
        assert_eq!(relay(libc::SYS_clone, args(&[user])), RET_EPERM);
        // No process: neither fork's flags nor posix_spawn's, also with high bits set.
        let fork = libc::SIGCHLD as u64;
        let spawn = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64;
        for flags in [fork, spawn, (1 << 32) | fork] {
            assert_eq!(
                relay(libc::SYS_clone, args(&[flags])),
                RET_EPERM,
                "{flags:#x}"
            );
        }
        let tiocsti = args(&[0, u64::from(libc::TIOCSTI as u32)]);
        assert_eq!(relay(libc::SYS_ioctl, tiocsti), RET_EPERM);
        // The shared allowlist still decides clone3, so threads fall back to clone.
        assert_eq!(relay(libc::SYS_clone3, [0; 6]), RET_ENOSYS);
    }

    #[test]
    fn the_factory_can_only_make_tcp_sockets() {
        let filters = factory().unwrap();
        let factory = |nr: i64, args: [u64; 6]| decide_with(&filters, NATIVE, nr, args);
        for nr in [
            libc::SYS_read,
            libc::SYS_sendmsg,
            libc::SYS_close,
            libc::SYS_exit_group,
        ] {
            assert_eq!(factory(nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        for family in [libc::AF_INET, libc::AF_INET6] {
            let tcp = socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert_eq!(factory(libc::SYS_socket, tcp), RET_ALLOW);
            let sctp = socket(family, libc::SOCK_STREAM, libc::IPPROTO_SCTP);
            assert_eq!(factory(libc::SYS_socket, sctp), RET_EPERM);
        }
        // The relay connects the sockets; the factory reaches nothing with them.
        for nr in [
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_recvmsg,
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_kill,
            libc::SYS_ioctl,
        ] {
            assert_eq!(factory(nr, [0; 6]), RET_EPERM, "system call {nr}");
        }
        for (family, kind) in [
            (libc::AF_UNIX, libc::SOCK_STREAM),
            (libc::AF_INET, libc::SOCK_DGRAM),
            (libc::AF_NETLINK, libc::SOCK_RAW),
        ] {
            let other = socket(family, kind, 0);
            assert_eq!(factory(libc::SYS_socket, other), RET_EPERM);
        }
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
    fn contained_children_keep_their_process_group() {
        for nr in [libc::SYS_setsid, libc::SYS_setpgid] {
            assert_eq!(call(&strict(), nr, [0; 6]), RET_EPERM, "system call {nr}");
            assert_eq!(call(&open(), nr, [0; 6]), RET_ALLOW, "system call {nr}");
        }
        assert_eq!(call(&strict(), libc::SYS_getpgid, [0; 6]), RET_ALLOW);
    }

    /// With isolated signals the program may lead a group of its own, but not join one that
    /// exists and not steer the terminal's job control.
    #[test]
    fn isolated_signals_allow_only_a_process_group_of_the_program_s_own() {
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        let child = u64::from(OWN_PID) + 1;
        for own_group in [args(&[0, 0]), args(&[child, 0]), args(&[0, HIGH])] {
            assert_eq!(call(&isolated(), libc::SYS_setpgid, own_group), RET_ALLOW);
            assert_eq!(call(&contained(), libc::SYS_setpgid, own_group), RET_EPERM);
        }
        // seccomp cannot compare two arguments, so setpgid(pid, pid) is denied as well.
        for existing_group in [args(&[0, child]), args(&[child, child])] {
            assert_eq!(
                call(&isolated(), libc::SYS_setpgid, existing_group),
                RET_EPERM
            );
            assert_eq!(call(&open(), libc::SYS_setpgid, existing_group), RET_ALLOW);
        }
        assert_eq!(call(&isolated(), libc::SYS_setsid, [0; 6]), RET_ALLOW);
        let terminal = [libc::TIOCSPGRP, libc::TIOCSWINSZ, libc::TIOCSIG];
        for command in terminal.map(|c| u64::from(c as u32)) {
            for high in [0, HIGH] {
                let args = args(&[0, high | command]);
                for config in [isolated(), contained()] {
                    assert_eq!(
                        call(&config, libc::SYS_ioctl, args),
                        RET_EPERM,
                        "{command:#x}"
                    );
                }
                assert_eq!(
                    call(&open(), libc::SYS_ioctl, args),
                    RET_ALLOW,
                    "{command:#x}"
                );
            }
        }
        for command in [libc::TIOCGPGRP, libc::TIOCGWINSZ].map(|c| u64::from(c as u32)) {
            let args = args(&[0, command]);
            assert_eq!(call(&isolated(), libc::SYS_ioctl, args), RET_ALLOW);
        }
    }

    #[test]
    fn personality_allows_only_harmless_values() {
        const ADDR_NO_RANDOMIZE: u64 = 0x4_0000;
        for value in [
            0,
            0xffff_ffff,
            ADDR_NO_RANDOMIZE,
            ADDR_NO_RANDOMIZE | 0x2_0000,
        ] {
            let args = args(&[value]);
            assert_eq!(
                call(&open(), libc::SYS_personality, args),
                RET_ALLOW,
                "{value:#x}"
            );
        }
        const READ_IMPLIES_EXEC: u64 = 0x040_0000;
        for value in [READ_IMPLIES_EXEC, READ_IMPLIES_EXEC | ADDR_NO_RANDOMIZE] {
            let args = args(&[value]);
            assert_eq!(
                call(&open(), libc::SYS_personality, args),
                RET_EPERM,
                "{value:#x}"
            );
        }
    }

    #[test]
    fn open_for_ioctl_only_is_denied() {
        for &(nr, flags_index) in arch::OPEN_CALLS {
            // The kernel's value, not libc's O_ACCMODE: musl adds O_PATH to that one.
            for flags in [3, 3 | libc::O_PATH as u64, 3 | libc::O_CLOEXEC as u64] {
                let mut ioctl_only = [0; 6];
                ioctl_only[usize::from(flags_index)] = flags;
                assert_eq!(call(&open(), nr, ioctl_only), RET_EPERM, "{flags:#x}");
            }
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
