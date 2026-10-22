//! The fixed parts of the profile: the `system = "minimal"` path set and the readable sysctls.
//! `docs/macos.md` explains every entry.

/// How the profile grants access to a system path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemAccess {
    /// Read a directory tree.
    ReadTree,
    /// Read a directory tree and map its files as executable code (for dyld).
    CodeTree,
    /// Read one file.
    ReadFile,
    /// Read one device.
    ReadDevice,
    /// Read and write one device. The target cannot create, delete or rename it.
    ReadWriteDevice,
    /// Read the metadata of one symbolic link, so path lookups can pass through it.
    Symlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPath {
    /// Real path without symbolic links, as the sandbox sees it.
    pub path: &'static str,
    pub access: SystemAccess,
    pub reason: &'static str,
}

/// What dyld and libSystem need to start a program. No entry contains user data.
pub const MINIMAL: &[SystemPath] = &[
    SystemPath {
        path: "/",
        access: SystemAccess::ReadFile,
        reason: "dyld opens the root directory while it locates the shared cache (libignition, \
                 macOS 13 and later); this lists the names in /, nothing below",
    },
    SystemPath {
        path: "/usr/lib",
        access: SystemAccess::CodeTree,
        reason: "dyld itself (/usr/lib/dyld) and system libraries outside the shared cache",
    },
    SystemPath {
        path: "/System/Library/dyld",
        access: SystemAccess::CodeTree,
        reason: "dyld shared cache on macOS 11 and 12",
    },
    SystemPath {
        path: "/System/Volumes/Preboot/Cryptexes/OS",
        access: SystemAccess::CodeTree,
        reason: "dyld shared cache since macOS 13 (Apple's dyld-support.sb)",
    },
    SystemPath {
        path: "/System/Cryptexes/OS",
        access: SystemAccess::CodeTree,
        reason: "mounted view of the same cryptex (Apple's dyld-support.sb)",
    },
    SystemPath {
        path: "/private/etc/localtime",
        access: SystemAccess::ReadFile,
        reason: "symbolic link that names the local time zone (tzset)",
    },
    SystemPath {
        path: "/private/var/db/timezone",
        access: SystemAccess::ReadTree,
        reason: "time zone database that /etc/localtime points into",
    },
    SystemPath {
        path: "/usr/share/zoneinfo.default",
        access: SystemAccess::ReadTree,
        reason: "time zone database shipped with the system",
    },
    SystemPath {
        path: "/usr/share/locale",
        access: SystemAccess::ReadTree,
        reason: "locale data for setlocale",
    },
    SystemPath {
        path: "/dev/null",
        access: SystemAccess::ReadWriteDevice,
        reason: "discarding output; also standard streams redirected to it",
    },
    SystemPath {
        path: "/dev/zero",
        access: SystemAccess::ReadDevice,
        reason: "zero bytes",
    },
    SystemPath {
        path: "/dev/random",
        access: SystemAccess::ReadDevice,
        reason: "random numbers",
    },
    SystemPath {
        path: "/dev/urandom",
        access: SystemAccess::ReadDevice,
        reason: "random numbers",
    },
    SystemPath {
        path: "/etc",
        access: SystemAccess::Symlink,
        reason: "link to /private/etc; programs use paths such as /etc/localtime",
    },
    SystemPath {
        path: "/tmp",
        access: SystemAccess::Symlink,
        reason: "link to /private/tmp; programs use paths below /tmp",
    },
    SystemPath {
        path: "/var",
        access: SystemAccess::Symlink,
        reason: "link to /private/var; programs use paths such as /var/run",
    },
];

/// The Unix socket of mDNSResponder. Name resolution (getaddrinfo) on macOS is a request to this
/// daemon, so it is IP networking through a proxy.
pub const DNS_RESOLVER_SOCKET: &str = "/private/var/run/mDNSResponder";

/// Read by the resolver library before it asks mDNSResponder.
pub const HOSTS_FILE: &str = "/private/etc/hosts";

/// Symbolic link the resolver library passes through: it connects to /var/run/mDNSResponder.
pub const VAR_SYMLINK: &str = "/var";

/// Readable sysctls: hardware and operating system facts that libSystem (sysconf, uname), dyld
/// and language runtimes query. None of them describes other processes or user data. The list
/// follows Chromium's common.sb, plus four names the OpenAI Codex CLI added for common tools.
pub const SYSCTL_NAMES: &[&str] = &[
    "hw.activecpu",
    "hw.busfrequency_compat",
    "hw.byteorder",
    "hw.cacheconfig",
    "hw.cachelinesize_compat",
    "hw.cpufamily",
    "hw.cpufrequency_compat",
    "hw.cputype",
    "hw.l1dcachesize_compat",
    "hw.l1icachesize_compat",
    "hw.l2cachesize_compat",
    "hw.l3cachesize_compat",
    "hw.logicalcpu",
    "hw.logicalcpu_max",
    "hw.machine",
    "hw.memsize",
    "hw.ncpu",
    "hw.nperflevels",
    "hw.packages",
    "hw.pagesize",
    "hw.pagesize_compat",
    "hw.physicalcpu",
    "hw.physicalcpu_max",
    "hw.tbfrequency_compat",
    "hw.vectorunit",
    "kern.argmax",
    "kern.hostname",
    "kern.hv_vmm_present",
    "kern.maxfilesperproc",
    "kern.osproductversion",
    "kern.osrelease",
    "kern.ostype",
    "kern.osvariant_status",
    "kern.osversion",
    "kern.secure_kernel",
    "kern.usrstack64",
    "kern.version",
    "sysctl.proc_cputype",
];

/// Readable sysctl prefixes: CPU feature flags (`hw.optional.*`, used for CPU feature detection)
/// and performance level descriptions (`hw.perflevel*`).
pub const SYSCTL_PREFIXES: &[&str] = &["hw.optional.", "hw.perflevel"];

/// ioctl request numbers on macOS, the same on arm64 and x86_64. The macOS module checks them
/// against the SDK values of the libc crate at compile time.
pub const FIONBIO: u64 = 0x8004_667e;
pub const FIOASYNC: u64 = 0x8004_667d;
pub const TIOCGETA: u64 = 0x4048_7413;
pub const TIOCGWINSZ: u64 = 0x4008_7468;
pub const TIOCSTI: u64 = 0x8001_7472;

/// The ioctls allowed on files and devices. fcntl(F_SETFL) issues FIONBIO and FIOASYNC;
/// TIOCGETA and TIOCGWINSZ only read terminal state (isatty, window size). Every other request
/// stays denied, among them TIOCSTI, which would type into the terminal of the caller.
pub const ALLOWED_IOCTLS: &[u64] = &[FIONBIO, FIOASYNC, TIOCGETA, TIOCGWINSZ];

/// System calls that find a file by volume id and inode number, without any path the profile
/// could check: fsgetpath and fsgetpath_ext return the file's path, openbyid_np opens it, and
/// searchfs searches a volume's catalog. Numbers from XNU `bsd/kern/syscalls.master`; older
/// profile compilers do not know every SYS_ name.
pub const BY_ID_SYSCALLS: &[(&str, u32)] = &[
    ("fsgetpath", 427),
    ("fsgetpath_ext", 217),
    ("openbyid_np", 479),
    ("searchfs", 225),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_are_absolute_real_paths() {
        for entry in MINIMAL {
            // Checked as text: on Windows, Path::is_absolute needs a drive letter.
            assert!(entry.path.starts_with('/'), "{}", entry.path);
            assert!(
                entry.path == "/" || !entry.path.ends_with('/'),
                "{}",
                entry.path
            );
            let symlink = entry.access == SystemAccess::Symlink;
            let below_link = ["/etc/", "/tmp/", "/var/"]
                .iter()
                .any(|link| entry.path.starts_with(link));
            assert!(symlink || !below_link, "not a real path: {}", entry.path);
            assert!(!entry.reason.is_empty());
        }
    }

    #[test]
    fn system_paths_contain_no_user_data() {
        for entry in MINIMAL {
            for user in [
                "/Users",
                "/var/root",
                "/private/var/root",
                "Library/Keychains",
            ] {
                assert!(!entry.path.contains(user), "{}", entry.path);
            }
        }
    }

    #[test]
    fn sysctl_names_are_plain_identifiers() {
        let plain = |name: &str| {
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
        };
        assert!(SYSCTL_NAMES.iter().all(|name| plain(name)));
        assert!(SYSCTL_PREFIXES.iter().all(|name| plain(name)));
        assert!(
            !SYSCTL_NAMES
                .iter()
                .any(|name| name.starts_with("kern.proc"))
        );
    }
}
