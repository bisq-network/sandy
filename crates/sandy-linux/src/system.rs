//! The minimal system set: system paths that programs need to start. `docs/linux.md` gives the
//! reason for every entry. The set never contains user data, and only /dev/null is writable.

use std::path::{Path, PathBuf};

/// What the program may do with a system path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemUse {
    Read,
    /// Read and execute. Only for the dynamic loader, which the kernel opens for execution.
    Execute,
    /// Read and write a device that discards writes.
    Discard,
}

/// When the program needs a system path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needed {
    Always,
    /// Only for name resolution, so only when the policy allows IP networking.
    WithIpNetwork,
}

/// A candidate that exists on this host, with symbolic links resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPath {
    pub path: PathBuf,
    pub is_dir: bool,
    pub usage: SystemUse,
    pub needed: Needed,
}

/// Dynamic loaders (glibc, musl) and the musl library path file of this CPU architecture.
#[cfg(target_arch = "x86_64")]
const ARCH_CANDIDATES: &[(&str, SystemUse)] = &[
    ("/lib64/ld-linux-x86-64.so.2", SystemUse::Execute),
    ("/lib/ld-musl-x86_64.so.1", SystemUse::Execute),
    ("/etc/ld-musl-x86_64.path", SystemUse::Read),
];
#[cfg(target_arch = "aarch64")]
const ARCH_CANDIDATES: &[(&str, SystemUse)] = &[
    ("/lib/ld-linux-aarch64.so.1", SystemUse::Execute),
    ("/lib/ld-musl-aarch64.so.1", SystemUse::Execute),
    ("/etc/ld-musl-aarch64.path", SystemUse::Read),
];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ARCH_CANDIDATES: &[(&str, SystemUse)] = &[];

const CANDIDATES: &[(&str, SystemUse, Needed)] = &[
    ("/usr/lib", SystemUse::Read, Needed::Always),
    ("/usr/lib64", SystemUse::Read, Needed::Always),
    ("/lib", SystemUse::Read, Needed::Always),
    ("/lib64", SystemUse::Read, Needed::Always),
    ("/etc/ld.so.cache", SystemUse::Read, Needed::Always),
    ("/etc/ld.so.preload", SystemUse::Read, Needed::Always),
    ("/etc/localtime", SystemUse::Read, Needed::Always),
    ("/usr/share/zoneinfo", SystemUse::Read, Needed::Always),
    ("/dev/null", SystemUse::Discard, Needed::Always),
    ("/dev/zero", SystemUse::Read, Needed::Always),
    ("/dev/random", SystemUse::Read, Needed::Always),
    ("/dev/urandom", SystemUse::Read, Needed::Always),
    (
        "/sys/devices/system/cpu/online",
        SystemUse::Read,
        Needed::Always,
    ),
    (
        "/sys/devices/system/cpu/possible",
        SystemUse::Read,
        Needed::Always,
    ),
    ("/etc/ssl/openssl.cnf", SystemUse::Read, Needed::Always),
    ("/etc/pki/tls/openssl.cnf", SystemUse::Read, Needed::Always),
    (
        "/etc/crypto-policies/back-ends",
        SystemUse::Read,
        Needed::Always,
    ),
    ("/etc/hosts", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/resolv.conf", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/nsswitch.conf", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/host.conf", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/gai.conf", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/services", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/protocols", SystemUse::Read, Needed::WithIpNetwork),
    ("/etc/ssl/certs", SystemUse::Read, Needed::WithIpNetwork),
    (
        "/usr/share/ca-certificates",
        SystemUse::Read,
        Needed::WithIpNetwork,
    ),
    ("/etc/pki/tls/certs", SystemUse::Read, Needed::WithIpNetwork),
    (
        "/etc/pki/ca-trust/extracted",
        SystemUse::Read,
        Needed::WithIpNetwork,
    ),
    (
        "/etc/ca-certificates/extracted",
        SystemUse::Read,
        Needed::WithIpNetwork,
    ),
    (
        "/var/lib/ca-certificates",
        SystemUse::Read,
        Needed::WithIpNetwork,
    ),
];

fn candidates() -> impl Iterator<Item = (&'static str, SystemUse, Needed)> {
    let arch = ARCH_CANDIDATES
        .iter()
        .map(|&(path, usage)| (path, usage, Needed::Always));
    CANDIDATES.iter().copied().chain(arch)
}

/// Returns the candidates that exist, with canonical paths. A candidate that cannot be resolved
/// is left out, which only removes access.
pub fn detect() -> Vec<SystemPath> {
    let mut found: Vec<SystemPath> = candidates()
        .filter_map(|(path, usage, needed)| {
            let path = Path::new(path).canonicalize().ok()?;
            let is_dir = path.metadata().ok()?.is_dir();
            Some(SystemPath {
                path,
                is_dir,
                usage,
                needed,
            })
        })
        .collect();
    // Merged /usr systems resolve /lib to /usr/lib, so several candidates can name one path.
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup_by(|a, b| a.path == b.path && a.usage == b.usage && a.needed == b.needed);
    found
}

/// Returns every candidate, also those that do not exist, where it is or would be: symbolic links
/// in the existing part of the path are resolved. A missing candidate such as /etc/ld.so.preload
/// matters too, because a program that can write its directory can create it.
pub fn locations() -> Vec<SystemPath> {
    candidates()
        .map(|(path, usage, needed)| {
            let path = resolve_existing_part(Path::new(path));
            let is_dir = path.metadata().is_ok_and(|metadata| metadata.is_dir());
            SystemPath {
                path,
                is_dir,
                usage,
                needed,
            }
        })
        .collect()
}

/// `path` with its longest existing prefix replaced by that prefix's canonical form.
fn resolve_existing_part(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut existing = path;
    loop {
        if let Ok(canonical) = existing.canonicalize() {
            return rest
                .iter()
                .rev()
                .fold(canonical, |path, name| path.join(name));
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_paths_are_canonical_and_unique() {
        let found = detect();
        assert!(!found.is_empty());
        for entry in &found {
            assert_eq!(entry.path.canonicalize().unwrap(), entry.path);
        }
        for pair in found.windows(2) {
            assert!(pair[0] != pair[1]);
        }
    }

    #[test]
    fn locations_include_missing_candidates() {
        let locations = locations();
        assert_eq!(locations.len(), candidates().count());
        let preload = locations
            .iter()
            .find(|entry| entry.path.ends_with("ld.so.preload"))
            .unwrap();
        // /etc exists everywhere sandy runs; the file itself usually does not.
        assert_eq!(
            preload.path.parent().unwrap(),
            Path::new("/etc").canonicalize().unwrap()
        );
    }

    #[test]
    fn only_dev_null_is_writable() {
        for entry in detect() {
            if entry.usage == SystemUse::Discard {
                assert_eq!(entry.path, Path::new("/dev/null"));
            }
        }
    }
}
