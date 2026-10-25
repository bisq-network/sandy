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
    // The back-ends are symbolic links into the policy texts; Landlock checks the target.
    (
        "/usr/share/crypto-policies",
        SystemUse::Read,
        Needed::Always,
    ),
    ("/etc/pki/tls/openssl.d", SystemUse::Read, Needed::Always),
    // What the OpenSSL configuration of Ubuntu 25.10 includes: the local directory and the one
    // of the system crypto profile (crypto-config).
    ("/etc/ssl/openssl.conf.d", SystemUse::Read, Needed::Always),
    (
        "/var/lib/crypto-config/profiles/current/openssl.conf.d",
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

/// The OpenSSL configuration files of the candidate list, whose `.include` directives decide
/// which crypto settings the program sees (`openssl::missing_includes`).
pub fn openssl_configs() -> Vec<PathBuf> {
    CANDIDATES
        .iter()
        .map(|&(path, _, _)| PathBuf::from(path))
        .filter(|path| path.ends_with("openssl.cnf"))
        .collect()
}

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

/// Returns every candidate, also those that do not exist, where it is or would be, and where each
/// symbolic link on the way to it is. A missing candidate such as /etc/ld.so.preload matters too,
/// because a program that can write its directory can create it. So does the missing target of
/// a symbolic link such as /etc/resolv.conf, which programs outside the sandbox would read once
/// it exists, and the link itself, which a program that can write its directory can replace.
pub fn locations() -> Vec<SystemPath> {
    candidates()
        .flat_map(|(path, usage, needed)| {
            let (location, links) = resolve_existing_part(Path::new(path));
            let is_dir = location.metadata().is_ok_and(|metadata| metadata.is_dir());
            let links = links.into_iter().map(move |link| SystemPath {
                path: link,
                is_dir: false,
                usage,
                needed,
            });
            std::iter::once(SystemPath {
                path: location,
                is_dir,
                usage,
                needed,
            })
            .chain(links)
        })
        .collect()
}

/// Where `path` is or would be, like `canonicalize`, except that the part from the first missing
/// entry on is kept as written, also the missing target of a symbolic link. Also returns where
/// each symbolic link on the way is (its canonical directory plus its name).
fn resolve_existing_part(path: &Path) -> (PathBuf, Vec<PathBuf>) {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;

    /// As the kernel's limit for one path lookup (MAXSYMLINKS).
    const MAX_LINKS: usize = 40;
    fn queue_front(pending: &mut VecDeque<OsString>, path: &Path) {
        for component in path.components().rev() {
            match component {
                Component::Normal(name) => pending.push_front(name.to_os_string()),
                Component::ParentDir => pending.push_front(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    }

    let mut resolved = PathBuf::from("/");
    let mut links = Vec::new();
    let mut pending = VecDeque::new();
    queue_front(&mut pending, path);
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        let entry = resolved.join(&name);
        let link = std::fs::symlink_metadata(&entry)
            .ok()
            .filter(|metadata| metadata.file_type().is_symlink())
            .and_then(|_| std::fs::read_link(&entry).ok());
        match link {
            Some(target) if links.len() < MAX_LINKS => {
                links.push(entry);
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                queue_front(&mut pending, &target);
            }
            _ if entry.symlink_metadata().is_ok() => resolved = entry,
            _ => {
                // Missing: the rest stays as written.
                resolved = entry;
                for rest in pending {
                    if rest == ".." {
                        resolved.pop();
                    } else {
                        resolved.push(rest);
                    }
                }
                break;
            }
        }
    }
    (resolved, links)
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
        assert!(locations.len() >= candidates().count());
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

    /// A symbolic link whose target is missing counts at both places: where the link is, and
    /// where its target would be.
    #[test]
    fn a_dangling_link_counts_where_it_is_and_where_it_points() {
        let dir = std::env::temp_dir().join(format!("sandy-system-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::create_dir_all(dir.join("run")).unwrap();
        let dir = dir.canonicalize().unwrap();
        std::os::unix::fs::symlink("../run/missing/stub.conf", dir.join("etc/resolv.conf"))
            .unwrap();
        let (location, links) = resolve_existing_part(&dir.join("etc/resolv.conf"));
        assert_eq!(location, dir.join("run/missing/stub.conf"));
        assert_eq!(links, [dir.join("etc/resolv.conf")]);
        // An existing path resolves like canonicalize.
        let (location, links) = resolve_existing_part(&dir.join("etc"));
        assert_eq!(location, dir.join("etc"));
        assert!(links.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The directories that the OpenSSL configuration of Ubuntu 25.10 includes are read
    /// candidates, so a host that has them keeps them inside the sandbox.
    #[test]
    fn the_openssl_includes_of_ubuntu_are_candidates() {
        for target in [
            "/var/lib/crypto-config/profiles/current/openssl.conf.d",
            "/etc/ssl/openssl.conf.d",
        ] {
            let read = candidates().any(|(path, usage, needed)| {
                path == target && usage == SystemUse::Read && needed == Needed::Always
            });
            assert!(read, "{target}");
        }
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
