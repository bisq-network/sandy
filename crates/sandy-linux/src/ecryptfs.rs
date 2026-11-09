//! eCryptfs stores each directory in a directory of another file system, the lower directory, and
//! opens that lower directory with the credentials of the process that opens the eCryptfs one
//! (`ecryptfs_dir_open`). Landlock checks that second open against the lower path, which no rule
//! of the policy names, so a program could not list a granted directory on eCryptfs: Linux Mint
//! and Ubuntu put the home directory on eCryptfs when it is encrypted. File opens are not
//! affected, because eCryptfs retries those with its own credentials, except on a read-only
//! lower file system, where it does not retry.
//!
//! sandy grants the right to list (`ReadDir`) beneath the lower directory of each granted
//! directory that lists its entries, and nothing else there. That shows the program the same
//! entries it already lists through the granted path, under their encrypted names, and any lower
//! name eCryptfs cannot decrypt and leaves out of its own listing.
//!
//! The lower names are encrypted when the mount encrypts file names, so the lower directory is
//! found by inode: eCryptfs gives each of its files the inode number of its lower file. The walk
//! starts at the lower directory of the mount's point, which must lie on the file system whose ID
//! eCryptfs reports and have the inode of the point (`lower_point`), and follows each name of the
//! granted path to the one lower directory with the inode of the eCryptfs directory, without
//! following a symbolic link or leaving that file system.

use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use landlock::{AccessFs, BitFlags};

use crate::plan::PathRights;

/// `ECRYPTFS_SUPER_MAGIC` of linux/magic.h.
const MAGIC: i64 = 0xf15f;

const TABLE: &str = "/proc/self/mountinfo";

/// An eCryptfs mount of the mount table.
#[derive(Debug, PartialEq)]
struct Mount {
    point: PathBuf,
    /// The path of the mount's root inside the eCryptfs file system.
    root: PathBuf,
    device: u64,
    /// The lower directory the mount was made from, as the mount table names it.
    source: PathBuf,
}

/// The directories of `rules` on eCryptfs, or holding an eCryptfs mount, that the program may
/// list.
#[derive(Debug, Default, PartialEq)]
pub struct LowerDirectories {
    /// A `ReadDir` rule for the lower directory of each.
    pub rules: Vec<PathRights>,
    /// The eCryptfs directories whose lower directory sandy did not find. The program cannot
    /// list them.
    pub unfound: Vec<PathBuf>,
}

pub fn lower_directories(rules: &[PathRights]) -> LowerDirectories {
    let listed: Vec<&Path> = rules
        .iter()
        .filter(|rule| rule.is_dir && rule.access.contains(AccessFs::ReadDir))
        .map(|rule| rule.path.as_path())
        .collect();
    if listed.is_empty() {
        return LowerDirectories::default();
    }
    let Ok(table) = std::fs::read(TABLE) else {
        // The plan refuses a policy when the mount table is unreadable (`PathIdentity::read`).
        return LowerDirectories::default();
    };
    // A mount that a later mount covers is not the one its point leads to.
    let mounts: Vec<Mount> = parse(&table)
        .into_iter()
        .filter(|mount| device_of(&mount.point) == Some(mount.device))
        .collect();
    if mounts.is_empty() {
        return LowerDirectories::default();
    }
    found_in(&listed, &mounts)
}

fn found_in(listed: &[&Path], mounts: &[Mount]) -> LowerDirectories {
    let mut found = LowerDirectories::default();
    for path in listed {
        for (directory, lower) in reached(path, mounts) {
            match lower {
                Some(lower) => found.rules.push(PathRights {
                    path: lower,
                    is_dir: true,
                    access: BitFlags::from(AccessFs::ReadDir),
                }),
                None => found.unfound.push(directory),
            }
        }
    }
    found.rules.sort_by(|a, b| a.path.cmp(&b.path));
    found.rules.dedup();
    found.unfound.sort();
    found.unfound.dedup();
    found
}

/// The eCryptfs directories a rule at `path` lets the program list, with their lower directory:
/// `path` itself when it lies on eCryptfs, and the root of every eCryptfs mount beneath it.
fn reached(path: &Path, mounts: &[Mount]) -> Vec<(PathBuf, Option<PathBuf>)> {
    let mut reached = Vec::new();
    for mount in mounts {
        if mount.point.starts_with(path) && mount.point != path {
            reached.push((mount.point.clone(), lower_of(mount, &mount.point, mounts)));
        }
    }
    // statfs mounts an automount point, so only a path below an eCryptfs mount gets one.
    if mounts.iter().any(|mount| path.starts_with(&mount.point)) && is_ecryptfs(path) {
        let holder = mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.point))
            .filter(|mount| device_of(path) == Some(mount.device))
            .max_by_key(|mount| mount.point.as_os_str().len());
        let lower = holder.and_then(|mount| lower_of(mount, path, mounts));
        reached.push((path.to_path_buf(), lower));
    }
    reached
}

/// The lower directory of the eCryptfs directory `path` of `mount`, a mount of `mounts`.
fn lower_of(mount: &Mount, path: &Path, mounts: &[Mount]) -> Option<PathBuf> {
    let (mut lower, device) = lower_point(mount, mounts)?;
    let mut upper = mount.point.clone();
    for component in path.strip_prefix(&mount.point).ok()?.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        upper.push(name);
        let wanted = upper.symlink_metadata().ok()?;
        if !wanted.is_dir() {
            return None;
        }
        lower = lower_entry(&lower, name, wanted.ino(), device)?;
    }
    Some(lower)
}

/// The lower directory of the mount point of `mount`, with its device. Whatever leads to it, a
/// directory counts only when it lies on the file system whose ID eCryptfs reports, not on
/// eCryptfs itself, and has the inode of the mount point (`is_lower_point`): eCryptfs gives a
/// directory the inode of its lower directory, and one file system has one directory with that
/// inode. A way that leads elsewhere therefore finds nothing, and the next way is tried.
///
/// For a mount of the whole file system the way is the mount's source. The source is often named
/// through a link inside the mount itself (an encrypted home directory holds `.Private`), which a
/// program granted that directory can replace. A mount of a subdirectory names its root by the
/// names inside eCryptfs, which are not the lower ones when names are encrypted: it is found
/// through a mount of the whole file system in the table, by inode as any directory below one,
/// and otherwise by the same names below the source, which holds them when the mount does not
/// encrypt names.
fn lower_point(mount: &Mount, mounts: &[Mount]) -> Option<(PathBuf, u64)> {
    let inside = mount.root.strip_prefix("/").ok()?;
    let accept = |found: PathBuf| is_lower_point(mount, found);
    if inside.as_os_str().is_empty() {
        return accept(mount.source.canonicalize().ok()?);
    }
    mounts
        .iter()
        .filter(|whole| whole.device == mount.device && whole.root == Path::new("/"))
        .find_map(|whole| accept(lower_of(whole, &whole.point.join(inside), mounts)?))
        .or_else(|| accept(by_names(&mount.source, inside)?))
}

/// `inside` below the canonical `source`, by its names, through no link.
fn by_names(source: &Path, inside: &Path) -> Option<PathBuf> {
    let mut lower = source.canonicalize().ok()?;
    for component in inside.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        lower.push(name);
        if !lower.symlink_metadata().ok()?.is_dir() {
            return None;
        }
    }
    Some(lower)
}

/// `found`, with its device, when it is the lower directory of the point of `mount`.
fn is_lower_point(mount: &Mount, found: PathBuf) -> Option<(PathBuf, u64)> {
    let metadata = found.symlink_metadata().ok()?;
    let (_, lower_id) = file_system(&mount.point)?;
    let (found_type, found_id) = file_system(&found)?;
    let is_lower = metadata.is_dir()
        && found_type != MAGIC
        && lower_id != [0, 0]
        && found_id == lower_id
        && metadata.ino() == mount.point.symlink_metadata().ok()?.ino();
    is_lower.then(|| (found, metadata.dev()))
}

/// The directory in `lower` with inode `inode` on device `device`. A directory has one name, so
/// at most one entry matches. Without file name encryption the lower name is the upper one.
fn lower_entry(lower: &Path, name: &std::ffi::OsStr, inode: u64, device: u64) -> Option<PathBuf> {
    let is_wanted = |path: &Path| {
        path.symlink_metadata().is_ok_and(|metadata| {
            metadata.is_dir() && metadata.ino() == inode && metadata.dev() == device
        })
    };
    let same_name = lower.join(name);
    if is_wanted(&same_name) {
        return Some(same_name);
    }
    let entries = std::fs::read_dir(lower).ok()?;
    let mut matches = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.ino() == inode)
        .map(|entry| entry.path())
        .filter(|path| is_wanted(path));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn is_ecryptfs(path: &Path) -> bool {
    file_system(path).is_some_and(|(magic, _)| magic == MAGIC)
}

/// The type and the ID of the file system that holds `path` (`statfs`).
fn file_system(path: &Path) -> Option<(i64, [i32; 2])> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero statfs is a valid value of the plain C struct.
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: name is a NUL-terminated path and info a statfs the call writes.
    if unsafe { libc::statfs(name.as_ptr(), &mut info) } != 0 {
        return None;
    }
    // SAFETY: fsid_t is two C ints (`__kernel_fsid_t`), whose fields the libc crate keeps private.
    let id: [i32; 2] = unsafe { std::mem::transmute(info.f_fsid) };
    #[allow(clippy::unnecessary_cast)]
    Some((info.f_type as i64, id))
}

fn device_of(path: &Path) -> Option<u64> {
    Some(path.symlink_metadata().ok()?.dev())
}

/// The eCryptfs mounts of a mount table in the format of `proc(5)`: field 3 is the device, 4
/// the root, 5 the mount point, and after the separator `-` come the type and the source.
fn parse(table: &[u8]) -> Vec<Mount> {
    table
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
            let separator = fields.iter().position(|field| *field == b"-")?;
            if fields.get(separator + 1)? != b"ecryptfs" {
                return None;
            }
            let (major, minor) = std::str::from_utf8(fields.get(2)?).ok()?.split_once(':')?;
            Some(Mount {
                device: libc::makedev(major.parse().ok()?, minor.parse().ok()?),
                root: unescape(fields.get(3)?),
                point: unescape(fields.get(4)?),
                source: unescape(fields.get(separator + 2)?),
            })
        })
        .collect()
}

/// Reverses the octal escapes the mount table uses for space, tab, newline and backslash.
fn unescape(field: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let mut name = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, tail)) = rest.split_first() {
        let digits = tail.get(..3).filter(|digits| {
            byte == b'\\' && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
        });
        match digits {
            Some(digits) => {
                let value = digits
                    .iter()
                    .fold(0u32, |value, digit| value * 8 + u32::from(digit - b'0'));
                name.push(value as u8);
                rest = &tail[3..];
            }
            None => {
                name.push(byte);
                rest = tail;
            }
        }
    }
    PathBuf::from(std::ffi::OsString::from_vec(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_names_each_ecryptfs_mount_with_its_source() {
        let table = b"29 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n\
            55 29 0:44 / /home/a\\040b rw,nosuid,nodev,relatime shared:263 - ecryptfs \
            /home/a\\040b/.Private rw,ecryptfs_sig=d1a0,ecryptfs_cipher=aes\n\
            56 29 0:45 / /mnt/x rw shared:7 master:3 - ecryptfs /srv/lower rw\n";
        assert_eq!(
            parse(table),
            vec![
                Mount {
                    point: PathBuf::from("/home/a b"),
                    root: PathBuf::from("/"),
                    device: libc::makedev(0, 44),
                    source: PathBuf::from("/home/a b/.Private"),
                },
                Mount {
                    point: PathBuf::from("/mnt/x"),
                    root: PathBuf::from("/"),
                    device: libc::makedev(0, 45),
                    source: PathBuf::from("/srv/lower"),
                },
            ]
        );
    }

    fn dir_rule(path: &Path) -> PathRights {
        PathRights {
            path: path.to_path_buf(),
            is_dir: true,
            access: AccessFs::ReadDir | AccessFs::ReadFile,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("sandy-ecryptfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// A mount whose source is its own mount point has the same inodes on both sides, as
    /// eCryptfs has, so the walk can be checked without mounting anything.
    fn mount_onto_itself(point: &Path) -> Mount {
        Mount {
            point: point.to_path_buf(),
            root: PathBuf::from("/"),
            device: device_of(point).unwrap(),
            source: point.to_path_buf(),
        }
    }

    #[test]
    fn the_walk_follows_the_policy_path_to_the_lower_directory() {
        let root = scratch("walk");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let mount = mount_onto_itself(&root);
        assert_eq!(
            lower_of(&mount, &root.join("a/b"), &[]),
            Some(root.join("a/b"))
        );
        assert_eq!(lower_of(&mount, &root, &[]), Some(root.clone()));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn encrypted_names_are_found_by_inode() {
        let root = scratch("names");
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("file"), "").unwrap();
        let data = root.join("data").symlink_metadata().unwrap();
        // The lower name differs from the upper one when names are encrypted.
        let encrypted = std::ffi::OsStr::new("ECRYPTFS_FNEK_ENCRYPTED.x");
        assert_eq!(
            lower_entry(&root, encrypted, data.ino(), data.dev()),
            Some(root.join("data"))
        );
        // A lower entry of the same name but another inode is not the one.
        std::fs::create_dir_all(root.join("decoy")).unwrap();
        assert_eq!(
            lower_entry(&root, std::ffi::OsStr::new("decoy"), data.ino(), data.dev()),
            Some(root.join("data"))
        );
        let file = root.join("file").symlink_metadata().unwrap();
        assert_eq!(lower_entry(&root, encrypted, file.ino(), file.dev()), None);
        assert_eq!(
            lower_entry(&root, encrypted, data.ino(), data.dev() + 1),
            None
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_source_with_another_root_inode_is_not_used() {
        let root = scratch("other");
        std::fs::create_dir_all(root.join("upper/data")).unwrap();
        std::fs::create_dir_all(root.join("lower/data")).unwrap();
        let mount = Mount {
            source: root.join("lower"),
            ..mount_onto_itself(&root.join("upper"))
        };
        assert_eq!(lower_of(&mount, &root.join("upper/data"), &[]), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A link of the right name is skipped, and the walk finds the directory by its inode.
    #[test]
    fn a_link_is_never_a_lower_directory() {
        let root = scratch("link");
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::os::unix::fs::symlink(root.join("data"), root.join("via")).unwrap();
        let data = root.join("data").symlink_metadata().unwrap();
        assert_eq!(
            lower_entry(&root, std::ffi::OsStr::new("via"), data.ino(), data.dev()),
            Some(root.join("data"))
        );
        let mount = mount_onto_itself(&root);
        assert_eq!(lower_of(&mount, &root.join("via"), &[]), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A mount of a subdirectory, `sub` of the file system mounted at `whole`, has the inode of
    /// `sub` at its point. Here the point is `sub` itself, so the inodes match as on eCryptfs.
    fn mount_of_subdirectory(whole: &Path, sub: &str) -> Mount {
        Mount {
            point: whole.join(sub),
            root: Path::new("/").join(sub),
            ..mount_onto_itself(whole)
        }
    }

    /// Without a mount of the whole file system, a mount of a subdirectory is found by the same
    /// names below the source, as without name encryption.
    #[test]
    fn a_mount_of_a_subdirectory_is_found_by_its_names() {
        let root = scratch("bind");
        std::fs::create_dir_all(root.join("sub/deeper/data")).unwrap();
        let mount = mount_of_subdirectory(&root, "sub/deeper");
        let point = root.join("sub/deeper");
        assert_eq!(lower_of(&mount, &point, &[]), Some(point.clone()));
        assert_eq!(
            lower_of(&mount, &point.join("data"), &[]),
            Some(point.join("data"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// With a mount of the whole file system in the table, a mount of a subdirectory is found
    /// through it, by inode as any directory below that mount, which also works with encrypted
    /// names. The source of the mount of the subdirectory leads nowhere here, so only that way
    /// finds it; the upper and lower trees are one here, so it does not show the walk by inode,
    /// which `lower_entry` tests.
    #[test]
    fn a_mount_of_a_subdirectory_is_found_through_the_mount_of_the_whole() {
        let root = scratch("whole");
        std::fs::create_dir_all(root.join("sub/data")).unwrap();
        let whole = mount_onto_itself(&root);
        let bind = Mount {
            source: root.join("missing"),
            ..mount_of_subdirectory(&root, "sub")
        };
        assert_eq!(
            lower_of(&bind, &bind.point, &[]),
            None,
            "without the whole mount"
        );
        let mounts = [whole];
        assert_eq!(
            lower_of(&bind, &bind.point.join("data"), &mounts),
            Some(root.join("sub/data"))
        );
        // A mount of another file system is not the whole of this one.
        let other = Mount {
            device: mounts[0].device + 1,
            ..mount_onto_itself(&root)
        };
        assert_eq!(lower_of(&bind, &bind.point, &[other]), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A mount of the whole file system that does not lead to the mount of a subdirectory, as
    /// where a later mount covers part of the way, leaves the way by names.
    #[test]
    fn a_whole_mount_that_leads_nowhere_leaves_the_way_by_names() {
        let root = scratch("fallback");
        std::fs::create_dir_all(root.join("tree/sub")).unwrap();
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        let bind = mount_of_subdirectory(&root.join("tree"), "sub");
        let whole = Mount {
            device: bind.device,
            ..mount_onto_itself(&root.join("elsewhere"))
        };
        assert_eq!(
            lower_of(&bind, &bind.point, &[whole]),
            Some(root.join("tree/sub"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A name below the source that leads elsewhere through a link is not followed, also where
    /// the link is not the last name, and a directory of the same names with another inode is
    /// not the one.
    #[test]
    fn a_mount_of_a_subdirectory_is_not_found_through_a_link_or_another_inode() {
        let root = scratch("bind-link");
        let [upper, lower] = ["upper", "lower"].map(|name| root.join(name));
        std::fs::create_dir_all(upper.join("a/sub")).unwrap();
        std::fs::create_dir_all(&lower).unwrap();
        std::os::unix::fs::symlink(upper.join("a"), lower.join("a")).unwrap();
        let bind = Mount {
            point: upper.join("a/sub"),
            root: PathBuf::from("/a/sub"),
            source: lower.clone(),
            ..mount_onto_itself(&upper)
        };
        assert_eq!(lower_of(&bind, &bind.point, &[]), None, "through a link");
        std::fs::remove_file(lower.join("a")).unwrap();
        std::fs::create_dir_all(lower.join("a/sub")).unwrap();
        assert_eq!(lower_of(&bind, &bind.point, &[]), None, "another inode");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_system_has_one_id_for_all_its_directories() {
        let root = scratch("id");
        std::fs::create_dir_all(root.join("a")).unwrap();
        let (_, id) = file_system(&root).unwrap();
        if id == [0, 0] {
            // Older kernels report no ID for tmpfs, which sandy then never trusts.
            std::fs::remove_dir_all(&root).unwrap();
            return;
        }
        assert_eq!(file_system(&root.join("a")).unwrap().1, id);
        assert_ne!(file_system(Path::new("/proc")).unwrap().1, id);
        assert!(!is_ecryptfs(&root));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_rule_above_a_mount_gets_the_lower_root_of_the_mount() {
        let root = scratch("above");
        let point = root.join("home");
        std::fs::create_dir_all(point.join("data")).unwrap();
        let mounts = [mount_onto_itself(&point)];
        assert_eq!(
            reached(&root, &mounts),
            vec![(point.clone(), Some(point.clone()))]
        );
        // The mount point itself lies on eCryptfs only on a real mount.
        assert_eq!(reached(&point, &mounts), vec![]);
        let found = found_in(&[root.as_path(), root.as_path()], &mounts);
        assert_eq!(
            found.rules,
            vec![PathRights {
                path: point.clone(),
                is_dir: true,
                access: BitFlags::from(AccessFs::ReadDir),
            }]
        );
        assert!(found.unfound.is_empty());
        let subdirectory = Mount {
            root: PathBuf::from("/sub"),
            ..mount_onto_itself(&point)
        };
        let found = found_in(&[root.as_path(), root.as_path()], &[subdirectory]);
        assert_eq!(found.unfound, vec![point.clone()]);
        assert!(found.rules.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rules_that_list_nothing_get_no_lower_directory() {
        let root = scratch("files");
        let rule = PathRights {
            access: BitFlags::from(AccessFs::ReadFile),
            ..dir_rule(&root)
        };
        assert_eq!(lower_directories(&[rule]), LowerDirectories::default());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rules_off_ecryptfs_get_no_lower_directory() {
        let root = scratch("plain");
        assert_eq!(
            lower_directories(&[dir_rule(&root)]),
            LowerDirectories::default()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
