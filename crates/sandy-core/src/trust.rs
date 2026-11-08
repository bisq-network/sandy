//! Locations of this user that programs outside the sandbox read or execute later, as far as
//! every Unix system has them: the startup files of bash, zsh and fish, the configuration of SSH,
//! GnuPG, git and cargo, and the home directory itself. A file the program leaves in one of them
//! runs outside the sandbox at the next login, the next shell or the next run of the tool, so a
//! writable path that reaches one is refused (rule 12 in DESIGN.md). The Linux and macOS backends
//! add the locations of their platform (`locations`) and compare the whole set with
//! `ResolvedPolicy::writable_conflict`. Windows keeps a list of its own and shares the
//! configuration of the tools that read it there too (`tool_configs`).
//!
//! The directories a shell looks commands up in are the same kind of location, but rule 12 warns
//! about them instead of refusing them (`path_locations`).
//!
//! The list is a heuristic and can never be complete: no list knows which files the programs of
//! this user trust. It names the locations of the usual shell and tool setups, and only those
//! that hold code or name a program to run: a location that only holds data is no escape.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::{ProtectedPath, canonical_location, path_directories};

/// Files below the home directory that a shell reads at its start. A missing one counts, because
/// the program could create it. Debian's `.bashrc` sources `.bash_aliases`.
const SHELL_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".bash_aliases",
    ".profile",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
];

/// The files Fedora's `.bashrc` sources.
const SHELL_TREES: &[&str] = &[".bashrc.d"];

/// The startup files of fish, below the configuration directory.
const SHELL_CONFIG_TREES: &[&str] = &["fish"];

/// Files below the home directory that a tool reads at its start. In `.gitconfig`,
/// `core.fsmonitor`, `core.sshCommand`, `core.pager` and `!` aliases run commands.
const TOOL_FILES: &[&str] = &[".gitconfig"];

/// Directories below the home directory whose content decides what a tool of this user runs:
/// the SSH configuration (`ProxyCommand`, `LocalCommand`, `authorized_keys`) and the GnuPG
/// configuration (`pinentry-program`, `photo-viewer`).
const TOOL_TREES: &[&str] = &[".ssh", ".gnupg"];

/// The git configuration that git reads besides `.gitconfig`, below the configuration directory.
const TOOL_CONFIG_TREES: &[&str] = &["git"];

/// Files in cargo's home that name programs the next cargo command runs: `build.rustc`,
/// `build.rustc-wrapper` and target runners. `config` is the name before `config.toml`, and cargo
/// still reads it.
const CARGO_CONFIGS: &[&str] = &["config.toml", "config"];

/// Directories below the home directory that the usual shell setups put on PATH: Debian's
/// `.profile` and Fedora's `.bashrc` add both, and pipx and uv install commands into the first.
/// cargo's `bin` directory joins them (`path_locations`), because rustup puts it on PATH.
const HOME_BIN_DIRECTORIES: &[&str] = &[".local/bin", "bin"];

/// On the default PATH of the usual Linux distributions, and on macOS put there by `/etc/paths`
/// and Homebrew, which on Intel Macs makes them the user's.
const LOCAL_BIN_DIRECTORIES: &[&str] = &["/usr/local/bin", "/usr/local/sbin"];

/// The trusted locations of this user below `homes`: the shared ones, then `platform`, then each
/// home directory itself. The home directory comes last, so that a writable home directory is
/// reported with the file that makes it dangerous. It protects only itself: the usual policies
/// make a directory below it writable, which stays allowed.
pub fn locations(
    homes: &[PathBuf],
    platform: Vec<ProtectedPath>,
    drives: &[PathBuf],
) -> Vec<ProtectedPath> {
    let mut locations = below_homes(homes, SHELL_FILES, SHELL_TREES, SHELL_CONFIG_TREES, drives);
    locations.extend(tool_configs(homes, drives));
    locations.extend(platform);
    locations.extend(homes.iter().map(ProtectedPath::entry));
    locations
}

/// The configuration of the tools that read it on every platform, Windows included: git, SSH,
/// GnuPG and cargo, below every home directory and the directories their variables name.
///
/// `drives` are the drives a path without one may mean, empty off Windows. A variable that names
/// a path with a drive protects that path; one rooted without a drive protects it on each of
/// `drives`, as the homes of `tool_homes` do.
pub fn tool_configs(homes: &[PathBuf], drives: &[PathBuf]) -> Vec<ProtectedPath> {
    let mut locations = below_homes(homes, TOOL_FILES, TOOL_TREES, TOOL_CONFIG_TREES, drives);
    locations.extend(cargo_configs(homes, drives));
    // GNUPGHOME names the GnuPG configuration directory, GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM
    // the one file git reads as the global and the system configuration, each replacing the
    // default. A writable path that reaches one lets the program change what gpg or git runs, so
    // protect it when the variable names a place (rule 12). gpg expands a leading `~` itself, git
    // does not.
    locations.extend(configured("GNUPGHOME", true, homes, drives));
    locations.extend(configured("GIT_CONFIG_GLOBAL", false, &[], drives));
    locations.extend(configured("GIT_CONFIG_SYSTEM", false, &[], drives));
    locations
}

/// The locations `variable` names (`named_directories`), with their tree when `subtree`. A value
/// that starts with the component `~` names the rest below each of `tilde_homes`, for a tool that
/// expands it itself; pass none for one that does not. A relative value names no one place: the
/// tool resolves it against its working directory, which sandy does not know.
///
/// A device or a named pipe, such as the `/dev/null` that CI sets `GIT_CONFIG_GLOBAL` to so that
/// git ignores the global configuration, holds nothing that persists, so it stays writable; the
/// directory it lies in is protected instead, because a writable path there could put a file in
/// its place.
fn configured(
    variable: &'static str,
    subtree: bool,
    tilde_homes: &[PathBuf],
    drives: &[PathBuf],
) -> Vec<ProtectedPath> {
    named_locations(
        variable,
        std::env::var_os(variable),
        subtree,
        tilde_homes,
        drives,
    )
}

/// `configured` for the `value` of `variable`.
fn named_locations(
    variable: &'static str,
    value: Option<OsString>,
    subtree: bool,
    tilde_homes: &[PathBuf],
    drives: &[PathBuf],
) -> Vec<ProtectedPath> {
    let rest = value
        .as_deref()
        .and_then(|value| Path::new(value).strip_prefix("~").ok())
        .filter(|_| !tilde_homes.is_empty());
    let paths = match rest {
        // `join` with an empty path would add a separator to the home directory.
        Some(rest) if rest.as_os_str().is_empty() => tilde_homes.to_vec(),
        Some(rest) => tilde_homes.iter().map(|home| home.join(rest)).collect(),
        None => named_directories(value, drives),
    };
    let mut locations = Vec::new();
    for path in paths {
        let special = std::fs::metadata(&path)
            .is_ok_and(|metadata| !metadata.is_file() && !metadata.is_dir());
        if !special {
            let location = if subtree {
                ProtectedPath::tree(path)
            } else {
                ProtectedPath::entry(path)
            };
            locations.push(location.named_by(variable));
            continue;
        }
        // Both the directory of the name and that of the file it leads to: whoever can write
        // where a link lies can repoint it.
        let target = canonical_location(&path);
        let mut parents: Vec<&Path> = [path.parent(), target.parent()]
            .into_iter()
            .flatten()
            .collect();
        parents.dedup();
        locations.extend(
            parents
                .into_iter()
                .map(|parent| ProtectedPath::entry(parent).named_by(variable)),
        );
    }
    locations
}

/// `files` and `trees` below every home directory, and `config_trees` below every configuration
/// directory.
fn below_homes(
    homes: &[PathBuf],
    files: &[&str],
    trees: &[&str],
    config_trees: &[&str],
    drives: &[PathBuf],
) -> Vec<ProtectedPath> {
    let mut locations = Vec::new();
    for home in homes {
        locations.extend(
            files
                .iter()
                .map(|name| ProtectedPath::entry(home.join(name))),
        );
        locations.extend(
            trees
                .iter()
                .map(|name| ProtectedPath::tree(home.join(name))),
        );
    }
    for config in user_directories("XDG_CONFIG_HOME", homes, ".config", drives) {
        locations.extend(
            config_trees
                .iter()
                .map(|name| ProtectedPath::tree(config.join(name))),
        );
    }
    locations
}

/// cargo's configuration files in `CARGO_HOME` and in `.cargo` below every home directory.
fn cargo_configs(homes: &[PathBuf], drives: &[PathBuf]) -> Vec<ProtectedPath> {
    user_directories("CARGO_HOME", homes, ".cargo", drives)
        .iter()
        .flat_map(|cargo| {
            CARGO_CONFIGS
                .iter()
                .map(|name| ProtectedPath::entry(cargo.join(name)))
        })
        .collect()
}

/// The directories rule 12 warns about instead of refusing them: those on `path`, sandy's own
/// PATH, and the usual ones of a user's PATH with `platform`'s, whether or not `path` holds
/// them. A service or a desktop application starts sandy with a minimal PATH, while the user's
/// shell looks for commands in `~/.local/bin` first. The list is short on purpose: each entry is
/// a directory that common setups put on PATH by default.
pub fn path_locations(
    path: Option<&OsStr>,
    homes: &[PathBuf],
    platform: &[&str],
    drives: &[PathBuf],
) -> Vec<ProtectedPath> {
    let mut directories = path_directories(path);
    let usual = homes
        .iter()
        .flat_map(|home| HOME_BIN_DIRECTORIES.iter().map(|name| home.join(name)))
        .chain(
            user_directories("CARGO_HOME", homes, ".cargo", drives)
                .into_iter()
                .map(|cargo| cargo.join("bin")),
        )
        .chain(
            LOCAL_BIN_DIRECTORIES
                .iter()
                .chain(platform)
                .map(PathBuf::from),
        );
    for directory in usual {
        if !directories.iter().any(|known| known.path == directory) {
            directories.push(ProtectedPath::entry(directory));
        }
    }
    directories
}

/// The place `variable` names, and `fallback` below every home directory. Both, because a program
/// that starts sandy with a minimal environment does not set the variable while the user's own
/// session does. `drives` are the drives a path without one may mean (empty off Windows); see
/// `named_directories`.
pub fn user_directories(
    variable: &str,
    homes: &[PathBuf],
    fallback: &str,
    drives: &[PathBuf],
) -> Vec<PathBuf> {
    let named = named_directories(std::env::var_os(variable), drives);
    let mut directories: Vec<PathBuf> = homes
        .iter()
        .map(|home| home.join(fallback))
        .chain(named)
        .collect();
    directories.sort();
    directories.dedup();
    directories
}

/// The places a variable's `value` names, so that one program reads the same file whichever way
/// the path is written. A value with a drive, or an absolute Unix path, names one place. A value
/// rooted without a drive, as on Windows (`\Users\x`), names one place on each of `drives`, the
/// drives a path without one may mean; `drives` is empty off Windows, where every rooted path is
/// absolute. A relative value names no one place and is left out. This is the expansion
/// `tool_homes` does for the home directory, applied to every variable that names a protected
/// place.
pub fn named_directories(value: Option<OsString>, drives: &[PathBuf]) -> Vec<PathBuf> {
    let Some(path) = value.map(PathBuf::from) else {
        return Vec::new();
    };
    if path.is_absolute() {
        vec![path]
    } else if path.has_root() {
        drives.iter().map(|drive| drive.join(&path)).collect()
    } else {
        Vec::new()
    }
}

/// Why there is no home directory to check, when neither source names one.
const NO_HOME: &str = "cannot find the home directory of this user: HOME is not set to an \
    absolute path and the password database names none, so sandy cannot check that no writable \
    path reaches the shell startup files and the other locations whose content runs outside the \
    sandbox; start sandy with HOME set to the home directory";

/// The home directory of this user, from the password database and from HOME. The password
/// database, because a program that starts sandy with a minimal environment sets no HOME; HOME
/// as well, because a user who moves their home with it keeps their files there.
///
/// `Err` with the reason when neither names one, which happens with a static build for a user
/// that only a directory service knows, and when the password database cannot be read, which
/// with a directory service on the network can pass. Without the home directory sandy cannot
/// tell whether a writable path reaches the locations below it, so the backends report a policy
/// with a writable path as `Status::Indeterminate`, as they do when they cannot read the mount
/// table.
pub fn home_directories() -> Result<Vec<PathBuf>, String> {
    homes(passwd_home()?, std::env::var_os("HOME"))
}

fn homes(passwd: Option<PathBuf>, variable: Option<OsString>) -> Result<Vec<PathBuf>, String> {
    let named = variable
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let mut homes: Vec<PathBuf> = passwd.into_iter().chain(named).collect();
    if homes.is_empty() {
        return Err(NO_HOME.to_string());
    }
    homes.sort();
    homes.dedup();
    Ok(homes)
}

/// The home directory the password database names for this user: `None` when it has no entry
/// for the user, `Err` when it cannot be read. With a directory service such as LDAP the lookup
/// can fail for a while, and treating that as "no entry" would quietly drop the home directory
/// it names from the protected locations.
#[cfg(unix)]
fn passwd_home() -> Result<Option<PathBuf>, String> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    /// The entry of a user with many groups is longer than the first buffer; the limit stops a
    /// password database that keeps asking for more.
    const LIMIT: usize = 64 * 1024;

    let mut buffer = vec![0u8; 1024];
    loop {
        // SAFETY: an all-zero passwd is a valid value of the type; the call below fills it.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: entry and found are valid out pointers, and the call writes at most
        // buffer.len() bytes through the buffer pointer.
        let error = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if error == libc::ERANGE && buffer.len() < LIMIT {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if error != 0 && !no_entry(error) {
            return Err(format!(
                "cannot read the password database entry of this user: {}",
                std::io::Error::from_raw_os_error(error)
            ));
        }
        if error != 0 || found.is_null() || entry.pw_dir.is_null() {
            return Ok(None);
        }
        // SAFETY: on success pw_dir points to a NUL-terminated string inside buffer, which is
        // not changed before it is read here.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) };
        let home = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
        return Ok(home.is_absolute().then_some(home));
    }
}

/// The errors with which some C libraries say that the password database has no entry for the
/// user, as getpwuid_r(3) lists them, instead of returning 0 with no entry.
#[cfg(unix)]
fn no_entry(error: libc::c_int) -> bool {
    [libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM].contains(&error)
}

/// Windows names the profile folder with an API of its own (`sys::user_profiles`).
#[cfg(not(unix))]
fn passwd_home() -> Result<Option<PathBuf>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The startup files of every Unix shell and the configuration of the tools are protected
    /// below each home directory, also those that do not exist, and the platform's own locations
    /// come before the home directory itself.
    #[test]
    fn the_shared_locations_cover_the_shells_and_tools_of_every_home() {
        let home = PathBuf::from("/home/someone");
        let platform = ProtectedPath::tree(home.join("platform"));
        let locations = locations(std::slice::from_ref(&home), vec![platform.clone()], &[]);
        let protects = |path: &str, subtree: bool| {
            locations
                .iter()
                .any(|entry| entry.path == home.join(path) && entry.subtree == subtree)
        };
        for file in [".bashrc", ".bash_login", ".bash_logout", ".bash_aliases"] {
            assert!(protects(file, false), "{file}: {locations:?}");
        }
        for file in [
            ".zshrc",
            ".gitconfig",
            ".cargo/config.toml",
            ".cargo/config",
        ] {
            assert!(protects(file, false), "{file}: {locations:?}");
        }
        for tree in [".bashrc.d", ".ssh", ".gnupg", ".config/fish", ".config/git"] {
            assert!(protects(tree, true), "{tree}: {locations:?}");
        }
        assert_eq!(locations.last(), Some(&ProtectedPath::entry(&home)));
        let position = |entry: &ProtectedPath| locations.iter().position(|e| e == entry);
        assert!(position(&platform) < position(&ProtectedPath::entry(&home)));
    }

    /// The usual directories of a user's PATH are warned about also when sandy's own PATH lacks
    /// them, and each directory once.
    #[test]
    fn the_usual_directories_on_path_count_without_sandys_path() {
        let home = std::env::temp_dir().join("someone");
        let named = std::env::temp_dir().join("tools");
        let path = std::env::join_paths([named.as_path(), Path::new("/usr/local/bin")]).unwrap();
        let directories = path_locations(
            Some(&path),
            std::slice::from_ref(&home),
            &["/opt/homebrew/bin"],
            &[],
        );
        let count = |directory: &Path| {
            directories
                .iter()
                .filter(|entry| entry.path == directory && !entry.subtree)
                .count()
        };
        for directory in [
            named,
            home.join(".local/bin"),
            home.join("bin"),
            home.join(".cargo/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
            PathBuf::from("/opt/homebrew/bin"),
        ] {
            assert_eq!(count(&directory), 1, "{directory:?}: {directories:?}");
        }
        assert!(!directories.iter().any(|entry| entry.path == home));
    }

    /// HOME counts only when it is absolute, and it adds to the password database. When
    /// neither names a home directory, the reason says how to name one.
    #[test]
    fn only_an_absolute_home_counts() {
        // Absolute on every platform, which "/home" is not on Windows.
        let passwd = std::env::temp_dir().join("someone");
        let moved = std::env::temp_dir().join("moved");
        for variable in [
            None,
            Some(OsString::from("relative")),
            Some(OsString::new()),
        ] {
            let reason = homes(None, variable).unwrap_err();
            assert!(reason.contains("start sandy with HOME set"), "{reason}");
        }
        assert_eq!(
            homes(None, Some(passwd.clone().into())),
            Ok(vec![passwd.clone()])
        );
        assert_eq!(homes(Some(passwd.clone()), None), Ok(vec![passwd.clone()]));
        assert_eq!(
            homes(Some(passwd.clone()), Some(passwd.clone().into())),
            Ok(vec![passwd.clone()])
        );
        assert_eq!(
            homes(Some(passwd.clone()), Some(moved.clone().into())),
            Ok(vec![moved, passwd])
        );
    }

    /// A configuration variable that names a device protects the directory the device lies in,
    /// not the device, which holds nothing that persists; a file or a directory protects itself.
    #[cfg(unix)]
    #[test]
    fn a_configured_device_protects_only_its_directory() {
        let locations = named_locations(
            "GIT_CONFIG_GLOBAL",
            Some("/dev/null".into()),
            false,
            &[],
            &[],
        );
        let paths: Vec<&Path> = locations
            .iter()
            .map(|location| location.path.as_path())
            .collect();
        assert_eq!(paths, [Path::new("/dev")]);
        assert!(!locations[0].subtree);
        assert_eq!(locations[0].describe(), "/dev (GIT_CONFIG_GLOBAL)");

        let directory = std::env::temp_dir();
        let locations =
            named_locations("GNUPGHOME", Some(directory.clone().into()), true, &[], &[]);
        assert_eq!(
            locations,
            [ProtectedPath::tree(&directory).named_by("GNUPGHOME")]
        );
    }

    /// gpg expands a leading `~` in GNUPGHOME with the home directory, so a quoted
    /// `GNUPGHOME="~/.local/share/gnupg"` names a place below every home directory; git does
    /// not, so for GIT_CONFIG_GLOBAL, which gets no homes to expand with, the value is relative
    /// and names none.
    #[test]
    fn a_leading_tilde_names_a_place_below_every_home_directory_that_is_given() {
        let homes = [PathBuf::from("/home/one"), PathBuf::from("/home/two")];
        let paths = |value: &str, tilde_homes: &[PathBuf]| -> Vec<PathBuf> {
            named_locations("GNUPGHOME", Some(value.into()), true, tilde_homes, &[])
                .into_iter()
                .map(|location| location.path)
                .collect()
        };
        assert_eq!(
            paths("~/.local/share/gnupg", &homes),
            [
                PathBuf::from("/home/one/.local/share/gnupg"),
                PathBuf::from("/home/two/.local/share/gnupg")
            ]
        );
        assert_eq!(paths("~", &homes), homes);
        assert_eq!(paths("~other/gnupg", &homes), Vec::<PathBuf>::new());
        assert_eq!(paths("~/gitconfig", &[]), Vec::<PathBuf>::new());
    }

    /// A variable that names a place with a drive, or an absolute Unix path, names one place; one
    /// rooted without a drive names one on each drive; a relative value or none names none.
    #[test]
    fn named_directories_expand_a_rooted_value_across_the_drives() {
        let drives = [PathBuf::from(r"C:\"), PathBuf::from(r"E:\")];
        assert_eq!(named_directories(None, &drives), Vec::<PathBuf>::new());
        assert_eq!(
            named_directories(Some("relative".into()), &drives),
            Vec::<PathBuf>::new()
        );
        if cfg!(windows) {
            assert_eq!(
                named_directories(Some(r"C:relative".into()), &drives),
                Vec::<PathBuf>::new()
            );
            assert_eq!(
                named_directories(Some(r"D:\config".into()), &drives),
                vec![PathBuf::from(r"D:\config")]
            );
            assert_eq!(
                named_directories(Some(r"\shared\config".into()), &drives),
                vec![
                    PathBuf::from(r"C:\shared\config"),
                    PathBuf::from(r"E:\shared\config")
                ]
            );
        } else {
            // Off Windows there are no drives and every rooted path is absolute.
            assert_eq!(
                named_directories(Some("/etc/config".into()), &[]),
                vec![PathBuf::from("/etc/config")]
            );
        }
    }
}
