//! Locations of this user that programs outside the sandbox read or execute later, as far as
//! every Unix system has them: the startup files of bash, zsh and fish, the configuration of SSH,
//! GnuPG, git and cargo, and the home directory itself. A file the program leaves in one of them
//! runs outside the sandbox at the next login, the next shell or the next run of the tool, so a
//! writable path that reaches one is refused (rule 12 in DESIGN.md). The Linux and macOS backends
//! add the locations of their platform (`locations`) and compare the whole set with
//! `ResolvedPolicy::writable_conflict`. Windows keeps a list of its own and shares only cargo's
//! configuration (`cargo_configs`).
//!
//! The directories a shell looks commands up in are the same kind of location, but rule 12 warns
//! about them instead of refusing them (`path_locations`).
//!
//! The list is a heuristic and can never be complete: no list knows which files the programs of
//! this user trust. It names the locations of the usual shell and tool setups, and only those
//! that hold code or name a program to run: a location that only holds data is no escape.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::{ProtectedPath, path_directories};

/// Files below the home directory that a shell or a tool reads at its start. A missing one
/// counts, because the program could create it. Debian's `.bashrc` sources `.bash_aliases`. In
/// `.gitconfig`, `core.fsmonitor`, `core.sshCommand`, `core.pager` and `!` aliases run commands.
const HOME_FILES: &[&str] = &[
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
    ".gitconfig",
];

/// Directories below the home directory whose content decides what other programs of this user
/// run: the files Fedora's `.bashrc` sources, the SSH configuration (`ProxyCommand`,
/// `LocalCommand`, `authorized_keys`) and the GnuPG configuration (`pinentry-program`,
/// `photo-viewer`).
const HOME_TREES: &[&str] = &[".bashrc.d", ".ssh", ".gnupg"];

/// Directories below the configuration directory: the startup files of fish, and the git
/// configuration that git reads besides `.gitconfig`.
const CONFIG_TREES: &[&str] = &["fish", "git"];

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
pub fn locations(homes: &[PathBuf], platform: Vec<ProtectedPath>) -> Vec<ProtectedPath> {
    let mut locations = Vec::new();
    for home in homes {
        locations.extend(
            HOME_FILES
                .iter()
                .map(|name| ProtectedPath::entry(home.join(name))),
        );
        locations.extend(
            HOME_TREES
                .iter()
                .map(|name| ProtectedPath::tree(home.join(name))),
        );
    }
    for config in user_directories("XDG_CONFIG_HOME", homes, ".config") {
        locations.extend(
            CONFIG_TREES
                .iter()
                .map(|name| ProtectedPath::tree(config.join(name))),
        );
    }
    locations.extend(cargo_configs(homes));
    locations.extend(platform);
    locations.extend(homes.iter().map(ProtectedPath::entry));
    locations
}

/// cargo's configuration files in `CARGO_HOME` and in `.cargo` below every home directory.
pub fn cargo_configs(homes: &[PathBuf]) -> Vec<ProtectedPath> {
    user_directories("CARGO_HOME", homes, ".cargo")
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
) -> Vec<ProtectedPath> {
    let mut directories = path_directories(path);
    let usual = homes
        .iter()
        .flat_map(|home| HOME_BIN_DIRECTORIES.iter().map(|name| home.join(name)))
        .chain(
            user_directories("CARGO_HOME", homes, ".cargo")
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

/// The directory `variable` names when it is absolute, and `fallback` below every home
/// directory. Both, because a program that starts sandy with a minimal environment does not set
/// the variable while the user's own session does.
pub fn user_directories(variable: &str, homes: &[PathBuf], fallback: &str) -> Vec<PathBuf> {
    let named = std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let mut directories: Vec<PathBuf> = homes
        .iter()
        .map(|home| home.join(fallback))
        .chain(named)
        .collect();
    directories.sort();
    directories.dedup();
    directories
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
/// that only a directory service knows. Without the home directory sandy cannot tell whether a
/// writable path reaches the locations below it, so the backends refuse a policy with a writable
/// path, as they do when they cannot read the mount table.
pub fn home_directories() -> Result<Vec<PathBuf>, String> {
    homes(passwd_home(), std::env::var_os("HOME"))
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

/// The home directory the password database names for this user.
#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
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
        if error != 0 || found.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success pw_dir points to a NUL-terminated string inside buffer, which is
        // not changed before it is read here.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) };
        let home = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
        return home.is_absolute().then_some(home);
    }
}

/// Windows names the profile folder with an API of its own (`sys::user_profiles`).
#[cfg(not(unix))]
fn passwd_home() -> Option<PathBuf> {
    None
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
        let locations = locations(std::slice::from_ref(&home), vec![platform.clone()]);
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
}
