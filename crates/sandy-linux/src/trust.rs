//! Locations of this user that programs outside the sandbox read or execute later: shell startup
//! files, autostart entries, user units, the session environment, and the SSH and GnuPG
//! configuration. A file the program leaves in one of them runs outside the sandbox at the next
//! login or the next shell, so a writable path that reaches one is refused
//! (`plan::trust_conflict`). Landlock rules are allow-only and apply to a whole tree, so a
//! writable home directory cannot exclude the shell startup file in it; refusing the policy is
//! the only way to keep the guarantee.
//!
//! The directories on sandy's PATH are the same kind of location, but rule 12 warns about them
//! instead of refusing them (`path_locations`, `plan::notes`).
//!
//! The list is a heuristic and can never be complete: no list knows which files the programs of
//! this user trust. It names the locations of the usual shell and desktop setups.

use std::path::PathBuf;

use sandy_core::{ProtectedPath, path_directories};

/// Files a shell or a session reads at every start, below the home directory. A missing one
/// counts, because the program could create it.
const STARTUP_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".pam_environment",
    ".xprofile",
    ".xinitrc",
    ".xsession",
];

/// Directories below the home directory whose content decides what other programs of this user
/// run: the SSH configuration (`ProxyCommand`, `LocalCommand`, `authorized_keys`) and the GnuPG
/// configuration (`pinentry-program`, `photo-viewer`).
const HOME_TREES: &[&str] = &[".ssh", ".gnupg"];

/// Directories below the configuration directory: desktop autostart entries, systemd user units,
/// the variables of the session, and the fish shell configuration.
const CONFIG_TREES: &[&str] = &["autostart", "systemd", "environment.d", "fish"];

/// Directories below the data directory: systemd user units, and the desktop entries that say
/// which program opens a file.
const DATA_TREES: &[&str] = &["systemd", "applications"];

/// Where the files are that other programs of this user read or execute. A writable path that
/// reaches one of them is refused.
pub fn locations() -> Vec<ProtectedPath> {
    let homes = home_directories();
    let mut locations = Vec::new();
    for home in &homes {
        locations.extend(
            STARTUP_FILES
                .iter()
                .map(|name| ProtectedPath::entry(home.join(name))),
        );
        locations.extend(
            HOME_TREES
                .iter()
                .map(|name| ProtectedPath::tree(home.join(name))),
        );
        // After the files in it, so that a writable home directory is reported with the file
        // that makes it dangerous. Only a writable path that contains the home directory is
        // refused: the usual policies make a directory below it writable, which stays allowed.
        locations.push(ProtectedPath::entry(home));
    }
    for config in xdg_directories("XDG_CONFIG_HOME", &homes, ".config") {
        locations.extend(
            CONFIG_TREES
                .iter()
                .map(|name| ProtectedPath::tree(config.join(name))),
        );
    }
    for data in xdg_directories("XDG_DATA_HOME", &homes, ".local/share") {
        locations.extend(
            DATA_TREES
                .iter()
                .map(|name| ProtectedPath::tree(data.join(name))),
        );
    }
    locations
}

/// The directories on sandy's PATH, which only warn. A program the sandboxed one leaves in one
/// of them runs outside the sandbox when the user next types its name, but a writable path that
/// holds such a directory is ordinary work, a package cache whose `bin` directory is on PATH for
/// example, so refusing it would turn away the common case (rule 12).
pub fn path_locations() -> Vec<ProtectedPath> {
    path_directories(std::env::var_os("PATH").as_deref())
}

/// The directory `variable` names when it is absolute, and `fallback` below every home
/// directory. Both, because a program that starts sandy with a minimal environment sets no XDG
/// variable while the user's own session does.
fn xdg_directories(variable: &str, homes: &[PathBuf], fallback: &str) -> Vec<PathBuf> {
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

/// The home directory of this user, from the password database and from HOME. The password
/// database, because a program that starts sandy with a minimal environment sets no HOME; HOME
/// as well, because a user who moves their home with it keeps their files there. When neither
/// names one, only the locations that do not depend on it are checked.
fn home_directories() -> Vec<PathBuf> {
    let named = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let mut homes: Vec<PathBuf> = passwd_home().into_iter().chain(named).collect();
    homes.sort();
    homes.dedup();
    homes
}

/// The home directory the password database names for this user.
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The home directory of this user is protected, and so are the startup files in it, also
    /// those that do not exist on this host.
    #[test]
    fn the_locations_cover_the_home_directory_of_this_user() {
        let Some(home) = home_directories().into_iter().next() else {
            // A host without a password database entry and without HOME.
            return;
        };
        let locations = locations();
        let holds = |path: &std::path::Path| locations.iter().any(|entry| entry.path == path);
        assert!(holds(&home), "{locations:?}");
        assert!(holds(&home.join(".bashrc")), "{locations:?}");
        assert!(holds(&home.join(".config/autostart")), "{locations:?}");
        assert!(holds(&home.join(".ssh")), "{locations:?}");
        // Only the home directory itself, so a writable directory below it keeps working.
        let home_entry = locations.iter().find(|entry| entry.path == home).unwrap();
        assert!(!home_entry.subtree);
    }

    /// The directories of PATH are in the set that warns and in no other
    /// (`sandy_core::path_directories` checks how they are read).
    #[test]
    fn the_directories_on_path_are_only_warned_about() {
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let refused = locations();
        let warned = path_locations();
        for directory in std::env::split_paths(&path).filter(|entry| entry.is_absolute()) {
            assert!(
                warned.iter().any(|entry| entry.path == directory),
                "{} is not warned about",
                directory.display()
            );
            assert!(
                !refused.iter().any(|entry| entry.path == directory),
                "{} is refused",
                directory.display()
            );
        }
    }
}
