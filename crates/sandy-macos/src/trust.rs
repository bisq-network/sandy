//! Locations of this user that programs outside the sandbox read or execute later: the launch
//! agents launchd starts at login, the shell startup files, the SSH and GnuPG configuration, and
//! the directories on sandy's PATH. A file the program leaves in one of them runs outside the
//! sandbox at the next login, the next shell or the next command, so a writable path that reaches
//! one is refused (`plan::trust_conflict`).
//!
//! A Seatbelt profile could deny these paths inside a writable path instead, because a later deny
//! rule overrides an earlier allow (`profile`). sandy refuses instead, so that one policy means
//! the same on every platform: Landlock rules are allow-only, so the Linux backend cannot carve
//! a file out of a writable tree.
//!
//! The list is a heuristic and can never be complete: no list knows which files the programs of
//! this user trust. It names the locations of the usual shell and desktop setups.
//!
//! Only the lookup of the home directory is specific to macOS. The rest is pure, so the planner
//! stays testable on every platform; off macOS the set holds the PATH directories alone.

use std::path::PathBuf;

use sandy_core::{ProtectedPath, path_directories};

/// Files a shell reads at every start, below the home directory. zsh is the login shell of
/// macOS; bash is still installed. A missing one counts, because the program could create it.
const STARTUP_FILES: &[&str] = &[
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".bashrc",
    ".bash_profile",
    ".profile",
];

/// Directories below the home directory whose content decides what other programs of this user
/// run: the launch agents launchd starts at login, the SSH configuration (`ProxyCommand`,
/// `LocalCommand`, `authorized_keys`) and the GnuPG configuration (`pinentry-program`).
const HOME_TREES: &[&str] = &["Library/LaunchAgents", ".ssh", ".gnupg"];

/// Where the files are that other programs of this user read or execute.
pub fn locations() -> Vec<ProtectedPath> {
    let mut locations = Vec::new();
    for home in home_directories() {
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
    locations.extend(path_directories(std::env::var_os("PATH").as_deref()));
    locations
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
#[cfg(target_os = "macos")]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    /// The entry of a user with many groups is longer than the first buffer; the limit stops a
    /// directory service that keeps asking for more.
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

/// Off macOS the crate builds for its unit tests only, and there is no macOS user to ask.
#[cfg(not(target_os = "macos"))]
fn passwd_home() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directories of PATH are in the set (`sandy_core::path_directories` checks how they
    /// are read).
    #[test]
    fn the_locations_cover_the_directories_on_path() {
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let locations = locations();
        for directory in std::env::split_paths(&path).filter(|entry| entry.is_absolute()) {
            assert!(
                locations.iter().any(|entry| entry.path == directory),
                "{} is not protected",
                directory.display()
            );
        }
    }

    /// On macOS the launch agents of this user and the files its shell reads are in the set.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_locations_cover_the_home_directory_of_this_user() {
        let Some(home) = home_directories().into_iter().next() else {
            return;
        };
        let locations = locations();
        let holds = |path: &std::path::Path| locations.iter().any(|entry| entry.path == path);
        assert!(holds(&home), "{locations:?}");
        assert!(holds(&home.join(".zshrc")), "{locations:?}");
        assert!(holds(&home.join("Library/LaunchAgents")), "{locations:?}");
        // Only the home directory itself, so a writable directory below it keeps working.
        let home_entry = locations.iter().find(|entry| entry.path == home).unwrap();
        assert!(!home_entry.subtree);
    }
}
