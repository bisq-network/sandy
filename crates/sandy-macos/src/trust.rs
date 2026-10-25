//! Locations of this user that programs outside the sandbox read or execute later and that only
//! macOS has: the launch agents launchd starts at login. They add to the locations every Unix
//! shares (`sandy_core::trust`): the shell startup files, the SSH, GnuPG, git and cargo
//! configuration, and the home directory. A file the program leaves in one of them runs outside
//! the sandbox at the next login, the next shell or the next run of the tool, so a writable path
//! that reaches one is refused (`plan::trust_conflict`).
//!
//! The directories on sandy's PATH and the usual ones of the user's PATH are the same kind of
//! location, but rule 12 warns about them instead of refusing them (`path_locations`,
//! `plan::notes`).
//!
//! A Seatbelt profile could deny these paths inside a writable path instead, because a later deny
//! rule overrides an earlier allow (`profile`). sandy refuses instead, so that one policy means
//! the same on every platform: Landlock rules are allow-only, so the Linux backend cannot carve
//! a file out of a writable tree.

use sandy_core::ProtectedPath;
use sandy_core::trust;

/// Directories below the home directory whose content decides what other programs of this user
/// run: the launch agents launchd starts at login.
const HOME_TREES: &[&str] = &["Library/LaunchAgents"];

/// Homebrew's directories on Apple silicon: they belong to the user who installed it, and the
/// `brew shellenv` line in `.zprofile` puts them on PATH.
const BIN_DIRECTORIES: &[&str] = &["/opt/homebrew/bin", "/opt/homebrew/sbin"];

/// Where the files are that other programs of this user read or execute. A writable path that
/// reaches one of them is refused, and so is every writable path when no source names the home
/// directory (`sandy_core::trust::home_directories`).
pub fn locations() -> Result<Vec<ProtectedPath>, String> {
    let homes = trust::home_directories()?;
    let platform = homes
        .iter()
        .flat_map(|home| {
            HOME_TREES
                .iter()
                .map(|name| ProtectedPath::tree(home.join(name)))
        })
        .collect();
    Ok(trust::locations(&homes, platform))
}

/// The directories on sandy's PATH and the usual ones of the user's PATH, which only warn. A
/// program the sandboxed one leaves in one of them runs outside the sandbox when the user next
/// types its name, but a writable path that holds such a directory is ordinary work, a package
/// cache whose `bin` directory is on PATH for example, so refusing it would turn away the common
/// case (rule 12).
pub fn path_locations() -> Vec<ProtectedPath> {
    trust::path_locations(
        std::env::var_os("PATH").as_deref(),
        &trust::home_directories().unwrap_or_default(),
        BIN_DIRECTORIES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directories of PATH and Homebrew's are in the set that warns and in no other
    /// (`sandy_core::trust::path_locations` checks which others join them).
    #[test]
    fn the_directories_on_path_are_only_warned_about() {
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let refused = locations().unwrap_or_default();
        let warned = path_locations();
        let homebrew = BIN_DIRECTORIES.iter().map(std::path::PathBuf::from);
        let path = std::env::split_paths(&path).filter(|entry| entry.is_absolute());
        for directory in path.chain(homebrew) {
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

    /// On macOS the launch agents of this user and the files its shell reads are in the set.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_locations_cover_the_home_directory_of_this_user() {
        let Ok(locations) = locations() else {
            return;
        };
        let home = trust::home_directories().unwrap().remove(0);
        let holds = |path: &std::path::Path| locations.iter().any(|entry| entry.path == path);
        assert!(holds(&home), "{locations:?}");
        assert!(holds(&home.join(".zshrc")), "{locations:?}");
        assert!(holds(&home.join(".bash_login")), "{locations:?}");
        assert!(holds(&home.join(".config/fish")), "{locations:?}");
        assert!(holds(&home.join("Library/LaunchAgents")), "{locations:?}");
        // Only the home directory itself, so a writable directory below it keeps working.
        let home_entry = locations.iter().find(|entry| entry.path == home).unwrap();
        assert!(!home_entry.subtree);
    }
}
