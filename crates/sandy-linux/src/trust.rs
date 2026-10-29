//! Locations of this user that programs outside the sandbox read or execute later and that only
//! Linux has: the files a graphical or PAM session reads, desktop autostart entries, systemd user
//! units, the variables of the session and the KDE Plasma startup and logout scripts. They add to
//! the locations every Unix shares (`sandy_core::trust`): the shell startup files, the SSH, GnuPG,
//! git and cargo configuration, and the home directory. A file the program leaves in one of them
//! runs outside the sandbox at the next login, the next shell or the next run of the tool, so a
//! writable path that reaches one is refused (`plan::trust_conflict`). Landlock rules are
//! allow-only and apply to a whole tree, so a writable home directory cannot exclude the shell
//! startup file in it; refusing the policy is the only way to keep the guarantee.
//!
//! The directories on sandy's PATH and the usual ones of the user's PATH are the same kind of
//! location, but rule 12 warns about them instead of refusing them (`path_locations`,
//! `plan::notes`).

use sandy_core::ProtectedPath;
use sandy_core::trust::{self, user_directories};

/// Files below the home directory that a session reads when it starts: PAM's variables and the
/// X session scripts (`.xsessionrc` is Debian's).
const SESSION_FILES: &[&str] = &[
    ".pam_environment",
    ".xprofile",
    ".xinitrc",
    ".xsession",
    ".xsessionrc",
];

/// Directories below the configuration directory: desktop autostart entries, systemd user units,
/// the variables of the session, and the scripts KDE Plasma sources at login (`env`), runs at
/// logout (`shutdown`) and runs at login from `autostart-scripts`.
const CONFIG_TREES: &[&str] = &[
    "autostart",
    "systemd",
    "environment.d",
    "plasma-workspace/env",
    "plasma-workspace/shutdown",
    "autostart-scripts",
];

/// Directories below the data directory: systemd user units, and the desktop entries that say
/// which program opens a file.
const DATA_TREES: &[&str] = &["systemd", "applications"];

/// Where the files are that other programs of this user read or execute. A writable path that
/// reaches one of them is refused, and so is every writable path when no source names the home
/// directory (`sandy_core::trust::home_directories`).
pub fn locations() -> Result<Vec<ProtectedPath>, String> {
    let homes = trust::home_directories()?;
    let mut platform = Vec::new();
    for home in &homes {
        platform.extend(
            SESSION_FILES
                .iter()
                .map(|name| ProtectedPath::entry(home.join(name))),
        );
    }
    for config in user_directories("XDG_CONFIG_HOME", &homes, ".config") {
        platform.extend(
            CONFIG_TREES
                .iter()
                .map(|name| ProtectedPath::tree(config.join(name))),
        );
    }
    for data in user_directories("XDG_DATA_HOME", &homes, ".local/share") {
        platform.extend(
            DATA_TREES
                .iter()
                .map(|name| ProtectedPath::tree(data.join(name))),
        );
    }
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
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The home directory of this user is protected, and so are the startup files in it, also
    /// those that do not exist on this host.
    #[test]
    fn the_locations_cover_the_home_directory_of_this_user() {
        let Ok(locations) = locations() else {
            // A host without a password database entry and without HOME.
            return;
        };
        let home = trust::home_directories().unwrap().remove(0);
        let holds = |path: &std::path::Path| locations.iter().any(|entry| entry.path == path);
        assert!(holds(&home), "{locations:?}");
        assert!(holds(&home.join(".bashrc")), "{locations:?}");
        assert!(holds(&home.join(".config/autostart")), "{locations:?}");
        assert!(
            holds(&home.join(".config/plasma-workspace/env")),
            "{locations:?}"
        );
        assert!(holds(&home.join(".xsessionrc")), "{locations:?}");
        assert!(holds(&home.join(".ssh")), "{locations:?}");
        // Only the home directory itself, so a writable directory below it keeps working.
        let home_entry = locations.iter().find(|entry| entry.path == home).unwrap();
        assert!(!home_entry.subtree);
    }

    /// The directories of PATH are in the set that warns and in no other
    /// (`sandy_core::trust::path_locations` checks which others join them).
    #[test]
    fn the_directories_on_path_are_only_warned_about() {
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let refused = locations().unwrap_or_default();
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
