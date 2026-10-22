//! Names sandy passes to the AppContainer API: the AppContainer name from the policy, and the
//! names of the capabilities that carry the file grants.

use sandy_core::PathAccess;

/// `CreateAppContainerProfile`: "This string can be up to 64 characters in length. Further, it
/// must fit into the pattern described by the regular expression `[-_. A-Za-z0-9]+`."
pub const MAX_APPCONTAINER_NAME: usize = 64;

/// Checks an AppContainer name against the documented rules. sandy enforces them for
/// `DeriveAppContainerSidFromAppContainerName` too, so a name works with every AppContainer API.
pub fn validate_appcontainer_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the AppContainer name is empty".into());
    }
    if name.chars().count() > MAX_APPCONTAINER_NAME {
        return Err(format!(
            "the AppContainer name {name:?} is longer than {MAX_APPCONTAINER_NAME} characters"
        ));
    }
    if let Some(c) = name
        .chars()
        .find(|&c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ')))
    {
        return Err(format!(
            "the AppContainer name {name:?} contains {c:?}; allowed are A-Z, a-z, 0-9, '-', '_', '.' and space"
        ));
    }
    Ok(())
}

/// Identity of a file system object: volume serial number and file ID (`FILE_ID_INFO`). Unlike a
/// path, it stays with the object when the object is renamed or another object takes its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume: u64,
    pub file: u128,
}

/// The name of the capability that carries the grant of `access` on one object for one
/// AppContainer.
///
/// sandy grants file access to this capability's SID, not to the AppContainer SID, and starts the
/// program with the capabilities of the current policy only. A grant that an older policy needed
/// stays on disk, but no later process holds its capability, so it grants nothing. Concurrent
/// runs therefore never need to remove grants, and a path removed from the policy is denied at
/// the next run.
pub fn grant_capability_name(
    appcontainer: &str,
    access: PathAccess,
    object: FileIdentity,
) -> String {
    let level = match access {
        PathAccess::Read => "r",
        PathAccess::ReadExec => "rx",
        PathAccess::ReadWrite => "rw",
    };
    format!(
        "sandy.grant.{level}.{:016x}.{:032x}.{appcontainer}",
        object.volume, object.file
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_documented_characters() {
        for name in ["a", "example.app", "My App-1_2", &"x".repeat(64)] {
            assert_eq!(validate_appcontainer_name(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn rejects_other_names() {
        for name in ["", &"x".repeat(65), "a/b", "a\\b", "ä", "a:b", "a\0"] {
            assert!(validate_appcontainer_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn capability_names_separate_level_object_and_container() {
        let object = FileIdentity { volume: 1, file: 2 };
        let other = FileIdentity { volume: 1, file: 3 };
        let names = [
            grant_capability_name("a", PathAccess::Read, object),
            grant_capability_name("a", PathAccess::ReadWrite, object),
            grant_capability_name("a", PathAccess::Read, other),
            grant_capability_name("b", PathAccess::Read, object),
        ];
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(
            names[0],
            "sandy.grant.r.0000000000000001.00000000000000000000000000000002.a"
        );
    }
}
