//! Names sandy passes to the AppContainer API: the AppContainer name from the policy, and the
//! names of the capabilities that carry the file grants.

use sandy_core::PathAccess;

/// `CreateAppContainerProfile`: "This string can be up to 64 characters in length. Further, it
/// must fit into the pattern described by the regular expression `[-_. A-Za-z0-9]+`."
pub const MAX_APPCONTAINER_NAME: usize = 64;

/// The suffix that `egress_broker_name` adds to the program's AppContainer name. A program may
/// not use a name ending in it, so the egress broker, which holds network capabilities, always
/// runs in a sandbox of its own and never one a program shares.
pub const EGRESS_BROKER_SUFFIX: &str = ".sandy-egress";

/// The AppContainer name of the egress broker for a program whose AppContainer is `name`: `name`
/// plus `EGRESS_BROKER_SUFFIX`. It differs from every name a program may use, so the broker never
/// shares a sandbox with a program. Fails when the result would be longer than Windows allows;
/// the fix is a shorter `appcontainer_name`.
pub fn egress_broker_name(name: &str) -> Result<String, String> {
    let broker = format!("{name}{EGRESS_BROKER_SUFFIX}");
    if broker.chars().count() > MAX_APPCONTAINER_NAME {
        return Err(format!(
            "the egress broker needs the AppContainer name {broker:?}, which is longer than \
             {MAX_APPCONTAINER_NAME} characters; with network.egress use an appcontainer_name of \
             at most {} characters",
            MAX_APPCONTAINER_NAME - EGRESS_BROKER_SUFFIX.chars().count()
        ));
    }
    Ok(broker)
}

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
    // Windows strips a trailing period or space from a path component, and `.` and `..` name
    // other directories, so such a name and the folder it reaches are not the same thing.
    if name.starts_with(' ') || name.ends_with(' ') || name.ends_with('.') {
        return Err(format!(
            "the AppContainer name {name:?} starts or ends with a space or ends with a period; \
             Windows drops those from a path, so the name would not match its folder"
        ));
    }
    if name.chars().all(|c| c == '.') {
        return Err(format!(
            "the AppContainer name {name:?} is made of periods only, which names a directory"
        ));
    }
    // An AppContainer SID ignores case, so reserve the broker suffix in either case.
    if name.to_ascii_lowercase().ends_with(EGRESS_BROKER_SUFFIX) {
        return Err(format!(
            "the AppContainer name {name:?} ends with {EGRESS_BROKER_SUFFIX:?}, which sandy \
             reserves for the egress broker's own sandbox; use another name"
        ));
    }
    if let Some(publisher) = package_family_publisher(name) {
        return Err(format!(
            "the AppContainer name {name:?} is shaped like the family name of an installed \
             application package ({publisher:?} looks like a publisher ID). An AppContainer SID \
             is derived from the name, so such a name would be the identity of that package: \
             sandy would change the permissions of its folder and share its sandbox. Use a name \
             without a 13 character suffix after an underscore"
        ));
    }
    Ok(())
}

/// The publisher ID of `name` read as a package family name, `Publisher.App_<13 characters>`.
/// Microsoft derives a package SID from the family name the same way sandy's AppContainer SID is
/// derived from its name, so a collision is one identity for two things.
fn package_family_publisher(name: &str) -> Option<&str> {
    let (app, publisher) = name.rsplit_once('_')?;
    let shaped = !app.is_empty()
        && publisher.len() == 13
        && publisher
            .chars()
            .all(|c| PUBLISHER_ID_ALPHABET.contains(c.to_ascii_lowercase()));
    shaped.then_some(publisher)
}

/// The characters of a publisher ID, a hash of the publisher in Crockford's base32, which has no
/// i, l, o or u. A suffix with one of them cannot be a publisher ID.
const PUBLISHER_ID_ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";

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

    /// Names that Windows and sandy would not read as the same thing.
    #[test]
    fn rejects_ambiguous_and_package_shaped_names() {
        for name in ["a.", " a", "a ", ".", "..", "..."] {
            assert!(validate_appcontainer_name(name).is_err(), "{name:?}");
        }
        for name in [
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
            "MICROSOFT.WINDOWSCALCULATOR_8WEKYB3D8BBWE",
        ] {
            assert!(validate_appcontainer_name(name).is_err(), "{name:?}");
        }
        // A short suffix after an underscore is not a publisher ID, and neither is one with a
        // letter that the alphabet of publisher IDs lacks; sandy 1.3.2 accepted both.
        assert_eq!(validate_appcontainer_name("My App-1_2"), Ok(()));
        assert_eq!(validate_appcontainer_name(".hidden"), Ok(()));
        for name in [
            "acme_productionenv",
            "sandy_windowsrunner",
            "CI_INTEGRATIONS1",
        ] {
            assert_eq!(validate_appcontainer_name(name), Ok(()), "{name}");
        }
        // Family names of installed packages, as Windows lists them.
        for name in [
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
            "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy",
            "Mozilla.Firefox_n80bbvh6b1yt2",
            "PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0",
        ] {
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

    #[test]
    fn the_broker_name_adds_the_reserved_suffix_and_is_refused_as_a_program_name() {
        assert_eq!(
            egress_broker_name("example.app"),
            Ok("example.app.sandy-egress".to_string())
        );
        // A program may not use a name that ends with the suffix, in either case, so it never
        // shares the broker's sandbox.
        for name in ["example.app.sandy-egress", "EXAMPLE.APP.SANDY-EGRESS"] {
            assert!(validate_appcontainer_name(name).is_err(), "{name}");
        }
        // The broker name itself is still a valid AppContainer name for the API.
        let broker = egress_broker_name("example.app").unwrap();
        assert!(broker.chars().count() <= MAX_APPCONTAINER_NAME);
    }

    #[test]
    fn the_broker_name_fails_when_it_would_be_too_long() {
        let longest = MAX_APPCONTAINER_NAME - EGRESS_BROKER_SUFFIX.chars().count();
        assert!(egress_broker_name(&"a".repeat(longest)).is_ok());
        assert!(egress_broker_name(&"a".repeat(longest + 1)).is_err());
    }
}
