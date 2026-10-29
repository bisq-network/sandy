//! File access rights that sandy grants on policy paths, and a small evaluator of access control
//! entries (ACEs).
//!
//! The constants carry the values of `winnt.h`. On Windows, a test in `sys` compares them with
//! the `windows-sys` definitions.

use sandy_core::PathAccess;

pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
/// On a directory the same bit is `FILE_TRAVERSE`.
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_DELETE_CHILD: u32 = 0x0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const FILE_GENERIC_READ: u32 =
    READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
pub const FILE_GENERIC_WRITE: u32 = READ_CONTROL
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
pub const FILE_GENERIC_EXECUTE: u32 =
    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;
pub const FILE_ALL_ACCESS: u32 =
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE | 0x1FF;

pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;

/// `S-1-15-2-1`, APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES, in binary form. Every
/// AppContainer process that is not a Less Privileged AppContainer is a member.
pub const ALL_APPLICATION_PACKAGES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0];

/// `S-1-15-2-2`, ALL RESTRICTED APPLICATION PACKAGES: what Windows grants it, it grants Less
/// Privileged AppContainers as well as all others.
pub const ALL_RESTRICTED_APPLICATION_PACKAGES: &[u8] =
    &[1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 2, 0, 0, 0];

/// The rights sandy grants on a policy path. Read and read-write never contain `FILE_EXECUTE`,
/// so the loader cannot map a file from these paths as a program or library. Neither level
/// contains `WRITE_DAC` or `WRITE_OWNER`, so the program cannot widen its own access.
pub fn access_mask(access: PathAccess) -> u32 {
    match access {
        PathAccess::Read => FILE_GENERIC_READ,
        PathAccess::ReadExec => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        PathAccess::ReadWrite => {
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD
        }
    }
}

/// Rights the AppContainer must not keep on its profile folder. Execute would let the program
/// run what it writes there; `WRITE_DAC` and `WRITE_OWNER` would let it grant execute back.
/// Windows creates the folder with `FILE_ALL_ACCESS`, which contains all three.
pub const PROFILE_DENIED: u32 = FILE_EXECUTE | WRITE_DAC | WRITE_OWNER;

/// ACE flags of a grant. A rule applies to everything beneath a directory, so the ACE on a
/// directory is inherited by files and subdirectories.
pub fn ace_flags(is_dir: bool) -> u8 {
    if is_dir {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceKind {
    Allow,
    /// An allow entry with a condition (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`), whose condition
    /// sandy does not evaluate. It counts where counting it refuses something (`may_grant`) and
    /// not where it would let sandy skip a grant (`grants`), so either way sandy errs towards
    /// less access.
    ConditionalAllow,
    Deny,
}

/// One ACE of a discretionary access control list (DACL), reduced to what the evaluator needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ace<'a> {
    pub kind: AceKind,
    pub flags: u8,
    pub mask: u32,
    /// Binary SID.
    pub sid: &'a [u8],
}

/// Whether `aces` grant every right of `mask` to `sid` on the object itself and, for a directory,
/// on all files and directories that inherit from it.
///
/// Only ACEs for `sid` count. The result is meant for skipping a grant that Windows already
/// gives, so an error towards "not granted" only causes a redundant grant.
pub fn grants(aces: &[Ace<'_>], sid: &[u8], mask: u32, is_dir: bool) -> bool {
    let evaluate = |applies: &dyn Fn(&Ace<'_>) -> bool| evaluate(aces, sid, mask, false, applies);
    let on_object = evaluate(&|ace: &Ace<'_>| ace.flags & INHERIT_ONLY_ACE == 0);
    if !is_dir {
        return on_object;
    }
    let inherited_by = |bit: u8| {
        move |ace: &Ace<'_>| ace.flags & bit != 0 && ace.flags & NO_PROPAGATE_INHERIT_ACE == 0
    };
    on_object
        && evaluate(&inherited_by(OBJECT_INHERIT_ACE))
        && evaluate(&inherited_by(CONTAINER_INHERIT_ACE))
}

/// Whether `aces` may give `sid` `right` on the object itself or, for a directory, on a file or
/// directory created in it. Unlike `grants`, one way suffices: the result is meant for refusing
/// a writable path whose files an AppContainer could execute, so an error towards "granted" only
/// refuses a policy.
pub fn may_grant(aces: &[Ace<'_>], sid: &[u8], right: u32, is_dir: bool) -> bool {
    let evaluate = |applies: &dyn Fn(&Ace<'_>) -> bool| evaluate(aces, sid, right, true, applies);
    let on_object = evaluate(&|ace: &Ace<'_>| ace.flags & INHERIT_ONLY_ACE == 0);
    if on_object || !is_dir {
        return on_object;
    }
    // NO_PROPAGATE_INHERIT_ACE still reaches the direct children, so it counts here.
    let inherited_by = |bit: u8| move |ace: &Ace<'_>| ace.flags & bit != 0;
    evaluate(&inherited_by(OBJECT_INHERIT_ACE)) || evaluate(&inherited_by(CONTAINER_INHERIT_ACE))
}

/// Whether `aces` contain the ACE sandy adds: explicit (not inherited), allow, exactly `mask` and
/// `flags`.
pub fn has_explicit_ace(aces: &[Ace<'_>], sid: &[u8], mask: u32, flags: u8) -> bool {
    aces.iter().any(|ace| {
        ace.kind == AceKind::Allow
            && ace.sid == sid
            && ace.mask == mask
            && ace.flags & !INHERITED_ACE == flags
            && ace.flags & INHERITED_ACE == 0
    })
}

/// Evaluates the ACEs in order, like the access check: a deny ACE that hits a right not granted
/// yet ends the check. `conditional` says whether an allow entry with a condition counts as
/// granting; the caller picks the answer that errs towards less access.
fn evaluate(
    aces: &[Ace<'_>],
    sid: &[u8],
    mask: u32,
    conditional: bool,
    applies: &dyn Fn(&Ace<'_>) -> bool,
) -> bool {
    let mut granted = 0;
    for ace in aces.iter().filter(|ace| ace.sid == sid && applies(ace)) {
        let rights = map_generic(ace.mask);
        match ace.kind {
            AceKind::Allow => granted |= rights,
            AceKind::ConditionalAllow if conditional => granted |= rights,
            AceKind::ConditionalAllow => {}
            AceKind::Deny if rights & mask & !granted != 0 => return false,
            AceKind::Deny => {}
        }
        if granted & mask == mask {
            return true;
        }
    }
    false
}

/// Maps generic rights with the generic mapping of files. Inheritable ACEs often carry generic
/// rights, for example `(OI)(CI)(IO)(GR,GE)`.
pub fn map_generic(mask: u32) -> u32 {
    let mut mapped = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    for (generic, specific) in [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (GENERIC_ALL, FILE_ALL_ACCESS),
    ] {
        if mask & generic != 0 {
            mapped |= specific;
        }
    }
    mapped
}

/// `S-1-5-18`, NT AUTHORITY\SYSTEM.
pub const LOCAL_SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
/// `S-1-5-32-544`, BUILTIN\Administrators.
pub const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
/// `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`, NT
/// SERVICE\TrustedInstaller, which owns the files of Windows itself.
pub const TRUSTED_INSTALLER: &[u8] = &[
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 181, 137, 251, 56, 25, 132, 194, 203, 92, 108, 35, 109,
    87, 0, 119, 110, 192, 2, 100, 135,
];
/// `S-1-3-4`, OWNER RIGHTS: an entry for whoever owns the object.
pub const OWNER_RIGHTS: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

/// The identities that only administrators control.
const ADMINISTRATIVE: [&[u8]; 3] = [LOCAL_SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

/// The rights on a program file that change what runs when it starts: its data and extended
/// attributes, deleting it, and its DACL and owner.
pub const CHANGES_FILE: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER;
/// The rights on a directory that replace an entry in it or the directory itself.
pub const REPLACES_ENTRY: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
/// `REPLACES_ENTRY` and adding an entry, on the directory that holds a program: Windows looks
/// for the program's libraries there first.
pub const ADDS_LIBRARY: u32 = REPLACES_ENTRY | FILE_WRITE_DATA | FILE_APPEND_DATA;

/// Who other than administrators can use `rights` on an object owned by `owner` with the DACL
/// `aces`, as an SID in string form, `None` when no one can. The owner counts as holding every
/// right, since it may rewrite the DACL. An allow entry counts whether or not it has a
/// condition, and deny entries are ignored, so the answer errs towards "someone can".
pub fn changeable_by_others(owner: &[u8], aces: &[Ace<'_>], rights: u32) -> Option<String> {
    if !ADMINISTRATIVE.contains(&owner) {
        return Some(sid_string(owner));
    }
    aces.iter()
        .filter(|ace| ace.kind != AceKind::Deny && ace.flags & INHERIT_ONLY_ACE == 0)
        .filter(|ace| map_generic(ace.mask) & rights != 0)
        // OWNER RIGHTS names the owner, which is administrative here.
        .find(|ace| !ADMINISTRATIVE.contains(&ace.sid) && ace.sid != OWNER_RIGHTS)
        .map(|ace| sid_string(ace.sid))
}

/// A binary SID in the `S-1-...` form.
pub fn sid_string(sid: &[u8]) -> String {
    if sid.len() < 8 {
        return "a malformed SID".to_string();
    }
    let authority = sid[2..8]
        .iter()
        .fold(0u64, |value, &byte| value << 8 | u64::from(byte));
    let mut text = format!("S-{}-{authority}", sid[0]);
    let (subauthorities, _) = sid[8..].as_chunks::<4>();
    for subauthority in subauthorities.iter().take(usize::from(sid[1])) {
        text.push_str(&format!("-{}", u32::from_le_bytes(*subauthority)));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const RX: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

    fn allow(flags: u8, mask: u32, sid: &[u8]) -> Ace<'_> {
        Ace {
            kind: AceKind::Allow,
            flags,
            mask,
            sid,
        }
    }

    fn deny(flags: u8, mask: u32, sid: &[u8]) -> Ace<'_> {
        Ace {
            kind: AceKind::Deny,
            ..allow(flags, mask, sid)
        }
    }

    fn conditional(flags: u8, mask: u32, sid: &[u8]) -> Ace<'_> {
        Ace {
            kind: AceKind::ConditionalAllow,
            ..allow(flags, mask, sid)
        }
    }

    /// An entry whose condition sandy cannot read counts where it refuses and not where it
    /// would let sandy skip a grant.
    #[test]
    fn a_conditional_entry_refuses_but_never_satisfies() {
        let aces = [conditional(
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            RX,
            ALL_APPLICATION_PACKAGES,
        )];
        assert!(may_grant(
            &aces,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            true
        ));
        assert!(!grants(&aces, ALL_APPLICATION_PACKAGES, RX, true));
    }

    #[test]
    fn read_and_read_write_never_execute() {
        for access in [PathAccess::Read, PathAccess::ReadWrite] {
            let mask = access_mask(access);
            assert_eq!(mask & FILE_EXECUTE, 0, "{access:?}");
            assert_eq!(mask & (GENERIC_EXECUTE | GENERIC_ALL), 0, "{access:?}");
        }
    }

    #[test]
    fn read_levels_cannot_change_metadata() {
        for access in [PathAccess::Read, PathAccess::ReadExec] {
            let mask = access_mask(access);
            for right in [WRITE_DAC, WRITE_OWNER, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA] {
                assert_eq!(mask & right, 0, "{access:?} {right:#x}");
            }
        }
    }

    #[test]
    fn no_level_can_change_permissions_or_owner() {
        for access in [
            PathAccess::Read,
            PathAccess::ReadExec,
            PathAccess::ReadWrite,
        ] {
            assert_eq!(access_mask(access) & (WRITE_DAC | WRITE_OWNER), 0);
        }
    }

    #[test]
    fn levels_grant_what_their_names_say() {
        assert_eq!(access_mask(PathAccess::Read), 0x0012_0089);
        assert_eq!(access_mask(PathAccess::ReadExec), 0x0012_00A9);
        let read_write = access_mask(PathAccess::ReadWrite);
        assert_eq!(read_write, 0x0013_01DF);
        for right in [FILE_WRITE_DATA, FILE_APPEND_DATA, DELETE, FILE_DELETE_CHILD] {
            assert_ne!(read_write & right, 0);
        }
        assert_eq!(access_mask(PathAccess::Read) & FILE_WRITE_DATA, 0);
        assert_eq!(access_mask(PathAccess::ReadExec) & FILE_WRITE_DATA, 0);
    }

    /// What stays of the profile folder entry Windows creates: exactly the read-write rights,
    /// so the program keeps its scratch space but can neither run what it writes there nor give
    /// itself execute back.
    #[test]
    fn reducing_the_profile_entry_leaves_the_read_write_rights() {
        assert_eq!(
            FILE_ALL_ACCESS & !PROFILE_DENIED,
            access_mask(PathAccess::ReadWrite)
        );
        // An entry that lost only FILE_EXECUTE keeps WRITE_DAC and WRITE_OWNER, so it still
        // needs reducing.
        assert_ne!((FILE_ALL_ACCESS & !FILE_EXECUTE) & PROFILE_DENIED, 0);
    }

    #[test]
    fn directories_inherit_files_do_not() {
        assert_eq!(ace_flags(true), OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        assert_eq!(ace_flags(false), 0);
    }

    #[test]
    fn system_directory_acl_grants_read_execute() {
        // The ALL APPLICATION PACKAGES entries of C:\Program Files: (RX) and (OI)(CI)(IO)(GR,GE).
        let aces = [
            allow(0, RX, ALL_APPLICATION_PACKAGES),
            allow(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
                GENERIC_READ | GENERIC_EXECUTE,
                ALL_APPLICATION_PACKAGES,
            ),
        ];
        assert!(grants(&aces, ALL_APPLICATION_PACKAGES, RX, true));
        assert!(!grants(
            &aces,
            ALL_APPLICATION_PACKAGES,
            access_mask(PathAccess::ReadWrite),
            true
        ));
    }

    #[test]
    fn directory_grant_must_reach_descendants() {
        let aces = [allow(0, RX, ALL_APPLICATION_PACKAGES)];
        assert!(grants(&aces, ALL_APPLICATION_PACKAGES, RX, false));
        assert!(!grants(&aces, ALL_APPLICATION_PACKAGES, RX, true));

        let only_children = [allow(
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            RX,
            ALL_APPLICATION_PACKAGES,
        )];
        assert!(!grants(&only_children, ALL_APPLICATION_PACKAGES, RX, true));
    }

    #[test]
    fn inherit_only_entries_do_not_apply_to_the_object() {
        let aces = [allow(
            INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
            RX,
            ALL_APPLICATION_PACKAGES,
        )];
        assert!(!grants(&aces, ALL_APPLICATION_PACKAGES, RX, false));
    }

    #[test]
    fn deny_before_allow_wins() {
        let aces = [
            deny(0, FILE_EXECUTE, ALL_APPLICATION_PACKAGES),
            allow(0, RX, ALL_APPLICATION_PACKAGES),
        ];
        assert!(!grants(&aces, ALL_APPLICATION_PACKAGES, RX, false));
        assert!(grants(
            &aces,
            ALL_APPLICATION_PACKAGES,
            FILE_GENERIC_READ,
            false
        ));
    }

    #[test]
    fn deny_after_full_grant_is_ignored() {
        let aces = [
            allow(0, RX, ALL_APPLICATION_PACKAGES),
            deny(0, FILE_EXECUTE, ALL_APPLICATION_PACKAGES),
        ];
        assert!(grants(&aces, ALL_APPLICATION_PACKAGES, RX, false));
    }

    #[test]
    fn entries_for_other_sids_do_not_count() {
        let aces = [allow(
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS,
            OTHER,
        )];
        assert!(!grants(&aces, ALL_APPLICATION_PACKAGES, RX, true));
    }

    #[test]
    fn partial_grants_add_up() {
        let aces = [
            allow(0, FILE_GENERIC_READ, ALL_APPLICATION_PACKAGES),
            allow(0, FILE_EXECUTE, ALL_APPLICATION_PACKAGES),
        ];
        assert!(grants(&aces, ALL_APPLICATION_PACKAGES, RX, false));
    }

    #[test]
    fn finds_only_the_exact_explicit_entry() {
        let flags = ace_flags(true);
        let mask = access_mask(PathAccess::Read);
        assert!(has_explicit_ace(
            &[allow(flags, mask, OTHER)],
            OTHER,
            mask,
            flags
        ));
        assert!(!has_explicit_ace(
            &[allow(flags | INHERITED_ACE, mask, OTHER)],
            OTHER,
            mask,
            flags
        ));
        assert!(!has_explicit_ace(
            &[allow(flags, RX, OTHER)],
            OTHER,
            mask,
            flags
        ));
        assert!(!has_explicit_ace(
            &[allow(0, mask, OTHER)],
            OTHER,
            mask,
            flags
        ));
        assert!(!has_explicit_ace(
            &[deny(flags, mask, OTHER)],
            OTHER,
            mask,
            flags
        ));
    }
    /// C:\Program Files gives ALL APPLICATION PACKAGES read and execute on everything created
    /// in it; a writable path below it must be refused.
    #[test]
    fn may_grant_finds_execute_for_new_files() {
        let program_files = [
            allow(0, RX, ALL_APPLICATION_PACKAGES),
            allow(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
                GENERIC_READ | GENERIC_EXECUTE,
                ALL_APPLICATION_PACKAGES,
            ),
        ];
        assert!(may_grant(
            &program_files,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            true
        ));
        // Inherited by new files only, or only by the direct children.
        let files_only = [allow(
            OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE | NO_PROPAGATE_INHERIT_ACE,
            GENERIC_EXECUTE,
            ALL_APPLICATION_PACKAGES,
        )];
        assert!(may_grant(
            &files_only,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            true
        ));
        // A file: only its own ACEs count; inheritance flags mean nothing there.
        assert!(!may_grant(
            &files_only,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            false
        ));
        // Read only, another SID, or a deny before the allow: no execute.
        let read_only = [allow(
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_GENERIC_READ,
            ALL_APPLICATION_PACKAGES,
        )];
        assert!(!may_grant(
            &read_only,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            true
        ));
        assert!(!may_grant(&program_files, OTHER, FILE_EXECUTE, true));
        let denied = [
            deny(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_EXECUTE,
                ALL_APPLICATION_PACKAGES,
            ),
            allow(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                RX,
                ALL_APPLICATION_PACKAGES,
            ),
        ];
        assert!(!may_grant(
            &denied,
            ALL_APPLICATION_PACKAGES,
            FILE_EXECUTE,
            true
        ));
    }

    const USERS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
    const AUTHENTICATED_USERS: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
    /// `S-1-5-21-1-2-3-1001`, a user.
    const USER: &[u8] = &[
        1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 233, 3, 0, 0,
    ];

    #[test]
    fn sids_read_as_strings() {
        assert_eq!(sid_string(ADMINISTRATORS), "S-1-5-32-544");
        assert_eq!(
            sid_string(TRUSTED_INSTALLER),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert_eq!(sid_string(USER), "S-1-5-21-1-2-3-1001");
        assert_eq!(sid_string(OWNER_RIGHTS), "S-1-3-4");
    }

    /// A file below Program Files: owned by an administrative identity, which alone may write;
    /// everyone else may read and execute.
    #[test]
    fn an_installed_program_only_administrators_can_change() {
        let aces = [
            allow(INHERITED_ACE, FILE_ALL_ACCESS, ADMINISTRATORS),
            allow(INHERITED_ACE, FILE_ALL_ACCESS, LOCAL_SYSTEM),
            allow(INHERITED_ACE, FILE_ALL_ACCESS, TRUSTED_INSTALLER),
            allow(INHERITED_ACE, RX, USERS),
            allow(INHERITED_ACE, RX, ALL_APPLICATION_PACKAGES),
            allow(0, FILE_ALL_ACCESS, OWNER_RIGHTS),
            // A deny entry takes nothing away from the answer, and grants nothing.
            deny(0, FILE_ALL_ACCESS, USER),
        ];
        for owner in [TRUSTED_INSTALLER, ADMINISTRATORS, LOCAL_SYSTEM] {
            assert_eq!(changeable_by_others(owner, &aces, CHANGES_FILE), None);
        }
        // An administrator's own account is not enough: its processes without elevation hold
        // its SID too.
        assert_eq!(
            changeable_by_others(USER, &aces, CHANGES_FILE).as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
    }

    #[test]
    fn any_right_that_changes_the_file_is_enough() {
        for mask in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            for ace in [allow(0, mask, USER), conditional(0, mask, USER)] {
                assert_eq!(
                    changeable_by_others(ADMINISTRATORS, &[ace], CHANGES_FILE).as_deref(),
                    Some("S-1-5-21-1-2-3-1001"),
                    "{mask:#x}"
                );
            }
        }
        // Attributes and timestamps leave the program as it is.
        let attributes = [allow(0, FILE_WRITE_ATTRIBUTES | RX, USER)];
        assert_eq!(
            changeable_by_others(ADMINISTRATORS, &attributes, CHANGES_FILE),
            None
        );
    }

    /// The root of a system drive lets every user create folders in it, and gives a creator's
    /// folders to the creator through an entry that applies only to what it inherits to. That
    /// replaces nothing above sandy, but it would add a library next to a program in that
    /// directory.
    #[test]
    fn a_directory_above_may_take_new_entries_the_one_holding_sandy_may_not() {
        let root = [
            allow(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                ADMINISTRATORS,
            ),
            allow(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, RX, USERS),
            allow(
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
                GENERIC_ALL,
                AUTHENTICATED_USERS,
            ),
            allow(0, FILE_APPEND_DATA, AUTHENTICATED_USERS),
        ];
        assert_eq!(
            changeable_by_others(TRUSTED_INSTALLER, &root, REPLACES_ENTRY),
            None
        );
        assert_eq!(
            changeable_by_others(TRUSTED_INSTALLER, &root, ADDS_LIBRARY).as_deref(),
            Some("S-1-5-11")
        );
        let deletes = [allow(0, FILE_DELETE_CHILD, USERS)];
        assert!(changeable_by_others(ADMINISTRATORS, &deletes, REPLACES_ENTRY).is_some());
    }
}
