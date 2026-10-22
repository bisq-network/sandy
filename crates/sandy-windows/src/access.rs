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
    let on_object = evaluate(aces, sid, mask, |ace| ace.flags & INHERIT_ONLY_ACE == 0);
    if !is_dir {
        return on_object;
    }
    let inherited_by = |bit: u8| {
        move |ace: &Ace<'_>| ace.flags & bit != 0 && ace.flags & NO_PROPAGATE_INHERIT_ACE == 0
    };
    on_object
        && evaluate(aces, sid, mask, inherited_by(OBJECT_INHERIT_ACE))
        && evaluate(aces, sid, mask, inherited_by(CONTAINER_INHERIT_ACE))
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
/// yet ends the check.
fn evaluate(aces: &[Ace<'_>], sid: &[u8], mask: u32, applies: impl Fn(&Ace<'_>) -> bool) -> bool {
    let mut granted = 0;
    for ace in aces.iter().filter(|ace| ace.sid == sid && applies(ace)) {
        let rights = map_generic(ace.mask);
        match ace.kind {
            AceKind::Allow => granted |= rights,
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
fn map_generic(mask: u32) -> u32 {
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
}
