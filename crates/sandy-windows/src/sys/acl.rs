//! File grants for the AppContainer: one access control entry (ACE) per policy path, for a
//! capability that names the path's object and access level (see `name::grant_capability_name`).

use std::fs;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use sandy_core::{PathAccess, PathRule, SandboxError};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
    WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

use super::host;
use super::util::{LocalBox, SessionLock, Sid, last_error, wide_nul, win32_error};
use crate::access::{
    ALL_APPLICATION_PACKAGES, ALL_RESTRICTED_APPLICATION_PACKAGES, Ace, AceKind,
    CONTAINER_INHERIT_ACE, FILE_EXECUTE, INHERITED_ACE, OBJECT_INHERIT_ACE, access_mask, ace_flags,
    grants, has_explicit_ace, may_grant,
};
use crate::name::{FileIdentity, grant_capability_name};

/// Makes sure the AppContainer can use `rule.path` at `rule.access` and returns the capability
/// the target must hold for it. Changes nothing when the grant is already in place.
pub fn grant(appcontainer: &str, rule: &PathRule) -> Result<Sid, SandboxError> {
    check_writable(rule).map_err(SandboxError::new)?;
    let path = wide_nul(rule.path.as_os_str());
    let capability = grant_capability(appcontainer, rule, &path)?;
    if !lacks_grant(rule, &capability, &Dacl::read(&path, &rule.path)?)? {
        return Ok(capability);
    }
    // A change reads the DACL, adds one ACE and writes the whole DACL back. Without the lock,
    // two runs that add different ACEs to the same object at the same time could each overwrite
    // the ACE of the other. If a run died while it held the lock during propagation, some
    // children may lack the inherited ACE, which denies access, never grants it.
    let _lock = SessionLock::acquire(r"Local\sandy-dacl-changes")?;
    // Another run may have changed the DACL while this one waited for the lock.
    let dacl = Dacl::read(&path, &rule.path)?;
    if lacks_grant(rule, &capability, &dacl)? {
        if rule.is_dir {
            refuse_links_below(&rule.path)?;
        }
        add_ace(
            &path,
            &rule.path,
            &dacl,
            &capability,
            access_mask(rule.access),
            ace_flags(rule.is_dir),
        )?;
    }
    Ok(capability)
}

/// Refuses a writable path where Windows lets every AppContainer execute files: on the path
/// itself, or on files and directories created in it, as below `C:\Program Files`. The program
/// could write a program there and run it (DESIGN.md rules 3 and 6). Changes nothing.
pub fn check_writable(rule: &PathRule) -> Result<(), String> {
    if rule.access != PathAccess::ReadWrite {
        return Ok(());
    }
    let path = wide_nul(rule.path.as_os_str());
    let aces = Dacl::read(&path, &rule.path)
        .and_then(|dacl| dacl.aces(&rule.path))
        .map_err(|error| error.to_string())?;
    if aces.has_unknown_types {
        return Err(format!(
            "the permissions of writable path {} contain entries that sandy cannot evaluate, so \
             it cannot tell whether AppContainers may execute files there",
            rule.path.display()
        ));
    }
    let entries = aces.entries();
    for (sid, group) in [
        (ALL_APPLICATION_PACKAGES, "ALL APPLICATION PACKAGES"),
        (
            ALL_RESTRICTED_APPLICATION_PACKAGES,
            "ALL RESTRICTED APPLICATION PACKAGES",
        ),
    ] {
        if may_grant(&entries, sid, FILE_EXECUTE, rule.is_dir) {
            return Err(format!(
                "Windows lets every AppContainer ({group}) execute files in writable path {}, so \
                 the program could write a program there and run it",
                rule.path.display()
            ));
        }
    }
    Ok(())
}

/// Whether `grant` would succeed for `rule`: the grant is in place, or the current user may
/// change the DACL. Changes nothing.
pub fn grantable(appcontainer: &str, rule: &PathRule) -> Result<(), String> {
    let path = wide_nul(rule.path.as_os_str());
    let in_place = grant_capability(appcontainer, rule, &path)
        .and_then(|capability| {
            lacks_grant(rule, &capability, &Dacl::read(&path, &rule.path)?).map(|lacks| !lacks)
        })
        .map_err(|error| error.to_string())?;
    if in_place {
        return Ok(());
    }
    // SAFETY: path is NUL-terminated; opening for WRITE_DAC only checks the right.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "the grant is missing, and the current user may not change the permissions: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: CreateFileW succeeded, so the handle is new; dropping it closes it.
    drop(unsafe { OwnedHandle::from_raw_handle(handle) });
    Ok(())
}

/// Allows `sid`, which the caller already holds as a capability, `mask` with `flags` on the
/// directory `path` that sandy created. Used for the socket directory of forwarded ports, which
/// only the relays may use.
pub fn allow(path: &Path, sid: &Sid, mask: u32, flags: u8) -> Result<(), SandboxError> {
    let wide = wide_nul(path.as_os_str());
    let _lock = SessionLock::acquire(r"Local\sandy-dacl-changes")?;
    let dacl = Dacl::read(&wide, path)?;
    // A NULL DACL would be replaced by one that grants only `sid`; refuse it like `grant` does.
    dacl.aces(path)?;
    set_access(&wide, path, &dacl, sid, mask, flags)
}

/// Removes `FILE_EXECUTE` from the AppContainer's access to its profile folder, so the program
/// cannot execute what it writes there.
///
/// Windows creates the folder (`...\Packages\<name>\AC`, which holds the program's `TEMP`) with
/// an inheritable allow ACE that grants the AppContainer SID `FILE_ALL`, including
/// `FILE_EXECUTE`. The folder is always present, persists across runs, and must stay writable
/// for data, so sandy cannot remove it. A deny ACE does not help: the AppContainer access check
/// ignores a deny ACE for the package SID (measured). sandy reduces the allow ACE instead, which
/// the access check does honor. `SetNamedSecurityInfoW` re-propagates the inheritable ACE, so
/// files the program wrote on an earlier run lose execute too.
///
/// Idempotent: it writes only while the AppContainer SID is still granted `FILE_EXECUTE`.
pub fn deny_execute_in_profile(appcontainer: &Sid, folder: &Path) -> Result<(), SandboxError> {
    let path = wide_nul(folder.as_os_str());
    // The union of the explicit allow masks for the AppContainer SID, when one grants execute.
    let allow_with_execute = |dacl: &Dacl| -> Result<Option<u32>, SandboxError> {
        let aces = dacl.aces(folder)?;
        let mut mask = 0u32;
        let mut grants_execute = false;
        for ace in aces.entries() {
            if ace.kind == AceKind::Allow
                && ace.flags & INHERITED_ACE == 0
                && ace.sid == appcontainer.bytes()
            {
                mask |= ace.mask;
                grants_execute |= ace.mask & FILE_EXECUTE != 0;
            }
        }
        Ok(grants_execute.then_some(mask))
    };

    if allow_with_execute(&Dacl::read(&path, folder)?)?.is_none() {
        return Ok(());
    }
    let _lock = SessionLock::acquire(r"Local\sandy-dacl-changes")?;
    let dacl = Dacl::read(&path, folder)?;
    if let Some(mask) = allow_with_execute(&dacl)? {
        set_access(
            &path,
            folder,
            &dacl,
            appcontainer,
            mask & !FILE_EXECUTE,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )?;
    }
    Ok(())
}

/// The capability that names the object at `path` and the access level of `rule`.
fn grant_capability(
    appcontainer: &str,
    rule: &PathRule,
    path: &[u16],
) -> Result<Sid, SandboxError> {
    let identity = file_identity(path, &rule.path)?;
    capability_sid(&grant_capability_name(appcontainer, rule.access, identity))
}

/// Whether `dacl` lacks what `rule` needs: an explicit ACE for `capability`, or a grant that
/// Windows gives every AppContainer.
fn lacks_grant(rule: &PathRule, capability: &Sid, dacl: &Dacl) -> Result<bool, SandboxError> {
    let mask = access_mask(rule.access);
    let aces = dacl.aces(&rule.path)?;
    let entries = aces.entries();
    if has_explicit_ace(&entries, capability.bytes(), mask, ace_flags(rule.is_dir)) {
        return Ok(false);
    }
    // Paths in the system set, such as the program C:\Windows\System32\cmd.exe, already
    // grant read and execute to every AppContainer, and the user usually cannot change their
    // ACL.
    let granted_by_windows = rule.access != PathAccess::ReadWrite
        && !aces.has_unknown_types
        && grants(&entries, ALL_APPLICATION_PACKAGES, mask, rule.is_dir);
    Ok(!granted_by_windows)
}

fn file_identity(path: &[u16], display: &Path) -> Result<FileIdentity, SandboxError> {
    // SAFETY: path is NUL-terminated; FILE_FLAG_BACKUP_SEMANTICS is required to open
    // directories and grants no extra rights to callers without the backup privilege.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error(format!("cannot open {}", display.display())));
    }
    // SAFETY: CreateFileW succeeded, so the handle is new and owned by nobody else.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: info is a writable FILE_ID_INFO and the size matches it.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error(format!(
            "cannot read the file ID of {}",
            display.display()
        )));
    }
    Ok(FileIdentity {
        volume: info.VolumeSerialNumber,
        file: u128::from_le_bytes(info.FileId.Identifier),
    })
}

/// The capability SID for `name` (`S-1-15-3-1024-...`).
fn capability_sid(name: &str) -> Result<Sid, SandboxError> {
    let wide = wide_nul(name.as_ref());
    let (mut groups, mut group_count): (*mut PSID, u32) = (ptr::null_mut(), 0);
    let (mut capabilities, mut capability_count): (*mut PSID, u32) = (ptr::null_mut(), 0);
    let derive = host::derive_capability_sids().map_err(SandboxError::new)?;
    // SAFETY: wide is NUL-terminated and all out pointers are valid.
    let ok = unsafe {
        derive(
            wide.as_ptr(),
            &mut groups,
            &mut group_count,
            &mut capabilities,
            &mut capability_count,
        )
    };
    if ok == 0 {
        return Err(last_error(format!("cannot derive the capability {name}")));
    }
    let sid = if capability_count == 1 {
        // SAFETY: the array holds one SID pointer from the function.
        unsafe { Sid::copy_from(*capabilities) }
            .map_err(|error| SandboxError::io(format!("capability {name}"), error))
    } else {
        Err(SandboxError::new(format!(
            "capability {name}: expected one SID, got {capability_count}"
        )))
    };
    // "The caller is expected to free the individual SIDs returned in each array by calling
    // LocalFree, as well as memory allocated for the array itself."
    for (array, count) in [(groups, group_count), (capabilities, capability_count)] {
        if array.is_null() {
            continue;
        }
        for i in 0..count as usize {
            // SAFETY: the function returned `count` SID pointers in the array.
            drop(LocalBox(unsafe { *array.add(i) }));
        }
        drop(LocalBox(array.cast()));
    }
    sid
}

/// Applying an inheritable ACE to a directory also changes every object below it. Whether this
/// propagation follows junctions and symbolic links is not documented. A program that could
/// write below the directory in an earlier run could have planted a link to a directory of the
/// user, which would then receive the grant. sandy therefore refuses to propagate through
/// links. Hard links cannot be detected this way; creating one needs write access to its target,
/// which the AppContainer lacks outside its paths.
fn refuse_links_below(directory: &Path) -> Result<(), SandboxError> {
    let mut pending = vec![directory.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir)
            .map_err(|error| SandboxError::io(format!("cannot list {}", dir.display()), error))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                SandboxError::io(format!("cannot list {}", dir.display()), error)
            })?;
            // The type comes from the directory listing and does not follow links. On Windows
            // `is_symlink` covers every name-surrogate reparse point, junctions included.
            let kind = entry.file_type().map_err(|error| {
                SandboxError::io(format!("cannot inspect {}", entry.path().display()), error)
            })?;
            if kind.is_symlink() {
                return Err(SandboxError::new(format!(
                    "{} is a junction or symbolic link inside the policy path {}; sandy does not \
                     grant access to a tree that contains links. Remove the link, or list its \
                     target in the policy",
                    entry.path().display(),
                    directory.display()
                )));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// The DACL of a file from `GetNamedSecurityInfoW`, in its security descriptor.
struct Dacl {
    descriptor: LocalBox,
    acl: *mut ACL,
}

impl Dacl {
    fn read(path: &[u16], display: &Path) -> Result<Dacl, SandboxError> {
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: path is NUL-terminated; the out pointers are valid or null for the parts not
        // requested.
        let error = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(win32_error(
                format!("cannot read the permissions of {}", display.display()),
                error,
            ));
        }
        Ok(Dacl {
            descriptor: LocalBox(descriptor),
            acl,
        })
    }

    fn protected(&self) -> Result<bool, SandboxError> {
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: the descriptor came from GetNamedSecurityInfoW and is still allocated.
        let ok =
            unsafe { GetSecurityDescriptorControl(self.descriptor.0, &mut control, &mut revision) };
        if ok == 0 {
            return Err(last_error("cannot read the security descriptor control"));
        }
        Ok(control & SE_DACL_PROTECTED != 0)
    }

    fn aces(&self, display: &Path) -> Result<ParsedAces, SandboxError> {
        if self.acl.is_null() {
            // A NULL DACL grants everyone full access. Adding an ACE would replace it with a
            // DACL that grants only the AppContainer, and the user would lose access.
            return Err(SandboxError::new(format!(
                "{} has no access control list (everyone has full access); sandy does not \
                 change it",
                display.display()
            )));
        }
        parse_acl(self.acl)
    }
}

/// The access allowed and access denied ACEs of an ACL, copied. `has_unknown_types` records
/// that the ACL has ACEs of other types, which the evaluator cannot judge.
struct ParsedAces {
    aces: Vec<(AceKind, u8, u32, Vec<u8>)>,
    has_unknown_types: bool,
}

impl ParsedAces {
    fn entries(&self) -> Vec<Ace<'_>> {
        self.aces
            .iter()
            .map(|(kind, flags, mask, sid)| Ace {
                kind: *kind,
                flags: *flags,
                mask: *mask,
                sid,
            })
            .collect()
    }
}

/// ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE: header, mask, then the SID.
const SID_OFFSET: usize = size_of::<ACE_HEADER>() + size_of::<u32>();
const MIN_SID_LEN: usize = 8;

fn parse_acl(acl: *const ACL) -> Result<ParsedAces, SandboxError> {
    let mut size = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: acl points to an ACL inside a security descriptor that is still allocated; size
    // is a writable ACL_SIZE_INFORMATION.
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(last_error("cannot read an access control list"));
    }
    let mut parsed = ParsedAces {
        aces: Vec::with_capacity(size.AceCount as usize),
        has_unknown_types: false,
    };
    for index in 0..size.AceCount {
        let mut ace: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: index is below the ACE count of a valid ACL.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(last_error("cannot read an access control entry"));
        }
        // SAFETY: GetAce returned a pointer to an ACE, which starts with an ACE_HEADER.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        let kind = match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
            ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
            _ => {
                parsed.has_unknown_types = true;
                continue;
            }
        };
        let size = usize::from(header.AceSize);
        if size < SID_OFFSET + MIN_SID_LEN {
            return Err(SandboxError::new("malformed access control entry"));
        }
        // SAFETY: the ACE is AceSize bytes long, which covers the header, the mask and the SID.
        let (mask, sid) = unsafe {
            let bytes = ace.cast::<u8>();
            (
                bytes
                    .add(size_of::<ACE_HEADER>())
                    .cast::<u32>()
                    .read_unaligned(),
                std::slice::from_raw_parts(bytes.add(SID_OFFSET), size - SID_OFFSET),
            )
        };
        let sid_len = MIN_SID_LEN + 4 * usize::from(sid[1]);
        if sid_len > sid.len() {
            return Err(SandboxError::new(
                "malformed SID in an access control entry",
            ));
        }
        parsed
            .aces
            .push((kind, header.AceFlags, mask, sid[..sid_len].to_vec()));
    }
    Ok(parsed)
}

fn add_ace(
    path: &[u16],
    display: &Path,
    current: &Dacl,
    capability: &Sid,
    mask: u32,
    flags: u8,
) -> Result<(), SandboxError> {
    set_access(path, display, current, capability, mask, flags)
}

/// Replaces every explicit ACE for `sid` in the DACL of `path` with one allow ACE for `mask`
/// with `flags`, and writes the DACL back, keeping its protection state. `SET_ACCESS` replaces
/// the existing entries for the trustee, so this both grants (a new SID) and reduces (an SID
/// Windows already granted more).
fn set_access(
    path: &[u16],
    display: &Path,
    current: &Dacl,
    sid: &Sid,
    mask: u32,
    flags: u8,
) -> Result<(), SandboxError> {
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: SET_ACCESS,
        grfInheritance: u32::from(flags),
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.as_psid().cast(),
        },
    };
    let mut merged: *mut ACL = ptr::null_mut();
    // SAFETY: access describes one entry whose SID outlives the call; current.acl is the valid,
    // non-null DACL of the path (checked in `aces`).
    let error = unsafe { SetEntriesInAclW(1, &access, current.acl, &mut merged) };
    if error != 0 {
        return Err(win32_error("cannot build the access control list", error));
    }
    let merged = LocalBox(merged.cast());
    // Without one of these flags SetNamedSecurityInfoW can drop the protection of the DACL.
    let protection = if current.protected()? {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: path is NUL-terminated and merged is a valid ACL from SetEntriesInAclW.
    let error = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            merged.0.cast(),
            ptr::null(),
        )
    };
    if error == ERROR_ACCESS_DENIED {
        return Err(SandboxError::new(format!(
            "cannot change the permissions of {}: the current user may not change them; for a \
             policy path, remove it or ask its owner to change the permissions",
            display.display()
        )));
    }
    if error != 0 {
        return Err(win32_error(
            format!("cannot change the permissions of {}", display.display()),
            error,
        ));
    }
    Ok(())
}
