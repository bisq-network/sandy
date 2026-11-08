//! File grants for the AppContainer: one access control entry (ACE) per policy path, two for a
//! read-write directory (`access::grant_entries`), for a capability that names the path's object
//! and access level (see `name::grant_capability_name`).

use std::cell::OnceCell;
use std::fs;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use sandy_core::{PathAccess, PathRule, ResolvedPolicy, SandboxError};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, GetSecurityInfo,
    NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
    SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, FileIdInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_ACE_TYPE, IO_REPARSE_TAG_MOUNT_POINT,
};

use super::host;
use super::lockfile::{LOCKS, SERIALIZE, UserLock};
use super::util::{LocalBox, Sid, last_error, wide_nul, win32_error};
use crate::access::{
    ADDS_LIBRARY, ALL_APPLICATION_PACKAGES, ALL_RESTRICTED_APPLICATION_PACKAGES, Ace, AceKind,
    CHANGES_CONTENT, CHANGES_FILE, CONTAINER_INHERIT_ACE, FILE_EXECUTE, GrantEntry, INHERITED_ACE,
    OBJECT_INHERIT_ACE, PROFILE_DENIED, REPLACES_ENTRY, access_mask, ace_flags,
    changeable_by_others, grant_entries, grants, has_explicit_ace, map_generic, may_grant,
};
use crate::name::{FileIdentity, grant_capability_name, junction_capability_name};
use crate::plan::Problem;
use crate::probe::Ungrantable;

/// Makes sure the AppContainer can use `rule.path` at `rule.access` and returns the capability
/// the target must hold for it. `held` are the other SIDs the program's token will carry (see
/// `check_rights`). Changes nothing when the grant is already in place.
pub fn grant(appcontainer: &str, rule: &PathRule, held: &[Sid]) -> Result<Sid, SandboxError> {
    check_rights(rule, held).map_err(|problem| SandboxError::new(problem.to_string()))?;
    let path = wide_nul(rule.path.as_os_str());
    let capability = grant_capability(appcontainer, rule, &path)?;
    if !lacks_grant(rule, &capability, &Dacl::read(&path, &rule.path)?)? {
        return Ok(capability);
    }
    // A change reads the DACL, adds the ACEs and writes the whole DACL back. Without the lock,
    // two runs that add different ACEs to the same object at the same time could each overwrite
    // the ACE of the other. If a run died while it held the lock during propagation, some
    // children may lack the inherited ACE, which denies access, never grants it.
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    // Another run may have changed the DACL while this one waited for the lock.
    let dacl = Dacl::read(&path, &rule.path)?;
    if lacks_grant(rule, &capability, &dacl)? {
        if rule.is_dir {
            let who = holders(held);
            check_tree_below(
                &rule.path,
                Excluded::of(rule.access)
                    .as_ref()
                    .map(|excluded| (excluded, &who[..])),
                "Remove the link, or list its target in the policy",
            )?;
        }
        add_ace(
            &path,
            &rule.path,
            &dacl,
            &capability,
            &grant_entries(rule.access, rule.is_dir),
        )?;
    }
    Ok(capability)
}

/// Refuses a policy path where Windows lets the program both write and execute files (DESIGN.md
/// rules 3 and 6): a writable path where it may execute files, on the path itself or on files
/// and directories created in it, as below `C:\Program Files`; and an executable path where it
/// may write them, as in its own profile folder, where Windows always gives the AppContainer
/// write access. Either way the program could write a program there and run it.
///
/// Who counts: the two groups Windows gives every AppContainer, and `held`, the SIDs of the
/// token that runs from the path that could carry an entry here: the AppContainer and its network
/// capabilities, of the program, or of the egress broker for sandy's executable. The grant
/// capabilities are not among them on purpose: each is derived from the identity of the object it
/// is granted on. sandy adds one to that object, and the relay's capability also to the forward
/// socket directory it creates (`forward`), which carries no execute right; the program adds
/// none, and the capability for one object does not match another, so it cannot combine write and
/// execute on a path through a grant capability. A file that is both writable and executable
/// through a second name is the link question of "Links and identity". Changes nothing.
///
/// What the permissions say is how their owner laid out the path, a conflict with the policy; a
/// list that sandy cannot read can pass, so that is indeterminate.
pub fn check_rights(rule: &PathRule, held: &[Sid]) -> Result<(), Problem> {
    let Some(excluded) = Excluded::of(rule.access) else {
        return Ok(());
    };
    let unreadable = |error: SandboxError| Problem::Indeterminate(error.to_string());
    let path = wide_nul(rule.path.as_os_str());
    let dacl = Dacl::read(&path, &rule.path).map_err(unreadable)?;
    let (kind, verb) = (excluded.kind, excluded.verb);
    if dacl.acl.is_null() {
        return Err(Problem::Conflict(format!(
            "{kind} path {} has no access control list, so everyone, every AppContainer among \
             them, may {verb} files there",
            rule.path.display()
        )));
    }
    let aces = dacl.aces(&rule.path).map_err(unreadable)?;
    if aces.has_unknown_types {
        return Err(Problem::Conflict(format!(
            "the permissions of {kind} path {} contain entries that sandy cannot evaluate, so \
             it cannot tell whether AppContainers may {verb} files there",
            rule.path.display()
        )));
    }
    match holder(
        &aces.entries(),
        &holders(held),
        excluded.rights,
        rule.is_dir,
    ) {
        Some(who) => Err(Problem::Conflict(format!(
            "{who} may {verb} files in {kind} path {}, so the program could write a program \
             there and run it",
            rule.path.display()
        ))),
        None => Ok(()),
    }
}

/// The rights the program must not hold on a policy path of some access level besides those of
/// its grant, and how the messages name them.
struct Excluded {
    rights: u32,
    /// The kind of policy path.
    kind: &'static str,
    /// What the rights let the program do to files.
    verb: &'static str,
}

impl Excluded {
    /// `None` for a path that may only be read, which nothing makes executable.
    fn of(access: PathAccess) -> Option<Excluded> {
        match access {
            PathAccess::Read => None,
            PathAccess::ReadExec => Some(Excluded {
                rights: CHANGES_CONTENT,
                kind: "executable",
                verb: "write",
            }),
            PathAccess::ReadWrite => Some(Excluded {
                rights: FILE_EXECUTE,
                kind: "writable",
                verb: "execute",
            }),
        }
    }
}

/// A SID whose rights would reach the program, and its name for the messages.
type Holder = (Vec<u8>, String);

/// Everyone whose rights on a policy path would reach the program, with a name for the message:
/// the two groups of every AppContainer and `held`.
fn holders(held: &[Sid]) -> Vec<Holder> {
    let mut who = vec![
        (
            ALL_APPLICATION_PACKAGES.to_vec(),
            "Windows (ALL APPLICATION PACKAGES)".to_string(),
        ),
        (
            ALL_RESTRICTED_APPLICATION_PACKAGES.to_vec(),
            "Windows (ALL RESTRICTED APPLICATION PACKAGES)".to_string(),
        ),
    ];
    who.extend(held.iter().map(|sid| {
        (
            sid.bytes().to_vec(),
            format!("the SID {sid} of the sandbox's own token"),
        )
    }));
    who
}

/// The first of `who` that `aces` may give one of `rights`, named.
fn holder(aces: &[Ace<'_>], who: &[Holder], rights: u32, is_dir: bool) -> Option<String> {
    who.iter()
        .find(|(sid, _)| may_grant(aces, sid, rights, is_dir))
        .map(|(_, name)| name.clone())
}

/// Removes the entry of the capability that carries the grant of `rule`, if it is there.
///
/// Only that one SID is touched. Other software uses capability SIDs too, and a capability SID
/// cannot be mapped back to its name, so removing anything else would be guesswork. A path that
/// is gone needs nothing removed.
pub fn revoke(appcontainer: &str, rule: &PathRule) -> Result<(), SandboxError> {
    if !rule.path.exists() {
        return Ok(());
    }
    let path = wide_nul(rule.path.as_os_str());
    let capability = grant_capability(appcontainer, rule, &path)?;
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    let dacl = Dacl::read(&path, &rule.path)?;
    let present = dacl
        .aces(&rule.path)?
        .entries()
        .iter()
        .any(|ace| ace.sid == capability.bytes());
    if !present {
        return Ok(());
    }
    set_access(
        Object::Path(&path),
        &rule.path,
        &dacl,
        &capability,
        REVOKE_ACCESS,
        0,
        ace_flags(rule.is_dir),
    )
}

/// Whether `grant` would succeed for `rule`: the grant is in place, or the current user may
/// change the DACL. Changes nothing.
pub fn grantable(appcontainer: &str, rule: &PathRule) -> Result<(), Ungrantable> {
    GrantTarget::read(rule.clone())?.grantable(appcontainer)
}

/// What decides whether sandy may give an AppContainer access to the object of a rule: the
/// object's identity, its DACL and, once a grant is missing, whether the current user may change
/// that DACL. Read once, so that every AppContainer name is asked about the same answers.
pub struct GrantTarget {
    rule: PathRule,
    path: Vec<u16>,
    identity: FileIdentity,
    dacl: Dacl,
    /// The Win32 error of opening the object for `WRITE_DAC`, `Ok` when it opened.
    may_change: OnceCell<Result<(), i32>>,
}

impl GrantTarget {
    pub fn read(rule: PathRule) -> Result<GrantTarget, Ungrantable> {
        let unreadable = |error: SandboxError| Ungrantable::Unreadable(error.to_string());
        let path = wide_nul(rule.path.as_os_str());
        let identity = file_identity(&path, &rule.path).map_err(unreadable)?;
        let dacl = Dacl::read(&path, &rule.path).map_err(unreadable)?;
        if dacl.acl.is_null() {
            return Err(Ungrantable::NoAcl);
        }
        Ok(GrantTarget {
            rule,
            path,
            identity,
            dacl,
            may_change: OnceCell::new(),
        })
    }

    pub fn rule(&self) -> &PathRule {
        &self.rule
    }

    /// Whether `grant` would succeed for `appcontainer`: the grant is in place, or the current
    /// user may change the DACL. Changes nothing.
    pub fn grantable(&self, appcontainer: &str) -> Result<(), Ungrantable> {
        let unreadable = |error: SandboxError| Ungrantable::Unreadable(error.to_string());
        let capability = capability_sid(&grant_capability_name(
            appcontainer,
            self.rule.access,
            self.identity,
        ))
        .map_err(unreadable)?;
        if !lacks_grant(&self.rule, &capability, &self.dacl).map_err(unreadable)? {
            return Ok(());
        }
        let may_change = self.may_change.get_or_init(|| may_change_dacl(&self.path));
        may_change.map_err(|code| Ungrantable::Denied(std::io::Error::from_raw_os_error(code)))
    }
}

/// Whether the current user may change the DACL of `path`, or the Win32 error that says no:
/// opening it for `WRITE_DAC` checks the right and changes nothing.
fn may_change_dacl(path: &[u16]) -> Result<(), i32> {
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
        // SAFETY: GetLastError has no preconditions.
        return Err(unsafe { GetLastError() } as i32);
    }
    // SAFETY: CreateFileW succeeded, so the handle is new; dropping it closes it.
    drop(unsafe { OwnedHandle::from_raw_handle(handle) });
    Ok(())
}

/// The rights on a junction that leads to a directory policy path. Windows checks the access a
/// program asks for on the junction itself when the path ends at it, and only then: the junction
/// in the middle of a path, and a file below it, need nothing (measured on Windows 11 build
/// 26200). Read lets the program list the directory under the name the policy used. A junction
/// takes its target from its own data, and writing that data, its attributes or its DACL would
/// let the program point it elsewhere before the next start, so no write right is among these.
const JUNCTION_MASK: u32 = crate::access::FILE_GENERIC_READ;

/// The junctions on the way to directory policy paths that the program could not open under
/// their names without an entry of sandy's, for `windows.junctions = "refuse"`, under which sandy
/// adds none. A junction every AppContainer may read already, or without DACL, is open; one sandy
/// cannot read or judge counts as closed. Changes nothing.
pub fn junctions_needing_entries(policy: &ResolvedPolicy) -> Vec<PathBuf> {
    final_junctions(policy)
        .into_iter()
        .filter(|junction| !open_to_every_appcontainer(junction).unwrap_or(false))
        .collect()
}

fn open_to_every_appcontainer(link: &Path) -> Result<bool, SandboxError> {
    let wide = wide_nul(link.as_os_str());
    let Some(opened) = open_junction(&wide, link, READ_CONTROL)? else {
        // Not a junction, or one whose permissions cannot be read: the latter counts as closed.
        return Ok(open_junction(&wide, link, 0)?.is_none());
    };
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), link)?;
    if dacl.acl.is_null() {
        return Ok(true);
    }
    let aces = dacl.aces(link)?;
    Ok(!aces.has_unknown_types
        && grants(
            &aces.entries(),
            ALL_APPLICATION_PACKAGES,
            JUNCTION_MASK,
            false,
        ))
}

/// Removes what `grant_junctions` added for `appcontainer`, from every junction the policy's
/// names pass, also one that no longer leads to a policy path, and returns the junctions whose
/// entry stays. An entry that stays grants nothing (see "One capability per path"), so a
/// junction that fails does not stop the rest of the removal.
pub fn revoke_junctions(appcontainer: &str, policy: &ResolvedPolicy) -> Vec<(PathBuf, String)> {
    policy
        .links
        .iter()
        .filter_map(|junction| {
            revoke_junction(appcontainer, junction)
                .err()
                .map(|error| (junction.clone(), error.to_string()))
        })
        .collect()
}

/// `Ok` when `junction` carries no entry of `appcontainer` afterwards, or is no junction. An
/// error names the SID of the entry that stays, so that the user can remove it by hand.
fn revoke_junction(appcontainer: &str, junction: &Path) -> Result<(), SandboxError> {
    let wide = wide_nul(junction.as_os_str());
    let Some(opened) = open_junction(&wide, junction, READ_CONTROL)? else {
        return Ok(());
    };
    let identity = opened.identity;
    let capability = capability_sid(&junction_capability_name(appcontainer, identity))?;
    if !carries(&opened, junction, &capability)? {
        return Ok(());
    }
    drop(opened);
    let sid = crate::access::sid_string(capability.bytes());
    remove_junction_entry(&wide, junction, identity, &capability)
        .map_err(|error| SandboxError::new(format!("{error}; its entry is for *{sid}")))
}

fn remove_junction_entry(
    wide: &[u16],
    junction: &Path,
    identity: FileIdentity,
    capability: &Sid,
) -> Result<(), SandboxError> {
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    let Some(opened) = open_junction(wide, junction, READ_CONTROL | WRITE_DAC)? else {
        return Err(SandboxError::new(format!(
            "cannot change the permissions of {}",
            junction.display()
        )));
    };
    if opened.identity != identity || !carries(&opened, junction, capability)? {
        return Ok(());
    }
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), junction)?;
    set_access(
        Object::Handle(opened.raw()),
        junction,
        &dacl,
        capability,
        REVOKE_ACCESS,
        0,
        0,
    )
}

/// Whether the junction's DACL holds any entry for `capability`.
fn carries(opened: &OpenJunction, link: &Path, capability: &Sid) -> Result<bool, SandboxError> {
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), link)?;
    if dacl.acl.is_null() {
        return Ok(false);
    }
    Ok(dacl
        .aces(link)?
        .entries()
        .iter()
        .any(|ace| ace.sid == capability.bytes()))
}

/// The links of `policy` that lead to a directory policy path or to a directory inside one, as
/// the last link of a name or as one of a chain of links that ends there: each of them is a name
/// the program may open such a directory by. Links that lead to a directory above or beside the
/// directory policy paths are left out, as the program may not open those anyway, and so is
/// every link that is not a junction (`grant_junction` checks the object itself).
fn final_junctions(policy: &ResolvedPolicy) -> Vec<PathBuf> {
    if policy.links.is_empty() {
        return Vec::new();
    }
    // A directory whose identity cannot be read gets no junction: that only leaves a name closed.
    let directories: Vec<FileIdentity> = policy
        .paths
        .iter()
        .filter(|rule| rule.is_dir)
        .filter_map(|rule| file_identity(&wide_nul(rule.path.as_os_str()), &rule.path).ok())
        .collect();
    let mut junctions = Vec::new();
    for link in &policy.links {
        // Follows the link; one that no longer resolves leads to no policy path. The target and
        // each directory above it are compared by identity, so an alias of a policy directory
        // counts as well.
        let Ok(target) = fs::canonicalize(link) else {
            continue;
        };
        let inside = target.ancestors().any(|directory| {
            file_identity(&wide_nul(directory.as_os_str()), directory)
                .is_ok_and(|identity| directories.contains(&identity))
        });
        if inside && target.is_dir() {
            junctions.push(link.clone());
        }
    }
    junctions
}

/// Gives the AppContainer read access to every junction that resolving a directory policy path
/// ended at (`final_junctions`), and returns the capabilities the target must hold for them.
///
/// The entry is on the junction object only, without inheritance, so it grants what the junction
/// itself holds, its target and attributes, and nothing below it: what the program reaches
/// through it is decided by the permissions of the target, also when a process outside the
/// sandbox points the junction elsewhere while the program runs. A junction that `assess` finds
/// closed, or that sandy fails to change for any other reason, is left as it is: the program
/// then cannot open the directory under that name, as before, which takes nothing away from the
/// policy, so the run goes on. The write of a DACL is one call, so a failure leaves nothing half
/// done.
pub fn grant_junctions(appcontainer: &str, policy: &ResolvedPolicy) -> Vec<Sid> {
    let junctions = final_junctions(policy);
    if junctions.is_empty() {
        return Vec::new();
    }
    let Ok(token) = TokenSids::of_this_process() else {
        return Vec::new();
    };
    junctions
        .iter()
        .filter_map(|junction| {
            grant_junction(appcontainer, junction, &token)
                .ok()
                .flatten()
        })
        .collect()
}

/// A junction `grant_junctions` leaves closed: why, and what the user can do instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedJunction {
    pub junction: PathBuf,
    pub reason: String,
    pub remedy: &'static str,
}

const NAME_IT_DIRECTLY: &str = "name the directory by its own path in the policy and the program";

/// The junctions `grant_junctions` would leave closed for `appcontainer`, for `sandy check`.
/// Decided by the same `assess` as the grant. Changes nothing.
pub fn closed_junctions(appcontainer: &str, policy: &ResolvedPolicy) -> Vec<ClosedJunction> {
    let junctions = final_junctions(policy);
    if junctions.is_empty() {
        return Vec::new();
    }
    let token = TokenSids::of_this_process();
    junctions
        .into_iter()
        .filter_map(|junction| {
            let closed = token
                .as_ref()
                .map_err(|error| SandboxError::new(error.to_string()))
                .and_then(|token| junction_grantable(appcontainer, &junction, token));
            let (reason, remedy) = match closed {
                Ok(None) => return None,
                Ok(Some(closed)) => closed,
                Err(error) => (error.to_string(), NAME_IT_DIRECTLY),
            };
            Some(ClosedJunction {
                junction,
                reason,
                remedy,
            })
        })
        .collect()
}

/// What sandy does with one junction, decided on its current DACL.
enum Decision {
    /// The program opens it without an entry: no DACL, or every AppContainer may read it.
    Open,
    /// Sandy's entry is in place already.
    Granted(Sid),
    /// It needs the entry, and sandy may add it.
    Grant(Sid),
    /// It stays closed: why, and what the user can do instead.
    Closed(String, &'static str),
}

/// The one decision both `grant_junction` and `junction_grantable` follow, so that `check`
/// says what `run` does.
fn assess(
    appcontainer: &str,
    opened: &OpenJunction,
    link: &Path,
    dacl: &Dacl,
    token: &TokenSids,
) -> Result<Decision, SandboxError> {
    // A junction without DACL lets everyone open it already, and adding an entry would take
    // that away from the user.
    if dacl.acl.is_null() {
        return Ok(Decision::Open);
    }
    let aces = dacl.aces(link)?;
    let entries = aces.entries();
    let capability = capability_sid(&junction_capability_name(appcontainer, opened.identity))?;
    if has_explicit_ace(&entries, capability.bytes(), JUNCTION_MASK, 0) {
        return Ok(Decision::Granted(capability));
    }
    if grants(&entries, ALL_APPLICATION_PACKAGES, JUNCTION_MASK, false) {
        return Ok(Decision::Open);
    }
    if aces.has_unknown_types {
        return Ok(Decision::Closed(
            "its permissions hold entries that sandy cannot evaluate".to_string(),
            NAME_IT_DIRECTLY,
        ));
    }
    // The AppContainer access check passes the user's own token first, so a deny entry for the
    // user or one of its groups keeps the program out whatever sandy adds.
    if let Some(sid) = denied_to(&entries, token) {
        return Ok(Decision::Closed(
            format!(
                "a deny entry for {} on it keeps this user out, so an entry of sandy's would \
                 not open it",
                crate::access::sid_string(sid)
            ),
            NAME_IT_DIRECTLY,
        ));
    }
    let owner = owner_of(opened, link)?;
    if !owner
        .as_ref()
        .is_some_and(|owner| token.owners.contains(owner))
    {
        let owner = owner.map_or("nobody".to_string(), |owner| {
            crate::access::sid_string(owner.bytes())
        });
        return Ok(Decision::Closed(
            format!(
                "it belongs to {owner}, not to the current user or the owner of what this \
                 process creates, and sandy changes only those junctions"
            ),
            "name the directory by its own path in the policy and the program, or make the \
             current user the junction's owner",
        ));
    }
    Ok(Decision::Grant(capability))
}

/// The SID of a deny entry on the junction itself that takes listing or waiting from the user
/// or one of its groups, deny-only groups included.
fn denied_to<'a>(entries: &[Ace<'a>], token: &TokenSids) -> Option<&'a [u8]> {
    use crate::access::{FILE_READ_DATA, INHERIT_ONLY_ACE, SYNCHRONIZE};
    entries
        .iter()
        .find(|ace| {
            ace.kind == AceKind::Deny
                && ace.flags & INHERIT_ONLY_ACE == 0
                && map_generic(ace.mask) & (FILE_READ_DATA | SYNCHRONIZE) != 0
                && token.all.iter().any(|sid| sid.bytes() == ace.sid)
        })
        .map(|ace| ace.sid)
}

/// One junction, see `grant_junctions`. `None` when it needs no entry or stays closed.
fn grant_junction(
    appcontainer: &str,
    link: &Path,
    token: &TokenSids,
) -> Result<Option<Sid>, SandboxError> {
    let wide = wide_nul(link.as_os_str());
    let Some(opened) = open_junction(&wide, link, READ_CONTROL)? else {
        return Ok(None);
    };
    let identity = opened.identity;
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), link)?;
    match assess(appcontainer, &opened, link, &dacl, token)? {
        Decision::Granted(capability) => return Ok(Some(capability)),
        Decision::Open | Decision::Closed(..) => return Ok(None),
        Decision::Grant(_) => {}
    }
    drop(opened);
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    let Some(opened) = open_junction(&wide, link, READ_CONTROL | WRITE_DAC)? else {
        return Ok(None);
    };
    // Another object took the name since: its capability is another one, so leave it. One of
    // the same owner that took the name since `final_junctions` gets the entry instead, which
    // gives nothing beyond the junction itself.
    if opened.identity != identity {
        return Ok(None);
    }
    // Decided again on the DACL as it is now, under the lock.
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), link)?;
    match assess(appcontainer, &opened, link, &dacl, token)? {
        Decision::Granted(capability) => Ok(Some(capability)),
        Decision::Open | Decision::Closed(..) => Ok(None),
        Decision::Grant(capability) => {
            set_access(
                Object::Handle(opened.raw()),
                link,
                &dacl,
                &capability,
                SET_ACCESS,
                JUNCTION_MASK,
                0,
            )?;
            Ok(Some(capability))
        }
    }
}

/// Why `grant_junction` would leave `link` closed, `None` when it would not.
fn junction_grantable(
    appcontainer: &str,
    link: &Path,
    token: &TokenSids,
) -> Result<Option<(String, &'static str)>, SandboxError> {
    let wide = wide_nul(link.as_os_str());
    let Some(opened) = open_junction(&wide, link, READ_CONTROL)? else {
        // Not a junction, or one the user may not read the permissions of: tell them apart. A
        // junction whose attributes the user may not read looks like none and is not named,
        // which takes listing rights away on its parent as well.
        return Ok(open_junction(&wide, link, 0)?.map(|_| {
            (
                "the current user may not read its permissions".to_string(),
                NAME_IT_DIRECTLY,
            )
        }));
    };
    let dacl = Dacl::read_object(Object::Handle(opened.raw()), link)?;
    Ok(match assess(appcontainer, &opened, link, &dacl, token)? {
        Decision::Open | Decision::Granted(_) => None,
        Decision::Closed(reason, remedy) => Some((reason, remedy)),
        Decision::Grant(_) => match open_junction(&wide, link, READ_CONTROL | WRITE_DAC)? {
            Some(_) => None,
            None => Some((
                "the current user may not change its permissions".to_string(),
                "name the directory by its own path in the policy and the program, or let the \
                 current user change the junction's permissions",
            )),
        },
    })
}

/// The owner of the junction, `None` when it has none sandy can read.
fn owner_of(opened: &OpenJunction, link: &Path) -> Result<Option<Sid>, SandboxError> {
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL; the out pointers are valid.
    let error = unsafe {
        GetSecurityInfo(
            opened.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(win32_error(
            format!("cannot read the owner of {}", link.display()),
            error,
        ));
    }
    let _descriptor = LocalBox(descriptor);
    // SAFETY: owner is null or points to the owner SID inside the descriptor, still allocated.
    Ok(unsafe { Sid::copy_from(owner) }.ok())
}

/// The SIDs of this process's token that decide about a junction: `owners`, its user and its
/// default owner, which owns what the process creates (Administrators for an elevated
/// administrator, which every elevated administrator shares); and `all`, its user and every
/// group, deny-only ones included, against which deny entries count.
struct TokenSids {
    owners: Vec<Sid>,
    all: Vec<Sid>,
}

impl TokenSids {
    fn of_this_process() -> Result<TokenSids, SandboxError> {
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY,
            TOKEN_USER, TokenGroups, TokenOwner, TokenUser,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: the pseudo handle of this process needs no closing; token is a valid out
        // pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error("cannot open this process's token"));
        }
        // SAFETY: OpenProcessToken returned a handle that nothing else owns.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        // The information of `class`, in a buffer of u64 so that it is aligned for every
        // structure and the SIDs that follow it.
        let read = |class: TOKEN_INFORMATION_CLASS| -> Result<Vec<u64>, SandboxError> {
            let mut length = 0u32;
            // SAFETY: a null buffer of length 0 asks for the length only.
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    class,
                    ptr::null_mut(),
                    0,
                    &mut length,
                )
            };
            let mut buffer = vec![0u64; (length as usize).div_ceil(8).max(1)];
            // SAFETY: the buffer is writable and holds at least `length` bytes.
            let ok = unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                    &mut length,
                )
            };
            if ok == 0 {
                return Err(last_error("cannot read this process's token"));
            }
            Ok(buffer)
        };
        let copy = |sid: PSID| {
            // SAFETY: the SID lies inside a buffer that is still alive.
            unsafe { Sid::copy_from(sid) }
                .map_err(|error| SandboxError::io("a SID of this process's token", error))
        };
        let user_buffer = read(TokenUser)?;
        // SAFETY: the call filled a TOKEN_USER at the start of the buffer.
        let user = copy(unsafe { user_buffer.as_ptr().cast::<TOKEN_USER>().read().User.Sid })?;
        let owner_buffer = read(TokenOwner)?;
        // SAFETY: the call filled a TOKEN_OWNER at the start of the buffer.
        let owner = copy(unsafe { owner_buffer.as_ptr().cast::<TOKEN_OWNER>().read().Owner })?;
        let groups_buffer = read(TokenGroups)?;
        let groups = groups_buffer.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: the call filled a TOKEN_GROUPS with GroupCount entries at the start of the
        // buffer.
        let count = unsafe { (*groups).GroupCount } as usize;
        let mut all = vec![user.clone()];
        for index in 0..count {
            // SAFETY: index is below GroupCount, and the array starts at the field Groups.
            let sid = unsafe {
                (*std::ptr::addr_of!((*groups).Groups)
                    .cast::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
                    .add(index))
                .Sid
            };
            all.push(copy(sid)?);
        }
        Ok(TokenSids {
            owners: vec![user, owner],
            all,
        })
    }
}

/// A junction opened as itself, not as the directory it leads to.
struct OpenJunction {
    handle: OwnedHandle,
    identity: FileIdentity,
}

impl OpenJunction {
    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

/// Opens `path` without following a reparse point there, with `access`, and returns it when it
/// is a junction (a mount point reparse point, which a volume mounted in a folder is as well). `None` when it is something else, is gone, or
/// the current user may not open it so.
fn open_junction(
    path: &[u16],
    display: &Path,
    access: u32,
) -> Result<Option<OpenJunction>, SandboxError> {
    // SAFETY: path is NUL-terminated; FILE_FLAG_OPEN_REPARSE_POINT opens the junction itself.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        // SAFETY: GetLastError has no preconditions.
        return match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            code => Err(win32_error(
                format!("cannot open {}", display.display()),
                code,
            )),
        };
    }
    // SAFETY: CreateFileW succeeded, so the handle is new and owned by nobody else.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: tag is a writable FILE_ATTRIBUTE_TAG_INFO and the size matches it.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error(format!(
            "cannot read the reparse tag of {}",
            display.display()
        )));
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || tag.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT
    {
        return Ok(None);
    }
    let identity = handle_identity(&handle, display)?;
    Ok(Some(OpenJunction { handle, identity }))
}

/// Allows `sid`, which the caller already holds as a capability, `mask` with `flags` on the
/// directory `path` that sandy created. Used for the socket directory of forwarded ports, which
/// only the relays may use.
pub fn allow(path: &Path, sid: &Sid, mask: u32, flags: u8) -> Result<(), SandboxError> {
    let wide = wide_nul(path.as_os_str());
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    let dacl = Dacl::read(&wide, path)?;
    // A NULL DACL would be replaced by one that grants only `sid`; refuse it like `grant` does.
    dacl.aces(path)?;
    set_access(
        Object::Path(&wide),
        path,
        &dacl,
        sid,
        SET_ACCESS,
        mask,
        flags,
    )
}

/// Reduces the AppContainer's access to its profile folder to the read-write rights, so the
/// program cannot execute what it writes there and cannot give itself execute back.
///
/// Windows creates the folder (`...\Packages\<name>\AC`, which holds the program's `TEMP`) with
/// an inheritable allow ACE that grants the AppContainer SID `FILE_ALL`, which contains
/// `FILE_EXECUTE`, `WRITE_DAC` and `WRITE_OWNER`. The folder is always present, persists across
/// runs, and must stay writable for data, so sandy cannot remove it. A deny ACE does not help:
/// the AppContainer access check ignores a deny ACE for the package SID (measured). sandy
/// reduces the allow ACE instead, which the access check does honor. `SetNamedSecurityInfoW`
/// re-propagates the inheritable ACE, so files the program wrote on an earlier run lose the
/// rights too.
///
/// Idempotent: it writes only while the entry still carries one of those rights, so it also
/// reduces an entry that lost only `FILE_EXECUTE`, or that someone widened again.
pub fn deny_execute_in_profile(appcontainer: &Sid, folder: &Path) -> Result<(), SandboxError> {
    let path = wide_nul(folder.as_os_str());
    if excess_profile_rights(&Dacl::read(&path, folder)?, folder, appcontainer)?.is_none() {
        return Ok(());
    }
    let _lock = UserLock::wait_for(LOCKS, "dacl-changes", SERIALIZE, true)?;
    let dacl = Dacl::read(&path, folder)?;
    if let Some(mask) = excess_profile_rights(&dacl, folder, appcontainer)? {
        // Writing the entry re-propagates it to everything below the folder, and the program
        // can write there, so refuse a planted link first, as `grant` does for a policy path.
        check_tree_below(
            folder,
            None,
            "Remove the link; the folder is the AppContainer's profile, whose rights sandy is \
             reducing",
        )?;
        set_access(
            Object::Path(&path),
            folder,
            &dacl,
            appcontainer,
            SET_ACCESS,
            mask & !PROFILE_DENIED,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )?;
    }
    Ok(())
}

/// The union of the explicit allow rights of `appcontainer` on its profile folder, when one of
/// them is a right the program must not have there (`PROFILE_DENIED`). `None` means the folder
/// is already reduced, so the run changes nothing.
fn excess_profile_rights(
    dacl: &Dacl,
    folder: &Path,
    appcontainer: &Sid,
) -> Result<Option<u32>, SandboxError> {
    let mut mask = 0u32;
    for ace in dacl.aces(folder)?.entries() {
        if ace.kind != AceKind::Deny
            && ace.flags & INHERITED_ACE == 0
            && ace.sid == appcontainer.bytes()
        {
            mask |= map_generic(ace.mask);
        }
    }
    Ok((mask & PROFILE_DENIED != 0).then_some(mask))
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
    if grant_entries(rule.access, rule.is_dir)
        .iter()
        .all(|grant| has_explicit_ace(&entries, capability.bytes(), grant.mask, grant.flags))
    {
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
    handle_identity(&handle, display)
}

fn handle_identity(handle: &OwnedHandle, display: &Path) -> Result<FileIdentity, SandboxError> {
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

/// Whether only administrators can change the program at `path`: no one else owns it or holds a
/// right there that changes it (`CHANGES_FILE`), or owns or holds a right on the directory that
/// holds it that adds or replaces an entry (`ADDS_LIBRARY`: Windows looks for a program's
/// libraries next to it first), or on a directory above that replaces an entry
/// (`REPLACES_ENTRY`). `Ok` is the path to run the program by, which is the one checked.
/// `Err` says who else can.
///
/// The check is on `path` with its links and junctions resolved. A junction answers for its
/// own permissions, not for those of its target, and changing its target needs only the right
/// to write its data or attributes, which every user holds on one below `C:\ProgramData`.
/// A file on a network share is refused: its permissions name the accounts of the machine that
/// serves it, whose administrators are not this machine's.
pub fn administrators_only(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if crate::plan::is_network_path(&path) {
        return Err(format!(
            "{} lies on a network share, whose administrators are not this machine's",
            path.display()
        ));
    }
    let mut rights = CHANGES_FILE;
    for entry in path.ancestors() {
        if let Some(who) = changeable_by(entry, rights)? {
            return Err(format!("{who} can change {}", entry.display()));
        }
        rights = if rights == CHANGES_FILE {
            ADDS_LIBRARY
        } else {
            REPLACES_ENTRY
        };
    }
    Ok(path)
}

/// Who other than administrators holds `rights` on `path` or owns it, `None` when no one does.
fn changeable_by(path: &Path, rights: u32) -> Result<Option<String>, String> {
    let wide = wide_nul(path.as_os_str());
    let (mut owner, mut acl): (PSID, *mut ACL) = (ptr::null_mut(), ptr::null_mut());
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: wide is NUL-terminated; the out pointers are valid or null for the parts not
    // requested.
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(format!(
            "cannot read the permissions of {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    let _descriptor = LocalBox(descriptor);
    if owner.is_null() {
        return Ok(Some("whoever takes ownership".to_string()));
    }
    if acl.is_null() {
        return Ok(Some("everyone (it has no access control list)".to_string()));
    }
    // SAFETY: owner points to a valid SID inside the descriptor, which is still allocated.
    let owner = unsafe {
        std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize).to_vec()
    };
    let parsed = parse_acl(acl).map_err(|error| error.to_string())?;
    if parsed.has_unknown_types {
        return Ok(Some(
            "an entry of a kind sandy does not read, which may name anyone,".to_string(),
        ));
    }
    Ok(changeable_by_others(&owner, &parsed.entries(), rights))
}

/// Checks the tree below a directory that is about to receive an inheritable ACE. Called only
/// when sandy adds the ACE, not on every run. `advice` ends the message that refuses a link.
///
/// Links: applying an inheritable ACE to a directory also changes every object below it.
/// Whether this propagation follows junctions and symbolic links is not documented. A program
/// that could write below the directory in an earlier run could have planted a link to a
/// directory of the user, which would then receive the grant. sandy therefore refuses to
/// propagate through links. Hard links cannot be detected this way; creating one needs write
/// access to its target, which the AppContainer lacks outside its paths.
///
/// Rights: a descendant can carry an explicit entry of its own that gives one of `who` a right
/// of `excluded`, which the DACL of the directory does not show: execute below a writable path,
/// write below an executable one. Together with the grant sandy is about to add it would make
/// that file writable and executable, so the walk refuses it. The program cannot add such an
/// entry later: it holds no right to change permissions outside its profile folder. Software
/// outside the sandbox can, which stays a residual risk because the walk runs once. `None`
/// looks only for links.
fn check_tree_below(
    directory: &Path,
    excluded: Option<(&Excluded, &[Holder])>,
    advice: &str,
) -> Result<(), SandboxError> {
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
                    "{} is a junction or symbolic link inside {}; sandy does not change the \
                     permissions of a tree that contains links. {advice}",
                    entry.path().display(),
                    directory.display()
                )));
            }
            if let Some((excluded, who)) = excluded {
                refuse_entry(&entry.path(), kind.is_dir(), directory, excluded, who)?;
            }
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// Refuses `path` when its own permissions may give one of `who` one of the rights `excluded`.
fn refuse_entry(
    path: &Path,
    is_dir: bool,
    directory: &Path,
    excluded: &Excluded,
    who: &[Holder],
) -> Result<(), SandboxError> {
    let wide = wide_nul(path.as_os_str());
    let aces = Dacl::read(&wide, path)?.aces(path)?;
    let found = if aces.has_unknown_types {
        Some("entries that sandy cannot evaluate".to_string())
    } else {
        holder(&aces.entries(), who, excluded.rights, is_dir)
    };
    match found {
        Some(who) => Err(SandboxError::new(format!(
            "the permissions of {} say that {who} may {} it, and it lies in the {} policy path \
             {}, so the program could write a program there and run it. Remove that \
             permission, or take the file out of the path",
            path.display(),
            excluded.verb,
            excluded.kind,
            directory.display()
        ))),
        None => Ok(()),
    }
}

/// What a DACL is read from and written to: a path, which Windows follows through links, or an
/// open handle, which names the object it was opened on.
#[derive(Clone, Copy)]
enum Object<'a> {
    Path(&'a [u16]),
    Handle(HANDLE),
}

/// The DACL of a file from `GetNamedSecurityInfoW` or `GetSecurityInfo`, in its security
/// descriptor.
struct Dacl {
    descriptor: LocalBox,
    acl: *mut ACL,
}

impl Dacl {
    fn read(path: &[u16], display: &Path) -> Result<Dacl, SandboxError> {
        Dacl::read_object(Object::Path(path), display)
    }

    fn read_object(object: Object<'_>, display: &Path) -> Result<Dacl, SandboxError> {
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let error = match object {
            // SAFETY: path is NUL-terminated; the out pointers are valid or null for the parts
            // not requested.
            Object::Path(path) => unsafe {
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
            },
            // SAFETY: the handle is open with READ_CONTROL; the out pointers are as above.
            Object::Handle(handle) => unsafe {
                GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut acl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
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
        // A callback entry starts like a plain one: header, mask, SID, then the condition.
        // sandy does not evaluate the condition; `AceKind::ConditionalAllow` says so. A
        // conditional deny is dropped, because a deny that may not apply protects nothing.
        let kind = match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
            ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE => AceKind::ConditionalAllow,
            ACCESS_DENIED_CALLBACK_ACE_TYPE => continue,
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

/// Replaces the explicit entries of `capability` on `path` with `entries`: the first replaces
/// them (`SET_ACCESS`), the others join it (`GRANT_ACCESS`), each an ACE of its own because
/// their flags differ.
fn add_ace(
    path: &[u16],
    display: &Path,
    current: &Dacl,
    capability: &Sid,
    entries: &[GrantEntry],
) -> Result<(), SandboxError> {
    let changes: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let mode = if index == 0 { SET_ACCESS } else { GRANT_ACCESS };
            (mode, entry.mask, entry.flags)
        })
        .collect();
    write_entries(Object::Path(path), display, current, capability, &changes)
}

/// Rewrites the explicit ACEs for `sid` in the DACL of `path` and writes the DACL back, keeping
/// its protection state. `SET_ACCESS` replaces the existing entries for the trustee with one
/// allow ACE for `mask` with `flags`, so it both grants (a new SID) and reduces (an SID Windows
/// already granted more); `REVOKE_ACCESS` removes them.
fn set_access(
    object: Object<'_>,
    display: &Path,
    current: &Dacl,
    sid: &Sid,
    mode: ACCESS_MODE,
    mask: u32,
    flags: u8,
) -> Result<(), SandboxError> {
    write_entries(object, display, current, sid, &[(mode, mask, flags)])
}

/// `set_access` with several changes for `sid` in one write, applied in order.
fn write_entries(
    object: Object<'_>,
    display: &Path,
    current: &Dacl,
    sid: &Sid,
    changes: &[(ACCESS_MODE, u32, u8)],
) -> Result<(), SandboxError> {
    let access: Vec<EXPLICIT_ACCESS_W> = changes
        .iter()
        .map(|&(mode, mask, flags)| EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: mode,
            grfInheritance: u32::from(flags),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.as_psid().cast(),
            },
        })
        .collect();
    let mut merged: *mut ACL = ptr::null_mut();
    // SAFETY: access holds access.len() entries whose SID outlives the call; current.acl is the
    // valid, non-null DACL of the path (checked in `aces`).
    let error = unsafe {
        SetEntriesInAclW(
            access.len() as u32,
            access.as_ptr(),
            current.acl,
            &mut merged,
        )
    };
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
    let information = DACL_SECURITY_INFORMATION | protection;
    let error = match object {
        // SAFETY: path is NUL-terminated and merged is a valid ACL from SetEntriesInAclW.
        Object::Path(path) => unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                information,
                ptr::null_mut(),
                ptr::null_mut(),
                merged.0.cast(),
                ptr::null(),
            )
        },
        // SAFETY: the handle is open with WRITE_DAC and merged is a valid ACL.
        Object::Handle(handle) => unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                information,
                ptr::null_mut(),
                ptr::null_mut(),
                merged.0.cast(),
                ptr::null(),
            )
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{FILE_GENERIC_EXECUTE, FILE_GENERIC_WRITE};

    /// A new, empty directory below the temporary directory.
    fn directory(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sandy-acl-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn writable(path: &Path) -> PathRule {
        PathRule {
            path: path.to_path_buf(),
            access: PathAccess::ReadWrite,
            is_dir: true,
        }
    }

    /// Gives `path` a NULL DACL: everyone has full access.
    fn remove_dacl(path: &Path) {
        let wide = wide_nul(path.as_os_str());
        // SAFETY: wide is NUL-terminated; a null DACL with DACL_SECURITY_INFORMATION sets a NULL
        // DACL.
        let error = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert_eq!(error, 0, "cannot remove the DACL of {}", path.display());
    }

    /// What the permissions of a writable path say is how its owner laid it out, a conflict with
    /// the policy; permissions that sandy cannot read are indeterminate, because the read can
    /// pass.
    #[test]
    fn writable_path_permissions_conflict_and_unreadable_ones_are_indeterminate() {
        let plain = directory("plain");
        assert_eq!(check_rights(&writable(&plain), &[]), Ok(()));
        assert!(grantable("example.app", &writable(&plain)).is_ok());

        let executable = directory("executable");
        let wide = wide_nul(executable.as_os_str());
        let any_package = Sid::from_bytes(ALL_APPLICATION_PACKAGES).unwrap();
        set_access(
            Object::Path(&wide),
            &executable,
            &Dacl::read(&wide, &executable).unwrap(),
            &any_package,
            SET_ACCESS,
            FILE_GENERIC_EXECUTE,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )
        .unwrap();
        assert!(matches!(
            check_rights(&writable(&executable), &[]),
            Err(Problem::Conflict(reason)) if reason.contains("ALL APPLICATION PACKAGES")
        ));

        let open = directory("open");
        remove_dacl(&open);
        assert!(matches!(
            check_rights(&writable(&open), &[]),
            Err(Problem::Conflict(reason)) if reason.contains("no access control list")
        ));
        assert!(matches!(
            grantable("example.app", &writable(&open)),
            Err(Ungrantable::NoAcl)
        ));

        let missing = plain.join("missing");
        assert!(matches!(
            check_rights(&writable(&missing), &[]),
            Err(Problem::Indeterminate(_))
        ));
        assert!(matches!(
            grantable("example.app", &writable(&missing)),
            Err(Ungrantable::Unreadable(_))
        ));

        for dir in [plain, executable, open] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    fn executable(path: &Path) -> PathRule {
        PathRule {
            access: PathAccess::ReadExec,
            ..writable(path)
        }
    }

    /// Gives `sid` `mask` on `path` with `flags`.
    fn allow_on(path: &Path, sid: &[u8], mask: u32, flags: u8) {
        let wide = wide_nul(path.as_os_str());
        set_access(
            Object::Path(&wide),
            path,
            &Dacl::read(&wide, path).unwrap(),
            &Sid::from_bytes(sid).unwrap(),
            SET_ACCESS,
            mask,
            flags,
        )
        .unwrap();
    }

    /// An executable path where an AppContainer may write files is refused like a writable path
    /// where it may execute them, as in the AppContainer's own profile folder: on the path
    /// itself, through any right that changes content, and at the grant for an entry below the
    /// path whose own permissions allow it.
    #[test]
    fn executable_path_permissions_that_allow_writing_conflict() {
        const INHERIT: u8 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        let plain = directory("exec-plain");
        assert_eq!(check_rights(&executable(&plain), &[]), Ok(()));

        let shared = directory("exec-shared");
        allow_on(
            &shared,
            ALL_APPLICATION_PACKAGES,
            FILE_GENERIC_WRITE,
            INHERIT,
        );
        assert!(matches!(
            check_rights(&executable(&shared), &[]),
            Err(Problem::Conflict(reason))
                if reason.contains("PACKAGES) may write files in executable path")
        ));

        // The program's own SID, S-1-15-2-99 here, with a right that lets it grant itself write.
        let own = directory("exec-own");
        let program = Sid::from_bytes(&[1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 99, 0, 0, 0]).unwrap();
        allow_on(own.as_path(), program.bytes(), WRITE_DAC, INHERIT);
        assert_eq!(check_rights(&executable(&own), &[]), Ok(()));
        assert!(matches!(
            check_rights(&executable(&own), std::slice::from_ref(&program)),
            Err(Problem::Conflict(reason)) if reason.contains("SID S-1-15-2-99 of the sandbox's own token")
        ));

        let below = directory("exec-below");
        let file = below.join("tool.exe");
        fs::write(&file, b"").unwrap();
        allow_on(&file, ALL_APPLICATION_PACKAGES, FILE_GENERIC_WRITE, 0);
        assert_eq!(check_rights(&executable(&below), &[]), Ok(()));
        let refused = grant("sandy.acl-exec-test", &executable(&below), &[]).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("may write it, and it lies in the executable policy path"),
            "{refused}"
        );
        revoke("sandy.acl-exec-test", &executable(&below)).unwrap();

        for dir in [plain, shared, own, below] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// A deny entry before the allow does not keep an AppContainer from a right: Windows ignores
    /// it for the package SID, the capabilities and the two package groups (measured on Windows
    /// 11 build 26200), so the check does too, for either kind of path.
    #[test]
    fn a_deny_entry_does_not_keep_a_path_from_conflicting() {
        // Every right that changes content, and execute.
        let cases = [
            (executable as fn(&Path) -> PathRule, "0xc0006", "write"),
            (writable, "0x20", "execute"),
        ];
        for (index, (rule, denied, verb)) in cases.into_iter().enumerate() {
            let dir = directory(&format!("deny-{index}"));
            let wide = wide_nul(dir.as_os_str());
            set_sddl(
                Object::Path(&wide),
                &format!("D:(D;OICI;{denied};;;AC)(A;OICI;FA;;;AC)"),
            );
            let checked = check_rights(&rule(&dir), &[]);
            assert!(
                matches!(
                    &checked,
                    Err(Problem::Conflict(reason))
                        if reason.contains(&format!("PACKAGES) may {verb} files in"))
                ),
                "{checked:?}"
            );
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// The explicit entries of `sid` on `path`, as sandy writes them.
    fn explicit_entries(path: &Path, sid: &Sid) -> Vec<GrantEntry> {
        let wide = wide_nul(path.as_os_str());
        let dacl = Dacl::read(&wide, path).unwrap();
        let aces = dacl.aces(path).unwrap();
        aces.entries()
            .iter()
            .filter(|ace| ace.sid == sid.bytes() && ace.flags & INHERITED_ACE == 0)
            .map(|ace| GrantEntry {
                mask: ace.mask,
                flags: ace.flags,
            })
            .collect()
    }

    /// A read-write grant gives the path itself every right of its level but `DELETE`, and
    /// everything below a directory all of them. An entry with `DELETE` on the path, as sandy
    /// wrote it before, is replaced; a second grant changes nothing, and the removal takes both
    /// entries away.
    #[test]
    fn a_read_write_grant_leaves_delete_off_the_path_itself() {
        const NAME: &str = "sandy.acl-rw-root";
        let dir = directory("rw-root");
        let child = dir.join("child");
        fs::write(&child, b"").unwrap();
        let file = directory("rw-root-file").join("file");
        fs::write(&file, b"").unwrap();
        let rules = [
            writable(&dir),
            PathRule {
                path: file.clone(),
                access: PathAccess::ReadWrite,
                is_dir: false,
            },
        ];
        for rule in &rules {
            let wide = wide_nul(rule.path.as_os_str());
            let capability = grant_capability(NAME, rule, &wide).unwrap();
            allow_on(
                &rule.path,
                capability.bytes(),
                access_mask(PathAccess::ReadWrite),
                ace_flags(rule.is_dir),
            );
            assert_eq!(grant(NAME, rule, &[]).unwrap(), capability);
            let expected = grant_entries(rule.access, rule.is_dir);
            assert_eq!(explicit_entries(&rule.path, &capability), expected);
            assert!(
                !lacks_grant(rule, &capability, &Dacl::read(&wide, &rule.path).unwrap()).unwrap()
            );
        }
        let capability = grant_capability(NAME, &rules[0], &wide_nul(dir.as_os_str())).unwrap();
        let wide = wide_nul(child.as_os_str());
        let below = Dacl::read(&wide, &child).unwrap();
        let below = below.aces(&child).unwrap();
        assert!(grants(
            &below.entries(),
            capability.bytes(),
            access_mask(PathAccess::ReadWrite),
            false
        ));
        for rule in &rules {
            let wide = wide_nul(rule.path.as_os_str());
            let capability = grant_capability(NAME, rule, &wide).unwrap();
            revoke(NAME, rule).unwrap();
            assert_eq!(explicit_entries(&rule.path, &capability), []);
        }
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(file.parent().unwrap());
    }

    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J {}", link.display());
    }

    /// The policy with `read`, resolved, so its links are those the resolver passed.
    fn resolved(read: &[PathBuf]) -> ResolvedPolicy {
        let mut policy = sandy_core::Policy::default();
        policy.filesystem.read = read.to_vec();
        ResolvedPolicy::resolve(&policy, None).unwrap()
    }

    /// Every entry of the junction object itself, not of its target.
    fn junction_entries(link: &Path) -> Vec<(AceKind, u8, u32, Vec<u8>)> {
        let opened = open_junction(&wide_nul(link.as_os_str()), link, READ_CONTROL)
            .unwrap()
            .unwrap();
        Dacl::read_object(Object::Handle(opened.raw()), link)
            .unwrap()
            .aces(link)
            .unwrap()
            .aces
    }

    fn target_entries(path: &Path) -> Vec<(AceKind, u8, u32, Vec<u8>)> {
        let wide = wide_nul(path.as_os_str());
        Dacl::read(&wide, path).unwrap().aces(path).unwrap().aces
    }

    /// Only junctions that lead to a directory policy path or into one count: each one of a
    /// chain that ends there, not a junction to a directory above a policy path.
    #[test]
    fn final_junctions_are_the_names_of_directory_policy_paths() {
        let root = directory("final-junctions");
        fs::create_dir_all(root.join("real")).unwrap();
        fs::create_dir_all(root.join("other/sub")).unwrap();
        junction(&root.join("j2"), &root.join("real"));
        junction(&root.join("j1"), &root.join("j2"));
        junction(&root.join("above"), &root.join("other"));
        // A directory inside a directory policy path, reached through a junction of its own.
        fs::create_dir_all(root.join("real/inner")).unwrap();
        junction(&root.join("inner"), &root.join("real").join("inner"));
        fs::write(root.join("real/inner/file"), b"x").unwrap();
        let policy = resolved(&[
            root.join("j1"),
            root.join("above/sub"),
            root.join("inner/file"),
        ]);
        let mut found: Vec<String> = final_junctions(&policy)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(found, ["inner", "j1", "j2"]);
        for name in ["j1", "j2", "above", "inner"] {
            fs::remove_dir(root.join(name)).unwrap();
        }
        fs::remove_dir_all(&root).unwrap();
    }

    /// The grant is one entry on the junction itself: read, no inheritance, for a capability of
    /// its own. The target's permissions stay as they were, a second grant adds nothing, and the
    /// removal takes the entry back.
    #[test]
    fn a_junction_grant_is_one_read_entry_on_the_junction_only() {
        let root = directory("junction-grant");
        fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        junction(&link, &root.join("real"));
        let policy = resolved(std::slice::from_ref(&link));
        let target_before = target_entries(&root.join("real"));
        let junction_before = junction_entries(&link);

        let capabilities = grant_junctions("sandy.acl-junction-test", &policy);
        assert_eq!(capabilities.len(), 1);
        let after = junction_entries(&link);
        let added: Vec<_> = after
            .iter()
            .filter(|entry| !junction_before.contains(entry))
            .collect();
        assert_eq!(added.len(), 1, "{after:?}");
        let (kind, flags, mask, sid) = added[0];
        assert_eq!(*kind, AceKind::Allow);
        assert_eq!(*flags, 0, "the entry must not be inherited by anything");
        assert_eq!(*mask, JUNCTION_MASK);
        assert_eq!(sid.as_slice(), capabilities[0].bytes());
        assert_eq!(map_generic(*mask) & !crate::access::FILE_GENERIC_READ, 0);
        assert_eq!(target_entries(&root.join("real")), target_before);

        let again = grant_junctions("sandy.acl-junction-test", &policy);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].bytes(), capabilities[0].bytes());
        assert_eq!(junction_entries(&link), after);

        revoke_junctions("sandy.acl-junction-test", &policy);
        assert_eq!(junction_entries(&link), junction_before);
        assert_eq!(target_entries(&root.join("real")), target_before);
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    fn icacls(path: &Path, args: &[&str]) {
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(args)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "icacls {} {args:?}", path.display());
    }

    /// Writing the junction's DACL must not reach the tree it leads to: the target and the
    /// files and directories in it keep their permissions, also when the junction's parent
    /// hands down entries that the target's parent does not. Windows propagates inheritable
    /// entries when a DACL is written through its security API, so a write that followed the
    /// junction would show here.
    #[test]
    fn a_junction_grant_leaves_the_tree_behind_it_alone() {
        let root = directory("junction-tree");
        let (links, targets) = (root.join("links"), root.join("targets"));
        fs::create_dir_all(targets.join("real/sub")).unwrap();
        fs::create_dir_all(&links).unwrap();
        fs::write(targets.join("real/file"), b"x").unwrap();
        // Distinct inheritable entries above the junction and above the target.
        icacls(&links, &["/grant", "*S-1-5-32-551:(OI)(CI)(R)"]);
        icacls(&targets, &["/grant", "*S-1-5-32-546:(OI)(CI)(R)"]);
        let link = links.join("link");
        junction(&link, &targets.join("real"));
        let policy = resolved(std::slice::from_ref(&link));
        let tree = [
            targets.join("real"),
            targets.join("real/file"),
            targets.join("real/sub"),
        ];
        let before: Vec<_> = tree.iter().map(|path| target_entries(path)).collect();
        // The setup the test rests on: the junction inherits what its parent hands down, and the
        // target does not.
        let backup_operators =
            Sid::from_bytes(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 39, 2, 0, 0]).unwrap();
        let inherits = |entries: &[(AceKind, u8, u32, Vec<u8>)]| {
            entries.iter().any(|(_, flags, _, sid)| {
                flags & INHERITED_ACE != 0 && sid.as_slice() == backup_operators.bytes()
            })
        };
        assert!(inherits(&junction_entries(&link)));
        assert!(!before.iter().any(|entries| inherits(entries)));

        assert_eq!(grant_junctions("sandy.acl-junction-test", &policy).len(), 1);
        let granted: Vec<_> = tree.iter().map(|path| target_entries(path)).collect();
        assert_eq!(granted, before);
        revoke_junctions("sandy.acl-junction-test", &policy);
        let revoked: Vec<_> = tree.iter().map(|path| target_entries(path)).collect();
        assert_eq!(revoked, before);
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// A junction every AppContainer may read already gets no entry and no capability.
    #[test]
    fn a_junction_every_appcontainer_reads_gets_nothing() {
        let root = directory("junction-packages");
        fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        junction(&link, &root.join("real"));
        icacls(&link, &["/L", "/grant", "*S-1-15-2-1:(R)"]);
        let policy = resolved(std::slice::from_ref(&link));
        let before = junction_entries(&link);
        assert!(grant_junctions("sandy.acl-junction-test", &policy).is_empty());
        assert_eq!(junction_entries(&link), before);
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// The DACL of `object` in SDDL, with its control flags (`P`, `AI`), every entry, the
    /// conditions of conditional entries, and the order.
    fn sddl(object: Object<'_>, display: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        let dacl = Dacl::read_object(object, display).unwrap();
        let mut text: windows_sys::core::PWSTR = ptr::null_mut();
        // SAFETY: the descriptor is valid; text receives a LocalAlloc'd string.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                dacl.descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        let text = LocalBox(text.cast());
        // SAFETY: the string is NUL-terminated.
        let len = (0..)
            .take_while(|&i| unsafe { *text.0.cast::<u16>().add(i) } != 0)
            .count();
        // SAFETY: len units are readable.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text.0.cast::<u16>(), len) })
            .unwrap()
    }

    /// Replaces the DACL of `object` with the one in `text`.
    fn set_sddl(object: Object<'_>, text: &str) {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: wide is NUL-terminated; descriptor receives a LocalAlloc'd descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{text}: {}", std::io::Error::last_os_error());
        let descriptor = LocalBox(descriptor);
        let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
        // SAFETY: the descriptor is valid; the out pointers are valid.
        let found = unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
        };
        assert_ne!(found, 0);
        let protection = if text.starts_with("D:P") {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let error = match object {
            // SAFETY: path is NUL-terminated and acl is a valid ACL inside the descriptor.
            Object::Path(path) => unsafe {
                SetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | protection,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            // SAFETY: the handle is open with WRITE_DAC and acl is valid.
            Object::Handle(handle) => unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | protection,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
        };
        assert_eq!(error, 0, "{text}");
    }

    /// DACLs of the shapes that sandy's merge must keep as they are: inherited entries,
    /// protection, automatic inheritance, a conditional entry, and an order that is not the
    /// canonical one (an allow before a deny). `None` keeps the DACL the junction or directory
    /// inherits.
    const SHAPES: &[(&str, Option<&str>)] = &[
        ("inherited", None),
        ("protected", Some("D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;OW)")),
        (
            "auto-inherited",
            Some("D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;OW)"),
        ),
        (
            "conditional",
            Some("D:P(A;;FA;;;BA)(A;;FA;;;SY)(XA;;FR;;;WD;(@User.Title == \"x\"))"),
        ),
        (
            "non-canonical",
            Some("D:P(A;;FA;;;BA)(A;;FR;;;WD)(D;;FR;;;BG)(A;;FA;;;SY)"),
        ),
    ];

    /// The list as Windows' security API writes it back: it sets the flag of automatic
    /// inheritance (`AI`) on every list it writes, as `icacls` and Explorer do, so a list
    /// without it gains it and nothing else.
    fn as_written(list: &str) -> String {
        if let Some(rest) = list.strip_prefix("D:P(") {
            format!("D:PAI({rest}")
        } else if let Some(rest) = list.strip_prefix("D:(") {
            format!("D:AI({rest}")
        } else {
            list.to_string()
        }
    }

    /// The list holds the entries of the shape, in its order (Windows writes SDDL keywords in
    /// capitals and adds `AI` to a protected list).
    fn assert_shape(text: &Option<&str>, list: &str) {
        let Some(text) = text else {
            assert!(list.contains("ID;"), "no inherited entry: {list}");
            return;
        };
        let entries = &text[text.find('(').unwrap()..];
        assert!(
            list.to_lowercase().ends_with(&entries.to_lowercase()),
            "{list} lacks {entries}"
        );
    }

    /// A grant adds its one entry and changes nothing else in the list, and the removal gives
    /// the list back as it was, for every shape, on a junction.
    #[test]
    fn a_junction_grant_keeps_every_shape_of_the_list() {
        for (shape, text) in SHAPES {
            let root = directory(&format!("junction-shape-{shape}"));
            fs::create_dir_all(root.join("real")).unwrap();
            let link = root.join("link");
            junction(&link, &root.join("real"));
            let wide = wide_nul(link.as_os_str());
            let handle = || {
                open_junction(&wide, &link, READ_CONTROL | WRITE_DAC)
                    .unwrap()
                    .unwrap()
            };
            if let Some(text) = text {
                let opened = handle();
                set_sddl(Object::Handle(opened.raw()), text);
            }
            let opened = handle();
            let before = sddl(Object::Handle(opened.raw()), &link);
            drop(opened);
            assert_shape(text, &before);
            let policy = resolved(std::slice::from_ref(&link));
            let capabilities = grant_junctions("sandy.acl-junction-test", &policy);
            assert_eq!(capabilities.len(), 1, "{shape}");
            let entry = format!(
                "(A;;FR;;;{})",
                crate::access::sid_string(capabilities[0].bytes())
            );
            let opened = handle();
            let after = sddl(Object::Handle(opened.raw()), &link);
            drop(opened);
            assert_eq!(after.matches(&entry).count(), 1, "{shape}: {after}");
            assert_eq!(
                after.replacen(&entry, "", 1),
                as_written(&before),
                "{shape}"
            );
            assert!(revoke_junctions("sandy.acl-junction-test", &policy).is_empty());
            let opened = handle();
            assert_eq!(
                sddl(Object::Handle(opened.raw()), &link),
                as_written(&before),
                "{shape}"
            );
            drop(opened);
            fs::remove_dir(&link).unwrap();
            fs::remove_dir_all(&root).unwrap();
        }
    }

    /// The same for the grant on a directory policy path, which writes through the path.
    #[test]
    fn a_path_grant_keeps_every_shape_of_the_list() {
        for (shape, text) in SHAPES {
            let dir = directory(&format!("path-shape-{shape}"));
            let wide = wide_nul(dir.as_os_str());
            if let Some(text) = text {
                set_sddl(Object::Path(&wide), text);
            }
            let before = sddl(Object::Path(&wide), &dir);
            assert_shape(text, &before);
            let rule = PathRule {
                path: dir.clone(),
                access: PathAccess::Read,
                is_dir: true,
            };
            let capability = grant("sandy.acl-shape-test", &rule, &[]).unwrap();
            let entry = format!(
                "(A;OICI;FR;;;{})",
                crate::access::sid_string(capability.bytes())
            );
            let after = sddl(Object::Path(&wide), &dir);
            assert_eq!(after.matches(&entry).count(), 1, "{shape}: {after}");
            assert_eq!(
                after.replacen(&entry, "", 1),
                as_written(&before),
                "{shape}"
            );
            revoke("sandy.acl-shape-test", &rule).unwrap();
            assert_eq!(
                sddl(Object::Path(&wide), &dir),
                as_written(&before),
                "{shape}"
            );
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    fn owned(opened: &OpenJunction, link: &Path) -> bool {
        let token = TokenSids::of_this_process().unwrap();
        owner_of(opened, link)
            .unwrap()
            .is_some_and(|owner| token.owners.contains(&owner))
    }

    /// A junction of another owner stays as it is, also for a token that could change it (the
    /// test runs elevated, with SeRestorePrivilege), and `check` names the reason.
    #[test]
    fn a_junction_of_another_owner_is_left_alone() {
        let root = directory("junction-owner");
        fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        junction(&link, &root.join("real"));
        icacls(&link, &["/L", "/setowner", "*S-1-5-18"]);
        let wide = wide_nul(link.as_os_str());
        let opened = open_junction(&wide, &link, READ_CONTROL).unwrap().unwrap();
        assert!(!owned(&opened, &link));
        // Control: this token may change the junction's permissions, so only the owner keeps
        // sandy from it.
        assert!(
            open_junction(&wide, &link, READ_CONTROL | WRITE_DAC)
                .unwrap()
                .is_some()
        );
        let before = sddl(Object::Handle(opened.raw()), &link);
        drop(opened);
        let policy = resolved(std::slice::from_ref(&link));
        assert!(grant_junctions("sandy.acl-junction-test", &policy).is_empty());
        let opened = open_junction(&wide, &link, READ_CONTROL).unwrap().unwrap();
        assert_eq!(sddl(Object::Handle(opened.raw()), &link), before);
        drop(opened);
        let closed = closed_junctions("sandy.acl-junction-test", &policy);
        assert_eq!(closed.len(), 1, "{closed:?}");
        assert!(
            closed[0].reason.contains("belongs to S-1-5-18"),
            "{closed:?}"
        );
        assert!(closed[0].remedy.contains("owner"), "{closed:?}");
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// A junction this user made is this user's, which is what the other tests rely on.
    #[test]
    fn a_junction_this_user_made_is_owned_by_this_user() {
        let root = directory("junction-own");
        fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        junction(&link, &root.join("real"));
        let opened = open_junction(&wide_nul(link.as_os_str()), &link, READ_CONTROL)
            .unwrap()
            .unwrap();
        assert!(owned(&opened, &link));
        drop(opened);
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// A deny entry for the user's own group keeps the program out of the junction whatever
    /// sandy adds, so sandy adds nothing and `check` names the deny entry.
    #[test]
    fn a_junction_denied_to_the_user_gets_nothing() {
        let root = directory("junction-deny");
        fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        junction(&link, &root.join("real"));
        // Authenticated Users, which every logged-on token holds.
        icacls(&link, &["/L", "/deny", "*S-1-5-11:(RD)"]);
        let policy = resolved(std::slice::from_ref(&link));
        let wide = wide_nul(link.as_os_str());
        let opened = open_junction(&wide, &link, READ_CONTROL).unwrap().unwrap();
        let before = sddl(Object::Handle(opened.raw()), &link);
        drop(opened);
        assert!(grant_junctions("sandy.acl-junction-test", &policy).is_empty());
        let opened = open_junction(&wide, &link, READ_CONTROL).unwrap().unwrap();
        assert_eq!(sddl(Object::Handle(opened.raw()), &link), before);
        drop(opened);
        let closed = closed_junctions("sandy.acl-junction-test", &policy);
        assert_eq!(closed.len(), 1, "{closed:?}");
        assert!(
            closed[0].reason.contains("deny entry for S-1-5-11"),
            "{closed:?}"
        );
        icacls(&link, &["/L", "/remove:d", "*S-1-5-11"]);
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
