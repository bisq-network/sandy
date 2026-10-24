use std::net::SocketAddr;
#[cfg(unix)]
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::plan::Requirement;
use crate::policy::{
    ChildProcesses, EnvironmentPolicy, ExposedPort, ForwardedPort, NetworkAccess, PathMetadata,
    Policy, PolicyError, ProcessPolicy, SignalScope, SystemAccess, WindowsPolicy,
};

/// Access to one path and everything beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathAccess {
    Read,
    ReadExec,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Canonical absolute path: symbolic links resolved, so backends that match on paths
    /// (macOS) and backends that match on inodes (Linux) see the same object.
    pub path: PathBuf,
    pub access: PathAccess,
    pub is_dir: bool,
}

/// A validated policy with canonical paths, ready for a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    /// One rule per path, sorted by path. No path is both writable and executable, also not
    /// through nesting.
    pub paths: Vec<PathRule>,
    /// Canonical path of the target executable, when the policy was resolved for one.
    pub program: Option<PathBuf>,
    pub system: SystemAccess,
    pub ip: NetworkAccess,
    pub unix_sockets: NetworkAccess,
    pub expose: Vec<ExposedPort>,
    pub forward: Vec<ForwardedPort>,
    pub signals: SignalScope,
    pub children: ChildProcesses,
    pub end_with_parent: bool,
    pub path_metadata: PathMetadata,
    pub environment: EnvironmentPolicy,
    pub windows: WindowsPolicy,
}

impl ResolvedPolicy {
    /// Validates `policy` and resolves its paths. `program` is the target executable; it gets
    /// read and execute access to the file itself.
    pub fn resolve(policy: &Policy, program: Option<&Path>) -> Result<Self, PolicyError> {
        let filesystem = &policy.filesystem;
        let mut rules = Vec::new();
        let mut traversals = Vec::new();
        for (paths, access) in [
            (&filesystem.read, PathAccess::Read),
            (&filesystem.read_exec, PathAccess::ReadExec),
            (&filesystem.read_write, PathAccess::ReadWrite),
        ] {
            for path in paths {
                let (rule, traversal) = resolve_path(path, access)?;
                rules.push(rule);
                traversals.push(traversal);
            }
        }
        let mut program_path = None;
        if let Some(program) = program {
            let (rule, traversal) = resolve_path(program, PathAccess::ReadExec)?;
            if rule.is_dir {
                return Err(PolicyError::ProgramNotAFile(rule.path));
            }
            program_path = Some(rule.path.clone());
            rules.push(rule);
            traversals.push(traversal);
        }

        let mounts = Mounts::read()?;
        let paths = merge(rules)?;
        check_writable_not_executable(&paths, &mounts)?;
        check_nothing_inside_writable(&paths, &mounts)?;
        check_not_resolved_through_writable(&paths, &traversals, &mounts)?;
        check_no_writable_second_name(&paths)?;
        validate_environment(&policy.environment)?;
        validate_expose(&policy.network.expose, policy.network.ip)?;
        validate_children(&policy.process, policy.network.unix_sockets)?;
        if policy.process.end_with_parent && policy.process.signals != SignalScope::Isolated {
            return Err(PolicyError::EndWithParentNeedsIsolatedSignals);
        }
        validate_forward(&policy.network.forward, policy.network.ip)?;
        validate_relay_addresses(&policy.network.expose, &policy.network.forward)?;

        Ok(ResolvedPolicy {
            paths,
            program: program_path,
            system: filesystem.system,
            ip: policy.network.ip,
            unix_sockets: policy.network.unix_sockets,
            expose: policy.network.expose.clone(),
            forward: policy.network.forward.clone(),
            signals: policy.process.signals,
            children: policy.process.children,
            end_with_parent: policy.process.end_with_parent,
            path_metadata: policy.linux.path_metadata,
            environment: policy.environment.clone(),
            windows: policy.windows.clone(),
        })
    }

    /// Everything the backend must enforce for this policy. The baseline items apply to every
    /// policy; the others follow from what the policy denies.
    pub fn requirements(&self) -> Vec<Requirement> {
        let mut requirements = vec![
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
            Requirement::ProcessMemoryIsolated,
            Requirement::InheritedHandlesClosed,
            Requirement::EnvironmentControlled,
        ];
        if self.ip == NetworkAccess::None {
            requirements.push(Requirement::IpNetworkDenied);
        }
        if self.unix_sockets == NetworkAccess::None {
            requirements.push(Requirement::UnixSocketsDenied);
        }
        if self.signals == SignalScope::Isolated {
            requirements.push(Requirement::SignalsIsolated);
        }
        match self.children {
            ChildProcesses::Allowed => {}
            ChildProcesses::None => requirements.push(Requirement::ChildProcessesDenied),
            ChildProcesses::Contained => requirements.push(Requirement::ChildProcessesContained),
        }
        if self.end_with_parent {
            requirements.push(Requirement::EndsWithParent);
        }
        if self.path_metadata == PathMetadata::Deny {
            requirements.push(Requirement::MetadataConfined);
        }
        if !self.expose.is_empty() {
            requirements.push(Requirement::ExposedPortsRelayed);
        }
        if !self.forward.is_empty() {
            requirements.push(Requirement::ForwardedPortsRelayed);
        }
        requirements
    }

    /// Why the kernel could not execute the program: it is a script whose interpreter the backend
    /// does not let it execute. The kernel reads the `#!` line of the program and executes the
    /// interpreter named there, which needs execute access of its own; `levels` is how many such
    /// lines the kernel follows, and `executable` are the paths the backend's plan executes, each
    /// covering everything beneath it. A backend reports this before it starts the program,
    /// because the `execve` would otherwise fail with "Permission denied" after the sandbox is
    /// already in place.
    pub fn interpreter_problem(&self, levels: usize, executable: &[PathBuf]) -> Option<String> {
        let mounts = Mounts::read().ok()?;
        let mut script = self.program.clone()?;
        for _ in 0..levels {
            // A file that cannot be read, or a `#!` line without a path, is left to the execve,
            // which reports its own error.
            let interpreter = shebang(&script)?.canonicalize().ok()?;
            if !executable
                .iter()
                .any(|allowed| is_within(&interpreter, allowed, &mounts))
            {
                return Some(format!(
                    "{} is a script and the kernel executes its interpreter {}, which no \
                     read_exec path covers",
                    script.display(),
                    interpreter.display()
                ));
            }
            script = interpreter;
        }
        None
    }

    /// The settings of this policy that give up part of the isolation, each with what the program
    /// gains by it. sandy enforces them as written; these are advice for whoever wrote the policy,
    /// which `sandy check` prints. `home` is the user's home directory, which only the caller can
    /// name because the variable that holds it differs per platform.
    ///
    /// A plain path comparison is enough here: the rules that must hold whatever the program does
    /// compare file identity instead (`is_within`).
    pub fn warnings(&self, home: Option<&Path>) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.unix_sockets == NetworkAccess::All {
            warnings.push(
                "unix_sockets = \"all\" gives up most of the isolation: the program can reach \
                 every local service that listens on a Unix socket, and some of them start \
                 programs or read files outside the policy (on Linux the D-Bus session bus and \
                 the systemd user manager, on macOS the DNS resolver)"
                    .to_string(),
            );
        }
        if self.signals == SignalScope::Any {
            warnings.push(
                "signals = \"any\" lets the program signal every process of this user, so it can \
                 stop or kill programs outside the sandbox; signals = \"isolated\" limits signals \
                 to the sandbox"
                    .to_string(),
            );
        }
        if self.path_metadata == PathMetadata::Allow {
            warnings.push(
                "path_metadata = \"allow\" lets the program change the permissions, owner, \
                 timestamps and extended attributes of every file this user owns on Linux, also \
                 outside the policy paths"
                    .to_string(),
            );
        }
        if let Some(home) = home {
            let writable = self
                .paths
                .iter()
                .filter(|rule| rule.access == PathAccess::ReadWrite);
            for rule in writable {
                if home.starts_with(&rule.path) {
                    warnings.push(format!(
                        "the writable path {} holds the home directory {}, so the program can \
                         change shell startup files, autostart entries and the configuration of \
                         other programs, and what it writes there runs outside the sandbox",
                        rule.path.display(),
                        home.display()
                    ));
                }
            }
        }
        warnings
    }

    /// sandy's own executable and the policy file are trusted: the program must not be able to
    /// change them for the next start (see "Threat model" in DESIGN.md). They are not policy
    /// paths, so rules 3 and 4 do not cover them; this applies the same checks. The caller
    /// passes the paths as it knows them, including the one it was executed under, because that
    /// can be a symbolic link to the file `current_exe` reports.
    pub fn check_trusted(&self, files: &[PathBuf]) -> Result<(), PolicyError> {
        let writable: Vec<&PathRule> = self
            .paths
            .iter()
            .filter(|rule| rule.access == PathAccess::ReadWrite)
            .collect();
        if writable.is_empty() {
            return Ok(());
        }
        let mounts = Mounts::read()?;
        let mut canonical = Vec::with_capacity(files.len());
        for file in files {
            let (rule, traversal) = resolve_path(file, PathAccess::Read)?;
            for w in &writable {
                // The entry that is the writable path itself is not inside it: replacing it
                // needs write access to its parent, as in `check_not_resolved_through_writable`.
                let reached = is_within(&rule.path, &w.path, &mounts)
                    .then_some(&rule.path)
                    .or_else(|| {
                        traversal
                            .entries
                            .iter()
                            .find(|entry| **entry != w.path && is_within(entry, &w.path, &mounts))
                    });
                if let Some(reached) = reached {
                    return Err(PolicyError::TrustedFileWritable {
                        path: rule.path.clone(),
                        through: reached.clone(),
                        writable: w.path.clone(),
                    });
                }
            }
            canonical.push(rule.path);
        }
        check_no_writable_trusted_name(&canonical, &self.paths)
    }
}

/// The interpreter of a `#!` line: the first word after `#!`, or `None` when `file` does not
/// start with one. The kernel reads only the beginning of the file (256 bytes on Linux) and the
/// first line of it, and takes everything after the interpreter as one argument.
fn shebang(file: &Path) -> Option<PathBuf> {
    use std::io::Read;

    /// As Linux (BINPRM_BUF_SIZE). macOS reads less.
    const HEADER: usize = 256;

    let mut header = Vec::with_capacity(HEADER);
    std::fs::File::open(file)
        .and_then(|file| file.take(HEADER as u64).read_to_end(&mut header))
        .ok()?;
    let line = header.strip_prefix(b"#!")?;
    // Without a newline the kernel uses what it read, so the end of the header ends the line.
    let end = line.iter().position(|byte| *byte == b'\n');
    let line = &line[..end.unwrap_or(line.len())];
    let word = line
        .split(|byte| matches!(byte, b' ' | b'\t'))
        .find(|word| !word.is_empty())?;
    Some(path_from_bytes(word))
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

/// Windows has no `#!`; a backend there follows no level.
#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

/// The directory entries that resolving one policy path passes, and the path as given.
struct Traversal {
    path: PathBuf,
    entries: Vec<PathBuf>,
}

fn resolve_path(path: &Path, access: PathAccess) -> Result<(PathRule, Traversal), PolicyError> {
    if !path.is_absolute() {
        return Err(PolicyError::RelativePath(path.to_path_buf()));
    }
    let not_found = |source| PolicyError::PathNotFound {
        path: path.to_path_buf(),
        source,
    };
    let canonical = path.canonicalize().map_err(not_found)?;
    let metadata = canonical.metadata().map_err(not_found)?;
    let traversal = Traversal {
        path: path.to_path_buf(),
        entries: traversed_entries(path).map_err(not_found)?,
    };
    let rule = PathRule {
        path: canonical,
        access,
        is_dir: metadata.is_dir(),
    };
    Ok((rule, traversal))
}

/// The directory entries that resolving `path` passes, each as its canonical parent plus its
/// name: every component of the path and of every symbolic link on the way, in order. Whoever
/// can write the directory of one of them can make the path resolve to another object.
#[cfg(unix)]
fn traversed_entries(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;

    /// As the kernel's limit for one path lookup (MAXSYMLINKS).
    const MAX_LINKS: usize = 40;
    fn queue_front(pending: &mut VecDeque<OsString>, path: &Path) {
        for component in path.components().rev() {
            match component {
                Component::Normal(name) => pending.push_front(name.to_os_string()),
                Component::ParentDir => pending.push_front(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    }

    let mut entries = Vec::new();
    let mut resolved = PathBuf::from("/");
    let mut pending = VecDeque::new();
    queue_front(&mut pending, path);
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        let entry = resolved.join(&name);
        let metadata = std::fs::symlink_metadata(&entry)?;
        entries.push(entry.clone());
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > MAX_LINKS {
                return Err(std::io::Error::other("too many levels of symbolic links"));
            }
            let target = std::fs::read_link(&entry)?;
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            }
            queue_front(&mut pending, &target);
        } else {
            resolved = entry;
        }
    }
    Ok(entries)
}

/// The Windows backend refuses links below a granted path itself (see `docs/windows.md`).
#[cfg(not(unix))]
fn traversed_entries(_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

/// Whether `inner` is `outer` or lies beneath it. Besides the path, on Unix the identity of the
/// file (device and inode) of `outer` is compared with `inner` and each of its ancestors, so one
/// directory reachable under two paths (a bind mount, a macOS firmlink) counts as one. On Linux
/// the physical location is compared as well, which also sees an alias of a subdirectory of
/// `outer`, which has no ancestor with `outer`'s identity.
fn is_within(inner: &Path, outer: &Path, mounts: &Mounts) -> bool {
    inner.starts_with(outer)
        || same_object_among_ancestors(inner, outer)
        || same_physical_location(inner, outer, mounts)
}

#[cfg(unix)]
fn same_object_among_ancestors(inner: &Path, outer: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let identity = |path: &Path| path.metadata().ok().map(|m| (m.dev(), m.ino()));
    let Some(outer) = identity(outer) else {
        return false;
    };
    inner
        .ancestors()
        .any(|ancestor| identity(ancestor) == Some(outer))
}

#[cfg(not(unix))]
fn same_object_among_ancestors(_inner: &Path, _outer: &Path) -> bool {
    // TODO: Windows has no traversal entries and no file identity here yet. The identity is
    // FILE_ID_INFO, which only the Windows backend can read; it has to reach sandy-core through
    // a backend hook. See "Links and identity" in docs/windows.md.
    false
}

/// Where the file systems of this host are mounted. A path says which directory it leads to but
/// not where that directory lies: a bind mount shows one directory under a second path that
/// shares no ancestor with the first. The physical location, the path inside the file system
/// that holds it, is the same for both spellings.
#[cfg(target_os = "linux")]
struct Mounts {
    /// Mount point and the path of the mount's root inside its file system, in mount order.
    entries: Vec<(PathBuf, PathBuf)>,
}

#[cfg(target_os = "linux")]
impl Mounts {
    const TABLE: &'static str = "/proc/self/mountinfo";

    /// sandy refuses the policy when the table is unreadable instead of falling back to the
    /// weaker path comparison. Nothing is lost: the Linux backend already needs /proc to count
    /// its threads before it applies Landlock, so a host without /proc cannot enforce a policy
    /// anyway.
    fn read() -> Result<Mounts, PolicyError> {
        let text = std::fs::read(Self::TABLE).map_err(|source| PolicyError::Unreadable {
            path: PathBuf::from(Self::TABLE),
            source,
        })?;
        Ok(Mounts::parse(&text))
    }

    /// Fields 4 and 5 of each line are the mount root and the mount point (`proc(5)`).
    fn parse(table: &[u8]) -> Mounts {
        let entries = table
            .split(|byte| *byte == b'\n')
            .filter_map(|line| {
                let mut fields = line.split(|byte| *byte == b' ');
                let root = unescape(fields.nth(3)?);
                let point = unescape(fields.next()?);
                Some((point, root))
            })
            .collect();
        Mounts { entries }
    }

    /// The location of `path` inside the file system that holds it, or `None` when no mount
    /// matches. The mount is the longest mount point that is a prefix of `path` and that
    /// `holds_path` accepts; a mount point on another file system is one that a later mount
    /// covers. `path` must have no symbolic links in it, so that mount points can be compared as
    /// prefixes.
    fn physical(&self, path: &Path, holds_path: impl Fn(&Path) -> bool) -> Option<PathBuf> {
        let mut best: Option<&(PathBuf, PathBuf)> = None;
        for entry in &self.entries {
            let (point, _) = entry;
            let longer =
                best.is_some_and(|(best, _)| best.as_os_str().len() > point.as_os_str().len());
            if longer || !path.starts_with(point) || !holds_path(point) {
                continue;
            }
            best = Some(entry);
        }
        let (point, root) = best?;
        Some(root.join(path.strip_prefix(point).ok()?))
    }
}

/// Reverses the octal escapes `/proc/self/mountinfo` uses for space, tab, newline and backslash.
#[cfg(target_os = "linux")]
fn unescape(field: &[u8]) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let octal = |byte: &u8| (b'0'..=b'7').contains(byte);
    let mut name = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((byte, tail)) = rest.split_first() {
        match tail.get(..3) {
            Some(digits) if *byte == b'\\' && digits.iter().all(octal) => {
                let value = digits
                    .iter()
                    .fold(0u32, |value, digit| value * 8 + u32::from(digit - b'0'));
                name.push(value as u8);
                rest = &tail[3..];
            }
            _ => {
                name.push(*byte);
                rest = tail;
            }
        }
    }
    PathBuf::from(OsString::from_vec(name))
}

#[cfg(target_os = "linux")]
fn device_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(path.metadata().ok()?.dev())
}

/// `path` with its directory resolved but its own name kept, so that a symbolic link is compared
/// where it lies and not where it leads, as `traversed_entries` spells its entries.
#[cfg(target_os = "linux")]
fn canonical_name(path: &Path) -> Option<PathBuf> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Some(parent.canonicalize().ok()?.join(name)),
        _ => path.canonicalize().ok(),
    }
}

/// Whether `inner` lies at or below `outer` inside the file system that holds them, whatever
/// mounts the two paths lead through.
#[cfg(target_os = "linux")]
fn same_physical_location(inner: &Path, outer: &Path, mounts: &Mounts) -> bool {
    use std::os::unix::fs::MetadataExt;

    let location = |path: &Path| {
        let path = canonical_name(path)?;
        let device = path.symlink_metadata().ok()?.dev();
        let physical = mounts.physical(&path, |point| device_of(point) == Some(device))?;
        Some((device, physical))
    };
    let (Some(inner), Some(outer)) = (location(inner), location(outer)) else {
        return false;
    };
    inner.0 == outer.0 && inner.1.starts_with(&outer.1)
}

/// Only Linux has bind mounts. A macOS firmlink aliases a whole volume, which the identity of
/// the ancestors already catches, and Windows is covered by `same_object_among_ancestors`.
#[cfg(not(target_os = "linux"))]
struct Mounts;

#[cfg(not(target_os = "linux"))]
impl Mounts {
    fn read() -> Result<Mounts, PolicyError> {
        Ok(Mounts)
    }
}

#[cfg(not(target_os = "linux"))]
fn same_physical_location(_inner: &Path, _outer: &Path, _mounts: &Mounts) -> bool {
    false
}

/// How a writable and an executable path lead to one file, for the error message: both lead to
/// the same place in the file system, through nesting or an alias of a directory.
const OVERLAPS: &str = "overlaps";

/// Keeps one rule per path. Read is contained in both other levels; read-exec and read-write on
/// the same path is a conflict that `check_writable_not_executable` reports.
fn merge(mut rules: Vec<PathRule>) -> Result<Vec<PathRule>, PolicyError> {
    rules.sort_by(|a, b| a.path.cmp(&b.path).then(a.access.cmp(&b.access)));
    let mut merged: Vec<PathRule> = Vec::with_capacity(rules.len());
    for rule in rules {
        match merged.last_mut() {
            Some(last) if last.path == rule.path => {
                let pair = (last.access, rule.access);
                if pair == (PathAccess::ReadExec, PathAccess::ReadWrite) {
                    return Err(PolicyError::WritableAndExecutable {
                        writable: rule.path,
                        executable: last.path.clone(),
                        relation: OVERLAPS,
                    });
                }
                last.access = last.access.max(rule.access);
            }
            _ => merged.push(rule),
        }
    }
    Ok(merged)
}

/// Rules apply to everything beneath a path, so a writable directory inside an executable one
/// (or the reverse) is writable and executable. The target could then drop a program that a
/// process outside the sandbox later runs.
fn check_writable_not_executable(rules: &[PathRule], mounts: &Mounts) -> Result<(), PolicyError> {
    let writable = rules.iter().filter(|r| r.access == PathAccess::ReadWrite);
    for w in writable {
        let executable = rules.iter().filter(|r| r.access == PathAccess::ReadExec);
        for x in executable {
            if is_within(&w.path, &x.path, mounts) || is_within(&x.path, &w.path, mounts) {
                return Err(PolicyError::WritableAndExecutable {
                    writable: w.path.clone(),
                    executable: x.path.clone(),
                    relation: OVERLAPS,
                });
            }
        }
    }
    Ok(())
}

/// sandy resolves symbolic links in policy paths at every start. A policy path inside a writable
/// path could be replaced with a symbolic link by the target, and the next start would then grant
/// access to wherever that link points.
fn check_nothing_inside_writable(rules: &[PathRule], mounts: &Mounts) -> Result<(), PolicyError> {
    let writable = rules.iter().filter(|r| r.access == PathAccess::ReadWrite);
    for w in writable {
        let nested = rules
            .iter()
            .find(|r| r.path != w.path && is_within(&r.path, &w.path, mounts));
        if let Some(nested) = nested {
            return Err(PolicyError::InsideWritable {
                path: nested.path.clone(),
                writable: w.path.clone(),
            });
        }
    }
    Ok(())
}

/// The same reason as `check_nothing_inside_writable`, for the way to a path: a policy path that
/// resolves through a symbolic link, or any other entry, inside a writable path would resolve to
/// wherever the program points that entry at the next start.
fn check_not_resolved_through_writable(
    rules: &[PathRule],
    traversals: &[Traversal],
    mounts: &Mounts,
) -> Result<(), PolicyError> {
    let writable = rules.iter().filter(|r| r.access == PathAccess::ReadWrite);
    for w in writable {
        for traversal in traversals {
            let inside = traversal
                .entries
                .iter()
                .find(|entry| **entry != w.path && is_within(entry, &w.path, mounts));
            if let Some(entry) = inside {
                return Err(PolicyError::ResolvedThroughWritable {
                    path: traversal.path.clone(),
                    entry: entry.clone(),
                    writable: w.path.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Identity of a file. Two names of one file, a hard link for example, share device and inode.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    device: u64,
    inode: u64,
}

/// A name inside a writable path, and the writable path that holds it.
#[cfg(unix)]
struct WritableName {
    path: PathBuf,
    writable: PathBuf,
}

/// The identity of a regular file that has more than one name, else `None`. A file with one name
/// is reachable only where the policy says it is.
#[cfg(unix)]
fn second_name_candidate(metadata: &std::fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    (metadata.is_file() && metadata.nlink() > 1).then(|| FileId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Rule 3 by identity: a file that also has a name inside a writable path is writable, whichever
/// name the policy grants execute access to. Landlock and Seatbelt check the name a call uses,
/// so the program could rewrite the file through the writable name and still run it through the
/// executable one. The program cannot create such a link itself, so this start-time check holds
/// against it; links that processes outside the sandbox make while it runs are not covered.
#[cfg(unix)]
fn check_no_writable_second_name(rules: &[PathRule]) -> Result<(), PolicyError> {
    let executable: Vec<&PathRule> = rules
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadExec)
        .collect();
    let files: Vec<(&PathRule, FileId)> = executable
        .iter()
        .filter(|rule| !rule.is_dir)
        .filter_map(|rule| {
            let metadata = rule.path.symlink_metadata().ok()?;
            Some((*rule, second_name_candidate(&metadata)?))
        })
        .collect();
    let directories: Vec<&&PathRule> = executable.iter().filter(|rule| rule.is_dir).collect();
    if files.is_empty() && directories.is_empty() {
        return Ok(());
    }
    // Hard links are rare, so the writable paths, which are usually the smaller trees, are
    // walked first; the executable trees are walked only when they can hold the other name.
    let writable = writable_names(rules)?;
    if writable.is_empty() {
        return Ok(());
    }
    let conflict = |name: &WritableName, executable: &Path| PolicyError::WritableAndExecutable {
        writable: name.path.clone(),
        executable: executable.to_path_buf(),
        relation: "is another name of",
    };
    for (rule, id) in files {
        if let Some(name) = writable.get(&id) {
            return Err(conflict(name, &rule.path));
        }
    }
    for rule in directories {
        let mut found = None;
        for_each_linked_file(&rule.path, &mut |path, id| match writable.get(&id) {
            Some(name) => {
                found = Some(conflict(name, path));
                ControlFlow::Break(())
            }
            None => ControlFlow::Continue(()),
        })
        .map_err(|source| PolicyError::Unreadable {
            path: rule.path.clone(),
            source,
        })?;
        if let Some(conflict) = found {
            return Err(conflict);
        }
    }
    Ok(())
}

/// The same for the files sandy itself trusts, which no policy path names: a second name inside
/// a writable path would let the program rewrite them for the next start.
#[cfg(unix)]
fn check_no_writable_trusted_name(
    files: &[PathBuf],
    rules: &[PathRule],
) -> Result<(), PolicyError> {
    let linked: Vec<(&PathBuf, FileId)> = files
        .iter()
        .filter_map(|file| {
            let metadata = file.symlink_metadata().ok()?;
            Some((file, second_name_candidate(&metadata)?))
        })
        .collect();
    if linked.is_empty() {
        return Ok(());
    }
    let writable = writable_names(rules)?;
    for (file, id) in linked {
        if let Some(name) = writable.get(&id) {
            return Err(PolicyError::TrustedFileWritable {
                path: file.clone(),
                through: name.path.clone(),
                writable: name.writable.clone(),
            });
        }
    }
    Ok(())
}

/// Every name below a writable path that its file shares with another name, by identity.
#[cfg(unix)]
fn writable_names(
    rules: &[PathRule],
) -> Result<std::collections::HashMap<FileId, WritableName>, PolicyError> {
    let mut names = std::collections::HashMap::new();
    let writable = rules
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadWrite);
    for rule in writable {
        for_each_linked_file(&rule.path, &mut |path, id| {
            names.entry(id).or_insert_with(|| WritableName {
                path: path.to_path_buf(),
                writable: rule.path.clone(),
            });
            ControlFlow::Continue(())
        })
        .map_err(|source| PolicyError::Unreadable {
            path: rule.path.clone(),
            source,
        })?;
    }
    Ok(names)
}

/// Calls `visit` for every regular file with more than one name at or below `root`. Symbolic
/// links are not followed, and a directory is entered once, so an alias of a directory inside
/// itself cannot make the walk endless.
///
/// Entries that disappear while the walk runs are skipped, and so are directories this user may
/// not list: the program runs as the same user, so it cannot list them either, and a name it
/// cannot reach cannot carry a grant. `EINVAL` counts as unlistable too, because a directory of
/// a process that is going away reports it (`/proc/<pid>/net` with `--read-write /proc`). Any
/// other error ends the walk, because a tree sandy cannot read is a tree it cannot clear.
#[cfg(unix)]
fn for_each_linked_file(
    root: &Path,
    visit: &mut impl FnMut(&Path, FileId) -> ControlFlow<()>,
) -> std::io::Result<()> {
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;

    let gone = |error: &std::io::Error| {
        matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::InvalidInput
        )
    };
    let mut entered = std::collections::HashSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(error),
        };
        if !metadata.is_dir() {
            if let Some(id) = second_name_candidate(&metadata)
                && visit(&path, id).is_break()
            {
                return Ok(());
            }
            continue;
        }
        if !entered.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            match entry {
                Ok(entry) => pending.push(entry.path()),
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// TODO: Windows needs FILE_ID_INFO for the identity and FindFirstFileNameW for the other names
/// of a file. Both are Windows API calls, which only the Windows backend may make, so they have
/// to reach sandy-core through a backend hook. Until then a pre-existing hard link between a
/// writable and an executable path stays undetected there (see "Links and identity" in
/// docs/windows.md).
#[cfg(not(unix))]
fn check_no_writable_second_name(_rules: &[PathRule]) -> Result<(), PolicyError> {
    Ok(())
}

#[cfg(not(unix))]
fn check_no_writable_trusted_name(
    _files: &[PathBuf],
    _rules: &[PathRule],
) -> Result<(), PolicyError> {
    Ok(())
}

/// Exposed ports listen on loopback only, so a relay never makes the target reachable from other
/// machines. The target must be able to listen, which needs IP networking in this version.
fn validate_expose(expose: &[ExposedPort], ip: NetworkAccess) -> Result<(), PolicyError> {
    let invalid = |expose: &ExposedPort, reason| PolicyError::InvalidExpose {
        expose: *expose,
        reason,
    };
    for entry in expose {
        if ip != NetworkAccess::All {
            return Err(invalid(entry, "the program needs ip = \"all\" to listen"));
        }
        if !entry.listen.ip().is_loopback() {
            return Err(invalid(entry, "listen must be a loopback address"));
        }
        if !plain_address(entry.listen) {
            return Err(invalid(entry, PLAIN_ADDRESS));
        }
        if entry.listen.port() == 0 || entry.port == 0 {
            return Err(invalid(entry, "ports must not be 0"));
        }
        if entry.listen == entry.target() {
            return Err(invalid(entry, "listen and the program's port must differ"));
        }
    }
    Ok(())
}

/// Forwarded ports reach loopback services only, so a relay never opens a way to other machines.
/// The target connects over IP, which needs IP networking.
fn validate_forward(forward: &[ForwardedPort], ip: NetworkAccess) -> Result<(), PolicyError> {
    let invalid = |forward: &ForwardedPort, reason| PolicyError::InvalidForward {
        forward: *forward,
        reason,
    };
    for entry in forward {
        if ip != NetworkAccess::All {
            return Err(invalid(entry, "the program needs ip = \"all\" to connect"));
        }
        if !entry.to.ip().is_loopback() {
            return Err(invalid(entry, "to must be a loopback address"));
        }
        if !plain_address(entry.to) {
            return Err(invalid(entry, PLAIN_ADDRESS));
        }
        if entry.port == 0 || entry.to.port() == 0 {
            return Err(invalid(entry, "ports must not be 0"));
        }
        if entry.listen() == entry.to {
            return Err(invalid(entry, "the program's port and to must differ"));
        }
    }
    Ok(())
}

const PLAIN_ADDRESS: &str = "a loopback address takes no IPv6 scope id or flow label";

/// An IPv6 scope id or flow label makes two spellings of one address compare unequal, so the
/// checks below could not see that two relays use the same address.
fn plain_address(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(address) => address.scope_id() == 0 && address.flowinfo() == 0,
    }
}

/// One relay of either kind: where it listens and where it connects.
#[derive(Clone, Copy)]
enum Relay {
    Expose(ExposedPort),
    Forward(ForwardedPort),
}

impl Relay {
    fn listen(self) -> SocketAddr {
        match self {
            Relay::Expose(expose) => expose.listen,
            Relay::Forward(forward) => forward.listen(),
        }
    }

    fn target(self) -> SocketAddr {
        match self {
            Relay::Expose(expose) => expose.target(),
            Relay::Forward(forward) => forward.to,
        }
    }

    fn error(self, reason: &'static str) -> PolicyError {
        match self {
            Relay::Expose(expose) => PolicyError::InvalidExpose { expose, reason },
            Relay::Forward(forward) => PolicyError::InvalidForward { forward, reason },
        }
    }
}

/// No address may be used by two relays, no relay may connect to a relay, and no forwarded port
/// may lead back into the sandbox. Every pair is compared in both directions, so the order of the
/// entries does not matter.
fn validate_relay_addresses(
    expose: &[ExposedPort],
    forward: &[ForwardedPort],
) -> Result<(), PolicyError> {
    let relays: Vec<Relay> = expose
        .iter()
        .map(|e| Relay::Expose(*e))
        .chain(forward.iter().map(|f| Relay::Forward(*f)))
        .collect();
    for (index, relay) in relays.iter().enumerate() {
        for (other_index, other) in relays.iter().enumerate() {
            if index == other_index {
                continue;
            }
            if relay.listen() == other.listen() {
                return Err(relay.error("address is used by two relays"));
            }
            if relay.target() == other.listen() {
                return Err(relay.error("the relay would connect to another relay"));
            }
            if let (Relay::Forward(_), Relay::Expose(_)) = (relay, other)
                && relay.target() == other.target()
            {
                return Err(relay.error("to leads back into the sandbox (an exposed port)"));
            }
        }
    }
    Ok(())
}

/// Both `none` and `contained` promise that nothing the program starts outlives it. Through a
/// Unix socket the program could ask a service of the user (for example the systemd user manager
/// over D-Bus) to start a process that is not its child. With `contained`, a program that can
/// signal sandy could kill it before it ends the program's processes.
fn validate_children(
    process: &ProcessPolicy,
    unix_sockets: NetworkAccess,
) -> Result<(), PolicyError> {
    if process.children == ChildProcesses::Allowed {
        return Ok(());
    }
    if unix_sockets == NetworkAccess::All {
        return Err(PolicyError::ChildrenNeedUnixSocketsDenied(process.children));
    }
    if process.children == ChildProcesses::Contained && process.signals != SignalScope::Isolated {
        return Err(PolicyError::ContainedChildrenNeedIsolatedSignals);
    }
    Ok(())
}

fn validate_environment(environment: &EnvironmentPolicy) -> Result<(), PolicyError> {
    let names = environment.pass.iter().chain(environment.set.keys());
    for name in names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(PolicyError::InvalidEnvironmentName(name.clone()));
        }
    }
    for (name, value) in &environment.set {
        if value.contains('\0') {
            return Err(PolicyError::InvalidEnvironmentValue(name.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sandy-core-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn policy_with(read: &[&Path], read_exec: &[&Path], read_write: &[&Path]) -> Policy {
        let mut policy = Policy::default();
        policy.filesystem.read = read.iter().map(|p| p.to_path_buf()).collect();
        policy.filesystem.read_exec = read_exec.iter().map(|p| p.to_path_buf()).collect();
        policy.filesystem.read_write = read_write.iter().map(|p| p.to_path_buf()).collect();
        policy
    }

    #[test]
    fn rejects_relative_path() {
        let policy = policy_with(&[Path::new("relative")], &[], &[]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::RelativePath(_)));
    }

    #[test]
    fn rejects_missing_path() {
        let dir = temp_dir();
        let policy = policy_with(&[&dir.join("missing")], &[], &[]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::PathNotFound { .. }));
    }

    #[test]
    fn merges_duplicate_paths_to_the_wider_access() {
        let dir = temp_dir();
        let policy = policy_with(&[&dir], &[&dir], &[]);
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        assert_eq!(resolved.paths.len(), 1);
        assert_eq!(resolved.paths[0].access, PathAccess::ReadExec);
    }

    #[test]
    fn rejects_same_path_writable_and_executable() {
        let dir = temp_dir();
        let policy = policy_with(&[], &[&dir], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn rejects_writable_inside_executable() {
        let dir = temp_dir();
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[], &[&dir], &[&data]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn rejects_executable_inside_writable() {
        let dir = temp_dir();
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let policy = policy_with(&[], &[&bin], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn accepts_sibling_writable_and_executable() {
        let dir = temp_dir();
        let bin = dir.join("bin");
        let data = dir.join("data");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[], &[&bin], &[&data]);
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        assert_eq!(resolved.paths.len(), 2);
    }

    #[test]
    fn rejects_paths_inside_a_writable_path() {
        let dir = temp_dir();
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).unwrap();
        for policy in [
            policy_with(&[&nested], &[], &[&dir]),
            policy_with(&[], &[], &[&dir, &nested]),
        ] {
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(
                matches!(error, PolicyError::InsideWritable { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn accepts_a_writable_path_inside_a_readable_one() {
        let dir = temp_dir();
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[&dir], &[], &[&data]);
        assert!(ResolvedPolicy::resolve(&policy, None).is_ok());
    }

    #[test]
    fn program_gets_read_exec_on_the_file() {
        let dir = temp_dir();
        let program = dir.join("program");
        fs::write(&program, b"").unwrap();
        let resolved = ResolvedPolicy::resolve(&Policy::default(), Some(&program)).unwrap();
        assert_eq!(
            resolved.paths,
            vec![PathRule {
                path: program,
                access: PathAccess::ReadExec,
                is_dir: false,
            }]
        );
    }

    #[test]
    fn program_inside_writable_directory_is_rejected() {
        let dir = temp_dir();
        let program = dir.join("program");
        fs::write(&program, b"").unwrap();
        let policy = policy_with(&[], &[], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, Some(&program)).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn program_must_be_a_file() {
        let dir = temp_dir();
        let error = ResolvedPolicy::resolve(&Policy::default(), Some(&dir)).unwrap_err();
        assert!(matches!(error, PolicyError::ProgramNotAFile(_)));
    }

    #[test]
    fn rejects_invalid_environment_names() {
        for name in ["", "A=B", "A\0"] {
            let mut policy = Policy::default();
            policy.environment.pass.push(name.to_string());
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(matches!(error, PolicyError::InvalidEnvironmentName(_)));
        }
    }

    fn expose(listen: &str, port: u16) -> ExposedPort {
        ExposedPort {
            listen: listen.parse().unwrap(),
            port,
        }
    }

    fn with_expose(ip: NetworkAccess, entries: &[ExposedPort]) -> Policy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.expose = entries.to_vec();
        policy
    }

    #[test]
    fn accepts_loopback_expose_with_ip() {
        for listen in ["127.0.0.1:18080", "[::1]:18080"] {
            let policy = with_expose(NetworkAccess::All, &[expose(listen, 8080)]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let requirements = resolved.requirements();
            assert!(requirements.contains(&Requirement::ExposedPortsRelayed));
        }
    }

    #[test]
    fn rejects_invalid_expose() {
        let cases = [
            with_expose(NetworkAccess::None, &[expose("127.0.0.1:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("0.0.0.0:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("192.168.1.2:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:0", 8080)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:18080", 0)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:8080", 8080)]),
            with_expose(
                NetworkAccess::All,
                &[
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:18080", 8081),
                ],
            ),
            with_expose(
                NetworkAccess::All,
                &[
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:8080", 8081),
                ],
            ),
        ];
        for policy in cases {
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(
                matches!(error, PolicyError::InvalidExpose { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn no_expose_no_relay_requirement() {
        let resolved = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        assert!(
            !resolved
                .requirements()
                .contains(&Requirement::ExposedPortsRelayed)
        );
    }

    fn forward(port: u16, to: &str) -> ForwardedPort {
        ForwardedPort {
            port,
            to: to.parse().unwrap(),
        }
    }

    fn with_forward(ip: NetworkAccess, entries: &[ForwardedPort]) -> Policy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.forward = entries.to_vec();
        policy
    }

    #[test]
    fn accepts_loopback_forward_with_ip() {
        for to in ["127.0.0.1:8080", "[::1]:8080"] {
            let policy = with_forward(NetworkAccess::All, &[forward(18080, to)]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let requirements = resolved.requirements();
            assert!(requirements.contains(&Requirement::ForwardedPortsRelayed));
        }
    }

    #[test]
    fn rejects_invalid_forward() {
        let mut cases = vec![
            with_forward(NetworkAccess::None, &[forward(18080, "127.0.0.1:8080")]),
            with_forward(NetworkAccess::All, &[forward(18080, "192.168.1.2:8080")]),
            with_forward(NetworkAccess::All, &[forward(18080, "0.0.0.0:8080")]),
            with_forward(NetworkAccess::All, &[forward(0, "127.0.0.1:8080")]),
            with_forward(NetworkAccess::All, &[forward(18080, "127.0.0.1:0")]),
            with_forward(NetworkAccess::All, &[forward(8080, "127.0.0.1:8080")]),
            with_forward(
                NetworkAccess::All,
                &[
                    forward(18080, "127.0.0.1:8080"),
                    forward(18080, "127.0.0.1:8081"),
                ],
            ),
        ];
        let mut clashing = with_forward(NetworkAccess::All, &[forward(18080, "127.0.0.1:8080")]);
        clashing.network.expose = vec![expose("127.0.0.1:18080", 9000)];
        cases.push(clashing);
        let mut looping = with_forward(NetworkAccess::All, &[forward(18081, "127.0.0.1:18080")]);
        looping.network.expose = vec![expose("127.0.0.1:18080", 9000)];
        cases.push(looping);
        for policy in cases {
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(
                matches!(
                    error,
                    PolicyError::InvalidForward { .. } | PolicyError::InvalidExpose { .. }
                ),
                "{error}"
            );
        }
    }

    /// Each relay conflict is found whatever the order of the entries.
    #[test]
    fn relay_conflicts_do_not_depend_on_the_order() {
        let both = |expose: Vec<ExposedPort>, forward: Vec<ForwardedPort>| {
            let mut policy = Policy::default();
            policy.network.ip = NetworkAccess::All;
            policy.network.expose = expose;
            policy.network.forward = forward;
            ResolvedPolicy::resolve(&policy, None)
        };
        let conflicts: Vec<(Vec<ExposedPort>, Vec<ForwardedPort>)> = vec![
            // An exposed relay that connects to another exposed relay's listener.
            (
                vec![
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:9000", 18080),
                ],
                vec![],
            ),
            // A forwarded relay that connects to another forwarded relay's listener.
            (
                vec![],
                vec![
                    forward(18081, "127.0.0.1:8081"),
                    forward(8081, "127.0.0.1:9000"),
                ],
            ),
        ];
        for (mut expose, mut forward) in conflicts {
            assert!(both(expose.clone(), forward.clone()).is_err());
            expose.reverse();
            forward.reverse();
            assert!(both(expose, forward).is_err());
        }
        // Two exposed ports may relay to the same port of the program.
        both(
            vec![
                expose("127.0.0.1:18080", 8080),
                expose("127.0.0.2:18080", 8080),
            ],
            vec![],
        )
        .unwrap();
    }

    /// A scope id or flow label would make one address compare unequal to itself.
    #[test]
    fn relay_addresses_take_no_scope_id_or_flow_label() {
        let scoped: SocketAddr = "[::1%1]:28080".parse().unwrap();
        let mut labeled = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 28080, 0, 0);
        labeled.set_flowinfo(5);
        for address in [scoped, SocketAddr::V6(labeled)] {
            let policy = with_expose(
                NetworkAccess::All,
                &[ExposedPort {
                    listen: address,
                    port: 28081,
                }],
            );
            assert!(matches!(
                ResolvedPolicy::resolve(&policy, None),
                Err(PolicyError::InvalidExpose { .. })
            ));
            let policy = with_forward(
                NetworkAccess::All,
                &[ForwardedPort {
                    port: 28081,
                    to: address,
                }],
            );
            assert!(matches!(
                ResolvedPolicy::resolve(&policy, None),
                Err(PolicyError::InvalidForward { .. })
            ));
        }
    }

    #[test]
    fn no_forward_no_relay_requirement() {
        let resolved = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        assert!(
            !resolved
                .requirements()
                .contains(&Requirement::ForwardedPortsRelayed)
        );
    }

    #[test]
    fn rejects_children_none_with_unix_sockets() {
        let mut policy = Policy::default();
        policy.process.children = ChildProcesses::None;
        policy.network.unix_sockets = NetworkAccess::All;
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::ChildrenNeedUnixSocketsDenied(ChildProcesses::None)
        ));
        policy.network.unix_sockets = NetworkAccess::None;
        assert!(ResolvedPolicy::resolve(&policy, None).is_ok());
    }

    #[test]
    fn contained_children_need_unix_sockets_denied_and_isolated_signals() {
        let mut policy = Policy::default();
        policy.process.children = ChildProcesses::Contained;
        policy.process.signals = SignalScope::Isolated;
        policy.network.unix_sockets = NetworkAccess::All;
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::ChildrenNeedUnixSocketsDenied(ChildProcesses::Contained)
        ));
        assert!(error.to_string().contains("\"contained\""), "{error}");

        policy.network.unix_sockets = NetworkAccess::None;
        policy.process.signals = SignalScope::Any;
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::ContainedChildrenNeedIsolatedSignals
        ));

        policy.process.signals = SignalScope::Isolated;
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(requirements.contains(&Requirement::ChildProcessesContained));
        assert!(requirements.contains(&Requirement::SignalsIsolated));
        assert!(!requirements.contains(&Requirement::ChildProcessesDenied));
    }

    #[test]
    fn end_with_parent_needs_isolated_signals() {
        let mut policy = Policy::default();
        policy.process.end_with_parent = true;
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::EndWithParentNeedsIsolatedSignals
        ));
        assert!(
            error.to_string().contains("signals = \"isolated\""),
            "{error}"
        );

        policy.process.signals = SignalScope::Isolated;
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(requirements.contains(&Requirement::EndsWithParent));

        policy.process.end_with_parent = false;
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(!requirements.contains(&Requirement::EndsWithParent));
    }

    #[test]
    fn requirements_follow_denials() {
        let mut policy = Policy::default();
        let baseline = [
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
            Requirement::ProcessMemoryIsolated,
            Requirement::InheritedHandlesClosed,
            Requirement::EnvironmentControlled,
        ];

        let all_denied = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(baseline.iter().all(|r| all_denied.contains(r)));
        assert!(all_denied.contains(&Requirement::IpNetworkDenied));
        assert!(all_denied.contains(&Requirement::UnixSocketsDenied));
        assert!(!all_denied.contains(&Requirement::SignalsIsolated));
        assert!(!all_denied.contains(&Requirement::ChildProcessesDenied));
        assert!(!all_denied.contains(&Requirement::ChildProcessesContained));
        assert!(all_denied.contains(&Requirement::MetadataConfined));

        policy.network.ip = NetworkAccess::All;
        policy.network.unix_sockets = NetworkAccess::All;
        policy.process.signals = SignalScope::Isolated;
        policy.linux.path_metadata = PathMetadata::Allow;
        let allowed = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(baseline.iter().all(|r| allowed.contains(r)));
        assert!(!allowed.contains(&Requirement::IpNetworkDenied));
        assert!(!allowed.contains(&Requirement::UnixSocketsDenied));
        assert!(allowed.contains(&Requirement::SignalsIsolated));
        assert!(!allowed.contains(&Requirement::MetadataConfined));

        // children = "none" needs unix_sockets = "none" (see rejects_children_none_with_unix_sockets).
        policy.network.unix_sockets = NetworkAccess::None;
        policy.process.children = ChildProcesses::None;
        let no_children = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(no_children.contains(&Requirement::ChildProcessesDenied));
    }

    /// The program can replace an entry inside a writable path between two starts, so a policy
    /// path that resolves through one would point elsewhere at the next start.
    #[cfg(unix)]
    #[test]
    fn rejects_a_path_resolved_through_a_link_in_a_writable_path() {
        use std::os::unix::fs::symlink;
        let root = temp_dir();
        let data = root.join("data");
        let outside = root.join("outside");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, data.join("shared")).unwrap();
        let through = data.join("shared");

        // Read, write and the program: each is refused.
        let policy = policy_with(&[&through], &[], &[&data]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(
            matches!(&error, PolicyError::ResolvedThroughWritable { entry, writable, .. }
                if *entry == through && *writable == data),
            "{error}"
        );
        let policy = policy_with(&[], &[], &[&data, &through]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, None),
            Err(PolicyError::ResolvedThroughWritable { .. })
        ));
        fs::write(outside.join("program"), b"").unwrap();
        let policy = policy_with(&[], &[], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, Some(&through.join("program"))),
            Err(PolicyError::ResolvedThroughWritable { .. })
        ));

        // A chain: a link outside the writable path leads through a link inside it.
        let chain = root.join("chain");
        symlink(&through, &chain).unwrap();
        let policy = policy_with(&[&chain], &[], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, None),
            Err(PolicyError::ResolvedThroughWritable { .. })
        ));

        // Control: the same links are fine without the writable path.
        let policy = policy_with(&[&through, &chain], &[], &[]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
        // A link outside writable paths may point anywhere outside them.
        let direct = root.join("direct");
        symlink(&outside, &direct).unwrap();
        let policy = policy_with(&[&direct], &[], &[&data]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
        // Passing the writable root itself and leaving it with .. passes no entry inside it.
        let policy = policy_with(&[&data.join("..").join("outside")], &[], &[&data]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
    }

    /// One directory under two paths is one object: rules 3 and 4 compare file identity too.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_same_directory_under_another_path_is_within_it() {
        let dir = temp_dir();
        fs::create_dir_all(dir.join("sub")).unwrap();
        // Another spelling of the same directory: through the process's root on Linux, through
        // the data volume on macOS, where the temporary directory lies.
        let prefix = if cfg!(target_os = "linux") {
            "/proc/self/root"
        } else {
            "/System/Volumes/Data"
        };
        let other = Path::new(prefix).join(dir.strip_prefix("/").unwrap());
        let mounts = Mounts::read().unwrap();
        assert!(!other.join("sub").starts_with(&dir));
        assert!(is_within(&other.join("sub"), &dir, &mounts));
        assert!(is_within(&dir.join("sub"), &other, &mounts));
        assert!(!is_within(&dir, &dir.join("sub"), &mounts));
    }

    /// Rule 3 by identity: one file under two names, one of them writable.
    #[cfg(unix)]
    #[test]
    fn rejects_an_executable_file_hard_linked_into_a_writable_path() {
        let root = temp_dir();
        let (data, tools) = (root.join("data"), root.join("tools"));
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&tools).unwrap();
        fs::write(tools.join("tool"), b"").unwrap();

        // Control: without the link the two trees are unrelated.
        let policy = policy_with(&[], &[&tools], &[&data]);
        ResolvedPolicy::resolve(&policy, None).unwrap();

        fs::hard_link(tools.join("tool"), data.join("copy")).unwrap();
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(
            matches!(&error, PolicyError::WritableAndExecutable { writable, executable, .. }
                if *writable == data.join("copy") && *executable == tools.join("tool")),
            "{error}"
        );
        // The same for an executable path that names the file itself, and for the program.
        let policy = policy_with(&[], &[&tools.join("tool")], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, None),
            Err(PolicyError::WritableAndExecutable { .. })
        ));
        let policy = policy_with(&[], &[], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, Some(&tools.join("tool"))),
            Err(PolicyError::WritableAndExecutable { .. })
        ));
    }

    /// The files sandy itself trusts get the same checks as policy paths.
    #[cfg(unix)]
    #[test]
    fn rejects_a_trusted_file_a_writable_path_reaches() {
        use std::os::unix::fs::symlink;
        let root = temp_dir();
        let (data, safe) = (root.join("data"), root.join("safe"));
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&safe).unwrap();
        let trusted = safe.join("policy.toml");
        fs::write(&trusted, b"").unwrap();
        let resolved = ResolvedPolicy::resolve(&policy_with(&[], &[], &[&data]), None).unwrap();
        resolved
            .check_trusted(std::slice::from_ref(&trusted))
            .unwrap();

        // Reached through a symbolic link inside the writable path.
        let through_link = data.join("policy.toml");
        symlink(&trusted, &through_link).unwrap();
        let error = resolved.check_trusted(&[through_link]).unwrap_err();
        assert!(
            matches!(&error, PolicyError::TrustedFileWritable { writable, .. } if *writable == data),
            "{error}"
        );

        // A second name inside the writable path.
        fs::hard_link(&trusted, data.join("other.toml")).unwrap();
        let error = resolved.check_trusted(&[trusted]).unwrap_err();
        assert!(
            matches!(&error, PolicyError::TrustedFileWritable { through, .. }
                if *through == data.join("other.toml")),
            "{error}"
        );
    }

    /// A bind mount of a subdirectory of a writable path shares no ancestor with it, so only the
    /// location inside the file system shows that both lead to the same place. Mounting needs
    /// privileges, so this uses the table that `escape_linux.rs` measures under `unshare -Urm`;
    /// the names there carry an escaped space, which the parser has to reverse.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_bind_mount_of_a_subdirectory_lies_inside_the_writable_path() {
        let table = concat!(
            "25 1 0:22 / / rw,relatime - btrfs /dev/sda2 rw\n",
            "1785 1542 0:57 / /odd\\040name rw,nosuid,nodev - tmpfs tmpfs rw\n",
            "2343 1785 0:57 /work/rw/sub /odd\\040name/alias rw,nosuid - tmpfs tmpfs rw\n",
        );
        let mounts = Mounts::parse(table.as_bytes());
        let tmpfs = |point: &Path| point != Path::new("/");
        let physical = |path: &str| mounts.physical(Path::new(path), tmpfs).unwrap();

        let writable = physical("/odd name/work/rw");
        assert_eq!(writable, Path::new("/work/rw"));
        assert_eq!(physical("/odd name/alias/t"), Path::new("/work/rw/sub/t"));
        assert!(physical("/odd name/alias/t").starts_with(&writable));
        // Another mount of the same file system that lies outside the writable path.
        assert!(!physical("/odd name/work/other").starts_with(&writable));
        // The file system a mount point belongs to decides, not the length of the prefix.
        assert_eq!(
            mounts.physical(Path::new("/odd name/alias/t"), |point| point
                == Path::new("/")),
            Some(PathBuf::from("/odd name/alias/t"))
        );
    }

    #[test]
    fn warns_about_every_setting_that_gives_up_isolation() {
        let dir = temp_dir();
        let home = dir.join("home");
        fs::create_dir_all(&home).unwrap();
        let mut policy = policy_with(&[], &[], &[&dir]);
        policy.network.unix_sockets = NetworkAccess::All;
        policy.linux.path_metadata = PathMetadata::Allow;
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        let warnings = resolved.warnings(Some(&home)).join("\n");
        for setting in [
            "unix_sockets = \"all\"",
            "signals = \"any\"",
            "path_metadata = \"allow\"",
        ] {
            assert!(warnings.contains(setting), "{warnings}");
        }
        assert!(warnings.contains(&home.display().to_string()), "{warnings}");

        // The strictest policy keeps quiet, and a writable path beside the home directory is not
        // one that holds it.
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let mut policy = policy_with(&[], &[], &[&data]);
        policy.process.signals = SignalScope::Isolated;
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        assert_eq!(resolved.warnings(Some(&home)), Vec::<String>::new());
    }
}
