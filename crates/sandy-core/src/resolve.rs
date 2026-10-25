use std::ffi::OsString;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::plan::Requirement;
use crate::policy::{
    ChildProcesses, EnvironmentPolicy, ExposedPort, ForwardedPort, IpAccess, NetworkAccess,
    PathMetadata, Policy, PolicyError, ProcessPolicy, SignalScope, SystemAccess, Win32k,
    WindowsPolicy,
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::{FileId, entry};

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

/// A location outside the policy paths that a writable path must not reach: an entry of a
/// backend's system set, or one of the user's trusted locations. The backends define their own,
/// because only they know their system set and their platform's locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPath {
    /// The location as the backend names it.
    pub path: PathBuf,
    /// The same location with the symbolic links on the way resolved, so that it compares with
    /// the canonical policy paths. Both spellings count: whoever can write where a link lies can
    /// repoint it, and whoever can write where it leads changes what other programs read.
    resolved: PathBuf,
    /// Whether everything beneath the location is protected too. A directory whose content other
    /// programs read or execute protects its tree; a location that must only not be contained in
    /// a writable path, such as the home directory, does not.
    pub subtree: bool,
}

impl ProtectedPath {
    /// A location that protects everything beneath it.
    pub fn tree(path: impl AsRef<Path>) -> ProtectedPath {
        ProtectedPath::new(path.as_ref(), true)
    }

    /// A location that protects only itself: a file, or a directory whose own entries other
    /// programs read while a writable path below it reaches none of them.
    pub fn entry(path: impl AsRef<Path>) -> ProtectedPath {
        ProtectedPath::new(path.as_ref(), false)
    }

    fn new(path: &Path, subtree: bool) -> ProtectedPath {
        ProtectedPath {
            path: path.to_path_buf(),
            resolved: canonical_location(path),
            subtree,
        }
    }

    fn spellings(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.path.as_path())
            .chain((self.resolved != self.path).then_some(self.resolved.as_path()))
    }
}

/// The directories of a `PATH` variable as protected locations. A program the sandboxed one
/// leaves in one of them runs outside the sandbox as soon as the user types its name. Only the
/// directories themselves are protected: a writable path below one of them puts nothing on PATH.
/// Entries that are not absolute name no fixed directory and are left out.
///
/// Rule 12 warns about these instead of refusing them (`ResolvedPolicy::path_directory_notes`),
/// so the backends keep them apart from the locations that are refused.
pub fn path_directories(path: Option<&std::ffi::OsStr>) -> Vec<ProtectedPath> {
    let Some(path) = path else {
        return Vec::new();
    };
    let mut directories: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .collect();
    directories.sort();
    directories.dedup();
    directories.iter().map(ProtectedPath::entry).collect()
}

/// As the kernel's limit for one path lookup (MAXSYMLINKS).
const MAX_LINKS: usize = 40;

/// `path` in the canonical form that policy paths have, also when it does not exist: the
/// canonical form of its nearest existing ancestor with the rest appended. A location that does
/// not exist counts, because the program could create it, and so does the target of a symbolic
/// link that does not exist yet: whoever creates it there changes what the link leads to.
pub fn canonical_location(path: &Path) -> PathBuf {
    let mut names = Vec::new();
    let mut base = path.to_path_buf();
    let mut links = 0;
    loop {
        if let Ok(canonical) = base.canonicalize() {
            return names
                .iter()
                .rev()
                .fold(canonical, |path, name| path.join(name));
        }
        if links < MAX_LINKS
            && let Ok(target) = std::fs::read_link(&base)
        {
            links += 1;
            base = match base.parent() {
                Some(parent) => parent.join(target),
                None => target,
            };
            continue;
        }
        let (Some(parent), Some(name)) = (base.parent(), base.file_name()) else {
            return path.to_path_buf();
        };
        names.push(name.to_os_string());
        base = parent.to_path_buf();
    }
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
    pub ip: IpAccess,
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
        check_no_writable_second_name(&paths, &mounts)?;
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
        match self.ip {
            IpAccess::None => requirements.push(Requirement::IpNetworkDenied),
            IpAccess::Client => requirements.push(Requirement::InboundIpDenied),
            IpAccess::All => {}
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
        if self.windows.win32k == Win32k::Deny {
            requirements.push(Requirement::Win32kDenied);
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
        check_no_writable_trusted_name(&canonical, &self.paths, &mounts)
    }

    /// The first writable path that reaches one of `protected`, with the location it reaches.
    /// A writable path reaches a location when it contains it, or when it lies inside one that
    /// protects its tree. The comparison is the one of rules 3 and 4 (`PathIdentity`), so
    /// another name of a protected directory counts as that directory.
    ///
    /// Backends call this for the locations outside the policy that their platform must keep out
    /// of a writable path: the entries of the minimal system set, and the locations of this user
    /// that other programs read or execute later.
    pub fn writable_conflict<'policy, 'protected>(
        &'policy self,
        protected: &'protected [ProtectedPath],
        identity: &PathIdentity,
    ) -> Option<(&'policy PathRule, &'protected ProtectedPath)> {
        self.writable_conflicts(protected, identity, Unknown::Overlaps)
            .next()
    }

    /// Every writable path that reaches one of `protected`, with the location it reaches, in the
    /// order of the paths. `writable_conflict` reports the first of them; the warning for the
    /// PATH directories names them all, so one `check` lists every directory to deal with.
    fn writable_conflicts<'policy, 'protected>(
        &'policy self,
        protected: &'protected [ProtectedPath],
        identity: &PathIdentity,
        unknown: Unknown,
    ) -> impl Iterator<Item = (&'policy PathRule, &'protected ProtectedPath)> {
        self.paths
            .iter()
            .filter(|rule| rule.access == PathAccess::ReadWrite)
            .flat_map(move |rule| {
                protected
                    .iter()
                    .filter(move |location| reaches(location, &rule.path, identity, unknown))
                    .map(move |location| (rule, location))
            })
    }

    /// Warnings for the writable paths that reach a directory on `PATH`: sandy's own, or one the
    /// usual shell setups put on the user's (the backends say which). The escape is the one of
    /// the other trusted locations, but a writable path that holds such a directory is often
    /// what the caller means, a package cache whose `bin` directory is on `PATH` for example, so
    /// rule 12 warns here instead of refusing. `check` prints the warnings; they change nothing
    /// sandy enforces. The advice names what removes the risk: a `PATH` without the directory
    /// only silences the warning, because the user's shell still looks there.
    ///
    /// The backends pass the directories, as they do for `writable_conflict`, and the comparison
    /// is the same, except where sandy cannot read the identity of a directory on the way: a
    /// warning then follows the spellings (`Unknown::Spelling`), so it names only an overlap sandy
    /// sees. A host whose comparison cannot be read gets no warning: its policy is refused
    /// anyway, for the same reason.
    pub fn path_directory_notes(&self, directories: &[ProtectedPath]) -> Vec<String> {
        let Ok(identity) = PathIdentity::read() else {
            return Vec::new();
        };
        self.writable_conflicts(directories, &identity, Unknown::Spelling)
            .map(|(rule, directory)| {
                format!(
                    "the writable path {} overlaps {}, a directory on sandy's PATH or on the \
                     usual PATH of a user's shell, so a file the program leaves there runs \
                     outside the sandbox when the user next types its name; make only the \
                     subdirectories the program needs writable, so that {} stays outside every \
                     writable path (taking it off sandy's PATH leaves the risk)",
                    rule.path.display(),
                    directory.path.display(),
                    directory.path.display()
                )
            })
            .collect()
    }
}

/// What a comparison counts as when sandy cannot read the identity of a file on the way, which
/// happens on Windows only: an elevated process may not follow a junction that a less trusted
/// one made (`ERROR_UNTRUSTED_MOUNT_POINT`), for example.
#[derive(Debug, Clone, Copy)]
enum Unknown {
    /// For a refusal: an overlap, so sandy refuses what it cannot tell apart.
    Overlaps,
    /// For a warning: what the spellings say. `within` compares them first, and a location has
    /// a canonical spelling besides its own, so the warning names only an overlap sandy sees.
    Spelling,
}

/// Whether the writable path `writable` reaches `location`: it contains the location, or it lies
/// inside one that protects its tree.
fn reaches(
    location: &ProtectedPath,
    writable: &Path,
    identity: &PathIdentity,
    unknown: Unknown,
) -> bool {
    let within = |inner: &Path, outer: &Path| {
        within(inner, outer, &identity.mounts).unwrap_or(matches!(unknown, Unknown::Overlaps))
    };
    let contains = location.spellings().any(|path| within(path, writable));
    let inside = location.subtree && location.spellings().any(|path| within(writable, path));
    contains || inside
}

/// How this host compares two paths: by the file they lead to, not by how they are spelled. The
/// resolver uses it for rules 3 and 4, and the backends for the locations a writable path must
/// not reach, so one policy is refused for the same reason whichever check sees it first.
///
/// What it sees per platform is in `is_within`.
#[derive(Debug)]
pub struct PathIdentity {
    mounts: Mounts,
}

impl PathIdentity {
    /// Reads what the comparison needs from the host: on Linux the mount table, which is the
    /// only way to see a bind alias of a subdirectory. sandy refuses the policy when it cannot
    /// be read, as the resolver does (`Mounts::read`).
    pub fn read() -> Result<PathIdentity, PolicyError> {
        Ok(PathIdentity {
            mounts: Mounts::read()?,
        })
    }

    /// Whether `inner` is `outer` or lies beneath it.
    pub fn within(&self, inner: &Path, outer: &Path) -> bool {
        is_within(inner, outer, &self.mounts)
    }
}

/// The interpreter of a `#!` line: the first word after `#!`, or `None` when `file` does not
/// start with one. The kernel reads only the beginning of the file (256 bytes on Linux) and the
/// first line of it, and takes everything after the interpreter as one argument.
pub fn shebang(file: &Path) -> Option<PathBuf> {
    use std::io::Read;

    /// As Linux (BINPRM_BUF_SIZE). macOS reads less.
    const HEADER: usize = 256;

    let file = open_regular_file(file)?;
    let mut header = Vec::with_capacity(HEADER);
    file.take(HEADER as u64).read_to_end(&mut header).ok()?;
    let line = header.strip_prefix(b"#!")?;
    // Without a newline the kernel uses what it read, so the end of the header ends the line.
    let end = line.iter().position(|byte| *byte == b'\n');
    let line = &line[..end.unwrap_or(line.len())];
    let word = line
        .split(|byte| matches!(byte, b' ' | b'\t'))
        .find(|word| !word.is_empty())?;
    Some(path_from_bytes(word))
}

/// `file` opened for reading when it is a regular file, the only kind the kernel executes. The
/// open does not wait: without O_NONBLOCK, opening a named pipe waits for a writer, and sandy
/// would hang on a program path that names one.
#[cfg(unix)]
fn open_regular_file(file: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file)
        .ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// Windows opens a named pipe without waiting.
#[cfg(not(unix))]
fn open_regular_file(file: &Path) -> Option<std::fs::File> {
    let file = std::fs::File::open(file).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
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
/// name: every component of the path and of every symbolic link on the way, in order, on
/// Windows also of every junction, which `std::fs` counts as a symbolic link. Whoever can write
/// the directory of one of them can make the path resolve to another object.
///
/// An entry that is no symbolic link is spelled as the file system spells it, which on macOS and
/// Windows can differ from the given name in case (and on macOS in Unicode normalization), so
/// that it compares with the canonical policy paths: the writable path itself, named in another
/// case, is not inside it.
fn traversed_entries(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::collections::VecDeque;

    let mut entries = Vec::new();
    let (mut resolved, names) = lookup(Path::new(""), path)?;
    let mut pending: VecDeque<OsString> = names.into();
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        let entry = resolved.join(&name);
        let metadata = std::fs::symlink_metadata(&entry)?;
        if metadata.file_type().is_symlink() {
            entries.push(entry.clone());
            links += 1;
            if links > MAX_LINKS {
                return Err(std::io::Error::other("too many levels of symbolic links"));
            }
            let target = std::fs::read_link(&entry)?;
            let (start, names) = lookup(&resolved, &target)?;
            resolved = start;
            for name in names.into_iter().rev() {
                pending.push_front(name);
            }
        } else {
            resolved = entry.canonicalize()?;
            entries.push(resolved.clone());
        }
    }
    Ok(entries)
}

/// Where looking up `path` from the directory `base` starts, and the names it then looks up in
/// order. Unix looks `..` up like any other name, after the links before it.
#[cfg(unix)]
fn lookup(base: &Path, path: &Path) -> std::io::Result<(PathBuf, Vec<OsString>)> {
    use std::path::Component;

    let start = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };
    let names = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect();
    Ok((start, names))
}

/// Windows resolves `.` and `..` by their spelling before it looks a path up, also in the target
/// of a relative symbolic link: `link\..\x` is `x` beside the link, wherever `link` leads
/// (measured on Windows 11; a verbatim path with `..` after a link does not resolve at all). The
/// start is the root of the path in canonical form, so the entries compare with the canonical
/// policy paths.
#[cfg(windows)]
fn lookup(base: &Path, path: &Path) -> std::io::Result<(PathBuf, Vec<OsString>)> {
    use std::path::Component;

    let mut root = PathBuf::new();
    let mut names = Vec::new();
    for component in std::path::absolute(base.join(path))?.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => root.push(component),
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::ParentDir => {
                names.pop();
            }
            Component::CurDir => {}
        }
    }
    Ok((root.canonicalize()?, names))
}

/// Whether `inner` is `outer` or lies beneath it. Besides the path, the identity of the file of
/// `outer` (device and inode on Unix, volume serial number and file ID on Windows) is compared
/// with `inner` and each of its ancestors, so one directory reachable under two paths (a bind
/// mount, a macOS firmlink, a junction, a spelling without the verbatim prefix on Windows) counts
/// as one. On Linux the physical location is compared as well, which also sees an alias of a
/// subdirectory of `outer`, which has no ancestor with `outer`'s identity.
///
/// A symbolic link at `inner` itself counts where it lies, not where it leads, as
/// `traversed_entries` spells its entries: a link outside `outer` that points at it is not inside
/// it, and the place it leads to is an entry or a spelling of its own that the callers compare.
///
/// What sandy cannot tell apart counts as within: the callers refuse on a match.
fn is_within(inner: &Path, outer: &Path, mounts: &Mounts) -> bool {
    within(inner, outer, mounts).unwrap_or(true)
}

/// The comparison of `is_within`, or `None` when the spellings differ and the identity of a
/// file on the way cannot be read.
fn within(inner: &Path, outer: &Path, mounts: &Mounts) -> Option<bool> {
    if inner.starts_with(outer) || same_physical_location(inner, outer, mounts) {
        return Some(true);
    }
    same_object_among_ancestors(inner, outer)
}

/// Unix always tells: a path whose metadata cannot be read matches nothing.
#[cfg(unix)]
fn same_object_among_ancestors(inner: &Path, outer: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let identity =
        |metadata: std::io::Result<std::fs::Metadata>| metadata.ok().map(|m| (m.dev(), m.ino()));
    let Some(outer) = identity(outer.metadata()) else {
        return Some(false);
    };
    let same = identity(inner.symlink_metadata()) == Some(outer)
        || inner
            .ancestors()
            .skip(1)
            .any(|ancestor| identity(ancestor.metadata()) == Some(outer));
    Some(same)
}

/// A path where no object is matches nothing, as on Unix. `None` when no path on the way
/// matches but the identity of one cannot be read.
#[cfg(windows)]
fn same_object_among_ancestors(inner: &Path, outer: &Path) -> Option<bool> {
    let outer = match windows::file_id(outer, true) {
        Ok(id) => id,
        Err(error) if windows::no_object(&error) => return Some(false),
        Err(_) => return None,
    };
    let on_the_way = std::iter::once((inner, false))
        .chain(inner.ancestors().skip(1).map(|ancestor| (ancestor, true)));
    let mut unknown = false;
    for (path, follow) in on_the_way {
        match windows::file_id(path, follow) {
            Ok(id) if id == outer => return Some(true),
            Ok(_) => {}
            Err(error) if windows::no_object(&error) => {}
            Err(_) => unknown = true,
        }
    }
    (!unknown).then_some(false)
}

/// Where the file systems of this host are mounted. A path says which directory it leads to but
/// not where that directory lies: a bind mount shows one directory under a second path that
/// shares no ancestor with the first. The physical location, the path inside the file system
/// that holds it, is the same for both spellings.
#[cfg(target_os = "linux")]
#[derive(Debug)]
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
#[derive(Debug)]
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

/// An entry as a walk sees it, read without following a link at it.
struct Entry {
    id: FileId,
    /// A directory, not a link to one.
    is_dir: bool,
    /// A regular file with more than one name. A file with one name is reachable only where the
    /// policy says it is.
    linked: bool,
}

#[cfg(unix)]
fn entry(path: &Path) -> std::io::Result<Entry> {
    use std::os::unix::fs::MetadataExt;

    let metadata = path.symlink_metadata()?;
    Ok(Entry {
        id: FileId {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        is_dir: metadata.is_dir(),
        linked: metadata.is_file() && metadata.nlink() > 1,
    })
}

/// The identity of the file at `path` when it is a regular file with more than one name.
fn linked_file(path: &Path) -> Result<Option<FileId>, PolicyError> {
    let entry = entry(path).map_err(|source| PolicyError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(entry.linked.then_some(entry.id))
}

/// A name inside a writable path, and the writable path that holds it.
#[derive(Clone)]
struct WritableName {
    path: PathBuf,
    writable: PathBuf,
}

/// The names inside the writable paths that files with more than one name have there. The
/// writable trees are walked once, when the first question needs it.
struct WritableNames<'a> {
    rules: &'a [PathRule],
    walked: Option<std::collections::HashMap<FileId, WritableName>>,
}

impl<'a> WritableNames<'a> {
    fn new(rules: &'a [PathRule]) -> Self {
        WritableNames {
            rules,
            walked: None,
        }
    }

    /// Every name below a writable path that its file shares with another name, by identity.
    fn walked(&mut self) -> Result<&std::collections::HashMap<FileId, WritableName>, PolicyError> {
        let walked = match self.walked.take() {
            Some(walked) => walked,
            None => writable_names(self.rules)?,
        };
        Ok(self.walked.insert(walked))
    }

    /// The name inside a writable path of the file at `path`, whose identity is `id`.
    #[cfg(unix)]
    fn of_file(
        &mut self,
        _path: &Path,
        id: FileId,
        _mounts: &Mounts,
    ) -> Result<Option<WritableName>, PolicyError> {
        Ok(self.walked()?.get(&id).cloned())
    }

    /// Windows lists the names of a file, so a single file needs no walk. That matters there:
    /// the programs in `System32` have a second name in the component store.
    #[cfg(windows)]
    fn of_file(
        &mut self,
        path: &Path,
        _id: FileId,
        mounts: &Mounts,
    ) -> Result<Option<WritableName>, PolicyError> {
        let names = windows::names(path).map_err(|source| PolicyError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let writable = self
            .rules
            .iter()
            .filter(|rule| rule.access == PathAccess::ReadWrite);
        for rule in writable {
            if let Some(name) = names
                .iter()
                .find(|name| is_within(name, &rule.path, mounts))
            {
                return Ok(Some(WritableName {
                    path: name.clone(),
                    writable: rule.path.clone(),
                }));
            }
        }
        Ok(None)
    }
}

/// Rule 3 by identity: a file that also has a name inside a writable path is writable, whichever
/// name the policy grants execute access to. Landlock and Seatbelt check the name a call uses,
/// and on Windows the grant of the writable parent lands on the file itself, so the program
/// could rewrite the file through the writable name and still run it through the executable
/// one. The program cannot create such a link itself, so this start-time check holds against
/// it; links that processes outside the sandbox make while it runs are not covered.
fn check_no_writable_second_name(rules: &[PathRule], mounts: &Mounts) -> Result<(), PolicyError> {
    let executable: Vec<&PathRule> = rules
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadExec)
        .collect();
    let conflict = |name: &WritableName, executable: &Path| PolicyError::WritableAndExecutable {
        writable: name.path.clone(),
        executable: executable.to_path_buf(),
        relation: "is another name of",
    };
    let mut writable = WritableNames::new(rules);
    for rule in executable.iter().filter(|rule| !rule.is_dir) {
        let Some(id) = linked_file(&rule.path)? else {
            continue;
        };
        if let Some(name) = writable.of_file(&rule.path, id, mounts)? {
            return Err(conflict(&name, &rule.path));
        }
    }
    let directories: Vec<&&PathRule> = executable.iter().filter(|rule| rule.is_dir).collect();
    if directories.is_empty() {
        return Ok(());
    }
    // Hard links are rare, so the writable paths, which are usually the smaller trees, are
    // walked first; the executable trees are walked only when they can hold the other name.
    let writable = writable.walked()?;
    if writable.is_empty() {
        return Ok(());
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
fn check_no_writable_trusted_name(
    files: &[PathBuf],
    rules: &[PathRule],
    mounts: &Mounts,
) -> Result<(), PolicyError> {
    let mut writable = WritableNames::new(rules);
    for file in files {
        let Some(id) = linked_file(file)? else {
            continue;
        };
        if let Some(name) = writable.of_file(file, id, mounts)? {
            return Err(PolicyError::TrustedFileWritable {
                path: file.clone(),
                through: name.path,
                writable: name.writable,
            });
        }
    }
    Ok(())
}

/// Every name below a writable path that its file shares with another name, by identity.
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
/// links (on Windows also junctions) are not followed, and a directory is entered once, so an
/// alias of a directory inside itself cannot make the walk endless.
///
/// Entries that disappear while the walk runs are skipped, and so are directories this user may
/// not list: the program runs as the same user, so it cannot list them either, and a name it
/// cannot reach cannot carry a grant. `EINVAL` counts as unlistable too, because a directory of
/// a process that is going away reports it (`/proc/<pid>/net` with `--read-write /proc`). Any
/// other error ends the walk, because a tree sandy cannot read is a tree it cannot clear.
fn for_each_linked_file(
    root: &Path,
    visit: &mut impl FnMut(&Path, FileId) -> ControlFlow<()>,
) -> std::io::Result<()> {
    use std::io::ErrorKind;

    let gone = |error: &std::io::Error| {
        matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::InvalidInput
        )
    };
    let mut entered = std::collections::HashSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let entry = match entry(&path) {
            Ok(entry) => entry,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(error),
        };
        if !entry.is_dir {
            if entry.linked && visit(&path, entry.id).is_break() {
                return Ok(());
            }
            continue;
        }
        if !entered.insert(entry.id) {
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

/// Exposed ports listen on loopback only, so a relay never makes the target reachable from other
/// machines. The target must be able to listen, which only `ip = "all"` allows.
fn validate_expose(expose: &[ExposedPort], ip: IpAccess) -> Result<(), PolicyError> {
    let invalid = |expose: &ExposedPort, reason| PolicyError::InvalidExpose {
        expose: *expose,
        reason,
    };
    for entry in expose {
        match ip {
            IpAccess::None => {
                return Err(invalid(entry, "the program needs ip = \"all\" to listen"));
            }
            IpAccess::Client => {
                return Err(invalid(
                    entry,
                    "the program must listen for the relay's connections, and ip = \"client\" \
                     denies listening; use ip = \"all\"",
                ));
            }
            IpAccess::All => {}
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
/// The target connects over IP, which `ip = "client"` and `ip = "all"` allow.
fn validate_forward(forward: &[ForwardedPort], ip: IpAccess) -> Result<(), PolicyError> {
    let invalid = |forward: &ForwardedPort, reason| PolicyError::InvalidForward {
        forward: *forward,
        reason,
    };
    for entry in forward {
        if ip == IpAccess::None {
            return Err(invalid(
                entry,
                "the program needs ip = \"client\" or \"all\" to connect",
            ));
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

    /// `path` without the verbatim prefix that canonical paths have on Windows, as a user or a
    /// known folder spells it.
    fn plain(path: &Path) -> String {
        let text = path.to_str().unwrap();
        text.strip_prefix(r"\\?\").unwrap_or(text).to_string()
    }

    /// A junction at `link` that leads to the directory `target`.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &plain(link), &plain(target)])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
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

    fn with_expose(ip: IpAccess, entries: &[ExposedPort]) -> Policy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.expose = entries.to_vec();
        policy
    }

    #[test]
    fn accepts_loopback_expose_with_ip() {
        for listen in ["127.0.0.1:18080", "[::1]:18080"] {
            let policy = with_expose(IpAccess::All, &[expose(listen, 8080)]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let requirements = resolved.requirements();
            assert!(requirements.contains(&Requirement::ExposedPortsRelayed));
        }
    }

    #[test]
    fn rejects_invalid_expose() {
        let cases = [
            with_expose(IpAccess::None, &[expose("127.0.0.1:18080", 8080)]),
            with_expose(IpAccess::All, &[expose("0.0.0.0:18080", 8080)]),
            with_expose(IpAccess::All, &[expose("192.168.1.2:18080", 8080)]),
            with_expose(IpAccess::All, &[expose("127.0.0.1:0", 8080)]),
            with_expose(IpAccess::All, &[expose("127.0.0.1:18080", 0)]),
            with_expose(IpAccess::All, &[expose("127.0.0.1:8080", 8080)]),
            with_expose(
                IpAccess::All,
                &[
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:18080", 8081),
                ],
            ),
            with_expose(
                IpAccess::All,
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

    /// The program must listen for the relay's connections, which `ip = "client"` denies.
    #[test]
    fn expose_is_refused_with_client() {
        let policy = with_expose(IpAccess::Client, &[expose("127.0.0.1:18080", 8080)]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(
            matches!(error, PolicyError::InvalidExpose { .. }),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("ip = \"client\" denies listening; use ip = \"all\""),
            "{error}"
        );
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

    fn with_forward(ip: IpAccess, entries: &[ForwardedPort]) -> Policy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.forward = entries.to_vec();
        policy
    }

    #[test]
    fn accepts_loopback_forward_with_ip() {
        for to in ["127.0.0.1:8080", "[::1]:8080"] {
            let policy = with_forward(IpAccess::All, &[forward(18080, to)]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let requirements = resolved.requirements();
            assert!(requirements.contains(&Requirement::ForwardedPortsRelayed));
        }
    }

    /// A forwarded port is a connection the program makes, which `ip = "client"` allows.
    #[test]
    fn forward_works_with_client() {
        let policy = with_forward(IpAccess::Client, &[forward(18080, "127.0.0.1:8080")]);
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(requirements.contains(&Requirement::ForwardedPortsRelayed));
        assert!(requirements.contains(&Requirement::InboundIpDenied));
    }

    #[test]
    fn rejects_invalid_forward() {
        let mut cases = vec![
            with_forward(IpAccess::None, &[forward(18080, "127.0.0.1:8080")]),
            with_forward(IpAccess::All, &[forward(18080, "192.168.1.2:8080")]),
            with_forward(IpAccess::All, &[forward(18080, "0.0.0.0:8080")]),
            with_forward(IpAccess::All, &[forward(0, "127.0.0.1:8080")]),
            with_forward(IpAccess::All, &[forward(18080, "127.0.0.1:0")]),
            with_forward(IpAccess::All, &[forward(8080, "127.0.0.1:8080")]),
            with_forward(
                IpAccess::All,
                &[
                    forward(18080, "127.0.0.1:8080"),
                    forward(18080, "127.0.0.1:8081"),
                ],
            ),
        ];
        let mut clashing = with_forward(IpAccess::All, &[forward(18080, "127.0.0.1:8080")]);
        clashing.network.expose = vec![expose("127.0.0.1:18080", 9000)];
        cases.push(clashing);
        let mut looping = with_forward(IpAccess::All, &[forward(18081, "127.0.0.1:18080")]);
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
            policy.network.ip = IpAccess::All;
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
                IpAccess::All,
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
                IpAccess::All,
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
        assert!(!all_denied.contains(&Requirement::InboundIpDenied));
        assert!(all_denied.contains(&Requirement::UnixSocketsDenied));
        assert!(!all_denied.contains(&Requirement::SignalsIsolated));
        assert!(!all_denied.contains(&Requirement::ChildProcessesDenied));
        assert!(!all_denied.contains(&Requirement::ChildProcessesContained));
        assert!(all_denied.contains(&Requirement::MetadataConfined));

        policy.network.ip = IpAccess::All;
        policy.network.unix_sockets = NetworkAccess::All;
        policy.process.signals = SignalScope::Isolated;
        policy.linux.path_metadata = PathMetadata::Allow;
        let allowed = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(baseline.iter().all(|r| allowed.contains(r)));
        assert!(!allowed.contains(&Requirement::IpNetworkDenied));
        assert!(!allowed.contains(&Requirement::InboundIpDenied));
        assert!(!allowed.contains(&Requirement::UnixSocketsDenied));
        assert!(allowed.contains(&Requirement::SignalsIsolated));
        assert!(!allowed.contains(&Requirement::MetadataConfined));

        policy.network.ip = IpAccess::Client;
        let client = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(client.contains(&Requirement::InboundIpDenied));
        assert!(!client.contains(&Requirement::IpNetworkDenied));

        // children = "none" needs unix_sockets = "none" (see rejects_children_none_with_unix_sockets).
        policy.network.unix_sockets = NetworkAccess::None;
        policy.process.children = ChildProcesses::None;
        let no_children = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(no_children.contains(&Requirement::ChildProcessesDenied));
    }

    /// `windows.win32k` is opt-in: the default asks for nothing, `deny` for the requirement,
    /// which every platform reports (the platforms without win32k as enforced).
    #[test]
    fn win32k_requirement_follows_the_policy() {
        let mut policy = Policy::default();
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(!requirements.contains(&Requirement::Win32kDenied));

        policy.windows.win32k = Win32k::Deny;
        let requirements = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(requirements.contains(&Requirement::Win32kDenied));
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

    /// The same with junctions, which Windows follows like symbolic links of directories and
    /// which every user may make.
    #[cfg(windows)]
    #[test]
    fn rejects_a_path_resolved_through_a_junction_in_a_writable_path() {
        let root = temp_dir();
        let data = root.join("data");
        let outside = root.join("outside");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let through = data.join("shared");
        junction(&through, &outside);

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
        fs::write(outside.join("program.exe"), b"").unwrap();
        let policy = policy_with(&[], &[], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, Some(&through.join("program.exe"))),
            Err(PolicyError::ResolvedThroughWritable { .. })
        ));

        // A chain: a junction outside the writable path leads through a junction inside it.
        let chain = root.join("chain");
        junction(&chain, &through);
        let policy = policy_with(&[&chain], &[], &[&data]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, None),
            Err(PolicyError::ResolvedThroughWritable { .. })
        ));

        // Control: the same junctions are fine without the writable path.
        let policy = policy_with(&[&through, &chain], &[], &[]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
        // A junction outside writable paths may point anywhere outside them.
        let direct = root.join("direct");
        junction(&direct, &outside);
        let policy = policy_with(&[&direct], &[], &[&data]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
        // Windows resolves `..` by its spelling before it looks a path up, so this path never
        // passes the junction.
        let back = Path::new(&plain(&through)).join(r"..\..\outside");
        let policy = policy_with(&[&back], &[], &[&data]);
        ResolvedPolicy::resolve(&policy, None).unwrap();
    }

    /// A writable path named through a symbolic link that lies outside it, a home directory link
    /// to another disk for example, or `/tmp` on macOS. The program cannot change that link, so
    /// the next start resolves the same way.
    #[cfg(unix)]
    #[test]
    fn accepts_a_writable_path_named_through_a_link_outside_it() {
        use std::os::unix::fs::symlink;
        let root = temp_dir();
        let (data, link) = (root.join("data"), root.join("link"));
        fs::create_dir_all(data.join("sub")).unwrap();
        symlink(&data, &link).unwrap();

        let resolved = ResolvedPolicy::resolve(&policy_with(&[], &[], &[&link]), None).unwrap();
        assert_eq!(resolved.paths[0].path, data);
        let trusted = root.join("policy.toml");
        fs::write(&trusted, b"").unwrap();
        resolved.check_trusted(&[trusted]).unwrap();

        // Control: a path that continues through the link into the writable path is refused.
        let policy = policy_with(&[&link.join("sub")], &[], &[&link]);
        assert!(matches!(
            ResolvedPolicy::resolve(&policy, None),
            Err(PolicyError::InsideWritable { .. })
        ));
    }

    /// The file systems of macOS ignore case and Unicode normalization by default, so a writable
    /// path may be named in another spelling than the one on disk. It is then the writable path
    /// itself, not an entry inside it.
    #[cfg(target_os = "macos")]
    #[test]
    fn accepts_a_writable_path_named_in_another_spelling() {
        let root = temp_dir();
        let (composed, decomposed) = ("caf\u{e9}", "cafe\u{301}");
        for (on_disk, given) in [("Data", "DATA"), (composed, decomposed)] {
            fs::create_dir_all(root.join(on_disk).join("sub")).unwrap();
            let given = root.join(given);
            let policy = policy_with(&[], &[], &[&given]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            assert_eq!(resolved.paths[0].path, root.join(on_disk));

            // Control: a path below it in the same spelling lies inside it.
            let policy = policy_with(&[&given.join("sub")], &[], &[&given]);
            assert!(matches!(
                ResolvedPolicy::resolve(&policy, None),
                Err(PolicyError::InsideWritable { .. })
            ));
        }
    }

    /// One directory under two paths is one object: rules 3 and 4 compare file identity too.
    #[test]
    fn the_same_directory_under_another_path_is_within_it() {
        let dir = temp_dir();
        fs::create_dir_all(dir.join("sub")).unwrap();
        // Another spelling of the same directory: through the process's root on Linux, through
        // the data volume on macOS, where the temporary directory lies, and on Windows without
        // the verbatim prefix and in upper case, which its file systems ignore.
        let other = if cfg!(windows) {
            PathBuf::from(plain(&dir).to_uppercase())
        } else {
            let prefix = if cfg!(target_os = "linux") {
                "/proc/self/root"
            } else {
                "/System/Volumes/Data"
            };
            Path::new(prefix).join(dir.strip_prefix("/").unwrap())
        };
        let mounts = Mounts::read().unwrap();
        assert!(!other.join("sub").starts_with(&dir));
        assert!(is_within(&other.join("sub"), &dir, &mounts));
        assert!(is_within(&dir.join("sub"), &other, &mounts));
        assert!(!is_within(&dir, &dir.join("sub"), &mounts));
    }

    /// A named pipe is no program. Reading its `#!` line must not wait for a writer that never
    /// comes, or check and run hang instead of reporting.
    #[cfg(unix)]
    #[test]
    fn a_named_pipe_has_no_shebang_and_does_not_block() {
        let dir = temp_dir();
        // Control: the `#!` line of a script.
        let script = dir.join("script");
        fs::write(&script, b"#!/bin/sh -e\n").unwrap();
        assert_eq!(shebang(&script), Some(PathBuf::from("/bin/sh")));

        let pipe = dir.join("pipe");
        let path = std::ffi::CString::new(pipe.to_str().unwrap()).unwrap();
        // SAFETY: the path is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o700) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || send.send(shebang(&pipe)));
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        assert_eq!(result, Ok(None));
    }

    /// Rule 3 by identity: one file under two names, one of them writable.
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
    #[test]
    fn rejects_a_trusted_file_a_writable_path_reaches() {
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

        // Reached through a symbolic link inside the writable path, on Windows through a
        // junction to its directory, which needs no privilege to make.
        #[cfg(unix)]
        let through_link = {
            std::os::unix::fs::symlink(&trusted, data.join("policy.toml")).unwrap();
            data.join("policy.toml")
        };
        #[cfg(windows)]
        let through_link = {
            junction(&data.join("safe"), &safe);
            data.join("safe").join("policy.toml")
        };
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

    fn writable_conflict(
        writable: &Path,
        protected: &[ProtectedPath],
    ) -> Option<(PathBuf, PathBuf)> {
        let policy = policy_with(&[], &[], &[writable]);
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        let identity = PathIdentity::read().unwrap();
        resolved
            .writable_conflict(protected, &identity)
            .map(|(rule, location)| (rule.path.clone(), location.path.clone()))
    }

    #[test]
    fn only_the_absolute_directories_of_a_path_variable_are_protected() {
        let (separator, first, second) = if cfg!(windows) {
            (";", "C:\\bin", "C:\\tools")
        } else {
            (":", "/usr/bin", "/usr/local/bin")
        };
        // A repeated entry, one that is not absolute, and an empty one.
        let value = [first, "relative", "", first, second].join(separator);
        let directories: Vec<PathBuf> = path_directories(Some(value.as_ref()))
            .into_iter()
            .map(|location| location.path)
            .collect();
        assert_eq!(
            directories,
            vec![PathBuf::from(first), PathBuf::from(second)]
        );
        assert!(path_directories(None).is_empty());
    }

    /// A protected location counts where it lies and where its symbolic links lead, also when
    /// the location itself does not exist yet.
    #[cfg(unix)]
    #[test]
    fn a_protected_location_counts_where_its_links_lead() {
        let dir = temp_dir();
        let (real, link) = (dir.join("real"), dir.join("link"));
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let shell_file = ProtectedPath::entry(link.join(".bashrc"));
        assert_eq!(
            writable_conflict(&real, &[shell_file]),
            Some((real.clone(), link.join(".bashrc")))
        );

        // A link whose target does not exist yet, which the program could create.
        let home = dir.join("home");
        fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink("../real/profile", home.join(".profile")).unwrap();
        let profile = ProtectedPath::entry(home.join(".profile"));
        assert_eq!(
            writable_conflict(&real, &[profile]),
            Some((real, home.join(".profile")))
        );
    }

    /// Windows names its known folders without the verbatim prefix of canonical paths, and a
    /// location counts where it lies and where its links lead. With a junction inside the
    /// writable path on the way, the location leads out of it, and only the identity of the
    /// directories on the way shows that the writable path holds it: the program could replace
    /// the junction with a directory of its own.
    #[cfg(windows)]
    #[test]
    fn a_protected_location_reached_through_a_junction_inside_a_writable_path_is_reported() {
        let dir = temp_dir();
        let (home, elsewhere, data) = (dir.join("home"), dir.join("elsewhere"), dir.join("data"));
        for directory in [&home, &elsewhere, &data] {
            fs::create_dir_all(directory).unwrap();
        }
        junction(&home.join("config"), &elsewhere);
        let startup = Path::new(&plain(&home)).join("config").join("startup");
        let location = ProtectedPath::tree(&startup);
        assert_eq!(
            writable_conflict(&home, std::slice::from_ref(&location)),
            Some((home.clone(), startup))
        );
        // Control: a writable path beside it.
        assert_eq!(writable_conflict(&data, &[location]), None);
    }

    #[test]
    fn a_writable_path_that_reaches_a_protected_location_is_reported() {
        let dir = temp_dir();
        let home = dir.join("home");
        let data = home.join("data");
        fs::create_dir_all(&data).unwrap();
        let conflict = writable_conflict;
        // The writable path holds the location, which does not exist yet.
        let shell_file = ProtectedPath::entry(home.join(".bashrc"));
        assert_eq!(
            conflict(&home, std::slice::from_ref(&shell_file)),
            Some((home.clone(), home.join(".bashrc")))
        );
        // A writable path beside it is accepted, and so is one below a location that protects
        // itself only.
        assert_eq!(conflict(&data, std::slice::from_ref(&shell_file)), None);
        assert_eq!(conflict(&data, &[ProtectedPath::entry(&home)]), None);
        // A location that protects its tree also refuses a writable path below it.
        assert_eq!(
            conflict(&data, &[ProtectedPath::tree(&home)]),
            Some((data.clone(), home.clone()))
        );
    }

    /// A link at `link` to the directory `target`: a symbolic link on Unix, a junction on
    /// Windows.
    fn directory_link(link: &Path, target: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        junction(link, target);
    }

    /// A warning names only a real overlap (rule 12). A PATH directory that does not exist, also
    /// one below a link that leads elsewhere, does not reach an unrelated writable path, and one
    /// whose identity sandy cannot read is compared by its spellings, while a refusal counts it
    /// as an overlap. On Windows a name the file system rejects stands for such a directory: the
    /// junction that an elevated process may not follow cannot be made from here (see
    /// `escape_windows::warns_only_about_path_directories_a_writable_path_really_holds`).
    #[test]
    fn a_path_directory_is_warned_about_only_where_a_writable_path_holds_it() {
        let dir = temp_dir();
        let (tools, data) = (dir.join("tools"), dir.join("data"));
        fs::create_dir_all(tools.join("1.0")).unwrap();
        fs::create_dir_all(&data).unwrap();
        directory_link(&tools.join("current"), &tools.join("1.0"));
        directory_link(&dir.join("into"), &data);
        let notes = |writable: &Path, directories: &[PathBuf]| {
            let policy = policy_with(&[], &[], &[writable]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let directories: Vec<ProtectedPath> =
                directories.iter().map(ProtectedPath::entry).collect();
            resolved.path_directory_notes(&directories).len()
        };
        let unreadable = dir.join("bad|name").join("bin");

        let mut unrelated = vec![
            tools.join("current").join("bin"),
            dir.join("missing").join("bin"),
        ];
        unrelated.push(unreadable.clone());
        for directory in &unrelated {
            assert_eq!(
                notes(&data, std::slice::from_ref(directory)),
                0,
                "{directory:?}"
            );
        }
        // Controls: inside the writable path, also through a link into it and not created yet.
        let inside = [data.join("bin"), dir.join("into").join("bin")];
        for directory in &inside {
            assert_eq!(
                notes(&data, std::slice::from_ref(directory)),
                1,
                "{directory:?}"
            );
        }
        // A refusal counts what sandy cannot tell apart as an overlap.
        let refused = writable_conflict(&data, &[ProtectedPath::entry(&unreadable)]);
        assert_eq!(refused.is_some(), cfg!(windows), "{refused:?}");
    }

    /// A writable path that holds a directory on PATH is warned about, not refused (rule 12),
    /// and every such directory is named, so one run lists them all.
    #[test]
    fn every_directory_on_path_inside_a_writable_path_is_named() {
        let dir = temp_dir();
        let tools = dir.join("tools");
        let directories = [
            ProtectedPath::entry(tools.join("bin")),
            ProtectedPath::entry(tools.join("sbin")),
            ProtectedPath::entry(dir.join("beside")),
        ];
        fs::create_dir_all(tools.join("bin/sub")).unwrap();
        let notes = |writable: &Path| {
            let policy = policy_with(&[], &[], &[writable]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            resolved.path_directory_notes(&directories)
        };

        let warned = notes(&tools);
        assert_eq!(warned.len(), 2, "{warned:?}");
        for (note, directory) in warned.iter().zip(["bin", "sbin"]) {
            assert!(note.contains("types its name"), "{note}");
            // The advice keeps the directory out of the writable paths; another PATH for sandy
            // would only silence the warning.
            assert!(note.contains("make only the subdirectories"), "{note}");
            assert!(!note.contains("start sandy with"), "{note}");
            assert!(
                note.contains(&tools.join(directory).display().to_string()),
                "{note}"
            );
        }
        // A directory on PATH that the writable path does not hold says nothing, and neither
        // does a writable path below one of them: it puts nothing on PATH.
        assert!(notes(&tools.join("bin/sub")).is_empty());
    }
}
