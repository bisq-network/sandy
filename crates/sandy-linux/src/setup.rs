//! `sandy setup` on Linux. On Ubuntu 23.10 and newer an unconfined process gets no capabilities in
//! a user namespace it creates (`kernel.apparmor_restrict_unprivileged_userns`), so
//! `ip = "private"` needs an AppArmor profile with the `userns,` rule for sandy. Only root can
//! load one. A profile attaches to a path, and whatever file sits there gets the right, so setup
//! writes one only for a path that only root can change (`root_only`):
//!
//! - `setup` prepares the file that runs.
//! - `setup --install-copy` installs a root-owned copy of the running image at `copy_path` and
//!   prepares that copy. A sandy whose own file is not root-owned hands over to it
//!   (`relaunch`).
//! - `setup --remove` unloads and deletes the profile of the file that runs, and only a file
//!   that carries sandy's marker; with `--install-copy` also the copy's profile, the copy and
//!   its directory.
//!
//! Where the restriction does not apply, setup has nothing to do.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use sandy_core::{SandboxError, SetupOptions, SetupOutcome};

use crate::namespace::{self, APPARMOR_RESTRICTION, Missing};

const APPARMOR_ENABLED: &str = "/sys/module/apparmor/parameters/enabled";
const PROFILE_DIRECTORY: &str = "/etc/apparmor.d";
/// One directory per loaded profile, `NAME.N`, with the files `name` and `mode`, which every
/// user may read. The attachment reads `<unknown>`, also for root.
const POLICY_PROFILES: &str = "/sys/kernel/security/apparmor/policy/profiles";
const PARSERS: [&str; 2] = ["/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"];
/// `--install-copy` puts the copy at `COPY_DIRECTORY/VERSION/sandy`.
pub const COPY_DIRECTORY: &str = "/usr/local/libexec/sandy";
/// Names of the files setup writes before it renames them into place. The leading dot keeps the
/// AppArmor parser from loading one that a crash left in /etc/apparmor.d.
const TEMPORARY_PREFIX: &str = ".sandy-setup.";
/// What every refusal of setup on Linux ends with, so a caller knows what to do instead.
pub const FALLBACK: &str = "nothing changed; until setup is done, run policies without \
    ip = \"private\" on this host";

/// The copy that `--install-copy` installs for this version of sandy.
pub fn copy_path() -> PathBuf {
    Path::new(COPY_DIRECTORY)
        .join(env!("CARGO_PKG_VERSION"))
        .join("sandy")
}

/// Why this host does not restrict the user namespaces of unconfined processes, `None` when it
/// does.
pub fn unrestricted() -> Option<&'static str> {
    if read(APPARMOR_RESTRICTION).as_deref() != Some("1") {
        return Some(
            "this host does not restrict user namespaces with AppArmor \
             (kernel.apparmor_restrict_unprivileged_userns is absent or 0)",
        );
    }
    if read(APPARMOR_ENABLED).as_deref() != Some("Y") {
        return Some(
            "AppArmor is not enabled, so its restriction of user namespaces does not apply",
        );
    }
    None
}

/// Whether only root can change what `path` names: the entry and every directory above it, up
/// to `/`, belong to root, none is writable by its group or by others, none is a symbolic link,
/// and none lies on a file system mounted `nosuid`, which is how a user's removable disk or FUSE
/// mount arrives. Only the mode is read: the group bits of a file with a POSIX ACL are the ACL's
/// mask, which bounds every named user and group entry, so a mask without write leaves only
/// root. Other kinds of ACL, such as NFSv4 ACLs, are not read.
///
/// With `allow_missing`, a path whose end does not exist yet passes when the part that exists
/// passes: only root can create entries in such a directory.
pub fn root_only(path: &Path, allow_missing: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(name) => current.push(name),
            _ => return Err(format!("{} is not a plain absolute path", path.display())),
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(format!("cannot read {}: {error}", current.display())),
        };
        let shown = current.display();
        if metadata.file_type().is_symlink() {
            return Err(format!("{shown} is a symbolic link"));
        }
        if metadata.uid() != 0 {
            return Err(format!(
                "{shown} belongs to user {}, not to root",
                metadata.uid()
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!(
                "{shown} is writable by its group or by others (mode {:o})",
                metadata.mode() & 0o7777
            ));
        }
        if mounted_nosuid(&current)? {
            return Err(format!(
                "{shown} lies on a file system mounted nosuid, whose files the system does not \
                 trust with rights"
            ));
        }
    }
    Ok(())
}

fn mounted_nosuid(path: &Path) -> Result<bool, String> {
    let failed = |error: io::Error| format!("cannot read the mount of {}: {error}", path.display());
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| failed(io::Error::from(io::ErrorKind::InvalidInput)))?;
    // SAFETY: statvfs is plain data; all zeros is a valid value that the call overwrites.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: name is NUL-terminated and stats is a writable statvfs.
    if unsafe { libc::statvfs(name.as_ptr(), &mut stats) } != 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    Ok(stats.f_flag & libc::ST_NOSUID != 0)
}

/// The file of this process, as the kernel resolved it: the path AppArmor compares a profile's
/// attachment with.
pub fn own_path() -> Result<PathBuf, String> {
    let path = fs::read_link("/proc/self/exe")
        .map_err(|error| format!("cannot find the file of this sandy: {error}"))?;
    let running = fs::metadata("/proc/self/exe");
    let at_path = fs::metadata(&path);
    match (running, at_path) {
        (Ok(running), Ok(at_path))
            if (running.dev(), running.ino()) == (at_path.dev(), at_path.ino()) =>
        {
            Ok(path)
        }
        // The kernel names a deleted file "PATH (deleted)".
        _ => Err(format!(
            "the file of this sandy, {}, was replaced or deleted since it started; start sandy \
             again",
            path.display()
        )),
    }
}

/// The AppArmor profile that lets the file at a path create user namespaces with rights in
/// them, and allows nothing else: `flags=(unconfined)` leaves every other right as an unconfined
/// process has it, and the profile's name becomes the label that the restriction looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The profile's name, which is also its file name in /etc/apparmor.d.
    pub name: String,
    pub file: PathBuf,
    /// The first line of the file: it marks the file as sandy's and names the path.
    pub marker: String,
    pub text: String,
}

impl Profile {
    /// The attachment is a pattern in AppArmor, so `path` may hold only characters that match
    /// themselves there; the profile name and file name are the path with `/` as `.`.
    pub fn for_path(path: &Path) -> Result<Profile, String> {
        let literal = path
            .to_str()
            .filter(|text| is_literal_path(text))
            .ok_or_else(|| {
                format!(
                    "{} holds characters other than letters, digits, '.', '_', '+' and '-', \
                     which an AppArmor attachment cannot name as they are",
                    path.display()
                )
            })?;
        let name = format!("sandy-setup{}", literal.replace('/', "."));
        if name.len() > 255 {
            return Err(format!(
                "{literal} is too long for the name of an AppArmor profile file"
            ));
        }
        let marker =
            format!("# Written by sandy setup for {literal}. `sandy setup --remove` deletes it.");
        let text = format!(
            "{marker}\nabi <abi/4.0>,\n\nprofile {name} {literal} flags=(unconfined) {{\n  \
             userns,\n}}\n"
        );
        Ok(Profile {
            file: Path::new(PROFILE_DIRECTORY).join(&name),
            name,
            marker,
            text,
        })
    }

    /// Whether `content`, read from a profile file, starts with the marker line `marker`.
    fn is_ours(content: &[u8], marker: &str) -> bool {
        content.split(|&byte| byte == b'\n').next() == Some(marker.as_bytes())
    }
}

fn is_literal_path(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    })
}

/// The mode of the loaded profile called `name`, `None` when the kernel has none.
pub fn loaded_mode(name: &str) -> Option<String> {
    let entries = fs::read_dir(POLICY_PROFILES).ok()?;
    for entry in entries.flatten() {
        let directory = entry.file_name();
        let number = directory
            .to_str()
            .and_then(|directory| directory.strip_prefix(name))
            .and_then(|rest| rest.strip_prefix('.'));
        if !number.is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            continue;
        }
        if read(entry.path().join("name")).as_deref() == Some(name) {
            return read(entry.path().join("mode"));
        }
    }
    None
}

/// How a step of setup stops early: refused with nothing changed (status 3), or failed (125).
#[derive(Debug)]
enum Stop {
    Refused(String),
    Failed(SandboxError),
}

impl From<SandboxError> for Stop {
    fn from(error: SandboxError) -> Self {
        Stop::Failed(error)
    }
}

type Step<T> = Result<T, Stop>;

fn finish(step: Step<String>) -> Result<SetupOutcome, SandboxError> {
    match step {
        Ok(done) => Ok(SetupOutcome::Done(done)),
        Err(Stop::Refused(reason)) => Ok(SetupOutcome::Refused(format!("{reason}; {FALLBACK}"))),
        Err(Stop::Failed(error)) => Err(error),
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn require_root() -> Step<()> {
    if is_root() {
        return Ok(());
    }
    Err(Stop::Refused(
        "setup needs root on this host; `sandy setup --elevate` asks for the rights, or run it \
         with sudo"
            .to_string(),
    ))
}

/// `sandy setup`, run as root.
pub fn setup(options: SetupOptions) -> Result<SetupOutcome, SandboxError> {
    finish(prepare(options))
}

fn prepare(options: SetupOptions) -> Step<String> {
    if let Some(reason) = disabled(&namespace::support(&namespace::Purpose::Any)) {
        return Err(Stop::Refused(reason));
    }
    if let Some(reason) = unrestricted() {
        return Ok(format!("nothing to do: {reason}"));
    }
    require_root()?;
    let target = if options.install_copy {
        install_copy()?
    } else {
        let own = own_path().map_err(Stop::Refused)?;
        root_only(&own, false).map_err(|reason| Stop::Refused(not_root_only(&reason)))?;
        own
    };
    install_profile(&target)
}

/// Why setup cannot help where the host disables user namespaces altogether, which `check`
/// reports as plainly unavailable: a profile lifts only the AppArmor restriction. `None` for
/// what `support` says otherwise.
pub fn disabled(support: &namespace::Support) -> Option<String> {
    match support {
        Err(Missing::Unavailable(reason)) => Some(format!(
            "{reason}; setup cannot change that, because an AppArmor profile does not enable              them"
        )),
        Err(Missing::NeedsSetup(_)) | Ok(()) => None,
    }
}

/// Why setup refuses a sandy whose own file is not root-owned, and what to do instead.
fn not_root_only(reason: &str) -> String {
    format!(
        "setup is not allowed for this binary: {reason}. An AppArmor profile gives user \
         namespaces to whatever file is at the path it names, so setup writes one only for a \
         path that only root can change. Install sandy from a package, or run \
         `sandy setup --install-copy`, which installs a root-owned copy of this sandy as {} and \
         prepares the host for that copy",
        copy_path().display()
    )
}

/// Copies the running image of sandy, never the file at its path, to `copy_path`, root-owned
/// with mode 0755. An identical copy stays as it is.
fn install_copy() -> Step<PathBuf> {
    let copy = copy_path();
    let directory = copy.parent().expect("the copy has a directory");
    root_only(directory, true).map_err(|reason| {
        Stop::Refused(format!(
            "cannot install the copy in {}: {reason}",
            directory.display()
        ))
    })?;
    let image = fs::read("/proc/self/exe")
        .map_err(|error| SandboxError::io("cannot read the running sandy", error))?;
    create_directories(directory)?;
    if !is_copy_of(&copy, &image) {
        write_atomically(&copy, &image, 0o755)
            .map_err(|error| SandboxError::io(format!("cannot write {}", copy.display()), error))?;
    }
    if !is_copy_of(&copy, &image) {
        return Err(Stop::Failed(SandboxError::new(format!(
            "{} is not a root-owned copy of the running sandy after writing it",
            copy.display()
        ))));
    }
    Ok(copy)
}

/// Whether `path` is a regular file that only root can change and holds `image`.
fn is_copy_of(path: &Path, image: &[u8]) -> bool {
    root_only(path, false).is_ok()
        && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
        && fs::read(path).is_ok_and(|content| content == image)
}

/// Creates the missing directories of `directory`, owned by root and with mode 0755 whatever
/// the umask and the parent's default ACL or set-group-ID bit say.
fn create_directories(directory: &Path) -> Result<(), SandboxError> {
    let mut missing: Vec<&Path> = directory
        .ancestors()
        .take_while(|path| fs::symlink_metadata(path).is_err())
        .collect();
    missing.reverse();
    for path in missing {
        let failed = |error| SandboxError::io(format!("cannot create {}", path.display()), error);
        match DirBuilder::new().mode(0o755).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(failed(error)),
        }
        std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(failed)?;
        fs::set_permissions(path, Permissions::from_mode(0o755)).map_err(failed)?;
    }
    root_only(directory, false).map_err(|reason| {
        SandboxError::new(format!(
            "{} is not root-only after creating it: {reason}",
            directory.display()
        ))
    })
}

/// Writes `content` to `path` through a new file in the same directory that is renamed into
/// place, so a reader sees the old file or the new one, never part of one. The directory must
/// be one only root can change, which makes the temporary name safe to reuse.
fn write_atomically(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let directory = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = directory.join(format!(
        "{TEMPORARY_PREFIX}{}.{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let written = (|| {
        file.write_all(content)?;
        std::os::unix::fs::fchown(&file, Some(0), Some(0))?;
        file.set_permissions(Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// Writes the profile for `target` unless an identical one is there, loads it and checks that
/// the kernel has it.
fn install_profile(target: &Path) -> Step<String> {
    let profile = Profile::for_path(target).map_err(Stop::Refused)?;
    let shown = profile.file.display();
    match fs::read(&profile.file) {
        Ok(content) if content == profile.text.as_bytes() => {}
        Ok(content) if Profile::is_ours(&content, &profile.marker) => {
            write_profile(&profile)?;
        }
        Ok(_) => {
            return Err(Stop::Refused(format!(
                "{shown} exists, and sandy did not write it, so setup leaves it alone"
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => write_profile(&profile)?,
        Err(error) => {
            return Err(Stop::Failed(SandboxError::io(
                format!("cannot read {shown}"),
                error,
            )));
        }
    }
    apparmor_parser("--replace", &profile.file)?;
    if loaded_mode(&profile.name).as_deref() != Some("unconfined") {
        return Err(Stop::Failed(SandboxError::new(format!(
            "apparmor_parser loaded {shown}, but the kernel has no unconfined profile {}",
            profile.name
        ))));
    }
    Ok(format!(
        "loaded the AppArmor profile {shown}, which lets {} use user namespaces; it loads \
         again at every start of the system",
        target.display()
    ))
}

fn write_profile(profile: &Profile) -> Result<(), SandboxError> {
    write_atomically(&profile.file, profile.text.as_bytes(), 0o644).map_err(|error| {
        SandboxError::io(format!("cannot write {}", profile.file.display()), error)
    })
}

/// Runs the AppArmor parser with `action` on the profile `file`, in an environment of its own.
fn apparmor_parser(action: &str, file: &Path) -> Result<(), SandboxError> {
    let parser = PARSERS
        .into_iter()
        .find(|parser| Path::new(parser).exists())
        .ok_or_else(|| {
            SandboxError::new(format!(
                "AppArmor is enabled, but its parser is in none of {}",
                PARSERS.join(", ")
            ))
        })?;
    let output = Command::new(parser)
        .arg(action)
        .arg("--")
        .arg(file)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| SandboxError::io(format!("cannot run {parser}"), error))?;
    if !output.status.success() {
        return Err(SandboxError::new(format!(
            "{parser} {action} {} failed ({}): {}",
            file.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// `sandy setup --remove`, run as root.
pub fn remove(options: SetupOptions) -> Result<SetupOutcome, SandboxError> {
    finish(take_back(options))
}

/// The files setup would remove: whether any is there.
pub fn something_to_remove(options: SetupOptions) -> bool {
    targets(options)
        .iter()
        .any(|target| marked_profile(target).is_some())
        || (options.install_copy && copy_path().parent().is_some_and(|path| path.exists()))
}

/// The paths whose profiles a removal takes back. The file of this process is named by its
/// path even when it was replaced since, because the profile follows the path.
fn targets(options: SetupOptions) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = fs::read_link("/proc/self/exe").into_iter().collect();
    if options.install_copy {
        targets.push(copy_path());
    }
    targets
}

/// The profile for `target` when its file is there and carries sandy's marker.
fn marked_profile(target: &Path) -> Option<Profile> {
    let profile = Profile::for_path(target).ok()?;
    let content = fs::read(&profile.file).ok()?;
    Profile::is_ours(&content, &profile.marker).then_some(profile)
}

fn take_back(options: SetupOptions) -> Step<String> {
    if !something_to_remove(options) {
        return Ok("nothing to remove".to_string());
    }
    require_root()?;
    let mut done = Vec::new();
    for target in targets(options) {
        let Some(profile) = marked_profile(&target) else {
            continue;
        };
        if loaded_mode(&profile.name).is_some() {
            apparmor_parser("--remove", &profile.file)?;
            if loaded_mode(&profile.name).is_some() {
                return Err(Stop::Failed(SandboxError::new(format!(
                    "apparmor_parser removed {}, but the kernel still has the profile {}",
                    profile.file.display(),
                    profile.name
                ))));
            }
        }
        remove_entry(&profile.file)?;
        done.push(format!("unloaded and deleted {}", profile.file.display()));
    }
    if options.install_copy {
        done.extend(remove_copy()?);
    }
    if done.is_empty() {
        return Ok("nothing to remove".to_string());
    }
    Ok(done.join("; "))
}

/// Deletes the copy, what setup left of its temporary files, and its directories when they are
/// empty then.
fn remove_copy() -> Step<Vec<String>> {
    let copy = copy_path();
    let directory = copy.parent().expect("the copy has a directory");
    // Root deletes here, so no one else may have been able to put a link in the way.
    root_only(directory, true).map_err(|reason| {
        Stop::Refused(format!(
            "leaves the copy in {} alone: {reason}",
            directory.display()
        ))
    })?;
    let mut done = Vec::new();
    if fs::symlink_metadata(&copy).is_ok() {
        remove_entry(&copy)?;
        done.push(format!("deleted {}", copy.display()));
    }
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(TEMPORARY_PREFIX)
            {
                remove_entry(&entry.path())?;
            }
        }
    }
    for directory in [directory, Path::new(COPY_DIRECTORY)] {
        match fs::remove_dir(directory) {
            Ok(()) => done.push(format!("deleted {}", directory.display())),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => {
                return Err(Stop::Failed(SandboxError::io(
                    format!("cannot delete {}", directory.display()),
                    error,
                )));
            }
        }
    }
    Ok(done)
}

fn remove_entry(path: &Path) -> Result<(), SandboxError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SandboxError::io(
                format!("cannot delete {}", path.display()),
                error,
            ));
        }
    }
    if let Some(directory) = path.parent() {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                SandboxError::io(format!("cannot sync {}", directory.display()), error)
            })?;
    }
    Ok(())
}

pub(crate) fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_allows_user_namespaces_for_the_exact_path() {
        let profile = Profile::for_path(Path::new("/usr/local/libexec/sandy/2.1.0/sandy")).unwrap();
        assert_eq!(
            profile.name,
            "sandy-setup.usr.local.libexec.sandy.2.1.0.sandy"
        );
        assert_eq!(
            profile.file,
            Path::new("/etc/apparmor.d/sandy-setup.usr.local.libexec.sandy.2.1.0.sandy")
        );
        assert_eq!(
            profile.text,
            "# Written by sandy setup for /usr/local/libexec/sandy/2.1.0/sandy. \
             `sandy setup --remove` deletes it.\n\
             abi <abi/4.0>,\n\
             \n\
             profile sandy-setup.usr.local.libexec.sandy.2.1.0.sandy \
             /usr/local/libexec/sandy/2.1.0/sandy flags=(unconfined) {\n  userns,\n}\n"
        );
        assert!(Profile::is_ours(profile.text.as_bytes(), &profile.marker));
        assert!(!Profile::is_ours(
            b"profile x /usr/bin/x {\n}\n",
            &profile.marker
        ));
        // A marker for another path is not this profile's.
        let other = Profile::for_path(Path::new("/usr/bin/sandy")).unwrap();
        assert!(!Profile::is_ours(profile.text.as_bytes(), &other.marker));
    }

    /// The attachment is an AppArmor pattern, and the profile is a file of rules: a path that
    /// could mean more than itself, or reach into the rules, gets no profile.
    #[test]
    fn a_path_that_is_not_literal_gets_no_profile() {
        for path in [
            "/opt/sandy*/sandy",
            "/opt/sandy?/sandy",
            "/opt/{a,b}/sandy",
            "/opt/[ab]/sandy",
            "/opt/@{HOME}/sandy",
            "/opt/my sandy/sandy",
            "/opt/sandy (deleted)",
            "/opt/x {\n  capability,\n}\n/sandy",
            "/opt/a\\b/sandy",
            "/opt/\"sandy\"",
            "/opt//sandy",
            "/opt/../sandy",
            "/opt/./sandy",
            "/opt/sandy/",
            "relative/sandy",
            "/opt/sändy",
        ] {
            assert!(Profile::for_path(Path::new(path)).is_err(), "{path}");
        }
        assert!(Profile::for_path(Path::new("/opt/My_Tool-2.1.0+rc1/sandy")).is_ok());
        let long = format!("/{}", "a".repeat(250));
        assert!(Profile::for_path(Path::new(&long)).is_err());
    }

    /// Where the host disables user namespaces, `check` reports them unavailable (status 1),
    /// so setup, which only lifts the AppArmor restriction, refuses instead of preparing.
    #[test]
    fn disabled_user_namespaces_are_beyond_setup() {
        let reason = "user namespaces are disabled on this host \
                      (kernel.unprivileged_userns_clone = 0)";
        let refusal = disabled(&Err(Missing::Unavailable(reason.to_string()))).unwrap();
        assert!(refusal.starts_with(reason), "{refusal}");
        assert!(refusal.contains("setup cannot change that"), "{refusal}");
        assert_eq!(
            disabled(&Err(Missing::NeedsSetup("restricted".to_string()))),
            None
        );
        assert_eq!(disabled(&Ok(())), None);
    }

    #[test]
    fn the_copy_belongs_to_this_version() {
        assert_eq!(
            copy_path(),
            Path::new(COPY_DIRECTORY)
                .join(env!("CARGO_PKG_VERSION"))
                .join("sandy")
        );
        assert!(Profile::for_path(&copy_path()).is_ok());
    }

    /// The system's own binaries only root can change; the user that runs the tests can change
    /// a temporary directory and the home directory.
    #[test]
    fn only_a_root_owned_chain_is_root_only() {
        root_only(Path::new("/usr/bin"), false).unwrap();
        // Some systems make /usr/bin/env a link to a multi-call binary, as Ubuntu 25.10 does.
        root_only(&fs::canonicalize("/usr/bin/env").unwrap(), false).unwrap();
        root_only(Path::new("/usr/bin/not-a-file-of-sandy"), true).unwrap();
        assert!(root_only(Path::new("/usr/bin/not-a-file-of-sandy"), false).is_err());
        assert!(root_only(Path::new("usr/bin"), false).is_err());

        let directory =
            std::env::temp_dir().join(format!("sandy-root-only-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let file = directory.join("sandy");
        fs::write(&file, b"x").unwrap();
        assert!(root_only(&file, false).is_err());
        // A missing end passes only when what exists passes.
        assert!(root_only(&directory.join("missing"), true).is_err());
        fs::remove_dir_all(&directory).unwrap();

        // The sticky bit does not make an entry root-only.
        let reason = root_only(Path::new("/tmp/sandy"), true).unwrap_err();
        assert!(
            reason.contains("/tmp is writable by its group or by others (mode 1777)"),
            "{reason}"
        );
        // Most systems keep /bin as a link to usr/bin, and a link is refused even when root
        // owns it.
        if fs::symlink_metadata("/bin").is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            let reason = root_only(Path::new("/bin/sh"), false).unwrap_err();
            assert!(reason.contains("/bin is a symbolic link"), "{reason}");
        }
        // SAFETY: getuid has no preconditions.
        let user = unsafe { libc::getuid() };
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
            && user != 0
            && fs::metadata(&home).is_ok_and(|metadata| metadata.uid() == user)
            && home
                .parent()
                .is_some_and(|parent| root_only(parent, false).is_ok())
        {
            let reason = root_only(&home.join("sandy"), true).unwrap_err();
            assert!(
                reason.contains(&format!("belongs to user {user}, not to root")),
                "{reason}"
            );
        }
    }
}
