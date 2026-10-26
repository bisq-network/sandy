//! The hand-over to the copy that `sandy setup --install-copy` installs. Under Ubuntu's AppArmor
//! restriction only a file with a profile gets user namespaces, and setup writes profiles only
//! for paths that only root can change. A sandy started from anywhere else (a portable one)
//! therefore replaces itself with the copy of its own version when that copy runs the same bytes
//! and its profile is loaded, so the copy enforces what the portable sandy cannot. The CLI does
//! the `execve`, before it opens anything.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::namespace::{APPARMOR_LABEL, APPARMOR_RESTRICTION};
use crate::setup::{self, NotRootOnly, Profile};

/// The copy to hand over to, `None` when this sandy runs on as itself. `Err` when the copy is
/// installed but a check of it fails for a reason that can pass, such as a full descriptor
/// table: running on as the portable sandy would then report that the host needs setup, which
/// is not so, and could make sandy pick a weaker fallback level.
pub fn hand_over_target() -> Result<Option<PathBuf>, String> {
    let copy = setup::copy_path();
    target(&ThisHost, copy.clone()).map_err(|reason| {
        format!(
            "cannot tell whether to hand over to the installed copy {}: {reason}",
            copy.display()
        )
    })
}

/// What the decision reads, so a test can describe any host. `Err` when it cannot be read.
trait Host {
    fn is_root(&self) -> bool;
    /// Whether the restriction applies to this process: on, and the process unconfined.
    fn restricted(&self) -> Result<bool, String>;
    fn own_path(&self) -> Result<PathBuf, String>;
    /// Whether `path` is a regular file that only root can change (`setup::root_only`).
    fn root_only(&self, path: &Path) -> Result<bool, String>;
    /// Whether the kernel has the unconfined profile called `name`.
    fn loaded(&self, name: &str) -> Result<bool, String>;
    /// Whether `copy` has the same bytes as the image this process runs.
    fn runs_image_of(&self, copy: &Path) -> Result<bool, String>;
}

/// Each condition is read only when the ones before it hold, cheapest first. Until sandy knows
/// that the copy is installed, a condition it cannot read means no hand-over; from there it is
/// an error, because the copy may be the one that should run.
fn target(host: &impl Host, copy: PathBuf) -> Result<Option<PathBuf>, String> {
    if host.is_root() {
        return Ok(None);
    }
    let restricted = host.restricted();
    if restricted == Ok(false) {
        return Ok(None);
    }
    // Never from the copy itself, whatever its label says, so a hand-over cannot loop.
    let own = host.own_path();
    if own.as_ref() == Ok(&copy) {
        return Ok(None);
    }
    if !host.root_only(&copy)? {
        return Ok(None);
    }
    restricted?;
    own?;
    let Ok(profile) = Profile::for_path(&copy) else {
        return Ok(None);
    };
    if !host.loaded(&profile.name)? {
        return Ok(None);
    }
    Ok(host.runs_image_of(&copy)?.then_some(copy))
}

#[derive(Debug)]
struct ThisHost;

impl Host for ThisHost {
    fn is_root(&self) -> bool {
        setup::is_root()
    }

    /// A profile that sandy setup installed shows as the process's label instead of
    /// `unconfined`.
    fn restricted(&self) -> Result<bool, String> {
        if setup::read_existing(Path::new(APPARMOR_RESTRICTION))?.as_deref() != Some("1") {
            return Ok(false);
        }
        let label = match std::fs::read_to_string(APPARMOR_LABEL) {
            Ok(label) => label,
            // No such file, or AppArmor is not the active security module.
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINVAL)) => {
                return Ok(false);
            }
            Err(error) => return Err(format!("cannot read {APPARMOR_LABEL}: {error}")),
        };
        Ok(label.trim() == "unconfined")
    }

    fn own_path(&self) -> Result<PathBuf, String> {
        std::fs::read_link("/proc/self/exe")
            .map_err(|error| format!("cannot find the file of this sandy: {error}"))
    }

    fn root_only(&self, path: &Path) -> Result<bool, String> {
        match setup::check_root_only(path, false) {
            Ok(()) => {}
            Err(NotRootOnly::Refused(_)) => return Ok(false),
            Err(NotRootOnly::Unreadable(reason)) => return Err(reason),
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    fn loaded(&self, name: &str) -> Result<bool, String> {
        setup::read_loaded_mode(name).map(|mode| mode.as_deref() == Some("unconfined"))
    }

    fn runs_image_of(&self, copy: &Path) -> Result<bool, String> {
        runs_image_of(copy)
    }
}

/// Whether `copy` is a regular file with the same bytes as the image this process runs. A copy
/// that is gone is not; a file that cannot be read is an error.
fn runs_image_of(copy: &Path) -> Result<bool, String> {
    let failed = |path: &Path, error: io::Error| format!("cannot read {}: {error}", path.display());
    let open = |path: &Path| -> Result<Option<(File, u64)>, String> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed(path, error)),
        };
        let metadata = file.metadata().map_err(|error| failed(path, error))?;
        Ok(metadata.is_file().then_some((file, metadata.len())))
    };
    let own_image = Path::new("/proc/self/exe");
    let (Some((mut copy_file, copy_len)), Some((mut own, own_len))) =
        (open(copy)?, open(own_image)?)
    else {
        return Ok(false);
    };
    if copy_len != own_len {
        return Ok(false);
    }
    let (mut a, mut b) = ([0u8; 65536], [0u8; 65536]);
    loop {
        let read = read_full(&mut copy_file, &mut a).map_err(|error| failed(copy, error))?;
        let other = read_full(&mut own, &mut b).map_err(|error| failed(own_image, error))?;
        if read != other || a[..read] != b[..read] {
            return Ok(false);
        }
        if read == 0 {
            return Ok(true);
        }
    }
}

/// Fills `buffer` as far as the file goes.
fn read_full(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use super::*;

    /// A host on which every condition holds, until a test turns one off. It records what the
    /// decision read.
    #[derive(Debug)]
    struct Fake {
        root: bool,
        restricted: Result<bool, String>,
        own: Result<PathBuf, String>,
        root_only: Result<bool, String>,
        loaded: Result<Option<String>, String>,
        same_bytes: Result<bool, String>,
        read: RefCell<Vec<&'static str>>,
    }

    const COPY: &str = "/usr/local/libexec/sandy/2.1.0/sandy";

    impl Fake {
        fn valid() -> Fake {
            Fake {
                root: false,
                restricted: Ok(true),
                own: Ok(PathBuf::from("/home/user/tools/sandy")),
                root_only: Ok(true),
                loaded: Ok(Some(Profile::for_path(Path::new(COPY)).unwrap().name)),
                same_bytes: Ok(true),
                read: RefCell::new(Vec::new()),
            }
        }

        fn decide(&self) -> Result<Option<PathBuf>, String> {
            target(self, PathBuf::from(COPY))
        }
    }

    impl Host for Fake {
        fn is_root(&self) -> bool {
            self.read.borrow_mut().push("root");
            self.root
        }
        fn restricted(&self) -> Result<bool, String> {
            self.read.borrow_mut().push("restricted");
            self.restricted.clone()
        }
        fn own_path(&self) -> Result<PathBuf, String> {
            self.read.borrow_mut().push("own");
            self.own.clone()
        }
        fn root_only(&self, path: &Path) -> Result<bool, String> {
            assert_eq!(path, Path::new(COPY));
            self.read.borrow_mut().push("root-only");
            self.root_only.clone()
        }
        fn loaded(&self, name: &str) -> Result<bool, String> {
            self.read.borrow_mut().push("loaded");
            self.loaded
                .clone()
                .map(|loaded| loaded.as_deref() == Some(name))
        }
        fn runs_image_of(&self, copy: &Path) -> Result<bool, String> {
            assert_eq!(copy, Path::new(COPY));
            self.read.borrow_mut().push("bytes");
            self.same_bytes.clone()
        }
    }

    #[test]
    fn a_portable_sandy_hands_over_to_a_valid_copy() {
        let host = Fake::valid();
        assert_eq!(host.decide(), Ok(Some(PathBuf::from(COPY))));
        // The byte comparison reads a megabyte, so it comes last.
        assert_eq!(
            *host.read.borrow(),
            ["root", "restricted", "own", "root-only", "loaded", "bytes"]
        );
    }

    #[test]
    fn every_condition_is_needed() {
        type Change = fn(&mut Fake);
        let cases: [(&str, Change); 7] = [
            ("root", |host| host.root = true),
            ("unrestricted or confined", |host| {
                host.restricted = Ok(false)
            }),
            ("the copy itself", |host| host.own = Ok(PathBuf::from(COPY))),
            ("no root-only copy", |host| host.root_only = Ok(false)),
            ("profile not loaded", |host| host.loaded = Ok(None)),
            ("another profile", |host| {
                host.loaded = Ok(Some("sandy-setup.usr.bin.sandy".into()))
            }),
            ("other bytes", |host| host.same_bytes = Ok(false)),
        ];
        for (case, change) in cases {
            let mut host = Fake::valid();
            change(&mut host);
            assert_eq!(host.decide(), Ok(None), "{case}");
        }
    }

    /// Once the copy is known to be installed, a condition sandy cannot read is an error, not
    /// a reason to run on as the portable sandy, which would report that the host needs setup.
    /// Before that, nothing is known to be lost, so it means no hand-over.
    #[test]
    fn a_check_of_an_installed_copy_that_fails_is_an_error() {
        type Change = fn(&mut Fake);
        fn failed<T>() -> Result<T, String> {
            Err("EMFILE".to_string())
        }
        let cases: [(&str, Change); 5] = [
            ("restriction", |host| host.restricted = failed()),
            ("own path", |host| host.own = failed()),
            ("root-only", |host| host.root_only = failed()),
            ("profiles", |host| host.loaded = failed()),
            ("bytes", |host| host.same_bytes = failed()),
        ];
        for (case, change) in cases {
            let mut host = Fake::valid();
            change(&mut host);
            assert_eq!(host.decide(), Err("EMFILE".to_string()), "{case}");
        }
        for change in [
            |host: &mut Fake| host.restricted = failed(),
            |host: &mut Fake| host.own = failed(),
        ] {
            let mut host = Fake::valid();
            change(&mut host);
            host.root_only = Ok(false);
            assert_eq!(host.decide(), Ok(None));
        }
        let mut host = Fake::valid();
        host.restricted = Ok(false);
        host.root_only = failed();
        assert_eq!(host.decide(), Ok(None));
    }

    /// The copy runs under its own profile, so it is no longer unconfined and the restriction
    /// does not apply to it; its own path stops a hand-over even where the label would not.
    #[test]
    fn the_copy_never_hands_over_again() {
        let mut host = Fake::valid();
        host.own = Ok(PathBuf::from(COPY));
        assert_eq!(host.decide(), Ok(None));
        assert!(!host.read.borrow().contains(&"bytes"));
    }

    #[test]
    fn a_file_with_the_same_bytes_runs_the_image() {
        let directory = std::env::temp_dir().join(format!("sandy-image-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let same = directory.join("same");
        fs::copy("/proc/self/exe", &same).unwrap();
        assert_eq!(runs_image_of(&same), Ok(true));
        let mut changed = fs::read(&same).unwrap();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let other = directory.join("other");
        fs::write(&other, &changed).unwrap();
        assert_eq!(runs_image_of(&other), Ok(false));
        changed.pop();
        fs::write(&other, &changed).unwrap();
        assert_eq!(runs_image_of(&other), Ok(false));
        assert_eq!(runs_image_of(&directory), Ok(false));
        assert_eq!(runs_image_of(&directory.join("missing")), Ok(false));
        // A file sandy may not read is an error, not another file.
        let unreadable = directory.join("unreadable");
        fs::write(&unreadable, b"x").unwrap();
        fs::set_permissions(
            &unreadable,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert!(runs_image_of(&unreadable).is_err());
        }
        fs::remove_dir_all(&directory).unwrap();
    }
}
