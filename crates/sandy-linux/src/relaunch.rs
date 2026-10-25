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
use crate::setup::{self, Profile};

/// The copy to hand over to, `None` when this sandy runs on as itself.
pub fn hand_over_target() -> Option<PathBuf> {
    target(&ThisHost, setup::copy_path())
}

/// What the decision reads, so a test can describe any host.
trait Host {
    fn is_root(&self) -> bool;
    /// Whether the restriction applies to this process: on, and the process unconfined.
    fn restricted(&self) -> bool;
    fn own_path(&self) -> Option<PathBuf>;
    /// Whether `path` is a regular file that only root can change (`setup::root_only`).
    fn root_only(&self, path: &Path) -> bool;
    /// Whether the kernel has the unconfined profile called `name`.
    fn loaded(&self, name: &str) -> bool;
    /// Whether `copy` has the same bytes as the image this process runs.
    fn runs_image_of(&self, copy: &Path) -> bool;
}

/// Each condition is read only when the ones before it hold, cheapest first.
fn target(host: &impl Host, copy: PathBuf) -> Option<PathBuf> {
    if host.is_root() || !host.restricted() {
        return None;
    }
    // Never from the copy itself, whatever its label says, so a hand-over cannot loop.
    if host.own_path()? == copy {
        return None;
    }
    if !host.root_only(&copy) {
        return None;
    }
    let profile = Profile::for_path(&copy).ok()?;
    if !host.loaded(&profile.name) {
        return None;
    }
    host.runs_image_of(&copy).then_some(copy)
}

#[derive(Debug)]
struct ThisHost;

impl Host for ThisHost {
    fn is_root(&self) -> bool {
        setup::is_root()
    }

    /// A profile that sandy setup installed shows as the process's label instead of
    /// `unconfined`.
    fn restricted(&self) -> bool {
        setup::read(APPARMOR_RESTRICTION).as_deref() == Some("1")
            && setup::read(APPARMOR_LABEL).as_deref() == Some("unconfined")
    }

    fn own_path(&self) -> Option<PathBuf> {
        std::fs::read_link("/proc/self/exe").ok()
    }

    fn root_only(&self, path: &Path) -> bool {
        setup::root_only(path, false).is_ok()
            && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    fn loaded(&self, name: &str) -> bool {
        setup::loaded_mode(name).as_deref() == Some("unconfined")
    }

    fn runs_image_of(&self, copy: &Path) -> bool {
        runs_image_of(copy)
    }
}

/// Whether `copy` is a regular file with the same bytes as the image this process runs.
fn runs_image_of(copy: &Path) -> bool {
    let open = |path: &Path| {
        let file = File::open(path).ok()?;
        let metadata = file.metadata().ok()?;
        metadata.is_file().then_some((file, metadata.len()))
    };
    let (Some((mut copy, copy_len)), Some((mut own, own_len))) =
        (open(copy), open(Path::new("/proc/self/exe")))
    else {
        return false;
    };
    if copy_len != own_len {
        return false;
    }
    let (mut a, mut b) = ([0u8; 65536], [0u8; 65536]);
    loop {
        let (Ok(read), Ok(other)) = (read_full(&mut copy, &mut a), read_full(&mut own, &mut b))
        else {
            return false;
        };
        if read != other || a[..read] != b[..read] {
            return false;
        }
        if read == 0 {
            return true;
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
        restricted: bool,
        own: PathBuf,
        root_only: bool,
        loaded: Option<String>,
        same_bytes: bool,
        read: RefCell<Vec<&'static str>>,
    }

    const COPY: &str = "/usr/local/libexec/sandy/2.1.0/sandy";

    impl Fake {
        fn valid() -> Fake {
            Fake {
                root: false,
                restricted: true,
                own: PathBuf::from("/home/user/tools/sandy"),
                root_only: true,
                loaded: Some(Profile::for_path(Path::new(COPY)).unwrap().name),
                same_bytes: true,
                read: RefCell::new(Vec::new()),
            }
        }

        fn decide(&self) -> Option<PathBuf> {
            target(self, PathBuf::from(COPY))
        }
    }

    impl Host for Fake {
        fn is_root(&self) -> bool {
            self.read.borrow_mut().push("root");
            self.root
        }
        fn restricted(&self) -> bool {
            self.read.borrow_mut().push("restricted");
            self.restricted
        }
        fn own_path(&self) -> Option<PathBuf> {
            self.read.borrow_mut().push("own");
            Some(self.own.clone())
        }
        fn root_only(&self, path: &Path) -> bool {
            assert_eq!(path, Path::new(COPY));
            self.read.borrow_mut().push("root-only");
            self.root_only
        }
        fn loaded(&self, name: &str) -> bool {
            self.read.borrow_mut().push("loaded");
            self.loaded.as_deref() == Some(name)
        }
        fn runs_image_of(&self, copy: &Path) -> bool {
            assert_eq!(copy, Path::new(COPY));
            self.read.borrow_mut().push("bytes");
            self.same_bytes
        }
    }

    #[test]
    fn a_portable_sandy_hands_over_to_a_valid_copy() {
        let host = Fake::valid();
        assert_eq!(host.decide(), Some(PathBuf::from(COPY)));
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
            ("unrestricted or confined", |host| host.restricted = false),
            ("the copy itself", |host| host.own = PathBuf::from(COPY)),
            ("copy not root-only", |host| host.root_only = false),
            ("profile not loaded", |host| host.loaded = None),
            ("another profile", |host| {
                host.loaded = Some("sandy-setup.usr.bin.sandy".into())
            }),
            ("other bytes", |host| host.same_bytes = false),
        ];
        for (case, change) in cases {
            let mut host = Fake::valid();
            change(&mut host);
            assert_eq!(host.decide(), None, "{case}");
        }
    }

    /// The copy runs under its own profile, so it is no longer unconfined and the restriction
    /// does not apply to it; its own path stops a hand-over even where the label would not.
    #[test]
    fn the_copy_never_hands_over_again() {
        let mut host = Fake::valid();
        host.own = PathBuf::from(COPY);
        assert_eq!(host.decide(), None);
        assert!(!host.read.borrow().contains(&"bytes"));
    }

    #[test]
    fn a_file_with_the_same_bytes_runs_the_image() {
        let directory = std::env::temp_dir().join(format!("sandy-image-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let same = directory.join("same");
        fs::copy("/proc/self/exe", &same).unwrap();
        assert!(runs_image_of(&same));
        let mut changed = fs::read(&same).unwrap();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let other = directory.join("other");
        fs::write(&other, &changed).unwrap();
        assert!(!runs_image_of(&other));
        changed.pop();
        fs::write(&other, &changed).unwrap();
        assert!(!runs_image_of(&other));
        assert!(!runs_image_of(&directory));
        assert!(!runs_image_of(&directory.join("missing")));
        fs::remove_dir_all(&directory).unwrap();
    }
}
