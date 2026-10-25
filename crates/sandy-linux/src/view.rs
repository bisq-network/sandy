//! The file system view of `filesystem.view = "policy"`. The program runs in a mount namespace
//! whose root holds only what the policy grants: the policy paths, the system set, the symbolic
//! links on the way to them, and a minimal `/dev`. Every other path looks missing. The view hides
//! and Landlock decides: the binds show the same files the Landlock rules name, so every rule
//! applies as without the view.
//!
//! The process that entered the namespaces (`namespace`) builds it, with descriptors only, so no
//! path is resolved twice:
//!
//! 1. It makes `/` private, so that nothing it mounts reaches the host.
//! 2. It opens every path to bind with `open_rule`: one component at a time, without following a
//!    link, and only if it is still the file sandy planned with. Only now, in the new mount
//!    namespace: a descriptor opened in the host's namespace cannot be bound (EINVAL, measured on
//!    Linux 6.8 and 7.2).
//! 3. A new tmpfs is attached at `/tmp` of the new namespace, because Linux before 6.15 cannot
//!    mount onto a mount that is not attached (EINVAL on 6.8). It becomes the root.
//! 4. Each path is cloned with its submounts (`open_tree` with `OPEN_TREE_CLONE | AT_RECURSIVE`),
//!    gets its flags on every mount of the clone (`mount_setattr` with `AT_RECURSIVE`), and is
//!    moved onto its place (`move_mount`). Recursive, because a mount whose submounts came from the
//!    host's namespace is locked to them and cannot be bound alone (EINVAL), and a read-only flag
//!    on the top mount alone would leave the submounts writable. Flags are only added: the kernel
//!    refuses to clear a flag the host set (EPERM), so it stays.
//! 5. The links are recreated, `/dev` gets its nodes, the tmpfs mounts become read-only, and
//!    `pivot_root` makes the tmpfs the root. The old root is detached.
//!
//! A path inside another bound path is mounted inside that bind, on the host's own file there,
//! which must still be the planned file. A path anywhere else gets the directories above it on
//! the tmpfs, with mode 0755 whatever the umask.

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use sandy_core::SandboxError;

use crate::launch::{open_path, open_rule};
use crate::plan::FileIdentity;

/// The view of one run, computed by `plan`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    /// Every path the program may use, sorted, so that a path comes after the paths that hold it.
    pub binds: Vec<Bind>,
    /// The symbolic links that the names of the policy paths, the system set, the program's
    /// loader and its interpreters pass, where they lie outside every bind.
    pub links: Vec<Link>,
}

/// A path of the host, mounted at the same path in the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub path: PathBuf,
    pub is_dir: bool,
    /// A writable path of the policy holds it.
    pub writable: bool,
    /// A `read_exec` path, the program file, the loader or the libraries of the system set hold
    /// it. Every other bind is mounted without execute.
    pub executable: bool,
}

/// A symbolic link of the host, recreated with the same text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub path: PathBuf,
    pub target: PathBuf,
}

/// `MOUNT_ATTR_*` of linux/mount.h.
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const OPEN_TREE_CLONE: u32 = 1;
const AT_RECURSIVE: u32 = 0x8000;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
const FSOPEN_CLOEXEC: u32 = 1;
const FSMOUNT_CLOEXEC: u32 = 1;
const FSCONFIG_SET_FLAG: u32 = 0;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;

/// The device nodes of every view, with their numbers (Documentation/admin-guide/devices.txt).
const DEVICES: [(&str, u32, u32); 5] = [
    ("null", 1, 3),
    ("zero", 1, 5),
    ("full", 1, 7),
    ("random", 1, 8),
    ("urandom", 1, 9),
];
/// `/dev/tty`, only when a standard stream is a terminal.
const TERMINAL: (&str, u32, u32) = ("tty", 5, 0);

/// Where the new root is attached before `pivot_root` moves it to `/`.
const ATTACH: &str = "/tmp";

impl Bind {
    /// The flags of the bind's mounts. A device under `/dev` opens only on a mount without
    /// `nodev`, so the devices the policy names keep working. `/proc` is read-only even under a
    /// writable grant, so that the program changes nothing of its own or other processes there.
    fn attributes(&self) -> u64 {
        let mut set = MOUNT_ATTR_NOSUID;
        if !self.path.starts_with("/dev") {
            set |= MOUNT_ATTR_NODEV;
        }
        if !self.writable || self.path.starts_with("/proc") {
            set |= MOUNT_ATTR_RDONLY;
        }
        if !self.executable {
            set |= MOUNT_ATTR_NOEXEC;
        }
        set
    }
}

/// Builds `view` in this process's new mount namespace and makes it the root, steps 1 to 5 of the
/// module documentation. `terminal` adds `/dev/tty` and a private `/dev/pts`. Afterwards the
/// working directory is the one before, when the view holds it, and `/` otherwise.
pub fn enter(
    view: &View,
    identities: &BTreeMap<PathBuf, FileIdentity>,
    terminal: bool,
) -> Result<(), SandboxError> {
    let working = std::env::current_dir().ok();
    make_root_private()?;
    let mut sources = Vec::with_capacity(view.binds.len());
    for bind in &view.binds {
        let source = open_rule(&bind.path, identities.get(&bind.path).copied())?;
        sources.push((bind, source));
    }
    let mut devices = Vec::new();
    for &(name, major, minor) in DEVICES.iter().chain(terminal.then_some(&TERMINAL)) {
        let path = Path::new("/dev").join(name);
        if !view.binds.iter().any(|bind| bind.path == path) {
            devices.push((name, open_device(&path, major, minor)?));
        }
    }

    let _umask = Umask::clear();
    let root = new_tmpfs("the root of the file system view")?;
    attach(&root)?;
    let dev = make_dev(&root, &devices, terminal)?;
    // The clones of the binds so far, by path: a path inside one is mounted inside it.
    let mut bound: Vec<(&Path, OwnedFd)> = Vec::new();
    for (bind, source) in sources {
        let tree = clone_tree(&source, bind)?;
        let target = match bound
            .iter()
            .rev()
            .find(|(path, _)| bind.path.starts_with(path))
        {
            Some((outer, outer_tree)) => {
                inside_bind(outer_tree, outer, bind, identities.get(&bind.path).copied())?
            }
            None => mount_point(&root, bind)?,
        };
        move_onto(&tree, &target)
            .map_err(|error| failed(format!("mount {}", bind.path.display()), error))?;
        bound.push((&bind.path, tree));
    }
    for link in &view.links {
        make_link(&root, link)?;
    }
    for mount in [&dev, &root] {
        set_attributes(mount, 0, MOUNT_ATTR_RDONLY)
            .map_err(|error| failed("make the root read-only".to_string(), error))?;
    }
    // With `/` in the policy, its bind covers the tmpfs, and the new root is the bind.
    let top = bound
        .iter()
        .find(|(path, _)| *path == Path::new("/"))
        .map_or(&root, |(_, tree)| tree);
    pivot(top)?;
    if let Some(working) = working
        && std::env::set_current_dir(&working).is_err()
    {
        std::env::set_current_dir("/")
            .map_err(|error| failed("change to the new root".to_string(), error))?;
    }
    Ok(())
}

fn failed(what: String, error: io::Error) -> SandboxError {
    SandboxError::io(format!("cannot {what} for the file system view"), error)
}

fn last_error(what: &str) -> SandboxError {
    failed(what.to_string(), io::Error::last_os_error())
}

fn c_path(path: &Path) -> Result<CString, SandboxError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::new(format!("{} contains a NUL byte", path.display())))
}

/// Nothing mounted in the new namespace propagates to the host's, and nothing the host mounts
/// later appears in the view.
fn make_root_private() -> Result<(), SandboxError> {
    // SAFETY: a mount call with a NUL-terminated path and no data changes only this namespace.
    let changed = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if changed != 0 {
        return Err(last_error("make / private"));
    }
    Ok(())
}

/// Opens a device node of `/dev` without following a link and checks its number, so the view
/// gets the device and nothing that took its name.
fn open_device(path: &Path, major: u32, minor: u32) -> Result<OwnedFd, SandboxError> {
    let open_error = |error| failed(format!("open {}", path.display()), error);
    let mut fd = open_path(None, Path::new("/")).map_err(open_error)?;
    for component in path.components().skip(1) {
        fd = open_path(Some(&fd), Path::new(component.as_os_str())).map_err(open_error)?;
    }
    let status = status_of(&fd).map_err(open_error)?;
    let device = libc::makedev(major, minor);
    if status.st_mode & libc::S_IFMT != libc::S_IFCHR || status.st_rdev != device {
        return Err(SandboxError::new(format!(
            "{} is not the device {major}:{minor}",
            path.display()
        )));
    }
    Ok(fd)
}

fn status_of(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: stat is plain data, which fstat fills in.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes into `status` for an open descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut status) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

/// Clears the umask while the view is built, so that every directory gets mode 0755, and gives
/// the old one back: the program inherits the umask.
struct Umask(libc::mode_t);

impl Umask {
    fn clear() -> Umask {
        // SAFETY: umask only sets the process's file creation mask.
        Umask(unsafe { libc::umask(0) })
    }
}

impl Drop for Umask {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { libc::umask(self.0) };
    }
}

/// A new tmpfs, not attached anywhere yet, without devices, setuid or execute: it holds only
/// directories, links and mount points.
fn new_tmpfs(name: &str) -> Result<OwnedFd, SandboxError> {
    new_mount(
        "tmpfs",
        &[("mode", Some("0755"))],
        MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        name,
    )
}

/// A new mount of `fstype` with `options` (a flag when the value is `None`) and `attributes`,
/// not attached anywhere yet.
fn new_mount(
    fstype: &str,
    options: &[(&str, Option<&str>)],
    attributes: u64,
    name: &str,
) -> Result<OwnedFd, SandboxError> {
    let what = |step: &str| format!("{step} {name}");
    let fstype = CString::new(fstype).expect("no NUL byte in a file system type");
    // SAFETY: fsopen takes a NUL-terminated name and returns a new descriptor or -1.
    let context = unsafe { libc::syscall(libc::SYS_fsopen, fstype.as_ptr(), FSOPEN_CLOEXEC) };
    if context < 0 {
        return Err(last_error(&what("create")));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    let context = unsafe { OwnedFd::from_raw_fd(context as RawFd) };
    for &(key, value) in options {
        let key = CString::new(key).expect("no NUL byte in an option");
        let value = value.map(|value| CString::new(value).expect("no NUL byte in a value"));
        let (command, value) = match &value {
            Some(value) => (FSCONFIG_SET_STRING, value.as_ptr()),
            None => (FSCONFIG_SET_FLAG, std::ptr::null()),
        };
        // SAFETY: fsconfig reads the NUL-terminated key and value.
        let set = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.as_raw_fd(),
                command,
                key.as_ptr(),
                value,
                0,
            )
        };
        if set != 0 {
            return Err(last_error(&what("configure")));
        }
    }
    // SAFETY: as above, with a command that takes no key.
    let created = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if created != 0 {
        return Err(last_error(&what("create")));
    }
    // SAFETY: fsmount takes the configured context and returns a new descriptor or -1.
    let mount = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            context.as_raw_fd(),
            FSMOUNT_CLOEXEC,
            attributes,
        )
    };
    if mount < 0 {
        return Err(last_error(&what("mount")));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(mount as RawFd) })
}

/// Attaches the new root at `ATTACH` of the new namespace.
fn attach(root: &OwnedFd) -> Result<(), SandboxError> {
    let at = open_path(None, Path::new(ATTACH))
        .map_err(|error| failed(format!("open {ATTACH}"), error))?;
    move_onto(root, &at).map_err(|error| failed(format!("attach the root at {ATTACH}"), error))
}

/// Moves the mount of `mount` onto the place `target` names.
fn move_onto(mount: &OwnedFd, target: &OwnedFd) -> io::Result<()> {
    // SAFETY: move_mount takes two descriptors and empty NUL-terminated paths.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if moved != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `struct mount_attr` of linux/mount.h.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Adds `set` to the mount of `mount`, with `AT_RECURSIVE` in `flags` to every mount below it too.
fn set_attributes(mount: &OwnedFd, flags: u32, set: u64) -> io::Result<()> {
    let attributes = MountAttr {
        attr_set: set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: mount_setattr reads a mount_attr of the size passed.
    let changed = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as u32 | flags,
            &attributes as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if changed != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A detached copy of the mounts at `source` and below, with the flags of `bind`.
fn clone_tree(source: &OwnedFd, bind: &Bind) -> Result<OwnedFd, SandboxError> {
    let flags =
        OPEN_TREE_CLONE | AT_RECURSIVE | libc::AT_EMPTY_PATH as u32 | libc::O_CLOEXEC as u32;
    // SAFETY: open_tree takes a descriptor, an empty NUL-terminated path and flags, and returns a
    // new descriptor or -1.
    let tree =
        unsafe { libc::syscall(libc::SYS_open_tree, source.as_raw_fd(), c"".as_ptr(), flags) };
    if tree < 0 {
        return Err(last_error(&format!(
            "copy the mounts of {}",
            bind.path.display()
        )));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    let tree = unsafe { OwnedFd::from_raw_fd(tree as RawFd) };
    set_attributes(&tree, AT_RECURSIVE, bind.attributes())
        .map_err(|error| failed(format!("set the flags of {}", bind.path.display()), error))?;
    Ok(tree)
}

/// The names of `path` below `outer`, which holds it.
fn names_below<'a>(path: &'a Path, outer: &Path) -> impl Iterator<Item = &'a OsStr> {
    path.strip_prefix(outer)
        .unwrap_or(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
}

/// The place of `bind` inside the bind of `outer`: the host's own file there, opened one
/// component at a time without following a link, which must be the file sandy planned with.
fn inside_bind(
    outer_tree: &OwnedFd,
    outer: &Path,
    bind: &Bind,
    planned: Option<FileIdentity>,
) -> Result<OwnedFd, SandboxError> {
    let changed = || {
        SandboxError::new(format!(
            "{} changed after sandy checked the policy: it names another file in the view",
            bind.path.display()
        ))
    };
    let open_error = |error| failed(format!("open {}", bind.path.display()), error);
    let mut fd = outer_tree.try_clone().map_err(open_error)?;
    for name in names_below(&bind.path, outer) {
        fd = open_path(Some(&fd), Path::new(name)).map_err(open_error)?;
        let status = status_of(&fd).map_err(open_error)?;
        if status.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(changed());
        }
    }
    let status = status_of(&fd).map_err(open_error)?;
    if planned != Some((status.st_dev, status.st_ino)) {
        return Err(changed());
    }
    Ok(fd)
}

/// The directory of `path` on the tmpfs of `root`, created with the directories above it where
/// missing.
fn directory_on_root(root: &OwnedFd, path: &Path) -> Result<OwnedFd, SandboxError> {
    let mut fd = root
        .try_clone()
        .map_err(|error| failed("open the root".to_string(), error))?;
    for name in names_below(path, Path::new("/")) {
        fd = make_directory(&fd, name, path)?;
    }
    Ok(fd)
}

/// The directory `name` in `parent`, created with mode 0755 if missing. A tmpfs holds only what
/// sandy put there, so anything but a directory is an error.
fn make_directory(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd, SandboxError> {
    let c_name = c_path(Path::new(name))?;
    // SAFETY: mkdirat takes a descriptor and a NUL-terminated name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o755) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(failed(
                format!("create the directories of {}", path.display()),
                error,
            ));
        }
    }
    let fd = open_path(Some(parent), Path::new(name))
        .map_err(|error| failed(format!("open the directories of {}", path.display()), error))?;
    let status = status_of(&fd)
        .map_err(|error| failed(format!("open the directories of {}", path.display()), error))?;
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(SandboxError::new(format!(
            "cannot create the directories of {} for the file system view: {} is no directory",
            path.display(),
            name.to_string_lossy()
        )));
    }
    Ok(fd)
}

/// The place of `bind` on the tmpfs of `root`: a new directory, or a new empty file for a file.
fn mount_point(root: &OwnedFd, bind: &Bind) -> Result<OwnedFd, SandboxError> {
    let (Some(parent), Some(name)) = (bind.path.parent(), bind.path.file_name()) else {
        // `/` itself: the bind covers the whole root.
        return root
            .try_clone()
            .map_err(|error| failed("open the root".to_string(), error));
    };
    let parent = directory_on_root(root, parent)?;
    if bind.is_dir {
        return make_directory(&parent, name, &bind.path);
    }
    let c_name = c_path(Path::new(name))?;
    let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: openat takes a descriptor, a NUL-terminated name, flags and a mode.
    let file = unsafe { libc::openat(parent.as_raw_fd(), c_name.as_ptr(), flags, 0o644) };
    if file < 0 {
        return Err(last_error(&format!(
            "create the place of {}",
            bind.path.display()
        )));
    }
    // SAFETY: the descriptor was just created; closing it is all that is done with it.
    drop(unsafe { OwnedFd::from_raw_fd(file) });
    open_path(Some(&parent), Path::new(name))
        .map_err(|error| failed(format!("open the place of {}", bind.path.display()), error))
}

/// `/dev` of the view: a tmpfs with the nodes of `devices` bound read-only, and with a terminal
/// a private devpts instance, whose `ptmx` makes ptys that only this sandbox sees, and a
/// `/dev/ptmx` link to it.
fn make_dev(
    root: &OwnedFd,
    devices: &[(&str, OwnedFd)],
    terminal: bool,
) -> Result<OwnedFd, SandboxError> {
    let dev_path = Path::new("/dev");
    let place = directory_on_root(root, dev_path)?;
    let dev = new_tmpfs("/dev of the file system view")?;
    move_onto(&dev, &place).map_err(|error| failed("mount /dev".to_string(), error))?;
    for (name, source) in devices {
        let bind = Bind {
            path: dev_path.join(name),
            is_dir: false,
            writable: false,
            executable: false,
        };
        let tree = clone_tree(source, &bind)?;
        let target = mount_point(root, &bind)?;
        move_onto(&tree, &target)
            .map_err(|error| failed(format!("mount {}", bind.path.display()), error))?;
    }
    if terminal {
        let pts = new_mount(
            "devpts",
            &[
                ("newinstance", None),
                ("ptmxmode", Some("0666")),
                ("mode", Some("620")),
            ],
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC,
            "/dev/pts of the file system view",
        )?;
        let dev_fd = directory_on_root(root, dev_path)?;
        let place = make_directory(&dev_fd, OsStr::new("pts"), Path::new("/dev/pts"))?;
        move_onto(&pts, &place).map_err(|error| failed("mount /dev/pts".to_string(), error))?;
        make_link(
            root,
            &Link {
                path: PathBuf::from("/dev/ptmx"),
                target: PathBuf::from("pts/ptmx"),
            },
        )?;
    }
    Ok(dev)
}

fn make_link(root: &OwnedFd, link: &Link) -> Result<(), SandboxError> {
    let (Some(parent), Some(name)) = (link.path.parent(), link.path.file_name()) else {
        return Ok(());
    };
    let parent = directory_on_root(root, parent)?;
    let (target, name) = (c_path(&link.target)?, c_path(Path::new(name))?);
    // SAFETY: symlinkat takes a NUL-terminated target, a descriptor and a NUL-terminated name.
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        // Two names that pass the same link.
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(failed(
                format!("create the link {}", link.path.display()),
                error,
            ));
        }
    }
    Ok(())
}

/// Makes the tmpfs of `root` the root of this mount namespace and detaches the old root, which
/// `pivot_root(".", ".")` leaves stacked on top of the new one.
fn pivot(root: &OwnedFd) -> Result<(), SandboxError> {
    // SAFETY: fchdir takes a descriptor; pivot_root and umount2 take NUL-terminated paths; chdir
    // a NUL-terminated path.
    unsafe {
        if libc::fchdir(root.as_raw_fd()) != 0 {
            return Err(last_error("change to the new root"));
        }
        if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0 {
            return Err(last_error("make the view the root"));
        }
        if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) != 0 {
            return Err(last_error("detach the old root"));
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            return Err(last_error("change to the new root"));
        }
    }
    Ok(())
}
