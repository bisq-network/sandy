//! The launch sequence of `run`. Everything that can fail on bad input is prepared first. Then the
//! process restricts itself step by step and replaces itself with the target. With
//! `process.children = "contained"` a forked child does that, and sandy supervises it (see
//! `contain`).

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;

use landlock::{
    CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
    RulesetError, RulesetStatus,
};
use sandy_core::{ParentProcess, SandboxError, StatusReport, TargetCommand};

use crate::explain::{self, Observer};
use crate::filter::{FilterConfig, Filters};
use crate::host::THREADS_DIR;
use crate::plan::{FileIdentity, LandlockConfig, Sandbox};
use crate::{contain, filter, relay, watch};

/// Applies `sandbox` and executes the target. Without `contain`, sandy applies it to itself and
/// returns only on failure. With `contain`, a forked child does, and sandy returns the exit
/// status when the target has ended.
///
/// Landlock and seccomp restrict the calling thread. sandy verifies right before Landlock that
/// it has a single thread, the filters are installed with TSYNC, and execve ends every other
/// thread, so the target runs with exactly the restrictions applied here.
pub fn launch(
    sandbox: &Sandbox,
    command: &TargetCommand,
    status: &StatusReport,
) -> Result<i32, SandboxError> {
    if command.explain && sandbox.end_with_parent && !sandbox.contain {
        return Err(SandboxError::new(
            "--explain cannot be used with process.end_with_parent unless \
             children = \"contained\": sandy stays the program's parent in this mode, and the \
             SIGKILL that ends a program which outlasts SIGTERM would end sandy alone; only the \
             guard of \"contained\" ends the program then",
        ));
    }
    // With `contained`, the relay also ends when the guard has ended the program's group, and
    // sandy stays to watch the relay in turn (see `contain::run`).
    let mut group_ended = None;
    let mut relay_alive = None;
    if let Some(relay) = &sandbox.relay {
        let ended = if sandbox.contain {
            let (read, write) = crate::helper::pipe("the pipe of the group's end")?;
            group_ended = Some(write);
            Some(read)
        } else {
            None
        };
        let started = relay::start(relay, ended)?;
        if sandbox.contain {
            relay_alive = Some(crate::helper::pidfd_open(started, "the relay")?);
        }
    }
    if sandbox.end_with_parent {
        let parent = command.parent.unwrap_or_else(|| ParentProcess {
            // SAFETY: getppid has no preconditions.
            id: unsafe { libc::getppid() } as u32,
            start: None,
        });
        watch::start(parent, sandbox.landlock.abi)?;
    }
    let ruleset = prepare_ruleset(&sandbox.landlock, &sandbox.identities)?;
    // The filter is built again in the forked child, whose process ID it needs, but a policy it
    // cannot express fails here, before anything starts.
    build_filters(&sandbox.filter)?;
    let (mut explain, observer) = match command.explain {
        true => {
            let (explain, observer) = explain::prepare(&sandbox.landlock)?;
            (Some(explain), Some(observer))
        }
        false => (None, None),
    };
    let exec = Exec::new(command)?;
    if let Some(cwd) = &command.cwd {
        std::env::set_current_dir(cwd).map_err(|error| {
            SandboxError::io(format!("cannot change to {}", cwd.display()), error)
        })?;
    }
    let start = || match confine(ruleset, &sandbox.filter, observer.as_ref()) {
        Ok(()) => exec.execute(),
        Err(error) => error,
    };
    if sandbox.contain {
        contain::run(start, group_ended, relay_alive, status, explain.as_mut())
    } else if let Some(explain) = explain {
        explain::supervise(start, explain, status)
    } else {
        // In the exec model sandy becomes the program, so its own process ID is the program's.
        // Reported before the sandbox, because the status channel is closed on execve and the
        // seccomp filter has no rule for it.
        status.started(std::process::id());
        Err(start())
    }
}

/// The filters for this process. The denylist names the caller's process ID.
fn build_filters(config: &FilterConfig) -> Result<Filters, SandboxError> {
    filter::build(config, std::process::id())
        .map_err(|error| SandboxError::new(format!("cannot build the seccomp filter: {error}")))
}

/// Restricts this process step by step: descriptors, no_new_privs, Landlock, seccomp. The
/// observer of the diagnostic mode comes last: from then on every call it watches waits for
/// sandy's answer.
fn confine(
    ruleset: RulesetCreated,
    filter: &FilterConfig,
    observer: Option<&Observer>,
) -> Result<(), SandboxError> {
    // Not before: until here sandy writes for itself, the status record of `--status-fd` for
    // one, and a reader that has gone must not end it, nor make it signal the program.
    restore_sigpipe()?;
    let filters = build_filters(filter)?;
    mark_descriptors_close_on_exec()?;
    set_no_new_privs()?;
    ensure_single_thread()?;
    restrict(ruleset)?;
    filter::install(&filters).map_err(|error| {
        SandboxError::new(format!("cannot install the seccomp filter: {error}"))
    })?;
    match observer {
        Some(observer) => observer.install(),
        None => Ok(()),
    }
}

fn landlock_error(error: RulesetError) -> SandboxError {
    SandboxError::new(format!("Landlock: {error}"))
}

/// Builds the ruleset completely before anything is restricted. With `HardRequirement`, every
/// right that the kernel does not support is an error instead of being dropped. Each rule binds
/// the file its path named when sandy planned the run (`open_rule`).
fn prepare_ruleset(
    config: &LandlockConfig,
    identities: &BTreeMap<PathBuf, FileIdentity>,
) -> Result<RulesetCreated, SandboxError> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(config.handled_fs)
        .map_err(landlock_error)?;
    if !config.handled_net.is_empty() {
        ruleset = ruleset
            .handle_access(config.handled_net)
            .map_err(landlock_error)?;
    }
    if !config.scopes.is_empty() {
        ruleset = ruleset.scope(config.scopes).map_err(landlock_error)?;
    }
    let mut ruleset = ruleset.create().map_err(landlock_error)?;
    for rule in &config.rules {
        let fd = open_rule(&rule.path, identities.get(&rule.path).copied())?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rule.access))
            .map_err(landlock_error)?;
    }
    Ok(ruleset)
}

/// Opens the canonical rule path `path` one component at a time without following a symbolic
/// link, and checks that it is still `planned`, the file sandy planned with. The checks of the
/// policy look at paths, and Landlock binds the file a descriptor refers to. A process that can
/// write a parent of a policy path, for example one a previous run left behind, could otherwise
/// replace the path with a link or with another directory after the checks, and the rule would
/// grant access where no check looked. A change refuses the run.
fn open_rule(path: &Path, planned: Option<FileIdentity>) -> Result<OwnedFd, SandboxError> {
    let changed = |why: &str| {
        SandboxError::new(format!(
            "{} changed after sandy checked the policy: {why}",
            path.display()
        ))
    };
    let open_error = |error| SandboxError::io(format!("cannot open {}", path.display()), error);
    let mut fd = open_path(None, Path::new("/")).map_err(open_error)?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(SandboxError::new(format!(
                "{} is not a canonical path",
                path.display()
            )));
        };
        fd = open_path(Some(&fd), Path::new(name)).map_err(open_error)?;
        let file = std::fs::File::from(fd);
        let metadata = file.metadata().map_err(open_error)?;
        if metadata.file_type().is_symlink() {
            return Err(changed("a symbolic link lies on its way now"));
        }
        fd = OwnedFd::from(file);
    }
    let file = std::fs::File::from(fd);
    let found = identity_of(&file.metadata().map_err(open_error)?);
    if planned != Some(found) {
        return Err(changed("it names another file now"));
    }
    Ok(OwnedFd::from(file))
}

/// The identity of the file at the canonical path `path`, read as `open_rule` reads it: through
/// an O_PATH open, which mounts an automount point where a `stat` would not.
pub(crate) fn identity(path: &Path) -> Option<FileIdentity> {
    let file = std::fs::File::from(open_path(None, path).ok()?);
    Some(identity_of(&file.metadata().ok()?))
}

fn identity_of(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

/// An O_PATH descriptor for `name`, below the directory `parent` or from the current
/// directory, without following a symbolic link in `name`.
fn open_path(parent: Option<&OwnedFd>, name: &Path) -> io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    let name = CString::new(name.as_os_str().as_bytes())?;
    let parent = parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `name` is NUL-terminated and `parent` is a descriptor this process owns or
    // AT_FDCWD.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Landlock restricts only the calling thread. Another thread would keep running without the
/// file system rules until execve ends it. sandy starts no threads; this check makes that a
/// verified fact instead of an assumption. LANDLOCK_RESTRICT_SELF_TSYNC (ABI 8) would cover such
/// a thread instead, but only on new kernels, and it would hide a thread that should not exist.
pub(crate) fn ensure_single_thread() -> Result<(), SandboxError> {
    let list_error = |error| SandboxError::io(format!("cannot list {THREADS_DIR}"), error);
    let threads = std::fs::read_dir(THREADS_DIR)
        .map_err(list_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(list_error)?
        .len();
    if threads != 1 {
        return Err(SandboxError::new(format!(
            "sandy has {threads} threads, but Landlock would restrict only one of them"
        )));
    }
    Ok(())
}

pub(crate) fn restrict(ruleset: RulesetCreated) -> Result<(), SandboxError> {
    let status = ruleset.restrict_self().map_err(landlock_error)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(SandboxError::new(format!(
            "Landlock is not fully enforced: {:?}",
            status.ruleset
        )));
    }
    Ok(())
}

/// The Rust runtime ignores SIGPIPE, and an ignored signal stays ignored across execve. Programs
/// expect the default action.
fn restore_sigpipe() -> Result<(), SandboxError> {
    // SAFETY: setting the default action of SIGPIPE has no memory safety requirements.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(SandboxError::io(
            "cannot restore SIGPIPE",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Marks every descriptor above 2 close-on-exec. Closing them now would also close the Landlock
/// ruleset that is still needed.
fn mark_descriptors_close_on_exec() -> Result<(), SandboxError> {
    // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only changes descriptor flags.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // close_range exists since Linux 5.9 and CLOSE_RANGE_CLOEXEC since 5.11.
        Some(libc::ENOSYS | libc::EINVAL) => mark_listed_descriptors_close_on_exec(),
        _ => Err(SandboxError::io(
            "cannot mark descriptors close-on-exec",
            error,
        )),
    }
}

fn mark_listed_descriptors_close_on_exec() -> Result<(), SandboxError> {
    let list_error = |error| SandboxError::io("cannot list the open descriptors", error);
    for entry in std::fs::read_dir("/proc/self/fd").map_err(list_error)? {
        let name = entry.map_err(list_error)?.file_name();
        let fd: libc::c_int = name
            .to_str()
            .and_then(|name| name.parse().ok())
            .ok_or_else(|| SandboxError::new(format!("unexpected descriptor name {name:?}")))?;
        if fd <= 2 {
            continue;
        }
        // SAFETY: F_SETFD only changes the flags of the descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(SandboxError::io(
                format!("cannot mark descriptor {fd} close-on-exec"),
                io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn set_no_new_privs() -> Result<(), SandboxError> {
    // SAFETY: PR_SET_NO_NEW_PRIVS only sets a process flag.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SandboxError::io(
            "cannot set no_new_privs",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// The arguments of execve, built before the sandbox is applied. After the seccomp filter is in
/// place only the execve call remains.
struct Exec {
    program: CString,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    // The pointer arrays point into these strings. Moving a CString does not move its buffer.
    _args: Vec<CString>,
    _env: Vec<CString>,
}

impl Exec {
    fn new(command: &TargetCommand) -> Result<Exec, SandboxError> {
        let program = c_string(command.program.as_os_str())?;
        let mut args = vec![c_string(&command.arg0)?];
        for arg in &command.args {
            args.push(c_string(arg)?);
        }
        let mut env = Vec::with_capacity(command.env.len());
        for (name, value) in &command.env {
            let mut entry = name.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            env.push(c_string(OsStr::from_bytes(&entry))?);
        }
        let pointers = |strings: &[CString]| {
            strings
                .iter()
                .map(|string| string.as_ptr())
                .chain([ptr::null()])
                .collect()
        };
        Ok(Exec {
            argv: pointers(&args),
            envp: pointers(&env),
            program,
            _args: args,
            _env: env,
        })
    }

    fn execute(&self) -> SandboxError {
        // SAFETY: every pointer points into a CString owned by `self`, and both arrays end with a
        // null pointer.
        unsafe {
            libc::execve(
                self.program.as_ptr(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
            )
        };
        let error = io::Error::last_os_error();
        SandboxError::io(format!("cannot execute {:?}", self.program), error)
    }
}

fn c_string(value: &OsStr) -> Result<CString, SandboxError> {
    CString::new(value.as_bytes())
        .map_err(|_| SandboxError::new(format!("{value:?} contains a NUL byte")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_second_thread_stops_the_launch() {
        let (stop, wait) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || wait.recv());
        let error = ensure_single_thread().unwrap_err();
        assert!(error.to_string().contains("threads"), "{error}");
        drop(stop);
        let _ = thread.join();
    }

    /// A directory with `rule/inner` and an unrelated `elsewhere`, canonical like a rule path.
    fn tree(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sandy-launch-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rule/inner")).unwrap();
        std::fs::create_dir_all(dir.join("elsewhere/inner")).unwrap();
        dir.canonicalize().unwrap()
    }

    /// Opens `target` as a rule after `change` ran between the plan and the launch.
    fn open_after(name: &str, target: &str, change: impl FnOnce(&Path)) -> Result<(), String> {
        let dir = tree(name);
        let path = dir.join(target);
        let planned = identity(&path);
        assert!(planned.is_some());
        change(&dir);
        let result = open_rule(&path, planned)
            .map(drop)
            .map_err(|error| error.to_string());
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn an_unchanged_rule_path_is_opened() {
        assert_eq!(open_after("same", "rule/inner", |_| {}), Ok(()));
    }

    #[test]
    fn a_rule_path_replaced_by_a_link_is_refused() {
        let error = open_after("link", "rule", |dir| {
            std::fs::rename(dir.join("rule"), dir.join("moved")).unwrap();
            std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("rule")).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("changed after sandy checked"), "{error}");
    }

    /// A link in a parent of the rule path, with the same names below it.
    #[test]
    fn a_link_on_the_way_to_a_rule_path_is_refused() {
        let error = open_after("parent-link", "rule/inner", |dir| {
            std::fs::rename(dir.join("rule"), dir.join("moved")).unwrap();
            std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("rule")).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("changed after sandy checked"), "{error}");
    }

    /// The resolver made the path canonical, so a link that is already there when sandy plans
    /// the run appeared after the checks of the resolver, and the identity sandy recorded is
    /// the link's target.
    #[test]
    fn a_link_that_appeared_before_the_plan_is_refused() {
        let dir = tree("early-link");
        std::fs::rename(dir.join("rule"), dir.join("moved")).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("rule")).unwrap();
        let path = dir.join("rule/inner");
        let error = open_rule(&path, identity(&path)).unwrap_err().to_string();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(error.contains("symbolic link"), "{error}");
    }

    #[test]
    fn a_rule_path_replaced_by_another_directory_is_refused() {
        let error = open_after("directory", "rule/inner", |dir| {
            std::fs::rename(dir.join("rule"), dir.join("moved")).unwrap();
            std::fs::rename(dir.join("elsewhere"), dir.join("rule")).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("changed after sandy checked"), "{error}");
    }
}
