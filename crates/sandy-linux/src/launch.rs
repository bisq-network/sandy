//! The launch sequence of `run`. Everything that can fail on bad input is prepared first. Then the
//! process restricts itself step by step and replaces itself with the target. With
//! `process.children = "contained"` a forked child does that, and sandy supervises it (see
//! `contain`).

use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use landlock::{
    CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, RulesetStatus,
};
use sandy_core::{ParentProcess, SandboxError, StatusReport, TargetCommand};

use crate::explain::{self, Observer};
use crate::filter::{FilterConfig, Filters};
use crate::host::THREADS_DIR;
use crate::plan::{LandlockConfig, Sandbox};
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
             children = \"contained\": sandy stays the program's parent in this mode, and only \
             the supervising sandy of \"contained\" passes on the signals that end the program",
        ));
    }
    // With `contained`, the relay also ends when the guard has ended the program's group.
    let mut group_ended = None;
    if let Some(relay) = &sandbox.relay {
        let ended = if sandbox.contain {
            let (read, write) = crate::helper::pipe("the pipe of the group's end")?;
            group_ended = Some(write);
            Some(read)
        } else {
            None
        };
        relay::start(relay, ended)?;
    }
    if sandbox.end_with_parent {
        let parent = command.parent.unwrap_or_else(|| ParentProcess {
            // SAFETY: getppid has no preconditions.
            id: unsafe { libc::getppid() } as u32,
            start: None,
        });
        watch::start(parent, sandbox.landlock.abi)?;
    }
    let ruleset = prepare_ruleset(&sandbox.landlock)?;
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
    restore_sigpipe()?;
    let start = || match confine(ruleset, &sandbox.filter, observer.as_ref()) {
        Ok(()) => exec.execute(),
        Err(error) => error,
    };
    if sandbox.contain {
        contain::run(start, group_ended, status, explain.as_mut())
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
/// right that the kernel does not support is an error instead of being dropped.
fn prepare_ruleset(config: &LandlockConfig) -> Result<RulesetCreated, SandboxError> {
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
        let fd = PathFd::new(&rule.path).map_err(|error| {
            SandboxError::new(format!("cannot open {}: {error}", rule.path.display()))
        })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rule.access))
            .map_err(landlock_error)?;
    }
    Ok(ruleset)
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
}
