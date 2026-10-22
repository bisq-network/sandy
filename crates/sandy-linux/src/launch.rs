//! The launch sequence of `run`. Everything that can fail on bad input is prepared first. Then the
//! process restricts itself step by step and replaces itself with the target.

use std::convert::Infallible;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use landlock::{
    CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, RulesetStatus,
};
use sandy_core::{SandboxError, TargetCommand};

use crate::filter;
use crate::plan::{LandlockConfig, Sandbox};

/// Applies `sandbox` to this process and executes the target. Returns only on failure.
///
/// Landlock and seccomp restrict the calling thread. sandy does not start threads, the filters
/// are installed with TSYNC, and execve ends every other thread, so the target runs with exactly
/// the restrictions applied here.
pub fn launch(sandbox: &Sandbox, command: &TargetCommand) -> Result<Infallible, SandboxError> {
    let ruleset = prepare_ruleset(&sandbox.landlock)?;
    let filters = filter::build(&sandbox.filter)
        .map_err(|error| SandboxError::new(format!("cannot build the seccomp filter: {error}")))?;
    let exec = Exec::new(command)?;
    if let Some(cwd) = &command.cwd {
        std::env::set_current_dir(cwd).map_err(|error| {
            SandboxError::io(format!("cannot change to {}", cwd.display()), error)
        })?;
    }
    restore_sigpipe()?;

    mark_descriptors_close_on_exec()?;
    set_no_new_privs()?;
    restrict(ruleset)?;
    filter::install(&filters).map_err(|error| {
        SandboxError::new(format!("cannot install the seccomp filter: {error}"))
    })?;
    Err(exec.execute())
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

fn restrict(ruleset: RulesetCreated) -> Result<(), SandboxError> {
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

fn set_no_new_privs() -> Result<(), SandboxError> {
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
        let mut args = vec![program.clone()];
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
