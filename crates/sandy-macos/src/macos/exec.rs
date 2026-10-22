//! Replaces sandy with the target. posix_spawn with the Apple extension POSIX_SPAWN_SETEXEC
//! works like execve: the target keeps sandy's process ID. POSIX_SPAWN_CLOEXEC_DEFAULT makes the
//! kernel close every descriptor that the file actions do not name, so sandy does not have to
//! find them itself. See posix_spawnattr_setflags(3) and posix_spawn_file_actions_addclose(3).

use std::ffi::{CString, c_char, c_int, c_short};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use sandy_core::{SandboxError, TargetCommand};

unsafe extern "C" {
    /// Apple extension in <spawn.h>, missing from the libc crate: keeps `fd` open in the new
    /// image when POSIX_SPAWN_CLOEXEC_DEFAULT is set.
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: c_int,
    ) -> c_int;
}

/// The target, converted to C strings before the sandbox is applied.
#[derive(Debug)]
pub struct Target {
    program: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
}

impl Target {
    pub fn new(command: &TargetCommand) -> Result<Target, SandboxError> {
        let program = c_string(command.program.as_os_str().as_bytes(), "the program path")?;
        let mut argv = vec![program.clone()];
        for arg in &command.args {
            argv.push(c_string(arg.as_bytes(), "an argument")?);
        }
        let mut envp = Vec::with_capacity(command.env.len());
        for (name, value) in &command.env {
            let mut entry = name.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            envp.push(c_string(&entry, "an environment variable")?);
        }
        Ok(Target {
            program,
            argv,
            envp,
        })
    }

    /// Replaces the current process image with the target, with exactly the target environment
    /// and only descriptors 0, 1 and 2. Returns only on failure.
    pub fn exec(&self) -> io::Error {
        let argv = null_terminated(&self.argv);
        let envp = null_terminated(&self.envp);
        let mut attributes: libc::posix_spawnattr_t = ptr::null_mut();
        let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
        // SAFETY: attributes and actions are initialized before use and destroyed on failure.
        // Every string pointer refers to a NUL-terminated string in self, and both arrays end
        // with NULL.
        let result = unsafe {
            spawn_exec(
                &mut attributes,
                &mut actions,
                self.program.as_ptr(),
                &argv,
                &envp,
            )
        };
        // SAFETY: destroying an object that init set up, or a null one after a failed init, is
        // allowed; the results do not matter on this failure path.
        unsafe {
            libc::posix_spawnattr_destroy(&mut attributes);
            libc::posix_spawn_file_actions_destroy(&mut actions);
        }
        match result {
            Err(error) => error,
            Ok(()) => io::Error::other("posix_spawn returned without replacing the process"),
        }
    }
}

/// # Safety
///
/// `program` must be a NUL-terminated string. `argv` and `envp` must point to NUL-terminated
/// strings and end with a null pointer.
unsafe fn spawn_exec(
    attributes: &mut libc::posix_spawnattr_t,
    actions: &mut libc::posix_spawn_file_actions_t,
    program: *const c_char,
    argv: &[*mut c_char],
    envp: &[*mut c_char],
) -> io::Result<()> {
    // SAFETY: the caller guarantees the string arguments; the spawn objects are initialized
    // here before they are used.
    unsafe {
        check(libc::posix_spawnattr_init(attributes))?;
        let flags = libc::POSIX_SPAWN_SETEXEC
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | libc::POSIX_SPAWN_SETSIGDEF;
        check(libc::posix_spawnattr_setflags(attributes, flags as c_short))?;
        // The Rust runtime of sandy ignores SIGPIPE. The target starts with the default action,
        // as it would after std::process::Command.
        let mut default_signals = MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(default_signals.as_mut_ptr());
        libc::sigaddset(default_signals.as_mut_ptr(), libc::SIGPIPE);
        check(libc::posix_spawnattr_setsigdefault(
            attributes,
            default_signals.as_ptr(),
        ))?;

        check(libc::posix_spawn_file_actions_init(actions))?;
        for fd in 0..=2 {
            // Inheriting a closed descriptor would make posix_spawn fail.
            if libc::fcntl(fd, libc::F_GETFD) != -1 {
                check(posix_spawn_file_actions_addinherit_np(actions, fd))?;
            }
        }
        check(libc::posix_spawn(
            ptr::null_mut(),
            program,
            actions,
            attributes,
            argv.as_ptr(),
            envp.as_ptr(),
        ))
    }
}

/// posix_spawn functions return an error number instead of setting errno.
fn check(result: c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

fn null_terminated(strings: &[CString]) -> Vec<*mut c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(ptr::null_mut()))
        .collect()
}

fn c_string(bytes: &[u8], what: &str) -> Result<CString, SandboxError> {
    CString::new(bytes).map_err(|_| SandboxError::new(format!("{what} contains a NUL byte")))
}
