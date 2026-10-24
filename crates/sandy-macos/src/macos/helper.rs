//! Helper processes that sandy starts before it confines itself and that must not be children of
//! the program: the relay of exposed and forwarded ports and the watcher of
//! `process.end_with_parent`.
//!
//! 1. sandy checks that it runs a single thread, because only then is `fork` safe, and forks
//!    twice. The intermediate process exits at once, so launchd adopts the helper. The program
//!    takes over sandy's process ID after the exec; the helper is not its child, so the program
//!    can neither reap it with `wait` nor receive `SIGCHLD` for it.
//! 2. The helper starts a session of its own and blocks every signal except the faults, so no
//!    terminal or process group signal reaches it. It points 0, 1 and 2 at `/dev/null` and closes
//!    every other descriptor except the ones it keeps and the readiness pipe.
//! 3. The helper confines itself with its own profile and reports over the pipe that it is ready,
//!    or why it is not. sandy continues only after a ready report.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{self, MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use sandy_core::SandboxError;

const READY: &[u8] = b"ready";
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Signals that report a fault of the process itself. They stay unblocked, so a fault ends it.
const FAULTS: [libc::c_int; 7] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
    libc::SIGSYS,
    libc::SIGABRT,
];

/// The helper's end of the readiness pipe.
pub struct Ready(File);

impl Ready {
    /// Reports that the helper is confined and serving. Ends the helper if sandy is gone.
    pub fn report(mut self) {
        if self.0.write_all(READY).is_err() {
            // SAFETY: ends the helper without running sandy's cleanup.
            unsafe { libc::_exit(1) };
        }
    }

    /// Reports why the helper did not start, and ends it.
    pub fn fail(mut self, message: &str) -> ! {
        let _ = self.0.write_all(message.as_bytes());
        // SAFETY: ends the helper without running sandy's cleanup.
        unsafe { libc::_exit(1) }
    }
}

/// Starts `main` in a helper process named `name` (for example "the relay") and returns once it
/// reported that it is ready. The helper keeps the descriptors in `keep`. `main` runs in the
/// helper and must call `Ready::report` after it has confined itself; the helper ends when `main`
/// returns. What `main` owns is dropped in sandy.
pub fn start(name: &str, keep: &[RawFd], main: impl FnOnce(Ready)) -> Result<(), SandboxError> {
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|error| SandboxError::io("cannot open /dev/null", error))?;
    let (ready_read, ready_write) = pipe(&format!("{name}'s pipe"))?;
    require_single_thread()?;

    // SAFETY: sandy is single-threaded (checked above), so the child may run any code. Both
    // children leave only through `_exit`, never by returning into sandy's code.
    let intermediate = unsafe { libc::fork() };
    match intermediate {
        -1 => {
            return Err(SandboxError::io(
                format!("cannot fork {name}"),
                io::Error::last_os_error(),
            ));
        }
        0 => {
            drop(ready_read);
            // SAFETY: as above; the intermediate process is single-threaded too.
            match unsafe { libc::fork() } {
                0 => {
                    let ready = Ready(ready_write);
                    if let Err(error) = prepare(keep, &null, &ready) {
                        ready.fail(&format!("{name} cannot start: {error}"));
                    }
                    drop(null);
                    // A panic must not unwind into sandy's code in this process.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| main(ready)));
                    // SAFETY: ends the helper without running sandy's cleanup.
                    unsafe { libc::_exit(0) }
                }
                -1 => Ready(ready_write).fail(&format!("cannot fork {name}")),
                // SAFETY: ends the intermediate process without running sandy's cleanup.
                _ => unsafe { libc::_exit(0) },
            }
        }
        _ => {}
    }
    drop(ready_write);
    drop(main);
    let mut status = 0;
    // SAFETY: waits for the intermediate child, which exits right after its fork.
    unsafe { libc::waitpid(intermediate, &mut status, 0) };

    let report = read_report(ready_read, READY_TIMEOUT)
        .map_err(|error| SandboxError::io(format!("cannot read {name}'s report"), error))?;
    match report {
        None => Err(SandboxError::new(format!(
            "{name} did not report within {} seconds",
            READY_TIMEOUT.as_secs()
        ))),
        Some(report) if report.is_empty() => Err(SandboxError::new(format!(
            "{name} ended before it was ready"
        ))),
        Some(report) if report == READY => Ok(()),
        Some(report) => Err(SandboxError::new(format!(
            "{name} did not start: {}",
            String::from_utf8_lossy(&report)
        ))),
    }
}

/// The helper's first steps: a session of its own, signals blocked, `/dev/null` as 0, 1 and 2, and
/// no descriptor of sandy's except `keep`.
fn prepare(keep: &[RawFd], null: &File, ready: &Ready) -> io::Result<()> {
    // SAFETY: setsid has no preconditions; a grandchild never leads a group.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    block_signals()?;
    for fd in 0..=2 {
        // SAFETY: both descriptors are open.
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut kept = keep.to_vec();
    kept.extend([0, 1, 2, ready.0.as_raw_fd(), null.as_raw_fd()]);
    close_all_except(&kept)
}

/// Reads the report until the helper closes the pipe. `None` when it is still open after
/// `timeout`.
fn read_report(mut pipe: File, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut report = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut poll = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        match unsafe { libc::poll(&mut poll, 1, left.as_millis() as libc::c_int) } {
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            -1 => return Err(io::Error::last_os_error()),
            0 => return Ok(None),
            _ => {}
        }
        let mut buffer = [0u8; 256];
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(Some(report)),
            Ok(read) => report.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Blocks every signal except the faults. Returns the blocked set and the previous mask. Blocked
/// signals stay pending; macOS discards them only while their action is to ignore them.
pub fn block_signals() -> io::Result<(libc::sigset_t, libc::sigset_t)> {
    // SAFETY: sigset_t is plain data; sigfillset and sigdelset initialize and change it, and
    // sigprocmask writes the previous mask into `previous`.
    unsafe {
        let mut blocked: libc::sigset_t = mem::zeroed();
        libc::sigfillset(&mut blocked);
        for fault in FAULTS {
            libc::sigdelset(&mut blocked, fault);
        }
        let mut previous: libc::sigset_t = mem::zeroed();
        if libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((blocked, previous))
    }
}

/// A close-on-exec pipe: (read end, write end). `name` names it in the error.
pub fn pipe(name: &str) -> Result<(File, File), SandboxError> {
    let error = |error| SandboxError::io(format!("cannot create {name}"), error);
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors pipe writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(error(io::Error::last_os_error()));
    }
    // SAFETY: both descriptors are new and owned by nothing else.
    let (read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        // SAFETY: fcntl on an open descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(error(io::Error::last_os_error()));
        }
    }
    Ok((read, write))
}

/// fork is safe only while no other thread could hold a lock that the child needs.
pub fn require_single_thread() -> Result<(), SandboxError> {
    let mut info = MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let size = size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: the buffer has exactly the size passed.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return Err(SandboxError::io(
            "cannot count the threads of sandy",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: proc_pidinfo filled the whole structure.
    let threads = unsafe { info.assume_init() }.pti_threadnum;
    if threads != 1 {
        return Err(SandboxError::new(format!(
            "sandy runs {threads} threads; it forks only with one"
        )));
    }
    Ok(())
}

/// The open descriptors of this process.
fn open_descriptors() -> io::Result<Vec<RawFd>> {
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: getpid has no requirements.
    let pid = unsafe { libc::getpid() };
    // SAFETY: a null buffer asks only for the size needed.
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for a few descriptors more than now; the caller opens none in between.
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(needed as usize / entry + 8);
    let capacity = (fds.capacity() * entry) as libc::c_int;
    // SAFETY: the buffer holds `capacity` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            capacity,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: proc_pidinfo initialized `written` bytes of whole entries.
    unsafe { fds.set_len(written as usize / entry) };
    Ok(fds.into_iter().map(|info| info.proc_fd).collect())
}

/// Closes every descriptor of this process that is not in `keep`.
pub fn close_all_except(keep: &[RawFd]) -> io::Result<()> {
    for fd in open_descriptors()? {
        if !keep.contains(&fd) {
            // SAFETY: closing a descriptor that nothing in this process uses any more.
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

/// Marks every descriptor except 0, 1 and 2 close-on-exec. Only safe while the process runs a
/// single thread, so that no descriptor appears in between.
pub fn mark_close_on_exec_above_standard() -> io::Result<()> {
    for fd in open_descriptors()? {
        // SAFETY: F_SETFD only changes the flags of an open descriptor.
        if fd > 2 && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn new_queue() -> io::Result<OwnedFd> {
    // SAFETY: kqueue has no arguments.
    let raw = unsafe { libc::kqueue() };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

pub fn register(queue: &OwnedFd, ident: usize, filter: i16, fflags: u32) -> io::Result<()> {
    let change = libc::kevent {
        ident,
        filter,
        flags: libc::EV_ADD,
        fflags,
        data: 0,
        udata: ptr::null_mut(),
    };
    // SAFETY: one valid change entry, no event buffer, no timeout.
    let result = unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &change,
            1,
            ptr::null_mut(),
            0,
            ptr::null(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An empty event for kevent's output buffer.
pub const NO_EVENT: libc::kevent = libc::kevent {
    ident: 0,
    filter: 0,
    flags: 0,
    fflags: 0,
    data: 0,
    udata: ptr::null_mut(),
};

/// Waits for events on `queue`, at most `timeout` (`None`: no limit). Returns the number of
/// events written into `events`; 0 after the timeout.
pub fn wait_events(
    queue: &OwnedFd,
    events: &mut [libc::kevent],
    timeout: Option<Duration>,
) -> io::Result<usize> {
    let timeout = timeout.map(|timeout| libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: timeout.subsec_nanos() as libc::c_long,
    });
    let timeout_pointer = timeout
        .as_ref()
        .map_or(ptr::null(), |timeout| timeout as *const _);
    loop {
        // SAFETY: no changes, room for events.len() events, a valid or null timeout.
        let count = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout_pointer,
            )
        };
        if count >= 0 {
            return Ok(count as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
