//! The relay behind `network.expose` and `network.forward`. sandy binds the listeners and then
//! forks twice: the relay is a grandchild that launchd adopts, so the target, which takes over
//! sandy's process ID, never sees it as a child and cannot reap it. The relay keeps only its
//! listeners, watches sandy's process ID with kqueue, applies its own Seatbelt profile, and only
//! then tells sandy that it is ready. It accepts connections until the target ends, then closes
//! its listeners and lets the accepted connections finish for at most one second.

use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sandy_core::SandboxError;

use super::seatbelt::Seatbelt;
use crate::profile::{Profile, RelayPair, relay_profile};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// After the target ends, the relay closes its listeners at once and gives the connections it
/// already accepted this long to deliver what is left (DESIGN.md, "Forwarded ports", rule 5).
const DRAIN: Duration = Duration::from_secs(1);
const DRAIN_POLL: Duration = Duration::from_millis(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);
const READY: u8 = 1;

/// Starts the relay for `pairs`. Returns once the relay is confined, watches this process and
/// serves; any failure before that is an error, and then no relay serves.
pub fn start(pairs: &[RelayPair], seatbelt: &Seatbelt) -> Result<(), SandboxError> {
    let mut listeners = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let listener = TcpListener::bind(pair.listen).map_err(|error| {
            SandboxError::io(format!("cannot listen on {}", pair.listen), error)
        })?;
        listeners.push((listener, pair.target));
    }
    let profile = relay_profile(pairs);
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|error| SandboxError::io("cannot open /dev/null", error))?;
    let (ready_read, ready_write) = pipe().map_err(|error| SandboxError::io("pipe", error))?;
    require_single_thread()?;
    // SAFETY: getpid has no requirements.
    let watched = unsafe { libc::getpid() };

    // SAFETY: the process has a single thread (checked above), so the child can run any code
    // without finding a lock that another thread held at the fork.
    match unsafe { libc::fork() } {
        -1 => {
            return Err(SandboxError::io(
                "cannot fork the relay",
                io::Error::last_os_error(),
            ));
        }
        0 => {
            // The intermediate process forks the relay and exits at once, so launchd adopts
            // the relay.
            // SAFETY: still a single thread, as above.
            if unsafe { libc::fork() } == 0 {
                drop(ready_read);
                let served = serve(listeners, &profile, seatbelt, watched, ready_write, null);
                // SAFETY: _exit ends the relay without running anything of sandy's.
                unsafe { libc::_exit(if served.is_ok() { 0 } else { 1 }) }
            }
            // SAFETY: as above.
            unsafe { libc::_exit(0) }
        }
        intermediate => {
            let mut status = 0;
            // SAFETY: waits for the intermediate process forked above, which exits at once.
            unsafe { libc::waitpid(intermediate, &mut status, 0) };
        }
    }
    drop(ready_write);
    drop(listeners);
    wait_until_ready(&ready_read)
}

/// The relay process. Returns when the target has ended, or with an error before it is ready.
fn serve(
    listeners: Vec<(TcpListener, SocketAddr)>,
    profile: &Profile,
    seatbelt: &Seatbelt,
    watched: libc::pid_t,
    ready: OwnedFd,
    null: File,
) -> io::Result<()> {
    // A session of its own: signals from the caller's terminal do not reach the relay.
    // SAFETY: setsid has no memory requirements.
    unsafe { libc::setsid() };
    for fd in 0..=2 {
        // SAFETY: both descriptors are open.
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    drop(null);
    let mut keep: Vec<RawFd> = listeners.iter().map(|(l, _)| l.as_raw_fd()).collect();
    keep.extend([0, 1, 2, ready.as_raw_fd()]);
    close_all_except(&keep)?;

    // Registered before the profile is applied, which denies process information about others.
    let queue = new_queue()?;
    register(&queue, watched as usize, libc::EVFILT_PROC, libc::NOTE_EXIT)?;
    for (listener, _) in &listeners {
        listener.set_nonblocking(true)?;
        register(&queue, listener.as_raw_fd() as usize, libc::EVFILT_READ, 0)?;
    }
    seatbelt.apply(profile).map_err(io::Error::other)?;
    // SAFETY: writes one byte from a valid buffer to an open pipe.
    if unsafe { libc::write(ready.as_raw_fd(), [READY].as_ptr().cast(), 1) } != 1 {
        return Err(io::Error::last_os_error());
    }
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));
    accept_until_exit(&queue, &listeners, &active);
    // The program has ended: no new connections, and the accepted ones get a last moment to
    // deliver what the program sent before it exited.
    drop(listeners);
    let start = Instant::now();
    while active.load(Ordering::Acquire) > 0 && start.elapsed() < DRAIN {
        std::thread::sleep(DRAIN_POLL);
    }
    Ok(())
}

/// Accepts connections on every listener whenever the kqueue reports one, until it reports that
/// the watched process exited. An error of kevent also ends the loop, so the relay never
/// outlives a watch it lost.
fn accept_until_exit(
    queue: &OwnedFd,
    listeners: &[(TcpListener, SocketAddr)],
    active: &Arc<AtomicUsize>,
) {
    let mut events = [libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: ptr::null_mut(),
    }; 16];
    loop {
        // SAFETY: no changes, room for events.len() events, no timeout.
        let count = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                ptr::null(),
            )
        };
        if count == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        for event in &events[..count as usize] {
            if event.filter == libc::EVFILT_PROC {
                return;
            }
            let ready = listeners
                .iter()
                .find(|(listener, _)| listener.as_raw_fd() as usize == event.ident);
            if let Some((listener, target)) = ready {
                accept_pending(listener, *target, active);
            }
        }
    }
}

/// Accepts every pending connection on `listener` and relays each one in a thread of its own.
fn accept_pending(listener: &TcpListener, target: SocketAddr, active: &Arc<AtomicUsize>) {
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            // A connection reset before the accept, or descriptors exhausted: pause, so a
            // listener that stays readable does not spin, and try again on the next event.
            Err(_) => {
                std::thread::sleep(ACCEPT_ERROR_PAUSE);
                return;
            }
        };
        if client.set_nonblocking(false).is_err() {
            continue;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= sandy_relay::MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let counter = Arc::clone(active);
        let spawned = std::thread::Builder::new().spawn(move || {
            let _ = sandy_relay::relay(client, target);
            counter.fetch_sub(1, Ordering::AcqRel);
        });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn new_queue() -> io::Result<OwnedFd> {
    // SAFETY: kqueue has no arguments.
    let raw = unsafe { libc::kqueue() };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn register(queue: &OwnedFd, ident: usize, filter: i16, fflags: u32) -> io::Result<()> {
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

/// Waits for the relay's ready byte. End of file or a timeout means that it did not start.
fn wait_until_ready(ready: &OwnedFd) -> Result<(), SandboxError> {
    let mut poll = libc::pollfd {
        fd: ready.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = READY_TIMEOUT.as_millis() as libc::c_int;
    let ready_now = loop {
        // SAFETY: one valid pollfd.
        match unsafe { libc::poll(&mut poll, 1, timeout) } {
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    if ready_now != 1 {
        return Err(SandboxError::new(
            "the relay for the exposed and forwarded ports did not start in time",
        ));
    }
    let mut byte = 0u8;
    // SAFETY: reads at most one byte into a valid buffer.
    let read = unsafe { libc::read(ready.as_raw_fd(), (&raw mut byte).cast(), 1) };
    if read == 1 && byte == READY {
        Ok(())
    } else {
        Err(SandboxError::new(
            "the relay for the exposed and forwarded ports failed to start",
        ))
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors pipe writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are new and owned by nothing else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        // SAFETY: fcntl on an open descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

/// fork is safe only while no other thread could hold a lock that the child needs.
fn require_single_thread() -> Result<(), SandboxError> {
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
            "sandy runs {threads} threads; it starts the relay only with one"
        )));
    }
    Ok(())
}

/// Closes every descriptor of this process that is not in `keep`.
fn close_all_except(keep: &[RawFd]) -> io::Result<()> {
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: getpid has no requirements.
    let pid = unsafe { libc::getpid() };
    // SAFETY: a null buffer asks only for the size needed.
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for a few descriptors more than now; this process opens none in between.
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
    for info in fds {
        if !keep.contains(&info.proc_fd) {
            // SAFETY: closing a descriptor that nothing in this process uses any more.
            unsafe { libc::close(info.proc_fd) };
        }
    }
    Ok(())
}
