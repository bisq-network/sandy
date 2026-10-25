//! The relay behind `network.expose` and `network.forward`. sandy binds the listeners and then
//! starts the relay as a helper process (see `helper`), which launchd adopts, so the target,
//! which takes over sandy's process ID, never sees it as a child and cannot reap it. The relay
//! keeps only its listeners and the holder sockets of `ip = "private"`, watches sandy's process
//! ID with kqueue, applies its own Seatbelt profile, and only then tells sandy that it is ready.
//! It accepts connections until the target ends, then closes its listeners and lets the accepted
//! connections finish for at most one second.

use std::fs::File;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sandy_core::SandboxError;

use super::helper::{self, NO_EVENT, Ready, new_queue, register};
use super::holder;
use super::seatbelt::Seatbelt;
use crate::profile::{Profile, RelayPair, relay_profile};

/// After the target ends, the relay closes its listeners at once and gives the connections it
/// already accepted this long to deliver what is left (DESIGN.md, "Forwarded ports", rule 5).
const DRAIN: Duration = Duration::from_secs(1);
const DRAIN_POLL: Duration = Duration::from_millis(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// Starts the relay for `pairs` as a helper process (see `helper`). Returns its process ID once
/// the relay is confined, watches this process and serves; any failure before that is an error,
/// and then no relay serves. The relay also keeps the `held` ports bound at the wildcard
/// addresses for as long as it runs (`holder`). With `children = "contained"`, `ended` is the
/// read end of a pipe whose write end only the guard holds: its end means that the program's
/// group has ended, also while the supervising sandy is stopped.
pub fn start(
    pairs: &[RelayPair],
    held: &[u16],
    seatbelt: &Seatbelt,
    ended: Option<File>,
) -> Result<libc::pid_t, SandboxError> {
    let mut holders = Vec::with_capacity(held.len() * 2);
    for port in held {
        holders.extend(holder::hold(*port)?);
    }
    let mut listeners = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let listener = TcpListener::bind(pair.listen).map_err(|error| {
            SandboxError::io(format!("cannot listen on {}", pair.listen), error)
        })?;
        listeners.push((listener, pair.target));
    }
    let profile = relay_profile(pairs);
    let seatbelt = *seatbelt;
    // SAFETY: getpid has no requirements.
    let watched = unsafe { libc::getpid() };
    let mut keep: Vec<RawFd> = listeners.iter().map(|(l, _)| l.as_raw_fd()).collect();
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(holders.iter().map(AsRawFd::as_raw_fd));
    helper::start("the relay", &keep, move |ready| {
        serve(listeners, ended, &profile, &seatbelt, watched, ready);
        drop(holders);
    })
}

/// The relay process. Returns when the target has ended.
fn serve(
    listeners: Vec<(TcpListener, SocketAddr)>,
    ended: Option<File>,
    profile: &Profile,
    seatbelt: &Seatbelt,
    watched: libc::pid_t,
    ready: Ready,
) {
    let queue = match watch_and_confine(&listeners, ended.as_ref(), profile, seatbelt, watched) {
        Ok(queue) => queue,
        Err(error) => ready.fail(&error.to_string()),
    };
    ready.report();

    // One count per listener: clients of one port cannot take the connections of another.
    let active: Vec<Arc<AtomicUsize>> = listeners
        .iter()
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();
    let total = || {
        active
            .iter()
            .map(|count| count.load(Ordering::Acquire))
            .sum::<usize>()
    };
    accept_until_exit(&queue, &listeners, &active);
    // The program has ended: no new connections, and the accepted ones get a last moment to
    // deliver what the program sent before it exited.
    drop(listeners);
    let start = Instant::now();
    while total() > 0 && start.elapsed() < DRAIN {
        std::thread::sleep(DRAIN_POLL);
    }
    if total() > 0 {
        // The relay ends now; the connections it still relays end with a reset, not with the
        // normal end that would look like a complete stream.
        sandy_relay::abort_all();
    }
}

/// Registers the end of the watched process and the listeners in a kqueue, then applies the
/// relay's profile. The registration comes first, because the profile denies process information
/// about others.
fn watch_and_confine(
    listeners: &[(TcpListener, SocketAddr)],
    ended: Option<&File>,
    profile: &Profile,
    seatbelt: &Seatbelt,
    watched: libc::pid_t,
) -> io::Result<OwnedFd> {
    sandy_relay::raise_descriptor_limit(listeners.len())?;
    let queue = new_queue()?;
    register(&queue, watched as usize, libc::EVFILT_PROC, libc::NOTE_EXIT)?;
    if let Some(ended) = ended {
        // Readable only at its end: nothing writes into this pipe.
        register(&queue, ended.as_raw_fd() as usize, libc::EVFILT_READ, 0)?;
    }
    for (listener, _) in listeners {
        listener.set_nonblocking(true)?;
        register(&queue, listener.as_raw_fd() as usize, libc::EVFILT_READ, 0)?;
    }
    seatbelt.apply(profile).map_err(io::Error::other)?;
    Ok(queue)
}

/// Accepts connections on every listener whenever the kqueue reports one, until it reports that
/// the watched process exited or the group's pipe ended. An error of kevent also ends the loop,
/// so the relay never outlives a watch it lost.
///
/// kqueue reports events in the order they became ready, so a connection the program made
/// before it exited is still accepted. A listener is reported once for its whole backlog, and
/// `accept_pending` takes all of it, so a connection that arrived after the end is accepted as
/// well when its listener became ready before the end. After a SIGSTOP and SIGCONT that is
/// everything the backlog collected while the relay was stopped (docs/macos.md).
fn accept_until_exit(
    queue: &OwnedFd,
    listeners: &[(TcpListener, SocketAddr)],
    active: &[Arc<AtomicUsize>],
) {
    let mut events = [NO_EVENT; 16];
    loop {
        let Ok(count) = helper::wait_events(queue, &mut events, None) else {
            return;
        };
        for event in &events[..count] {
            let ready = listeners
                .iter()
                .zip(active)
                .find(|((listener, _), _)| listener.as_raw_fd() as usize == event.ident);
            match ready {
                Some(((listener, target), count)) if event.filter == libc::EVFILT_READ => {
                    accept_pending(listener, *target, count)
                }
                // The watched process exited, or the group's pipe ended.
                _ => return,
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
