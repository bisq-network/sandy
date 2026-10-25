//! The egress broker behind `network.egress` (DESIGN.md, "Egress broker"). sandy binds its
//! listener on the program's `127.0.0.1:<port>` and holds the port at every other address of
//! this Mac (`holder`), then starts the broker as a helper process (see `helper`) of its own,
//! apart from the relay, so the relay keeps its narrower rights. The broker watches sandy's
//! process ID with kqueue, applies its own profile (`profile::broker_profile`), checks that it
//! can still read this Mac's addresses, and only then tells sandy that it is ready. It serves
//! `sandy_relay::broker` until the program ends, then stops as the relay does.

use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use sandy_core::destination::HostNetwork;
use sandy_core::{Egress, EgressReach, SandboxError};
use sandy_relay::Stop;

use super::helper::{self, NO_EVENT, Ready, new_queue, register};
use super::holder;
use super::interfaces::Interfaces;
use super::seatbelt::Seatbelt;
use crate::profile::{Hold, Profile, broker_profile};

/// Starts the broker for `egress` as a helper process and returns its process ID once it is
/// confined, watches this process and serves; any failure before that is an error, and then no
/// broker serves. It keeps the port of `hold` bound for as long as it runs. With
/// `children = "contained"`, `ended` is the read end of the pipe whose end means that the
/// program's group has ended (`relay::start`).
pub fn start(
    egress: Egress,
    hold: Option<&Hold>,
    seatbelt: &Seatbelt,
    ended: Option<File>,
) -> Result<libc::pid_t, SandboxError> {
    let holders = match hold {
        Some(hold) => holder::hold(hold.port, &hold.leave)?,
        None => Vec::new(),
    };
    let listen = egress.listen();
    let listener = TcpListener::bind(listen).map_err(|error| {
        SandboxError::io(
            format!("cannot listen on {listen} for the egress broker"),
            error,
        )
    })?;
    let profile = broker_profile(egress.port);
    let seatbelt = *seatbelt;
    // SAFETY: getpid has no requirements.
    let watched = unsafe { libc::getpid() };
    let mut keep: Vec<RawFd> = vec![listener.as_raw_fd()];
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(holders.iter().map(AsRawFd::as_raw_fd));
    helper::start("the egress broker", &keep, move |ready| {
        let sockets = (listener, holders);
        serve(
            sockets,
            egress.reach,
            ended,
            &profile,
            &seatbelt,
            watched,
            ready,
        );
    })
}

/// The broker process. Returns when the program has ended. Like the relay's listeners, the
/// holder sockets go as soon as the program has ended.
fn serve(
    (listener, holders): (TcpListener, Vec<OwnedFd>),
    reach: EgressReach,
    ended: Option<File>,
    profile: &Profile,
    seatbelt: &Seatbelt,
    watched: libc::pid_t,
    ready: Ready,
) {
    let queue = match watch_and_confine(ended.as_ref(), profile, seatbelt, watched) {
        Ok(queue) => queue,
        Err(error) => ready.fail(&error.to_string()),
    };
    ready.report();
    let stop = Stop::new();
    let request = stop.clone();
    let server = std::thread::Builder::new()
        .name("broker".into())
        .spawn(move || {
            sandy_relay::broker::serve(
                listener,
                |listener: &TcpListener| listener.accept().map(|(client, _)| client),
                reach,
                Interfaces,
                &request,
                sandy_relay::DRAIN,
            );
        });
    let Ok(server) = server else {
        return;
    };
    // Any event is the end: the watched process exited or the group's pipe ended. An error of
    // kevent ends the broker too, so it never outlives a watch it lost.
    let mut events = [NO_EVENT; 2];
    let _ = helper::wait_events(&queue, &mut events, None);
    stop.request();
    drop(holders);
    let _ = server.join();
}

/// Registers the end of the watched process in a kqueue, raises the descriptor limit, applies
/// the profile and checks that the destination check still works under it.
fn watch_and_confine(
    ended: Option<&File>,
    profile: &Profile,
    seatbelt: &Seatbelt,
    watched: libc::pid_t,
) -> io::Result<OwnedFd> {
    sandy_relay::broker::raise_descriptor_limit()?;
    let queue = new_queue()?;
    register(&queue, watched as usize, libc::EVFILT_PROC, libc::NOTE_EXIT)?;
    if let Some(ended) = ended {
        // Readable only at its end: nothing writes into this pipe.
        register(&queue, ended.as_raw_fd() as usize, libc::EVFILT_READ, 0)?;
    }
    seatbelt.apply(profile).map_err(io::Error::other)?;
    // Without its addresses the broker would refuse every destination with reply 1; better to
    // refuse the run.
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    if !Interfaces.is_host(loopback)? {
        return Err(io::Error::other(
            "the egress broker does not find 127.0.0.1 among this Mac's addresses",
        ));
    }
    Ok(queue)
}
