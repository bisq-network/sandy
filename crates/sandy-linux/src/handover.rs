//! Listeners that a helper outside the sandbox's network namespace serves inside it. A socket
//! belongs to the network namespace it was created in, and a helper that must connect out from
//! the host's namespace (the relay of forwarded ports) cannot create one inside it. So:
//!
//! 1. Before the helper forks, `pair` makes a socket pair: the helper keeps the `Inbox`, the
//!    process that becomes the program keeps the `Handover` with the addresses.
//! 2. The helper confines itself and reports that it is ready, then waits on its inbox. Its
//!    filter needs `recvmsg` for that and nothing else.
//! 3. After `Namespaces::enter`, the process binds every address inside the namespace and sends
//!    the listeners over the pair (`SCM_RIGHTS`), before the program can run and take a port.
//! 4. The helper receives them in order and serves them. When the process that holds the
//!    handover ends before it sent them, the inbox ends and the helper with it.
//!
//! The helper reports ready before it has its listeners because with `children = "contained"`
//! sandy must know the helper before it forks the guard, and the program's child, which binds
//! the listeners, comes after the guard.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use sandy_core::SandboxError;

use crate::helper::{self, Watchdog, receive_descriptor, send_descriptor, socket_pair};

/// The side of the process that enters the namespace: what to bind there, and where the
/// listeners go.
#[derive(Debug)]
pub struct Handover {
    socket: OwnedFd,
    addresses: Vec<SocketAddr>,
    /// The helper, for errors.
    name: String,
}

/// The helper's side.
#[derive(Debug)]
pub struct Inbox {
    socket: OwnedFd,
    count: usize,
}

/// A handover of listeners on `addresses` to the helper `name` (for example "the relay").
pub fn pair(addresses: Vec<SocketAddr>, name: &str) -> Result<(Handover, Inbox), SandboxError> {
    let (sender, receiver) = socket_pair(
        libc::SOCK_SEQPACKET,
        &format!("the socket pair that hands {name} its listeners"),
    )?;
    let count = addresses.len();
    Ok((
        Handover {
            socket: sender,
            addresses,
            name: name.to_string(),
        },
        Inbox {
            socket: receiver,
            count,
        },
    ))
}

impl Handover {
    /// Binds every address in this process's network namespace and sends the listeners to the
    /// helper. This process keeps no copy.
    pub fn send(self) -> Result<(), SandboxError> {
        for address in &self.addresses {
            let listener = TcpListener::bind(address)
                .map_err(|error| SandboxError::io(format!("cannot listen on {address}"), error))?;
            send_descriptor(self.socket.as_raw_fd(), listener.as_raw_fd()).map_err(|error| {
                SandboxError::io(
                    format!("cannot hand the listener {address} to {}", self.name),
                    error,
                )
            })?;
        }
        Ok(())
    }
}

impl Inbox {
    /// The descriptor the helper must keep open until it has received the listeners.
    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Waits for the listeners as `receive` does, while it watches `ends`, the end of the program
    /// and of the guard's pipe, and keeps `watchdog` armed. `None` when one of `ends` ended first
    /// or the listeners never came.
    pub fn wait(self, ends: &[RawFd], watchdog: Option<&Watchdog>) -> Option<Vec<TcpListener>> {
        let fds: Vec<RawFd> = [self.fd()]
            .into_iter()
            .chain(ends.iter().copied())
            .collect();
        let ready = helper::wait_for(&fds, watchdog)?;
        if ready[1..].contains(&true) {
            return None;
        }
        self.receive().ok()
    }

    /// Waits for the listeners, in the order of the addresses. An error when the other end
    /// ended before it sent all of them.
    pub fn receive(self) -> io::Result<Vec<TcpListener>> {
        (0..self.count)
            .map(|_| {
                receive_descriptor(&self.socket)
                    .map(TcpListener::from)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the listeners were not handed over",
                        )
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    /// The listeners arrive in order and accept, and the sender keeps none of them. In a process
    /// of its own (`alone`): a child that another test forks meanwhile would hold copies of them.
    #[test]
    fn listeners_arrive_in_order_and_the_sender_keeps_none() {
        if !crate::alone::in_own_process() {
            return;
        }
        // A port that was free a moment ago can be taken by any process of the host before the
        // handover binds it again, so the test takes a few tries.
        let (addresses, listeners) = (0..5)
            .find_map(|_| {
                let addresses: Vec<SocketAddr> = (0..2)
                    .map(|_| {
                        TcpListener::bind("127.0.0.1:0")
                            .unwrap()
                            .local_addr()
                            .unwrap()
                    })
                    .collect();
                let (handover, inbox) = pair(addresses.clone(), "the test").unwrap();
                match handover.send() {
                    Ok(()) => Some((addresses, inbox.receive().unwrap())),
                    Err(error) => {
                        let source = std::error::Error::source(&error)
                            .and_then(|source| source.downcast_ref::<io::Error>());
                        assert!(
                            source.is_some_and(|source| source.kind() == io::ErrorKind::AddrInUse),
                            "{error}"
                        );
                        None
                    }
                }
            })
            .expect("no two free ports in five tries");
        for (listener, address) in listeners.iter().zip(&addresses) {
            assert_eq!(listener.local_addr().unwrap(), *address);
            let _client = TcpStream::connect(address).unwrap();
            listener.accept().unwrap();
        }
        // Once the helper closes them, the ports are free: the sender held no copy.
        drop(listeners);
        for address in &addresses {
            assert!(TcpStream::connect(address).is_err(), "{address}");
        }
    }

    #[test]
    fn an_inbox_whose_sender_ended_reports_it() {
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (handover, inbox) = pair(vec![address], "the test").unwrap();
        drop(handover);
        let error = inbox.receive().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
