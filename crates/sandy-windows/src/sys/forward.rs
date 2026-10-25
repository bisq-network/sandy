//! The outside half of `network.forward`. An AppContainer cannot connect to loopback services
//! outside it without the loopback exemption, and a listener that sandy creates outside the
//! AppContainer is outside it too. So a relay inside the AppContainer (`sandy __forward`) creates
//! the program's listener itself; for each connection it connects to an AF_UNIX socket, which
//! loopback isolation does not filter. sandy listens on that socket here and connects each
//! connection to the forward target.
//!
//! The sockets live in a directory of their own below `%LOCALAPPDATA%\sandy\forward`. The user's
//! local application data grants nothing to AppContainers, and sandy adds one entry for the
//! relays' capability, which the program does not hold: only the relays (and the user) can open
//! the sockets.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sandy_core::{ForwardedPort, SandboxError};
use sandy_relay::{Stop, unix};

use super::acl;
use super::util::Sid;
use crate::access::{
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE,
    SYNCHRONIZE,
};

/// What the relays need to connect to a socket file: AF_UNIX connect checks write access to the
/// file. Granted on the files only (inherit-only), not on the directory, so a relay can neither
/// list nor create anything there.
const SOCKET_ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// The longest name below the base directory: a 16-digit run directory, a separator, and a port.
const RUN_SUFFIX_BYTES: usize = 1 + 16 + 1 + 5;

/// Marks a run directory as in use. The run holds it open without `FILE_SHARE_DELETE`, so a
/// later run that can open it exclusively knows that no run owns the directory any more. The
/// kernel closes the handle when the run ends, also after a kill, which is what makes the
/// leftover directory of a killed run removable. The file inherits the relays' entry like the
/// sockets do, which lets them open it but not delete it, and they end with the run.
const LOCK_NAME: &str = "lock";

/// One forwarded port as its relay sees it: the program's address it listens on, and the socket
/// it passes each connection to.
pub struct Route {
    pub listen: SocketAddr,
    pub socket: PathBuf,
}

/// The sockets of one run and the threads that serve them.
pub struct Forwarding {
    directory: PathBuf,
    /// Dropped before the directory is removed, because the run itself holds it.
    lock: Option<std::fs::File>,
    servers: Vec<(Stop, JoinHandle<()>)>,
}

/// The directory that holds the socket directories of all runs.
fn base() -> Result<PathBuf, SandboxError> {
    Ok(super::state_directory()?.join("forward"))
}

/// Why forwarded ports cannot work on this host, if they cannot: AF_UNIX is missing, or the
/// socket paths would not fit into `sun_path`. Changes nothing.
pub fn check() -> Result<(), String> {
    let base = base().map_err(|error| error.to_string())?;
    let length = base.as_os_str().len() + RUN_SUFFIX_BYTES;
    let fits = base.to_str().is_some() && length <= unix::MAX_PATH_BYTES;
    if !fits {
        return Err(format!(
            "the socket paths below {} would be {length} bytes; AF_UNIX allows at most {}",
            base.display(),
            unix::MAX_PATH_BYTES
        ));
    }
    unix::available().map_err(|error| format!("AF_UNIX sockets are not available: {error}"))
}

impl Forwarding {
    /// Creates the socket directory, lets `relay_capability` open the sockets in it, binds one
    /// socket per forwarded port and serves each by connecting to its target.
    pub fn start(
        forward: &[ForwardedPort],
        relay_capability: &Sid,
    ) -> Result<(Forwarding, Vec<Route>), SandboxError> {
        let base = base()?;
        std::fs::create_dir_all(&base).map_err(|error| {
            SandboxError::io(format!("cannot create {}", base.display()), error)
        })?;
        remove_dead_runs(&base);
        let directory = create_run_directory(&base)?;
        let lock = hold_run_directory(&directory)?;
        let mut forwarding = Forwarding {
            directory,
            lock: Some(lock),
            servers: Vec::new(),
        };
        // Set before the sockets exist, so that each socket file inherits the entry.
        acl::allow(
            &forwarding.directory,
            relay_capability,
            SOCKET_ACCESS,
            OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
        )?;
        let mut routes = Vec::with_capacity(forward.len());
        for entry in forward {
            let socket = forwarding.directory.join(entry.port.to_string());
            let listener = unix::Listener::bind(&socket).map_err(|error| {
                SandboxError::io(format!("cannot listen on {}", socket.display()), error)
            })?;
            let stop = Stop::new();
            let request = stop.clone();
            let target = entry.to;
            let server = thread::Builder::new()
                .spawn(move || {
                    sandy_relay::serve_until(
                        listener,
                        |listener| listener.accept(),
                        move || sandy_relay::connect(target),
                        &request,
                        sandy_relay::DRAIN,
                    )
                })
                .map_err(|error| SandboxError::io("cannot start a forward server", error))?;
            forwarding.servers.push((stop, server));
            routes.push(Route {
                listen: entry.listen(),
                socket,
            });
        }
        Ok((forwarding, routes))
    }

    /// Stops taking connections, lets accepted ones finish until `deadline`, and removes the
    /// sockets. Connections still open at the deadline end with sandy.
    pub fn stop(self, deadline: Instant) {
        for (stop, _) in &self.servers {
            stop.request();
        }
        while self.servers.iter().any(|(_, server)| !server.is_finished())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        // Dropping self removes the directory.
    }
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        // The lock file cannot be deleted while this run holds it open.
        self.lock.take();
        // Windows deletes a socket file also while its socket listens; then no one can connect.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Opens the lock file of a run directory and keeps the handle. Without `FILE_SHARE_DELETE` no
/// other process can delete it while this run lives.
fn hold_run_directory(directory: &Path) -> Result<std::fs::File, SandboxError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let path = directory.join(LOCK_NAME);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .map_err(|error| SandboxError::io(format!("cannot create {}", path.display()), error))
}

/// Removes the socket directories of runs that ended without cleaning up, for example after a
/// kill. Best effort: a directory stays when something else holds a file in it.
fn remove_dead_runs(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let directory = entry.path();
        if directory.is_dir() && run_ended(&directory) {
            let _ = std::fs::remove_dir_all(&directory);
        }
    }
}

/// Whether no run owns `directory`: its lock file opens with no sharing, which fails while the
/// run that created it holds the file. A directory without a lock file counts as owned: a run
/// creates its directory first and the lock file next, so another run can see it in between.
fn run_ended(directory: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(directory.join(LOCK_NAME))
        .is_ok()
}

/// A new directory with a random 16-digit name below `base`.
fn create_run_directory(base: &Path) -> Result<PathBuf, SandboxError> {
    for _ in 0..8 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        let directory = base.join(format!("{:016x}", hasher.finish()));
        match std::fs::create_dir(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(SandboxError::io(
                    format!("cannot create {}", directory.display()),
                    error,
                ));
            }
        }
    }
    Err(SandboxError::new(format!(
        "cannot create a socket directory below {}",
        base.display()
    )))
}
