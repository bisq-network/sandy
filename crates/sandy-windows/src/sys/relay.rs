//! The relays of `network.expose` and `network.forward`. For `expose`: Windows drops every
//! inbound loopback connection into an AppContainer, so sandy listens outside the AppContainer
//! and starts `sandy __relay` inside it.
//! A socket created outside the AppContainer keeps the security context of its creator and
//! accepts outside connections; the relay reaches the program over loopback because both run in
//! the same AppContainer. For `forward`, the relay `sandy __forward` creates the program's
//! listener inside the AppContainer itself (see `forward`).

use std::net::{SocketAddr, TcpListener};
use std::os::windows::io::AsRawSocket;

use sandy_core::{ExposedPort, PathAccess, PathRule, SandboxError};
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};

use super::acl;
use super::util::last_error;

/// The internal command of the sandy command line that runs a relay.
pub const RELAY_COMMAND: &str = "__relay";

/// The internal command of the sandy command line that runs a forward relay.
pub const FORWARD_COMMAND: &str = "__forward";

/// The internal command of the sandy command line that runs the egress broker.
pub const BROKER_COMMAND: &str = "__broker";

/// The rule that lets the relays run sandy's own executable. The backend runs inside the sandy
/// command line, so this is `sandy.exe`.
pub fn relay_rule() -> Result<PathRule, String> {
    let exe = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .map_err(|error| format!("cannot find sandy's own executable: {error}"))?;
    Ok(PathRule {
        path: exe,
        access: PathAccess::ReadExec,
        is_dir: false,
    })
}

/// `relay_rule`, if sandy can apply it for `appcontainer` now. Changes nothing.
pub fn relay_program(appcontainer: &str) -> Result<PathRule, String> {
    let rule = relay_rule()?;
    acl::grantable(appcontainer, &rule).map_err(|reason| {
        format!(
            "cannot allow the relays to run {}: {reason}; `sandy setup` with this policy, run as \
             administrator, adds the grant",
            rule.path.display()
        )
    })?;
    Ok(rule)
}

/// One listening socket per exposed port, created outside the AppContainer and inheritable, with
/// the program's address that its relay connects to.
pub fn listen(expose: &[ExposedPort]) -> Result<Vec<(TcpListener, SocketAddr)>, SandboxError> {
    expose
        .iter()
        .map(|entry| {
            let listener = TcpListener::bind(entry.listen).map_err(|error| {
                SandboxError::io(format!("cannot listen on {}", entry.listen), error)
            })?;
            // Base-provider sockets are kernel handles. The standard library creates them
            // without inheritance; the relay receives this one through the handle list.
            let handle = listener.as_raw_socket() as HANDLE;
            // SAFETY: handle is the open socket of `listener`; only its inherit flag changes.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                == 0
            {
                return Err(last_error(format!(
                    "cannot pass the socket of {} to the relay",
                    entry.listen
                )));
            }
            Ok((listener, entry.target()))
        })
        .collect()
}
