//! What the answers of the host probes in `sys` mean for a plan. A probe that reads a lasting
//! state of the host reports a shortfall when the mechanism is missing; a probe that fails, or
//! finds a state in passing, leaves sandy unable to tell (`Problem`). The classes depend only on
//! the Win32 error codes and the states the probes report, so the tests run on every platform
//! with injected ones; `sys` checks that the constants match the Windows headers.

use std::fmt;
use std::io;

use crate::plan::Problem;

/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: i32 = 5;

/// `WSAEAFNOSUPPORT`: no Winsock provider supports the address family.
pub const WSAEAFNOSUPPORT: i32 = 10047;

/// Values of `SERVICE_STATUS::dwCurrentState`.
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_STOP_PENDING: u32 = 3;
pub const SERVICE_RUNNING: u32 = 4;

/// The Windows Firewall service from the state that the service control manager reports, or the
/// step that failed and its error. A stopped service is a shortfall: it stays stopped until an
/// administrator starts it. Every other state passes (the service is starting, stopping or
/// paused), and an error says nothing lasting about the service.
pub fn firewall(state: Result<u32, (&str, io::Error)>) -> Result<(), Problem> {
    const SERVICE: &str = "the Windows Firewall service (MpsSvc)";
    match state {
        Ok(SERVICE_RUNNING) => Ok(()),
        Ok(SERVICE_STOPPED) => Err(Problem::Unavailable(format!("{SERVICE} is stopped"))),
        Ok(SERVICE_START_PENDING) => Err(Problem::Indeterminate(format!("{SERVICE} is starting"))),
        Ok(SERVICE_STOP_PENDING) => Err(Problem::Indeterminate(format!("{SERVICE} is stopping"))),
        Ok(state) => Err(Problem::Indeterminate(format!(
            "{SERVICE} is neither running nor stopped (state {state})"
        ))),
        Err((step, error)) => Err(Problem::Indeterminate(format!("cannot {step}: {error}"))),
    }
}

/// AF_UNIX from the result of a trial socket (`sandy_relay::unix::available`). Winsock without
/// the address family is a shortfall of the host. Any other error can pass: no buffer space,
/// too many sockets, or a Winsock that does not start (`WSAStartup`).
pub fn af_unix(trial: io::Result<()>) -> Result<(), Problem> {
    match trial {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(WSAEAFNOSUPPORT) => Err(Problem::Unavailable(
            format!("AF_UNIX sockets are not available: {error}"),
        )),
        Err(error) => Err(Problem::Indeterminate(format!(
            "cannot create a trial AF_UNIX socket: {error}"
        ))),
    }
}

/// Why sandy cannot say that it may give an AppContainer access to a file (`acl::grantable`).
#[derive(Debug)]
pub enum Ungrantable {
    /// The grant is missing, and opening the file for `WRITE_DAC` failed with this error.
    Denied(io::Error),
    /// The file has no access control list, so everyone has full access. sandy does not change
    /// it: the list that would replace it grants only the AppContainer.
    NoAcl,
    /// sandy cannot read the identity or the access control list of the file.
    Unreadable(String),
}

impl fmt::Display for Ungrantable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ungrantable::Denied(error) => write!(
                f,
                "the grant is missing, and the current user may not change the permissions: \
                 {error}"
            ),
            Ungrantable::NoAcl => f.write_str(
                "it has no access control list (everyone has full access); sandy does not change \
                 it",
            ),
            Ungrantable::Unreadable(reason) => f.write_str(reason),
        }
    }
}

/// The class of `Ungrantable` for a policy path. Its owner laid out its permissions so that the
/// current user may not add the grant, or gave it no access control list: the policy names a
/// path that this host does not let sandy use, a conflict. It is the same for every fallback
/// level, because the levels share their paths. Any other error can pass.
pub fn path_grant(problem: Ungrantable) -> Problem {
    match problem {
        Ungrantable::Denied(ref error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            Problem::Conflict(problem.to_string())
        }
        Ungrantable::NoAcl => Problem::Conflict(problem.to_string()),
        Ungrantable::Denied(_) | Ungrantable::Unreadable(_) => {
            Problem::Indeterminate(problem.to_string())
        }
    }
}

/// The class of `Ungrantable` for sandy's own executable, which the relays and the egress broker
/// run. `sandy setup` adds a grant that the current user may not add; it fixes nothing else, and
/// it fails itself on a file without an access control list, so every other problem is
/// indeterminate rather than a promise that setup helps.
pub fn relay_grant(problem: Ungrantable) -> Problem {
    match problem {
        Ungrantable::Denied(ref error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            Problem::NeedsSetup(problem.to_string())
        }
        Ungrantable::Denied(_) | Ungrantable::NoAcl | Ungrantable::Unreadable(_) => {
            Problem::Indeterminate(problem.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ERROR_SHARING_VIOLATION`, `ERROR_FILE_NOT_FOUND` and `ERROR_SERVICE_DOES_NOT_EXIST`.
    const OTHER_ERRORS: [i32; 3] = [32, 2, 1060];

    fn error(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn a_stopped_firewall_is_a_shortfall_and_a_passing_state_is_not() {
        assert_eq!(firewall(Ok(SERVICE_RUNNING)), Ok(()));
        assert!(matches!(
            firewall(Ok(SERVICE_STOPPED)),
            Err(Problem::Unavailable(reason)) if reason.contains("stopped")
        ));
        // Starting, stopping, continuing, pausing, paused, and a state Windows does not define.
        for state in [SERVICE_START_PENDING, SERVICE_STOP_PENDING, 5, 6, 7, 99] {
            assert!(
                matches!(firewall(Ok(state)), Err(Problem::Indeterminate(_))),
                "{state}"
            );
        }
        assert!(matches!(
            firewall(Ok(SERVICE_START_PENDING)),
            Err(Problem::Indeterminate(reason)) if reason.contains("starting")
        ));
    }

    /// Every error of opening the service control manager or the service, or of the query, is
    /// indeterminate, also access denied and a service the manager does not know.
    #[test]
    fn a_firewall_that_cannot_be_read_is_indeterminate() {
        for code in [ERROR_ACCESS_DENIED].into_iter().chain(OTHER_ERRORS) {
            match firewall(Err(("open the service control manager", error(code)))) {
                Err(Problem::Indeterminate(reason)) => {
                    assert!(
                        reason.starts_with("cannot open the service control manager: "),
                        "{reason}"
                    );
                    assert!(reason.contains(&format!("os error {code}")), "{reason}");
                }
                other => panic!("{code}: {other:?}"),
            }
        }
    }

    #[test]
    fn af_unix_is_missing_only_without_the_address_family() {
        assert_eq!(af_unix(Ok(())), Ok(()));
        assert!(matches!(
            af_unix(Err(error(WSAEAFNOSUPPORT))),
            Err(Problem::Unavailable(reason)) if reason.contains("not available")
        ));
        // WSAEMFILE, WSAENOBUFS, WSAEPROCLIM, WSASYSNOTREADY, WSAVERNOTSUPPORTED, WSAEINPROGRESS,
        // WSANOTINITIALISED.
        for code in [10024, 10055, 10067, 10091, 10092, 10036, 10093] {
            assert!(
                matches!(af_unix(Err(error(code))), Err(Problem::Indeterminate(_))),
                "{code}"
            );
        }
    }

    /// The finding of the audit (8): only a grant that the current user may not add is for
    /// `sandy setup`; a file without an access control list or one sandy cannot read is not.
    #[test]
    fn only_a_denied_relay_grant_needs_setup() {
        assert!(matches!(
            relay_grant(Ungrantable::Denied(error(ERROR_ACCESS_DENIED))),
            Problem::NeedsSetup(reason) if reason.contains("may not change the permissions")
        ));
        for problem in OTHER_ERRORS
            .map(|code| Ungrantable::Denied(error(code)))
            .into_iter()
            .chain([
                Ungrantable::NoAcl,
                Ungrantable::Unreadable("cannot read the file ID".into()),
            ])
        {
            let text = problem.to_string();
            assert!(
                matches!(relay_grant(problem), Problem::Indeterminate(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_policy_path_that_sandy_may_not_grant_is_a_conflict() {
        for problem in [
            Ungrantable::Denied(error(ERROR_ACCESS_DENIED)),
            Ungrantable::NoAcl,
        ] {
            let text = problem.to_string();
            assert!(
                matches!(path_grant(problem), Problem::Conflict(_)),
                "{text}"
            );
        }
        for problem in OTHER_ERRORS
            .map(|code| Ungrantable::Denied(error(code)))
            .into_iter()
            .chain([Ungrantable::Unreadable("cannot open C:\\data".into())])
        {
            let text = problem.to_string();
            assert!(
                matches!(path_grant(problem), Problem::Indeterminate(_)),
                "{text}"
            );
        }
    }
}
