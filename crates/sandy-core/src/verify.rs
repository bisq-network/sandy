//! The checks behind `Backend::verify`: they touch the host, which `plan` must not do, so they
//! run only for `sandy check`.

use std::net::{SocketAddr, TcpListener};

use crate::plan::{PlanItem, Requirement};
use crate::resolve::ResolvedPolicy;

/// Reports the relay requirements whose listeners sandy cannot bind right now. Every platform
/// listens on the `listen` address of each exposed port and on the loopback port of each
/// forwarded port (on Windows from inside the AppContainer, which shares the host's ports), and
/// `run` refuses when one of those binds fails. This binds the same addresses the same way, with
/// the socket options the standard library sets, and releases them again.
///
/// A trial bind is racy: another process can take the port in the moment between it and the bind
/// of `run`, and `run` can bind a port that was busy here. `run` stays the authoritative answer.
pub fn relay_listeners(policy: &ResolvedPolicy) -> Vec<PlanItem> {
    let exposed: Vec<SocketAddr> = policy.expose.iter().map(|entry| entry.listen).collect();
    let forwarded: Vec<SocketAddr> = policy.forward.iter().map(|entry| entry.listen()).collect();
    [
        (Requirement::ExposedPortsRelayed, exposed),
        (Requirement::ForwardedPortsRelayed, forwarded),
    ]
    .into_iter()
    .filter_map(|(requirement, addresses)| {
        let busy = addresses.into_iter().find_map(|address| {
            let error = TcpListener::bind(address).err()?;
            Some(format!("cannot listen on {address}: {error}"))
        })?;
        Some(PlanItem::unavailable(requirement, busy))
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ExposedPort, ForwardedPort, NetworkAccess, Policy};

    fn policy(expose: Vec<ExposedPort>, forward: Vec<ForwardedPort>) -> ResolvedPolicy {
        let mut policy = Policy::default();
        policy.network.ip = NetworkAccess::All;
        policy.network.expose = expose;
        policy.network.forward = forward;
        ResolvedPolicy::resolve(&policy, None).unwrap()
    }

    #[test]
    fn a_busy_listener_is_reported_and_a_free_one_is_not() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap();
        let expose = vec![ExposedPort {
            listen: busy,
            port: busy.port() + 1,
        }];
        let forward = vec![ForwardedPort {
            port: busy.port(),
            to: "127.0.0.1:1".parse().unwrap(),
        }];

        let items = relay_listeners(&policy(expose.clone(), Vec::new()));
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].requirement, Requirement::ExposedPortsRelayed);
        assert!(format!("{:?}", items[0].status).contains(&busy.to_string()));

        let items = relay_listeners(&policy(Vec::new(), forward));
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].requirement, Requirement::ForwardedPortsRelayed);

        // The trial bind releases the port again, so a free address reports nothing.
        drop(held);
        assert!(relay_listeners(&policy(expose, Vec::new())).is_empty());
    }
}
