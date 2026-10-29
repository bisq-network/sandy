//! Linux backend of sandy: Landlock, a seccomp filter and no_new_privs, applied to sandy's own
//! process before it executes the target. The crate is empty on other platforms. See
//! `docs/linux.md`.
#![cfg(target_os = "linux")]

#[cfg(test)]
mod alone;
mod broker;
mod cgroup;
mod contain;
mod elevate;
mod explain;
mod factory;
mod filter;
mod handover;
mod helper;
mod host;
mod launch;
mod loader;
mod namespace;
mod openssl;
mod peer;
mod plan;
mod relaunch;
mod relay;
mod routes;
mod setup;
mod system;
mod trust;
mod view;
mod watch;

use std::ffi::OsString;

use sandy_core::streams::CreatableSocket;
use sandy_core::{
    Backend, IpAccess, PlanItem, Requirement, ResolvedLevel, ResolvedPolicy, SandboxError,
    SetupOptions, SetupOutcome, StatusReport, TargetCommand,
};

use host::{Detected, ThisHost};

pub use relaunch::hand_over_target;

#[derive(Debug)]
pub struct LinuxBackend {
    host: Detected,
}

impl LinuxBackend {
    /// A backend that detects what this host offers when a policy first needs it, and keeps
    /// the answers for every later call (`Backend`).
    pub fn new() -> LinuxBackend {
        LinuxBackend {
            host: Detected::new(Box::new(ThisHost)),
        }
    }

    /// The configuration `run` applies, planned against the kept answers, so the run uses the
    /// host that `plan` saw.
    fn sandbox(&self, policy: &ResolvedPolicy) -> Result<plan::Sandbox, SandboxError> {
        plan::plan_for(policy, &self.host.for_policy(policy))
            .sandbox
            .ok_or_else(|| SandboxError::new("this host cannot enforce the policy"))
    }
}

/// `Backend::verify` with the route lookup it tries, `open_routes`.
fn verified<R, E: std::fmt::Display>(
    policy: &ResolvedPolicy,
    open_routes: impl FnOnce() -> Result<R, E>,
) -> Vec<PlanItem> {
    let mut items = sandy_core::verify::relay_listeners(policy);
    if policy.ip == IpAccess::Private {
        items.retain(|item| item.requirement != Requirement::ForwardedPortsRelayed);
    }
    if policy.egress.is_some()
        && let Err(error) = open_routes()
    {
        items.push(PlanItem::indeterminate(
            Requirement::EgressBrokered,
            error.to_string(),
        ));
    }
    items
}

impl Default for LinuxBackend {
    fn default() -> Self {
        LinuxBackend::new()
    }
}

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &self.host.for_policy(policy)).items
    }

    /// The trial binds of the relay ports, and with an egress broker the kernel's answers about
    /// this host's addresses, which `run` asks for before it starts the broker. With
    /// `ip = "private"` the forward listeners bind inside the sandbox's new network namespace,
    /// where no port is taken, so a busy port on the host's loopback says nothing about them.
    /// What fails here can pass, so it is indeterminate. The namespaces are tried by `plan`.
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        verified(policy, routes::Routes::open)
    }

    fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        plan::notes(policy, &self.host.common())
    }

    fn ip_also_allows(&self) -> &'static [CreatableSocket] {
        filter::IP_ALSO_ALLOWS
    }

    fn can_explain(&self) -> bool {
        true
    }

    fn explain_paths(
        &self,
        policy: &ResolvedPolicy,
        paths: &[std::path::PathBuf],
    ) -> Option<Vec<String>> {
        let Some(landlock) = plan::landlock_for(policy, &self.host.common()) else {
            return Some(vec![
                "this host has no Landlock, so the policy grants nothing and sandy refuses to \
                 start the program"
                    .to_string(),
            ]);
        };
        Some(
            paths
                .iter()
                .map(|path| explain::explain_path(&landlock, path))
                .collect(),
        )
    }

    fn run(
        &self,
        policy: &ResolvedPolicy,
        command: &TargetCommand,
        status: &StatusReport,
    ) -> Result<i32, SandboxError> {
        launch::launch(&self.sandbox(policy)?, command, status)
    }

    /// Under Ubuntu's AppArmor restriction, the profile that gives sandy user namespaces; the
    /// policy plays no part (`setup`).
    fn setup(
        &self,
        _policy: &ResolvedPolicy,
        options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        setup::setup(options)
    }

    fn remove(
        &self,
        _policy: &ResolvedPolicy,
        options: SetupOptions,
    ) -> Result<SetupOutcome, SandboxError> {
        setup::remove(options)
    }

    fn elevate(
        &self,
        _levels: &[ResolvedLevel],
        remove: bool,
        options: SetupOptions,
        args: &[OsString],
    ) -> Result<SetupOutcome, SandboxError> {
        elevate::elevate(remove, options, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use host::{Recording, resolved};

    /// `plan` of a second policy, the `notes` and `explain_paths` of either, and the
    /// configuration that `run` applies all use the answers of the first `plan`.
    #[test]
    fn one_backend_detects_each_property_once() {
        let probes = Recording::new();
        let backend = LinuxBackend {
            host: Detected::new(Box::new(probes.clone())),
        };
        let contained = resolved("[process]\nchildren = \"contained\"\nsignals = \"isolated\"");
        let plain = resolved("[process]\nsignals = \"isolated\"");
        backend.plan(&contained);
        let detected = probes.ran();
        assert!(detected.len() > 1, "{detected:?}");
        backend.plan(&plain);
        backend.notes(&contained);
        backend.explain_paths(&contained, &["/".into()]);
        let _ = backend.sandbox(&contained);
        backend.plan(&contained);
        assert_eq!(probes.ran(), detected);
    }

    /// Whatever `verify` finds can pass, so it reports it as indeterminate: a route lookup that
    /// failed, and a relay port that another process holds. A forwarded port under
    /// `ip = "private"` listens inside the sandbox's own namespace, so the host's port is not
    /// tried.
    #[test]
    fn verify_reports_what_can_pass_as_indeterminate() {
        let egress = resolved("[network]\nip = \"private\"\negress = { port = 1080 }");
        assert_eq!(
            verified(&egress, || Err::<(), _>("the kernel did not answer")),
            [PlanItem::indeterminate(
                Requirement::EgressBrokered,
                "the kernel did not answer"
            )]
        );
        assert_eq!(verified(&egress, || Ok::<_, String>(())), []);

        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let forward = |ip: &str| {
            resolved(&format!(
                "[network]\nip = \"{ip}\"\nforward = [{{ port = {port}, to = \"127.0.0.1:1\" }}]"
            ))
        };
        let items = verified(&forward("all"), || Ok::<_, String>(()));
        assert!(
            matches!(
                &items[..],
                [PlanItem {
                    requirement: Requirement::ForwardedPortsRelayed,
                    status: sandy_core::Status::Indeterminate { .. },
                }]
            ),
            "{items:?}"
        );
        assert_eq!(verified(&forward("private"), || Ok::<_, String>(())), []);
    }
}
