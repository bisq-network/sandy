//! Linux backend of sandy: Landlock, a seccomp filter and no_new_privs, applied to sandy's own
//! process before it executes the target. The crate is empty on other platforms. See
//! `docs/linux.md`.
#![cfg(target_os = "linux")]

mod cgroup;
mod contain;
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
mod relay;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux egress broker, a later task, uses it")
)]
mod routes;
mod system;
mod trust;
mod watch;

use sandy_core::streams::CreatableSocket;
use sandy_core::{
    Backend, IpAccess, PlanItem, Requirement, ResolvedPolicy, SandboxError, StatusReport,
    TargetCommand,
};

use host::HostCapabilities;
use namespace::Namespaces;

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &HostCapabilities::detect_for(policy)).items
    }

    /// The trial binds of the relay ports, and with `ip = "private"` a trial of the namespace
    /// steps when the host says nothing against them. The forward listeners then bind inside the
    /// sandbox's new network namespace, where no port is taken, so a busy port on the host's
    /// loopback says nothing about them.
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let private = policy.ip == IpAccess::Private;
        let mut items = sandy_core::verify::relay_listeners(policy);
        if private {
            items.retain(|item| item.requirement != Requirement::ForwardedPortsRelayed);
            if namespace::support().is_ok()
                && let Err(reason) = namespace::probe(Namespaces { network: true })
            {
                items.push(PlanItem::unavailable(
                    Requirement::IpNetworkPrivate,
                    format!("a trial of the sandbox's namespaces failed: {reason}"),
                ));
            }
        }
        items
    }

    fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        plan::notes(policy, &HostCapabilities::detect_for(policy))
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
        let host = HostCapabilities::detect_for(policy);
        let Some(landlock) = plan::landlock_for(policy, &host) else {
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
        let plan = plan::plan_for(policy, &HostCapabilities::detect_for(policy));
        let sandbox = plan
            .sandbox
            .ok_or_else(|| SandboxError::new("this host cannot enforce the policy"))?;
        launch::launch(&sandbox, command, status)
    }
}
