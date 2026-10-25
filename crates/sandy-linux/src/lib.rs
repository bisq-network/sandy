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
    Backend, FileView, IpAccess, PlanItem, Requirement, ResolvedPolicy, SandboxError, SetupOptions,
    SetupOutcome, StatusReport, TargetCommand,
};

use host::HostCapabilities;
use namespace::Namespaces;

pub use relaunch::hand_over_target;

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &HostCapabilities::detect_for(policy)).items
    }

    /// The trial binds of the relay ports, and with `ip = "private"` or `filesystem.view =
    /// "policy"` a trial of the namespace steps when the host says nothing against them. The
    /// forward listeners then bind inside the sandbox's new network namespace, where no port is taken, so a busy port on the host's
    /// loopback says nothing about them. The egress broker needs the namespace too, and the
    /// kernel's answers about this host's addresses, which `run` asks for before it starts it.
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let private = policy.ip == IpAccess::Private;
        let hidden = policy.view == FileView::Policy;
        let mut items = sandy_core::verify::relay_listeners(policy);
        if private {
            items.retain(|item| item.requirement != Requirement::ForwardedPortsRelayed);
        }
        let namespaces = Namespaces {
            network: private,
            mount: hidden,
            pid: false,
        };
        if (private || hidden)
            && namespace::support(&namespace::Purpose::of(policy)).is_ok()
            && let Err(reason) = namespace::probe(namespaces)
        {
            let reason = format!("a trial of the sandbox's namespaces failed: {reason}");
            let requirements = [
                (private, Requirement::IpNetworkPrivate),
                (
                    private && policy.egress.is_some(),
                    Requirement::EgressBrokered,
                ),
                (hidden, Requirement::PathsHidden),
            ];
            for (_, requirement) in requirements.into_iter().filter(|(needed, _)| *needed) {
                items.push(PlanItem::unavailable(requirement, reason.clone()));
            }
        }
        if policy.egress.is_some()
            && let Err(error) = routes::Routes::open()
        {
            items.push(PlanItem::unavailable(
                Requirement::EgressBrokered,
                error.to_string(),
            ));
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
        _policy: &ResolvedPolicy,
        remove: bool,
        options: SetupOptions,
        args: &[OsString],
    ) -> Result<SetupOutcome, SandboxError> {
        elevate::elevate(remove, options, args)
    }
}
