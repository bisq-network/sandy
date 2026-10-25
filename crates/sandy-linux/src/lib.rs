//! Linux backend of sandy: Landlock, a seccomp filter and no_new_privs, applied to sandy's own
//! process before it executes the target. The crate is empty on other platforms. See
//! `docs/linux.md`.
#![cfg(target_os = "linux")]

mod cgroup;
mod contain;
mod explain;
mod filter;
mod helper;
mod host;
mod launch;
mod loader;
mod openssl;
mod peer;
mod plan;
mod relay;
mod system;
mod trust;
mod watch;

use sandy_core::streams::CreatableSocket;
use sandy_core::{Backend, PlanItem, ResolvedPolicy, SandboxError, StatusReport, TargetCommand};

use host::HostCapabilities;

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &HostCapabilities::detect_for(policy)).items
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
