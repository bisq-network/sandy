//! Linux backend of sandy: Landlock, a seccomp filter and no_new_privs, applied to sandy's own
//! process before it executes the target. The crate is empty on other platforms. See
//! `docs/linux.md`.
#![cfg(target_os = "linux")]

mod cgroup;
mod contain;
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

use sandy_core::{Backend, PlanItem, ResolvedPolicy, SandboxError, TargetCommand};

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

    fn run(&self, policy: &ResolvedPolicy, command: &TargetCommand) -> Result<i32, SandboxError> {
        let plan = plan::plan_for(policy, &HostCapabilities::detect_for(policy));
        let sandbox = plan
            .sandbox
            .ok_or_else(|| SandboxError::new("this host cannot enforce the policy"))?;
        launch::launch(&sandbox, command)
    }
}
