//! Linux backend of sandy: Landlock, a seccomp filter and no_new_privs, applied to sandy's own
//! process before it executes the target. The crate is empty on other platforms. See
//! `docs/linux.md`.
#![cfg(target_os = "linux")]

mod contain;
mod filter;
mod host;
mod launch;
mod plan;
mod relay;
mod system;

use sandy_core::{Backend, PlanItem, ResolvedPolicy, SandboxError, TargetCommand};

use host::HostCapabilities;

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &HostCapabilities::detect()).items
    }

    fn run(&self, policy: &ResolvedPolicy, command: &TargetCommand) -> Result<i32, SandboxError> {
        let plan = plan::plan_for(policy, &HostCapabilities::detect());
        let sandbox = plan
            .sandbox
            .ok_or_else(|| SandboxError::new("this host cannot enforce the policy"))?;
        launch::launch(&sandbox, command)
    }
}
