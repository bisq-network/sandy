//! Linux backend of sandy. The crate is empty on other platforms.
#![cfg(target_os = "linux")]

use sandy_core::{Backend, PlanItem, ResolvedPolicy, SandboxError, TargetCommand};

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        policy
            .requirements()
            .into_iter()
            .map(|requirement| PlanItem::unavailable(requirement, "not implemented yet"))
            .collect()
    }

    fn run(&self, _policy: &ResolvedPolicy, _command: &TargetCommand) -> Result<i32, SandboxError> {
        Err(SandboxError::new(
            "the Linux backend is not implemented yet",
        ))
    }
}
