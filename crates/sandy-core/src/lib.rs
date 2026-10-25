//! Platform-neutral part of sandy: the policy model, its validation, the list of requirements a
//! policy creates, and the contract every platform backend implements.
//!
//! The central rule: a backend reports for every requirement how it enforces it on this host, or
//! why it cannot. sandy starts the target only when every requirement is enforced.

mod backend;
mod env;
mod plan;
mod policy;
mod resolve;
pub mod streams;
pub mod trust;
pub mod verify;

pub use backend::{Backend, ParentProcess, SandboxError, StatusReport, TargetCommand};
pub use env::target_environment;
pub use plan::{EnforcementPlan, PlanItem, Requirement, Status};
pub use policy::{
    ChildProcesses, EnvironmentPolicy, ExposedPort, FilesystemPolicy, ForwardedPort, LinuxPolicy,
    NetworkAccess, NetworkPolicy, POLICY_VERSION, PathMetadata, Policy, PolicyError, ProcessPolicy,
    SignalScope, SystemAccess, WindowsPolicy,
};
pub use resolve::{
    PathAccess, PathIdentity, PathRule, ProtectedPath, ResolvedPolicy, canonical_location,
    path_directories, shebang,
};
