//! Platform-neutral part of sandy: the policy model, its validation, the list of requirements a
//! policy creates, and the contract every platform backend implements.
//!
//! The central rule: a backend reports for every requirement how it enforces it on this host, or
//! why it cannot. sandy starts the target only when every requirement is enforced.

mod backend;
pub mod destination;
mod env;
mod plan;
mod policy;
mod resolve;
mod selection;
pub mod streams;
pub mod trust;
pub mod verify;

pub use backend::{
    Backend, ParentProcess, SandboxError, SetupOptions, SetupOutcome, StatusReport, TargetCommand,
    setup_levels,
};
pub use env::target_environment;
pub use plan::{EnforcementPlan, PlanItem, Requirement, Status};
pub use policy::{
    BASE_LEVEL, ChildProcesses, Egress, EgressReach, EnvironmentPolicy, ExposedPort, Fallback,
    FallbackEgress, FileView, FilesystemPolicy, ForwardedPort, IpAccess, Level, LinuxPolicy,
    MAX_LEVEL_NAME, MAX_POLICY_LEN, MAX_POLICY_NESTING, MachService, MacosPolicy, NetworkAccess,
    NetworkPolicy, POLICY_VERSION, PathMetadata, Policy, PolicyError, ProcessPolicy, Relays,
    SignalScope, SystemAccess, Win32k, WindowsPolicy,
};
pub use resolve::{
    PathAccess, PathIdentity, PathRule, ProtectedPath, ResolvedLevel, ResolvedPolicy,
    canonical_location, path_directories, shebang,
};
pub use selection::{Outcome, Selection, select};
