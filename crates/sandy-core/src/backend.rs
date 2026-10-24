use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::plan::PlanItem;
use crate::resolve::ResolvedPolicy;

/// The program to start inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCommand {
    /// Canonical absolute path of the executable.
    pub program: PathBuf,
    /// The program as the caller named it, passed as `argv[0]`. Multi-call programs choose
    /// their behavior by this name, which can differ from the resolved `program`.
    pub arg0: OsString,
    pub args: Vec<OsString>,
    /// The complete environment of the target, already filtered by the policy. A backend may
    /// add variables the platform needs to start any process (documented per backend).
    pub env: Vec<(OsString, OsString)>,
    /// Working directory; `None` keeps the current one.
    pub cwd: Option<PathBuf>,
    /// For `process.end_with_parent`: the process ID of the process that started sandy. On Unix
    /// sandy reads it as its first step, or the caller names it and sandy checks it then; on
    /// Windows only the caller names it. `None` lets the backend find the parent itself.
    pub parent: Option<u32>,
}

/// One operating system sandbox implementation.
///
/// Contract:
/// - `plan` reports every requirement of `policy.requirements()` as enforced (naming the
///   mechanism) or unavailable (naming the reason). It must not change any state.
/// - `verify` adds what `plan` cannot see without touching the host. Only `check` calls it.
/// - `run` is called only when the plan is fully enforceable. It applies every mechanism the
///   plan named. If any step fails, it returns an error and never starts the target with a
///   weaker sandbox.
/// - On Unix, `run` replaces the current process with the target and returns only on failure.
///   Elsewhere it waits for the target and returns its exit code.
pub trait Backend {
    fn name(&self) -> &'static str;

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem>;

    /// Conditions that would make `run` refuse and that `plan` cannot see without touching the
    /// host, for example a relay port another process holds. `check` adds these reports to the
    /// plan, where any unavailable report wins; `run` does not call it, because it finds out
    /// while it applies the sandbox. An implementation must leave the host as it found it, and
    /// its answer can be stale a moment later, so `run` stays the authoritative answer.
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        crate::verify::relay_listeners(policy)
    }

    fn run(&self, policy: &ResolvedPolicy, command: &TargetCommand) -> Result<i32, SandboxError>;

    /// One-time host preparation that needs elevated rights, for example on Windows. Must be
    /// idempotent.
    fn setup(&self, _policy: &ResolvedPolicy) -> Result<(), SandboxError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SandboxError {
    context: String,
    source: Option<io::Error>,
}

impl SandboxError {
    pub fn new(context: impl Into<String>) -> Self {
        SandboxError {
            context: context.into(),
            source: None,
        }
    }

    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        SandboxError {
            context: context.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}: {source}", self.context),
            None => f.write_str(&self.context),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}
