use std::cell::RefCell;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
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
    /// For `process.end_with_parent`: the process that started sandy. `None` lets the backend
    /// find the parent itself.
    pub parent: Option<ParentProcess>,
}

/// For `process.end_with_parent`: the process sandy watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentProcess {
    /// The process ID. On Unix sandy reads it as its first step, or the caller names it with
    /// `--parent-pid` and sandy checks it then; on Windows only the caller names it.
    pub id: u32,
    /// `--parent-start`: the start of the process with that ID, which only the caller itself
    /// can know, so a process that got the ID after the caller ended is told apart from the
    /// caller. The form is platform-specific (see the platform docs). Without it a named
    /// process ID must be sandy's own parent.
    pub start: Option<u64>,
}

/// The record of `--status-fd`. sandy stays the parent of the program with
/// `process.children = "contained"` and on Windows, so its own exit status does not say which
/// process the program was, and 125 means both "sandy refused" and "the program exited with
/// 125". A caller that needs to tell these apart reads the record instead. One line per event,
/// in this order:
///
/// - `pid N` once the program runs, with the program's process ID. In the exec model (Linux and
///   macOS without `contained`) sandy writes it right before it replaces itself with the
///   program, because afterwards it cannot write any more.
/// - `exited N` or `signaled N` when sandy saw the program end. The exec model has no such
///   line: sandy is the program there, and the caller's own wait status is the program's.
/// - `failed` when sandy itself failed or refused. Without a `pid` line the program never ran;
///   after one it means that the last step, the `execve`, failed.
///
/// Writing is best effort: a caller that closed the read end gets no record, and the program
/// keeps running.
#[derive(Debug)]
pub struct StatusReport {
    channel: Option<RefCell<File>>,
}

impl StatusReport {
    /// No record: the caller passed no `--status-fd`.
    pub fn none() -> StatusReport {
        StatusReport { channel: None }
    }

    /// Writes the record to `channel`, which the caller must have made close-on-exec, so that
    /// the program never sees it.
    pub fn to(channel: File) -> StatusReport {
        StatusReport {
            channel: Some(RefCell::new(channel)),
        }
    }

    pub fn started(&self, pid: u32) {
        self.write(format_args!("pid {pid}"));
    }

    pub fn exited(&self, code: i32) {
        self.write(format_args!("exited {code}"));
    }

    pub fn signaled(&self, signal: i32) {
        self.write(format_args!("signaled {signal}"));
    }

    pub fn failed(&self) {
        self.write(format_args!("failed"));
    }

    fn write(&self, line: fmt::Arguments<'_>) {
        let Some(channel) = &self.channel else {
            return;
        };
        let mut channel = channel.borrow_mut();
        let _ = writeln!(channel, "{line}");
        let _ = channel.flush();
    }
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
/// - `run` reports the program's process ID to `status` once the program runs, and how it ended
///   when it waits for the program. It writes nothing else there; `failed` is the caller's.
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

    fn run(
        &self,
        policy: &ResolvedPolicy,
        command: &TargetCommand,
        status: &StatusReport,
    ) -> Result<i32, SandboxError>;

    /// What makes the program behave differently inside the sandbox than outside on this host,
    /// beyond the requirements, for example a configuration file the policy does not cover.
    /// `check` prints these as warnings next to the ones of the policy; they change neither what
    /// sandy enforces nor the exit status, so a backend reports a fact here instead of refusing
    /// when the program may well not be affected. Like `verify`, it may read host state and must
    /// leave the host as it found it.
    fn notes(&self, _policy: &ResolvedPolicy) -> Vec<String> {
        Vec::new()
    }

    /// One-time host preparation that needs elevated rights, for example on Windows. Must be
    /// idempotent.
    fn setup(&self, _policy: &ResolvedPolicy) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Takes back what `setup` and the runs of this policy left on the host. Must be
    /// idempotent, and must touch only what sandy itself created for this policy. A backend
    /// that leaves nothing behind does nothing here.
    fn remove(&self, _policy: &ResolvedPolicy) -> Result<(), SandboxError> {
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
