//! The parts that call macOS: loading Seatbelt, applying the profile and replacing sandy with
//! the target.

mod exec;
mod seatbelt;

use sandy_core::{Backend, PlanItem, ResolvedPolicy, SandboxError, TargetCommand};

use crate::plan::{HostCapabilities, plan_for};
use crate::profile::{Profile, generate};
use seatbelt::Seatbelt;

// The profile is generated on every platform, so it carries its own copy of these numbers.
const _: () = {
    use crate::system;
    assert!(system::FIONBIO == libc::FIONBIO);
    assert!(system::FIOASYNC == libc::FIOASYNC);
    assert!(system::TIOCGETA == libc::TIOCGETA);
    assert!(system::TIOCGWINSZ == libc::TIOCGWINSZ);
    assert!(system::TIOCSTI == libc::TIOCSTI);
};

/// Seatbelt profile applied in-process with sandbox_init_with_parameters, then the target
/// replaces sandy (see `docs/macos.md`).
#[derive(Debug, Default)]
pub struct MacosBackend;

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan_for(policy, &detect(&generate(policy)))
    }

    fn run(&self, policy: &ResolvedPolicy, command: &TargetCommand) -> Result<i32, SandboxError> {
        let profile = generate(policy);
        let target = exec::Target::new(command)?;
        if let Some(cwd) = &command.cwd {
            std::env::set_current_dir(cwd).map_err(|error| {
                SandboxError::io(format!("cannot change to {}", cwd.display()), error)
            })?;
        }
        let seatbelt = Seatbelt::load().map_err(SandboxError::new)?;
        seatbelt.apply(&profile).map_err(|message| {
            SandboxError::new(format!("cannot apply the Seatbelt profile: {message}"))
        })?;
        let error = target.exec();
        Err(SandboxError::io(
            format!("cannot execute {}", command.program.display()),
            error,
        ))
    }
}

/// Loads Seatbelt and compiles `profile` without applying it. Neither step changes the
/// sandbox state of the process.
fn detect(profile: &Profile) -> HostCapabilities {
    match Seatbelt::load() {
        Ok(seatbelt) => HostCapabilities {
            seatbelt: Ok(()),
            profile: seatbelt.compile(profile),
            already_sandboxed: seatbelt.is_sandboxed(),
        },
        Err(reason) => HostCapabilities {
            seatbelt: Err(reason),
            profile: Err("not compiled".to_string()),
            already_sandboxed: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{
        EnvironmentPolicy, NetworkAccess, PathAccess, PathMetadata, PathRule, SignalScope,
        SystemAccess, WindowsPolicy,
    };
    use std::path::PathBuf;

    fn policies() -> Vec<ResolvedPolicy> {
        let rule = |path: &str, access, is_dir| PathRule {
            path: PathBuf::from(path),
            access,
            is_dir,
        };
        let base = ResolvedPolicy {
            paths: vec![
                rule("/private/tmp/sandy-ro", PathAccess::Read, true),
                rule("/private/tmp/sandy-rw", PathAccess::ReadWrite, true),
                rule("/private/tmp/sandy-rw/nested", PathAccess::Read, false),
                rule("/private/tmp/sandy-bin", PathAccess::ReadExec, true),
                rule("/bin/ls", PathAccess::ReadExec, false),
            ],
            program: Some(PathBuf::from("/bin/ls")),
            system: SystemAccess::Minimal,
            ip: NetworkAccess::None,
            unix_sockets: NetworkAccess::None,
            signals: SignalScope::Any,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            windows: WindowsPolicy::default(),
        };
        let mut policies = Vec::new();
        for system in [SystemAccess::Minimal, SystemAccess::None] {
            for ip in [NetworkAccess::None, NetworkAccess::All] {
                for unix_sockets in [NetworkAccess::None, NetworkAccess::All] {
                    for signals in [SignalScope::Any, SignalScope::Isolated] {
                        policies.push(ResolvedPolicy {
                            system,
                            ip,
                            unix_sockets,
                            signals,
                            ..base.clone()
                        });
                    }
                }
            }
        }
        policies
    }

    /// Compiles without applying, so the test process stays unsandboxed.
    #[test]
    fn this_macos_compiles_every_profile_variant() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        for policy in policies() {
            let profile = generate(&policy);
            if let Err(message) = seatbelt.compile(&profile) {
                panic!("{message}\n{}", profile.text);
            }
        }
    }

    #[test]
    fn this_macos_rejects_an_invalid_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = Profile {
            text: "(version 1)\n(deny default)\n(allow no-such-operation)\n".to_string(),
            parameters: Vec::new(),
        };
        assert!(seatbelt.compile(&profile).is_err());
    }

    #[test]
    fn plan_is_enforceable_here() {
        let policy = policies().remove(0);
        let plan =
            sandy_core::EnforcementPlan::new(&policy.requirements(), MacosBackend.plan(&policy));
        assert!(plan.is_enforceable(), "{plan}");
    }
}
