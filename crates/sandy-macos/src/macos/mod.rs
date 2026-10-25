//! The parts that call macOS: loading Seatbelt, applying the profile and replacing sandy with
//! the target.

mod contain;
mod exec;
mod helper;
mod relay;
mod seatbelt;
mod watch;

use sandy_core::{
    Backend, ChildProcesses, ParentProcess, PlanItem, ResolvedPolicy, SandboxError, StatusReport,
    TargetCommand,
};

use std::ffi::CStr;
use std::io::Read;

use crate::binary;
use crate::plan::{HostCapabilities, SHEBANG_LEVELS, executable_paths, plan_for};
use crate::profile::{generate, relay_pairs, relay_profile, watcher_profile};
use seatbelt::Seatbelt;

// The profile is generated on every platform, so it carries its own copy of these numbers.
const _: () = {
    use crate::system;
    assert!(system::FIONBIO == libc::FIONBIO);
    assert!(system::FIOASYNC == libc::FIOASYNC);
    assert!(system::TIOCGETA == libc::TIOCGETA);
    assert!(system::TIOCGWINSZ == libc::TIOCGWINSZ);
    assert!(system::TIOCSTI == libc::TIOCSTI);
    assert!(system::F_SETOWN as libc::c_int == libc::F_SETOWN);
};

/// Seatbelt profile applied in-process with sandbox_init_with_parameters, then the target
/// replaces sandy, or with `children = "contained"` a forked child of sandy (see
/// `docs/macos.md`).
#[derive(Debug, Default)]
pub struct MacosBackend;

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan_for(policy, &detect(policy))
    }

    fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        crate::plan::notes(policy)
    }

    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let mut items = sandy_core::verify::relay_listeners(policy);
        if let Err(reason) = applies_in_a_trial(policy) {
            items.extend(crate::plan::profile_unavailable(policy, &reason));
        }
        items
    }

    fn run(
        &self,
        policy: &ResolvedPolicy,
        command: &TargetCommand,
        status: &StatusReport,
    ) -> Result<i32, SandboxError> {
        let profile = generate(policy);
        let target = exec::Target::new(command)?;
        if let Some(cwd) = &command.cwd {
            std::env::set_current_dir(cwd).map_err(|error| {
                SandboxError::io(format!("cannot change to {}", cwd.display()), error)
            })?;
        }
        let seatbelt = Seatbelt::load().map_err(SandboxError::new)?;
        // Before anything is forked, so that no process sandy starts keeps the ports either.
        exec::reset_exception_ports()?;
        let contained = policy.children == ChildProcesses::Contained;
        let pairs = relay_pairs(policy);
        // With `contained`, the relay also ends when the guard has ended the program's group,
        // and the guard watches the relay in turn (see `contain::run`).
        let mut group_ended = None;
        let mut relay = None;
        if !pairs.is_empty() {
            let ended = if contained {
                let (read, write) = helper::pipe("the pipe of the group's end")?;
                group_ended = Some(write);
                Some(read)
            } else {
                None
            };
            relay = Some(relay::start(&pairs, &seatbelt, ended)?);
        }
        if policy.end_with_parent {
            let parent = command.parent.unwrap_or_else(|| ParentProcess {
                // SAFETY: getppid has no preconditions.
                id: unsafe { libc::getppid() } as u32,
                start: None,
            });
            watch::start(parent, &seatbelt)?;
        }
        let apply = || {
            seatbelt.apply(&profile).map_err(|message| {
                SandboxError::new(format!("cannot apply the Seatbelt profile: {message}"))
            })
        };
        let cannot_execute = |error| {
            SandboxError::io(
                format!("cannot execute {}", command.program.display()),
                error,
            )
        };
        if contained {
            return contain::run(
                || match apply() {
                    Ok(()) => cannot_execute(target.execve()),
                    Err(error) => error,
                },
                group_ended,
                relay,
                status,
            );
        }
        // In the exec model sandy becomes the program, so its own process ID is the program's.
        status.started(std::process::id());
        apply()?;
        Err(cannot_execute(target.exec()))
    }
}

/// Loads Seatbelt and compiles the profiles of `policy` (the program's, the relay's with exposed
/// or forwarded ports, and the watcher's with `end_with_parent`) without applying them. Neither
/// step changes the sandbox state of the process.
fn detect(policy: &ResolvedPolicy) -> HostCapabilities {
    let interpreter = policy.interpreter_problem(SHEBANG_LEVELS, &executable_paths(policy));
    let trusted_locations = crate::trust::locations();
    match Seatbelt::load() {
        Ok(seatbelt) => HostCapabilities {
            seatbelt: Ok(()),
            interpreter,
            trusted_locations,
            profile: seatbelt
                .compile(&generate(policy))
                .and_then(|()| {
                    let pairs = relay_pairs(policy);
                    if pairs.is_empty() {
                        return Ok(());
                    }
                    seatbelt
                        .compile(&relay_profile(&pairs))
                        .map_err(|message| format!("relay profile: {message}"))
                })
                .and_then(|()| {
                    if !policy.end_with_parent {
                        return Ok(());
                    }
                    seatbelt
                        .compile(&watcher_profile())
                        .map_err(|message| format!("watcher profile: {message}"))
                }),
            already_sandboxed: seatbelt.is_sandboxed(),
            rosetta: rosetta(policy),
        },
        Err(reason) => HostCapabilities {
            seatbelt: Err(reason),
            profile: Err("not compiled".to_string()),
            already_sandboxed: false,
            rosetta: rosetta(policy),
            interpreter,
            trusted_locations,
        },
    }
}

/// Applies the program's profile in a helper process, which ends right after. `check` compiles
/// the profile, but a profile that compiles can still be refused when it is applied, and sandy
/// must not apply it to itself: `check` has to leave its own process unsandboxed.
///
/// The helper only applies the profile and ends. It must not execute anything: only a `read_exec`
/// path grants `process-exec*`, so the profile would refuse that and the trial would report a
/// problem the run does not have.
///
/// A missing Seatbelt and a sandbox around sandy are reported by the plan, so the trial stays
/// silent about them.
fn applies_in_a_trial(policy: &ResolvedPolicy) -> Result<(), String> {
    let Ok(seatbelt) = Seatbelt::load() else {
        return Ok(());
    };
    if seatbelt.is_sandboxed() {
        return Ok(());
    }
    let profile = generate(policy);
    helper::start("the trial sandbox", &[], move |ready| {
        match seatbelt.apply(&profile) {
            Ok(()) => ready.report(),
            Err(message) => ready.fail(&message),
        }
    })
    .map(drop)
    .map_err(|error| error.to_string())
}

/// Why the program would run as x86_64 code through Rosetta, if it would. Rosetta loads its
/// runtime into every translated process, and the profile does not allow it, so the program would
/// abort at its start. A process that runs translated executes universal programs as x86_64 too.
fn rosetta(policy: &ResolvedPolicy) -> Option<String> {
    if sysctl_flag(c"sysctl.proc_translated") {
        return Some(
            "sandy runs as x86_64 code through Rosetta, which cannot load its runtime inside the \
             sandbox, so no program would start; use the arm64 build of sandy"
                .to_string(),
        );
    }
    if !sysctl_flag(c"hw.optional.arm64") {
        return None;
    }
    let program = policy.program.as_ref()?;
    // The kernel loads a script's interpreter, so that file decides, as it does for the
    // `read_exec` check (`SHEBANG_LEVELS`).
    let mut loaded = program.clone();
    let mut named_by = None;
    for _ in 0..SHEBANG_LEVELS {
        match sandy_core::shebang(&loaded) {
            Some(interpreter) => {
                named_by = Some(loaded);
                loaded = interpreter;
            }
            None => break,
        }
    }
    match binary::has_arm64_code(&header_of(&loaded)?) {
        Some(false) => Some(match named_by {
            Some(script) => format!(
                "{}, the interpreter of the script {}, has no arm64 code, so it would run \
                 through Rosetta, which cannot load its runtime inside the sandbox; use an \
                 arm64 or universal build of the interpreter",
                loaded.display(),
                script.display()
            ),
            None => format!(
                "{} has no arm64 code, so it would run through Rosetta, which cannot load its \
                 runtime inside the sandbox; use an arm64 or universal build of the program",
                loaded.display()
            ),
        }),
        _ => None,
    }
}

/// The beginning of `file`, as much as `binary::has_arm64_code` needs. A file that cannot be
/// read is left to the exec, which reports its own error. Only a regular file is read, the only
/// kind the kernel executes, and the open does not wait: without O_NONBLOCK, opening a named
/// pipe waits for a writer, and sandy would hang on a program path that names one.
fn header_of(file: &std::path::Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut header = Vec::with_capacity(binary::HEADER_SIZE);
    file.take(binary::HEADER_SIZE as u64)
        .read_to_end(&mut header)
        .ok()?;
    Some(header)
}

/// Whether the integer sysctl `name` is 1. A name this Mac does not know counts as 0.
fn sysctl_flag(name: &CStr) -> bool {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: name is a C string; value and size describe a buffer of size bytes; no new value.
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    result == 0 && value == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{
        EnvironmentPolicy, IpAccess, NetworkAccess, PathAccess, PathMetadata, PathRule,
        SignalScope, SystemAccess, WindowsPolicy,
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
            ip: IpAccess::None,
            unix_sockets: NetworkAccess::None,
            expose: Vec::new(),
            forward: Vec::new(),
            egress: None,
            view: sandy_core::FileView::All,
            signals: SignalScope::Any,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            windows: WindowsPolicy::default(),
        };
        let mut policies = Vec::new();
        for system in [SystemAccess::Minimal, SystemAccess::None] {
            for ip in [IpAccess::None, IpAccess::Client, IpAccess::All] {
                for unix_sockets in [NetworkAccess::None, NetworkAccess::All] {
                    for signals in [SignalScope::Any, SignalScope::Isolated] {
                        policies.push(ResolvedPolicy {
                            system,
                            ip,
                            unix_sockets,
                            signals,
                            children: sandy_core::ChildProcesses::Allowed,
                            end_with_parent: false,
                            ..base.clone()
                        });
                    }
                }
            }
        }
        policies.push(ResolvedPolicy {
            children: sandy_core::ChildProcesses::None,
            end_with_parent: false,
            ..base.clone()
        });
        policies.push(ResolvedPolicy {
            children: sandy_core::ChildProcesses::Contained,
            signals: SignalScope::Isolated,
            end_with_parent: true,
            ..base.clone()
        });
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
    fn this_macos_compiles_the_relay_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = relay_profile(&[
            crate::profile::RelayPair {
                listen: "127.0.0.1:18080".parse().unwrap(),
                target: "127.0.0.1:8080".parse().unwrap(),
            },
            crate::profile::RelayPair {
                listen: "[::1]:18081".parse().unwrap(),
                target: "[::1]:8081".parse().unwrap(),
            },
        ]);
        if let Err(message) = seatbelt.compile(&profile) {
            panic!("{message}\n{}", profile.text);
        }
    }

    #[test]
    fn this_macos_compiles_the_watcher_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = watcher_profile();
        if let Err(message) = seatbelt.compile(&profile) {
            panic!("{message}\n{}", profile.text);
        }
    }

    #[test]
    fn this_macos_rejects_an_invalid_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = crate::profile::Profile {
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

    /// A named pipe is no program. Reading its header must not wait for a writer that never
    /// comes, or check and run hang instead of reporting.
    #[test]
    fn a_named_pipe_has_no_header_and_does_not_block() {
        let dir = std::env::temp_dir().join(format!("sandy-macos-header-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Control: the header of a regular file.
        let program = dir.join("program");
        std::fs::write(&program, b"\xcf\xfa\xed\xfe").unwrap();
        assert_eq!(header_of(&program), Some(b"\xcf\xfa\xed\xfe".to_vec()));

        let pipe = dir.join("pipe");
        let path = std::ffi::CString::new(pipe.to_str().unwrap()).unwrap();
        // SAFETY: the path is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o700) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || send.send(header_of(&pipe)));
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result, Ok(None));
    }
}
