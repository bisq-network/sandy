//! The parts that call macOS: loading Seatbelt, applying the profile and replacing sandy with
//! the target.

mod broker;
mod contain;
mod exec;
mod helper;
mod holder;
mod interfaces;
mod relay;
mod seatbelt;
mod watch;

use sandy_core::{
    Backend, ChildProcesses, ParentProcess, PlanItem, Requirement, ResolvedPolicy, SandboxError,
    StatusReport, TargetCommand,
};

use std::ffi::CStr;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::binary;
use crate::detect::{Detected, Probes};
use crate::plan::{ProfileError, SHEBANG_LEVELS};
use crate::profile::{Profile, broker_holds, generate, relay_holds, relay_pairs};
use seatbelt::Seatbelt;

/// The tests that bind ports at every address of this Mac take this first: a port that one of
/// them chose as free can be the next one the kernel hands another of them for an address.
#[cfg(test)]
static BINDS: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
/// `docs/macos.md`). One value detects this Mac once (`Detected`), and its `run` applies the
/// profiles with the Seatbelt functions that its plans saw.
#[derive(Debug, Default)]
pub struct MacosBackend {
    host: Detected<ThisMac>,
}

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        self.host.plan(policy)
    }

    fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        self.host.notes(policy)
    }

    /// Every finding here is `Indeterminate`: any local user can hold a port at an address of
    /// this Mac, and any process of sandy's user can stop the trial's helper.
    fn verify(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let mut items = held_ports(policy);
        if let Err(reason) = self.applies_in_a_trial(policy) {
            items.extend(crate::plan::profile_indeterminate(policy, &reason));
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
        let seatbelt = self.host.seatbelt().map_err(SandboxError::new)?;
        // Before anything is forked, so that no process sandy starts keeps the ports either.
        exec::reset_exception_ports()?;
        let contained = policy.children == ChildProcesses::Contained;
        let pairs = relay_pairs(policy);
        // With `contained`, the relay and the broker also end when the guard has ended the
        // program's group, and the guard watches them in turn (see `contain::run`).
        let mut group_ended = None;
        let mut ended = None;
        if contained && (!pairs.is_empty() || policy.egress.is_some()) {
            let (read, write) = helper::pipe("the pipe of the group's end")?;
            group_ended = Some(write);
            ended = Some(read);
        }
        let ended_copy = || {
            ended
                .as_ref()
                .map(std::fs::File::try_clone)
                .transpose()
                .map_err(|error| SandboxError::io("cannot copy the pipe of the group's end", error))
        };
        let mut helpers = Vec::new();
        if !pairs.is_empty() {
            let pid = relay::start(&pairs, &relay_holds(policy), &seatbelt, ended_copy()?)?;
            helpers.push(contain::Helper {
                pid,
                name: "the relay of the exposed or forwarded ports",
            });
        }
        if let Some(egress) = policy.egress {
            let hold = broker_holds(policy);
            let pid = broker::start(egress, hold.as_ref(), &seatbelt, ended_copy()?)?;
            helpers.push(contain::Helper {
                pid,
                name: "the egress broker",
            });
        }
        drop(ended);
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
                helpers,
                status,
            );
        }
        // In the exec model sandy becomes the program, so its own process ID is the program's.
        status.started(std::process::id());
        apply()?;
        Err(cannot_execute(target.exec()))
    }
}

impl MacosBackend {
    pub fn new() -> MacosBackend {
        MacosBackend::default()
    }

    /// Applies the program's profile in a helper process, which ends right after. `check`
    /// compiles the profile, but a profile that compiles can still be refused when it is
    /// applied, and sandy must not apply it to itself: `check` has to leave its own process
    /// unsandboxed.
    ///
    /// The helper only applies the profile and ends. It must not execute anything: only a
    /// `read_exec` path grants `process-exec*`, so the profile would refuse that and the trial
    /// would report a problem the run does not have.
    ///
    /// A missing Seatbelt and a sandbox around sandy are reported by the plan, so the trial stays
    /// silent about them.
    fn applies_in_a_trial(&self, policy: &ResolvedPolicy) -> Result<(), String> {
        let Ok(seatbelt) = self.host.seatbelt() else {
            return Ok(());
        };
        if self.host.sandboxed(&seatbelt) {
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
}

/// The ports of the relay and the broker that another socket holds now, which would make `run`
/// fail. Each is `Indeterminate`: a port can be free a moment later, and any local user can take
/// one. The trial sockets close at once.
fn held_ports(policy: &ResolvedPolicy) -> Vec<PlanItem> {
    let mut items = sandy_core::verify::relay_listeners(policy);
    let holds = relay_holds(policy).into_iter().chain(broker_holds(policy));
    items.extend(holds.into_iter().find_map(|hold| {
        let error = holder::hold(hold.port, &hold.leave).err()?;
        Some(PlanItem::indeterminate(
            Requirement::IpNetworkPrivate,
            error.to_string(),
        ))
    }));
    if let Some(egress) = policy.egress {
        let listen = egress.listen();
        if let Err(error) = std::net::TcpListener::bind(listen) {
            items.push(PlanItem::indeterminate(
                Requirement::EgressBrokered,
                format!("cannot listen on {listen}: {error}"),
            ));
        }
    }
    items
}

/// The probes of this Mac. Neither changes the sandbox state of the process.
#[derive(Debug, Default)]
struct ThisMac;

impl Probes for ThisMac {
    type Seatbelt = Seatbelt;

    fn load(&self) -> Result<Seatbelt, String> {
        Seatbelt::load()
    }

    fn sandboxed(&self, seatbelt: &Seatbelt) -> bool {
        seatbelt.is_sandboxed()
    }

    fn compile(&self, seatbelt: &Seatbelt, profile: &Profile) -> Result<(), ProfileError> {
        seatbelt.compile(profile)
    }

    fn rosetta(&self, program: Option<&Path>) -> Option<String> {
        rosetta(program)
    }

    fn home_directories(&self) -> Result<Vec<PathBuf>, String> {
        sandy_core::trust::home_directories()
    }
}

/// Why the program would run as x86_64 code through Rosetta, if it would. Rosetta loads its
/// runtime into every translated process, and the profile does not allow it, so the program would
/// abort at its start. A process that runs translated executes universal programs as x86_64 too.
fn rosetta(program: Option<&Path>) -> Option<String> {
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
    // The kernel loads a script's interpreter, so that file decides, as it does for the
    // `read_exec` check (`SHEBANG_LEVELS`).
    let mut loaded = program?.to_path_buf();
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
            links: Vec::new(),
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
            macos: sandy_core::MacosPolicy::default(),
            windows: WindowsPolicy::default(),
        };
        let mut policies = Vec::new();
        for system in [SystemAccess::Minimal, SystemAccess::None] {
            for ip in [
                IpAccess::None,
                IpAccess::Private,
                IpAccess::Client,
                IpAccess::All,
            ] {
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
        // The relay and egress rules of a private network, and the view.
        policies.push(ResolvedPolicy {
            ip: IpAccess::Private,
            expose: vec![sandy_core::ExposedPort {
                listen: "127.0.0.1:18080".parse().unwrap(),
                port: 8080,
            }],
            forward: vec![
                sandy_core::ForwardedPort {
                    port: 18081,
                    to: "127.0.0.1:8081".parse().unwrap(),
                },
                sandy_core::ForwardedPort {
                    port: 18082,
                    to: "[::1]:8082".parse().unwrap(),
                },
            ],
            egress: Some(sandy_core::Egress {
                port: 1080,
                reach: sandy_core::EgressReach::Public,
            }),
            view: sandy_core::FileView::Policy,
            ..base.clone()
        });
        policies.push(ResolvedPolicy {
            ip: IpAccess::Private,
            forward: vec![sandy_core::ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap(),
            }],
            egress: Some(sandy_core::Egress {
                port: 1080,
                reach: sandy_core::EgressReach::Public,
            }),
            macos: sandy_core::MacosPolicy {
                relays: sandy_core::Relays::Ipv4,
                ..Default::default()
            },
            ..base.clone()
        });
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
            if let Err(error) = seatbelt.compile(&profile) {
                panic!("{error:?}\n{}", profile.text);
            }
        }
    }

    #[test]
    fn this_macos_compiles_the_relay_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = crate::profile::relay_profile(&[
            crate::profile::RelayPair {
                listen: "127.0.0.1:18080".parse().unwrap(),
                target: "127.0.0.1:8080".parse().unwrap(),
            },
            crate::profile::RelayPair {
                listen: "[::1]:18081".parse().unwrap(),
                target: "[::1]:8081".parse().unwrap(),
            },
        ]);
        if let Err(error) = seatbelt.compile(&profile) {
            panic!("{error:?}\n{}", profile.text);
        }
    }

    #[test]
    fn this_macos_compiles_the_watcher_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = crate::profile::watcher_profile();
        if let Err(error) = seatbelt.compile(&profile) {
            panic!("{error:?}\n{}", profile.text);
        }
    }

    #[test]
    fn this_macos_compiles_the_broker_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = crate::profile::broker_profile(1080);
        if let Err(error) = seatbelt.compile(&profile) {
            panic!("{error:?}\n{}", profile.text);
        }
    }

    /// Set in the child process of `the_broker_profile_keeps_this_mac_out_of_reach`: `deny` or
    /// `allow`, then the addresses to connect to, separated by commas.
    const BROKER_TRIAL: &str = "SANDY_BROKER_PROFILE_TRIAL";

    /// The broker's profile denies connections to `localhost`, every address of this Mac, after
    /// the allow of TCP out. Seatbelt's compiler drops some denials that follow a broad allow,
    /// depending on the rest of the profile (docs/macos.md, "The egress broker"), so this applies
    /// the real profile, in a child process of its own, and connects to listeners at 127.0.0.1,
    /// at ::1 and at this Mac's address on the local network: each is refused. The control is the
    /// same profile without the deny, which reaches each. The child also reads this Mac's addresses
    /// and routing table, which the destination check needs under the profile.
    #[test]
    fn the_broker_profile_keeps_this_mac_out_of_reach() {
        if let Ok(trial) = std::env::var(BROKER_TRIAL) {
            return broker_trial(&trial);
        }
        let _binds = BINDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut listeners = vec![
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            std::net::TcpListener::bind("[::1]:0").unwrap(),
        ];
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("192.0.2.1:9").is_ok() {
            let own = probe.local_addr().unwrap().ip();
            listeners.push(std::net::TcpListener::bind((own, 0)).unwrap());
        }
        let targets: Vec<String> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().to_string())
            .collect();
        for (mode, expected) in [("deny", "denied"), ("allow", "connected")] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::the_broker_profile_keeps_this_mac_out_of_reach",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(BROKER_TRIAL, format!("{mode},{}", targets.join(",")))
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{output:?}");
            for target in &targets {
                assert!(
                    stdout.contains(&format!("trial {target} {expected}")),
                    "{mode}: {stdout}"
                );
            }
            assert!(stdout.contains("trial addresses read"), "{mode}: {stdout}");
            assert!(stdout.contains("trial routes read"), "{mode}: {stdout}");
        }
    }

    fn broker_trial(trial: &str) {
        let mut fields = trial.split(',');
        let mode = fields.next().unwrap();
        let mut profile = crate::profile::broker_profile(1080);
        if mode == "allow" {
            profile.text = profile
                .text
                .replace(crate::profile::BROKER_LOCALHOST_DENY, "");
        }
        Seatbelt::load().unwrap().apply(&profile).unwrap();
        for target in fields {
            let address: std::net::SocketAddr = target.parse().unwrap();
            let result =
                std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(3));
            let outcome = match result {
                Ok(_) => "connected",
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => "denied",
                Err(_) => "failed",
            };
            println!("trial {target} {outcome}");
        }
        if interfaces::addresses().is_ok_and(|all| !all.is_empty()) {
            println!("trial addresses read");
        }
        if interfaces::routing_table().is_ok_and(|table| !table.is_empty()) {
            println!("trial routes read");
        }
    }

    #[test]
    fn this_macos_rejects_an_invalid_profile() {
        let seatbelt = Seatbelt::load().expect("Seatbelt functions");
        let profile = crate::profile::Profile {
            text: "(version 1)\n(deny default)\n(allow no-such-operation)\n".to_string(),
            parameters: Vec::new(),
        };
        assert!(
            matches!(seatbelt.compile(&profile), Err(ProfileError::Rejected(_))),
            "a compiler message is a shortfall of this macOS"
        );
    }

    /// `verify` decides no level: the egress port that another socket holds, at the broker's
    /// own address or at another address of this Mac, is indeterminate. Control: the free port
    /// is reported by nothing.
    #[test]
    fn a_held_port_is_indeterminate() {
        let _binds = BINDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut policy = policies().remove(0);
        policy.ip = sandy_core::IpAccess::Private;
        policy.signals = sandy_core::SignalScope::Isolated;
        for address in ["127.0.0.1", "0.0.0.0"] {
            let held = std::net::TcpListener::bind((address, 0)).unwrap();
            policy.egress = Some(sandy_core::Egress {
                port: held.local_addr().unwrap().port(),
                reach: sandy_core::EgressReach::Public,
            });
            let items = held_ports(&policy);
            assert!(!items.is_empty(), "{address}");
            for item in &items {
                assert!(
                    matches!(item.status, sandy_core::Status::Indeterminate { .. }),
                    "{address}: {item:?}"
                );
            }
            drop(held);
            assert_eq!(held_ports(&policy), Vec::new(), "{address}");
        }
    }

    #[test]
    fn plan_is_enforceable_here() {
        let policy = policies().remove(0);
        let plan = sandy_core::EnforcementPlan::new(
            &policy.requirements(),
            MacosBackend::new().plan(&policy),
        );
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
