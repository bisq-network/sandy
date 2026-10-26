//! What this Mac offers, each answer detected at most once per backend value (`Detected`). Every
//! level that one invocation plans, the notes of the selected one and its run see the same
//! answers, so a probe that fails for a moment cannot make one level look unavailable and the
//! next one not. The probes sit behind a trait, so this is pure and is tested on every platform.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

use sandy_core::{PlanItem, ResolvedPolicy};

use crate::plan::{self, HostCapabilities, ProfileError, SHEBANG_LEVELS, executable_paths};
use crate::profile::{
    Profile, broker_profile, generate, relay_pairs, relay_profile, watcher_profile,
};
use crate::trust;

/// What detection reads from the host, so a test can describe any host and count the reads.
pub trait Probes {
    /// The loaded Seatbelt functions, which `run` applies the profiles with.
    type Seatbelt: Copy + Debug;

    /// Loads the Seatbelt functions, or says which one this macOS lacks.
    fn load(&self) -> Result<Self::Seatbelt, String>;
    /// Whether sandy already runs in a Seatbelt sandbox.
    fn sandboxed(&self, seatbelt: &Self::Seatbelt) -> bool;
    /// Compiles `profile` without applying it.
    fn compile(&self, seatbelt: &Self::Seatbelt, profile: &Profile) -> Result<(), ProfileError>;
    /// Why `program` would run as x86_64 code through Rosetta, if it would
    /// (`HostCapabilities::rosetta`).
    fn rosetta(&self, program: Option<&Path>) -> Option<String>;
    /// The home directories of this user (`sandy_core::trust::home_directories`).
    fn home_directories(&self) -> Result<Vec<PathBuf>, String>;
}

/// The answers of `Probes`, each read on first use and kept. Only the profiles are compiled for
/// every plan, because their text differs per level.
#[derive(Debug)]
pub struct Detected<P: Probes> {
    probes: P,
    seatbelt: OnceCell<Result<P::Seatbelt, String>>,
    sandboxed: OnceCell<bool>,
    /// Per program, although every level of one invocation has the same one.
    rosetta: RefCell<HashMap<Option<PathBuf>, Option<String>>>,
    homes: OnceCell<Result<Vec<PathBuf>, String>>,
}

impl<P: Probes + Default> Default for Detected<P> {
    fn default() -> Self {
        Detected::new(P::default())
    }
}

impl<P: Probes> Detected<P> {
    pub fn new(probes: P) -> Self {
        Detected {
            probes,
            seatbelt: OnceCell::new(),
            sandboxed: OnceCell::new(),
            rosetta: RefCell::new(HashMap::new()),
            homes: OnceCell::new(),
        }
    }

    /// The Seatbelt functions, or why this macOS lacks them.
    pub fn seatbelt(&self) -> Result<P::Seatbelt, String> {
        self.seatbelt.get_or_init(|| self.probes.load()).clone()
    }

    /// Whether sandy already runs in a Seatbelt sandbox, which only the loaded functions tell.
    pub fn sandboxed(&self, seatbelt: &P::Seatbelt) -> bool {
        *self
            .sandboxed
            .get_or_init(|| self.probes.sandboxed(seatbelt))
    }

    pub fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        plan::plan_for(policy, &self.capabilities(policy))
    }

    pub fn notes(&self, policy: &ResolvedPolicy) -> Vec<String> {
        let homes = self.homes().as_deref().unwrap_or_default();
        plan::notes(policy, &trust::path_locations(homes))
    }

    /// What this host offers for `policy`.
    fn capabilities(&self, policy: &ResolvedPolicy) -> HostCapabilities {
        let seatbelt = self.seatbelt();
        let (already_sandboxed, profile) = match &seatbelt {
            Ok(seatbelt) => (self.sandboxed(seatbelt), self.compile(seatbelt, policy)),
            Err(_) => (
                false,
                Err(ProfileError::Failed(
                    "not compiled without the Seatbelt functions".to_string(),
                )),
            ),
        };
        HostCapabilities {
            seatbelt: seatbelt.map(drop),
            profile,
            already_sandboxed,
            rosetta: self.rosetta(policy.program.as_deref()),
            // Read for every plan, against the level's `read_exec` paths. It can only be a
            // conflict, which ends the selection whatever the next level would say.
            interpreter: policy.interpreter_problem(SHEBANG_LEVELS, &executable_paths(policy)),
            trusted_locations: self
                .homes()
                .as_ref()
                .map(|homes| trust::locations(homes))
                .map_err(Clone::clone),
        }
    }

    /// Compiles the profiles of `policy`: the program's, and the relay's with exposed or forwarded
    /// ports, the egress broker's and the watcher's with `end_with_parent`. Neither changes the
    /// sandbox state of the process.
    fn compile(&self, seatbelt: &P::Seatbelt, policy: &ResolvedPolicy) -> Result<(), ProfileError> {
        self.probes.compile(seatbelt, &generate(policy))?;
        let pairs = relay_pairs(policy);
        let mut helpers = Vec::new();
        if !pairs.is_empty() {
            helpers.push(("relay profile", relay_profile(&pairs)));
        }
        if let Some(egress) = policy.egress {
            helpers.push(("egress broker profile", broker_profile(egress.port)));
        }
        if policy.end_with_parent {
            helpers.push(("watcher profile", watcher_profile()));
        }
        for (name, profile) in helpers {
            self.probes
                .compile(seatbelt, &profile)
                .map_err(|error| error.of(name))?;
        }
        Ok(())
    }

    fn rosetta(&self, program: Option<&Path>) -> Option<String> {
        self.rosetta
            .borrow_mut()
            .entry(program.map(Path::to_path_buf))
            .or_insert_with(|| self.probes.rosetta(program))
            .clone()
    }

    fn homes(&self) -> &Result<Vec<PathBuf>, String> {
        self.homes.get_or_init(|| self.probes.home_directories())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{
        EnforcementPlan, EnvironmentPolicy, IpAccess, NetworkAccess, PathAccess, PathMetadata,
        PathRule, Requirement, SignalScope, Status, SystemAccess, WindowsPolicy,
    };

    /// A Mac on which every probe gives the answer set here. It records what detection read.
    #[derive(Debug)]
    struct Fake {
        seatbelt: Result<(), String>,
        compile: Result<(), ProfileError>,
        homes: Result<Vec<PathBuf>, String>,
        read: RefCell<Vec<String>>,
    }

    impl Fake {
        fn capable() -> Fake {
            Fake {
                seatbelt: Ok(()),
                compile: Ok(()),
                homes: Ok(vec![PathBuf::from("/Users/someone")]),
                read: RefCell::new(Vec::new()),
            }
        }

        fn reads(&self, what: &str) -> usize {
            self.read
                .borrow()
                .iter()
                .filter(|read| *read == what)
                .count()
        }
    }

    impl Probes for Fake {
        type Seatbelt = ();

        fn load(&self) -> Result<(), String> {
            self.read.borrow_mut().push("load".to_string());
            self.seatbelt.clone()
        }
        fn sandboxed(&self, _: &()) -> bool {
            self.read.borrow_mut().push("sandboxed".to_string());
            false
        }
        fn compile(&self, _: &(), _: &Profile) -> Result<(), ProfileError> {
            self.read.borrow_mut().push("compile".to_string());
            self.compile.clone()
        }
        fn rosetta(&self, program: Option<&Path>) -> Option<String> {
            self.read.borrow_mut().push(format!(
                "rosetta {}",
                program.unwrap_or(Path::new("-")).display()
            ));
            None
        }
        fn home_directories(&self) -> Result<Vec<PathBuf>, String> {
            self.read.borrow_mut().push("homes".to_string());
            self.homes.clone()
        }
    }

    /// A level with a writable path, so the trusted locations count, and the program `/bin/ls`.
    fn base() -> ResolvedPolicy {
        ResolvedPolicy {
            paths: vec![PathRule {
                path: PathBuf::from("/Users/someone/work"),
                access: PathAccess::ReadWrite,
                is_dir: true,
            }],
            program: Some(PathBuf::from("/bin/ls")),
            links: Vec::new(),
            system: SystemAccess::Minimal,
            ip: IpAccess::None,
            unix_sockets: NetworkAccess::None,
            expose: Vec::new(),
            forward: Vec::new(),
            egress: None,
            view: sandy_core::FileView::All,
            signals: SignalScope::Isolated,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            macos: sandy_core::MacosPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }

    /// The same paths and program with other hardening keys, as a fallback level has: a private
    /// network with a relay and a broker, and a watcher.
    fn fallback() -> ResolvedPolicy {
        ResolvedPolicy {
            ip: IpAccess::Private,
            forward: vec![sandy_core::ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap(),
            }],
            egress: Some(sandy_core::Egress {
                port: 1080,
                reach: sandy_core::EgressReach::Public,
            }),
            end_with_parent: true,
            ..base()
        }
    }

    fn enforceable(detected: &Detected<Fake>, policy: &ResolvedPolicy) -> bool {
        EnforcementPlan::new(&policy.requirements(), detected.plan(policy)).is_enforceable()
    }

    /// Each host property is read once, on the first plan; the second plan, of another level,
    /// the notes and the Seatbelt functions that `run` takes reuse the answers. Only the profiles
    /// are compiled again, because their text is the level's: one for the base, the program's,
    /// relay's, broker's and watcher's for the fallback.
    #[test]
    fn a_second_plan_reuses_the_answers() {
        let detected = Detected::new(Fake::capable());
        assert!(enforceable(&detected, &base()));
        assert!(enforceable(&detected, &fallback()));
        assert!(detected.notes(&fallback()).len() > 1);
        assert_eq!(detected.seatbelt(), Ok(()));
        let host = &detected.probes;
        for read in ["load", "sandboxed", "rosetta /bin/ls", "homes"] {
            assert_eq!(host.reads(read), 1, "{read}: {:?}", host.read);
        }
        assert_eq!(host.reads("compile"), 1 + 4, "{:?}", host.read);
    }

    /// A program of its own is a program of its own: the Rosetta check reads it.
    #[test]
    fn another_program_is_checked_for_rosetta_on_its_own() {
        let detected = Detected::new(Fake::capable());
        detected.plan(&base());
        let other = ResolvedPolicy {
            program: Some(PathBuf::from("/bin/cat")),
            ..base()
        };
        detected.plan(&other);
        detected.plan(&base());
        let host = &detected.probes;
        assert_eq!(host.reads("rosetta /bin/ls"), 1, "{:?}", host.read);
        assert_eq!(host.reads("rosetta /bin/cat"), 1, "{:?}", host.read);
    }

    /// Without the Seatbelt functions nothing that needs them is probed, also not on the next
    /// plan, and the plan names the missing function as a shortfall of this macOS.
    #[test]
    fn without_seatbelt_nothing_that_needs_it_is_probed() {
        let detected = Detected::new(Fake {
            seatbelt: Err("dlsym(sandbox_compile_string): symbol not found".to_string()),
            ..Fake::capable()
        });
        let items = detected.plan(&base());
        detected.plan(&fallback());
        let host = &detected.probes;
        assert_eq!(host.reads("load"), 1, "{:?}", host.read);
        assert_eq!(host.reads("sandboxed") + host.reads("compile"), 0);
        let confined = items
            .iter()
            .find(|item| item.requirement == Requirement::ProcessMemoryIsolated)
            .unwrap();
        assert!(
            matches!(&confined.status, Status::Unavailable { reason } if reason.contains("sandbox_compile_string")),
            "{confined:?}"
        );
    }

    /// A compile without a verdict says nothing about this macOS, while the compiler's message
    /// does; a helper's profile is named in either.
    #[test]
    fn a_compile_without_a_verdict_is_indeterminate() {
        let status_of = |error: ProfileError, policy: &ResolvedPolicy| {
            let detected = Detected::new(Fake {
                compile: Err(error),
                ..Fake::capable()
            });
            detected
                .plan(policy)
                .into_iter()
                .find(|item| item.requirement == Requirement::ProcessMemoryIsolated)
                .unwrap()
                .status
        };
        let failed = ProfileError::Failed("sandbox_create_params failed".to_string());
        assert_eq!(
            status_of(failed, &base()),
            Status::Indeterminate {
                reason: "cannot compile the generated Seatbelt profile: sandbox_create_params \
                         failed"
                    .to_string()
            }
        );
        let rejected = ProfileError::Rejected("unbound variable: x".to_string());
        assert_eq!(
            status_of(rejected, &base()),
            Status::Unavailable {
                reason: "this macOS rejects the generated Seatbelt profile: unbound variable: x"
                    .to_string()
            }
        );
        assert_eq!(
            ProfileError::Failed("sandbox_set_param(PATH_0) failed".to_string())
                .of("relay profile"),
            ProfileError::Failed("relay profile: sandbox_set_param(PATH_0) failed".to_string())
        );
    }

    /// A password database that cannot be read now makes a level with a writable path
    /// indeterminate, not unavailable: a weaker level must not run for it.
    #[test]
    fn a_failed_home_lookup_is_indeterminate() {
        let reason = "cannot read the password database entry of this user: Input/output error";
        let detected = Detected::new(Fake {
            homes: Err(reason.to_string()),
            ..Fake::capable()
        });
        let policy = base();
        let plan = EnforcementPlan::new(&policy.requirements(), detected.plan(&policy));
        let reports: Vec<_> = plan.final_reports().collect();
        assert_eq!(reports.len(), 1, "{plan}");
        assert_eq!(reports[0].requirement, Requirement::FilesystemConfined);
        assert_eq!(
            reports[0].status,
            Status::Indeterminate {
                reason: reason.to_string()
            }
        );
        // Without a writable path no trusted location can be reached.
        let read_only = ResolvedPolicy {
            paths: Vec::new(),
            ..base()
        };
        assert!(enforceable(&detected, &read_only));
    }
}
