//! One detection of the host per backend value (the `Backend` contract): a property of the host
//! is probed when a plan first needs it and kept, so every level that one invocation plans, the
//! notes of the selected one and its run see the same host. What depends on the policy, such as
//! the SID of its AppContainer name and whether that SID is exempt from loopback isolation, is
//! computed for each policy from the kept answers.

use std::cell::{OnceCell, RefCell};
use std::fmt;
use std::path::{Path, PathBuf};

use sandy_core::{PathAccess, PlanItem, ResolvedPolicy};

use crate::plan::{Host, Problem, plan_for};
use crate::version::WindowsVersion;

/// The probes of the host. `sys` answers them with the Windows API, the tests with fakes. Each
/// answer is `Err` with the class of its problem (`crate::probe`).
pub trait Probes {
    /// The SID that Windows derives from an AppContainer name.
    type Sid: PartialEq;
    /// sandy's own executable as the relays need it: its path and what decides the grants.
    type Relay;
    /// The locations of this host that a writable path must not reach.
    type Layout;

    // Properties of the host. `Detection` asks for each at most once.
    fn windows_version(&self) -> Result<WindowsVersion, Problem>;
    fn capability_sids(&self) -> Result<(), Problem>;
    fn outer_job_ui(&self) -> Result<Option<u32>, Problem>;
    fn firewall(&self) -> Result<(), Problem>;
    /// The SIDs of the AppContainers exempt from loopback isolation.
    fn loopback_exemptions(&self) -> Result<Vec<Self::Sid>, Problem>;
    fn forward_sockets(&self) -> Result<(), Problem>;
    fn relay(&self) -> Result<Self::Relay, Problem>;
    fn layout(&self) -> Result<Self::Layout, Problem>;

    // What a policy needs from them.
    fn appcontainer_sid(&self, name: &str) -> Result<Self::Sid, Problem>;
    fn relay_path<'relay>(&self, relay: &'relay Self::Relay) -> &'relay Path;
    /// Whether sandy may let the AppContainer `name` run the relay program.
    fn relay_grantable(&self, relay: &Self::Relay, name: &str) -> Result<(), Problem>;
    /// `Host::writable_paths` for a policy with a writable path, whose AppContainer is
    /// `container`.
    fn writable_paths(
        &self,
        layout: &Self::Layout,
        policy: &ResolvedPolicy,
        container: &Self::Sid,
    ) -> Result<(), Problem>;
    /// `Host::grants` for the AppContainer `name`.
    fn grants(&self, name: &str, policy: &ResolvedPolicy) -> Result<(), Problem>;
}

/// The host as one backend value sees it: each property probed on first use and kept, and the
/// plan of each policy kept too, so that `run` checks the plan of the level it runs without
/// probing again.
pub struct Detection<P: Probes> {
    probes: P,
    windows: OnceCell<Result<WindowsVersion, Problem>>,
    capability_sids: OnceCell<Result<(), Problem>>,
    outer_job_ui: OnceCell<Result<Option<u32>, Problem>>,
    firewall: OnceCell<Result<(), Problem>>,
    exemptions: OnceCell<Result<Vec<P::Sid>, Problem>>,
    forward_sockets: OnceCell<Result<(), Problem>>,
    relay: OnceCell<Result<P::Relay, Problem>>,
    layout: OnceCell<Result<P::Layout, Problem>>,
    plans: RefCell<Vec<(ResolvedPolicy, Vec<PlanItem>)>>,
}

impl<P: Probes> Detection<P> {
    pub fn new(probes: P) -> Self {
        Detection {
            probes,
            windows: OnceCell::new(),
            capability_sids: OnceCell::new(),
            outer_job_ui: OnceCell::new(),
            firewall: OnceCell::new(),
            exemptions: OnceCell::new(),
            forward_sockets: OnceCell::new(),
            relay: OnceCell::new(),
            layout: OnceCell::new(),
            plans: RefCell::new(Vec::new()),
        }
    }

    /// The plan of `policy` on this host, the same one for every call with an equal policy.
    pub fn plan(&self, policy: &ResolvedPolicy) -> Vec<PlanItem> {
        let planned = self.plans.borrow();
        if let Some((_, items)) = planned.iter().find(|(planned, _)| planned == policy) {
            return items.clone();
        }
        drop(planned);
        let items = plan_for(
            policy,
            &ForPolicy {
                detection: self,
                policy,
            },
        );
        self.plans
            .borrow_mut()
            .push((policy.clone(), items.clone()));
        items
    }

    /// The UI restrictions of the job sandy runs in, for the trial of `verify`.
    pub fn outer_job_ui(&self) -> &Result<Option<u32>, Problem> {
        self.outer_job_ui.get_or_init(|| self.probes.outer_job_ui())
    }

    /// sandy's own executable for the relays, for `run`.
    pub fn relay(&self) -> &Result<P::Relay, Problem> {
        self.relay.get_or_init(|| self.probes.relay())
    }

    #[cfg(test)]
    fn probes(&self) -> &P {
        &self.probes
    }

    fn exemptions(&self) -> Result<&[P::Sid], Problem> {
        self.exemptions
            .get_or_init(|| self.probes.loopback_exemptions())
            .as_deref()
            .map_err(Clone::clone)
    }
}

/// The kept answers hold SIDs and handles that have no `Debug` of their own.
impl<P: Probes> fmt::Debug for Detection<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Detection")
            .field("plans", &self.plans.borrow().len())
            .finish_non_exhaustive()
    }
}

/// The host for one policy: the kept answers of `detection` and what follows from them for
/// `policy`.
struct ForPolicy<'a, P: Probes> {
    detection: &'a Detection<P>,
    policy: &'a ResolvedPolicy,
}

impl<'a, P: Probes> ForPolicy<'a, P> {
    /// `plan_for` asks for an AppContainer only once it has the policy's valid name.
    fn name(&self) -> Result<&str, Problem> {
        self.policy
            .windows
            .appcontainer_name
            .as_deref()
            .ok_or_else(|| Problem::Conflict("the policy names no AppContainer".into()))
    }

    fn sid(&self) -> Result<P::Sid, Problem> {
        self.detection.probes.appcontainer_sid(self.name()?)
    }

    fn exempt(&self, sid: &P::Sid) -> Result<bool, Problem> {
        Ok(self.detection.exemptions()?.contains(sid))
    }

    /// The egress broker's AppContainer name; `None` without egress, and for a name with no room
    /// for the broker's suffix, which the plan reports itself.
    fn broker(&self) -> Option<String> {
        self.policy.egress?;
        crate::name::egress_broker_name(self.name().ok()?).ok()
    }

    fn relay(&self) -> Result<&'a P::Relay, Problem> {
        self.detection.relay().as_ref().map_err(Clone::clone)
    }
}

impl<P: Probes> Host for ForPolicy<'_, P> {
    fn appcontainer(&self) -> Result<(), Problem> {
        self.sid().map(|_| ())
    }

    fn windows(&self) -> Result<WindowsVersion, Problem> {
        let detection = self.detection;
        detection
            .windows
            .get_or_init(|| detection.probes.windows_version())
            .clone()
    }

    fn capability_sids(&self) -> Result<(), Problem> {
        let detection = self.detection;
        detection
            .capability_sids
            .get_or_init(|| detection.probes.capability_sids())
            .clone()
    }

    fn writable_paths(&self) -> Result<(), Problem> {
        let writable = self
            .policy
            .paths
            .iter()
            .any(|rule| rule.access == PathAccess::ReadWrite);
        if !writable {
            return Ok(());
        }
        let detection = self.detection;
        let layout = detection
            .layout
            .get_or_init(|| detection.probes.layout())
            .as_ref()
            .map_err(Clone::clone)?;
        detection
            .probes
            .writable_paths(layout, self.policy, &self.sid()?)
    }

    fn grants(&self) -> Result<(), Problem> {
        self.detection.probes.grants(self.name()?, self.policy)
    }

    fn outer_job_ui(&self) -> Result<Option<u32>, Problem> {
        self.detection.outer_job_ui().clone()
    }

    fn firewall(&self) -> Result<(), Problem> {
        let detection = self.detection;
        detection
            .firewall
            .get_or_init(|| detection.probes.firewall())
            .clone()
    }

    fn loopback_exempt(&self) -> Result<bool, Problem> {
        self.exempt(&self.sid()?)
    }

    fn broker_loopback_exempt(&self) -> Result<bool, Problem> {
        match self.broker() {
            Some(broker) => self.exempt(&self.detection.probes.appcontainer_sid(&broker)?),
            None => Ok(false),
        }
    }

    fn relay_program(&self) -> Result<PathBuf, Problem> {
        Ok(self
            .detection
            .probes
            .relay_path(self.relay()?)
            .to_path_buf())
    }

    fn relay_grants(&self) -> Result<(), Problem> {
        let relay = self.relay()?;
        let probes = &self.detection.probes;
        probes.relay_grantable(relay, self.name()?)?;
        match self.broker() {
            Some(broker) => probes.relay_grantable(relay, &broker),
            None => Ok(()),
        }
    }

    fn forward_sockets(&self) -> Result<(), Problem> {
        let detection = self.detection;
        detection
            .forward_sockets
            .get_or_init(|| detection.probes.forward_sockets())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use sandy_core::{
        EgressReach, ExposedPort, ForwardedPort, IpAccess, PathRule, Policy, Requirement, Status,
        WindowsPolicy,
    };

    use super::*;

    /// Answers every probe as a host that enforces everything, except that the AppContainers
    /// named in `exempt` are exempt from loopback isolation, and records each call.
    #[derive(Default)]
    struct Fake {
        exempt: Vec<String>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Fake {
        fn called(&self, probe: &'static str) {
            self.calls.borrow_mut().push(probe);
        }

        fn count(&self, probe: &str) -> usize {
            self.calls.borrow().iter().filter(|c| **c == probe).count()
        }
    }

    /// The probes of host properties, which a detection asks for at most once.
    const HOST_PROBES: [&str; 8] = [
        "windows_version",
        "capability_sids",
        "outer_job_ui",
        "firewall",
        "loopback_exemptions",
        "forward_sockets",
        "relay",
        "layout",
    ];

    impl Probes for Fake {
        // Windows derives an AppContainer SID from the name without regard to case.
        type Sid = String;
        type Relay = PathBuf;
        type Layout = ();

        fn windows_version(&self) -> Result<WindowsVersion, Problem> {
            self.called("windows_version");
            Ok(WindowsVersion {
                build: 26200,
                revision: Ok(7000),
            })
        }
        fn capability_sids(&self) -> Result<(), Problem> {
            self.called("capability_sids");
            Ok(())
        }
        fn outer_job_ui(&self) -> Result<Option<u32>, Problem> {
            self.called("outer_job_ui");
            Ok(None)
        }
        fn firewall(&self) -> Result<(), Problem> {
            self.called("firewall");
            Ok(())
        }
        fn loopback_exemptions(&self) -> Result<Vec<String>, Problem> {
            self.called("loopback_exemptions");
            Ok(self.exempt.iter().map(|name| name.to_lowercase()).collect())
        }
        fn forward_sockets(&self) -> Result<(), Problem> {
            self.called("forward_sockets");
            Ok(())
        }
        fn relay(&self) -> Result<PathBuf, Problem> {
            self.called("relay");
            Ok(PathBuf::from("sandy.exe"))
        }
        fn layout(&self) -> Result<(), Problem> {
            self.called("layout");
            Ok(())
        }
        fn appcontainer_sid(&self, name: &str) -> Result<String, Problem> {
            Ok(name.to_lowercase())
        }
        fn relay_path<'relay>(&self, relay: &'relay PathBuf) -> &'relay Path {
            relay
        }
        fn relay_grantable(&self, _: &PathBuf, _: &str) -> Result<(), Problem> {
            self.called("relay_grantable");
            Ok(())
        }
        fn writable_paths(&self, _: &(), _: &ResolvedPolicy, _: &String) -> Result<(), Problem> {
            self.called("writable_paths");
            Ok(())
        }
        fn grants(&self, _: &str, _: &ResolvedPolicy) -> Result<(), Problem> {
            self.called("grants");
            Ok(())
        }
    }

    /// A policy that needs every probe: a private network with egress, an exposed and a
    /// forwarded port, and a writable path.
    fn needing_everything(name: &str) -> ResolvedPolicy {
        let mut policy = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        policy.windows = WindowsPolicy {
            appcontainer_name: Some(name.into()),
            ..WindowsPolicy::default()
        };
        policy.ip = IpAccess::Private;
        policy.egress = Some(sandy_core::Egress {
            port: 1080,
            reach: EgressReach::Public,
        });
        policy.expose = vec![ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        policy.forward = vec![ForwardedPort {
            port: 18081,
            to: "127.0.0.1:8081".parse().unwrap(),
        }];
        policy.paths.push(PathRule {
            path: PathBuf::from(r"C:\data"),
            access: PathAccess::ReadWrite,
            is_dir: true,
        });
        policy
    }

    fn status(items: &[PlanItem], requirement: Requirement) -> &Status {
        &items
            .iter()
            .find(|item| item.requirement == requirement)
            .expect("reported")
            .status
    }

    /// Two levels with AppContainer names of their own see one host: every property is probed
    /// once, and what depends on the name is computed for each from the kept answers. Here only
    /// the second name is exempt, read from the one exemption list.
    #[test]
    fn a_second_plan_of_a_policy_with_another_name_reuses_the_host_answers() {
        let detection = Detection::new(Fake {
            exempt: vec!["Second.Level".into()],
            ..Fake::default()
        });
        let first = detection.plan(&needing_everything("first.level"));
        let second = detection.plan(&needing_everything("second.level"));
        for probe in HOST_PROBES {
            assert_eq!(detection.probes().count(probe), 1, "{probe}");
        }
        assert!(first.iter().all(PlanItem::is_enforced), "{first:?}");
        assert!(matches!(
            status(&second, Requirement::IpNetworkPrivate),
            Status::NeedsSetup { reason } if reason.contains("second.level")
        ));
        // The paths, the grants and the relay grants of each name are its own.
        for probe in ["writable_paths", "grants"] {
            assert_eq!(detection.probes().count(probe), 2, "{probe}");
        }
    }

    /// A policy planned again is not probed again, so `run`, which checks the plan of the level
    /// it runs, sees the answers the selection saw.
    #[test]
    fn a_policy_planned_again_gets_the_same_plan_without_a_probe() {
        let detection = Detection::new(Fake::default());
        let policy = needing_everything("a.level");
        let first = detection.plan(&policy);
        let calls = detection.probes().calls.borrow().len();
        assert_eq!(detection.plan(&policy), first);
        assert_eq!(detection.probes().calls.borrow().len(), calls);
        // Control: another policy is planned on its own.
        detection.plan(&needing_everything("another.level"));
        assert!(detection.probes().calls.borrow().len() > calls);
    }

    /// A probe runs only for a policy that needs it, so the plan of a level runs no probe that
    /// only another level needs.
    #[test]
    fn a_plan_probes_only_what_its_policy_needs() {
        let detection = Detection::new(Fake::default());
        let mut policy = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        policy.windows.appcontainer_name = Some("all.level".into());
        policy.ip = IpAccess::All;
        let items = detection.plan(&policy);
        assert!(items.iter().all(PlanItem::is_enforced), "{items:?}");
        let mut calls = detection.probes().calls.borrow().clone();
        calls.sort();
        assert_eq!(
            calls,
            [
                "capability_sids",
                "grants",
                "outer_job_ui",
                "windows_version"
            ]
        );

        // Without an AppContainer name the plan is a conflict, which needs no probe at all.
        let detection = Detection::new(Fake::default());
        policy.windows.appcontainer_name = None;
        let items = detection.plan(&policy);
        assert!(
            items
                .iter()
                .any(|item| matches!(item.status, Status::Conflict { .. }))
        );
        assert!(detection.probes().calls.borrow().is_empty());
    }
}
