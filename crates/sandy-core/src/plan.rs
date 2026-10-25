use std::fmt;

/// A guarantee sandy gives about the target. `ResolvedPolicy::requirements` lists the ones a
/// policy needs; a backend reports how it enforces each one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Requirement {
    /// Files and directories outside the policy paths (and the system set) cannot be read,
    /// written or executed.
    FilesystemConfined,
    /// The target cannot gain privileges, for example through setuid programs or file
    /// capabilities.
    NoPrivilegeEscalation,
    /// The target cannot debug, read or write the memory of processes outside the sandbox.
    ProcessMemoryIsolated,
    /// The target inherits no open files, sockets or handles except standard input, output and
    /// error.
    InheritedHandlesClosed,
    /// The target environment contains only the variables the policy allows.
    EnvironmentControlled,
    /// IPv4 and IPv6 networking is denied, including loopback.
    IpNetworkDenied,
    /// The target reaches IPv4 and IPv6 addresses only inside its sandbox, on a loopback of its
    /// own: not the host's loopback services, not the host's other addresses, not the local
    /// network and not the internet, also not with datagrams. The exposed, forwarded and egress
    /// relays are the only ways in and out.
    IpNetworkPrivate,
    /// Connections out leave only through the egress broker, which connects only to the
    /// destinations of the policy's `reach` and never to the host itself.
    EgressBrokered,
    /// Paths outside the policy paths and the system set look missing to the target.
    PathsHidden,
    /// The target can connect out over IPv4 and IPv6, loopback included, but cannot listen for
    /// TCP connections or accept one, so no other process can connect to it. A datagram socket
    /// that is not connected still receives from every sender on Linux and macOS (DESIGN.md,
    /// the exceptions table).
    InboundIpDenied,
    /// The target cannot connect to Unix domain sockets outside the paths it may write, so it
    /// cannot reach local services (session bus, service managers, resolvers). This is a lower
    /// bound: Linux and macOS deny Unix sockets completely; Windows, where access to a socket
    /// follows the file's access control list, allows the sockets in the read_write paths and
    /// in the target's private AppContainer folder.
    UnixSocketsDenied,
    /// Signals cannot reach processes outside the sandbox.
    SignalsIsolated,
    /// Permissions, owner, timestamps and extended attributes of files outside the policy paths
    /// cannot be changed.
    MetadataConfined,
    /// Every exposed port is relayed from outside the sandbox to the target's loopback port, and
    /// the relay ends with the target. This is a promise of function, not a restriction; a
    /// backend without a relay must refuse rather than start a server nobody can reach.
    ExposedPortsRelayed,
    /// Every forwarded port is relayed from inside the sandbox to its loopback service outside,
    /// and the relay ends with the target. Like `ExposedPortsRelayed`, a promise of function.
    ForwardedPortsRelayed,
    /// The target cannot create child processes (threads stay allowed).
    ChildProcessesDenied,
    /// Every process the target starts, directly or through its children, ends when the target
    /// ends, and also when sandy itself is killed. The target cannot move a process out of reach.
    ChildProcessesContained,
    /// When the process that started sandy ends, the target ends too: it gets a request to end
    /// and, if it has not ended after a grace period, is killed. The target cannot keep this from
    /// happening; the policy also requires isolated signals for that.
    EndsWithParent,
    /// The target cannot make the system calls of win32k, the GUI part of the Windows kernel.
    /// Platforms without win32k give this without a mechanism.
    Win32kDenied,
}

impl Requirement {
    pub fn description(self) -> &'static str {
        match self {
            Requirement::FilesystemConfined => "filesystem confined to policy paths",
            Requirement::NoPrivilegeEscalation => "no privilege escalation",
            Requirement::ProcessMemoryIsolated => "other processes cannot be debugged or read",
            Requirement::InheritedHandlesClosed => {
                "only standard input, output and error inherited"
            }
            Requirement::EnvironmentControlled => "environment limited to policy",
            Requirement::IpNetworkDenied => "IP networking denied",
            Requirement::IpNetworkPrivate => "IP networking limited to the sandbox's own loopback",
            Requirement::EgressBrokered => "connections out only through the egress broker",
            Requirement::PathsHidden => "paths outside the policy hidden",
            Requirement::InboundIpDenied => "no inbound IP connections",
            Requirement::UnixSocketsDenied => "Unix sockets outside writable paths denied",
            Requirement::SignalsIsolated => "signals limited to the sandbox",
            Requirement::MetadataConfined => "metadata of files outside policy paths protected",
            Requirement::ExposedPortsRelayed => "exposed ports relayed into the sandbox",
            Requirement::ForwardedPortsRelayed => "forwarded ports relayed out of the sandbox",
            Requirement::ChildProcessesDenied => "no child processes",
            Requirement::ChildProcessesContained => "child processes end with the program",
            Requirement::EndsWithParent => "the program ends when sandy's parent ends",
            Requirement::Win32kDenied => "win32k system calls denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Enforced {
        mechanism: String,
    },
    Unavailable {
        reason: String,
    },
    /// Unavailable on this host until `sandy setup`, run once with administrator rights,
    /// prepares it. `check` exits with `EXIT_NEEDS_SETUP` when nothing else is missing.
    NeedsSetup {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    pub requirement: Requirement,
    pub status: Status,
}

impl PlanItem {
    pub fn enforced(requirement: Requirement, mechanism: impl Into<String>) -> Self {
        PlanItem {
            requirement,
            status: Status::Enforced {
                mechanism: mechanism.into(),
            },
        }
    }

    pub fn unavailable(requirement: Requirement, reason: impl Into<String>) -> Self {
        PlanItem {
            requirement,
            status: Status::Unavailable {
                reason: reason.into(),
            },
        }
    }

    /// Unavailable until `sandy setup` prepares the host. `reason` says what is missing; the plan
    /// adds that setup fixes it.
    pub fn needs_setup(requirement: Requirement, reason: impl Into<String>) -> Self {
        PlanItem {
            requirement,
            status: Status::NeedsSetup {
                reason: reason.into(),
            },
        }
    }

    pub fn is_enforced(&self) -> bool {
        matches!(self.status, Status::Enforced { .. })
    }
}

/// How each required guarantee is enforced on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPlan {
    items: Vec<PlanItem>,
}

impl EnforcementPlan {
    /// Builds the plan for `required` from the backend's report. A requirement the backend did
    /// not report counts as unavailable, and a requirement reported more than once counts as
    /// unavailable if any report says so. A backend therefore cannot weaken the sandbox by
    /// omission. Among several reports that it is missing, one that setup cannot fix wins over one
    /// that it can, so the plan never promises that setup is enough when it is not.
    pub fn new(required: &[Requirement], reported: Vec<PlanItem>) -> Self {
        let items = required
            .iter()
            .map(|&requirement| {
                let reports: Vec<&PlanItem> = reported
                    .iter()
                    .filter(|i| i.requirement == requirement)
                    .collect();
                let worst = reports
                    .iter()
                    .find(|item| matches!(item.status, Status::Unavailable { .. }))
                    .or_else(|| reports.iter().find(|item| !item.is_enforced()))
                    .or(reports.first());
                match worst {
                    Some(item) => (*item).clone(),
                    None => PlanItem::unavailable(
                        requirement,
                        "the platform backend does not support this requirement",
                    ),
                }
            })
            .collect();
        EnforcementPlan { items }
    }

    pub fn items(&self) -> &[PlanItem] {
        &self.items
    }

    pub fn is_enforceable(&self) -> bool {
        self.items.iter().all(PlanItem::is_enforced)
    }

    pub fn unavailable(&self) -> impl Iterator<Item = &PlanItem> {
        self.items.iter().filter(|item| !item.is_enforced())
    }

    /// Whether `sandy setup` would make this plan enforceable: something is missing, and all of
    /// it is something setup prepares.
    pub fn needs_only_setup(&self) -> bool {
        !self.is_enforceable()
            && self
                .unavailable()
                .all(|item| matches!(item.status, Status::NeedsSetup { .. }))
    }
}

impl fmt::Display for EnforcementPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.items {
            let description = item.requirement.description();
            match &item.status {
                Status::Enforced { mechanism } => {
                    writeln!(f, "enforced     {description}: {mechanism}")?
                }
                Status::Unavailable { reason } => {
                    writeln!(f, "UNAVAILABLE  {description}: {reason}")?
                }
                Status::NeedsSetup { reason } => writeln!(
                    f,
                    "UNAVAILABLE  {description}: {reason}; `sandy setup`, run once with \
                     administrator rights, prepares this host"
                )?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: [Requirement; 2] = [
        Requirement::FilesystemConfined,
        Requirement::IpNetworkDenied,
    ];

    #[test]
    fn enforceable_when_every_requirement_is_enforced() {
        let plan = EnforcementPlan::new(
            &REQUIRED,
            vec![
                PlanItem::enforced(Requirement::FilesystemConfined, "a"),
                PlanItem::enforced(Requirement::IpNetworkDenied, "b"),
            ],
        );
        assert!(plan.is_enforceable());
    }

    #[test]
    fn missing_report_is_unavailable() {
        let plan = EnforcementPlan::new(
            &REQUIRED,
            vec![PlanItem::enforced(Requirement::FilesystemConfined, "a")],
        );
        assert!(!plan.is_enforceable());
        let missing: Vec<_> = plan.unavailable().map(|i| i.requirement).collect();
        assert_eq!(missing, vec![Requirement::IpNetworkDenied]);
    }

    #[test]
    fn any_unavailable_report_wins() {
        let plan = EnforcementPlan::new(
            &REQUIRED,
            vec![
                PlanItem::enforced(Requirement::FilesystemConfined, "a"),
                PlanItem::enforced(Requirement::IpNetworkDenied, "b"),
                PlanItem::unavailable(Requirement::IpNetworkDenied, "c"),
            ],
        );
        assert!(!plan.is_enforceable());
    }

    /// Every order of up to three reports for one requirement, with a report for another
    /// requirement among them: the first report that setup cannot fix wins, then the first that
    /// it fixes, and only reports that all say enforced make the requirement enforced. Status 2
    /// of `check` follows from a plan whose only gap setup fixes.
    #[test]
    fn the_worst_report_wins_in_every_order() {
        let required = Requirement::IpNetworkDenied;
        let report = |kind: usize, place: u32| {
            let text = format!("report {place}");
            match kind {
                0 => PlanItem::enforced(required, text),
                1 => PlanItem::needs_setup(required, text),
                _ => PlanItem::unavailable(required, text),
            }
        };
        let rank = |item: &PlanItem| match item.status {
            Status::Enforced { .. } => 0,
            Status::NeedsSetup { .. } => 1,
            Status::Unavailable { .. } => 2,
        };
        let other = PlanItem::unavailable(Requirement::FilesystemConfined, "other");
        for length in 0..=3u32 {
            for index in 0..3usize.pow(length) {
                let reports: Vec<PlanItem> = (0..length)
                    .map(|place| report(index / 3usize.pow(place) % 3, place))
                    .collect();
                let mut reported = reports.clone();
                reported.insert(index % (reports.len() + 1), other.clone());
                let plan = EnforcementPlan::new(&[required], reported);
                let merged = &plan.items()[0];
                let worst = reports.iter().map(rank).max();
                match reports.iter().find(|item| Some(rank(item)) == worst) {
                    Some(expected) => assert_eq!(merged, expected, "{reports:?}"),
                    None => assert!(
                        matches!(merged.status, Status::Unavailable { .. }),
                        "{merged:?}"
                    ),
                }
                assert_eq!(
                    plan.is_enforceable(),
                    !reports.is_empty() && reports.iter().all(PlanItem::is_enforced),
                    "{reports:?}"
                );
                assert_eq!(plan.needs_only_setup(), worst == Some(1), "{reports:?}");
            }
        }
    }

    #[test]
    fn setup_is_enough_only_when_all_that_is_missing_needs_it() {
        let only_setup = EnforcementPlan::new(
            &REQUIRED,
            vec![
                PlanItem::enforced(Requirement::FilesystemConfined, "a"),
                PlanItem::needs_setup(Requirement::IpNetworkDenied, "b"),
            ],
        );
        assert!(!only_setup.is_enforceable());
        assert!(only_setup.needs_only_setup());
        assert!(only_setup.to_string().contains("sandy setup"));

        let more = EnforcementPlan::new(
            &REQUIRED,
            vec![
                PlanItem::unavailable(Requirement::FilesystemConfined, "a"),
                PlanItem::needs_setup(Requirement::IpNetworkDenied, "b"),
            ],
        );
        assert!(!more.needs_only_setup());

        let enforceable = EnforcementPlan::new(
            &REQUIRED,
            vec![
                PlanItem::enforced(Requirement::FilesystemConfined, "a"),
                PlanItem::enforced(Requirement::IpNetworkDenied, "b"),
            ],
        );
        assert!(!enforceable.needs_only_setup());
    }

    #[test]
    fn a_report_setup_cannot_fix_wins_over_one_it_can() {
        for reports in [
            vec![
                PlanItem::needs_setup(Requirement::IpNetworkDenied, "setup"),
                PlanItem::unavailable(Requirement::IpNetworkDenied, "kernel"),
            ],
            vec![
                PlanItem::unavailable(Requirement::IpNetworkDenied, "kernel"),
                PlanItem::needs_setup(Requirement::IpNetworkDenied, "setup"),
                PlanItem::enforced(Requirement::IpNetworkDenied, "x"),
            ],
        ] {
            let plan = EnforcementPlan::new(&[Requirement::IpNetworkDenied], reports);
            assert_eq!(
                plan.items()[0].status,
                Status::Unavailable {
                    reason: "kernel".to_string()
                }
            );
            assert!(!plan.needs_only_setup());
        }
    }

    #[test]
    fn reports_for_unrequired_items_are_ignored() {
        let plan = EnforcementPlan::new(
            &[Requirement::FilesystemConfined],
            vec![
                PlanItem::enforced(Requirement::FilesystemConfined, "a"),
                PlanItem::unavailable(Requirement::SignalsIsolated, "old kernel"),
            ],
        );
        assert!(plan.is_enforceable());
        assert_eq!(plan.items().len(), 1);
    }
}
