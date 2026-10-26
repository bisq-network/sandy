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
    /// The target reaches its forwarded ports and the egress broker over IPv4 only, so no IPv6
    /// address, such as a link-local address of the host at the scope of another link, takes
    /// its connections to those ports out of the sandbox. Platforms whose private network has
    /// no such route give this without a mechanism.
    RelaysIpv4Only,
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
    /// Every requirement, in the order of the enum.
    pub const ALL: [Requirement; 20] = [
        Requirement::FilesystemConfined,
        Requirement::NoPrivilegeEscalation,
        Requirement::ProcessMemoryIsolated,
        Requirement::InheritedHandlesClosed,
        Requirement::EnvironmentControlled,
        Requirement::IpNetworkDenied,
        Requirement::IpNetworkPrivate,
        Requirement::EgressBrokered,
        Requirement::RelaysIpv4Only,
        Requirement::PathsHidden,
        Requirement::InboundIpDenied,
        Requirement::UnixSocketsDenied,
        Requirement::SignalsIsolated,
        Requirement::MetadataConfined,
        Requirement::ExposedPortsRelayed,
        Requirement::ForwardedPortsRelayed,
        Requirement::ChildProcessesDenied,
        Requirement::ChildProcessesContained,
        Requirement::EndsWithParent,
        Requirement::Win32kDenied,
    ];

    /// A stable name for programs that read `check --json`. It never changes once released, while
    /// `description` may be reworded.
    pub fn key(self) -> &'static str {
        match self {
            Requirement::FilesystemConfined => "filesystem-confined",
            Requirement::NoPrivilegeEscalation => "no-privilege-escalation",
            Requirement::ProcessMemoryIsolated => "process-memory-isolated",
            Requirement::InheritedHandlesClosed => "inherited-handles-closed",
            Requirement::EnvironmentControlled => "environment-controlled",
            Requirement::IpNetworkDenied => "ip-network-denied",
            Requirement::IpNetworkPrivate => "ip-network-private",
            Requirement::EgressBrokered => "egress-brokered",
            Requirement::RelaysIpv4Only => "relays-ipv4-only",
            Requirement::PathsHidden => "paths-hidden",
            Requirement::InboundIpDenied => "inbound-ip-denied",
            Requirement::UnixSocketsDenied => "unix-sockets-denied",
            Requirement::SignalsIsolated => "signals-isolated",
            Requirement::MetadataConfined => "metadata-confined",
            Requirement::ExposedPortsRelayed => "exposed-ports-relayed",
            Requirement::ForwardedPortsRelayed => "forwarded-ports-relayed",
            Requirement::ChildProcessesDenied => "child-processes-denied",
            Requirement::ChildProcessesContained => "child-processes-contained",
            Requirement::EndsWithParent => "ends-with-parent",
            Requirement::Win32kDenied => "win32k-denied",
        }
    }

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
            Requirement::RelaysIpv4Only => "forwarded and egress ports reached over IPv4 only",
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
    /// sandy cannot tell right now whether this host enforces the requirement: a probe failed
    /// for a reason that can pass (out of memory or processes, a timeout, a service that is
    /// starting) or that someone other than an administrator can cause. It is no shortfall of
    /// the host, so it never makes sandy try a weaker fallback level: `check` and `run` fail
    /// with status 125 instead.
    Indeterminate {
        reason: String,
    },
    /// The policy asks for something that contradicts itself or this host's fixed layout, for
    /// example a writable path that reaches a location whose content runs outside the sandbox.
    /// Every level of the policy shares it, so like `Indeterminate` it stops the selection
    /// with status 125 instead of moving to a weaker level.
    Conflict {
        reason: String,
    },
}

impl Status {
    /// How bad a report is when several report on one requirement: the worst one wins.
    fn rank(&self) -> u8 {
        match self {
            Status::Enforced { .. } => 0,
            Status::NeedsSetup { .. } => 1,
            Status::Unavailable { .. } => 2,
            Status::Indeterminate { .. } => 3,
            Status::Conflict { .. } => 4,
        }
    }

    /// Why the requirement is not enforced; `None` when it is.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Status::Enforced { .. } => None,
            Status::Unavailable { reason }
            | Status::NeedsSetup { reason }
            | Status::Indeterminate { reason }
            | Status::Conflict { reason } => Some(reason),
        }
    }

    /// Whether this report ends the selection of a level instead of letting sandy try the next
    /// one.
    pub fn is_final(&self) -> bool {
        matches!(self, Status::Indeterminate { .. } | Status::Conflict { .. })
    }
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

    /// sandy cannot tell right now whether the host enforces it (`Status::Indeterminate`).
    pub fn indeterminate(requirement: Requirement, reason: impl Into<String>) -> Self {
        PlanItem {
            requirement,
            status: Status::Indeterminate {
                reason: reason.into(),
            },
        }
    }

    /// The policy contradicts itself or the host's fixed layout (`Status::Conflict`).
    pub fn conflict(requirement: Requirement, reason: impl Into<String>) -> Self {
        PlanItem {
            requirement,
            status: Status::Conflict {
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
    /// not report counts as unavailable, and a requirement reported more than once takes its
    /// worst report: a conflict, then an indeterminate one, then one that setup cannot fix, then
    /// one that it can. A backend therefore cannot weaken the sandbox by omission, the plan
    /// never promises that setup is enough when it is not, and a report that ends the selection
    /// is never hidden behind one that would let sandy try the next level. Among reports of the
    /// same rank the first wins.
    pub fn new(required: &[Requirement], reported: Vec<PlanItem>) -> Self {
        let items = required
            .iter()
            .map(|&requirement| {
                let worst = reported
                    .iter()
                    .filter(|item| item.requirement == requirement)
                    .reduce(|worst, item| {
                        if item.status.rank() > worst.status.rank() {
                            item
                        } else {
                            worst
                        }
                    });
                match worst {
                    Some(item) => item.clone(),
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

    /// The reports that end the selection of a level (`Status::is_final`): with one of them the
    /// plan says nothing about the host's capabilities, so sandy fails instead of trying another
    /// level.
    pub fn final_reports(&self) -> impl Iterator<Item = &PlanItem> {
        self.items.iter().filter(|item| item.status.is_final())
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
                Status::Indeterminate { reason } => writeln!(
                    f,
                    "UNDECIDED    {description}: {reason}; sandy cannot tell now whether this \
                     host enforces it"
                )?,
                Status::Conflict { reason } => writeln!(f, "CONFLICT     {description}: {reason}")?,
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
    /// requirement among them: the first conflict wins, then the first indeterminate report, then
    /// the first that setup cannot fix, then the first that it fixes, and only reports that all
    /// say enforced make the requirement enforced. Status 2 of `check` follows from a plan whose
    /// only gap setup fixes, and a final report is never hidden.
    #[test]
    fn the_worst_report_wins_in_every_order() {
        const KINDS: usize = 5;
        let required = Requirement::IpNetworkDenied;
        let report = |kind: usize, place: u32| {
            let text = format!("report {place}");
            match kind {
                0 => PlanItem::enforced(required, text),
                1 => PlanItem::needs_setup(required, text),
                2 => PlanItem::unavailable(required, text),
                3 => PlanItem::indeterminate(required, text),
                _ => PlanItem::conflict(required, text),
            }
        };
        let rank = |item: &PlanItem| match item.status {
            Status::Enforced { .. } => 0,
            Status::NeedsSetup { .. } => 1,
            Status::Unavailable { .. } => 2,
            Status::Indeterminate { .. } => 3,
            Status::Conflict { .. } => 4,
        };
        let other = PlanItem::unavailable(Requirement::FilesystemConfined, "other");
        for length in 0..=3u32 {
            for index in 0..KINDS.pow(length) {
                let reports: Vec<PlanItem> = (0..length)
                    .map(|place| report(index / KINDS.pow(place) % KINDS, place))
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
                assert_eq!(
                    plan.final_reports().count(),
                    usize::from(worst >= Some(3)),
                    "{reports:?}"
                );
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

    /// `ALL` lists every requirement once, and every key is distinct and in kebab case, since
    /// `check --json` promises them as stable names.
    #[test]
    fn every_requirement_has_a_distinct_key() {
        let mut keys: Vec<&str> = Requirement::ALL.iter().map(|r| r.key()).collect();
        assert!(keys.iter().all(|key| {
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        }));
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), Requirement::ALL.len());
        let mut all = Requirement::ALL.to_vec();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), Requirement::ALL.len());
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
