//! Which level of a policy runs (DESIGN.md, "Fallback levels").

use crate::plan::EnforcementPlan;

/// How the choice of a level ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The level at this index runs: the host enforces it, and every level before it was
    /// skipped for a shortfall of the host.
    Selected(usize),
    /// The plan of the level at this index has a final report (`Status::is_final`): sandy cannot
    /// tell what the host enforces, or the policy conflicts with it, so no weaker level is tried.
    Stopped(usize),
    /// No level is enforceable. The last level is the floor: nothing weaker runs.
    NoneEnforceable {
        /// `sandy setup` would make one of them enforceable.
        setup_helps: bool,
    },
}

/// The plans of the levels tried and the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// One plan per level tried, from the first level on. The levels after the selected one, or
    /// after the one that stopped the choice, are not planned.
    pub plans: Vec<EnforcementPlan>,
    pub outcome: Outcome,
}

/// Plans the levels `0..count` in order with `plan` and takes the first that the host enforces.
/// A level is skipped only when its plan is not enforceable for a shortfall of the host
/// (`Unavailable` or `NeedsSetup`); a final report stops the choice there. Levels are planned
/// lazily, so a probe that only a skipped-to level needs runs only when sandy gets there.
pub fn select(count: usize, mut plan: impl FnMut(usize) -> EnforcementPlan) -> Selection {
    let mut plans = Vec::new();
    for index in 0..count {
        let level = plan(index);
        let stopped = level.final_reports().next().is_some();
        let enforceable = level.is_enforceable();
        plans.push(level);
        if stopped {
            return Selection {
                plans,
                outcome: Outcome::Stopped(index),
            };
        }
        if enforceable {
            return Selection {
                plans,
                outcome: Outcome::Selected(index),
            };
        }
    }
    let setup_helps = plans.iter().any(EnforcementPlan::needs_only_setup);
    Selection {
        plans,
        outcome: Outcome::NoneEnforceable { setup_helps },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{PlanItem, Requirement};

    const REQUIRED: Requirement = Requirement::IpNetworkPrivate;

    fn plan(item: fn(Requirement, &'static str) -> PlanItem) -> EnforcementPlan {
        EnforcementPlan::new(&[REQUIRED], vec![item(REQUIRED, "x")])
    }

    fn levels(kinds: &[fn(Requirement, &'static str) -> PlanItem]) -> (Selection, Vec<usize>) {
        let mut planned = Vec::new();
        let selection = select(kinds.len(), |index| {
            planned.push(index);
            plan(kinds[index])
        });
        assert_eq!(selection.plans.len(), planned.len());
        (selection, planned)
    }

    fn enforced(requirement: Requirement, mechanism: &'static str) -> PlanItem {
        PlanItem::enforced(requirement, mechanism)
    }

    fn unavailable(requirement: Requirement, reason: &'static str) -> PlanItem {
        PlanItem::unavailable(requirement, reason)
    }

    fn needs_setup(requirement: Requirement, reason: &'static str) -> PlanItem {
        PlanItem::needs_setup(requirement, reason)
    }

    fn indeterminate(requirement: Requirement, reason: &'static str) -> PlanItem {
        PlanItem::indeterminate(requirement, reason)
    }

    fn conflict(requirement: Requirement, reason: &'static str) -> PlanItem {
        PlanItem::conflict(requirement, reason)
    }

    #[test]
    fn the_first_enforceable_level_runs_and_later_ones_are_not_planned() {
        let (selection, planned) = levels(&[enforced, enforced]);
        assert_eq!(selection.outcome, Outcome::Selected(0));
        assert_eq!(planned, [0]);

        let (selection, planned) = levels(&[unavailable, needs_setup, enforced, enforced]);
        assert_eq!(selection.outcome, Outcome::Selected(2));
        assert_eq!(planned, [0, 1, 2]);
    }

    /// An indeterminate report or a conflict ends the choice, also when a weaker level after it
    /// would be enforceable: neither says that the host lacks something.
    #[test]
    fn a_final_report_stops_before_any_weaker_level() {
        for kind in [indeterminate, conflict] {
            let (selection, planned) = levels(&[kind, enforced]);
            assert_eq!(selection.outcome, Outcome::Stopped(0));
            assert_eq!(planned, [0]);

            let (selection, planned) = levels(&[unavailable, kind, enforced]);
            assert_eq!(selection.outcome, Outcome::Stopped(1));
            assert_eq!(planned, [0, 1]);
        }
    }

    /// A final report stops the choice even when the same plan also has a shortfall, so the
    /// outcome never depends on which report a backend happens to find first.
    #[test]
    fn a_final_report_wins_over_a_shortfall_in_the_same_plan() {
        let level = |index: usize| {
            let items = vec![
                PlanItem::unavailable(Requirement::FilesystemConfined, "old kernel"),
                PlanItem::indeterminate(REQUIRED, "cannot fork"),
            ];
            let plan = EnforcementPlan::new(&[Requirement::FilesystemConfined, REQUIRED], items);
            if index == 0 {
                plan
            } else {
                EnforcementPlan::new(&[], Vec::new())
            }
        };
        assert_eq!(select(2, level).outcome, Outcome::Stopped(0));
    }

    /// The last level is the floor, and status 2 of `check` follows when setup would make any
    /// level enforceable.
    #[test]
    fn without_an_enforceable_level_nothing_runs() {
        let (selection, planned) = levels(&[unavailable, unavailable]);
        assert_eq!(
            selection.outcome,
            Outcome::NoneEnforceable { setup_helps: false }
        );
        assert_eq!(planned, [0, 1]);

        for kinds in [
            &[needs_setup, unavailable][..],
            &[unavailable, needs_setup],
            &[needs_setup],
        ] {
            let (selection, _) = levels(kinds);
            assert_eq!(
                selection.outcome,
                Outcome::NoneEnforceable { setup_helps: true }
            );
        }
    }

    #[test]
    fn a_policy_without_levels_is_its_own_floor() {
        for (kind, outcome) in [
            (enforced as fn(_, _) -> _, Outcome::Selected(0)),
            (unavailable, Outcome::NoneEnforceable { setup_helps: false }),
            (needs_setup, Outcome::NoneEnforceable { setup_helps: true }),
            (indeterminate, Outcome::Stopped(0)),
            (conflict, Outcome::Stopped(0)),
        ] {
            assert_eq!(levels(&[kind]).0.outcome, outcome);
        }
    }
}
