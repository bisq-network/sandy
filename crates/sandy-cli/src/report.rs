//! What `check` prints about the levels it planned: the text form, and the JSON object of
//! `--json`, whose keys are documented in README.md and stay stable.

use std::fmt::Write;

use sandy_core::{EnforcementPlan, Outcome, ResolvedLevel, Selection, Status};

/// The plan of each level `check` tried, for a policy with fallback levels: a `[NAME]` line and
/// the plan of that level, and then `level: NAME` for the level that runs, or `level: none`. A
/// choice that stopped at a final report has no last line; `check` fails instead.
pub fn levels_text(levels: &[ResolvedLevel], selection: &Selection) -> String {
    let mut text = String::new();
    for (level, plan) in levels.iter().zip(&selection.plans) {
        let _ = write!(text, "[{}]\n{plan}", level.name);
    }
    match selection.outcome {
        Outcome::Selected(index) => {
            let _ = writeln!(text, "level: {}", levels[index].name);
        }
        Outcome::NoneEnforceable { .. } => text.push_str("level: none\n"),
        Outcome::Stopped(_) => {}
    }
    text
}

/// The JSON object of `check --json`, on one line. `check` prints it only for a choice that
/// ended without a final report. `level_warnings` has the warnings of each level tried, and
/// `warnings` those that concern every level, such as an option that widens the policy file.
pub fn json(
    backend: &str,
    levels: &[ResolvedLevel],
    selection: &Selection,
    level_warnings: &[Vec<String>],
    warnings: &[String],
) -> String {
    let (selected, setup_helps) = match selection.outcome {
        Outcome::Selected(index) => (Some(levels[index].name.as_str()), false),
        Outcome::NoneEnforceable { setup_helps } => (None, setup_helps),
        Outcome::Stopped(_) => (None, false),
    };
    let tried: Vec<String> = levels
        .iter()
        .zip(&selection.plans)
        .zip(level_warnings)
        .map(|((level, plan), warnings)| level_json(&level.name, plan, warnings))
        .collect();
    format!(
        "{{\"backend\":{},\"selected\":{},\"setup_would_help\":{setup_helps},\"levels\":[{}],\
         \"warnings\":{}}}",
        string(backend),
        selected.map_or_else(|| "null".to_string(), string),
        tried.join(","),
        strings(warnings),
    )
}

fn level_json(name: &str, plan: &EnforcementPlan, warnings: &[String]) -> String {
    let mut enforced = Vec::new();
    let mut missing = Vec::new();
    for item in plan.items() {
        let key = string(item.requirement.key());
        match &item.status {
            Status::Enforced { mechanism } => enforced.push(format!(
                "{{\"requirement\":{key},\"mechanism\":{}}}",
                string(mechanism)
            )),
            status => {
                let kind = match status {
                    Status::NeedsSetup { .. } => "needs-setup",
                    Status::Indeterminate { .. } => "indeterminate",
                    Status::Conflict { .. } => "conflict",
                    _ => "unavailable",
                };
                missing.push(format!(
                    "{{\"requirement\":{key},\"status\":\"{kind}\",\"reason\":{}}}",
                    string(status.reason().unwrap_or_default())
                ));
            }
        }
    }
    format!(
        "{{\"name\":{},\"enforceable\":{},\"needs_setup\":{},\"enforced\":[{}],\"missing\":[{}],\
         \"warnings\":{}}}",
        string(name),
        plan.is_enforceable(),
        plan.needs_only_setup(),
        enforced.join(","),
        missing.join(","),
        strings(warnings),
    )
}

fn strings(texts: &[String]) -> String {
    let items: Vec<String> = texts.iter().map(|text| string(text)).collect();
    format!("[{}]", items.join(","))
}

/// `text` as a JSON string (RFC 8259).
fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{PlanItem, Policy, Requirement, ResolvedPolicy, select};

    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("plain"), "\"plain\"");
        assert_eq!(
            string("a \"b\" \\ c\nd\te\r\u{1}\u{7f}é"),
            "\"a \\\"b\\\" \\\\ c\\nd\\te\\r\\u0001\u{7f}é\""
        );
    }

    fn levels() -> Vec<ResolvedLevel> {
        let text = "version = 1\n[network]\nip = \"private\"\n\
                    [[fallback]]\nname = \"open\"\nnetwork.ip = \"all\"\n";
        ResolvedPolicy::resolve_levels(&Policy::from_toml(text).unwrap(), None).unwrap()
    }

    fn selection(levels: &[ResolvedLevel]) -> Selection {
        select(levels.len(), |index| {
            let policy = &levels[index].policy;
            let items = policy
                .requirements()
                .into_iter()
                .map(|requirement| {
                    if requirement == Requirement::IpNetworkPrivate {
                        PlanItem::needs_setup(requirement, "no \"namespaces\"")
                    } else {
                        PlanItem::enforced(requirement, "m")
                    }
                })
                .collect();
            EnforcementPlan::new(&policy.requirements(), items)
        })
    }

    #[test]
    fn the_text_names_each_level_tried_and_the_one_that_runs() {
        let levels = levels();
        let selection = selection(&levels);
        let text = levels_text(&levels, &selection);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"[base]"));
        assert!(lines.contains(&"[open]"), "{text}");
        assert_eq!(lines.last(), Some(&"level: open"));
        assert!(
            text.contains("UNAVAILABLE  IP networking limited"),
            "{text}"
        );
    }

    #[test]
    fn the_json_has_the_documented_keys() {
        let levels = levels();
        let selection = selection(&levels);
        let notes = [vec!["w\"1".to_string()], Vec::new()];
        let json = json("linux", &levels, &selection, &notes, &["option".into()]);
        assert!(!json.contains('\n'), "{json}");
        assert!(
            json.starts_with(
                "{\"backend\":\"linux\",\"selected\":\"open\",\"setup_would_help\":false,\
                 \"levels\":[{\"name\":\"base\",\"enforceable\":false,\"needs_setup\":true,"
            ),
            "{json}"
        );
        assert!(
            json.contains(
                "\"missing\":[{\"requirement\":\"ip-network-private\",\"status\":\"needs-setup\",\
                 \"reason\":\"no \\\"namespaces\\\"\"}],\"warnings\":[\"w\\\"1\"]}"
            ),
            "{json}"
        );
        assert!(
            json.contains(
                "{\"name\":\"open\",\"enforceable\":true,\"needs_setup\":false,\"enforced\":["
            ),
            "{json}"
        );
        assert!(json.ends_with("\"warnings\":[\"option\"]}"), "{json}");
    }
}
