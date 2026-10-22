use std::ffi::{OsStr, OsString};

use crate::policy::EnvironmentPolicy;

/// Builds the target environment: the variables of `current` named in `policy.pass`, then the
/// fixed values of `policy.set`. Nothing else is inherited. Names compare case-insensitively on
/// Windows, like the Windows environment does.
pub fn target_environment<I>(policy: &EnvironmentPolicy, current: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut environment: Vec<(OsString, OsString)> = current
        .into_iter()
        .filter(|(name, _)| policy.pass.iter().any(|p| same_name(name, OsStr::new(p))))
        .collect();
    for (name, value) in &policy.set {
        environment.retain(|(existing, _)| !same_name(existing, OsStr::new(name)));
        environment.push((OsString::from(name), OsString::from(value)));
    }
    environment
}

fn same_name(a: &OsStr, b: &OsStr) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(n, v)| (OsString::from(n), OsString::from(v)))
            .collect()
    }

    #[test]
    fn inherits_nothing_by_default() {
        let env = target_environment(&EnvironmentPolicy::default(), vars(&[("HOME", "/h")]));
        assert!(env.is_empty());
    }

    #[test]
    fn passes_named_variables_only() {
        let policy = EnvironmentPolicy {
            pass: vec!["LANG".into(), "MISSING".into()],
            ..Default::default()
        };
        let env = target_environment(&policy, vars(&[("HOME", "/h"), ("LANG", "C")]));
        assert_eq!(env, vars(&[("LANG", "C")]));
    }

    #[test]
    fn set_overrides_pass() {
        let mut policy = EnvironmentPolicy {
            pass: vec!["HOME".into()],
            ..Default::default()
        };
        policy.set.insert("HOME".into(), "/sandbox".into());
        let env = target_environment(&policy, vars(&[("HOME", "/h")]));
        assert_eq!(env, vars(&[("HOME", "/sandbox")]));
    }
}
