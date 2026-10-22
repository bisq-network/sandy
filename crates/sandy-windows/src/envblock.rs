//! The environment block of the target, in the form `CreateProcessW` expects with
//! `CREATE_UNICODE_ENVIRONMENT`: `NAME=VALUE` strings, each NUL-terminated, sorted by name, and a
//! final NUL.

use std::cmp::Ordering;
use std::fmt;

const NUL: u16 = 0;
const EQUALS: u16 = b'=' as u16;

/// The Windows directory. System DLLs locate it through this variable; without it, for example,
/// Winsock initialization and the random number generator of the C runtime fail.
pub const SYSTEM_ROOT: &str = "SystemRoot";

/// The local application data folder of the user. `CreateProcessW` fails with
/// `ERROR_ENVVAR_NOT_FOUND` for an AppContainer process whose environment lacks it. Windows then
/// replaces it with `<value>\Packages\<AppContainer name>\AC` and sets `TEMP` and `TMP` to
/// the `Temp` folder below that, also when the policy sets them.
pub const LOCAL_APP_DATA: &str = "LOCALAPPDATA";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentError {
    InvalidName(String),
    InvalidValue(String),
    Duplicate(String),
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvironmentError::InvalidName(name) => {
                write!(f, "invalid environment variable name {name:?}")
            }
            EnvironmentError::InvalidValue(name) => {
                write!(f, "invalid value for environment variable {name}")
            }
            EnvironmentError::Duplicate(name) => {
                write!(f, "environment variable {name} is set twice")
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

/// Builds the block from `vars` (UTF-16 name and value) and `fixed`, the variables Windows needs
/// to start the program. A fixed variable replaces a variable of `vars` with the same name: its
/// value must name the real folder, and a policy has no reason to change it.
pub fn environment_block(
    vars: &[(Vec<u16>, Vec<u16>)],
    fixed: &[(Vec<u16>, Vec<u16>)],
) -> Result<Vec<u16>, EnvironmentError> {
    let mut entries: Vec<&(Vec<u16>, Vec<u16>)> = vars
        .iter()
        .filter(|(name, _)| !fixed.iter().any(|(fixed, _)| same_name(name, fixed)))
        .collect();
    entries.extend(fixed);
    for (name, value) in &entries {
        // A leading `=` would be a hidden per-drive variable, and an inner `=` would split the
        // entry at the wrong place.
        if name.is_empty() || name.contains(&EQUALS) || name.contains(&NUL) {
            return Err(EnvironmentError::InvalidName(String::from_utf16_lossy(
                name,
            )));
        }
        if value.contains(&NUL) {
            return Err(EnvironmentError::InvalidValue(String::from_utf16_lossy(
                name,
            )));
        }
    }
    entries.sort_by(|a, b| compare_names(&a.0, &b.0));
    if let Some(pair) = entries
        .windows(2)
        .find(|pair| same_name(&pair[0].0, &pair[1].0))
    {
        return Err(EnvironmentError::Duplicate(String::from_utf16_lossy(
            &pair[0].0,
        )));
    }

    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend_from_slice(name);
        block.push(EQUALS);
        block.extend_from_slice(value);
        block.push(NUL);
    }
    if block.is_empty() {
        block.push(NUL);
    }
    block.push(NUL);
    Ok(block)
}

/// "All strings in the environment block must be sorted alphabetically by name. The sort is
/// case-insensitive, Unicode order, without regard to locale." ("Changing Environment
/// Variables", Microsoft Learn)
fn compare_names(a: &[u16], b: &[u16]) -> Ordering {
    let folded = |name: &[u16]| name.iter().map(|&unit| upper(unit)).collect::<Vec<_>>();
    folded(a).cmp(&folded(b)).then_with(|| a.cmp(b))
}

fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upper(x) == upper(y))
}

/// Simple uppercase mapping of one UTF-16 unit, like the case-insensitive ordinal comparison of
/// Windows: units without a single-unit uppercase form stay unchanged.
fn upper(unit: u16) -> u16 {
    let Some(c) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u16::try_from(u32::from(u)).unwrap_or(unit),
        _ => unit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn vars(pairs: &[(&str, &str)]) -> Vec<(Vec<u16>, Vec<u16>)> {
        pairs.iter().map(|(n, v)| (wide(n), wide(v))).collect()
    }

    fn text(block: &[u16]) -> String {
        String::from_utf16(block).unwrap()
    }

    #[test]
    fn empty_environment_is_two_nuls() {
        assert_eq!(environment_block(&[], &[]).unwrap(), vec![0, 0]);
    }

    #[test]
    fn sorts_case_insensitively() {
        let block = environment_block(
            &vars(&[("b", "2"), ("A", "1"), ("_X", "3"), ("a1", "4")]),
            &[],
        )
        .unwrap();
        assert_eq!(text(&block), "A=1\0a1=4\0b=2\0_X=3\0\0");
    }

    #[test]
    fn fixed_variables_replace_the_policy() {
        let fixed = vars(&[("SystemRoot", r"C:\Windows")]);
        let block = environment_block(&vars(&[("LANG", "C")]), &fixed).unwrap();
        assert_eq!(text(&block), "LANG=C\0SystemRoot=C:\\Windows\0\0");

        let block = environment_block(&vars(&[("SYSTEMROOT", r"D:\Win")]), &fixed).unwrap();
        assert_eq!(text(&block), "SystemRoot=C:\\Windows\0\0");
    }

    #[test]
    fn values_may_contain_equals_signs() {
        let block = environment_block(&vars(&[("A", "b=c")]), &[]).unwrap();
        assert_eq!(text(&block), "A=b=c\0\0");
    }

    #[test]
    fn rejects_invalid_names_and_values() {
        for name in ["", "=C:", "A=B", "A\0"] {
            assert_eq!(
                environment_block(&vars(&[(name, "x")]), &[]),
                Err(EnvironmentError::InvalidName(name.to_string()))
            );
        }
        assert_eq!(
            environment_block(&vars(&[("A", "x\0y")]), &[]),
            Err(EnvironmentError::InvalidValue("A".to_string()))
        );
    }

    #[test]
    fn rejects_names_that_differ_only_in_case() {
        assert!(matches!(
            environment_block(&vars(&[("Path", "a"), ("PATH", "b")]), &[]),
            Err(EnvironmentError::Duplicate(_))
        ));
    }

    #[test]
    fn folds_non_ascii_letters() {
        assert_eq!(compare_names(&wide("é"), &wide("É")), Ordering::Greater);
        assert!(same_name(&wide("é"), &wide("É")));
        assert!(!same_name(&wide("ß"), &wide("SS")));
    }
}
