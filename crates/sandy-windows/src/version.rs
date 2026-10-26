//! The Windows versions this backend supports.

use crate::plan::Problem;

/// Build and update revision (UBR) of the host. The revision is `Err` with the reason when it
/// could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVersion {
    pub build: u32,
    pub revision: Result<u32, String>,
}

impl std::fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.revision {
            Ok(revision) => write!(f, "{}.{revision}", self.build),
            Err(_) => write!(f, "{}", self.build),
        }
    }
}

/// Windows 10 version 1809 and Server 2019. Earlier builds lack `DeriveCapabilitySidsFromName`
/// and no longer receive security updates.
pub const MINIMUM_BUILD: u32 = 17763;

/// The first update revision of each affected build that contains the fix for CVE-2021-41338,
/// a bypass of the AppContainer firewall rules, from the CVE record
/// <https://www.cve.org/CVERecord?id=CVE-2021-41338>. `None`: the build never received the fix.
/// Builds at or above `MINIMUM_BUILD` that are not listed were released with the fix.
const FIREWALL_BYPASS_FIXED: &[(u32, Option<u32>)] = &[
    (17763, Some(2237)), // Windows 10 1809, Server 2019
    (18362, None),       // Windows 10 1903, out of service before the fix
    (18363, Some(1854)), // Windows 10 1909
    (19041, Some(1288)), // Windows 10 2004, Server 2004
    (19042, Some(1288)), // Windows 10 20H2, Server 20H2
    (19043, Some(1288)), // Windows 10 21H1
    (20348, Some(288)),  // Server 2022
    (22000, Some(258)),  // Windows 11 21H2
];

/// Why the host is too old for any AppContainer requirement, or `None`.
pub fn below_minimum(version: &WindowsVersion) -> Option<String> {
    (version.build < MINIMUM_BUILD).then(|| {
        format!(
            "sandy needs Windows 10 version 1809 (build {MINIMUM_BUILD}) or later; this host runs \
             build {version}"
        )
    })
}

/// Why AppContainer network isolation cannot be trusted on this host, or `None`. A build without
/// the fix is a shortfall; an affected build whose update revision sandy cannot read is
/// indeterminate, because the read can pass.
pub fn firewall_bypass(version: &WindowsVersion) -> Option<Problem> {
    let &(_, fixed) = FIREWALL_BYPASS_FIXED
        .iter()
        .find(|(build, _)| *build == version.build)?;
    let problem = match (fixed, &version.revision) {
        (None, _) => Problem::Unavailable(format!(
            "build {} never received the fix for CVE-2021-41338, which lets AppContainer \
             processes bypass the network isolation; update Windows to a supported version",
            version.build
        )),
        (Some(fixed), Ok(revision)) if *revision >= fixed => return None,
        (Some(fixed), Ok(_)) => Problem::Unavailable(format!(
            "build {version} lacks the fix for CVE-2021-41338, which lets AppContainer processes \
             bypass the network isolation; install the updates up to {}.{fixed} or later",
            version.build
        )),
        (Some(fixed), Err(reason)) => Problem::Indeterminate(format!(
            "cannot read the update revision of build {}, which needs {}.{fixed} or later for \
             the fix of CVE-2021-41338: {reason}",
            version.build, version.build
        )),
    };
    Some(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(build: u32, revision: u32) -> WindowsVersion {
        WindowsVersion {
            build,
            revision: Ok(revision),
        }
    }

    fn unavailable(problem: Option<Problem>) -> bool {
        matches!(problem, Some(Problem::Unavailable(_)))
    }

    #[test]
    fn refuses_builds_before_1809() {
        assert!(below_minimum(&version(17134, 2208)).is_some());
        assert!(below_minimum(&version(17763, 0)).is_none());
        assert!(below_minimum(&version(26200, 0)).is_none());
    }

    /// A revision read successfully that lacks the fix is a lasting shortfall.
    #[test]
    fn needs_the_firewall_fix_on_affected_builds() {
        for (build, fixed) in [(17763, 2237), (18363, 1854), (19041, 1288), (19043, 1288)] {
            assert!(
                unavailable(firewall_bypass(&version(build, fixed - 1))),
                "{build}"
            );
            assert!(firewall_bypass(&version(build, fixed)).is_none(), "{build}");
        }
        assert!(unavailable(firewall_bypass(&version(20348, 287))));
        assert!(firewall_bypass(&version(22000, 258)).is_none());
    }

    #[test]
    fn build_18362_never_got_the_fix() {
        assert!(unavailable(firewall_bypass(&version(18362, 9999))));
        let unread = WindowsVersion {
            build: 18362,
            revision: Err("access denied".into()),
        };
        assert!(unavailable(firewall_bypass(&unread)));
    }

    /// An affected build whose revision cannot be read fails closed, and as indeterminate: the
    /// registry read can pass, so it must not make sandy pick a level without network isolation.
    #[test]
    fn unknown_revision_of_an_affected_build_is_indeterminate() {
        let unknown = WindowsVersion {
            build: 19044,
            revision: Err("access denied".into()),
        };
        assert!(
            firewall_bypass(&unknown).is_none(),
            "released after the fix"
        );
        let affected = WindowsVersion {
            build: 19043,
            revision: Err("Access is denied. (os error 5)".into()),
        };
        match firewall_bypass(&affected) {
            Some(Problem::Indeterminate(reason)) => {
                assert!(reason.contains("19043.1288"), "{reason}");
                assert!(reason.contains("os error 5"), "{reason}");
            }
            other => panic!("not indeterminate: {other:?}"),
        }
    }

    #[test]
    fn later_builds_need_nothing() {
        for build in [19044, 19045, 22621, 22631, 26100, 26200] {
            assert!(firewall_bypass(&version(build, 1)).is_none(), "{build}");
        }
    }
}
