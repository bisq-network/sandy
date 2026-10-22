//! The Windows versions this backend supports.

/// Build and update revision (UBR) of the host. The revision is `None` when it could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsVersion {
    pub build: u32,
    pub revision: Option<u32>,
}

impl std::fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.revision {
            Some(revision) => write!(f, "{}.{revision}", self.build),
            None => write!(f, "{}", self.build),
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
pub fn below_minimum(version: WindowsVersion) -> Option<String> {
    (version.build < MINIMUM_BUILD).then(|| {
        format!(
            "sandy needs Windows 10 version 1809 (build {MINIMUM_BUILD}) or later; this host runs \
             build {version}"
        )
    })
}

/// Why AppContainer network isolation cannot be trusted on this host, or `None`.
pub fn firewall_bypass(version: WindowsVersion) -> Option<String> {
    let &(_, fixed) = FIREWALL_BYPASS_FIXED
        .iter()
        .find(|(build, _)| *build == version.build)?;
    let reason = match (fixed, version.revision) {
        (None, _) => format!(
            "build {} never received the fix for CVE-2021-41338, which lets AppContainer \
             processes bypass the network isolation; update Windows to a supported version",
            version.build
        ),
        (Some(fixed), Some(revision)) if revision >= fixed => return None,
        (Some(fixed), Some(_)) => format!(
            "build {version} lacks the fix for CVE-2021-41338, which lets AppContainer processes \
             bypass the network isolation; install the updates up to {}.{fixed} or later",
            version.build
        ),
        (Some(fixed), None) => format!(
            "cannot read the update revision of build {}; it needs {}.{fixed} or later for the \
             fix of CVE-2021-41338",
            version.build, version.build
        ),
    };
    Some(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(build: u32, revision: u32) -> WindowsVersion {
        WindowsVersion {
            build,
            revision: Some(revision),
        }
    }

    #[test]
    fn refuses_builds_before_1809() {
        assert!(below_minimum(version(17134, 2208)).is_some());
        assert!(below_minimum(version(17763, 0)).is_none());
        assert!(below_minimum(version(26200, 0)).is_none());
    }

    #[test]
    fn needs_the_firewall_fix_on_affected_builds() {
        for (build, fixed) in [(17763, 2237), (18363, 1854), (19041, 1288), (19043, 1288)] {
            assert!(
                firewall_bypass(version(build, fixed - 1)).is_some(),
                "{build}"
            );
            assert!(firewall_bypass(version(build, fixed)).is_none(), "{build}");
        }
        assert!(firewall_bypass(version(20348, 287)).is_some());
        assert!(firewall_bypass(version(22000, 258)).is_none());
    }

    #[test]
    fn build_18362_never_got_the_fix() {
        assert!(firewall_bypass(version(18362, 9999)).is_some());
    }

    #[test]
    fn unknown_revision_of_an_affected_build_fails_closed() {
        let unknown = WindowsVersion {
            build: 19044,
            revision: None,
        };
        assert!(firewall_bypass(unknown).is_none(), "released after the fix");
        let affected = WindowsVersion {
            build: 19043,
            revision: None,
        };
        assert!(firewall_bypass(affected).is_some());
    }

    #[test]
    fn later_builds_need_nothing() {
        for build in [19044, 19045, 22621, 22631, 26100, 26200] {
            assert!(firewall_bypass(version(build, 1)).is_none(), "{build}");
        }
    }
}
