use std::path::{Path, PathBuf};

use crate::plan::Requirement;
use crate::policy::{
    EnvironmentPolicy, ExposedPort, NetworkAccess, PathMetadata, Policy, PolicyError, SignalScope,
    SystemAccess, WindowsPolicy,
};

/// Access to one path and everything beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathAccess {
    Read,
    ReadExec,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Canonical absolute path: symbolic links resolved, so backends that match on paths
    /// (macOS) and backends that match on inodes (Linux) see the same object.
    pub path: PathBuf,
    pub access: PathAccess,
    pub is_dir: bool,
}

/// A validated policy with canonical paths, ready for a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    /// One rule per path, sorted by path. No path is both writable and executable, also not
    /// through nesting.
    pub paths: Vec<PathRule>,
    /// Canonical path of the target executable, when the policy was resolved for one.
    pub program: Option<PathBuf>,
    pub system: SystemAccess,
    pub ip: NetworkAccess,
    pub unix_sockets: NetworkAccess,
    pub expose: Vec<ExposedPort>,
    pub signals: SignalScope,
    pub path_metadata: PathMetadata,
    pub environment: EnvironmentPolicy,
    pub windows: WindowsPolicy,
}

impl ResolvedPolicy {
    /// Validates `policy` and resolves its paths. `program` is the target executable; it gets
    /// read and execute access to the file itself.
    pub fn resolve(policy: &Policy, program: Option<&Path>) -> Result<Self, PolicyError> {
        let filesystem = &policy.filesystem;
        let mut rules = Vec::new();
        for (paths, access) in [
            (&filesystem.read, PathAccess::Read),
            (&filesystem.read_exec, PathAccess::ReadExec),
            (&filesystem.read_write, PathAccess::ReadWrite),
        ] {
            for path in paths {
                rules.push(resolve_path(path, access)?);
            }
        }
        let mut program_path = None;
        if let Some(program) = program {
            let rule = resolve_path(program, PathAccess::ReadExec)?;
            if rule.is_dir {
                return Err(PolicyError::ProgramNotAFile(rule.path));
            }
            program_path = Some(rule.path.clone());
            rules.push(rule);
        }

        let paths = merge(rules)?;
        check_writable_not_executable(&paths)?;
        check_nothing_inside_writable(&paths)?;
        validate_environment(&policy.environment)?;
        validate_expose(&policy.network.expose, policy.network.ip)?;

        Ok(ResolvedPolicy {
            paths,
            program: program_path,
            system: filesystem.system,
            ip: policy.network.ip,
            unix_sockets: policy.network.unix_sockets,
            expose: policy.network.expose.clone(),
            signals: policy.process.signals,
            path_metadata: policy.linux.path_metadata,
            environment: policy.environment.clone(),
            windows: policy.windows.clone(),
        })
    }

    /// Everything the backend must enforce for this policy. The baseline items apply to every
    /// policy; the others follow from what the policy denies.
    pub fn requirements(&self) -> Vec<Requirement> {
        let mut requirements = vec![
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
            Requirement::ProcessMemoryIsolated,
            Requirement::InheritedHandlesClosed,
            Requirement::EnvironmentControlled,
        ];
        if self.ip == NetworkAccess::None {
            requirements.push(Requirement::IpNetworkDenied);
        }
        if self.unix_sockets == NetworkAccess::None {
            requirements.push(Requirement::UnixSocketsDenied);
        }
        if self.signals == SignalScope::Isolated {
            requirements.push(Requirement::SignalsIsolated);
        }
        if self.path_metadata == PathMetadata::Deny {
            requirements.push(Requirement::MetadataConfined);
        }
        if !self.expose.is_empty() {
            requirements.push(Requirement::ExposedPortsRelayed);
        }
        requirements
    }
}

fn resolve_path(path: &Path, access: PathAccess) -> Result<PathRule, PolicyError> {
    if !path.is_absolute() {
        return Err(PolicyError::RelativePath(path.to_path_buf()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|source| PolicyError::PathNotFound {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = canonical
        .metadata()
        .map_err(|source| PolicyError::PathNotFound {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(PathRule {
        path: canonical,
        access,
        is_dir: metadata.is_dir(),
    })
}

/// Keeps one rule per path. Read is contained in both other levels; read-exec and read-write on
/// the same path is a conflict that `check_writable_not_executable` reports.
fn merge(mut rules: Vec<PathRule>) -> Result<Vec<PathRule>, PolicyError> {
    rules.sort_by(|a, b| a.path.cmp(&b.path).then(a.access.cmp(&b.access)));
    let mut merged: Vec<PathRule> = Vec::with_capacity(rules.len());
    for rule in rules {
        match merged.last_mut() {
            Some(last) if last.path == rule.path => {
                let pair = (last.access, rule.access);
                if pair == (PathAccess::ReadExec, PathAccess::ReadWrite) {
                    return Err(PolicyError::WritableAndExecutable {
                        writable: rule.path,
                        executable: last.path.clone(),
                    });
                }
                last.access = last.access.max(rule.access);
            }
            _ => merged.push(rule),
        }
    }
    Ok(merged)
}

/// Rules apply to everything beneath a path, so a writable directory inside an executable one
/// (or the reverse) is writable and executable. The target could then drop a program that a
/// process outside the sandbox later runs.
fn check_writable_not_executable(rules: &[PathRule]) -> Result<(), PolicyError> {
    let writable = rules.iter().filter(|r| r.access == PathAccess::ReadWrite);
    for w in writable {
        let executable = rules.iter().filter(|r| r.access == PathAccess::ReadExec);
        for x in executable {
            if w.path.starts_with(&x.path) || x.path.starts_with(&w.path) {
                return Err(PolicyError::WritableAndExecutable {
                    writable: w.path.clone(),
                    executable: x.path.clone(),
                });
            }
        }
    }
    Ok(())
}

/// sandy resolves symbolic links in policy paths at every start. A policy path inside a writable
/// path could be replaced with a symbolic link by the target, and the next start would then grant
/// access to wherever that link points.
fn check_nothing_inside_writable(rules: &[PathRule]) -> Result<(), PolicyError> {
    let writable = rules.iter().filter(|r| r.access == PathAccess::ReadWrite);
    for w in writable {
        let nested = rules
            .iter()
            .find(|r| r.path != w.path && r.path.starts_with(&w.path));
        if let Some(nested) = nested {
            return Err(PolicyError::InsideWritable {
                path: nested.path.clone(),
                writable: w.path.clone(),
            });
        }
    }
    Ok(())
}

/// Exposed ports listen on loopback only, so a relay never makes the target reachable from other
/// machines. The target must be able to listen, which needs IP networking in this version.
fn validate_expose(expose: &[ExposedPort], ip: NetworkAccess) -> Result<(), PolicyError> {
    let invalid = |expose: &ExposedPort, reason| PolicyError::InvalidExpose {
        expose: *expose,
        reason,
    };
    for (index, entry) in expose.iter().enumerate() {
        if ip != NetworkAccess::All {
            return Err(invalid(entry, "the program needs ip = \"all\" to listen"));
        }
        if !entry.listen.ip().is_loopback() {
            return Err(invalid(entry, "listen must be a loopback address"));
        }
        if entry.listen.port() == 0 || entry.port == 0 {
            return Err(invalid(entry, "ports must not be 0"));
        }
        if entry.listen == entry.target() {
            return Err(invalid(entry, "listen and the program's port must differ"));
        }
        let collides =
            |other: &ExposedPort| other.listen == entry.listen || other.target() == entry.listen;
        if expose[..index].iter().any(collides) {
            return Err(invalid(entry, "listen address is used twice"));
        }
    }
    Ok(())
}

fn validate_environment(environment: &EnvironmentPolicy) -> Result<(), PolicyError> {
    let names = environment.pass.iter().chain(environment.set.keys());
    for name in names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(PolicyError::InvalidEnvironmentName(name.clone()));
        }
    }
    for (name, value) in &environment.set {
        if value.contains('\0') {
            return Err(PolicyError::InvalidEnvironmentValue(name.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sandy-core-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn policy_with(read: &[&Path], read_exec: &[&Path], read_write: &[&Path]) -> Policy {
        let mut policy = Policy::default();
        policy.filesystem.read = read.iter().map(|p| p.to_path_buf()).collect();
        policy.filesystem.read_exec = read_exec.iter().map(|p| p.to_path_buf()).collect();
        policy.filesystem.read_write = read_write.iter().map(|p| p.to_path_buf()).collect();
        policy
    }

    #[test]
    fn rejects_relative_path() {
        let policy = policy_with(&[Path::new("relative")], &[], &[]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::RelativePath(_)));
    }

    #[test]
    fn rejects_missing_path() {
        let dir = temp_dir();
        let policy = policy_with(&[&dir.join("missing")], &[], &[]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::PathNotFound { .. }));
    }

    #[test]
    fn merges_duplicate_paths_to_the_wider_access() {
        let dir = temp_dir();
        let policy = policy_with(&[&dir], &[&dir], &[]);
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        assert_eq!(resolved.paths.len(), 1);
        assert_eq!(resolved.paths[0].access, PathAccess::ReadExec);
    }

    #[test]
    fn rejects_same_path_writable_and_executable() {
        let dir = temp_dir();
        let policy = policy_with(&[], &[&dir], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn rejects_writable_inside_executable() {
        let dir = temp_dir();
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[], &[&dir], &[&data]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn rejects_executable_inside_writable() {
        let dir = temp_dir();
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let policy = policy_with(&[], &[&bin], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn accepts_sibling_writable_and_executable() {
        let dir = temp_dir();
        let bin = dir.join("bin");
        let data = dir.join("data");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[], &[&bin], &[&data]);
        let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
        assert_eq!(resolved.paths.len(), 2);
    }

    #[test]
    fn rejects_paths_inside_a_writable_path() {
        let dir = temp_dir();
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).unwrap();
        for policy in [
            policy_with(&[&nested], &[], &[&dir]),
            policy_with(&[], &[], &[&dir, &nested]),
        ] {
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(
                matches!(error, PolicyError::InsideWritable { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn accepts_a_writable_path_inside_a_readable_one() {
        let dir = temp_dir();
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let policy = policy_with(&[&dir], &[], &[&data]);
        assert!(ResolvedPolicy::resolve(&policy, None).is_ok());
    }

    #[test]
    fn program_gets_read_exec_on_the_file() {
        let dir = temp_dir();
        let program = dir.join("program");
        fs::write(&program, b"").unwrap();
        let resolved = ResolvedPolicy::resolve(&Policy::default(), Some(&program)).unwrap();
        assert_eq!(
            resolved.paths,
            vec![PathRule {
                path: program,
                access: PathAccess::ReadExec,
                is_dir: false,
            }]
        );
    }

    #[test]
    fn program_inside_writable_directory_is_rejected() {
        let dir = temp_dir();
        let program = dir.join("program");
        fs::write(&program, b"").unwrap();
        let policy = policy_with(&[], &[], &[&dir]);
        let error = ResolvedPolicy::resolve(&policy, Some(&program)).unwrap_err();
        assert!(matches!(error, PolicyError::WritableAndExecutable { .. }));
    }

    #[test]
    fn program_must_be_a_file() {
        let dir = temp_dir();
        let error = ResolvedPolicy::resolve(&Policy::default(), Some(&dir)).unwrap_err();
        assert!(matches!(error, PolicyError::ProgramNotAFile(_)));
    }

    #[test]
    fn rejects_invalid_environment_names() {
        for name in ["", "A=B", "A\0"] {
            let mut policy = Policy::default();
            policy.environment.pass.push(name.to_string());
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(matches!(error, PolicyError::InvalidEnvironmentName(_)));
        }
    }

    fn expose(listen: &str, port: u16) -> ExposedPort {
        ExposedPort {
            listen: listen.parse().unwrap(),
            port,
        }
    }

    fn with_expose(ip: NetworkAccess, entries: &[ExposedPort]) -> Policy {
        let mut policy = Policy::default();
        policy.network.ip = ip;
        policy.network.expose = entries.to_vec();
        policy
    }

    #[test]
    fn accepts_loopback_expose_with_ip() {
        for listen in ["127.0.0.1:18080", "[::1]:18080"] {
            let policy = with_expose(NetworkAccess::All, &[expose(listen, 8080)]);
            let resolved = ResolvedPolicy::resolve(&policy, None).unwrap();
            let requirements = resolved.requirements();
            assert!(requirements.contains(&Requirement::ExposedPortsRelayed));
        }
    }

    #[test]
    fn rejects_invalid_expose() {
        let cases = [
            with_expose(NetworkAccess::None, &[expose("127.0.0.1:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("0.0.0.0:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("192.168.1.2:18080", 8080)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:0", 8080)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:18080", 0)]),
            with_expose(NetworkAccess::All, &[expose("127.0.0.1:8080", 8080)]),
            with_expose(
                NetworkAccess::All,
                &[
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:18080", 8081),
                ],
            ),
            with_expose(
                NetworkAccess::All,
                &[
                    expose("127.0.0.1:18080", 8080),
                    expose("127.0.0.1:8080", 8081),
                ],
            ),
        ];
        for policy in cases {
            let error = ResolvedPolicy::resolve(&policy, None).unwrap_err();
            assert!(
                matches!(error, PolicyError::InvalidExpose { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn no_expose_no_relay_requirement() {
        let resolved = ResolvedPolicy::resolve(&Policy::default(), None).unwrap();
        assert!(
            !resolved
                .requirements()
                .contains(&Requirement::ExposedPortsRelayed)
        );
    }

    #[test]
    fn requirements_follow_denials() {
        let mut policy = Policy::default();
        let baseline = [
            Requirement::FilesystemConfined,
            Requirement::NoPrivilegeEscalation,
            Requirement::ProcessMemoryIsolated,
            Requirement::InheritedHandlesClosed,
            Requirement::EnvironmentControlled,
        ];

        let all_denied = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(baseline.iter().all(|r| all_denied.contains(r)));
        assert!(all_denied.contains(&Requirement::IpNetworkDenied));
        assert!(all_denied.contains(&Requirement::UnixSocketsDenied));
        assert!(!all_denied.contains(&Requirement::SignalsIsolated));
        assert!(all_denied.contains(&Requirement::MetadataConfined));

        policy.network.ip = NetworkAccess::All;
        policy.network.unix_sockets = NetworkAccess::All;
        policy.process.signals = SignalScope::Isolated;
        policy.linux.path_metadata = PathMetadata::Allow;
        let allowed = ResolvedPolicy::resolve(&policy, None)
            .unwrap()
            .requirements();
        assert!(baseline.iter().all(|r| allowed.contains(r)));
        assert!(!allowed.contains(&Requirement::IpNetworkDenied));
        assert!(!allowed.contains(&Requirement::UnixSocketsDenied));
        assert!(allowed.contains(&Requirement::SignalsIsolated));
        assert!(!allowed.contains(&Requirement::MetadataConfined));
    }
}
