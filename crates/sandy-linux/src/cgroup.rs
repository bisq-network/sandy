//! The cgroup limits of sandy's own process. Resource limits are a non-goal, so sandy sets none
//! and removes none. They matter here for one reason: a program inside the sandbox cannot see
//! the limits it runs under, because `/proc` and `/sys/fs/cgroup` are not in the minimal system
//! set, so a runtime that sizes its heap or its thread pool from the cgroup uses the numbers of
//! the whole host instead. That ends in an out-of-memory kill or in far too many threads. sandy
//! reports the limit it found and leaves it to the integrator to pass it on, because the policy
//! decides the environment of the program.

use std::path::Path;

/// The tightest limits that apply to this process, each `None` when nothing limits it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `memory.max` in bytes.
    pub memory: Option<u64>,
    /// `cpu.max` as a number of CPUs, rounded up, as a runtime would use it.
    pub cpus: Option<u64>,
}

impl Limits {
    fn is_empty(self) -> bool {
        self.memory.is_none() && self.cpus.is_none()
    }
}

/// The limits of this process, read from the version 2 cgroup hierarchy. A limit on any cgroup
/// between this one and the root applies, so the tightest value of the whole chain counts.
pub fn limits() -> Limits {
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    match unified_path(&own) {
        Some(path) => limits_in(Path::new("/sys/fs/cgroup"), path),
        None => Limits::default(),
    }
}

/// The cgroup of the version 2 hierarchy, which `/proc/self/cgroup` lists as `0::<path>`.
fn unified_path(own: &str) -> Option<&str> {
    own.lines().find_map(|line| line.strip_prefix("0::"))
}

fn limits_in(root: &Path, path: &str) -> Limits {
    let mut limits = Limits::default();
    let mut directory = root.join(path.trim_start_matches('/'));
    loop {
        limits.memory = tightest(limits.memory, memory_max(&directory.join("memory.max")));
        limits.cpus = tightest(limits.cpus, cpu_max(&directory.join("cpu.max")));
        if !directory.pop() || !directory.starts_with(root) {
            return limits;
        }
    }
}

fn tightest(found: Option<u64>, other: Option<u64>) -> Option<u64> {
    match (found, other) {
        (Some(found), Some(other)) => Some(found.min(other)),
        (found, other) => found.or(other),
    }
}

/// `memory.max` holds a number of bytes or `max`.
fn memory_max(file: &Path) -> Option<u64> {
    std::fs::read_to_string(file).ok()?.trim().parse().ok()
}

/// `cpu.max` holds a quota and a period in microseconds, or `max` and a period. The number of
/// CPUs is rounded up, like the runtimes that read it.
fn cpu_max(file: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(file).ok()?;
    let mut fields = text.split_whitespace();
    let quota: u64 = fields.next()?.parse().ok()?;
    let period: u64 = fields.next()?.parse().ok()?;
    (period > 0).then(|| quota.div_ceil(period).max(1))
}

/// What to tell the integrator about a limit the program cannot see. `None` when nothing limits
/// this process.
pub fn note(limits: Limits) -> Option<String> {
    if limits.is_empty() {
        return None;
    }
    let mut found = Vec::new();
    let mut pass = Vec::new();
    let mut java = Vec::new();
    if let Some(cpus) = limits.cpus {
        found.push(format!("{cpus} CPU(s) from cpu.max"));
        pass.push(format!("--set-env GOMAXPROCS={cpus}"));
        java.push(format!("-XX:ActiveProcessorCount={cpus}"));
    }
    if let Some(memory) = limits.memory {
        found.push(format!("{memory} bytes from memory.max"));
        java.push(format!("-XX:MaxRAM={memory}"));
    }
    pass.push(format!(
        "--set-env JAVA_TOOL_OPTIONS=\"{}\"",
        java.join(" ")
    ));
    Some(format!(
        "this process runs under a cgroup limit that the program cannot see ({}): /proc and \
         /sys/fs/cgroup are not in the minimal system set, so a runtime sizes its heap and its \
         thread pool from the memory and the CPU count of the whole host. Pass the limit to the \
         program yourself, for example {}. sandy does not set these variables, because the \
         policy decides the environment of the program",
        found.join(", "),
        pass.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tree(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("sandy-cgroup-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("user.slice/app.scope")).unwrap();
        root
    }

    fn write(root: &Path, path: &str, text: &str) {
        std::fs::write(root.join(path), text).unwrap();
    }

    #[test]
    fn the_unified_cgroup_is_the_one_numbered_zero() {
        let own = "1:net_cls:/\n0::/user.slice/app.scope\n";
        assert_eq!(unified_path(own), Some("/user.slice/app.scope"));
        assert_eq!(unified_path("1:net_cls:/\n"), None);
    }

    /// A limit on a cgroup above this one applies too, and the tightest of the chain counts.
    #[test]
    fn the_tightest_limit_of_the_chain_is_reported() {
        let root = tree("chain");
        write(&root, "user.slice/memory.max", "1073741824\n");
        write(&root, "user.slice/cpu.max", "max 100000\n");
        write(&root, "user.slice/app.scope/memory.max", "536870912\n");
        write(&root, "user.slice/app.scope/cpu.max", "150000 100000\n");
        assert_eq!(
            limits_in(&root, "/user.slice/app.scope"),
            Limits {
                memory: Some(536_870_912),
                cpus: Some(2),
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_cgroup_without_limits_reports_nothing() {
        let root = tree("none");
        write(&root, "user.slice/memory.max", "max\n");
        write(&root, "user.slice/app.scope/cpu.max", "max 100000\n");
        let limits = limits_in(&root, "/user.slice/app.scope");
        assert_eq!(limits, Limits::default());
        assert_eq!(note(limits), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The note names the limit and what to pass on, and sets nothing itself.
    #[test]
    fn the_note_names_the_limit_and_the_variables() {
        let note = note(Limits {
            memory: Some(536_870_912),
            cpus: Some(1),
        })
        .unwrap();
        assert!(note.contains("1 CPU(s) from cpu.max"), "{note}");
        assert!(note.contains("536870912 bytes from memory.max"), "{note}");
        assert!(note.contains("--set-env GOMAXPROCS=1"), "{note}");
        assert!(note.contains("-XX:ActiveProcessorCount=1"), "{note}");
        assert!(note.contains("-XX:MaxRAM=536870912"), "{note}");
    }
}
