//! Generation of the Seatbelt profile (SBPL) from a resolved policy. Pure code, so it runs and is
//! tested on every platform.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sandy_core::{NetworkAccess, PathAccess, ResolvedPolicy, SignalScope, SystemAccess};

use crate::system::{self, SystemAccess as Grant};

/// A Seatbelt profile and the values of its parameters.
///
/// The text contains no path. Every path reaches the sandbox as the value of a parameter that
/// the text names with `(param "NAME")`. The sandbox library hands parameter values to the
/// profile as strings and never parses them as profile code, so no character in a path can
/// change the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub text: String,
    /// Parameter names and values, in the order the text uses them. Names are unique.
    pub parameters: Vec<(String, PathBuf)>,
}

/// Builds the profile that enforces `policy`. Rules that appear later take precedence over
/// earlier ones, so the denials that protect the sandbox come last.
pub fn generate(policy: &ResolvedPolicy) -> Profile {
    let mut writer = Writer::default();
    writer.line("(version 1)");
    writer.line("(deny default)");
    writer.comment(
        "(deny default) does not cover some operations. These are denied explicitly; the rules\n\
         below allow them again only for the target itself, for policy paths and for harmless\n\
         ioctls. file-write* includes mode, owner, flags, times, extended attributes and ACLs.",
    );
    writer.line("(deny process-info* file-map-executable file-ioctl file-write*)");
    process_rules(&mut writer, policy.signals);
    ioctl_rules(&mut writer);
    sysctl_rules(&mut writer);
    if policy.system == SystemAccess::Minimal {
        system_rules(&mut writer);
    }
    policy_path_rules(&mut writer, policy);
    network_rules(&mut writer, policy);
    ancestor_rules(&mut writer);
    protection_rules(&mut writer, policy);
    Profile {
        text: writer.text,
        parameters: writer.parameters,
    }
}

#[derive(Default)]
struct Writer {
    text: String,
    parameters: Vec<(String, PathBuf)>,
    counters: BTreeMap<&'static str, usize>,
    /// Every path the profile grants access to, for the ancestor rule.
    granted: BTreeSet<PathBuf>,
}

impl Writer {
    fn line(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
    }

    fn comment(&mut self, comment: &str) {
        self.text.push('\n');
        for line in comment.lines() {
            self.text.push_str("; ");
            self.text.push_str(line);
            self.text.push('\n');
        }
    }

    /// Adds `path` as the parameter `<prefix>_<n>` and returns `(param "<prefix>_<n>")`.
    fn param(&mut self, prefix: &'static str, path: &Path) -> String {
        let counter = self.counters.entry(prefix).or_default();
        let name = format!("{prefix}_{counter}");
        *counter += 1;
        let reference = format!("(param \"{name}\")");
        self.parameters.push((name, path.to_path_buf()));
        reference
    }

    /// Like `param`, and records `path` as granted.
    fn grant(&mut self, prefix: &'static str, path: &Path) -> String {
        self.granted.insert(path.to_path_buf());
        self.param(prefix, path)
    }

    fn rule(&mut self, action: &str, operations: &[&str], filters: &[String]) {
        if filters.is_empty() {
            return;
        }
        self.text.push('(');
        self.text.push_str(action);
        for operation in operations {
            self.text.push(' ');
            self.text.push_str(operation);
        }
        for filter in filters {
            self.text.push_str("\n  ");
            self.text.push_str(filter);
        }
        self.text.push_str(")\n");
    }
}

fn subpath(param: String) -> String {
    format!("(subpath {param})")
}

fn literal(param: String) -> String {
    format!("(literal {param})")
}

const READ: &[&str] = &["file-read*", "file-test-existence"];
const READ_EXEC: &[&str] = &[
    "file-read*",
    "file-test-existence",
    "file-map-executable",
    "process-exec*",
];
/// `file-clone` lets `clonefile` and `std::fs::copy` work inside writable paths.
const READ_WRITE: &[&str] = &[
    "file-read*",
    "file-test-existence",
    "file-write*",
    "file-clone",
];
const CODE: &[&str] = &["file-read*", "file-test-existence", "file-map-executable"];
const READ_WRITE_DEVICE: &[&str] = &["file-read*", "file-test-existence", "file-write-data"];
const METADATA: &[&str] = &["file-read-metadata", "file-test-existence"];

fn process_rules(writer: &mut Writer, signals: SignalScope) {
    writer.comment("Processes. Children inherit the sandbox.");
    writer.line("(allow process-fork)");
    writer.line("(allow process-info* (target self))");
    match signals {
        SignalScope::Any => writer.line("(allow signal)"),
        SignalScope::Isolated => writer.line("(allow signal (target self) (target same-sandbox))"),
    }
}

fn ioctl_rules(writer: &mut Writer) {
    writer.comment(
        "ioctls on open files and devices: only the two that fcntl(F_SETFL) issues and two that\n\
         read terminal state (FIONBIO, FIOASYNC, TIOCGETA, TIOCGWINSZ).",
    );
    let filters: Vec<String> = system::ALLOWED_IOCTLS
        .iter()
        .map(|request| format!("(ioctl-command {request})"))
        .collect();
    writer.rule("allow", &["file-ioctl"], &filters);
}

fn sysctl_rules(writer: &mut Writer) {
    writer.comment("Hardware and operating system facts.");
    let filters: Vec<String> = system::SYSCTL_NAMES
        .iter()
        .map(|name| format!("(sysctl-name \"{name}\")"))
        .chain(
            system::SYSCTL_PREFIXES
                .iter()
                .map(|prefix| format!("(sysctl-name-prefix \"{prefix}\")")),
        )
        .collect();
    writer.rule("allow", &["sysctl-read"], &filters);
}

fn system_rules(writer: &mut Writer) {
    writer.comment("System paths that dyld and libSystem need (system = \"minimal\").");
    let groups: [(Grant, &[&str]); 6] = [
        (Grant::CodeTree, CODE),
        (Grant::ReadTree, READ),
        (Grant::ReadFile, READ),
        (Grant::ReadDevice, READ),
        (Grant::ReadWriteDevice, READ_WRITE_DEVICE),
        (Grant::Symlink, METADATA),
    ];
    for (grant, operations) in groups {
        let filters: Vec<String> = system::MINIMAL
            .iter()
            .filter(|entry| entry.access == grant)
            .map(|entry| {
                let param = writer.grant("SYSTEM", Path::new(entry.path));
                match grant {
                    Grant::CodeTree | Grant::ReadTree => subpath(param),
                    _ => literal(param),
                }
            })
            .collect();
        writer.rule("allow", operations, &filters);
    }
}

fn policy_path_rules(writer: &mut Writer, policy: &ResolvedPolicy) {
    writer.comment("Policy paths. A directory rule covers everything beneath it.");
    let groups: [(PathAccess, &'static str, &[&str]); 3] = [
        (PathAccess::Read, "READ", READ),
        (PathAccess::ReadExec, "READ_EXEC", READ_EXEC),
        (PathAccess::ReadWrite, "READ_WRITE", READ_WRITE),
    ];
    for (access, prefix, operations) in groups {
        let filters: Vec<String> = policy
            .paths
            .iter()
            .filter(|rule| rule.access == access)
            .map(|rule| {
                let param = writer.grant(prefix, &rule.path);
                // A file rule must stay a file rule: `subpath` would also cover entries of a
                // directory that later replaces the file.
                if rule.is_dir {
                    subpath(param)
                } else {
                    literal(param)
                }
            })
            .collect();
        writer.rule("allow", operations, &filters);
    }
}

fn network_rules(writer: &mut Writer, policy: &ResolvedPolicy) {
    writer.comment("Networking. A Unix socket can be created, but not bound or connected.");
    writer.line("(allow system-socket (socket-domain AF_UNIX))");
    if policy.ip == NetworkAccess::All {
        writer.comment(
            "IP networking, and name resolution: getaddrinfo asks mDNSResponder through its\n\
             Unix socket.",
        );
        writer.line("(allow network-outbound (remote ip))");
        writer.line("(allow network-bind network-inbound (local ip))");
        let resolver = writer.grant("DNS", Path::new(system::DNS_RESOLVER_SOCKET));
        writer.rule("allow", &["network-outbound"], &[literal(resolver)]);
        let hosts = writer.grant("DNS", Path::new(system::HOSTS_FILE));
        writer.rule("allow", READ, &[literal(hosts)]);
        let var = writer.grant("DNS", Path::new(system::VAR_SYMLINK));
        writer.rule("allow", METADATA, &[literal(var)]);
    }
    if policy.unix_sockets == NetworkAccess::All {
        writer.comment("Unix sockets.");
        writer.line("(allow network-outbound (remote unix-socket))");
        writer.line("(allow network-bind network-inbound (local unix-socket))");
    }
}

/// Metadata of every ancestor of a granted path, so that realpath, getcwd and directory
/// creation can walk to the granted path. It reveals no directory contents.
fn ancestor_rules(writer: &mut Writer) {
    let ancestors: BTreeSet<PathBuf> = writer
        .granted
        .iter()
        .flat_map(|path| path.ancestors().skip(1).map(Path::to_path_buf))
        .collect();
    writer.comment("Ancestors of granted paths: metadata only.");
    let filters: Vec<String> = ancestors
        .iter()
        .map(|path| literal(writer.param("ANCESTOR", path)))
        .collect();
    writer.rule("allow", METADATA, &filters);
}

fn protection_rules(writer: &mut Writer, policy: &ResolvedPolicy) {
    writer.comment(
        "The root of a writable path cannot be deleted or replaced. Otherwise the target could\n\
         put a symbolic link in its place, and the next run would resolve the path to the\n\
         link's target. (Policy paths inside writable paths are rejected before this.)",
    );
    let filters: Vec<String> = policy
        .paths
        .iter()
        .filter(|rule| rule.access == PathAccess::ReadWrite)
        .map(|rule| literal(writer.param("ANCHOR", &rule.path)))
        .collect();
    writer.rule(
        "deny",
        &["file-write-unlink", "file-write-create"],
        &filters,
    );

    writer.comment(
        "Operations that (deny default) may not cover and that nothing allows again: hard links\n\
         (a link would make a file from outside reachable through a writable path), NVRAM and\n\
         IOKit properties, task ports of other processes, and ptrace attach (system-debug).",
    );
    writer.line(
        "(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read \
         mach-task-inspect system-debug)",
    );

    writer.comment("TIOCSTI would type commands into the terminal of the caller.");
    writer.line(&format!(
        "(deny file-ioctl (ioctl-command {}))",
        system::TIOCSTI
    ));

    writer.comment("Setuid and setgid programs never start.");
    writer.line("(deny process-exec* (file-mode #o4000) (file-mode #o2000))");

    writer.comment(
        "F_MAKECOMPRESSED (80) and F_TRANSFEREXTENTS (110) change files through read-only\n\
         descriptors; (deny default) does not cover them.",
    );
    writer.line("(deny system-fcntl (fcntl-command 80 110))");

    writer.comment("No Mach or XPC services, also not the services of application bundles.");
    writer.line("(deny mach-lookup (xpc-service-name-prefix \"\"))");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandy_core::{EnvironmentPolicy, PathMetadata, PathRule, WindowsPolicy};

    fn rule(path: &str, access: PathAccess, is_dir: bool) -> PathRule {
        PathRule {
            path: PathBuf::from(path),
            access,
            is_dir,
        }
    }

    fn policy(paths: Vec<PathRule>) -> ResolvedPolicy {
        ResolvedPolicy {
            paths,
            program: None,
            system: SystemAccess::Minimal,
            ip: NetworkAccess::None,
            unix_sockets: NetworkAccess::None,
            signals: SignalScope::Any,
            path_metadata: PathMetadata::Deny,
            environment: EnvironmentPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }

    /// A policy with one path of each kind, rooted at `root`.
    fn typical(root: &str) -> ResolvedPolicy {
        let mut policy = policy(vec![
            rule(&format!("{root}/bin/program"), PathAccess::ReadExec, false),
            rule(&format!("{root}/data"), PathAccess::ReadWrite, true),
            rule(&format!("{root}/etc/config"), PathAccess::Read, false),
            rule(&format!("{root}/share"), PathAccess::Read, true),
        ]);
        policy.program = Some(PathBuf::from(format!("{root}/bin/program")));
        policy
    }

    fn references(text: &str) -> Vec<String> {
        text.split("(param \"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap().to_string())
            .collect()
    }

    #[test]
    fn expected_text_for_the_strictest_policy() {
        let mut policy = typical("/srv");
        policy.system = SystemAccess::None;
        policy.signals = SignalScope::Isolated;
        let profile = generate(&policy);
        let sysctls: String = system::SYSCTL_NAMES
            .iter()
            .map(|name| format!("\n  (sysctl-name \"{name}\")"))
            .chain(
                system::SYSCTL_PREFIXES
                    .iter()
                    .map(|prefix| format!("\n  (sysctl-name-prefix \"{prefix}\")")),
            )
            .collect();
        let expected = format!(
            r#"(version 1)
(deny default)

; (deny default) does not cover some operations. These are denied explicitly; the rules
; below allow them again only for the target itself, for policy paths and for harmless
; ioctls. file-write* includes mode, owner, flags, times, extended attributes and ACLs.
(deny process-info* file-map-executable file-ioctl file-write*)

; Processes. Children inherit the sandbox.
(allow process-fork)
(allow process-info* (target self))
(allow signal (target self) (target same-sandbox))

; ioctls on open files and devices: only the two that fcntl(F_SETFL) issues and two that
; read terminal state (FIONBIO, FIOASYNC, TIOCGETA, TIOCGWINSZ).
(allow file-ioctl
  (ioctl-command 2147772030)
  (ioctl-command 2147772029)
  (ioctl-command 1078490131)
  (ioctl-command 1074295912))

; Hardware and operating system facts.
(allow sysctl-read{sysctls})

; Policy paths. A directory rule covers everything beneath it.
(allow file-read* file-test-existence
  (literal (param "READ_0"))
  (subpath (param "READ_1")))
(allow file-read* file-test-existence file-map-executable process-exec*
  (literal (param "READ_EXEC_0")))
(allow file-read* file-test-existence file-write* file-clone
  (subpath (param "READ_WRITE_0")))

; Networking. A Unix socket can be created, but not bound or connected.
(allow system-socket (socket-domain AF_UNIX))

; Ancestors of granted paths: metadata only.
(allow file-read-metadata file-test-existence
  (literal (param "ANCESTOR_0"))
  (literal (param "ANCESTOR_1"))
  (literal (param "ANCESTOR_2"))
  (literal (param "ANCESTOR_3")))

; The root of a writable path cannot be deleted or replaced. Otherwise the target could
; put a symbolic link in its place, and the next run would resolve the path to the
; link's target. (Policy paths inside writable paths are rejected before this.)
(deny file-write-unlink file-write-create
  (literal (param "ANCHOR_0")))

; Operations that (deny default) may not cover and that nothing allows again: hard links
; (a link would make a file from outside reachable through a writable path), NVRAM and
; IOKit properties, task ports of other processes, and ptrace attach (system-debug).
(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read mach-task-inspect system-debug)

; TIOCSTI would type commands into the terminal of the caller.
(deny file-ioctl (ioctl-command 2147578994))

; Setuid and setgid programs never start.
(deny process-exec* (file-mode #o4000) (file-mode #o2000))

; F_MAKECOMPRESSED (80) and F_TRANSFEREXTENTS (110) change files through read-only
; descriptors; (deny default) does not cover them.
(deny system-fcntl (fcntl-command 80 110))

; No Mach or XPC services, also not the services of application bundles.
(deny mach-lookup (xpc-service-name-prefix ""))
"#
        );
        assert_eq!(profile.text, expected);
        let parameters: Vec<(&str, &str)> = profile
            .parameters
            .iter()
            .map(|(name, path)| (name.as_str(), path.to_str().unwrap()))
            .collect();
        assert_eq!(
            parameters,
            vec![
                ("READ_0", "/srv/etc/config"),
                ("READ_1", "/srv/share"),
                ("READ_EXEC_0", "/srv/bin/program"),
                ("READ_WRITE_0", "/srv/data"),
                ("ANCESTOR_0", "/"),
                ("ANCESTOR_1", "/srv"),
                ("ANCESTOR_2", "/srv/bin"),
                ("ANCESTOR_3", "/srv/etc"),
                ("ANCHOR_0", "/srv/data"),
            ]
        );
    }

    #[test]
    fn text_contains_no_path_and_every_parameter_is_used_once() {
        let mut policy = typical("/srv");
        policy.ip = NetworkAccess::All;
        policy.unix_sockets = NetworkAccess::All;
        let profile = generate(&policy);
        assert!(!profile.text.contains('/'), "{}", profile.text);
        let mut used = references(&profile.text);
        let mut defined: Vec<String> = profile.parameters.iter().map(|(n, _)| n.clone()).collect();
        used.sort();
        defined.sort();
        assert_eq!(used, defined);
        let unique: BTreeSet<&String> = defined.iter().collect();
        assert_eq!(unique.len(), defined.len(), "duplicate parameter names");
        let values: Vec<&Path> = profile
            .parameters
            .iter()
            .map(|(_, p)| p.as_path())
            .collect();
        for rule in &policy.paths {
            assert!(
                values.contains(&rule.path.as_path()),
                "{}",
                rule.path.display()
            );
        }
        for entry in system::MINIMAL {
            assert!(values.contains(&Path::new(entry.path)), "{}", entry.path);
        }
    }

    #[test]
    fn path_characters_cannot_change_the_profile() {
        let benign = generate(&typical("/srv"));
        // One path component each, so the policy keeps the shape of the benign one. A backslash
        // is a separator on Windows, so that case runs only where macOS paths behave the same.
        let backslash = cfg!(unix).then_some("a\\\"b");
        for component in [
            "a\"b",
            "a)(allow default)(b",
            "a\n(allow default)\n;",
            "a;b",
            "a#\"b\"",
            "a b(param \"READ_0\")",
            "\u{e9}\u{301}\u{202e}",
        ]
        .into_iter()
        .chain(backslash)
        {
            let hostile = format!("/{component}");
            let profile = generate(&typical(&hostile));
            assert_eq!(profile.text, benign.text, "path {hostile:?}");
            let read = profile.parameters.iter().find(|(name, _)| name == "READ_0");
            assert_eq!(
                read.map(|(_, path)| path.clone()),
                Some(PathBuf::from(format!("{hostile}/etc/config")))
            );
        }
    }

    #[test]
    fn file_rules_cover_only_the_file() {
        let profile = generate(&policy(vec![
            rule("/a/file", PathAccess::Read, false),
            rule("/a/dir", PathAccess::Read, true),
        ]));
        assert!(
            profile
                .text
                .contains("(literal (param \"READ_0\"))\n  (subpath (param \"READ_1\")))")
        );
    }

    #[test]
    fn only_read_exec_paths_are_executable() {
        let profile = generate(&typical("/srv"));
        let executable: Vec<&str> = profile
            .text
            .lines()
            .filter(|line| line.contains("process-exec") || line.contains("file-map-executable"))
            .collect();
        assert_eq!(
            executable,
            vec![
                "(deny process-info* file-map-executable file-ioctl file-write*)",
                "(allow file-read* file-test-existence file-map-executable",
                "(allow file-read* file-test-existence file-map-executable process-exec*",
                "(deny process-exec* (file-mode #o4000) (file-mode #o2000))",
            ]
        );
        let code: Vec<&str> = system::MINIMAL
            .iter()
            .filter(|entry| entry.access == Grant::CodeTree)
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            code,
            vec![
                "/usr/lib",
                "/System/Library/dyld",
                "/System/Volumes/Preboot/Cryptexes/OS",
                "/System/Cryptexes/OS"
            ]
        );
    }

    #[test]
    fn protections_come_after_every_allow() {
        let profile = generate(&typical("/srv"));
        let last_allow = profile.text.rfind("(allow").unwrap();
        let first_protection = profile.text.find("(deny file-write-unlink").unwrap();
        assert!(last_allow < first_protection);
    }

    #[test]
    fn writable_roots_cannot_be_deleted_or_replaced() {
        let profile = generate(&policy(vec![
            rule("/r", PathAccess::Read, true),
            rule("/r/w", PathAccess::ReadWrite, true),
            rule("/w", PathAccess::ReadWrite, false),
        ]));
        let anchors: Vec<&str> = profile
            .parameters
            .iter()
            .filter(|(name, _)| name.starts_with("ANCHOR_"))
            .map(|(_, path)| path.to_str().unwrap())
            .collect();
        assert_eq!(anchors, vec!["/r/w", "/w"]);
        assert!(profile.text.contains(
            "(deny file-write-unlink file-write-create\n  (literal (param \"ANCHOR_0\"))\n  \
             (literal (param \"ANCHOR_1\")))"
        ));
    }

    #[test]
    fn network_rules_follow_the_policy() {
        let rules = |ip, unix_sockets| {
            let mut policy = typical("/srv");
            policy.ip = ip;
            policy.unix_sockets = unix_sockets;
            let profile = generate(&policy);
            let resolver = profile
                .parameters
                .iter()
                .find(|(_, path)| path == Path::new(system::DNS_RESOLVER_SOCKET))
                .map(|(name, _)| format!("(literal (param \"{name}\"))"));
            let resolver_rule = |action: &str| {
                resolver.as_ref().is_some_and(|filter| {
                    profile
                        .text
                        .contains(&format!("({action} network-outbound\n  {filter})"))
                })
            };
            [
                profile
                    .text
                    .contains("(allow network-outbound (remote ip))"),
                profile
                    .text
                    .contains("(allow network-outbound (remote unix-socket))"),
                resolver_rule("allow"),
                resolver_rule("deny"),
            ]
        };
        use NetworkAccess::{All, None};
        // IP, Unix sockets, resolver allowed, resolver denied.
        assert_eq!(rules(None, None), [false, false, false, false]);
        assert_eq!(rules(All, None), [true, false, true, false]);
        // All Unix sockets include the resolver, as on every platform.
        assert_eq!(rules(None, All), [false, true, false, false]);
        assert_eq!(rules(All, All), [true, true, true, false]);
    }

    #[test]
    fn signals_follow_the_policy() {
        let mut policy = typical("/srv");
        assert!(generate(&policy).text.contains("\n(allow signal)\n"));
        policy.signals = SignalScope::Isolated;
        let text = generate(&policy).text;
        assert!(text.contains("\n(allow signal (target self) (target same-sandbox))\n"));
        assert!(!text.contains("\n(allow signal)\n"));
    }

    #[test]
    fn system_none_adds_no_system_path() {
        let mut policy = typical("/srv");
        policy.system = SystemAccess::None;
        let profile = generate(&policy);
        assert!(!profile.text.contains("SYSTEM_"));
        let values: Vec<&Path> = profile
            .parameters
            .iter()
            .map(|(_, p)| p.as_path())
            .collect();
        assert!(!values.contains(&Path::new("/dev/null")));
        assert!(!values.contains(&Path::new("/usr/lib")));
    }

    #[test]
    fn generates_no_mach_lookup_allowance() {
        let mut policy = typical("/srv");
        policy.ip = NetworkAccess::All;
        policy.unix_sockets = NetworkAccess::All;
        let text = generate(&policy).text;
        assert!(!text.contains("(allow mach"));
        assert!(!text.contains("(allow appleevent"));
        assert!(!text.contains("(allow lsopen"));
        assert!(!text.contains("(allow iokit"));
        assert!(!text.contains("(allow ipc"));
        assert!(!text.contains("(allow file-link"));
        let clone: Vec<&str> = text.lines().filter(|l| l.contains("file-clone")).collect();
        assert_eq!(
            clone,
            vec!["(allow file-read* file-test-existence file-write* file-clone"]
        );
    }

    #[test]
    fn allows_only_listed_ioctls_and_never_tiocsti() {
        let text = generate(&typical("/srv")).text;
        let allowed: Vec<&str> = text
            .split("(allow file-ioctl")
            .skip(1)
            .map(|rest| &rest[..rest.find("))\n").unwrap() + 1])
            .collect();
        assert_eq!(allowed.len(), 1);
        for request in system::ALLOWED_IOCTLS {
            assert!(allowed[0].contains(&format!("(ioctl-command {request})")));
        }
        assert!(!system::ALLOWED_IOCTLS.contains(&system::TIOCSTI));
        let deny = format!("(deny file-ioctl (ioctl-command {}))", system::TIOCSTI);
        assert!(text.rfind(&deny).unwrap() > text.rfind("(allow").unwrap());
    }
}
