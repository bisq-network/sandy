//! Generation of the Seatbelt profile (SBPL) from a resolved policy. Pure code, so it runs and is
//! tested on every platform.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sandy_core::{
    ChildProcesses, IpAccess, NetworkAccess, PathAccess, ResolvedPolicy, SignalScope, SystemAccess,
};

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
    hiding_rules(&mut writer);
    process_rules(&mut writer, policy.signals, policy.children);
    ioctl_rules(&mut writer);
    sysctl_rules(&mut writer);
    if policy.system == SystemAccess::Minimal {
        system_rules(&mut writer);
    }
    policy_path_rules(&mut writer, policy);
    network_rules(&mut writer, policy);
    ancestor_rules(&mut writer);
    link_rules(&mut writer);
    protection_rules(&mut writer, policy);
    Profile {
        text: writer.text,
        parameters: writer.parameters,
    }
}

/// One path through the relay: it accepts connections on `listen` and connects each one to
/// `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPair {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

/// The relay pairs of `policy`. An exposed port leads from outside into the program; a forwarded
/// port is the mirror and leads from the program to a loopback service outside. One relay
/// process serves both kinds.
pub fn relay_pairs(policy: &ResolvedPolicy) -> Vec<RelayPair> {
    let exposed = policy.expose.iter().map(|exposure| RelayPair {
        listen: exposure.listen,
        target: exposure.target(),
    });
    let forwarded = policy.forward.iter().map(|forward| RelayPair {
        listen: forward.listen(),
        target: forward.to,
    });
    exposed.chain(forwarded).collect()
}

/// The ports that the relay binds at the wildcard addresses of both families without listening:
/// under `ip = "private"` the forwarded ports, which the program's profile lets it reach at every
/// address of this Mac. A connection to one of them at an address other than the relay's
/// listener then finds sandy's socket there and goes unanswered, and, by XNU's `in_pcbbind`, no
/// process of another user can bind the port at any address while the relay runs.
pub fn held_ports(policy: &ResolvedPolicy) -> Vec<u16> {
    if policy.ip != IpAccess::Private {
        return Vec::new();
    }
    let ports: BTreeSet<u16> = policy.forward.iter().map(|entry| entry.port).collect();
    ports.into_iter().collect()
}

/// The profile of the watcher of `process.end_with_parent`. Like the relay, it keeps running the
/// code that sandy has already loaded and needs no file. It registered its kqueue events before
/// the profile applies, and it only waits and signals the program.
pub fn watcher_profile() -> Profile {
    let mut writer = Writer::default();
    writer.line("(version 1)");
    writer.line("(deny default)");
    writer.comment("(deny default) does not cover these operations, and the watcher needs none.");
    writer.line("(deny process-info* file-map-executable file-ioctl file-write*)");
    writer.comment("The program runs in another sandbox; the watcher ends it.");
    writer.line("(allow signal)");
    hardening_rules(&mut writer);
    Profile {
        text: writer.text,
        parameters: writer.parameters,
    }
}

/// The profile of the relay process. The relay keeps running the code that sandy has already
/// loaded and never executes anything, so it needs no file at all: it accepts on the listeners
/// sandy passed it and connects only to the targets. Every address is loopback and every port a
/// number, so the text needs no parameters.
pub fn relay_profile(pairs: &[RelayPair]) -> Profile {
    let mut writer = Writer::default();
    writer.line("(version 1)");
    writer.line("(deny default)");
    writer.comment("(deny default) does not cover these operations, and the relay needs none.");
    writer.line("(deny process-info* file-map-executable file-ioctl file-write*)");
    writer.comment("Accept on the relay's listeners; connect only to the targets.");
    let inbound: Vec<String> = pairs
        .iter()
        .map(|pair| format!("(local ip \"localhost:{}\")", pair.listen.port()))
        .collect();
    writer.rule("allow", &["network-inbound"], &inbound);
    let outbound: Vec<String> = pairs
        .iter()
        .map(|pair| format!("(remote ip \"localhost:{}\")", pair.target.port()))
        .collect();
    writer.rule("allow", &["network-outbound"], &outbound);
    writer.comment("Non-blocking mode for the sockets (connect with a timeout).");
    let flags: Vec<String> = [system::FIONBIO, system::FIOASYNC]
        .iter()
        .map(|request| format!("(ioctl-command {request})"))
        .collect();
    writer.rule("allow", &["file-ioctl"], &flags);
    hardening_rules(&mut writer);
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

/// Outside the policy every path answers like a path that does not exist, and every other
/// process like a process that does not exist. The rules below allow the policy paths and the
/// program's own process again. Writes keep EPERM: a write to a `read` path must not say that
/// the path is missing.
fn hiding_rules(writer: &mut Writer) {
    writer.comment(
        "Outside the policy, paths look missing and other processes look gone. (deny default)\n\
         does not cover file-test-existence, the only check of access, statfs, chdir and of\n\
         the path that getattrlist returns, so it is denied here. ENOENT and ESRCH are the\n\
         answers for a path and a process that do not exist.",
    );
    writer.line("(deny file-read* file-test-existence (with errno ENOENT))");
    writer.line("(deny process-info* (with errno ESRCH))");
}

fn process_rules(writer: &mut Writer, signals: SignalScope, children: ChildProcesses) {
    writer.comment("Processes. Children inherit the sandbox.");
    if children != ChildProcesses::None {
        writer.line("(allow process-fork)");
    }
    writer.line("(allow process-info* (target self))");
    match signals {
        SignalScope::Any => writer.line("(allow signal)"),
        SignalScope::Isolated => {
            writer.line("(allow signal (target self) (target same-sandbox))");
            writer.comment(
                "F_SETOWN makes the kernel send SIGIO to any process, of this or another user,\n\
                 when a socket or pipe becomes ready, and the kernel sends it with no owner\n\
                 check that `signal` covers. A profile cannot filter the owner, so the command\n\
                 is denied. The ioctls FIOSETOWN, SIOCSPGRP and TIOCSPGRP set the same owner on\n\
                 sockets and pipes, and no operation reaches them.",
            );
            writer.line(&format!(
                "(deny system-fcntl (fcntl-command {}))",
                system::F_SETOWN
            ));
        }
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
    let groups: [(Grant, &[&str]); 7] = [
        (Grant::CodeTree, CODE),
        (Grant::ReadTree, READ),
        (Grant::ReadFile, READ),
        (Grant::ReadDevice, READ),
        (Grant::ReadWriteDevice, READ_WRITE_DEVICE),
        (Grant::ReadWriteDeviceTree, READ_WRITE_DEVICE),
        (Grant::Symlink, METADATA),
    ];
    for (grant, operations) in groups {
        let filters: Vec<String> = system::MINIMAL
            .iter()
            .filter(|entry| entry.access == grant)
            .map(|entry| {
                let param = writer.grant("SYSTEM", Path::new(entry.path));
                match grant {
                    Grant::CodeTree | Grant::ReadTree | Grant::ReadWriteDeviceTree => {
                        subpath(param)
                    }
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
    writer.comment(
        "Networking. Creating a socket is separate from binding and connecting it. A Unix socket\n\
         can always be created (socketpair). Seatbelt never checks the creation of IP sockets, so\n\
         they can be created in any case; binding and connecting them follow the rules below.",
    );
    writer.line("(allow system-socket (socket-domain AF_UNIX))");
    match policy.ip {
        IpAccess::None => {}
        IpAccess::Private => {
            writer.comment(
                "ip = \"private\": TCP only, out only to the forwarded ports and in only on the\n\
                 exposed ports. Seatbelt's localhost is every address of this Mac, not loopback,\n\
                 so the relay holds the forwarded ports at the wildcard addresses. No UDP and no\n\
                 name resolution.",
            );
            let forwarded: BTreeSet<u16> = policy.forward.iter().map(|entry| entry.port).collect();
            let filters: Vec<String> = forwarded
                .iter()
                .map(|port| format!("(remote tcp \"localhost:{port}\")"))
                .collect();
            writer.rule("allow", &["network-outbound"], &filters);
            let exposed: BTreeSet<u16> = policy.expose.iter().map(|entry| entry.port).collect();
            let filters: Vec<String> = exposed
                .iter()
                .map(|port| format!("(local tcp \"localhost:{port}\")"))
                .collect();
            writer.rule("allow", &["network-bind", "network-inbound"], &filters);
        }
        IpAccess::Client => {
            writer.comment(
                "IP networking out, and name resolution: getaddrinfo asks mDNSResponder through\n\
                 its Unix socket. network-inbound covers listen and accept, and every datagram\n\
                 that a socket which is not connected receives, so it is allowed for UDP only:\n\
                 a TCP socket cannot listen. Seatbelt cannot tell port 0 from a chosen port, so\n\
                 binding stays allowed.",
            );
            writer.line("(allow network-outbound (remote ip))");
            writer.line("(allow network-bind (local ip))");
            writer.line("(allow network-inbound (local udp))");
        }
        IpAccess::All => {
            writer.comment(
                "IP networking, and name resolution: getaddrinfo asks mDNSResponder through its\n\
                 Unix socket.",
            );
            writer.line("(allow network-outbound (remote ip))");
            writer.line("(allow network-bind network-inbound (local ip))");
        }
    }
    if matches!(policy.ip, IpAccess::Client | IpAccess::All) {
        // A connect looks up the socket's path first, which is a file-test-existence.
        let resolver = writer.grant("DNS", Path::new(system::DNS_RESOLVER_SOCKET));
        writer.rule(
            "allow",
            &["network-outbound", "file-test-existence"],
            &[literal(resolver)],
        );
        let hosts = writer.grant("DNS", Path::new(system::HOSTS_FILE));
        writer.rule("allow", READ, &[literal(hosts)]);
        let var = writer.grant("DNS", Path::new(system::VAR_SYMLINK));
        writer.rule("allow", METADATA, &[literal(var)]);
    }
    if policy.unix_sockets == NetworkAccess::All {
        writer.comment(
            "Unix sockets. A connect looks up the socket's path, which Seatbelt checks as\n\
             file-test-existence before the kernel knows that the path is a socket, so a socket\n\
             outside the policy needs it for every path.",
        );
        writer.line("(allow network-outbound (remote unix-socket))");
        writer.line("(allow network-bind network-inbound (local unix-socket))");
        writer.line("(allow file-test-existence)");
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

/// Paths spelled through a granted link of the system set, such as `/etc/hosts` for
/// `/private/etc/hosts`. Seatbelt checks file-test-existence for the path as the program spelled
/// it and again for the path the link leads to, so this grants nothing that the rules for the
/// real paths do not.
fn link_rules(writer: &mut Writer) {
    let links: Vec<&Path> = system::DIRECTORY_LINKS
        .iter()
        .map(Path::new)
        .filter(|link| writer.granted.contains(*link))
        .collect();
    if links.is_empty() {
        return;
    }
    writer.comment("Paths spelled through the links of the system set.");
    let filters: Vec<String> = links
        .into_iter()
        .map(|link| subpath(writer.param("LINK", link)))
        .collect();
    writer.rule("allow", &["file-test-existence"], &filters);
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
    if policy.children == ChildProcesses::None {
        writer.comment(
            "process.children = \"none\": no fork, vfork or posix_spawn. Threads, and replacing\n\
             the program's own image, stay possible.",
        );
        writer.line("(deny process-fork)");
    }
    if policy.children == ChildProcesses::Contained {
        writer.comment(
            "process.children = \"contained\": no process may leave the process group that sandy\n\
             ends with the program: no setpgid, no setsid, and no posix_spawn, whose flags would\n\
             change the group inside the kernel. fork, vfork and execve stay possible.",
        );
        let filters: Vec<String> = system::GROUP_LEAVING_SYSCALLS
            .iter()
            .map(|(_, number)| format!("(syscall-number {number})"))
            .collect();
        writer.rule("deny", &["syscall-unix"], &filters);
    }
    writer.comment(
        "The priority, process group and session of any process ID reach no profile operation:\n\
         getpriority, getpgid, getsid. A rule cannot tell the program's own ID from another.",
    );
    let filters: Vec<String> = system::PROCESS_QUERY_SYSCALLS
        .iter()
        .map(|(_, number)| format!("(syscall-number {number})"))
        .collect();
    writer.rule("deny", &["syscall-unix"], &filters);
    if matches!(policy.ip, IpAccess::None | IpAccess::Private) {
        writer.comment(
            "ip = \"none\" and \"private\": no NECP, the kernel's network policy layer that\n\
             Network.framework works through, and no trigger of its network agents:\n\
             necp_match_policy, netagent_trigger, necp_open, necp_client_action,\n\
             necp_session_open, necp_session_action.",
        );
        let filters: Vec<String> = system::NECP_SYSCALLS
            .iter()
            .map(|(_, number)| format!("(syscall-number {number})"))
            .collect();
        writer.rule("deny", &["syscall-unix"], &filters);
    }
    hardening_rules(writer);
}

/// Denials that the profiles of the program, the relay and the watcher end with.
fn hardening_rules(writer: &mut Writer) {
    writer.comment(
        "Operations that (deny default) may not cover and that nothing allows again: hard links\n\
         (a link would make a file from outside reachable through a writable path), NVRAM and\n\
         IOKit properties, task ports of other processes, and ptrace attach (system-debug).",
    );
    writer.line(
        "(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read \
         mach-task-inspect system-debug)",
    );

    writer.comment(
        "Calls that find a file by volume id and inode number reach no file operation, so the\n\
         rules above cannot stop them: fsgetpath, fsgetpath_ext, openbyid_np, searchfs.",
    );
    let filters: Vec<String> = system::BY_ID_SYSCALLS
        .iter()
        .map(|(_, number)| format!("(syscall-number {number})"))
        .collect();
    writer.rule("deny", &["syscall-unix"], &filters);

    writer.comment(
        "The hardware UUID, which the denial of IOKit properties already hides: gethostuuid.",
    );
    let filters: Vec<String> = system::MACHINE_ID_SYSCALLS
        .iter()
        .map(|(_, number)| format!("(syscall-number {number})"))
        .collect();
    writer.rule("deny", &["syscall-unix"], &filters);

    writer.comment(
        "The list of every mounted volume reaches no file operation either, so the rules above\n\
         cannot stop it: getfsstat, getfsstat64. It names the disks of the system, including\n\
         any attached external disks.",
    );
    let filters: Vec<String> = system::VOLUME_LIST_SYSCALLS
        .iter()
        .map(|(_, number)| format!("(syscall-number {number})"))
        .collect();
    writer.rule("deny", &["syscall-unix"], &filters);

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
            ip: IpAccess::None,
            unix_sockets: NetworkAccess::None,
            expose: Vec::new(),
            forward: Vec::new(),
            egress: None,
            view: sandy_core::FileView::All,
            signals: SignalScope::Any,
            children: sandy_core::ChildProcesses::Allowed,
            end_with_parent: false,
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

; Outside the policy, paths look missing and other processes look gone. (deny default)
; does not cover file-test-existence, the only check of access, statfs, chdir and of
; the path that getattrlist returns, so it is denied here. ENOENT and ESRCH are the
; answers for a path and a process that do not exist.
(deny file-read* file-test-existence (with errno ENOENT))
(deny process-info* (with errno ESRCH))

; Processes. Children inherit the sandbox.
(allow process-fork)
(allow process-info* (target self))
(allow signal (target self) (target same-sandbox))

; F_SETOWN makes the kernel send SIGIO to any process, of this or another user,
; when a socket or pipe becomes ready, and the kernel sends it with no owner
; check that `signal` covers. A profile cannot filter the owner, so the command
; is denied. The ioctls FIOSETOWN, SIOCSPGRP and TIOCSPGRP set the same owner on
; sockets and pipes, and no operation reaches them.
(deny system-fcntl (fcntl-command 6))

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

; Networking. Creating a socket is separate from binding and connecting it. A Unix socket
; can always be created (socketpair). Seatbelt never checks the creation of IP sockets, so
; they can be created in any case; binding and connecting them follow the rules below.
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

; The priority, process group and session of any process ID reach no profile operation:
; getpriority, getpgid, getsid. A rule cannot tell the program's own ID from another.
(deny syscall-unix
  (syscall-number 100)
  (syscall-number 151)
  (syscall-number 310))

; ip = "none" and "private": no NECP, the kernel's network policy layer that
; Network.framework works through, and no trigger of its network agents:
; necp_match_policy, netagent_trigger, necp_open, necp_client_action,
; necp_session_open, necp_session_action.
(deny syscall-unix
  (syscall-number 460)
  (syscall-number 490)
  (syscall-number 501)
  (syscall-number 502)
  (syscall-number 522)
  (syscall-number 523))

; Operations that (deny default) may not cover and that nothing allows again: hard links
; (a link would make a file from outside reachable through a writable path), NVRAM and
; IOKit properties, task ports of other processes, and ptrace attach (system-debug).
(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read mach-task-inspect system-debug)

; Calls that find a file by volume id and inode number reach no file operation, so the
; rules above cannot stop them: fsgetpath, fsgetpath_ext, openbyid_np, searchfs.
(deny syscall-unix
  (syscall-number 427)
  (syscall-number 217)
  (syscall-number 479)
  (syscall-number 225))

; The hardware UUID, which the denial of IOKit properties already hides: gethostuuid.
(deny syscall-unix
  (syscall-number 142))

; The list of every mounted volume reaches no file operation either, so the rules above
; cannot stop it: getfsstat, getfsstat64. It names the disks of the system, including
; any attached external disks.
(deny syscall-unix
  (syscall-number 18)
  (syscall-number 347))

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
        policy.ip = IpAccess::All;
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
            let resolver_rule = |rule: &str| {
                resolver
                    .as_ref()
                    .is_some_and(|filter| profile.text.contains(&format!("({rule}\n  {filter})")))
            };
            [
                profile
                    .text
                    .contains("(allow network-outbound (remote ip))"),
                profile
                    .text
                    .contains("(allow network-outbound (remote unix-socket))"),
                resolver_rule("allow network-outbound file-test-existence"),
                resolver_rule("deny network-outbound"),
            ]
        };
        use NetworkAccess::{All, None};
        // IP, Unix sockets, resolver allowed, resolver denied.
        assert_eq!(rules(IpAccess::None, None), [false, false, false, false]);
        assert_eq!(rules(IpAccess::All, None), [true, false, true, false]);
        assert_eq!(rules(IpAccess::Client, None), [true, false, true, false]);
        // A private network reaches no resolver; its relay rules are TCP rules.
        assert_eq!(rules(IpAccess::Private, None), [false, false, false, false]);
        assert_eq!(rules(IpAccess::Private, All), [false, true, false, false]);
        // All Unix sockets include the resolver, as on every platform.
        assert_eq!(rules(IpAccess::None, All), [false, true, false, false]);
        assert_eq!(rules(IpAccess::All, All), [true, true, true, false]);
    }

    /// `ip = "client"` allows network-inbound for UDP only, so that a TCP socket cannot listen or
    /// accept; `ip = "all"` allows it for every IP socket.
    #[test]
    fn client_allows_inbound_only_for_udp() {
        let inbound = |ip| {
            let mut policy = typical("/srv");
            policy.ip = ip;
            generate(&policy)
                .text
                .lines()
                .filter(|line| line.starts_with("(allow") && line.contains("network-inbound"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            inbound(IpAccess::Client),
            vec!["(allow network-inbound (local udp))"]
        );
        assert_eq!(
            inbound(IpAccess::All),
            vec!["(allow network-bind network-inbound (local ip))"]
        );
        assert!(inbound(IpAccess::None).is_empty());
    }

    #[test]
    fn by_id_syscalls_are_denied_after_every_allow() {
        let mut policy = typical("/srv");
        policy.ip = IpAccess::All;
        policy.unix_sockets = NetworkAccess::All;
        let text = generate(&policy).text;
        let deny = text.find("(deny syscall-unix").unwrap();
        assert!(deny > text.rfind("(allow").unwrap());
        assert!(!text.contains("(allow syscall"));
        for (name, number) in system::BY_ID_SYSCALLS {
            assert!(
                text.contains(&format!("(syscall-number {number})")),
                "{name}"
            );
        }
    }

    #[test]
    fn relay_profile_allows_only_the_relay_ports() {
        let pairs = [
            RelayPair {
                listen: "127.0.0.1:18080".parse().unwrap(),
                target: "127.0.0.1:8080".parse().unwrap(),
            },
            RelayPair {
                listen: "[::1]:18081".parse().unwrap(),
                target: "[::1]:8081".parse().unwrap(),
            },
        ];
        let profile = relay_profile(&pairs);
        assert!(profile.parameters.is_empty());
        let allows: Vec<&str> = profile
            .text
            .lines()
            .filter(|line| line.starts_with("(allow") || line.starts_with("  ("))
            .filter(|line| !line.contains("syscall-number"))
            .collect();
        assert_eq!(
            allows,
            vec![
                "(allow network-inbound",
                "  (local ip \"localhost:18080\")",
                "  (local ip \"localhost:18081\"))",
                "(allow network-outbound",
                "  (remote ip \"localhost:8080\")",
                "  (remote ip \"localhost:8081\"))",
                "(allow file-ioctl",
                "  (ioctl-command 2147772030)",
                "  (ioctl-command 2147772029))",
            ]
        );
        assert!(profile.text.starts_with("(version 1)\n(deny default)\n"));
        assert!(
            profile
                .text
                .contains("(deny mach-lookup (xpc-service-name-prefix \"\"))")
        );
        assert!(!profile.text.contains("file-read"));
    }

    #[test]
    fn exposed_and_forwarded_ports_are_mirrored_pairs() {
        let mut policy = typical("/srv");
        policy.expose = vec![sandy_core::ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        policy.forward = vec![sandy_core::ForwardedPort {
            port: 18082,
            to: "[::1]:8082".parse().unwrap(),
        }];
        assert_eq!(
            relay_pairs(&policy),
            vec![
                RelayPair {
                    listen: "127.0.0.1:18080".parse().unwrap(),
                    target: "127.0.0.1:8080".parse().unwrap(),
                },
                RelayPair {
                    listen: "[::1]:18082".parse().unwrap(),
                    target: "[::1]:8082".parse().unwrap(),
                },
            ]
        );
        policy.expose.clear();
        policy.forward.clear();
        assert!(relay_pairs(&policy).is_empty());
    }

    #[test]
    fn children_none_denies_process_fork() {
        let mut policy = typical("/srv");
        let allowed = generate(&policy).text;
        assert!(allowed.contains("\n(allow process-fork)\n"));
        assert!(!allowed.contains("(deny process-fork)"));
        policy.children = ChildProcesses::None;
        let denied = generate(&policy).text;
        assert!(!denied.contains("(allow process-fork)"));
        let deny = denied.find("\n(deny process-fork)\n").unwrap();
        assert!(deny > denied.rfind("(allow").unwrap());
        assert!(denied.contains("process-exec*"));
    }

    #[test]
    fn children_contained_denies_leaving_the_group() {
        let mut policy = typical("/srv");
        let group_rule = "(deny syscall-unix\n  (syscall-number 82)\n  (syscall-number 147)\n  \
                          (syscall-number 244))\n";
        assert!(!generate(&policy).text.contains(group_rule));
        policy.children = ChildProcesses::Contained;
        let text = generate(&policy).text;
        assert!(text.contains("\n(allow process-fork)\n"));
        let deny = text.find(group_rule).unwrap();
        assert!(deny > text.rfind("(allow").unwrap());
        for (name, number) in system::GROUP_LEAVING_SYSCALLS {
            assert!(
                text.contains(&format!("(syscall-number {number})")),
                "{name}"
            );
        }
    }

    #[test]
    fn watcher_profile_allows_only_signals() {
        let profile = watcher_profile();
        assert!(profile.parameters.is_empty());
        assert!(profile.text.starts_with("(version 1)\n(deny default)\n"));
        let allows: Vec<&str> = profile
            .text
            .lines()
            .filter(|line| line.starts_with("(allow"))
            .collect();
        assert_eq!(allows, ["(allow signal)"]);
    }

    #[test]
    fn signals_follow_the_policy() {
        let mut policy = typical("/srv");
        let setown = format!("(deny system-fcntl (fcntl-command {}))", system::F_SETOWN);
        let open = generate(&policy).text;
        assert!(open.contains("\n(allow signal)\n"));
        // With signals = "any" the program may signal every process anyway.
        assert!(!open.contains(&setown));
        policy.signals = SignalScope::Isolated;
        let text = generate(&policy).text;
        assert!(text.contains("\n(allow signal (target self) (target same-sandbox))\n"));
        assert!(!text.contains("\n(allow signal)\n"));
        assert!(text.contains(&setown));
    }

    /// `/dev/fd` is the one tree of the system set that the target may write to, because
    /// `/dev/fd/N` is only another name for a descriptor it already holds. The links
    /// `/dev/stdin`, `/dev/stdout` and `/dev/stderr` point into it, so the lookup must pass
    /// through them.
    #[test]
    fn descriptor_paths_are_granted_as_a_tree() {
        let profile = generate(&typical("/srv"));
        let parameter = |path: &str| {
            profile
                .parameters
                .iter()
                .find(|(_, value)| value == Path::new(path))
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| panic!("{path} is not in the system set"))
        };
        let writable: String = profile
            .text
            .split("(allow file-read* file-test-existence file-write-data")
            .skip(1)
            .filter_map(|rest| rest.split_once("))\n").map(|(rule, _)| rule.to_string()))
            .collect();
        assert!(
            writable.contains(&format!("(subpath (param \"{}\"", parameter("/dev/fd"))),
            "{writable}"
        );
        for link in ["/dev/stdin", "/dev/stdout", "/dev/stderr"] {
            let metadata = profile
                .text
                .split("(allow file-read-metadata file-test-existence")
                .nth(1)
                .expect("the link rule");
            assert!(
                metadata.contains(&format!("(literal (param \"{}\"", parameter(link))),
                "{link} is not readable as a link"
            );
        }
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
        policy.ip = IpAccess::All;
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

    /// Paths outside the policy answer ENOENT, so the denial must come before every rule that
    /// allows something again. Writes keep EPERM.
    #[test]
    fn paths_outside_the_policy_look_missing() {
        let text = generate(&typical("/srv")).text;
        let rule = "\n(deny file-read* file-test-existence (with errno ENOENT))\n";
        assert_eq!(text.matches(rule).count(), 1);
        assert!(text.find(rule).unwrap() < text.find("(allow").unwrap());
        assert!(!text.contains("file-write* (with errno"));
    }

    /// Other processes answer ESRCH; the program's own process stays visible.
    #[test]
    fn other_processes_look_gone() {
        let text = generate(&typical("/srv")).text;
        let rule = "\n(deny process-info* (with errno ESRCH))\n";
        assert_eq!(text.matches(rule).count(), 1);
        let allow = text
            .find("\n(allow process-info* (target self))\n")
            .unwrap();
        assert!(text.find(rule).unwrap() < allow);
        assert!(text.find(rule).unwrap() < text.find("(allow").unwrap());
    }

    #[test]
    fn link_spellings_follow_the_granted_links() {
        let links = |system: SystemAccess, ip: IpAccess| {
            let mut policy = typical("/srv");
            policy.system = system;
            policy.ip = ip;
            let profile = generate(&policy);
            let links: Vec<String> = profile
                .parameters
                .iter()
                .filter(|(name, _)| name.starts_with("LINK_"))
                .map(|(_, path)| path.to_str().unwrap().to_string())
                .collect();
            if !links.is_empty() {
                let rule = profile
                    .text
                    .split("(allow file-test-existence\n")
                    .nth(1)
                    .unwrap();
                assert!(rule.starts_with("  (subpath (param \"LINK_0\"))"), "{rule}");
            }
            links
        };
        assert_eq!(
            links(SystemAccess::Minimal, IpAccess::None),
            ["/etc", "/tmp", "/var"]
        );
        // The resolver reaches its socket through /var.
        assert_eq!(links(SystemAccess::None, IpAccess::Client), ["/var"]);
        assert!(links(SystemAccess::None, IpAccess::Private).is_empty());
        assert!(links(SystemAccess::None, IpAccess::None).is_empty());
    }

    /// A connect to a Unix socket outside the policy needs file-test-existence for its path, so
    /// `unix_sockets = "all"` allows it everywhere, after the rule that denies it.
    #[test]
    fn unix_sockets_all_lets_every_path_be_tested() {
        let mut policy = typical("/srv");
        let rule = "\n(allow file-test-existence)\n";
        assert!(!generate(&policy).text.contains(rule));
        policy.unix_sockets = NetworkAccess::All;
        let text = generate(&policy).text;
        let deny = text
            .find("(deny file-read* file-test-existence (with errno ENOENT))")
            .unwrap();
        assert!(text.find(rule).unwrap() > deny);
    }

    /// A private network is relay only: TCP out to the forwarded ports and in on the exposed
    /// ports, each port once, and nothing else of IP, no name resolution included.
    #[test]
    fn a_private_network_reaches_only_the_relay_ports() {
        let mut policy = typical("/srv");
        policy.ip = IpAccess::Private;
        policy.forward = vec![
            sandy_core::ForwardedPort {
                port: 18082,
                to: "[::1]:8082".parse().unwrap(),
            },
            sandy_core::ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap(),
            },
            sandy_core::ForwardedPort {
                port: 18081,
                to: "[::1]:8083".parse().unwrap(),
            },
        ];
        policy.expose = vec![
            sandy_core::ExposedPort {
                listen: "127.0.0.1:18080".parse().unwrap(),
                port: 8080,
            },
            sandy_core::ExposedPort {
                listen: "[::1]:18090".parse().unwrap(),
                port: 8080,
            },
        ];
        let profile = generate(&policy);
        let network: Vec<&str> = profile
            .text
            .split("\n(allow network-")
            .skip(1)
            .map(|rule| &rule[..rule.find("))").unwrap() + 2])
            .collect();
        assert_eq!(
            network,
            [
                "outbound\n  (remote tcp \"localhost:18081\")\n  (remote tcp \"localhost:18082\"))",
                "bind network-inbound\n  (local tcp \"localhost:8080\"))",
            ]
        );
        assert!(
            !profile
                .parameters
                .iter()
                .any(|(_, path)| path == Path::new(system::DNS_RESOLVER_SOCKET)),
            "{:?}",
            profile.parameters
        );
        let necp = format!("(syscall-number {})", system::NECP_SYSCALLS[0].1);
        assert!(profile.text.contains(&necp));

        // Without relays the program gets no IP rule at all.
        policy.forward.clear();
        policy.expose.clear();
        assert!(!generate(&policy).text.contains("(allow network-"));
    }

    #[test]
    fn only_a_private_network_holds_the_forwarded_ports() {
        let mut policy = typical("/srv");
        policy.forward = vec![
            sandy_core::ForwardedPort {
                port: 18082,
                to: "127.0.0.1:8082".parse().unwrap(),
            },
            sandy_core::ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap(),
            },
            sandy_core::ForwardedPort {
                port: 18081,
                to: "[::1]:8083".parse().unwrap(),
            },
        ];
        policy.expose = vec![sandy_core::ExposedPort {
            listen: "127.0.0.1:18080".parse().unwrap(),
            port: 8080,
        }];
        for ip in [IpAccess::Client, IpAccess::All] {
            policy.ip = ip;
            assert!(held_ports(&policy).is_empty(), "{ip:?}");
        }
        policy.ip = IpAccess::Private;
        assert_eq!(held_ports(&policy), [18081, 18082]);
        policy.forward.clear();
        assert!(held_ports(&policy).is_empty());
    }

    #[test]
    fn necp_is_denied_unless_ip_reaches_the_network() {
        let necp = |ip| {
            let mut policy = typical("/srv");
            policy.ip = ip;
            let text = generate(&policy).text;
            let denied: Vec<bool> = system::NECP_SYSCALLS
                .iter()
                .map(|(_, number)| text.contains(&format!("(syscall-number {number})")))
                .collect();
            if denied.iter().any(|denied| *denied) {
                let deny = text.find("(syscall-number 501)").unwrap();
                assert!(deny > text.rfind("(allow").unwrap());
            }
            denied
        };
        assert!(necp(IpAccess::None).iter().all(|denied| *denied));
        assert!(necp(IpAccess::Private).iter().all(|denied| *denied));
        assert!(necp(IpAccess::Client).iter().all(|denied| !denied));
        assert!(necp(IpAccess::All).iter().all(|denied| !denied));
    }

    #[test]
    fn process_queries_are_denied_for_every_policy() {
        for ip in [
            IpAccess::None,
            IpAccess::Private,
            IpAccess::Client,
            IpAccess::All,
        ] {
            for signals in [SignalScope::Any, SignalScope::Isolated] {
                let mut policy = typical("/srv");
                policy.ip = ip;
                policy.signals = signals;
                let text = generate(&policy).text;
                let rule = "(deny syscall-unix\n  (syscall-number 100)\n  (syscall-number 151)\n  \
                            (syscall-number 310))\n";
                let deny = text.find(rule).unwrap();
                assert!(deny > text.rfind("(allow").unwrap());
            }
        }
        let names: Vec<&str> = system::PROCESS_QUERY_SYSCALLS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(names, ["getpriority", "getpgid", "getsid"]);
    }
}
