use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use lexopt::prelude::*;
use sandy_core::{
    ChildProcesses, Egress, EgressReach, ExposedPort, FileView, ForwardedPort, IpAccess,
    NetworkAccess, PathMetadata, Policy, SignalScope, SystemAccess, Win32k,
};

pub const USAGE: &str = "\
Usage:
  sandy run [OPTIONS] [--] PROGRAM [ARGS...]   run PROGRAM inside the sandbox
  sandy check [OPTIONS] [[--] PROGRAM]         show how this host enforces the policy
  sandy setup [OPTIONS]                        prepare the host (needs admin rights on Windows,
                                               and on Linux under Ubuntu's AppArmor restriction)
  sandy setup --remove [OPTIONS]               take back what setup and the runs of the policy
                                               left on the host

PROGRAM must be an absolute path. sandy refuses to start it when any restriction of the policy
cannot be enforced on this host.

Options (they extend the policy file):
  --policy FILE              read the policy from a TOML file
  --read PATH                allow reading PATH (repeatable)
  --read-exec PATH           allow reading and executing PATH (repeatable)
  --read-write PATH          allow reading and writing PATH (repeatable)
  --system minimal|none      add the minimal system paths (default: minimal)
  --view all|policy          policy makes paths outside the policy look missing (default: all)
  --ip all|client|private|none
                             IP networking; client connects out but takes no connections;
                             private keeps the program on a loopback of its own, reached only
                             through --expose, --forward and --egress (default: none)
  --unix-sockets all|none    Unix domain sockets (default: none)
  --signals any|isolated     who the program may signal (default: any)
  --children allowed|none|contained
                             whether the program may start other processes; contained ends
                             them all when the program ends (default: allowed)
  --end-with-parent          end the program when the process that started sandy ends
                             (needs --signals isolated)
  --parent-pid PID           with --end-with-parent: the process ID of the caller; sandy
                             refuses to start if its parent is another process
  --parent-start TOKEN       with --parent-pid: when that process started, so sandy can tell
                             the caller from a process that got its ID later; the caller may
                             then start sandy through a wrapper (see the platform docs)
  --status-fd N              report the program's process ID and how it ended on descriptor N
                             (on Windows: an inherited handle); run only
  --explain                  name the paths of the run that the policy does not grant, on
                             standard error; off by default, it sees not every denial, and it
                             is not available on every platform (run only)
  --explain-path PATH        say what the policy allows for PATH and which rule decides it
                             (repeatable; check only)
  --expose ADDRESS=PORT      relay connections on the loopback ADDRESS to the program's
                             loopback PORT, for example 127.0.0.1:18080=8080 (repeatable;
                             needs --ip all or --ip private)
  --forward PORT=ADDRESS     relay connections from the program to its loopback PORT to the
                             loopback ADDRESS outside, for example 18081=127.0.0.1:8081
                             (repeatable; needs --ip private, client or all)
  --egress PORT[=REACH]      a SOCKS5 broker on the program's 127.0.0.1:PORT that connects out
                             only to REACH: public (the default) or public-and-local; never to
                             this host (needs --ip private)
  --linux-path-metadata deny|allow
                             metadata changes by path on Linux (default: deny)
  --pass-env NAME            copy variable NAME into the program environment (repeatable)
  --set-env NAME=VALUE       set a variable in the program environment (repeatable)
  --appcontainer NAME        AppContainer profile name (Windows)
  --windows-win32k allow|deny
                             the system calls of win32k, the GUI part of the Windows kernel;
                             deny stops many programs that load user32.dll (default: allow)
  --cwd DIR                  working directory of the program
  -h, --help                 show this help
  -V, --version              show the version

Setup options:
  --install-copy             on Linux, install a root-owned copy of this sandy in
                             /usr/local/libexec/sandy/VERSION and prepare the host for it; for
                             a sandy whose own file is not root-owned
  --elevate                  ask for the administrator rights setup needs (pkexec on Linux,
                             UAC on Windows); --policy must then be an absolute path

Exit status: the program's status; 125 when sandy fails or refuses; for check, 0 when the policy
is enforceable, 1 when it is not, and 2 when only `sandy setup`, run once with administrator
rights, is missing; for setup, 0 when it is done or nothing is to do, 3 when it is not done and
nothing changed (the rights were not given, or setup is not allowed for this binary), and 125
when it failed.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Run,
    Check,
    Setup,
    /// `setup --remove`.
    Remove,
}

#[derive(Debug, Default)]
pub struct Overrides {
    read: Vec<PathBuf>,
    read_exec: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    system: Option<SystemAccess>,
    view: Option<FileView>,
    ip: Option<IpAccess>,
    egress: Option<Egress>,
    unix_sockets: Option<NetworkAccess>,
    signals: Option<SignalScope>,
    children: Option<ChildProcesses>,
    end_with_parent: bool,
    path_metadata: Option<PathMetadata>,
    win32k: Option<Win32k>,
    pass_env: Vec<String>,
    set_env: Vec<(String, String)>,
    appcontainer: Option<String>,
    expose: Vec<ExposedPort>,
    forward: Vec<ForwardedPort>,
}

impl Overrides {
    /// Applies the command line options to `policy`. With `from_file`, `policy` comes from a
    /// policy file, and the result names every option that replaced a stricter value of that
    /// file: the option still wins, because the caller is trusted (DESIGN.md, "Threat model"),
    /// but it widens what the program may do without the file saying so. A policy without a file
    /// is the options themselves, so there is nothing to report.
    pub fn apply(self, policy: &mut Policy, from_file: bool) -> Vec<String> {
        let mut weakened = Vec::new();
        let mut note = |option: &str, value: &str, setting: &str, before: &str| {
            if !from_file {
                return;
            }
            weakened.push(format!(
                "{option} {value} replaces {setting} = {before:?} from the policy file and allows \
                 more than the file does"
            ));
        };
        let filesystem = &mut policy.filesystem;
        filesystem.read.extend(self.read);
        filesystem.read_exec.extend(self.read_exec);
        filesystem.read_write.extend(self.read_write);
        if let Some(system) = self.system {
            if system == SystemAccess::Minimal && filesystem.system == SystemAccess::None {
                note("--system", "minimal", "system", "none");
            }
            filesystem.system = system;
        }
        if let Some(view) = self.view {
            if view == FileView::All && policy.filesystem.view == FileView::Policy {
                note("--view", "all", "view", "policy");
            }
            policy.filesystem.view = view;
        }
        if let Some(ip) = self.ip {
            if ip_strictness(ip) < ip_strictness(policy.network.ip) {
                note("--ip", ip.name(), "ip", policy.network.ip.name());
            }
            policy.network.ip = ip;
        }
        if let Some(egress) = self.egress {
            let value = format!("{}={}", egress.port, egress.reach.name());
            match policy.network.egress {
                None => note("--egress", &value, "egress", "none"),
                Some(before)
                    if before.reach == EgressReach::Public
                        && egress.reach == EgressReach::PublicAndLocal =>
                {
                    note("--egress", &value, "egress reach", before.reach.name())
                }
                Some(_) => {}
            }
            policy.network.egress = Some(egress);
        }
        if let Some(unix_sockets) = self.unix_sockets {
            if unix_sockets == NetworkAccess::All
                && policy.network.unix_sockets == NetworkAccess::None
            {
                note("--unix-sockets", "all", "unix_sockets", "none");
            }
            policy.network.unix_sockets = unix_sockets;
        }
        if let Some(signals) = self.signals {
            if signals == SignalScope::Any && policy.process.signals == SignalScope::Isolated {
                note("--signals", "any", "signals", "isolated");
            }
            policy.process.signals = signals;
        }
        if let Some(children) = self.children {
            if strictness(children) < strictness(policy.process.children) {
                note(
                    "--children",
                    children.name(),
                    "children",
                    policy.process.children.name(),
                );
            }
            policy.process.children = children;
        }
        if self.end_with_parent {
            policy.process.end_with_parent = true;
        }
        if let Some(path_metadata) = self.path_metadata {
            if path_metadata == PathMetadata::Allow
                && policy.linux.path_metadata == PathMetadata::Deny
            {
                note("--linux-path-metadata", "allow", "path_metadata", "deny");
            }
            policy.linux.path_metadata = path_metadata;
        }
        policy.environment.pass.extend(self.pass_env);
        policy.environment.set.extend(self.set_env);
        policy.network.expose.extend(self.expose);
        policy.network.forward.extend(self.forward);
        if let Some(name) = self.appcontainer {
            policy.windows.appcontainer_name = Some(name);
        }
        if let Some(win32k) = self.win32k {
            if win32k == Win32k::Allow && policy.windows.win32k == Win32k::Deny {
                note("--windows-win32k", "allow", "win32k", "deny");
            }
            policy.windows.win32k = win32k;
        }
        weakened
    }
}

/// How strict a `children` value is, higher is stricter. Only the order matters.
fn ip_strictness(ip: IpAccess) -> u8 {
    match ip {
        IpAccess::All => 0,
        IpAccess::Client => 1,
        IpAccess::Private => 2,
        IpAccess::None => 3,
    }
}

fn strictness(children: ChildProcesses) -> u8 {
    match children {
        ChildProcesses::Allowed => 0,
        ChildProcesses::Contained => 1,
        ChildProcesses::None => 2,
    }
}

#[derive(Debug)]
pub enum Command {
    Help,
    Version,
    Sandbox(Box<Invocation>),
    /// Internal: serve an exposed port. A backend starts sandy this way with a listening socket
    /// it passed by descriptor or handle number.
    Relay {
        listener: u64,
        target: SocketAddr,
    },
    /// Internal: serve a forwarded port. A backend starts sandy this way inside the sandbox; it
    /// listens on `listen` and passes each connection to the Unix domain socket at `socket`.
    Forward {
        listen: SocketAddr,
        socket: PathBuf,
    },
    /// Internal: run the egress broker (`network.egress`). A backend starts sandy this way, in a
    /// sandbox of its own, with a listening socket it passed by descriptor or handle number; the
    /// broker serves SOCKS5 on it and connects out to the destinations `reach` allows.
    Broker {
        listener: u64,
        reach: EgressReach,
    },
}

/// The internal command that runs a relay. It is not part of the documented interface.
pub const RELAY_COMMAND: &str = "__relay";

/// The internal command that runs a forward relay. It is not part of the documented interface.
pub const FORWARD_COMMAND: &str = "__forward";

/// The internal command that runs the egress broker. It is not part of the documented interface.
pub const BROKER_COMMAND: &str = "__broker";

#[derive(Debug)]
pub struct Invocation {
    pub mode: Mode,
    pub policy_file: Option<PathBuf>,
    pub overrides: Overrides,
    pub cwd: Option<PathBuf>,
    pub parent_pid: Option<u32>,
    pub parent_start: Option<u64>,
    /// `--status-fd`: the descriptor, or on Windows the handle, sandy writes the status record
    /// to. The number is checked when `run` takes it over.
    pub status_fd: Option<u64>,
    /// `--explain`: the diagnostic mode of `run`.
    pub explain: bool,
    /// `--explain-path`: the paths `check` answers for.
    pub explain_paths: Vec<PathBuf>,
    /// `--install-copy` of setup.
    pub install_copy: bool,
    /// `--elevate` of setup.
    pub elevate: bool,
    pub program: Option<PathBuf>,
    pub args: Vec<OsString>,
}

pub fn parse<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    parse_inner(args).map_err(|error| error.to_string())
}

fn parse_inner<I>(args: I) -> Result<Command, lexopt::Error>
where
    I: IntoIterator<Item = OsString>,
{
    let mut parser = lexopt::Parser::from_args(args);
    let mode = match parser.next()? {
        Some(Short('h') | Long("help")) => return Ok(Command::Help),
        Some(Short('V') | Long("version")) => return Ok(Command::Version),
        Some(Value(value)) => match value.to_str() {
            Some("run") => Mode::Run,
            Some("check") => Mode::Check,
            Some("setup") => Mode::Setup,
            Some(RELAY_COMMAND) => {
                let listener = parser.value()?.parse()?;
                let target = parser.value()?.parse()?;
                return Ok(Command::Relay { listener, target });
            }
            Some(FORWARD_COMMAND) => {
                let listen = parser.value()?.parse()?;
                let socket = PathBuf::from(parser.value()?);
                return Ok(Command::Forward { listen, socket });
            }
            Some(BROKER_COMMAND) => {
                let listener = parser.value()?.parse()?;
                let value = parser.value()?;
                let reach = [EgressReach::Public, EgressReach::PublicAndLocal]
                    .into_iter()
                    .find(|reach| value.to_str() == Some(reach.name()))
                    .ok_or_else(|| format!("unknown egress reach {value:?}"))?;
                return Ok(Command::Broker { listener, reach });
            }
            _ => return Err(format!("unknown command {value:?}").into()),
        },
        Some(other) => return Err(other.unexpected()),
        None => return Err("missing command".into()),
    };

    let mut invocation = Invocation {
        mode,
        policy_file: None,
        overrides: Overrides::default(),
        cwd: None,
        parent_pid: None,
        parent_start: None,
        status_fd: None,
        explain: false,
        explain_paths: Vec::new(),
        install_copy: false,
        elevate: false,
        program: None,
        args: Vec::new(),
    };
    let overrides = &mut invocation.overrides;
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Long("policy") => {
                if invocation.policy_file.is_some() {
                    return Err("--policy given twice".into());
                }
                invocation.policy_file = Some(parser.value()?.into())
            }
            Long("read") => overrides.read.push(parser.value()?.into()),
            Long("read-exec") => overrides.read_exec.push(parser.value()?.into()),
            Long("read-write") => overrides.read_write.push(parser.value()?.into()),
            Long("system") => {
                overrides.system = Some(match parser.value()?.string()?.as_str() {
                    "minimal" => SystemAccess::Minimal,
                    "none" => SystemAccess::None,
                    other => return Err(format!("invalid --system value {other:?}").into()),
                })
            }
            Long("view") => {
                overrides.view = Some(match parser.value()?.string()?.as_str() {
                    "all" => FileView::All,
                    "policy" => FileView::Policy,
                    other => return Err(format!("invalid --view value {other:?}").into()),
                })
            }
            Long("egress") => {
                let value = parser.value()?.string()?;
                let (port, reach) = match value.split_once('=') {
                    Some((port, reach)) => (port, Some(reach)),
                    None => (value.as_str(), None),
                };
                let port = port
                    .parse()
                    .map_err(|_| format!("invalid --egress port {port:?}"))?;
                let reach = match reach {
                    None | Some("public") => EgressReach::Public,
                    Some("public-and-local") => EgressReach::PublicAndLocal,
                    Some(other) => return Err(format!("invalid --egress reach {other:?}").into()),
                };
                overrides.egress = Some(Egress { port, reach });
            }
            Long("ip") => {
                overrides.ip = Some(match parser.value()?.string()?.as_str() {
                    "all" => IpAccess::All,
                    "client" => IpAccess::Client,
                    "private" => IpAccess::Private,
                    "none" => IpAccess::None,
                    other => return Err(format!("invalid --ip value {other:?}").into()),
                })
            }
            Long("unix-sockets") => {
                overrides.unix_sockets = Some(network_access(&mut parser, "--unix-sockets")?)
            }
            Long("children") => {
                overrides.children = Some(match parser.value()?.string()?.as_str() {
                    "allowed" => ChildProcesses::Allowed,
                    "none" => ChildProcesses::None,
                    "contained" => ChildProcesses::Contained,
                    other => return Err(format!("invalid --children value {other:?}").into()),
                })
            }
            Long("signals") => {
                overrides.signals = Some(match parser.value()?.string()?.as_str() {
                    "any" => SignalScope::Any,
                    "isolated" => SignalScope::Isolated,
                    other => return Err(format!("invalid --signals value {other:?}").into()),
                })
            }
            Long("end-with-parent") => overrides.end_with_parent = true,
            Long("remove") if invocation.mode == Mode::Setup => invocation.mode = Mode::Remove,
            Long("install-copy") => invocation.install_copy = true,
            Long(ELEVATE_OPTION) => {
                // Given once, so that `--elevate` among the arguments is this flag and nothing
                // else (see `without_elevate`).
                if invocation.elevate {
                    return Err("--elevate given twice".into());
                }
                invocation.elevate = true
            }
            Long("linux-path-metadata") => {
                overrides.path_metadata = Some(match parser.value()?.string()?.as_str() {
                    "deny" => PathMetadata::Deny,
                    "allow" => PathMetadata::Allow,
                    other => {
                        return Err(format!("invalid --linux-path-metadata value {other:?}").into());
                    }
                })
            }
            Long("pass-env") => overrides.pass_env.push(parser.value()?.string()?),
            Long("set-env") => {
                let assignment = parser.value()?.string()?;
                let (name, value) = assignment
                    .split_once('=')
                    .ok_or_else(|| format!("--set-env needs NAME=VALUE, got {assignment:?}"))?;
                overrides
                    .set_env
                    .push((name.to_string(), value.to_string()));
            }
            Long("appcontainer") => overrides.appcontainer = Some(parser.value()?.string()?),
            Long("windows-win32k") => {
                overrides.win32k = Some(match parser.value()?.string()?.as_str() {
                    "allow" => Win32k::Allow,
                    "deny" => Win32k::Deny,
                    other => return Err(format!("invalid --windows-win32k value {other:?}").into()),
                })
            }
            Long("forward") => {
                let value = parser.value()?.string()?;
                let (port, to) = value
                    .split_once('=')
                    .ok_or_else(|| format!("--forward needs PORT=ADDRESS, got {value:?}"))?;
                let port = port
                    .parse()
                    .map_err(|_| format!("invalid --forward port {port:?}"))?;
                let to = to
                    .parse()
                    .map_err(|_| format!("invalid --forward address {to:?}"))?;
                overrides.forward.push(ForwardedPort { port, to });
            }
            Long("expose") => {
                let value = parser.value()?.string()?;
                let (listen, port) = value
                    .rsplit_once('=')
                    .ok_or_else(|| format!("--expose needs ADDRESS=PORT, got {value:?}"))?;
                let listen = listen
                    .parse()
                    .map_err(|_| format!("invalid --expose address {listen:?}"))?;
                let port = port
                    .parse()
                    .map_err(|_| format!("invalid --expose port {port:?}"))?;
                overrides.expose.push(ExposedPort { listen, port });
            }
            Long("cwd") => invocation.cwd = Some(parser.value()?.into()),
            Long("parent-pid") => invocation.parent_pid = Some(parser.value()?.parse()?),
            Long("parent-start") => invocation.parent_start = Some(parser.value()?.parse()?),
            Long("status-fd") => invocation.status_fd = Some(parser.value()?.parse()?),
            Long("explain") => invocation.explain = true,
            Long("explain-path") => invocation.explain_paths.push(parser.value()?.into()),
            Value(program) => {
                invocation.program = Some(program.into());
                invocation.args = parser.raw_args()?.collect();
                break;
            }
            other => return Err(other.unexpected()),
        }
    }

    match (invocation.mode, &invocation.program) {
        (Mode::Run, None) => return Err("run needs a PROGRAM".into()),
        (Mode::Setup | Mode::Remove, Some(_)) => return Err("setup takes no PROGRAM".into()),
        _ => {}
    }
    if invocation.explain && invocation.mode != Mode::Run {
        return Err("--explain belongs to run".into());
    }
    if !invocation.explain_paths.is_empty() && invocation.mode != Mode::Check {
        return Err("--explain-path belongs to check".into());
    }
    let setup = matches!(invocation.mode, Mode::Setup | Mode::Remove);
    if invocation.install_copy && !setup {
        return Err("--install-copy belongs to setup".into());
    }
    if invocation.elevate && !setup {
        return Err("--elevate belongs to setup".into());
    }
    // The elevated sandy may start in another directory: pkexec starts it in root's home.
    if invocation.elevate
        && invocation
            .policy_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
    {
        return Err("with --elevate, --policy needs an absolute path".into());
    }
    Ok(Command::Sandbox(Box::new(invocation)))
}

const ELEVATE_OPTION: &str = "elevate";

/// The arguments sandy was given, without `--elevate`: what the elevated sandy runs with. The
/// caller has parsed them, so `--elevate` occurs once and as the flag: an option value of that
/// spelling would make `parse` find the flag a second time, or no option at all.
pub fn without_elevate(args: &[OsString]) -> Result<Vec<OsString>, String> {
    let flag = format!("--{ELEVATE_OPTION}");
    let kept: Vec<OsString> = args.iter().filter(|arg| **arg != *flag).cloned().collect();
    if args.len() - kept.len() != 1 {
        return Err(format!(
            "{flag} must appear exactly once, and not as the value of another option"
        ));
    }
    Ok(kept)
}

fn network_access(
    parser: &mut lexopt::Parser,
    option: &str,
) -> Result<NetworkAccess, lexopt::Error> {
    match parser.value()?.string()?.as_str() {
        "all" => Ok(NetworkAccess::All),
        "none" => Ok(NetworkAccess::None),
        other => Err(format!("invalid {option} value {other:?}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn a_second_policy_file_is_an_error() {
        let error = parse_strs(&["check", "--policy", "/a.toml", "--policy", "/b.toml"]);
        assert!(error.unwrap_err().contains("--policy given twice"));
    }

    fn invocation(args: &[&str]) -> Invocation {
        match parse_strs(args).unwrap() {
            Command::Sandbox(invocation) => *invocation,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn program_arguments_are_not_parsed_as_options() {
        let invocation = invocation(&["run", "--ip", "all", "/bin/prog", "--read", "x"]);
        assert_eq!(invocation.program, Some(PathBuf::from("/bin/prog")));
        assert_eq!(
            invocation.args,
            vec![OsString::from("--read"), OsString::from("x")]
        );
    }

    #[test]
    fn double_dash_separates_the_program() {
        let invocation = invocation(&["run", "--", "/bin/prog", "-x"]);
        assert_eq!(invocation.program, Some(PathBuf::from("/bin/prog")));
        assert_eq!(invocation.args, vec![OsString::from("-x")]);
    }

    #[test]
    fn overrides_extend_the_policy() {
        let invocation = invocation(&[
            "check",
            "--read",
            "/a",
            "--read-write",
            "/b",
            "--ip",
            "all",
            "--signals",
            "isolated",
            "--children",
            "none",
            "--end-with-parent",
            "--linux-path-metadata",
            "allow",
            "--set-env",
            "A=b=c",
            "--appcontainer",
            "name",
            "--windows-win32k",
            "deny",
            "--expose",
            "127.0.0.1:18080=8080",
            "--forward",
            "18081=127.0.0.1:8081",
        ]);
        let mut policy = Policy::default();
        policy.filesystem.read.push("/z".into());
        invocation.overrides.apply(&mut policy, true);
        assert_eq!(
            policy.filesystem.read,
            vec![PathBuf::from("/z"), PathBuf::from("/a")]
        );
        assert_eq!(policy.filesystem.read_write, vec![PathBuf::from("/b")]);
        assert_eq!(policy.network.ip, IpAccess::All);
        assert_eq!(policy.process.signals, SignalScope::Isolated);
        assert_eq!(policy.process.children, ChildProcesses::None);
        assert!(policy.process.end_with_parent);
        assert_eq!(policy.linux.path_metadata, PathMetadata::Allow);
        assert_eq!(policy.environment.set["A"], "b=c");
        assert_eq!(policy.windows.appcontainer_name.as_deref(), Some("name"));
        assert_eq!(policy.windows.win32k, Win32k::Deny);
        assert_eq!(
            policy.network.forward,
            vec![ForwardedPort {
                port: 18081,
                to: "127.0.0.1:8081".parse().unwrap()
            }]
        );
        assert_eq!(
            policy.network.expose,
            vec![ExposedPort {
                listen: "127.0.0.1:18080".parse().unwrap(),
                port: 8080
            }]
        );
    }

    #[test]
    fn parses_the_view_the_private_network_and_egress() {
        let parsed = invocation(&[
            "check", "--view", "policy", "--ip", "private", "--egress", "1080",
        ]);
        let mut policy = Policy::default();
        assert!(parsed.overrides.apply(&mut policy, false).is_empty());
        assert_eq!(policy.filesystem.view, FileView::Policy);
        assert_eq!(policy.network.ip, IpAccess::Private);
        assert_eq!(
            policy.network.egress,
            Some(Egress {
                port: 1080,
                reach: EgressReach::Public
            })
        );
        let local = invocation(&["check", "--egress", "1080=public-and-local"]);
        let mut policy = Policy::default();
        local.overrides.apply(&mut policy, false);
        assert_eq!(
            policy.network.egress.unwrap().reach,
            EgressReach::PublicAndLocal
        );
        for bad in [
            &["check", "--view", "none"][..],
            &["check", "--egress", "x"],
            &["check", "--egress", "1080=local"],
            &["check", "--ip", "loopback"],
        ] {
            assert!(parse_strs(bad).is_err(), "{bad:?}");
        }
    }

    /// An option that shows more of the file system, or adds or widens the egress broker, over
    /// a file that does not is named like a wider `--ip`.
    #[test]
    fn a_wider_view_or_egress_over_the_file_is_named() {
        let mut policy = Policy::default();
        policy.filesystem.view = FileView::Policy;
        let notes = invocation(&["check", "--view", "all"])
            .overrides
            .apply(&mut policy, true);
        assert_eq!(notes.len(), 1, "{notes:?}");

        let mut policy = Policy::default();
        let notes = invocation(&["check", "--egress", "1080"])
            .overrides
            .apply(&mut policy, true);
        assert_eq!(
            notes,
            [
                "--egress 1080=public replaces egress = \"none\" from the policy file and allows \
              more than the file does"
            ]
        );
        let notes = invocation(&["check", "--egress", "1080=public-and-local"])
            .overrides
            .apply(&mut policy, true);
        assert_eq!(notes.len(), 1, "{notes:?}");
        let notes = invocation(&["check", "--egress", "1081=public"])
            .overrides
            .apply(&mut policy, true);
        assert!(notes.is_empty(), "{notes:?}");

        let mut policy = Policy::default();
        policy.network.ip = IpAccess::Private;
        assert_eq!(
            invocation(&["check", "--ip", "client"])
                .overrides
                .apply(&mut policy, true)
                .len(),
            1
        );
        let mut policy = Policy::default();
        assert_eq!(
            invocation(&["check", "--ip", "private"])
                .overrides
                .apply(&mut policy, true)
                .len(),
            1
        );
    }

    /// `--ip client` widens a file without IP networking and narrows one with `ip = "all"`.
    #[test]
    fn a_wider_ip_setting_over_the_file_is_named() {
        let weakened = |file: IpAccess, option: &str| {
            let mut policy = Policy::default();
            policy.network.ip = file;
            let notes = invocation(&["check", "--ip", option])
                .overrides
                .apply(&mut policy, true);
            assert_eq!(policy.network.ip.name(), option);
            notes
        };
        assert_eq!(
            weakened(IpAccess::None, "client"),
            vec![
                "--ip client replaces ip = \"none\" from the policy file and allows more than the \
                 file does"
                    .to_string()
            ]
        );
        assert_eq!(weakened(IpAccess::Client, "all").len(), 1);
        assert_eq!(weakened(IpAccess::None, "all").len(), 1);
        assert!(weakened(IpAccess::All, "client").is_empty());
        assert!(weakened(IpAccess::Client, "none").is_empty());
        assert!(matches!(
            parse_strs(&["check", "--ip", "server"]),
            Err(message) if message.contains("invalid --ip value \"server\"")
        ));
    }

    /// `--system minimal` adds the system set to what the program may read, so it widens a file
    /// that says `system = "none"`. The other way round it narrows the file and says nothing.
    #[test]
    fn a_system_set_over_a_file_without_one_is_named() {
        let weakened = |file: SystemAccess, option: &str, from_file: bool| {
            let mut policy = Policy::default();
            policy.filesystem.system = file;
            invocation(&["check", "--system", option])
                .overrides
                .apply(&mut policy, from_file)
        };
        assert_eq!(
            weakened(SystemAccess::None, "minimal", true),
            vec![
                "--system minimal replaces system = \"none\" from the policy file and allows more \
                 than the file does"
                    .to_string()
            ]
        );
        assert!(weakened(SystemAccess::Minimal, "none", true).is_empty());
        assert!(weakened(SystemAccess::None, "minimal", false).is_empty());
    }

    /// `--windows-win32k allow` gives the program back what a file with `win32k = "deny"` takes.
    #[test]
    fn win32k_allowed_over_a_file_that_denies_it_is_named() {
        let weakened = |file: Win32k, option: &str| {
            let mut policy = Policy::default();
            policy.windows.win32k = file;
            invocation(&["check", "--windows-win32k", option])
                .overrides
                .apply(&mut policy, true)
        };
        assert_eq!(
            weakened(Win32k::Deny, "allow"),
            vec![
                "--windows-win32k allow replaces win32k = \"deny\" from the policy file and \
                 allows more than the file does"
                    .to_string()
            ]
        );
        assert!(weakened(Win32k::Allow, "deny").is_empty());
        assert!(parse_strs(&["check", "--windows-win32k", "none"]).is_err());
    }

    #[test]
    fn parses_every_children_value() {
        for (value, expected) in [
            ("allowed", ChildProcesses::Allowed),
            ("none", ChildProcesses::None),
            ("contained", ChildProcesses::Contained),
        ] {
            let invocation = invocation(&["check", "--children", value]);
            let mut policy = Policy::default();
            invocation.overrides.apply(&mut policy, true);
            assert_eq!(policy.process.children, expected);
        }
        assert!(parse_strs(&["check", "--children", "some"]).is_err());
    }

    #[test]
    fn parses_the_internal_relay_command() {
        match parse_strs(&[RELAY_COMMAND, "7", "127.0.0.1:8080"]).unwrap() {
            Command::Relay { listener, target } => {
                assert_eq!(listener, 7);
                assert_eq!(target, "127.0.0.1:8080".parse().unwrap());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_strs(&[RELAY_COMMAND, "x", "127.0.0.1:8080"]).is_err());
    }

    #[test]
    fn parses_the_internal_forward_command() {
        match parse_strs(&[FORWARD_COMMAND, "127.0.0.1:8081", r"C:\sockets\s"]).unwrap() {
            Command::Forward { listen, socket } => {
                assert_eq!(listen, "127.0.0.1:8081".parse().unwrap());
                assert_eq!(socket, PathBuf::from(r"C:\sockets\s"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_strs(&[FORWARD_COMMAND, "8081", "socket"]).is_err());
        assert!(parse_strs(&[FORWARD_COMMAND, "127.0.0.1:8081"]).is_err());
    }

    #[test]
    fn parses_the_internal_broker_command() {
        match parse_strs(&[BROKER_COMMAND, "9", "public"]).unwrap() {
            Command::Broker { listener, reach } => {
                assert_eq!(listener, 9);
                assert_eq!(reach, EgressReach::Public);
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_strs(&[BROKER_COMMAND, "9", "public-and-local"]).unwrap() {
            Command::Broker { reach, .. } => assert_eq!(reach, EgressReach::PublicAndLocal),
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_strs(&[BROKER_COMMAND, "x", "public"]).is_err());
        assert!(parse_strs(&[BROKER_COMMAND, "9", "local"]).is_err());
        assert!(parse_strs(&[BROKER_COMMAND, "9"]).is_err());
    }

    #[test]
    fn run_needs_a_program() {
        assert!(parse_strs(&["run", "--ip", "all"]).is_err());
    }

    #[test]
    fn setup_takes_install_copy_and_elevate() {
        let setup = invocation(&["setup", "--install-copy", "--elevate"]);
        assert_eq!(setup.mode, Mode::Setup);
        assert!(setup.install_copy && setup.elevate);
        let remove = invocation(&["setup", "--elevate", "--install-copy", "--remove"]);
        assert_eq!(remove.mode, Mode::Remove);
        assert!(remove.install_copy && remove.elevate);
        let plain = invocation(&["setup"]);
        assert!(!plain.install_copy && !plain.elevate);
        for (args, error) in [
            (
                &["check", "--install-copy"][..],
                "--install-copy belongs to setup",
            ),
            (
                &["run", "--elevate", "/bin/true"][..],
                "--elevate belongs to setup",
            ),
            (
                &["setup", "--elevate", "--elevate"][..],
                "--elevate given twice",
            ),
            (
                &["setup", "--elevate", "--policy", "policy.toml"][..],
                "absolute path",
            ),
        ] {
            let message = parse_strs(args).unwrap_err();
            assert!(message.contains(error), "{args:?}: {message}");
        }
        let absolute = if cfg!(windows) {
            r"C:\policy.toml"
        } else {
            "/etc/policy.toml"
        };
        assert!(parse_strs(&["setup", "--elevate", "--policy", absolute]).is_ok());
    }

    /// The elevated sandy runs with the same arguments, less the flag. A value spelled like the
    /// flag would make the count differ from what `parse` saw, so it is refused instead of
    /// dropped.
    #[test]
    fn the_elevated_arguments_drop_only_the_flag() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            without_elevate(&args(&["setup", "--elevate", "--policy", "/p.toml"])).unwrap(),
            args(&["setup", "--policy", "/p.toml"])
        );
        let value_too = args(&["setup", "--appcontainer", "--elevate", "--elevate"]);
        assert!(matches!(
            parse(value_too.clone()),
            Ok(Command::Sandbox(invocation)) if invocation.elevate
        ));
        assert!(without_elevate(&value_too).is_err());
        assert!(without_elevate(&args(&["setup"])).is_err());
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse_strs(&["check", "--ip", "some"]).is_err());
        assert!(parse_strs(&["check", "--set-env", "NOVALUE"]).is_err());
        assert!(parse_strs(&["check", "--expose", "127.0.0.1:18080"]).is_err());
        assert!(parse_strs(&["check", "--forward", "18081"]).is_err());
        assert!(parse_strs(&["check", "--forward", "x=127.0.0.1:1"]).is_err());
        assert!(parse_strs(&["check", "--expose", "localhost:1=2"]).is_err());
        assert!(parse_strs(&["unknown"]).is_err());
    }
}
