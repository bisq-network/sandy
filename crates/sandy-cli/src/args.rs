use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use lexopt::prelude::*;
use sandy_core::{
    ChildProcesses, ExposedPort, ForwardedPort, NetworkAccess, PathMetadata, Policy, SignalScope,
    SystemAccess,
};

pub const USAGE: &str = "\
Usage:
  sandy run [OPTIONS] [--] PROGRAM [ARGS...]   run PROGRAM inside the sandbox
  sandy check [OPTIONS] [[--] PROGRAM]         show how this host enforces the policy
  sandy setup [OPTIONS]                        prepare the host (needs admin rights on Windows)
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
  --ip all|none              IP networking (default: none)
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
                             needs --ip all)
  --forward PORT=ADDRESS     relay connections from the program to its loopback PORT to the
                             loopback ADDRESS outside, for example 18081=127.0.0.1:8081
                             (repeatable; needs --ip all)
  --linux-path-metadata deny|allow
                             metadata changes by path on Linux (default: deny)
  --pass-env NAME            copy variable NAME into the program environment (repeatable)
  --set-env NAME=VALUE       set a variable in the program environment (repeatable)
  --appcontainer NAME        AppContainer profile name (Windows)
  --cwd DIR                  working directory of the program
  -h, --help                 show this help
  -V, --version              show the version

Exit status: the program's status; 125 when sandy fails or refuses; for check, 0 when the policy
is enforceable and 1 when it is not.
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
    ip: Option<NetworkAccess>,
    unix_sockets: Option<NetworkAccess>,
    signals: Option<SignalScope>,
    children: Option<ChildProcesses>,
    end_with_parent: bool,
    path_metadata: Option<PathMetadata>,
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
            filesystem.system = system;
        }
        if let Some(ip) = self.ip {
            if ip == NetworkAccess::All && policy.network.ip == NetworkAccess::None {
                note("--ip", "all", "ip", "none");
            }
            policy.network.ip = ip;
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
        weakened
    }
}

/// How strict a `children` value is, higher is stricter. Only the order matters.
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
}

/// The internal command that runs a relay. It is not part of the documented interface.
pub const RELAY_COMMAND: &str = "__relay";

/// The internal command that runs a forward relay. It is not part of the documented interface.
pub const FORWARD_COMMAND: &str = "__forward";

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
            Long("ip") => overrides.ip = Some(network_access(&mut parser, "--ip")?),
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
    Ok(Command::Sandbox(Box::new(invocation)))
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
        assert_eq!(policy.network.ip, NetworkAccess::All);
        assert_eq!(policy.process.signals, SignalScope::Isolated);
        assert_eq!(policy.process.children, ChildProcesses::None);
        assert!(policy.process.end_with_parent);
        assert_eq!(policy.linux.path_metadata, PathMetadata::Allow);
        assert_eq!(policy.environment.set["A"], "b=c");
        assert_eq!(policy.windows.appcontainer_name.as_deref(), Some("name"));
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
    fn run_needs_a_program() {
        assert!(parse_strs(&["run", "--ip", "all"]).is_err());
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
