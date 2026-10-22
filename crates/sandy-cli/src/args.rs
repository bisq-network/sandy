use std::ffi::OsString;
use std::path::PathBuf;

use lexopt::prelude::*;
use sandy_core::{NetworkAccess, PathMetadata, Policy, SignalScope, SystemAccess};

pub const USAGE: &str = "\
Usage:
  sandy run [OPTIONS] [--] PROGRAM [ARGS...]   run PROGRAM inside the sandbox
  sandy check [OPTIONS] [[--] PROGRAM]         show how this host enforces the policy
  sandy setup [OPTIONS]                        prepare the host (needs admin rights on Windows)

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
    path_metadata: Option<PathMetadata>,
    pass_env: Vec<String>,
    set_env: Vec<(String, String)>,
    appcontainer: Option<String>,
}

impl Overrides {
    pub fn apply(self, policy: &mut Policy) {
        let filesystem = &mut policy.filesystem;
        filesystem.read.extend(self.read);
        filesystem.read_exec.extend(self.read_exec);
        filesystem.read_write.extend(self.read_write);
        if let Some(system) = self.system {
            filesystem.system = system;
        }
        if let Some(ip) = self.ip {
            policy.network.ip = ip;
        }
        if let Some(unix_sockets) = self.unix_sockets {
            policy.network.unix_sockets = unix_sockets;
        }
        if let Some(signals) = self.signals {
            policy.process.signals = signals;
        }
        if let Some(path_metadata) = self.path_metadata {
            policy.linux.path_metadata = path_metadata;
        }
        policy.environment.pass.extend(self.pass_env);
        policy.environment.set.extend(self.set_env);
        if let Some(name) = self.appcontainer {
            policy.windows.appcontainer_name = Some(name);
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Help,
    Version,
    Sandbox(Box<Invocation>),
}

#[derive(Debug)]
pub struct Invocation {
    pub mode: Mode,
    pub policy_file: Option<PathBuf>,
    pub overrides: Overrides,
    pub cwd: Option<PathBuf>,
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
        program: None,
        args: Vec::new(),
    };
    let overrides = &mut invocation.overrides;
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Long("policy") => invocation.policy_file = Some(parser.value()?.into()),
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
            Long("signals") => {
                overrides.signals = Some(match parser.value()?.string()?.as_str() {
                    "any" => SignalScope::Any,
                    "isolated" => SignalScope::Isolated,
                    other => return Err(format!("invalid --signals value {other:?}").into()),
                })
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
            Long("cwd") => invocation.cwd = Some(parser.value()?.into()),
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
        (Mode::Setup, Some(_)) => return Err("setup takes no PROGRAM".into()),
        _ => {}
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
            "--linux-path-metadata",
            "allow",
            "--set-env",
            "A=b=c",
            "--appcontainer",
            "name",
        ]);
        let mut policy = Policy::default();
        policy.filesystem.read.push("/z".into());
        invocation.overrides.apply(&mut policy);
        assert_eq!(
            policy.filesystem.read,
            vec![PathBuf::from("/z"), PathBuf::from("/a")]
        );
        assert_eq!(policy.filesystem.read_write, vec![PathBuf::from("/b")]);
        assert_eq!(policy.network.ip, NetworkAccess::All);
        assert_eq!(policy.process.signals, SignalScope::Isolated);
        assert_eq!(policy.linux.path_metadata, PathMetadata::Allow);
        assert_eq!(policy.environment.set["A"], "b=c");
        assert_eq!(policy.windows.appcontainer_name.as_deref(), Some("name"));
    }

    #[test]
    fn run_needs_a_program() {
        assert!(parse_strs(&["run", "--ip", "all"]).is_err());
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse_strs(&["check", "--ip", "some"]).is_err());
        assert!(parse_strs(&["check", "--set-env", "NOVALUE"]).is_err());
        assert!(parse_strs(&["unknown"]).is_err());
    }
}
