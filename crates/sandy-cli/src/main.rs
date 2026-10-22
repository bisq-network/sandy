//! Command line entry point. It parses the arguments, builds the policy and hands it to the
//! platform backend. All enforcement lives in the backends.

mod args;

use std::process::ExitCode;

use args::{Command, Invocation, Mode};
use sandy_core::{
    Backend, EnforcementPlan, Policy, ResolvedPolicy, TargetCommand, target_environment,
};

const EXIT_FAILURE: u8 = 125;
const EXIT_NOT_ENFORCEABLE: u8 = 1;

fn main() -> ExitCode {
    let command = match args::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("sandy: {message}\n\n{}", args::USAGE);
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    match command {
        Command::Help => {
            print!("{}", args::USAGE);
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("sandy {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Relay { listener, target } => relay(listener, target),
        Command::Forward { listen, socket } => forward(listen, &socket),
        Command::Sandbox(invocation) => match execute(*invocation) {
            Ok(code) => code,
            Err(message) => {
                eprintln!("sandy: {message}");
                ExitCode::from(EXIT_FAILURE)
            }
        },
    }
}

fn relay(listener: u64, target: std::net::SocketAddr) -> ExitCode {
    // SAFETY: a backend starts this command only with a listening socket it passed to this
    // process and that nothing else here owns.
    let listener = match unsafe { sandy_relay::inherited_listener(listener) } {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("sandy: relay failed: {error}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    serve_relay(listener, target)
}

/// On Windows the backend keeps the relay's standard input open while the program runs and
/// closes it when the program ends; the relay then ends by rule 5 (see `serve_until`).
#[cfg(windows)]
fn serve_relay(listener: std::net::TcpListener, target: std::net::SocketAddr) -> ExitCode {
    if let Err(error) = listener.set_nonblocking(false) {
        eprintln!("sandy: relay failed: {error}");
        return ExitCode::from(EXIT_FAILURE);
    }
    sandy_relay::serve_until(
        listener,
        |listener| listener.accept().map(|(client, _)| client),
        move || sandy_relay::connect(target),
        &stop_at_end_of_input(),
        sandy_relay::DRAIN,
    );
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn serve_relay(listener: std::net::TcpListener, target: std::net::SocketAddr) -> ExitCode {
    match sandy_relay::serve(listener, target) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandy: relay failed: {error}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// A stop request that this process's standard input triggers when it reaches its end. The
/// backend that starts a relay holds the other end of that pipe; it closes it when the program
/// ends, and its own exit closes it too.
#[cfg(windows)]
fn stop_at_end_of_input() -> sandy_relay::Stop {
    use std::io::Read;

    let stop = sandy_relay::Stop::new();
    let request = stop.clone();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        let mut input = std::io::stdin();
        while matches!(input.read(&mut buffer), Ok(read) if read > 0) {}
        request.request();
    });
    stop
}

/// The line the forward relay writes to standard output once it listens. The backend that starts
/// it waits for this line before it starts the program, so the program's first connection does
/// not race the relay. It matches the Windows backend.
#[cfg(windows)]
const FORWARD_READY: &str = "ready";

#[cfg(windows)]
fn forward(listen: std::net::SocketAddr, socket: &std::path::Path) -> ExitCode {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = match TcpListener::bind(listen) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("sandy: forward relay cannot listen on {listen}: {error}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let mut stdout = std::io::stdout().lock();
    if writeln!(stdout, "{FORWARD_READY}")
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    let socket = socket.to_path_buf();
    sandy_relay::serve_until(
        listener,
        |listener| listener.accept().map(|(client, _)| client),
        move || sandy_relay::unix::connect_to(&socket),
        &stop_at_end_of_input(),
        sandy_relay::DRAIN,
    );
    ExitCode::SUCCESS
}

/// Only the Windows backend starts the forward relay as a separate sandy process.
#[cfg(not(windows))]
fn forward(_listen: std::net::SocketAddr, _socket: &std::path::Path) -> ExitCode {
    eprintln!("sandy: {} is used only on Windows", args::FORWARD_COMMAND);
    ExitCode::from(EXIT_FAILURE)
}

fn execute(invocation: Invocation) -> Result<ExitCode, String> {
    let mut policy = match &invocation.policy_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read policy {}: {error}", path.display()))?;
            Policy::from_toml(&text).map_err(|error| error.to_string())?
        }
        None => Policy::default(),
    };
    invocation.overrides.apply(&mut policy);
    let resolved = ResolvedPolicy::resolve(&policy, invocation.program.as_deref())
        .map_err(|error| error.to_string())?;
    let backend = platform_backend();
    let plan = EnforcementPlan::new(&resolved.requirements(), backend.plan(&resolved));

    match invocation.mode {
        Mode::Check => {
            print!("backend: {}\n{plan}", backend.name());
            if plan.is_enforceable() {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(EXIT_NOT_ENFORCEABLE))
            }
        }
        Mode::Setup => {
            backend
                .setup(&resolved)
                .map_err(|error| format!("setup failed: {error}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Mode::Run => {
            if !plan.is_enforceable() {
                return Err(refusal(&plan));
            }
            let program = resolved
                .program
                .clone()
                .ok_or_else(|| "run needs a PROGRAM".to_string())?;
            let arg0 = invocation
                .program
                .clone()
                .map(|p| p.into_os_string())
                .unwrap_or_else(|| program.clone().into_os_string());
            let command = TargetCommand {
                program,
                arg0,
                args: invocation.args,
                env: target_environment(&resolved.environment, std::env::vars_os()),
                cwd: invocation.cwd,
            };
            let code = backend
                .run(&resolved, &command)
                .map_err(|error| format!("cannot start the program in the sandbox: {error}"))?;
            // Exit codes on Windows are 32 bits wide; ExitCode only carries 8.
            std::process::exit(code)
        }
    }
}

fn refusal(plan: &EnforcementPlan) -> String {
    let mut message =
        String::from("refusing to start the program; this host cannot enforce the policy:");
    for item in plan.unavailable() {
        if let sandy_core::Status::Unavailable { reason } = &item.status {
            message.push_str(&format!(
                "\n  - {}: {reason}",
                item.requirement.description()
            ));
        }
    }
    message
}

#[cfg(target_os = "linux")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_linux::LinuxBackend)
}

#[cfg(target_os = "macos")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_macos::MacosBackend)
}

#[cfg(windows)]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_windows::WindowsBackend)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(UnsupportedBackend)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[derive(Debug)]
struct UnsupportedBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl Backend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn plan(&self, policy: &ResolvedPolicy) -> Vec<sandy_core::PlanItem> {
        policy
            .requirements()
            .into_iter()
            .map(|r| sandy_core::PlanItem::unavailable(r, "this operating system is not supported"))
            .collect()
    }

    fn run(
        &self,
        _policy: &ResolvedPolicy,
        _command: &TargetCommand,
    ) -> Result<i32, sandy_core::SandboxError> {
        Err(sandy_core::SandboxError::new(
            "this operating system is not supported",
        ))
    }
}
