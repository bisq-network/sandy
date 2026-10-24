//! Command line entry point. It parses the arguments, builds the policy and hands it to the
//! platform backend. All enforcement lives in the backends.

mod args;
mod status;
mod stdio;

use std::process::ExitCode;

use args::{Command, Invocation, Mode};
use sandy_core::streams::StandardStream;
use sandy_core::{
    Backend, EnforcementPlan, ParentProcess, Policy, ResolvedPolicy, StatusReport, TargetCommand,
    target_environment,
};

const EXIT_FAILURE: u8 = 125;
const EXIT_NOT_ENFORCEABLE: u8 = 1;

/// Marks the advice `check` writes to standard error. `run` prints none: its standard error
/// belongs to the program.
const WARNING_PREFIX: &str = "warning: ";

fn main() -> ExitCode {
    // First, so that the window in which sandy's parent can end unseen stays as short as possible
    // (`process.end_with_parent`).
    let parent_at_start = parent_process_id();
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
        Command::Sandbox(invocation) => match execute(*invocation, parent_at_start) {
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

/// The process ID of sandy's parent. Windows does not re-parent processes, so the backend finds
/// the parent there.
#[cfg(unix)]
fn parent_process_id() -> Option<u32> {
    // SAFETY: getppid has no preconditions.
    Some(unsafe { libc::getppid() } as u32)
}

#[cfg(not(unix))]
fn parent_process_id() -> Option<u32> {
    None
}

/// The parent for `end_with_parent`: the one the caller named with `--parent-pid`, which must be
/// the parent sandy saw at its start, or else that parent. With `--parent-start` the caller
/// proves which process it means, so the named one need not be sandy's own parent; the backend
/// checks the token against the process.
fn parent_for(
    named: Option<u32>,
    start: Option<u64>,
    at_start: Option<u32>,
    end_with_parent: bool,
) -> Result<Option<ParentProcess>, String> {
    match (named, start) {
        (_, Some(_)) if named.is_none() => {
            return Err("--parent-start needs --parent-pid".to_string());
        }
        (Some(_), _) if !end_with_parent => {
            return Err("--parent-pid needs end_with_parent".to_string());
        }
        _ => {}
    }
    match (named, at_start) {
        (Some(named), Some(actual)) if start.is_none() && named != actual => Err(format!(
            "the process that started sandy is {actual}, not {named} (--parent-pid); \
             {named} may have ended already, or sandy was started through a wrapper; \
             --parent-start says which process {named} is"
        )),
        (Some(id), _) => Ok(Some(ParentProcess { id, start })),
        (None, at_start) => Ok(at_start.map(|id| ParentProcess { id, start: None })),
    }
}

/// Opens the status channel before anything else, so that every refusal of `run` is reported on
/// it, and marks a failure on the way out.
fn execute(invocation: Invocation, parent_at_start: Option<u32>) -> Result<ExitCode, String> {
    let status = match invocation.mode {
        Mode::Run => status::open(invocation.status_fd)?,
        _ => StatusReport::none(),
    };
    let result = sandbox(invocation, parent_at_start, &status);
    if result.is_err() {
        status.failed();
    }
    result
}

fn sandbox(
    invocation: Invocation,
    parent_at_start: Option<u32>,
    status: &StatusReport,
) -> Result<ExitCode, String> {
    let mut policy = match &invocation.policy_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read policy {}: {error}", path.display()))?;
            Policy::from_toml(&text).map_err(|error| error.to_string())?
        }
        None => Policy::default(),
    };
    let weakened = invocation
        .overrides
        .apply(&mut policy, invocation.policy_file.is_some());
    let resolved = ResolvedPolicy::resolve(&policy, invocation.program.as_deref())
        .map_err(|error| error.to_string())?;
    // Checked in every mode, so that check reports what run would refuse.
    let parent = parent_for(
        invocation.parent_pid,
        invocation.parent_start,
        parent_at_start,
        resolved.end_with_parent,
    )?;
    refuse_writable_trusted_files(&resolved, invocation.policy_file.as_deref())?;
    let backend = platform_backend();
    let mut reported = backend.plan(&resolved);
    if invocation.mode == Mode::Check {
        reported.extend(backend.verify(&resolved));
    }
    let plan = EnforcementPlan::new(&resolved.requirements(), reported);

    match invocation.mode {
        Mode::Check => {
            print!("backend: {}\n{plan}", backend.name());
            // On standard error and with a prefix of their own, so that a caller which reads the
            // one line per requirement that check prints keeps working (see README.md).
            for warning in resolved.warnings(home_directory().as_deref()) {
                eprintln!("{WARNING_PREFIX}{warning}");
            }
            for warning in backend.notes(&resolved) {
                eprintln!("{WARNING_PREFIX}{warning}");
            }
            for warning in weakened {
                eprintln!("{WARNING_PREFIX}{warning}");
            }
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
        Mode::Remove => {
            backend
                .remove(&resolved)
                .map_err(|error| format!("setup --remove failed: {error}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Mode::Run => {
            if !plan.is_enforceable() {
                return Err(refusal(&plan));
            }
            refuse_sockets_on_standard_streams(&resolved)?;
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
                parent,
            };
            let code = backend
                .run(&resolved, &command, status)
                // Also after the program started: with children = "contained" on Linux and
                // macOS, sandy supervises it and can fail while it runs.
                .map_err(|error| format!("run failed: {error}"))?;
            // Exit codes on Windows are 32 bits wide; ExitCode only carries 8.
            std::process::exit(code)
        }
    }
}

/// The user's home directory, for the warning about a writable path that holds it. The variable
/// that names it differs per platform, so `ResolvedPolicy::warnings` takes it from here. The
/// canonical form matches the canonical policy paths.
fn home_directory() -> Option<std::path::PathBuf> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(variable).filter(|home| !home.is_empty())?;
    std::path::Path::new(&home).canonicalize().ok()
}

/// sandy and its policy are trusted: the program must not be able to change them for the next
/// start (see "Threat model" in DESIGN.md). The resolver applies the checks of rules 3 and 4 to
/// them, so a writable path reaches them neither directly nor through a link, an alias or a
/// second name.
fn refuse_writable_trusted_files(
    resolved: &ResolvedPolicy,
    policy_file: Option<&std::path::Path>,
) -> Result<(), String> {
    let sandy_path = std::env::current_exe()
        .map_err(|error| format!("cannot find the path of sandy: {error}"))?;
    // The resolver takes absolute paths; the caller may have spelled these relative to the
    // current directory, which sandy does not change.
    let absolute = |path: &std::path::Path| {
        std::path::absolute(path)
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))
    };
    let mut trusted = vec![absolute(&sandy_path)?];
    // The name sandy was started under leads to the same file, but a second name can lie in a
    // writable path. One that no longer exists cannot be used for the next start, so it is left
    // out instead of refused.
    for path in executed_paths() {
        let Ok(path) = absolute(&path) else { continue };
        if path.exists() && !trusted.contains(&path) {
            trusted.push(path);
        }
    }
    if let Some(policy_file) = policy_file {
        trusted.push(absolute(policy_file)?);
    }
    resolved
        .check_trusted(&trusted)
        .map_err(|error| error.to_string())
}

/// The program inherits standard input, output and error as they are, and a socket among them
/// keeps the access it was created with (see `sandy_core::streams`). Only `run` can check this:
/// the streams of a `check` are not the streams the later `run` gets.
fn refuse_sockets_on_standard_streams(resolved: &ResolvedPolicy) -> Result<(), String> {
    for stream in StandardStream::ALL {
        let Some(socket) = stdio::socket_on(stream)? else {
            continue;
        };
        if let Some(reason) = sandy_core::streams::refusal(resolved, stream, socket) {
            return Err(reason);
        }
    }
    Ok(())
}

/// The names sandy was started under. `current_exe` reads `/proc/self/exe` on Linux, which the
/// kernel has already resolved, so a symbolic link or a hard link inside a writable path would
/// stay unseen. `AT_EXECFN` keeps the name execve was given, and argv[0] is what the caller
/// chose to tell the program.
#[cfg(unix)]
fn executed_paths() -> Vec<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut paths = Vec::new();
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // SAFETY: getauxval has no preconditions. It returns 0 when the kernel passed no
        // AT_EXECFN entry, and else a pointer to a NUL-terminated string on this process's
        // stack, which lives as long as the process.
        let name = unsafe { libc::getauxval(libc::AT_EXECFN) } as *const libc::c_char;
        if !name.is_null() {
            // SAFETY: the kernel NUL-terminates AT_EXECFN.
            let name = unsafe { std::ffi::CStr::from_ptr(name) };
            paths.push(std::path::PathBuf::from(OsString::from_vec(
                name.to_bytes().to_vec(),
            )));
        }
    }
    let arg0 = std::env::args_os().next().unwrap_or_default();
    if arg0.as_bytes().contains(&b'/') {
        paths.push(std::path::PathBuf::from(arg0));
    }
    paths
}

/// TODO: on Windows the path of the running image comes from the process parameters, which
/// `current_exe` reads, so there is no second name to check yet. A junction or a hard link that
/// leads to sandy needs the identity work described in docs/windows.md.
#[cfg(not(unix))]
fn executed_paths() -> Vec<std::path::PathBuf> {
    Vec::new()
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
        _status: &StatusReport,
    ) -> Result<i32, sandy_core::SandboxError> {
        Err(sandy_core::SandboxError::new(
            "this operating system is not supported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(id: u32, start: Option<u64>) -> Result<Option<ParentProcess>, String> {
        Ok(Some(ParentProcess { id, start }))
    }

    #[test]
    fn the_named_parent_must_be_the_parent_at_start() {
        assert_eq!(parent_for(None, None, Some(7), true), parent(7, None));
        assert_eq!(parent_for(None, None, None, true), Ok(None));
        assert_eq!(parent_for(Some(7), None, Some(7), true), parent(7, None));
        // Windows reads no parent at start; the backend checks the named one.
        assert_eq!(parent_for(Some(7), None, None, true), parent(7, None));
        let error = parent_for(Some(7), None, Some(1), true).unwrap_err();
        assert!(error.contains("is 1, not 7"), "{error}");
        assert!(parent_for(Some(7), None, Some(7), false).is_err());
    }

    #[test]
    fn a_start_token_allows_a_parent_that_is_not_sandys_own() {
        assert_eq!(
            parent_for(Some(7), Some(99), Some(1), true),
            parent(7, Some(99))
        );
        let error = parent_for(None, Some(99), Some(1), true).unwrap_err();
        assert!(
            error.contains("--parent-start needs --parent-pid"),
            "{error}"
        );
        assert!(parent_for(Some(7), Some(99), Some(7), false).is_err());
    }
}
