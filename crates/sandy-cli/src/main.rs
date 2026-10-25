//! Command line entry point. It parses the arguments, builds the policy and hands it to the
//! platform backend. All enforcement lives in the backends.

mod args;
mod status;
mod stdio;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use args::{Command, Invocation, Mode};
use sandy_core::streams::{CreatableSocket, StandardStream};
use sandy_core::{
    Backend, EnforcementPlan, ParentProcess, Policy, ResolvedPolicy, SetupOptions, SetupOutcome,
    StatusReport, TargetCommand, target_environment,
};

const EXIT_FAILURE: u8 = 125;
const EXIT_NOT_ENFORCEABLE: u8 = 1;
/// `check`: not enforceable, and `sandy setup` with administrator rights would make it so. A
/// caller can then ask for those rights and run setup, which it cannot tell from status 1.
const EXIT_NEEDS_SETUP: u8 = 2;
/// `setup`: not done, and nothing changed. A caller then runs without what setup prepares,
/// which it cannot tell from status 125, where something may be half done.
const EXIT_SETUP_NOT_DONE: u8 = 3;

/// The names a sandy was started under before it handed over to the copy that setup installs
/// (`hand_over`), separated like `PATH`. Every sandy checks them like its own names and removes
/// the variable from its environment, so it can only add checks, and the program never sees it.
const STARTED_AS_VARIABLE: &str = "SANDY_STARTED_AS";

/// The parent process ID that a sandy read as its first step before it handed over to the copy
/// that setup installs. The copy reads its own parent again, later; when the two differ, the
/// parent ended in between, and `end_with_parent` refuses instead of watching another process.
/// It can only add that refusal, and the program never sees it.
const PARENT_AT_START_VARIABLE: &str = "SANDY_PARENT_AT_START";

/// Marks the advice `check` writes to standard error. `run` prints none: its standard error
/// belongs to the program.
const WARNING_PREFIX: &str = "warning: ";

fn main() -> ExitCode {
    // First, so that the window in which sandy's parent can end unseen stays as short as possible
    // (`process.end_with_parent`).
    let parent_at_start = parent_process_id();
    let started_as = take_started_as();
    let handed_parent = take_handed_parent();
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = match args::parse(arguments.clone()) {
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
        Command::Broker { listener, reach } => broker(listener, reach),
        Command::Sandbox(invocation) => {
            if matches!(invocation.mode, Mode::Run | Mode::Check) {
                hand_over(&started_as, handed_parent.or(parent_at_start));
            }
            let context = Context {
                parent_at_start,
                handed_parent,
                started_as,
                arguments,
            };
            match execute(*invocation, &context) {
                Ok(code) => code,
                Err(message) => {
                    eprintln!("sandy: {message}");
                    ExitCode::from(EXIT_FAILURE)
                }
            }
        }
    }
}

/// What `main` learns before the invocation runs.
struct Context {
    parent_at_start: Option<u32>,
    /// The value of `PARENT_AT_START_VARIABLE`.
    handed_parent: Option<u32>,
    /// The names of `STARTED_AS_VARIABLE`.
    started_as: Vec<PathBuf>,
    /// sandy's arguments, without the program name.
    arguments: Vec<OsString>,
}

/// Reads and removes `PARENT_AT_START_VARIABLE`, before any thread starts. A value that is not
/// a process ID counts as a parent that differs, so the refusal it can add is not lost.
fn take_handed_parent() -> Option<u32> {
    let value = std::env::var_os(PARENT_AT_START_VARIABLE)?;
    // SAFETY: sandy has one thread here, so nothing reads the environment at the same time.
    unsafe { std::env::remove_var(PARENT_AT_START_VARIABLE) };
    Some(value.to_str().and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Why `end_with_parent` cannot hold after a hand-over: the parent that the first sandy saw is
/// not this process's parent any more, so it ended while sandy handed over.
fn parent_ended_during_hand_over(
    handed: Option<u32>,
    at_start: Option<u32>,
    end_with_parent: bool,
) -> Option<String> {
    let handed = handed?;
    (end_with_parent && Some(handed) != at_start).then(|| {
        format!(
            "the process that started sandy ({handed}) ended while sandy handed over to its \
             installed copy, so there is no parent left to end the program with"
        )
    })
}

/// Reads and removes `STARTED_AS_VARIABLE`, before any thread starts.
fn take_started_as() -> Vec<PathBuf> {
    let Some(value) = std::env::var_os(STARTED_AS_VARIABLE) else {
        return Vec::new();
    };
    // SAFETY: sandy has one thread here, so nothing reads the environment at the same time.
    unsafe { std::env::remove_var(STARTED_AS_VARIABLE) };
    std::env::split_paths(&value)
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

/// On a Linux host where only a root-owned copy of sandy gets user namespaces (`sandy setup
/// --install-copy`), replaces this process with that copy, with the same arguments, environment
/// and descriptors, before sandy opens anything. The copy checks the names this sandy was
/// started under as its own (`STARTED_AS_VARIABLE`), because the next start runs this file
/// again. Returns when there is no such copy, or when the names cannot be passed intact; this
/// sandy then runs on as itself.
#[cfg(target_os = "linux")]
fn hand_over(started_as: &[PathBuf], parent_at_start: Option<u32>) {
    use std::ffi::CString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let Some(copy) = sandy_linux::hand_over_target() else {
        return;
    };
    let mut names = started_as.to_vec();
    if let Ok(path) = std::env::current_exe() {
        names.push(path);
    }
    names.extend(
        executed_paths()
            .into_iter()
            .filter_map(|path| std::path::absolute(path).ok()),
    );
    // A name that holds the separator would arrive as two other names, and its own check would
    // be lost.
    let Ok(joined) = std::env::join_paths(&names) else {
        return;
    };
    let c_string = |bytes: Vec<u8>| CString::new(bytes).ok();
    let Some(program) = c_string(copy.into_os_string().into_vec()) else {
        return;
    };
    let arguments: Option<Vec<CString>> = std::env::args_os()
        .map(|arg| c_string(arg.into_vec()))
        .collect();
    let mut variable = OsString::from(STARTED_AS_VARIABLE);
    variable.push("=");
    variable.push(&joined);
    let parent =
        parent_at_start.map(|id| OsString::from(format!("{PARENT_AT_START_VARIABLE}={id}")));
    let environment: Option<Vec<CString>> = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name;
            entry.push("=");
            entry.push(value);
            entry
        })
        .chain(std::iter::once(variable))
        .chain(parent)
        .map(|entry| c_string(entry.as_bytes().to_vec()))
        .collect();
    let (Some(arguments), Some(environment)) = (arguments, environment) else {
        return;
    };
    let pointers = |strings: &[CString]| {
        strings
            .iter()
            .map(|string| string.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>()
    };
    // SAFETY: program is NUL-terminated, and both arrays hold NUL-terminated strings that
    // outlive the call and end with a null pointer. execve returns only when it fails.
    unsafe {
        libc::execve(
            program.as_ptr(),
            pointers(&arguments).as_ptr(),
            pointers(&environment).as_ptr(),
        )
    };
}

#[cfg(not(target_os = "linux"))]
fn hand_over(_started_as: &[PathBuf], _parent_at_start: Option<u32>) {}

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

/// The egress broker (`network.egress`). The Windows backend starts it as a separate sandy
/// process in a sandbox of its own, with the AF_UNIX listener that the forward relay inside the
/// program's AppContainer passes the program's connections to. It serves SOCKS5 on that listener
/// and connects out to the destinations `reach` allows, asking the Windows host which addresses
/// are its own. It ends like a relay when sandy closes its standard input.
#[cfg(windows)]
fn broker(listener: u64, reach: sandy_core::EgressReach) -> ExitCode {
    // The inherited socket came from another process, so this one must start Winsock before it
    // uses it, or `accept` fails with WSANOTINITIALISED (`sandy_relay::unix`).
    if let Err(error) = sandy_relay::unix::available() {
        eprintln!("sandy: broker failed: {error}");
        return ExitCode::from(EXIT_FAILURE);
    }
    // SAFETY: a backend starts this command only with a listening AF_UNIX socket it passed to
    // this process and that nothing else here owns.
    let listener = unsafe { sandy_relay::unix::Listener::from_inherited(listener) };
    sandy_relay::broker::serve(
        listener,
        |listener| listener.accept(),
        reach,
        sandy_windows::WindowsHost,
        &stop_at_end_of_input(),
        sandy_relay::DRAIN,
    );
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn broker(_listener: u64, _reach: sandy_core::EgressReach) -> ExitCode {
    eprintln!("sandy: {} is used only on Windows", args::BROKER_COMMAND);
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
fn execute(invocation: Invocation, context: &Context) -> Result<ExitCode, String> {
    let status = match invocation.mode {
        Mode::Run => status::open(invocation.status_fd)?,
        _ => StatusReport::none(),
    };
    let result = sandbox(invocation, context, &status);
    if result.is_err() {
        status.failed();
    }
    result
}

fn sandbox(
    invocation: Invocation,
    context: &Context,
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
    if let Some(reason) = parent_ended_during_hand_over(
        context.handed_parent,
        context.parent_at_start,
        resolved.end_with_parent,
    ) {
        return Err(reason);
    }
    let parent = parent_for(
        invocation.parent_pid,
        invocation.parent_start,
        context.parent_at_start,
        resolved.end_with_parent,
    )?;
    refuse_writable_trusted_files(
        &resolved,
        invocation.policy_file.as_deref(),
        &context.started_as,
    )?;
    let backend = platform_backend();
    if invocation.explain && !backend.can_explain() {
        return Err(format!(
            "--explain is not available on this host: the {} backend has no way to report what \
             it denied that does not need more rights than sandy has (see the platform \
             documentation)",
            backend.name()
        ));
    }
    let mut reported = backend.plan(&resolved);
    if invocation.mode == Mode::Check {
        reported.extend(backend.verify(&resolved));
    }
    let plan = EnforcementPlan::new(&resolved.requirements(), reported);

    match invocation.mode {
        Mode::Check => {
            print!("backend: {}\n{plan}", backend.name());
            if !invocation.explain_paths.is_empty() {
                let answers = backend
                    .explain_paths(&resolved, &invocation.explain_paths)
                    .ok_or_else(|| {
                        format!(
                            "--explain-path is not available on this host: the {} backend cannot \
                             say which rule decides a path (see the platform documentation)",
                            backend.name()
                        )
                    })?;
                for answer in answers {
                    println!("{answer}");
                }
            }
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
            } else if plan.needs_only_setup() {
                Ok(ExitCode::from(EXIT_NEEDS_SETUP))
            } else {
                Ok(ExitCode::from(EXIT_NOT_ENFORCEABLE))
            }
        }
        Mode::Setup | Mode::Remove => {
            let remove = invocation.mode == Mode::Remove;
            let options = SetupOptions {
                install_copy: invocation.install_copy,
            };
            let outcome = if invocation.elevate {
                let arguments = args::without_elevate(&context.arguments)?;
                backend.elevate(&resolved, remove, options, &arguments)
            } else if remove {
                backend.remove(&resolved, options)
            } else {
                backend.setup(&resolved, options)
            };
            let command = if remove { "setup --remove" } else { "setup" };
            // An empty message comes from an elevated sandy that has already written its own.
            match outcome.map_err(|error| format!("{command} failed: {error}"))? {
                SetupOutcome::Done(message) => {
                    if !message.is_empty() {
                        println!("sandy {command}: {message}");
                    }
                    Ok(ExitCode::SUCCESS)
                }
                SetupOutcome::Refused(message) => {
                    if !message.is_empty() {
                        eprintln!("sandy: {command} not done: {message}");
                    }
                    Ok(ExitCode::from(EXIT_SETUP_NOT_DONE))
                }
            }
        }
        Mode::Run => {
            if !plan.is_enforceable() {
                return Err(refusal(&plan));
            }
            refuse_unsafe_standard_streams(&resolved, backend.ip_also_allows())?;
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
                explain: invocation.explain,
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
    started_as: &[PathBuf],
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
    // out instead of refused. After a hand-over, the names of the sandy that handed over count
    // too: the next start runs that file again.
    for path in executed_paths()
        .into_iter()
        .chain(started_as.iter().cloned())
    {
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

/// The program inherits standard input, output and error as they are: a socket among them keeps
/// the access it was created with, and the master side of a pseudo-terminal lets the program
/// signal the processes on the other side (see `sandy_core::streams`). Only `run` can check
/// this: the streams of a `check` are not the streams the later `run` gets.
fn refuse_unsafe_standard_streams(
    resolved: &ResolvedPolicy,
    ip_also_allows: &[CreatableSocket],
) -> Result<(), String> {
    for stream in StandardStream::ALL {
        if stdio::terminal_master_on(stream)? {
            if let Some(reason) = sandy_core::streams::terminal_master_refusal(resolved, stream) {
                return Err(reason);
            }
            continue;
        }
        let Some(socket) = stdio::socket_on(stream)? else {
            continue;
        };
        if let Some(reason) = sandy_core::streams::refusal(resolved, stream, socket, ip_also_allows)
        {
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

/// On Windows `current_exe` is the name sandy was started under, as the process parameters
/// record it, so the resolver already sees a junction or symbolic link on the way through it,
/// and it asks the file for its other names.
#[cfg(not(unix))]
fn executed_paths() -> Vec<std::path::PathBuf> {
    Vec::new()
}

fn refusal(plan: &EnforcementPlan) -> String {
    let mut message =
        String::from("refusing to start the program; this host cannot enforce the policy:");
    for item in plan.unavailable() {
        match &item.status {
            sandy_core::Status::Unavailable { reason } => message.push_str(&format!(
                "\n  - {}: {reason}",
                item.requirement.description()
            )),
            sandy_core::Status::NeedsSetup { reason } => message.push_str(&format!(
                "\n  - {}: {reason}; `sandy setup`, run once with administrator rights, \
                 prepares this host",
                item.requirement.description()
            )),
            sandy_core::Status::Enforced { .. } => {}
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

    /// After a hand-over the copy refuses `end_with_parent` when its parent is not the one the
    /// first sandy saw, and the variable decides nothing else.
    #[test]
    fn a_parent_that_ended_during_the_hand_over_is_refused() {
        assert!(parent_ended_during_hand_over(Some(7), Some(1), true).is_some());
        assert!(parent_ended_during_hand_over(Some(0), Some(7), true).is_some());
        assert_eq!(parent_ended_during_hand_over(Some(7), Some(7), true), None);
        assert_eq!(parent_ended_during_hand_over(Some(7), Some(1), false), None);
        assert_eq!(parent_ended_during_hand_over(None, Some(1), true), None);
    }
}
