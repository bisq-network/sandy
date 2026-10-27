//! Command line entry point. It parses the arguments, builds the policy and hands it to the
//! platform backend. All enforcement lives in the backends.

mod args;
mod report;
mod status;
mod stdio;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use args::{Command, Invocation, Mode, PolicySource};
use sandy_core::streams::{CreatableSocket, StandardStream};
use sandy_core::{
    Backend, EnforcementPlan, Outcome, ParentProcess, Policy, ResolvedLevel, ResolvedPolicy,
    Selection, SetupOptions, SetupOutcome, StatusReport, TargetCommand, select, setup_levels,
    target_environment,
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
        Command::Relay {
            exposed,
            sockets,
            forwarded,
        } => relay(exposed, sockets, forwarded),
        Command::Broker { listener, reach } => broker(listener, reach),
        Command::Sandbox(invocation) => {
            let handed_over = match invocation.mode {
                Mode::Run | Mode::Check => {
                    hand_over(&started_as, handed_parent.or(parent_at_start))
                }
                _ => Ok(()),
            };
            let context = Context {
                parent_at_start,
                handed_parent,
                started_as,
                arguments,
                handed_over,
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
    /// `Err` with the reason when the hand-over to the installed copy failed (`hand_over`). It
    /// is reported once the status channel is open, so a caller that reads it learns of it too.
    handed_over: Result<(), String>,
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
/// again. Returns `Ok` when there is no such copy; this sandy then runs on as itself. Returns
/// `Err` when the copy is installed and sandy cannot tell whether to hand over, or cannot hand
/// over: running on as itself would report that the host needs setup, which is not so.
#[cfg(target_os = "linux")]
fn hand_over(started_as: &[PathBuf], parent_at_start: Option<u32>) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let Some(copy) = sandy_linux::hand_over_target()? else {
        return Ok(());
    };
    let failed = |reason: &str| {
        format!(
            "cannot hand over to the installed copy {}: {reason}",
            copy.display()
        )
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
        return Err(failed(
            "a name sandy was started under holds ':', which cannot be passed to the copy",
        ));
    };
    let c_string = |bytes: Vec<u8>| CString::new(bytes).ok();
    let Some(program) = c_string(copy.as_os_str().as_bytes().to_vec()) else {
        return Err(failed("its path holds a NUL byte"));
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
        return Err(failed("an argument or a variable holds a NUL byte"));
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
    Err(failed(&std::io::Error::last_os_error().to_string()))
}

#[cfg(not(target_os = "linux"))]
fn hand_over(_started_as: &[PathBuf], _parent_at_start: Option<u32>) -> Result<(), String> {
    Ok(())
}

/// How the relay reaches the other side of one port.
type Connect = Box<dyn Fn() -> std::io::Result<std::net::TcpStream> + Send + Sync>;

/// One relay serves every exposed and forwarded port that it is given.
fn relay(
    exposed: Vec<(u64, std::net::SocketAddr)>,
    sockets: Option<std::path::PathBuf>,
    forwarded: Vec<std::net::SocketAddr>,
) -> ExitCode {
    let mut handles: Vec<u64> = exposed.iter().map(|(listener, _)| *listener).collect();
    handles.sort_unstable();
    handles.dedup();
    if handles.len() != exposed.len() {
        eprintln!("sandy: relay failed: a socket is named twice");
        return ExitCode::from(EXIT_FAILURE);
    }
    let mut routes: Vec<(std::net::TcpListener, Connect)> = Vec::new();
    for (listener, target) in exposed {
        // SAFETY: a backend starts this command only with listening sockets it passed to this
        // process and that nothing else here owns, and each is named once (checked above).
        let listener = unsafe { sandy_relay::inherited_listener(listener) }
            .and_then(|listener| listener.set_nonblocking(false).map(|()| listener));
        match listener {
            Ok(listener) => routes.push((listener, Box::new(move || sandy_relay::connect(target)))),
            Err(error) => {
                eprintln!("sandy: relay failed: {error}");
                return ExitCode::from(EXIT_FAILURE);
            }
        }
    }
    if let Err(message) = forward_routes(sockets, forwarded, &mut routes) {
        eprintln!("sandy: {message}");
        return ExitCode::from(EXIT_FAILURE);
    }
    serve_relay(routes)
}

/// The routes of the forwarded ports: the relay listens on each address inside the sandbox and
/// passes every connection to the socket named after its port in `sockets`.
#[cfg(windows)]
fn forward_routes(
    sockets: Option<std::path::PathBuf>,
    forwarded: Vec<std::net::SocketAddr>,
    routes: &mut Vec<(std::net::TcpListener, Connect)>,
) -> Result<(), String> {
    let Some(directory) = sockets else {
        return Ok(());
    };
    for listen in forwarded {
        let listener = std::net::TcpListener::bind(listen)
            .map_err(|error| format!("relay cannot listen on {listen}: {error}"))?;
        let socket = sandy_relay::unix::socket_path(&directory, listen.port());
        routes.push((
            listener,
            Box::new(move || sandy_relay::unix::connect_to(&socket)),
        ));
    }
    Ok(())
}

/// Only the Windows backend relays forwarded ports through a separate sandy process.
#[cfg(not(windows))]
fn forward_routes(
    _sockets: Option<std::path::PathBuf>,
    forwarded: Vec<std::net::SocketAddr>,
    _routes: &mut Vec<(std::net::TcpListener, Connect)>,
) -> Result<(), String> {
    if forwarded.is_empty() {
        Ok(())
    } else {
        Err("the relay serves forwarded ports only on Windows".to_string())
    }
}

/// The line the relay writes to standard output once it listens. The backend that starts it
/// waits for this line before it starts the program, so the program's first connection to a
/// forwarded port does not race the relay. It matches the Windows backend.
#[cfg(windows)]
const RELAY_READY: &str = "ready";

/// On Windows the backend keeps the relay's standard input open while the program runs and
/// closes it when the program ends; the relay then ends by rule 5 (see `serve_until`).
#[cfg(windows)]
fn serve_relay(routes: Vec<(std::net::TcpListener, Connect)>) -> ExitCode {
    use std::io::Write;

    let stop = match stop_at_end_of_input() {
        Ok(stop) => stop,
        Err(error) => {
            eprintln!("sandy: relay failed: {error}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let mut stdout = std::io::stdout().lock();
    if writeln!(stdout, "{RELAY_READY}")
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    drop(stdout);
    sandy_relay::serve_until(
        routes,
        |listener| listener.accept().map(|(client, _)| client),
        &stop,
        sandy_relay::DRAIN,
    );
    ExitCode::SUCCESS
}

/// No Unix backend starts the relay as a process of its own; started by hand, it serves until it
/// is ended.
#[cfg(not(windows))]
fn serve_relay(routes: Vec<(std::net::TcpListener, Connect)>) -> ExitCode {
    match sandy_relay::Stop::new() {
        Ok(never) => {
            sandy_relay::serve_until(
                routes,
                |listener| listener.accept().map(|(client, _)| client),
                &never,
                sandy_relay::DRAIN,
            );
            ExitCode::SUCCESS
        }
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
fn stop_at_end_of_input() -> std::io::Result<sandy_relay::Stop> {
    use std::io::Read;

    let stop = sandy_relay::Stop::new()?;
    let request = stop.clone();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        let mut input = std::io::stdin();
        while matches!(input.read(&mut buffer), Ok(read) if read > 0) {}
        request.request();
    });
    Ok(stop)
}

/// The egress broker (`network.egress`). The Windows backend starts it as a separate sandy
/// process in a sandbox of its own, with the AF_UNIX listener that the relay inside the
/// program's AppContainer passes the program's connections to. It serves SOCKS5 on that listener
/// and connects out to the destinations `reach` allows, asking the Windows host which addresses
/// are its own. It ends like a relay when sandy closes its standard input.
#[cfg(windows)]
fn broker(listener: u64, reach: sandy_core::EgressReach) -> ExitCode {
    // The inherited socket came from another process, so this one must start Winsock before it
    // uses it, or `accept` fails with WSANOTINITIALISED (`sandy_relay::unix`).
    let stop = match sandy_relay::unix::available().and_then(|()| stop_at_end_of_input()) {
        Ok(stop) => stop,
        Err(error) => {
            eprintln!("sandy: broker failed: {error}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    // SAFETY: a backend starts this command only with a listening AF_UNIX socket it passed to
    // this process and that nothing else here owns.
    let listener = unsafe { sandy_relay::unix::Listener::from_inherited(listener) };
    sandy_relay::broker::serve(
        listener,
        |listener| listener.accept(),
        reach,
        sandy_windows::WindowsHost,
        &stop,
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
    mut invocation: Invocation,
    context: &Context,
    status: &StatusReport,
) -> Result<ExitCode, String> {
    context.handed_over.clone()?;
    let mut policy = load_policy(invocation.policy.as_ref())?;
    let weakened = std::mem::take(&mut invocation.overrides)
        .apply(&mut policy, invocation.policy.is_some())?;
    let has_levels = !policy.fallback.is_empty();
    if has_levels && invocation.mode == Mode::Check && invocation.program.is_none() {
        return Err(
            "check of a policy with fallback levels needs the PROGRAM: which level run takes can \
             depend on it, and check must decide as run does"
                .to_string(),
        );
    }
    let mut levels = ResolvedPolicy::resolve_levels(&policy, invocation.program.as_deref())
        .map_err(|error| error.to_string())?;
    // The paths, the program and the environment are the same in every level, so the checks
    // of the invocation hold for all of them. The parent is checked for any level that ends
    // with it, also when another level is chosen or pinned with --level: checked in every mode,
    // so that check reports what run would refuse, and run --level takes the options that check
    // took. A level that does not end with its parent ignores it.
    let ends_with_parent = levels.iter().any(|level| level.policy.end_with_parent);
    if let Some(name) = &invocation.level {
        let index = levels
            .iter()
            .position(|level| level.name == *name)
            .ok_or_else(|| {
                let names: Vec<&str> = levels.iter().map(|level| level.name.as_str()).collect();
                format!(
                    "the policy has no level {name:?}; its levels are {}",
                    names.join(", ")
                )
            })?;
        levels = vec![levels.swap_remove(index)];
    }
    if let Some(reason) = parent_ended_during_hand_over(
        context.handed_parent,
        context.parent_at_start,
        ends_with_parent,
    ) {
        return Err(reason);
    }
    let parent = parent_for(
        invocation.parent_pid,
        invocation.parent_start,
        context.parent_at_start,
        ends_with_parent,
    )?;
    let policy_file = match &invocation.policy {
        Some(PolicySource::File(path)) => Some(path.as_path()),
        _ => None,
    };
    refuse_writable_trusted_files(&levels[0].policy, policy_file, &context.started_as)?;
    let backend = platform_backend();
    if invocation.explain && !backend.can_explain() {
        return Err(format!(
            "--explain is not available on this host: the {} backend has no way to report what \
             it denied that does not need more rights than sandy has (see the platform \
             documentation)",
            backend.name()
        ));
    }

    if matches!(invocation.mode, Mode::Setup | Mode::Remove) {
        return setup(&invocation, context, backend.as_ref(), &levels);
    }
    // One backend value for every level: it detects each host property once, so a passing
    // probe failure cannot hit one level and not the next.
    let selection = select(levels.len(), |index| {
        let policy = &levels[index].policy;
        EnforcementPlan::new(&policy.requirements(), backend.plan(policy))
    });
    if invocation.mode == Mode::Check {
        return check(
            &invocation,
            backend.as_ref(),
            &levels,
            &selection,
            has_levels,
            &weakened,
        );
    }

    let index = match selection.outcome {
        Outcome::Selected(index) => index,
        _ => return Err(refusal(&levels, &selection, has_levels)),
    };
    let resolved = &levels[index].policy;
    if has_levels {
        if index > 0 {
            eprintln!(
                "{WARNING_PREFIX}running fallback level {}: {}",
                levels[index].name,
                skipped(&levels, &selection.plans[..index])
            );
        }
        status.level(&levels[index].name);
    }
    refuse_unsafe_standard_streams(resolved, backend.ip_also_allows())?;
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
        .run(resolved, &command, status)
        // Also after the program started: with children = "contained" on Linux and macOS, sandy
        // supervises it and can fail while it runs. Never a reason to try another level.
        .map_err(|error| format!("run failed: {error}"))?;
    // Exit codes on Windows are 32 bits wide; ExitCode only carries 8.
    std::process::exit(code)
}

/// The policy the invocation names, or the empty one.
fn load_policy(source: Option<&PolicySource>) -> Result<Policy, String> {
    let text = match source {
        None => return Ok(Policy::default()),
        Some(PolicySource::File(path)) => read_policy_file(path)?,
        Some(PolicySource::Input) => stdio::take_policy_input()?,
    };
    Policy::from_toml(&text).map_err(|error| error.to_string())
}

/// Reads a policy file, and stops at more than a policy may hold rather than reading all of a
/// file that does not end, such as a device.
fn read_policy_file(path: &Path) -> Result<String, String> {
    use std::io::Read;

    let cannot = |error: std::io::Error| format!("cannot read policy {}: {error}", path.display());
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(cannot)?
        .take(sandy_core::MAX_POLICY_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(cannot)?;
    if bytes.len() > sandy_core::MAX_POLICY_LEN {
        return Err(format!(
            "policy {} is longer than {} KiB",
            path.display(),
            sandy_core::MAX_POLICY_LEN / 1024
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("policy {} is not valid UTF-8", path.display()))
}

/// `sandy check`: the plan of each level tried and which one runs, with warnings on standard
/// error, or the JSON object of `--json` on standard output.
fn check(
    invocation: &Invocation,
    backend: &dyn Backend,
    levels: &[ResolvedLevel],
    selection: &Selection,
    has_levels: bool,
    weakened: &[String],
) -> Result<ExitCode, String> {
    // The level the answers are about: the one that runs, the one that stopped the choice, or
    // the base when none is enforceable.
    let shown = match selection.outcome {
        Outcome::Selected(index) | Outcome::Stopped(index) => index,
        Outcome::NoneEnforceable { .. } => 0,
    };
    let warnings = |level: &ResolvedLevel| -> Vec<String> {
        let mut warnings = level.policy.warnings(home_directory().as_deref());
        warnings.extend(backend.notes(&level.policy));
        warnings
    };
    if !invocation.json {
        if has_levels {
            print!(
                "backend: {}\n{}",
                backend.name(),
                report::levels_text(levels, selection)
            );
        } else {
            print!("backend: {}\n{}", backend.name(), selection.plans[0]);
        }
        if !invocation.explain_paths.is_empty() {
            let answers = backend
                .explain_paths(&levels[shown].policy, &invocation.explain_paths)
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
        for warning in warnings(&levels[shown]).iter().chain(weakened) {
            eprintln!("{WARNING_PREFIX}{warning}");
        }
    }
    let code = match selection.outcome {
        Outcome::Stopped(index) => {
            return Err(stopped(&levels[index], &selection.plans[index], has_levels));
        }
        Outcome::NoneEnforceable { setup_helps: true } => ExitCode::from(EXIT_NEEDS_SETUP),
        Outcome::NoneEnforceable { setup_helps: false } => ExitCode::from(EXIT_NOT_ENFORCEABLE),
        Outcome::Selected(index) => {
            let busy: Vec<_> = backend
                .verify(&levels[index].policy)
                .into_iter()
                .filter(|item| !item.is_enforced())
                .collect();
            if !busy.is_empty() {
                let level = if has_levels {
                    format!("level {}: ", levels[index].name)
                } else {
                    String::new()
                };
                return Err(list(
                    &format!("{level}this host enforces the policy, but run would fail now:"),
                    &busy,
                ));
            }
            ExitCode::SUCCESS
        }
    };
    if invocation.json {
        let level_warnings: Vec<Vec<String>> = levels
            .iter()
            .take(selection.plans.len())
            .map(warnings)
            .collect();
        println!(
            "{}",
            report::json(backend.name(), levels, selection, &level_warnings, weakened)
        );
    }
    Ok(code)
}

/// `sandy setup` and `sandy setup --remove`, for every level the invocation has.
fn setup(
    invocation: &Invocation,
    context: &Context,
    backend: &dyn Backend,
    levels: &[ResolvedLevel],
) -> Result<ExitCode, String> {
    let remove = invocation.mode == Mode::Remove;
    let options = SetupOptions {
        install_copy: invocation.install_copy,
    };
    let outcome = if invocation.elevate {
        let arguments = args::without_elevate(&context.arguments)?;
        backend.elevate(levels, remove, options, &arguments)
    } else {
        setup_levels(levels, |policy| {
            if remove {
                backend.remove(policy, options)
            } else {
                backend.setup(policy, options)
            }
        })
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

/// Why `run` refuses when no level runs.
fn refusal(levels: &[ResolvedLevel], selection: &Selection, has_levels: bool) -> String {
    if let Outcome::Stopped(index) = selection.outcome {
        return format!(
            "refusing to start the program; {}",
            stopped(&levels[index], &selection.plans[index], has_levels)
        );
    }
    if !has_levels {
        let missing: Vec<_> = selection.plans[0].unavailable().cloned().collect();
        return list(
            "refusing to start the program; this host cannot enforce the policy:",
            &missing,
        );
    }
    let mut message =
        String::from("refusing to start the program; this host enforces no level of the policy:");
    for (level, plan) in levels.iter().zip(&selection.plans) {
        let missing: Vec<_> = plan.unavailable().cloned().collect();
        message.push_str("\n  ");
        message.push_str(&list(&format!("level {}:", level.name), &missing).replace('\n', "\n  "));
    }
    message
}

/// Why the choice stopped at `level`, whose plan has a final report.
fn stopped(level: &ResolvedLevel, plan: &EnforcementPlan, has_levels: bool) -> String {
    if has_levels {
        format!("level {}: {}", level.name, final_failure(plan))
    } else {
        final_failure(plan)
    }
}

/// Why the levels before the one that runs were skipped, for the warning of `run`.
fn skipped(levels: &[ResolvedLevel], plans: &[EnforcementPlan]) -> String {
    let reasons: Vec<String> = levels
        .iter()
        .zip(plans)
        .map(|(level, plan)| {
            let missing: Vec<String> = plan
                .unavailable()
                .map(|item| {
                    format!(
                        "{}: {}",
                        item.requirement.description(),
                        item.status.reason().unwrap_or_default()
                    )
                })
                .collect();
            format!(
                "this host cannot enforce level {} ({})",
                level.name,
                missing.join("; ")
            )
        })
        .collect();
    reasons.join(", and ")
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

/// Why a plan with a final report (`Status::is_final`) ends the run or check with status 125.
/// The final reports come first, then the other requirements that are not enforced, so a lasting
/// shortfall of the host is not lost behind them.
fn final_failure(plan: &EnforcementPlan) -> String {
    let mut reports: Vec<_> = plan.final_reports().cloned().collect();
    reports.extend(
        plan.unavailable()
            .filter(|item| !item.status.is_final())
            .cloned(),
    );
    let headline = if reports
        .iter()
        .any(|item| matches!(item.status, sandy_core::Status::Conflict { .. }))
    {
        "the policy cannot be enforced as written on this host:"
    } else {
        "sandy cannot tell now whether this host enforces the policy:"
    };
    list(headline, &reports)
}

/// `headline` and one line per report.
fn list(headline: &str, items: &[sandy_core::PlanItem]) -> String {
    let mut message = String::from(headline);
    for item in items {
        let description = item.requirement.description();
        match &item.status {
            sandy_core::Status::Unavailable { reason }
            | sandy_core::Status::Indeterminate { reason }
            | sandy_core::Status::Conflict { reason } => {
                message.push_str(&format!("\n  - {description}: {reason}"))
            }
            sandy_core::Status::NeedsSetup { reason } => message.push_str(&format!(
                "\n  - {description}: {reason}; `sandy setup`, run once with administrator \
                 rights, prepares this host"
            )),
            sandy_core::Status::Enforced { .. } => {}
        }
    }
    message
}

#[cfg(target_os = "linux")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_linux::LinuxBackend::new())
}

#[cfg(target_os = "macos")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_macos::MacosBackend::new())
}

#[cfg(windows)]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(sandy_windows::WindowsBackend::new())
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
