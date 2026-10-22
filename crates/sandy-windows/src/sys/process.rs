//! Starts the target and the relays of its exposed and forwarded ports in the AppContainer,
//! waits for the target, and ends the relays by the lifetime rule (docs/DESIGN.md, "Forwarded
//! ports", rule 5).

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, size_of_val};
use std::net::TcpListener;
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, STATUS_CONTROL_C_EXIT, SetHandleInformation, TRUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, GetFileType, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CTRL_BREAK_EVENT, CTRL_C_EVENT, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
    STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::util::{Sid, last_error, wide_nul};

/// The processes to start in the AppContainer, prepared by the caller.
pub struct Launch<'a> {
    pub appcontainer: &'a Sid,
    pub program: Process<'a>,
    /// One relay per exposed or forwarded port.
    pub relays: Vec<Relay<'a>>,
}

/// A relay process: `sandy __relay` for an exposed port or `sandy __forward` for a forwarded
/// port. Its standard input is a pipe that sandy closes when the program ends; the relay then
/// stops taking connections and ends within `sandy_relay::DRAIN`.
pub struct Relay<'a> {
    pub process: Process<'a>,
    /// The listening socket an exposed-port relay receives.
    pub socket: Option<TcpListener>,
    /// The relay writes the line "ready" to standard output once it listens, and the program
    /// starts only after that. A forwarded-port relay creates its listener itself.
    pub reports_ready: bool,
}

/// How a run ended: the program's exit code, and the time by which everything that served the
/// program must have ended (the program's end plus `sandy_relay::DRAIN`).
pub struct Ended {
    pub code: i32,
    pub deadline: Instant,
}

/// The line a forwarded-port relay writes once it listens. It matches the sandy command line.
const RELAY_READY: &str = "ready";
/// How long a relay may take to report that it listens.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything `CreateProcessW` needs for one process.
pub struct Process<'a> {
    /// NUL-terminated path of the executable.
    pub application: Vec<u16>,
    /// NUL-terminated command line.
    pub command_line: Vec<u16>,
    pub environment: Vec<u16>,
    /// NUL-terminated working directory, or `None` for the current one.
    pub cwd: Option<Vec<u16>>,
    pub capabilities: &'a [Sid],
}

/// The job that `on_console_control` terminates. Only a raw handle fits into a static.
static CONSOLE_JOB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub fn run(launch: Launch<'_>) -> Result<Ended, SandboxError> {
    let job = create_job()?;
    let stdio = StandardHandles::prepare()?;

    CONSOLE_JOB.store(job.as_raw_handle(), Ordering::SeqCst);
    // SAFETY: on_console_control has the signature of a HandlerRoutine and stays valid for the
    // life of the process.
    if unsafe { SetConsoleCtrlHandler(Some(on_console_control), TRUE) } == 0 {
        return Err(last_error("cannot install the console control handler"));
    }

    let result = start_and_wait(launch, &job, stdio);
    CONSOLE_JOB.store(ptr::null_mut(), Ordering::SeqCst);
    result
}

fn start_and_wait(
    launch: Launch<'_>,
    job: &OwnedHandle,
    stdio: StandardHandles,
) -> Result<Ended, SandboxError> {
    let Launch {
        appcontainer,
        mut program,
        relays: port_relays,
    } = launch;
    // The relays start before the program, so a relay that cannot start ends the run before the
    // program runs. They run in a job of their own, so that sandy can end the processes the
    // program left behind at once while the relays still deliver accepted connections.
    let relay_job = if port_relays.is_empty() {
        None
    } else {
        Some(create_job()?)
    };
    let mut running = Vec::with_capacity(port_relays.len());
    if let Some(relay_job) = &relay_job {
        for relay in port_relays {
            running.push(start_relay(relay, appcontainer, relay_job, &stdio)?);
        }
    }
    let stdio_handles = stdio.child.each_ref().map(|handle| handle.as_raw_handle());
    let process = start(
        &mut program,
        appcontainer,
        job,
        stdio_handles,
        &[],
        "program",
    )?;
    let StandardHandles { child, relays } = stdio;
    // The target owns its copies now. sandy's copies of the pipe ends would keep the relays
    // from seeing the end of the output.
    drop(child);

    // SAFETY: process is a valid process handle owned by this function.
    let waited = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    if waited != WAIT_OBJECT_0 {
        return Err(last_error("cannot wait for the program"));
    }
    let deadline = Instant::now() + sandy_relay::DRAIN;
    let mut code = 0u32;
    // SAFETY: process is valid and code is a writable u32.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(last_error("cannot read the exit code of the program"));
    }
    // Processes the program left behind would die when sandy exits and the job closes. Ending
    // them now also closes their copies of the output pipes, so the console relays finish, and
    // nothing in the sandbox can make a new connection while the relays drain.
    // SAFETY: job is a valid job handle.
    unsafe { TerminateJobObject(job.as_raw_handle(), code) };
    if let Some(relay_job) = relay_job {
        end_relays(running, &relay_job, deadline, code);
    }
    for relay in relays {
        let _ = relay.join();
    }
    // Windows exit codes are 32 bits wide; the caller passes them on unchanged.
    Ok(Ended {
        code: code as i32,
        deadline,
    })
}

/// A started relay: its process and the write end of its standard input.
struct RunningRelay {
    process: OwnedHandle,
    input: OwnedHandle,
}

/// Starts `relay` suspended in `relay_job` like the program, with a pipe as standard input,
/// "ready" reporting on standard output if it asks for it, and the program's standard error.
fn start_relay(
    mut relay: Relay<'_>,
    appcontainer: &Sid,
    relay_job: &OwnedHandle,
    stdio: &StandardHandles,
) -> Result<RunningRelay, SandboxError> {
    let (input_read, input) = pipe("input of a relay")?;
    make_inheritable(&input_read, "input of a relay")?;
    let (ready_read, output) = if relay.reports_ready {
        let (read, write) = pipe("output of a relay")?;
        make_inheritable(&write, "output of a relay")?;
        (Some(read), write)
    } else {
        (None, open_null("output of a relay")?)
    };
    let relay_stdio = [
        input_read.as_raw_handle(),
        output.as_raw_handle(),
        stdio.child[2].as_raw_handle(),
    ];
    let socket = relay
        .socket
        .as_ref()
        .map(|socket| socket.as_raw_socket() as HANDLE);
    let process = start(
        &mut relay.process,
        appcontainer,
        relay_job,
        relay_stdio,
        socket.as_slice(),
        "relay",
    )?;
    // The relay holds its own handles now. Without sandy's copies, the relay sees the end of its
    // input when sandy closes `input`, and clients of an exposed port are refused once the relay
    // closes its socket.
    drop((input_read, output, relay.socket));
    if let Some(ready_read) = ready_read {
        wait_until_ready(ready_read)?;
    }
    Ok(RunningRelay { process, input })
}

/// Waits until the relay writes "ready", ends, or `READY_TIMEOUT` passes.
fn wait_until_ready(output: OwnedHandle) -> Result<(), SandboxError> {
    let (sender, receiver) = mpsc::channel();
    // The thread ends when the relay writes a line or ends; if the relay hangs, the job closes
    // when the run fails, which ends the relay and with it the thread.
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = io::BufRead::read_line(&mut io::BufReader::new(File::from(output)), &mut line);
        let _ = sender.send(read.map(|_| line));
    });
    match receiver.recv_timeout(READY_TIMEOUT) {
        Ok(Ok(line)) if line.trim_end() == RELAY_READY => Ok(()),
        Ok(_) => Err(SandboxError::new(
            "a forwarded-port relay ended before it listened; its error is on standard error",
        )),
        Err(_) => Err(SandboxError::new(format!(
            "a forwarded-port relay did not listen within {} seconds",
            READY_TIMEOUT.as_secs()
        ))),
    }
}

/// Ends the relays by the lifetime rule: closing their input tells them to take no new
/// connection and to let accepted ones finish; at `deadline` sandy ends whatever still runs.
fn end_relays(running: Vec<RunningRelay>, relay_job: &OwnedHandle, deadline: Instant, code: u32) {
    let mut processes = Vec::with_capacity(running.len());
    for relay in running {
        drop(relay.input);
        processes.push(relay.process);
    }
    for process in &processes {
        let left = deadline.saturating_duration_since(Instant::now());
        let millis = u32::try_from(left.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: process is a valid process handle; a timeout only limits the wait.
        unsafe { WaitForSingleObject(process.as_raw_handle(), millis) };
    }
    // SAFETY: relay_job is a valid job handle.
    unsafe { TerminateJobObject(relay_job.as_raw_handle(), code) };
}

/// Kills the job on Ctrl+C and Ctrl+Break. The target has its own console (see `start`), so the
/// console of sandy does not reach it. The exit status is the one a console program gets when
/// Ctrl+C ends it.
unsafe extern "system" fn on_console_control(event: u32) -> windows_sys::core::BOOL {
    let job = CONSOLE_JOB.load(Ordering::SeqCst);
    if !job.is_null() {
        // SAFETY: CONSOLE_JOB holds a job handle while `run` waits, and null otherwise.
        unsafe { TerminateJobObject(job, STATUS_CONTROL_C_EXIT as u32) };
    }
    if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
        TRUE
    } else {
        FALSE
    }
}

fn create_job() -> Result<OwnedHandle, SandboxError> {
    // SAFETY: null attributes and name create an unnamed job with a handle that is not
    // inheritable.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(last_error("cannot create the job object"));
    }
    // SAFETY: raw is a new handle that nothing else owns.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };

    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    // No JOB_OBJECT_LIMIT_BREAKAWAY_OK: every child of the target stays in the job.
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    set_job_information(
        &job,
        JobObjectExtendedLimitInformation,
        &limits,
        "kill-on-close limit",
    )?;

    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    set_job_information(&job, JobObjectBasicUIRestrictions, &ui, "UI restrictions")?;
    Ok(job)
}

fn set_job_information<T>(
    job: &OwnedHandle,
    class: i32,
    value: &T,
    what: &str,
) -> Result<(), SandboxError> {
    // SAFETY: value points to a structure of the type that `class` names, and the length is its
    // size.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            class,
            (value as *const T).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error(format!("cannot set the job {what}")));
    }
    Ok(())
}

/// Creates the process suspended in the AppContainer, puts it into the job, then lets it run.
/// It cannot run any code before it is in the job. It inherits `stdio` and `extra`, which must
/// be inheritable, and no other handle.
fn start(
    launch: &mut Process<'_>,
    appcontainer: &Sid,
    job: &OwnedHandle,
    stdio: [HANDLE; 3],
    extra: &[HANDLE],
    what: &str,
) -> Result<OwnedHandle, SandboxError> {
    let mut capabilities: Vec<SID_AND_ATTRIBUTES> = launch
        .capabilities
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED as u32,
        })
        .collect();
    let security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer.as_psid(),
        Capabilities: if capabilities.is_empty() {
            ptr::null_mut()
        } else {
            capabilities.as_mut_ptr()
        },
        CapabilityCount: capabilities.len() as u32,
        Reserved: 0,
    };
    // Windows may reject a handle list that names a handle twice.
    let mut inherited: Vec<HANDLE> = Vec::with_capacity(stdio.len() + extra.len());
    for handle in stdio.iter().chain(extra) {
        if !inherited.contains(handle) {
            inherited.push(*handle);
        }
    }

    let mut attributes = AttributeList::new(2)?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &security_capabilities,
    )?;
    // The handle list limits inheritance to these handles, although bInheritHandles is TRUE.
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.as_slice())?;

    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdio[0];
    startup.StartupInfo.hStdOutput = stdio[1];
    startup.StartupInfo.hStdError = stdio[2];
    startup.lpAttributeList = attributes.as_ptr();

    // CREATE_NO_WINDOW gives a console program its own console without a window instead of
    // the console of sandy. A shared console would let the target write keystrokes into the
    // console input that the shell reads after sandy exits, and send Ctrl+C to every process on
    // it.
    let flags = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW;
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: all strings are NUL-terminated (application, command_line, cwd) or a
    // double-NUL-terminated block (environment); command_line is writable as CreateProcessW
    // requires; startup, the attribute list and the values it points to outlive the call.
    let ok = unsafe {
        CreateProcessW(
            launch.application.as_ptr(),
            launch.command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            TRUE,
            flags,
            launch.environment.as_ptr().cast(),
            launch.cwd.as_ref().map_or(ptr::null(), |cwd| cwd.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(last_error(format!(
            "cannot create the {what} process in the AppContainer"
        )));
    }
    // SAFETY: CreateProcessW succeeded, so both handles are new and owned by sandy.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };

    let abort = |error: SandboxError| {
        // SAFETY: process is a valid handle; the process never ran because it is suspended.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        error
    };
    // SAFETY: job and process are valid handles.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        return Err(abort(last_error(format!(
            "cannot put the {what} into the job object"
        ))));
    }
    // SAFETY: thread is the valid handle of the suspended main thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(abort(last_error(format!("cannot resume the {what}"))));
    }
    Ok(process)
}

/// A `PROC_THREAD_ATTRIBUTE_LIST`. The values it points to must outlive it.
struct AttributeList {
    buffer: Vec<usize>,
}

impl AttributeList {
    fn new(count: u32) -> Result<AttributeList, SandboxError> {
        let mut size = 0usize;
        // SAFETY: a null list with a size pointer only queries the required size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size) };
        let mut list = AttributeList {
            buffer: vec![0; size.div_ceil(size_of::<usize>())],
        };
        // SAFETY: the buffer is at least `size` bytes and pointer-aligned.
        let ok = unsafe { InitializeProcThreadAttributeList(list.as_ptr(), count, 0, &mut size) };
        if ok == 0 {
            // Nothing to delete: the list was not initialized.
            std::mem::forget(list);
            return Err(last_error("cannot initialize the process attribute list"));
        }
        Ok(list)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }

    fn set<T: ?Sized>(&mut self, attribute: u32, value: &T) -> Result<(), SandboxError> {
        // SAFETY: the list is initialized; value points to `size_of_val(value)` bytes in the
        // layout the attribute expects, and the caller keeps it alive until CreateProcessW.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute as usize,
                (value as *const T).cast(),
                size_of_val(value),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(last_error(format!(
                "cannot set process attribute {attribute:#x}"
            )));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new`.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// The three standard handles of the target, all inheritable, and the threads that copy data
/// between a console of sandy and a pipe of the target.
struct StandardHandles {
    child: [OwnedHandle; 3],
    relays: Vec<JoinHandle<()>>,
}

impl StandardHandles {
    fn prepare() -> Result<StandardHandles, SandboxError> {
        let mut relays = Vec::new();
        let input = Self::slot(STD_INPUT_HANDLE, "input", &mut relays)?;
        let output = Self::slot(STD_OUTPUT_HANDLE, "output", &mut relays)?;
        let error = Self::slot(STD_ERROR_HANDLE, "error", &mut relays)?;
        Ok(StandardHandles {
            child: [input, output, error],
            relays,
        })
    }

    /// The target never receives a console handle: with one it could write keystrokes into the
    /// console input buffer even without being attached to the console. A console is relayed
    /// through a pipe instead. Other handles are duplicated, a missing one becomes NUL.
    fn slot(
        which: STD_HANDLE,
        name: &str,
        relays: &mut Vec<JoinHandle<()>>,
    ) -> Result<OwnedHandle, SandboxError> {
        // SAFETY: GetStdHandle has no preconditions.
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return open_null(name);
        }
        if !is_console(handle) {
            return duplicate_inheritable(handle, name);
        }
        let (read, write) = pipe(name)?;
        let (child, relay) = if which == STD_INPUT_HANDLE {
            let sink = File::from(write);
            (read, std::thread::spawn(move || relay_input(sink)))
        } else {
            let source = File::from(read);
            let to_error = which == STD_ERROR_HANDLE;
            (
                write,
                std::thread::spawn(move || {
                    if to_error {
                        relay_output(source, io::stderr())
                    } else {
                        relay_output(source, io::stdout())
                    }
                }),
            )
        };
        make_inheritable(&child, name)?;
        // The input relay blocks on the console until sandy exits; only output relays are
        // joined.
        if which != STD_INPUT_HANDLE {
            relays.push(relay);
        }
        Ok(child)
    }
}

fn is_console(handle: HANDLE) -> bool {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: handle is a standard handle of this process; both calls only query it.
    unsafe { GetFileType(handle) == FILE_TYPE_CHAR && GetConsoleMode(handle, &mut mode) != 0 }
}

fn duplicate_inheritable(handle: HANDLE, name: &str) -> Result<OwnedHandle, SandboxError> {
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: handle is a valid handle of this process; the duplicate is a new handle that
    // sandy owns.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(last_error(format!(
            "cannot pass standard {name} to the program"
        )));
    }
    // SAFETY: DuplicateHandle succeeded, so duplicate is a new handle owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

fn open_null(name: &str) -> Result<OwnedHandle, SandboxError> {
    let path = wide_nul(r"\\.\NUL".as_ref());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: TRUE,
    };
    // SAFETY: path is NUL-terminated and attributes outlives the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error(format!(
            "cannot open the NUL device for standard {name}"
        )));
    }
    // SAFETY: CreateFileW succeeded, so handle is new and owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn pipe(name: &str) -> Result<(OwnedHandle, OwnedHandle), SandboxError> {
    let (mut read, mut write): (HANDLE, HANDLE) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: both out pointers are valid; null attributes create handles that are not
    // inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(last_error(format!(
            "cannot create the pipe for standard {name}"
        )));
    }
    // SAFETY: CreatePipe succeeded, so both handles are new and owned by nobody else.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

fn make_inheritable(handle: &OwnedHandle, name: &str) -> Result<(), SandboxError> {
    // SAFETY: handle is valid; the call changes only its inherit flag.
    let ok = unsafe {
        SetHandleInformation(
            handle.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if ok == 0 {
        return Err(last_error(format!(
            "cannot pass standard {name} to the program"
        )));
    }
    Ok(())
}

/// Copies console input to the target. The standard library reads the console as UTF-16 and
/// returns UTF-8, the encoding a program expects from a pipe.
fn relay_input(mut sink: File) {
    let _ = io::copy(&mut io::stdin().lock(), &mut sink);
}

/// Copies the output of the target to the console. The standard library writes UTF-8 to the
/// console as UTF-16; it rejects bytes that are not UTF-8, which become U+FFFD here.
fn relay_output(mut source: File, mut console: impl Write) {
    let mut buffer = [0u8; 8192];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        let mut rest = &buffer[..read];
        while !rest.is_empty() {
            match console.write(rest) {
                Ok(0) => return,
                Ok(written) => rest = &rest[written..],
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    if console.write_all("\u{FFFD}".as_bytes()).is_err() {
                        return;
                    }
                    rest = &rest[1..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
        let _ = console.flush();
    }
}
