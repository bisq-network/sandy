//! Windows-specific escape tests. Like `escape.rs`, they run `sandy-probe` inside the sandbox
//! and check every denial against a control run outside it, so a test cannot pass because the
//! action was impossible anyway.
//!
//! Tests that need the loopback exemption call `prepare_loopback_exemption`, which runs
//! `sandy setup` and needs administrator rights once per machine.
#![cfg(windows)]

mod common;

use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

const EXIT_NOT_ENFORCEABLE: i32 = 1;

/// The status of a program that Ctrl+C or Ctrl+Break ended (`STATUS_CONTROL_C_EXIT`).
const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013A_u32 as i32;

fn user_profile() -> PathBuf {
    PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE is set"))
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|arg| arg.to_string()).collect()
}

/// `sandy run` arguments without the probe: platform options, then `extra`, then `program`.
fn run_program(extra: &[String], program: &str, program_args: &[&str]) -> Vec<String> {
    let mut run = vec!["run".to_string()];
    run.extend(platform_args());
    run.extend_from_slice(extra);
    run.extend(["--".to_string(), program.to_string()]);
    run.extend(args(program_args));
    run
}

#[test]
fn reads_in_the_user_profile_only_when_allowed() {
    let fixture = Fixture::new_in(&user_profile(), "profile");
    let lines = controlled(
        &fixture.access_args(),
        &[
            ("read", &fixture.arg("ro/file")),
            ("read", &fixture.arg("secret/file")),
            ("list", &fixture.arg("secret")),
            ("write", &fixture.arg("secret/new")),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    lines[2].assert_blocked();
    lines[3].assert_blocked();
}

/// A directory laid out like the Startup folder, whose programs run at logon. The real folder
/// is not touched.
#[test]
fn cannot_write_to_a_startup_like_directory() {
    let fixture = Fixture::new_in(&user_profile(), "startup");
    let startup = fixture.path("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    fs::create_dir_all(&startup).unwrap();
    let dropped = startup.join("dropped.cmd");
    let target = dropped.to_str().unwrap();
    probe_outside(&[("write", target)])[0].assert_ok();
    fs::remove_file(&dropped).unwrap();

    let lines = probe_inside(&fixture.access_args(), &[("write", target)]);
    lines[0].assert_blocked();
    assert!(!dropped.exists());
}

/// Read-write grants never contain FILE_EXECUTE or WRITE_DAC, also not for files the program
/// creates itself.
#[test]
fn read_write_paths_are_not_executable() {
    let fixture = Fixture::new("rwexec");
    let copied = fixture.copy_probe("rw");
    let lines = controlled(
        &fixture.access_args(),
        &[("exec", &copied), ("write-dac", &copied)],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();

    let made = fixture.arg("rw/made-inside.exe");
    let lines = probe_inside(
        &fixture.access_args(),
        &[("copy-self", &made), ("exec", &made), ("write-dac", &made)],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    lines[2].assert_blocked();
}

/// A writable directory where Windows lets every AppContainer execute new files, as below
/// C:\Program Files, would make files the program writes executable (rules 3 and 6). sandy
/// refuses such a policy before it starts anything.
#[test]
fn a_writable_path_that_all_appcontainers_may_execute_is_refused() {
    let fixture = Fixture::new("rw-aap-exec");
    let check = |fixture: &Fixture| {
        let mut args = vec!["check".to_string()];
        args.extend(platform_args());
        args.extend(fixture.access_args());
        sandy(&args)
    };
    // Control: the fixture's writable directory is accepted.
    let output = check(&fixture);
    assert!(output.status.success(), "{output:?}");

    // ALL APPLICATION PACKAGES, read and execute, inherited by everything created inside.
    let granted = Command::new("icacls")
        .args([&fixture.arg("rw"), "/grant", "*S-1-15-2-1:(OI)(CI)(RX)"])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");
    let output = check(&fixture);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALL APPLICATION PACKAGES"), "{stdout}");
}

/// sandy grants each path to a capability that only runs with this path in the policy hold.
/// The access control entry stays on disk, but it must grant nothing to a later run.
#[test]
fn a_path_removed_from_the_policy_is_denied_at_the_next_run() {
    let fixture = Fixture::new("removed");
    let file = fixture.arg("ro/file");
    let lines = controlled(&fixture.access_args(), &[("read", &file)]);
    lines[0].assert_ok();
    let without_ro = args(&["--read-write", &fixture.arg("rw")]);
    let lines = probe_inside(&without_ro, &[("read", &file)]);
    lines[0].assert_blocked();
}

#[test]
fn refuses_to_grant_through_a_junction() {
    let fixture = Fixture::new("junction");
    let link = fixture.path("ro/link");
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(plain_path(&link))
        .arg(plain_path(&fixture.path("secret")))
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");
    let secret = fixture.arg("secret/file");
    let output = sandy(run_program(
        &fixture.access_args(),
        &probe_path(),
        &["read", &secret],
    ));
    // Remove the junction itself, not the files it points to.
    fs::remove_dir(&link).unwrap();
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("junction"), "{stderr}");
}

#[test]
fn cannot_open_processes_outside() {
    let fixture = Fixture::new("process");
    let test_process = std::process::id().to_string();
    let lines = controlled(
        &fixture.access_args(),
        &[
            ("open-process-read", &test_process),
            ("open-process-terminate", &test_process),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_blocked();
}

/// sandy itself inherits every inheritable handle of this test, because the standard library
/// creates processes with handle inheritance on. The program must still receive none of them.
#[test]
fn inherits_no_handles_but_the_standard_ones() {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    // A process with strict handle checks ends with this status when it uses a value that is
    // not a handle. The CI runners enable these checks; then the crash shows that nothing was
    // inherited.
    const STATUS_INVALID_HANDLE: i32 = 0xC000_0008_u32 as i32;

    let fixture = Fixture::new("handles");
    let file = fs::File::open(fixture.path("secret/file")).unwrap();
    // SAFETY: the handle belongs to `file`, which outlives both probe runs.
    let ok = unsafe {
        SetHandleInformation(
            file.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(ok, 0);
    let value = (file.as_raw_handle() as usize).to_string();

    let outside = probe_outside(&[("handle-path", &value)]);
    outside[0].assert_ok();
    assert!(outside[0].detail.ends_with(r"secret\file"), "{outside:?}");

    let output = sandy(run_args(&fixture.access_args(), &[("handle-path", &value)]));
    if output.status.code() == Some(STATUS_INVALID_HANDLE) {
        return;
    }
    assert!(output.status.success(), "{output:?}");
    let inside = parse(&output);
    assert!(
        inside[0].result != "ok" || inside[0].detail != outside[0].detail,
        "the program inherited a handle to the secret file: {inside:?}"
    );
}

/// The registry autostart key of the user runs programs at logon. The AppContainer may at most
/// write to its own registry storage; the real key must not change.
#[test]
fn cannot_add_a_registry_autostart_entry() {
    let fixture = Fixture::new("registry");
    let value = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Run\sandy-escape-test-{}",
        std::process::id()
    );
    let control = probe_outside(&[("reg-set-hkcu", &value), ("reg-get-hkcu", &value)]);
    control[0].assert_ok();
    control[1].assert_ok();
    probe_outside(&[("reg-delete-hkcu", &value)])[0].assert_ok();

    let _ = probe_inside(&fixture.access_args(), &[("reg-set-hkcu", &value)]);
    let after = probe_outside(&[("reg-get-hkcu", &value)]);
    if after[0].result == "ok" {
        let _ = probe_outside(&[("reg-delete-hkcu", &value)]);
    }
    after[0].assert_blocked();
}

#[test]
fn cannot_connect_to_a_named_pipe_outside() {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let fixture = Fixture::new("pipe");
    let name = format!(r"\\.\pipe\sandy-escape-test-{}", std::process::id());
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // One instance for the control run and one for the sandboxed run. A null security
    // descriptor gives the default DACL of named pipes.
    let instances: Vec<_> = (0..2)
        .map(|_| {
            // SAFETY: wide is NUL-terminated; the other arguments are plain values.
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE);
            handle
        })
        .collect();
    let lines = controlled(&fixture.access_args(), &[("pipe-connect", &name)]);
    for handle in instances {
        // SAFETY: each handle is a pipe instance owned by this test.
        unsafe { CloseHandle(handle) };
    }
    lines[0].assert_blocked();
}

/// The loopback exemption that `sandy setup` installs allows connections from the program to
/// listeners outside the sandbox; without it, AppContainer network isolation blocks them.
#[test]
fn loopback_from_the_program_needs_the_exemption() {
    let fixture = Fixture::new("loopout");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    probe_outside(&[("tcp-connect", &address)])[0].assert_ok();

    let mut not_exempt = fixture.access_args();
    not_exempt.extend(args(&[
        "--ip",
        "all",
        "--appcontainer",
        &appcontainer_name(),
    ]));
    probe_inside(&not_exempt, &[("tcp-connect", &address)])[0].assert_blocked();

    prepare_loopback_exemption();
    let mut exempt = fixture.access_args();
    exempt.extend(args(&[
        "--ip",
        "all",
        "--appcontainer",
        &appcontainer_loopback_name(),
    ]));
    probe_inside(&exempt, &[("tcp-connect", &address)])[0].assert_ok();
}

/// Microsoft documents that the loopback exemption covers only connections from the
/// AppContainer; connections to it need a debugging mode of CheckNetIsolation.
#[test]
fn loopback_to_the_program_is_blocked_with_and_without_exemption() {
    let (connected, line) = inbound_tcp(None);
    assert!(connected, "control: {line:?}");
    line.assert_ok();

    prepare_loopback_exemption();
    let fixture = Fixture::new("loopin");
    for container in [appcontainer_name(), appcontainer_loopback_name()] {
        let mut sandbox_args = fixture.access_args();
        sandbox_args.extend(args(&["--ip", "all", "--appcontainer", &container]));
        let (connected, line) = inbound_tcp(Some(&sandbox_args));
        assert!(
            !connected,
            "connected to the program in {container}: {line:?}"
        );
        line.assert_blocked();
    }
}

/// An exempt AppContainer reaches 127.0.0.1 even without network capabilities, so sandy must
/// refuse it for a policy without IP networking.
#[test]
fn an_exempt_appcontainer_cannot_deny_ip() {
    prepare_loopback_exemption();
    let output = sandy(["check", "--appcontainer", &appcontainer_loopback_name()]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exempt"), "{stdout}");
}

/// The program has its own console. Ctrl+Break sent to every process on the console must not
/// reach sandy, whose handler would end the job with STATUS_CONTROL_C_EXIT. sandy runs in a new
/// console, so a failure cannot reach this test or Cargo.
#[test]
fn console_control_events_stay_inside() {
    use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

    let fixture = Fixture::new("console");
    let output = Command::new(sandy_path())
        .args(run_args(
            &fixture.access_args(),
            &[("ctrl-break-console", "0")],
        ))
        .creation_flags(CREATE_NEW_CONSOLE)
        .output()
        .unwrap();
    assert_ne!(
        output.status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "{output:?}"
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(parse(&output).len(), 1, "{output:?}");
}

/// The path without the `\\?\` prefix of canonical paths, for interfaces whose documentation
/// shows only ordinary paths: AF_UNIX addresses and `mklink`.
fn plain_path(path: &Path) -> String {
    let text = path.to_str().unwrap();
    text.strip_prefix(r"\\?\").unwrap_or(text).to_string()
}

/// A listening AF_UNIX socket of this test, closed on drop.
struct UnixListener(windows_sys::Win32::Networking::WinSock::SOCKET);

impl UnixListener {
    fn bind(path: &str) -> UnixListener {
        use windows_sys::Win32::Networking::WinSock::{
            AF_UNIX, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, WSADATA, WSAStartup, bind,
            listen, socket,
        };
        // SAFETY: WSADATA is plain data that WSAStartup fills.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: data is a valid out pointer.
        assert_eq!(unsafe { WSAStartup(0x0202, &mut data) }, 0);
        let mut address = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        let bytes = path.as_bytes();
        assert!(bytes.len() < address.sun_path.len(), "socket path too long");
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as i8;
        }
        // SAFETY: socket has no memory safety preconditions.
        let handle = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        assert_ne!(handle, INVALID_SOCKET);
        // SAFETY: address is a SOCKADDR_UN and its size is passed.
        let bound = unsafe {
            bind(
                handle,
                (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(),
                std::mem::size_of::<SOCKADDR_UN>() as i32,
            )
        };
        assert_eq!(bound, 0, "bind {path}");
        // SAFETY: handle is a bound socket.
        assert_eq!(unsafe { listen(handle, 4) }, 0);
        UnixListener(handle)
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        // SAFETY: the socket is open and closed exactly once.
        unsafe { windows_sys::Win32::Networking::WinSock::closesocket(self.0) };
    }
}

/// The program can write no socket file outside its read-write paths, so it cannot connect to
/// sockets there, also when the policy has read-write paths.
#[test]
fn unix_sockets_outside_writable_paths_are_unreachable() {
    let fixture = Fixture::new("afunix");
    let socket = plain_path(&fixture.path("secret/socket"));
    let _listener = UnixListener::bind(&socket);
    probe_outside(&[("afunix-connect", &socket)])[0].assert_ok();
    probe_inside(&fixture.access_args(), &[("afunix-connect", &socket)])[0].assert_blocked();
}

/// A socket in a read-write path is reachable: Windows checks only write access to the socket
/// file. UnixSocketsDenied is a lower bound that allows this. If this test fails, AppContainers
/// cannot use AF_UNIX at all.
#[test]
fn unix_sockets_in_writable_paths_are_reachable() {
    let fixture = Fixture::new("afunixrw");
    let socket = plain_path(&fixture.path("rw/socket"));
    let _listener = UnixListener::bind(&socket);
    probe_inside(&fixture.access_args(), &[("afunix-connect", &socket)])[0].assert_ok();
}

/// A program that serves on an AF_UNIX socket in a read-write path is reachable from outside the
/// sandbox. Inbound loopback TCP is always blocked for AppContainers, so this is the way a
/// sandboxed server can take local connections on Windows.
#[test]
fn unix_socket_server_in_a_writable_path_is_reachable_from_outside() {
    let fixture = Fixture::new("afunixserver");
    let socket = plain_path(&fixture.path("rw/server"));
    let mut child = Command::new(sandy_path())
        .args(run_args(
            &fixture.access_args(),
            &[("afunix-accept", &socket)],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut connected = false;
    while !connected && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        connected = probe_outside(&[("afunix-connect", &socket)])[0].result == "ok";
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = child.wait_with_output().unwrap();
    assert!(connected, "no connection to the program: {output:?}");
    parse(&output)[0].assert_ok();
}

/// cmd.exe lies in the system set, whose permissions the user cannot change; sandy must run it
/// without a grant and pass its full 32-bit exit code on.
#[test]
fn passes_the_32_bit_exit_code_of_a_system_program() {
    let cmd = Path::new(&std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join("cmd.exe");
    let output = sandy(run_program(
        &[],
        cmd.to_str().unwrap(),
        &["/c", "exit", "305419896"],
    ));
    assert_eq!(output.status.code(), Some(0x1234_5678), "{output:?}");
    delete_test_profiles();
}

#[test]
fn environment_has_system_root_and_nothing_else_unasked() {
    let fixture = Fixture::new("env");
    let lines = probe_inside(
        &fixture.access_args(),
        &[
            ("env", "SystemRoot"),
            ("env", "PATH"),
            ("env", "USERPROFILE"),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    lines[2].assert_blocked();
}

#[test]
fn refuses_batch_files() {
    let fixture = Fixture::new("batch");
    let script = fixture.path("bin/run.cmd");
    fs::write(&script, b"@echo off\r\n").unwrap();
    let output = sandy(run_program(
        &args(&["--read-exec", &fixture.arg("bin")]),
        script.to_str().unwrap(),
        &[],
    ));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
}

#[test]
fn needs_an_appcontainer_name() {
    let output = sandy(["check"]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("appcontainer"), "{stdout}");
}

#[test]
fn system_none_is_not_enforceable() {
    let output = sandy([
        "check",
        "--appcontainer",
        &appcontainer_name(),
        "--system",
        "none",
    ]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
}

/// Starts sandy with `sandy_args` inside a new job with UI restrictions `ui`, like a CI agent or
/// an IDE that runs it in a job. Returns the exit code and the standard output.
fn sandy_in_job(ui: u32, sandy_args: &[String]) -> (u32, String) {
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JobObjectBasicUIRestrictions, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
    };

    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: both out pointers are valid.
    let piped = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
    assert_ne!(piped, 0);
    // SAFETY: CreatePipe returned two new handles that this function owns.
    let (read, write) = unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    };
    // SAFETY: write is a valid handle; only its inherit flag changes.
    unsafe {
        SetHandleInformation(
            write.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };

    // SAFETY: null attributes and name create an unnamed job.
    let job = unsafe {
        OwnedHandle::from_raw_handle(CreateJobObjectW(std::ptr::null(), std::ptr::null()))
    };
    if ui != 0 {
        let restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: ui,
        };
        // SAFETY: the structure matches the information class and outlives the call.
        let ok = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectBasicUIRestrictions,
                (&restrictions as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        };
        assert_ne!(ok, 0);
    }

    let mut line = format!("\"{}\"", sandy_path());
    for arg in sandy_args {
        line.push_str(&format!(" \"{arg}\""));
    }
    let mut line: Vec<u16> = line.encode_utf16().chain([0]).collect();
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write.as_raw_handle();
    startup.hStdError = write.as_raw_handle();
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: line is NUL-terminated and writable; startup and info outlive the call.
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut info,
        )
    };
    assert_ne!(created, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: CreateProcessW returned two new handles that this function owns.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    // SAFETY: the job and the suspended process are valid handles.
    let assigned =
        unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) };
    assert_ne!(assigned, 0);
    // SAFETY: thread is the suspended main thread of sandy.
    unsafe { ResumeThread(thread.as_raw_handle()) };
    drop(write);
    let mut output = String::new();
    let _ = std::fs::File::from(read).read_to_string(&mut output);
    let mut code = 0u32;
    // SAFETY: process is valid; code is a writable u32.
    unsafe {
        WaitForSingleObject(process.as_raw_handle(), INFINITE);
        GetExitCodeProcess(process.as_raw_handle(), &mut code);
    }
    (code, output)
}

/// A job with UI restrictions cannot hold sandy's job, which sets UI restrictions too. `check`
/// must predict this, so that it agrees with `run`; sandy must not break away from the job.
#[test]
fn check_and_run_agree_inside_a_job_with_ui_restrictions() {
    const READ_CLIPBOARD: u32 = 0x2;
    let check = args(&["check", "--appcontainer", &appcontainer_name()]);
    let run = run_args(&[], &[("env", "SystemRoot")]);

    let (code, output) = sandy_in_job(0, &check);
    assert_eq!(code, 0, "check in a job without UI restrictions: {output}");
    let (code, output) = sandy_in_job(0, &run);
    assert_eq!(code, 0, "run in a job without UI restrictions: {output}");

    let (code, output) = sandy_in_job(READ_CLIPBOARD, &check);
    assert_eq!(code as i32, EXIT_NOT_ENFORCEABLE, "{output}");
    assert!(output.contains("UI restrictions"), "{output}");
    let (code, output) = sandy_in_job(READ_CLIPBOARD, &run);
    assert_eq!(code as i32, EXIT_FAILURE, "{output}");

    delete_test_profiles();
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Connects to `port` until `sandy` listens there.
fn connect_when_listening(sandy: &mut Child, port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return stream,
            Err(error) => assert!(Instant::now() < deadline, "sandy never listened: {error}"),
        }
        if sandy.try_wait().unwrap().is_some() {
            let output = sandy.stderr.take().map(std::io::read_to_string);
            panic!("sandy ended before it listened: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether `listener` (non-blocking) accepts a connection within `wait`.
fn accepts_within(listener: &TcpListener, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
    false
}

/// A relay connects only to the program's port it was started for, and it connects from inside
/// the AppContainer. So a listener outside the sandbox stays unreachable through a relay, also
/// when the policy exposes that listener's port number. The relay to the program shows that the
/// relays run, and the last connection shows that the outside listener accepts.
#[test]
fn relays_reach_only_the_program() {
    let fixture = Fixture::new("expose-only");
    let outside = TcpListener::bind("127.0.0.1:0").unwrap();
    outside.set_nonblocking(true).unwrap();
    let outside_port = outside.local_addr().unwrap().port();
    let (inner, to_program, to_outside) = (free_port(), free_port(), free_port());
    let mut sandbox_args = fixture.access_args();
    // Without the loopback exemption, which would let the program itself reach the listener.
    sandbox_args.extend(args(&[
        "--appcontainer",
        &appcontainer_name(),
        "--ip",
        "all",
        "--expose",
        &format!("127.0.0.1:{to_program}={inner}"),
        "--expose",
        &format!("127.0.0.1:{to_outside}={outside_port}"),
    ]));
    let inner_address = format!("127.0.0.1:{inner}");
    let mut server = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &[("tcp-accept", &inner_address)]))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut client = connect_when_listening(&mut server, to_outside);
    let _ = client.write_all(b"probe");
    assert!(
        !accepts_within(&outside, Duration::from_secs(3)),
        "a relay reached a listener outside the sandbox"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the program never accepted");
        let _ = TcpStream::connect_timeout(
            &format!("127.0.0.1:{to_program}").parse().unwrap(),
            Duration::from_millis(500),
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = server.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();

    assert!(!accepts_within(&outside, Duration::from_millis(200)));
    let _control = TcpStream::connect(("127.0.0.1", outside_port)).unwrap();
    assert!(accepts_within(&outside, Duration::from_secs(3)));
}

/// Deletes an AppContainer profile and its folder. Best effort, so a repeated run starts clean.
fn delete_profile(name: &str) {
    use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: the name is NUL-terminated.
    unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
}

/// `sandy run` arguments with an explicit AppContainer name (not the shared test name), extra
/// options, and the probe with `actions`.
fn named_run(name: &str, extra: &[&str], actions: &[(&str, &str)]) -> Vec<String> {
    let mut run = vec![
        "run".to_string(),
        "--appcontainer".to_string(),
        name.to_string(),
    ];
    run.extend(extra.iter().map(|option| option.to_string()));
    run.push("--".to_string());
    run.push(probe_path());
    run.extend(
        actions
            .iter()
            .flat_map(|(action, target)| [action.to_string(), target.to_string()]),
    );
    run
}

/// Two runs that share one AppContainer name share one sandbox: processes in it reach and control
/// each other. So a second run with the same name must match the first run's resolved policy
/// while the first is active. The same policy may run at the same time; a different one is
/// refused until the first run ends, then allowed. The coordination uses a named kernel object
/// the sandboxed program cannot reach, and the first run holds it only while it runs, so a
/// crashed run does not block the name forever.
#[test]
fn a_concurrent_run_must_match_the_active_policy() {
    let name = "sandy.concurrency-test";
    delete_profile(name);
    let fixture = Fixture::new("concurrency");
    let writable = ["--read-write", &fixture.arg("rw")];
    let other_policy = [
        "--read-write",
        &fixture.arg("rw"),
        "--read",
        &fixture.arg("ro"),
    ];
    let ready = fixture.path("rw/ready");
    let ready_arg = ready.to_str().unwrap();

    // The first run holds the name. It writes a marker, then stays alive, so the test knows the
    // run is active (its coordination object is held before the program starts).
    let mut first = Command::new(sandy_path())
        .args(named_run(
            name,
            &writable,
            &[("write", ready_arg), ("sleep", "20000")],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        if let Some(status) = first.try_wait().unwrap() {
            panic!("the first run exited early: {status:?}");
        }
        assert!(Instant::now() < deadline, "the first run never started");
        std::thread::sleep(Duration::from_millis(100));
    }

    // The same policy (same options, different probe action) runs concurrently.
    let same = sandy(named_run(name, &writable, &[("env", "PATH")]));
    assert!(
        same.status.success(),
        "a same-policy concurrent run was refused: {}",
        String::from_utf8_lossy(&same.stderr)
    );

    // A different policy under the same name is refused while the first run is active.
    let different = sandy(named_run(name, &other_policy, &[("env", "PATH")]));
    assert_eq!(different.status.code(), Some(EXIT_FAILURE), "{different:?}");
    let reason = String::from_utf8_lossy(&different.stderr);
    assert!(reason.contains("different policy"), "{reason}");

    // End the first run. Its coordination object closes with it.
    first.kill().unwrap();
    first.wait().unwrap();

    // The different policy now runs: the name is free once no run holds it.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let sequential = sandy(named_run(name, &other_policy, &[("env", "PATH")]));
        if sequential.status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a different policy stayed blocked after the first run ended: {}",
            String::from_utf8_lossy(&sequential.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    delete_profile(name);
}

/// What the probe's tcp-send action writes.
const TCP_SEND_PAYLOAD: &[u8] = b"sent just before exit";

/// A loopback service outside the sandbox that takes one connection and returns what the client
/// sent, or `None` if no client came within 20 seconds.
fn one_shot_service() -> (u16, std::thread::JoinHandle<Option<Vec<u8>>>) {
    use std::io::Read;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let received = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut data = Vec::new();
                    let _ = (&stream).read_to_end(&mut data);
                    return Some(data);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        None
    });
    (port, received)
}

/// `--forward` options for this test's AppContainer without the loopback exemption. The shared
/// harness picks the exempt name for `--ip all`, so the name is set here explicitly.
fn forward_args(fixture: &Fixture, inner: u16, target_port: u16) -> Vec<String> {
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&[
        "--appcontainer",
        &appcontainer_name(),
        "--ip",
        "all",
        "--forward",
        &format!("{inner}=127.0.0.1:{target_port}"),
    ]));
    sandbox_args
}

/// The socket file of the forwarded port `port` while a run serves it.
fn forward_socket(port: u16) -> Option<PathBuf> {
    let base = user_local_app_data().join("sandy").join("forward");
    fs::read_dir(base)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join(port.to_string()))
        .find(|socket| socket.exists())
}

fn user_local_app_data() -> PathBuf {
    PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set"))
}

/// The point of `network.forward` on Windows: a program in an AppContainer without the loopback
/// exemption reaches a loopback service outside. It cannot reach a listener outside directly,
/// and the relay connects only to the forward target.
#[test]
fn forward_works_without_the_loopback_exemption() {
    let fixture = Fixture::new("forward-plain");
    let (service, received) = one_shot_service();
    let outside = TcpListener::bind("127.0.0.1:0").unwrap();
    outside.set_nonblocking(true).unwrap();
    let outside_port = outside.local_addr().unwrap().port();
    let inner = free_port();

    let lines = probe_inside(
        &forward_args(&fixture, inner, service),
        &[
            ("tcp-connect", &format!("127.0.0.1:{outside_port}")),
            ("tcp-connect", &format!("127.0.0.1:{inner}")),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_ok();
    assert!(
        received.join().unwrap().is_some(),
        "the service saw no connection"
    );
    assert!(
        !accepts_within(&outside, Duration::from_millis(200)),
        "something reached the listener that the policy does not forward to"
    );
    // Control: the listener outside works.
    let _control = TcpStream::connect(("127.0.0.1", outside_port)).unwrap();
    assert!(accepts_within(&outside, Duration::from_secs(3)));
}

/// The drain of the relay lifetime rule: a program that connects through a forwarded port, writes
/// and exits at once does not lose its data. Without the exemption, as above.
#[test]
fn forward_relay_delivers_data_sent_just_before_exit() {
    let fixture = Fixture::new("forward-drain");
    let (service, received) = one_shot_service();
    let inner = free_port();
    let lines = probe_inside(
        &forward_args(&fixture, inner, service),
        &[("tcp-send", &format!("127.0.0.1:{inner}"))],
    );
    lines[0].assert_ok();
    assert_eq!(received.join().unwrap().as_deref(), Some(TCP_SEND_PAYLOAD));
}

/// The relay lifetime rule for an exposed port: when the program ends, the relay takes no new
/// connection at once, also while it still lets an accepted connection finish. The test holds
/// one accepted connection open, so sandy waits up to one second for it; a new connection in
/// that window must be refused.
#[test]
fn relay_stops_listening_as_soon_as_the_program_ends() {
    use std::io::BufRead;
    let fixture = Fixture::new("relay-stop");
    let (inner, outer) = (free_port(), free_port());
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&[
        "--ip",
        "all",
        "--expose",
        &format!("127.0.0.1:{outer}={inner}"),
    ]));
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[("tcp-accept", &format!("127.0.0.1:{inner}"))],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The program writes its result line to the pipe when it exits, so the line marks its end.
    let (lines_sender, lines_receiver) = std::sync::mpsc::channel();
    let stdout = run.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = lines_sender.send(line);
        }
    });

    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    let mut held = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let line = loop {
        if let Ok(line) = lines_receiver.recv_timeout(Duration::from_millis(200)) {
            break line;
        }
        assert!(Instant::now() < deadline, "the program never accepted");
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) {
            held.push(stream);
        }
    };
    assert!(line.contains("\tok\t"), "{line}");
    std::thread::sleep(Duration::from_millis(300));
    let refused = TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err();
    let still_draining = run.try_wait().unwrap().is_none();
    assert!(refused, "the relay still accepts after the program ended");
    // Informative: the check above is strongest while sandy still drains the held connection.
    if !still_draining {
        eprintln!("note: sandy had already ended when the test connected again");
    }
    drop(held);
    assert!(run.wait().unwrap().success());
}

/// The socket between the relay and sandy grants only the relays' capability: the program
/// itself cannot connect to it, while the user outside and the relay can.
#[test]
fn forward_socket_is_reachable_only_by_the_relay() {
    let fixture = Fixture::new("forward-socket");
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port();
    let inner = free_port();
    let path_file = fixture.arg("rw/socket-path");
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &forward_args(&fixture, inner, service_port),
            &[
                ("sleep", "5000"),
                ("afunix-connect-file", &path_file),
                ("tcp-connect", &format!("127.0.0.1:{inner}")),
            ],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let socket = loop {
        if let Some(socket) = forward_socket(inner) {
            break socket;
        }
        if run.try_wait().unwrap().is_some() {
            panic!("sandy ended early: {:?}", run.wait_with_output());
        }
        assert!(Instant::now() < deadline, "no forward socket appeared");
        std::thread::sleep(Duration::from_millis(50));
    };
    let socket = plain_path(&socket);
    // Control: the socket is live, and the user outside the sandbox can connect.
    probe_outside(&[("afunix-connect", &socket)])[0].assert_ok();
    fs::write(&path_file, &socket).unwrap();

    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    // Strictly "denied": an unreadable path file or a missing socket would be "error".
    assert_eq!(lines[1].result, "denied", "{lines:?}");
    lines[2].assert_ok();
}

/// The relay ends with the program and the socket directory goes away, also while a relayed
/// connection stays open: the target holds it, so only the lifetime rule ends it.
#[test]
fn forward_relay_ends_with_the_program() {
    let fixture = Fixture::new("forward-end");
    let holder = TcpListener::bind("127.0.0.1:0").unwrap();
    let holder_port = holder.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in holder.incoming() {
            held.push(stream);
        }
    });
    let inner = free_port();
    let started = Instant::now();
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &forward_args(&fixture, inner, holder_port),
            &[
                ("sleep", "1000"),
                ("tcp-connect", &format!("127.0.0.1:{inner}")),
            ],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let socket = loop {
        if let Some(socket) = forward_socket(inner) {
            break socket;
        }
        assert!(run.try_wait().unwrap().is_none(), "sandy ended early");
        assert!(Instant::now() < deadline, "no forward socket appeared");
        std::thread::sleep(Duration::from_millis(50));
    };
    // sandy creates the socket before it starts the relay.
    let relays = loop {
        let relays = relay_processes(run.id());
        if !relays.is_empty() {
            break relays;
        }
        assert!(run.try_wait().unwrap().is_none(), "sandy ended early");
        assert!(
            Instant::now() < deadline,
            "no relay process of sandy {}",
            run.id()
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    parse(&output)[1].assert_ok();
    for relay in &relays {
        // SAFETY: relay is a process handle this test owns; a zero timeout only polls it.
        let state = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(relay.as_raw_handle(), 0)
        };
        assert_eq!(state, 0, "a relay outlived sandy");
    }
    assert!(!socket.exists(), "the forward socket outlived sandy");
    assert!(socket.parent().is_some_and(|dir| !dir.exists()));
    // A hang would show here; the exact one-second limit is a unit test of sandy-relay.
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

/// Handles of the `sandy.exe` processes whose parent is `parent`: the relays of that run.
fn relay_processes(parent: u32) -> Vec<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    // SAFETY: a process snapshot needs no process id.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    // SAFETY: the structure is plain data; dwSize is set before use.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut handles = Vec::new();
    // SAFETY: snapshot is valid and entry has its size set.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let length = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(0);
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ParentProcessID == parent && name.eq_ignore_ascii_case("sandy.exe") {
            // SAFETY: OpenProcess has no memory preconditions.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                    0,
                    entry.th32ProcessID,
                )
            };
            if !handle.is_null() {
                // SAFETY: OpenProcess returned a new handle that this test owns.
                handles.push(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) });
            }
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: snapshot is a handle this function owns.
    unsafe { CloseHandle(snapshot) };
    handles
}

/// `--children none`: the program cannot start even a system program that every AppContainer may
/// run; the same policy without the option can.
#[test]
fn children_none_denies_starting_a_system_program() {
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("children-system");
    let system = std::env::var("SystemRoot").expect("SystemRoot is set");
    let whoami = format!(r"{system}\System32\whoami.exe");
    probe_inside(&fixture.access_args(), &[("exec", &whoami)])[0].assert_ok();
    let mut denied = fixture.access_args();
    denied.extend(args(&["--children", "none"]));
    probe_inside(&denied, &[("exec", &whoami)])[0].assert_blocked();
}

/// With `--children none` the relays still work, and they cannot start processes themselves:
/// the program can open them (one AppContainer), so they must not be a way around the rule.
/// Their child-process policy is read from outside.
#[test]
fn relays_work_with_children_none_and_cannot_start_processes() {
    let fixture = Fixture::new("children-relay");
    let (service, received) = one_shot_service();
    let inner = free_port();
    let mut sandbox_args = forward_args(&fixture, inner, service);
    sandbox_args.extend(args(&["--children", "none"]));
    let run = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[
                ("sleep", "1500"),
                ("tcp-send", &format!("127.0.0.1:{inner}")),
            ],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let relays = loop {
        let relays = relay_processes(run.id());
        if !relays.is_empty() {
            break relays;
        }
        assert!(
            Instant::now() < deadline,
            "no relay process of sandy {}",
            run.id()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    for relay in &relays {
        assert!(
            cannot_create_children(relay),
            "a relay may start child processes"
        );
    }
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    parse(&output)[1].assert_ok();
    assert_eq!(received.join().unwrap().as_deref(), Some(TCP_SEND_PAYLOAD));
}

/// An exposed port works with `--children none` too.
#[test]
fn exposed_port_works_with_children_none() {
    let fixture = Fixture::new("children-expose");
    let (inner, outer) = (free_port(), free_port());
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&[
        "--children",
        "none",
        "--ip",
        "all",
        "--expose",
        &format!("127.0.0.1:{outer}={inner}"),
    ]));
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[("tcp-accept", &format!("127.0.0.1:{inner}"))],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let address = format!("127.0.0.1:{outer}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while run.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the program never accepted");
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    parse(&output)[0].assert_ok();
}

/// Whether the process may not create child processes (`ProcessChildProcessPolicy`,
/// `NoChildProcessCreation`, bit 0 of the policy flags).
fn cannot_create_children(process: &std::os::windows::io::OwnedHandle) -> bool {
    use windows_sys::Win32::System::Threading::{
        GetProcessMitigationPolicy, ProcessChildProcessPolicy,
    };
    let mut flags = 0u32;
    // SAFETY: process is a valid handle with query access; flags is a writable 4-byte buffer,
    // the size of PROCESS_MITIGATION_CHILD_PROCESS_POLICY.
    let ok = unsafe {
        GetProcessMitigationPolicy(
            process.as_raw_handle(),
            ProcessChildProcessPolicy,
            (&mut flags as *mut u32).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    flags & 1 != 0
}
