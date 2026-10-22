//! Windows-specific escape tests. Like `escape.rs`, they run `sandy-probe` inside the sandbox
//! and check every denial against a control run outside it, so a test cannot pass because the
//! action was impossible anyway.
//!
//! Tests that need the loopback exemption call `prepare_loopback_exemption`, which runs
//! `sandy setup` and needs administrator rights once per machine.
#![cfg(windows)]

mod common;

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
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

    let inside = probe_inside(&fixture.access_args(), &[("handle-path", &value)]);
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
    not_exempt.extend(args(&["--ip", "all", "--appcontainer", APPCONTAINER]));
    probe_inside(&not_exempt, &[("tcp-connect", &address)])[0].assert_blocked();

    prepare_loopback_exemption();
    let mut exempt = fixture.access_args();
    exempt.extend(args(&[
        "--ip",
        "all",
        "--appcontainer",
        APPCONTAINER_LOOPBACK,
    ]));
    probe_inside(&exempt, &[("tcp-connect", &address)])[0].assert_ok();
}

fn free_loopback_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Connects to `address` from this process while `child` waits for a connection there.
fn connects_while_running(child: &mut Child, address: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
            return true;
        }
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Microsoft documents that the loopback exemption covers only connections from the
/// AppContainer; connections to it need a debugging mode of CheckNetIsolation.
#[test]
fn loopback_to_the_program_is_blocked_with_and_without_exemption() {
    let address = free_loopback_address();
    let target = address.to_string();
    let mut control = Command::new(probe_path())
        .args(["tcp-accept", &target])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(connects_while_running(&mut control, address));
    let _ = control.wait_with_output();

    prepare_loopback_exemption();
    let fixture = Fixture::new("loopin");
    for container in [APPCONTAINER, APPCONTAINER_LOOPBACK] {
        let address = free_loopback_address();
        let target = address.to_string();
        let mut sandbox_args = fixture.access_args();
        sandbox_args.extend(args(&["--ip", "all", "--appcontainer", container]));
        let mut child = Command::new(sandy_path())
            .args(run_args(&sandbox_args, &[("tcp-accept", &target)]))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let connected = connects_while_running(&mut child, address);
        let output = child.wait_with_output().unwrap();
        assert!(
            !connected,
            "connected to the program in {container}: {output:?}"
        );
        parse(&output)[0].assert_blocked();
    }
}

/// An exempt AppContainer reaches 127.0.0.1 even without network capabilities, so sandy must
/// refuse it for a policy without IP networking.
#[test]
fn an_exempt_appcontainer_cannot_deny_ip() {
    prepare_loopback_exemption();
    let output = sandy(["check", "--appcontainer", APPCONTAINER_LOOPBACK]);
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

/// Without read-write paths the program has write access to no socket file, so sandy can deny
/// Unix sockets.
#[test]
fn unix_sockets_outside_the_policy_are_unreachable() {
    let fixture = Fixture::new("afunix");
    let socket = plain_path(&fixture.path("secret/socket"));
    let _listener = UnixListener::bind(&socket);
    probe_outside(&[("afunix-connect", &socket)])[0].assert_ok();

    let read_only = args(&["--read", &fixture.arg("ro"), "--unix-sockets", "none"]);
    probe_inside(&read_only, &[("afunix-connect", &socket)])[0].assert_blocked();
}

/// A socket in a read-write path is reachable, which is why sandy refuses a policy with
/// read-write paths and unix_sockets = "none". If this test fails, AppContainers cannot use
/// AF_UNIX at all, and that refusal could be lifted.
#[test]
fn unix_sockets_in_writable_paths_are_reachable() {
    let fixture = Fixture::new("afunixrw");
    let socket = plain_path(&fixture.path("rw/socket"));
    let _listener = UnixListener::bind(&socket);
    probe_inside(&fixture.access_args(), &[("afunix-connect", &socket)])[0].assert_ok();

    let mut check = vec!["check".to_string()];
    check.extend(fixture.access_args());
    check.extend(args(&["--appcontainer", APPCONTAINER]));
    let output = sandy(&check);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
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
    let output = sandy(["check", "--appcontainer", APPCONTAINER, "--system", "none"]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
}
