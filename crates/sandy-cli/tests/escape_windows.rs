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
/// `check`: not enforceable, but `sandy setup` with administrator rights would make it so.
const EXIT_NEEDS_SETUP: i32 = 2;
/// `check` and `run` for a policy that contradicts itself or the layout of this host, which no
/// fallback level changes (`Status::Conflict`).
const EXIT_CONFLICT: i32 = EXIT_FAILURE;

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
///
/// `exec` alone would not show that: on the Server images no AppContainer process can start a
/// child process at all (docs/windows.md limitation 11), so its denial would hold even if the
/// grant did contain FILE_EXECUTE. `load-library` maps the image inside the program's own
/// process and needs FILE_EXECUTE, and the same action on the `read_exec` copy is the positive
/// control: only when that one loads does a denial in the writable path mean anything.
#[test]
fn read_write_paths_are_not_executable() {
    let fixture = Fixture::new("rwexec");
    let copied = fixture.copy_probe("rw");
    // A name of its own: for a module name the process already has loaded, LoadLibraryExW could
    // answer from its module list without opening the file.
    let loadable = fixture.path("bin").join("loadable-copy.exe");
    fs::copy(probe_path(), &loadable).unwrap();
    let loadable = loadable.to_str().unwrap().to_string();

    let lines = controlled(
        &fixture.access_args(),
        &[
            ("load-library", &loadable),
            ("load-library", &copied),
            ("exec", &copied),
            ("write-dac", &copied),
        ],
    );
    let maps_images = lines[0].result == "ok";
    if maps_images {
        lines[1].assert_blocked();
    } else {
        skip(
            "load-library-inside",
            &format!(
                "an image in a read_exec path does not map inside this host's AppContainer \
                 ({}), so a denial in a read-write path shows nothing",
                lines[0].detail
            ),
        );
    }
    lines[2].assert_blocked();
    lines[3].assert_blocked();

    let made = fixture.arg("rw/made-inside.exe");
    let lines = probe_inside(
        &fixture.access_args(),
        &[
            ("copy-self", &made),
            ("load-library", &made),
            ("exec", &made),
            ("write-dac", &made),
        ],
    );
    lines[0].assert_ok();
    if maps_images {
        lines[1].assert_blocked();
    }
    lines[2].assert_blocked();
    lines[3].assert_blocked();
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
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALL APPLICATION PACKAGES"), "{stdout}");
}

/// A file below a writable path can carry an execute entry of its own, which the permissions of
/// the path do not show. Together with sandy's write grant it would be writable and executable,
/// so sandy refuses it. The walk runs when sandy first adds the grant, not on every run:
/// `check` reads the path's own permissions only, which this test records.
#[test]
fn a_file_below_a_writable_path_that_all_appcontainers_may_execute_is_refused() {
    let fixture = Fixture::new("rw-child-exec");
    let child = fixture.arg("rw/file");
    let check = || {
        let mut args = vec!["check".to_string()];
        args.extend(platform_args());
        args.extend(fixture.access_args());
        sandy(&args)
    };

    // Control: the same policy and the same tree without the entry work.
    probe_inside(&fixture.access_args(), &[("read", &child)])[0].assert_ok();

    // A new tree, so sandy adds the grant again instead of finding its entry in place.
    fixture.reset();
    let granted = Command::new("icacls")
        .args([&child, "/grant", "*S-1-15-2-1:(RX)"])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");

    let output = sandy(run_program(
        &fixture.access_args(),
        &probe_path(),
        &["read", &child],
    ));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ALL APPLICATION PACKAGES"), "{stderr}");
    assert!(stderr.contains(r"rw\file"), "{stderr}");

    // Recorded: `check` only reads the permissions of the path itself.
    assert!(check().status.success(), "{:?}", check());
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

/// Recorded, not a guarantee: a grant on Windows is an entry on the object, not on the path. A
/// file renamed out of a granted directory keeps the entry it inherited from it, and an
/// AppContainer token keeps `SeChangeNotifyPrivilege`, so no traverse check stops the program
/// from opening the file at its new place by its full path. The run's capability is the one of
/// the directory, so the access ends only when the policy drops the directory. Linux and macOS
/// bind the rule to the path, where the moved file is denied at once.
///
/// docs/windows.md, "Links and identity", carries the same statement. Closing it would mean a
/// new capability generation per run and a fresh propagation over every policy path on every
/// run; the test is here so the behaviour is not lost.
#[test]
fn a_file_moved_out_of_a_granted_directory_keeps_its_grant() {
    let fixture = Fixture::new("movedout");
    // The first run adds the entry on the read directory, which the file inherits.
    probe_inside(&fixture.access_args(), &[("read", &fixture.arg("ro/file"))])[0].assert_ok();

    fs::rename(fixture.path("ro/file"), fixture.path("secret/moved")).unwrap();
    let lines = probe_inside(
        &fixture.access_args(),
        &[
            ("read", &fixture.arg("secret/moved")),
            ("read", &fixture.arg("secret/file")),
        ],
    );
    lines[0].assert_ok();
    // Control: a file of the same directory that never carried the entry stays unreadable, so
    // the read above is the inherited entry and not general access to the directory.
    lines[1].assert_blocked();
}

/// sandy looks for second names and links inside writable paths when it starts ("Links and
/// identity" in docs/windows.md), so it relies on the sandboxed program not making them while it
/// runs. This records that it cannot: it cannot hard-link a file of a read, read-exec or
/// unreadable path into a writable path, cannot make a junction that points out of its writable
/// paths, and cannot make a symbolic link at all (the AppContainer token holds no
/// `SeCreateSymbolicLinkPrivilege`). What the start-time check does not see therefore needs a
/// second name planted by a process other than the sandboxed one while it runs. Each denial has
/// an outside control that succeeds for the file owner, so a denial inside is the sandbox and not
/// an impossible action.
#[test]
fn the_program_cannot_plant_a_link_reaching_outside_its_writable_paths() {
    let fixture = Fixture::new("plant-link");
    let outside_targets = || {
        // A file in the read-exec directory to hard-link, and a writable subdirectory to point a
        // junction at as the in-policy control. Recreated after `reset`.
        fs::write(fixture.path("bin/file"), b"content").unwrap();
        fs::create_dir_all(fixture.path("rw/sub")).unwrap();
    };
    let p = |from: &str, to: &str| format!("{}\u{1f}{}", fixture.arg(from), fixture.arg(to));
    // Index 0 and 4 stay inside the writable path and are the positive controls: the operation
    // itself works in the sandbox, so the other denials are about the target, not the call.
    let hard = [
        ("hardlink", p("rw/file", "rw/hl-in")),
        ("hardlink", p("ro/file", "rw/hl-ro")),
        ("hardlink", p("bin/file", "rw/hl-rx")),
        ("hardlink", p("secret/file", "rw/hl-secret")),
        ("junction", p("rw/sub", "rw/j-in")),
        ("junction", p("ro", "rw/j-ro")),
        ("junction", p("secret", "rw/j-secret")),
    ];
    let hard: Vec<(&str, &str)> = hard.iter().map(|(a, t)| (*a, t.as_str())).collect();

    outside_targets();
    for line in probe_outside(&hard) {
        line.assert_ok();
    }
    fixture.reset();
    outside_targets();
    let inside = probe_inside(&fixture.access_args(), &hard);
    inside[0].assert_ok(); // hard link within the writable path
    inside[1].assert_blocked();
    inside[2].assert_blocked();
    inside[3].assert_blocked();
    inside[4].assert_ok(); // junction within the writable path
    inside[5].assert_blocked();
    inside[6].assert_blocked();

    // A symbolic link needs a privilege the AppContainer token never has. The outside control
    // needs it too, so this part runs only where the test host grants it (an elevated session or
    // developer mode); a standard user without it would see the same denial inside anyway.
    let link = p("secret", "rw/s-secret");
    let symlink = [("symbolic-link", link.as_str())];
    fixture.reset();
    outside_targets();
    if probe_outside(&symlink)[0].result == "ok" {
        fixture.reset();
        outside_targets();
        probe_inside(&fixture.access_args(), &symlink)[0].assert_blocked();
    }
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

/// sandy grants a policy path by adding an entry to its access control list, which needs the
/// right to change that list. `check` reports a path where the user lacks it instead of calling
/// the policy enforced, as a conflict of the policy with that path, and `run` refuses it. An
/// OWNER RIGHTS entry takes the right from the owner too.
///
/// sandy runs without the privileges of this process here: an administrator's SSH session has
/// `SeRestorePrivilege` enabled, which lets sandy change every access list, as `check` then
/// correctly reports. A standard user holds no such privilege.
#[test]
fn check_reports_a_path_whose_permissions_the_user_cannot_change() {
    let fixture = Fixture::new("no-write-dac");
    let file = fixture.arg("secret/file");
    let policy = args(&["--read", &file]);
    let mut check = vec!["check".to_string()];
    check.extend(platform_args());
    check.extend_from_slice(&policy);
    // Control: the user may change the list, so the path is enforced.
    let (code, output) = sandy_without_privileges(&check);
    assert_eq!(code, 0, "{output}");

    for change in [&["/grant:r", "*S-1-3-4:(R)"][..], &["/inheritance:r"]] {
        let changed = Command::new("icacls")
            .arg(&file)
            .args(change)
            .output()
            .unwrap();
        assert!(changed.status.success(), "{changed:?}");
    }
    // The change takes the right only where this token holds it as the owner. Where the token
    // still opens the file for WRITE_DAC without its privileges, sandy may change the list, and
    // `check` correctly calls the path enforced, so the conflict cannot be built here.
    let (_, opened) = executable_with_restricted_token(
        &probe_path(),
        windows_sys::Win32::Security::DISABLE_MAX_PRIVILEGE,
        &["write-dac".to_string(), file.clone()],
    );
    let opened = parse_line(
        opened
            .lines()
            .find(|line| line.starts_with("write-dac\t"))
            .unwrap_or_default(),
    );
    if opened.result == "ok" {
        return skip(
            "write-dac-revocable",
            "this user still opens the file for WRITE_DAC without privileges after the change, \
             so no path here lacks the right",
        );
    }
    let (code, output) = sandy_without_privileges(&check);
    assert_eq!(code as i32, EXIT_CONFLICT, "{output}");
    assert!(output.contains(&file), "{output}");
    let run = run_program(&policy, &probe_path(), &["read", &file]);
    let (code, output) = sandy_without_privileges(&run);
    assert_eq!(code as i32, EXIT_FAILURE, "{output}");
}

/// Runs sandy with `sandy_args` under the token of this process without its privileges. Returns
/// the exit code and the standard output and error.
fn sandy_without_privileges(sandy_args: &[String]) -> (u32, String) {
    sandy_with_restricted_token(
        windows_sys::Win32::Security::DISABLE_MAX_PRIVILEGE,
        sandy_args,
    )
}

/// Runs sandy with `sandy_args` under a token that UAC would give this user without elevation:
/// the administrators group for deny only and no privileges (`LUA_TOKEN`).
fn sandy_without_administrator_rights(sandy_args: &[String]) -> (u32, String) {
    sandy_with_restricted_token(windows_sys::Win32::Security::LUA_TOKEN, sandy_args)
}

/// Runs sandy with `sandy_args` under the token of this process restricted with `flags`
/// (`CreateRestrictedToken`). Returns the exit code and the standard output and error.
fn sandy_with_restricted_token(flags: u32, sandy_args: &[String]) -> (u32, String) {
    executable_with_restricted_token(&sandy_path(), flags, sandy_args)
}

/// Runs the sandy executable `sandy` as `sandy_with_restricted_token` does.
fn executable_with_restricted_token(
    sandy: &str,
    flags: u32,
    sandy_args: &[String],
) -> (u32, String) {
    use std::io::Read;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
    };

    let mut own: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process needs no closing; own is a valid out pointer.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut own,
        )
    };
    assert_ne!(opened, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: OpenProcessToken returned a new handle that this function owns.
    let own = unsafe { OwnedHandle::from_raw_handle(own) };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: own is a token handle with TOKEN_DUPLICATE; no SIDs or privileges are listed.
    let restricted = unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut token,
        )
    };
    assert_ne!(restricted, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: CreateRestrictedToken returned a new handle that this function owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

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
    let mut line = format!("\"{sandy}\"");
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
    // SAFETY: token is a primary token derived from this process's own; line is NUL-terminated
    // and writable; startup and info outlive the call.
    let created = unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut info,
        )
    };
    assert_ne!(created, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: CreateProcessAsUserW returned two new handles that this function owns.
    let (process, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    drop(write);
    let mut output = String::new();
    let _ = fs::File::from(read).read_to_string(&mut output);
    let mut code = 0u32;
    // SAFETY: process is valid; code is a writable u32.
    unsafe {
        WaitForSingleObject(process.as_raw_handle(), INFINITE);
        GetExitCodeProcess(process.as_raw_handle(), &mut code);
    }
    (code, output)
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

/// The two rights the test above uses are a sample. Every other right that would let the
/// program change a process of the user must be refused too, and so must the rights on its
/// threads. The outside control opens the same process and thread, which always succeeds for
/// the owner, so a denial inside is the AppContainer boundary.
#[test]
fn cannot_open_processes_and_threads_outside_with_any_right() {
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    let fixture = Fixture::new("process-rights");
    // SAFETY: GetCurrentThreadId has no preconditions and no out parameters.
    let thread = unsafe { GetCurrentThreadId() }.to_string();
    let process = std::process::id().to_string();
    let process_rights = [
        "vm-write",
        "vm-operation",
        "dup-handle",
        "create-thread",
        "set-information",
        "set-quota",
        "suspend-resume",
        "query-information",
        "all-access",
    ];
    let thread_rights = [
        "terminate",
        "suspend-resume",
        "get-context",
        "set-context",
        "set-information",
        "query-information",
        "all-access",
    ];
    let targets: Vec<(String, String)> = process_rights
        .iter()
        .map(|right| {
            (
                "open-process-right".to_string(),
                format!("{process}\u{1f}{right}"),
            )
        })
        .chain(thread_rights.iter().map(|right| {
            (
                "open-thread-right".to_string(),
                format!("{thread}\u{1f}{right}"),
            )
        }))
        .collect();
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|(action, target)| (action.as_str(), target.as_str()))
        .collect();

    for line in controlled(&fixture.access_args(), &actions) {
        line.assert_blocked();
    }
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
/// refuse it for a policy without IP networking. `sandy setup` removes the exemption, so `check`
/// reports it as needing setup and exits with the setup status (2), not the plain refusal (1).
#[test]
fn an_exempt_appcontainer_cannot_deny_ip() {
    prepare_loopback_exemption();
    let output = sandy(["check", "--appcontainer", &appcontainer_loopback_name()]);
    assert_eq!(output.status.code(), Some(EXIT_NEEDS_SETUP), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exempt"), "{stdout}");
}

/// `setup --elevate` in a session that has administrator rights already, as the test VM's SSH
/// session and the CI runners have, runs setup in this process: no UAC prompt, the outcome on
/// standard output, and the exemption in place; `setup --remove --elevate` takes it back.
#[test]
fn elevate_with_administrator_rights_runs_setup_directly() {
    let name = "sandy.elevate-test";
    let setup = sandy(["setup", "--elevate", "--appcontainer", name, "--ip", "all"]);
    let stdout = String::from_utf8_lossy(&setup.stdout);
    assert!(setup.status.success(), "{setup:?}");
    assert!(stdout.contains("is in the loopback exemption"), "{stdout}");
    // The exemption that setup gave the policy with `ip = "all"` is one that setup for the
    // policy without IP networking takes back, so check names setup.
    let check = || sandy(["check", "--appcontainer", name]).status.code();
    assert_eq!(check(), Some(EXIT_NEEDS_SETUP));

    let removed = sandy(["setup", "--remove", "--elevate", "--appcontainer", name]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(
        String::from_utf8_lossy(&removed.stdout).contains("removed what sandy left"),
        "{removed:?}"
    );
    assert_eq!(check(), Some(0));
    delete_profile(name);
}

/// Without administrator rights and without `--elevate`, setup and its removal change nothing
/// and end with status 3, as on Linux, also where nothing would change, and say how to get the
/// rights. Control: the same commands with the rights succeed.
#[test]
fn setup_without_administrator_rights_is_not_done() {
    let name = "sandy.limited-setup-test";
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
    };
    let exempt = || {
        String::from_utf8_lossy(&sandy(["check", "--appcontainer", name]).stdout)
            .contains("is exempt from loopback isolation")
    };
    assert!(!exempt());
    for command in [
        args(&["setup", "--appcontainer", name, "--ip", "all"]),
        args(&["setup", "--appcontainer", name]),
        args(&["setup", "--remove", "--appcontainer", name]),
    ] {
        let (code, output) = sandy_without_administrator_rights(&command);
        assert_eq!(code as i32, 3, "{command:?}: {output}");
        for part in [
            "needs administrator rights",
            "--elevate",
            "elevated prompt",
            "nothing changed",
        ] {
            assert!(output.contains(part), "{command:?}: {part}: {output}");
        }
    }
    assert!(!exempt());

    let setup = sandy(["setup", "--appcontainer", name, "--ip", "all"]);
    assert!(setup.status.success(), "{setup:?}");
    assert!(exempt());
    let (code, output) =
        sandy_without_administrator_rights(&args(&["setup", "--remove", "--appcontainer", name]));
    assert_eq!(code as i32, 3, "{output}");
    assert!(exempt(), "the removal without rights changed the exemption");
    let removed = sandy(["setup", "--remove", "--appcontainer", name]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!exempt());
    delete_profile(name);
}

/// `--elevate` without administrator rights asks for them only for a `sandy.exe` that only
/// administrators can change. The tests' `sandy.exe` lies in the user's profile, so it refuses
/// with status 3 and names who else can change it, before any prompt, and changes nothing.
/// Control: `elevate_with_administrator_rights_runs_setup_directly`.
#[test]
fn elevate_refuses_a_sandy_that_others_can_change() {
    let name = "sandy.elevate-refused-test";
    let exempt = || {
        String::from_utf8_lossy(&sandy(["check", "--appcontainer", name]).stdout)
            .contains("is exempt from loopback isolation")
    };
    let (code, output) = sandy_without_administrator_rights(&args(&[
        "setup",
        "--elevate",
        "--appcontainer",
        name,
        "--ip",
        "all",
    ]));
    assert_eq!(code as i32, 3, "{output}");
    for part in [
        "only administrators can change",
        "can change",
        "nothing changed",
    ] {
        assert!(output.contains(part), "{part}: {output}");
    }
    assert!(!exempt());
    delete_profile(name);
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
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT), "{output:?}");
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
    executable_in_job(&sandy_path(), ui, sandy_args)
}

/// `sandy_in_job` with the sandy executable at `sandy`.
fn executable_in_job(sandy: &str, ui: u32, sandy_args: &[String]) -> (u32, String) {
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

    let mut line = format!("\"{sandy}\"");
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

/// `check` inside a job without UI restrictions tries whether sandy's job nests by starting a
/// suspended process of `sandy.exe`. It must start that file and no other: from an unquoted
/// command line Windows would start `<dir>\a.exe` for `<dir>\a b\sandy.exe`, here a file that
/// is no program, and report the nesting as unavailable.
#[test]
fn the_nesting_trial_starts_sandy_from_a_path_with_a_space() {
    let fixture = Fixture::new("trial-space");
    let directory = fixture.path("a b");
    fs::create_dir_all(&directory).unwrap();
    let sandy = directory.join("sandy.exe");
    fs::copy(sandy_path(), &sandy).unwrap();
    fs::write(fixture.path("a.exe"), b"not a program").unwrap();

    let check = args(&["check", "--appcontainer", &appcontainer_name()]);
    let (code, output) = executable_in_job(sandy.to_str().unwrap(), 0, &check);
    assert_eq!(code, 0, "{output}");
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

/// `setup --remove` takes back what sandy left: the access control entry of every policy path
/// and the AppContainer profile with its folder. It must leave everything else alone, so the
/// test checks that the entry of a path the policy does not name stays.
#[test]
fn setup_remove_takes_back_the_grant_and_the_profile() {
    let name = "sandy.remove-test";
    delete_profile(name);
    let fixture = Fixture::new("remove");
    let (granted, kept) = (fixture.arg("ro"), fixture.arg("rw"));
    let folder = user_local_app_data().join("Packages").join(name);

    // One run grants both paths and creates the profile.
    let run = sandy(named_run(
        name,
        &["--read", &granted, "--read-write", &kept],
        &[("read", &fixture.arg("ro/file"))],
    ));
    assert!(run.status.success(), "{run:?}");
    assert!(capability_entries(&granted) > 0, "no entry on {granted}");
    assert!(capability_entries(&kept) > 0, "no entry on {kept}");
    assert!(folder.is_dir(), "no profile folder {}", folder.display());

    // Remove with a policy that names only one of the two paths.
    let removed = sandy([
        "setup",
        "--remove",
        "--appcontainer",
        name,
        "--read",
        &granted,
    ]);
    assert!(removed.status.success(), "{removed:?}");
    assert_eq!(
        capability_entries(&granted),
        0,
        "the entry on {granted} stayed"
    );
    assert!(
        capability_entries(&kept) > 0,
        "the entry on {kept} was removed, although the policy does not name it"
    );
    assert!(
        !folder.exists(),
        "the profile folder {} stayed",
        folder.display()
    );

    // Idempotent: a second removal changes nothing and still succeeds.
    let again = sandy([
        "setup",
        "--remove",
        "--appcontainer",
        name,
        "--read",
        &granted,
    ]);
    assert!(again.status.success(), "{again:?}");
}

/// `setup --remove` takes the grants back, so it must not run while a program in that
/// AppContainer runs: the program would lose its access in the middle. It refuses then, and
/// succeeds once the run has ended.
#[test]
fn setup_remove_refuses_while_a_run_is_active() {
    let name = "sandy.remove-active-test";
    delete_profile(name);
    let fixture = Fixture::new("remove-active");
    let writable = fixture.arg("rw");
    let remove = || {
        sandy([
            "setup",
            "--remove",
            "--appcontainer",
            name,
            "--read-write",
            &writable,
        ])
    };

    let mut run = long_run(
        name,
        &["--read-write", &writable],
        &fixture.path("rw/ready"),
    );
    let during = remove();
    let entries = capability_entries(&writable);
    run.kill().unwrap();
    run.wait().unwrap();
    assert_eq!(during.status.code(), Some(EXIT_FAILURE), "{during:?}");
    let stderr = String::from_utf8_lossy(&during.stderr);
    assert!(stderr.contains("is using the AppContainer"), "{stderr}");
    assert!(entries > 0, "the grant on {writable} went during the run");

    // Control: with the run gone the same removal succeeds. The kernel releases the run's lock
    // when its process is gone, which may take a moment after the kill.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let after = remove();
        if after.status.success() {
            break;
        }
        assert!(Instant::now() < deadline, "{after:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(capability_entries(&writable), 0);
    delete_profile(name);
}

/// A run also grants the program file itself. `setup` takes no program, so `setup --remove`
/// leaves that entry, unless the removal names the program as a `read_exec` path, which derives
/// the same capability (docs/windows.md, "Removing the changes").
#[test]
fn setup_remove_takes_back_the_program_entry_only_when_named() {
    let name = "sandy.remove-program-test";
    delete_profile(name);
    let fixture = Fixture::new("remove-program");
    fs::create_dir_all(fixture.path("prog")).unwrap();
    let program = fixture.path("prog").join("probe.exe");
    fs::copy(probe_path(), &program).unwrap();
    let program = program.to_str().unwrap();
    let writable = fixture.arg("rw");
    let remove = |extra: &[&str]| {
        let mut remove = vec![
            "setup",
            "--remove",
            "--appcontainer",
            name,
            "--read-write",
            &writable,
        ];
        remove.extend_from_slice(extra);
        sandy(remove)
    };

    let run = sandy([
        "run",
        "--appcontainer",
        name,
        "--read-write",
        &writable,
        "--",
        program,
        "env",
        "PATH",
    ]);
    assert!(run.status.success(), "{run:?}");
    assert_eq!(capability_entries(program), 1);

    let removed = remove(&[]);
    assert!(removed.status.success(), "{removed:?}");
    assert_eq!(capability_entries(&writable), 0);
    assert_eq!(capability_entries(program), 1, "recorded: the entry stays");
    let removed = remove(&["--read-exec", program]);
    assert!(removed.status.success(), "{removed:?}");
    assert_eq!(capability_entries(program), 0);
    delete_profile(name);
}

/// How many capability entries (`S-1-15-3-1024-...`) the permissions of `path` carry.
fn capability_entries(path: &str) -> usize {
    let output = Command::new("icacls").arg(path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout)
        .matches("S-1-15-3-1024-")
        .count()
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
/// refused until the first run ends, then allowed. The coordination uses a lock file the
/// sandboxed program cannot reach (`the_program_cannot_reach_the_coordination_files`), and the
/// first run holds its lock only while it runs, so a crashed run does not block the name
/// forever.
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

/// Starts a run in `name` that writes `ready` and then stays alive, so the test knows its
/// coordination state is set. The caller ends it.
fn long_run(name: &str, policy: &[&str], ready: &Path) -> Child {
    let ready_arg = ready.to_str().unwrap();
    let mut run = Command::new(sandy_path())
        .args(named_run(
            name,
            policy,
            &[("write", ready_arg), ("sleep", "20000")],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        if let Some(status) = run.try_wait().unwrap() {
            panic!("the run in {name} exited early: {status:?}");
        }
        assert!(Instant::now() < deadline, "the run in {name} never started");
        std::thread::sleep(Duration::from_millis(100));
    }
    run
}

/// Windows derives the AppContainer SID from the name without regard to case, and so do the
/// capability names and the profile folder. Two spellings of one name are therefore one
/// AppContainer and one sandbox, so a concurrent run under the other spelling must be held to
/// the active policy just like one under the same spelling.
#[test]
fn a_concurrent_run_under_another_spelling_must_match_the_active_policy() {
    let (first, second) = ("sandy.Case-Test", "sandy.case-test");
    assert_eq!(
        appcontainer_sid(first),
        appcontainer_sid(second),
        "this host derives different SIDs for the two spellings, so they are not one sandbox"
    );
    delete_profile(first);
    let fixture = Fixture::new("case");
    let writable = ["--read-write", &fixture.arg("rw")];
    let other_policy = [
        "--read-write",
        &fixture.arg("rw"),
        "--read",
        &fixture.arg("ro"),
    ];
    let ready = fixture.path("rw/ready");

    let mut run = long_run(first, &writable, &ready);

    // The same policy under the other spelling joins the sandbox, as it does under the same
    // spelling.
    let same = sandy(named_run(second, &writable, &[("env", "PATH")]));
    assert!(
        same.status.success(),
        "a same-policy run under the other spelling was refused: {}",
        String::from_utf8_lossy(&same.stderr)
    );

    // A different policy under the other spelling must be refused.
    let different = sandy(named_run(second, &other_policy, &[("env", "PATH")]));
    run.kill().unwrap();
    run.wait().unwrap();
    assert_eq!(different.status.code(), Some(EXIT_FAILURE), "{different:?}");
    let reason = String::from_utf8_lossy(&different.stderr);
    assert!(reason.contains("different policy"), "{reason}");

    delete_profile(first);
}

/// Two policies that differ only in `--end-with-parent` confine differently: a run that ends
/// with its parent can be kept alive through a sibling in the same AppContainer, which may open
/// its processes. So the second one must be refused while the first runs.
#[test]
fn end_with_parent_separates_concurrent_policies() {
    let name = "sandy.endparent-test";
    delete_profile(name);
    let fixture = Fixture::new("endparent");
    // `end_with_parent` needs isolated signals, so both policies set them and differ only in
    // the flag under test.
    let writable = ["--read-write", &fixture.arg("rw"), "--signals", "isolated"];
    let mut ends = writable.to_vec();
    ends.push("--end-with-parent");
    let ready = fixture.path("rw/ready");

    let mut run = long_run(name, &writable, &ready);
    let different = sandy(named_run(name, &ends, &[("env", "PATH")]));
    run.kill().unwrap();
    run.wait().unwrap();
    assert_eq!(different.status.code(), Some(EXIT_FAILURE), "{different:?}");
    let reason = String::from_utf8_lossy(&different.stderr);
    assert!(reason.contains("different policy"), "{reason}");

    delete_profile(name);
}

/// The kernel releases the lock that marks an AppContainer as in use when sandy dies, so the next
/// run may set another policy. That is sound only because kill-on-close ends the program's job
/// at the same time: a program that outlived sandy would share its AppContainer with that run.
#[test]
fn a_killed_run_leaves_no_program_behind() {
    let name = "sandy.killed-test";
    delete_profile(name);
    let fixture = Fixture::new("killed");
    let mut run = long_run(
        name,
        &["--read-write", &fixture.arg("rw")],
        &fixture.path("rw/ready"),
    );
    let programs = child_processes(run.id(), "sandy-probe.exe");
    assert_eq!(programs.len(), 1, "the program of sandy {}", run.id());
    // Control: the program runs while sandy does, so its end below is sandy's death.
    assert!(!ends_within(&programs[0], Duration::ZERO));
    run.kill().unwrap();
    run.wait().unwrap();
    assert!(
        ends_within(&programs[0], Duration::from_secs(5)),
        "the program outlived sandy"
    );
    delete_profile(name);
}

/// When the program ends, sandy ends the processes it left behind and waits until they are gone,
/// so none of them outlives sandy: ending a job only starts the termination of its processes.
/// Control: the process runs while the program does.
#[test]
fn a_process_the_program_left_behind_ends_before_sandy_exits() {
    use std::io::{BufRead, BufReader};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};

    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("left-behind");
    let child = format!("{}\u{1f}sleep\u{1f}60000", probe_path());
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &fixture.access_args(),
            &[("start", &child), ("read-line", "-")],
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Kept open until the run ends, so that the program can write its other results.
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let started = parse_line(line.trim_end());
    started.assert_ok();
    let pid: u32 = started.detail.parse().unwrap();
    // SAFETY: OpenProcess takes no pointers; the handle is checked before use.
    let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!raw.is_null(), "cannot open process {pid}");
    // SAFETY: raw is a new process handle that nothing else owns.
    let left_behind = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert!(
        !ends_within(&left_behind, Duration::ZERO),
        "control: the process the program started did not run"
    );
    writeln!(run.stdin.take().unwrap(), "end").unwrap();
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        ends_within(&left_behind, Duration::ZERO),
        "a process the program left behind outlived sandy"
    );
    drop(stdout);
}

/// Whether `process` ends within `wait`.
fn ends_within(process: &std::os::windows::io::OwnedHandle, wait: Duration) -> bool {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    let millis = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: process is a process handle with SYNCHRONIZE access; the wait is limited.
    unsafe { WaitForSingleObject(process.as_raw_handle(), millis) == WAIT_OBJECT_0 }
}

/// sandy's coordination files lie below `%LOCALAPPDATA%\sandy`, which grants nothing to
/// AppContainers. The program cannot read the state of its own AppContainer, change it so that
/// a run with another policy joins its sandbox, or open a lock file to make later runs wait.
#[test]
fn the_program_cannot_reach_the_coordination_files() {
    let fixture = Fixture::new("coordination");
    // The first run creates the state file of this AppContainer and adds grants, which creates
    // the lock file of DACL changes.
    probe_inside(&fixture.access_args(), &[("env", "PATH")]);
    let directory = user_local_app_data().join("sandy");
    let state = directory
        .join("runs")
        .join(appcontainer_sid(&appcontainer_name()));
    let lock = directory.join("locks").join("dacl-changes");
    let created = format!("{}.new", state.display());
    let lines = controlled(
        &fixture.access_args(),
        &[
            ("read", state.to_str().unwrap()),
            ("read", lock.to_str().unwrap()),
            ("list", directory.to_str().unwrap()),
            ("write", &created),
        ],
    );
    let _ = fs::remove_file(&created);
    for line in &lines {
        line.assert_blocked();
    }
}

/// A name that Windows and sandy would read as different things, or that is the identity of an
/// installed application package, is refused before anything runs.
#[test]
fn refuses_ambiguous_and_package_shaped_appcontainer_names() {
    for name in [
        "sandy.trailing.",
        "sandy.trailing ",
        "..",
        "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
    ] {
        let output = sandy(["check", "--appcontainer", name]);
        assert_eq!(
            output.status.code(),
            Some(EXIT_CONFLICT),
            "{name:?}: {output:?}"
        );
    }
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

/// One relay serves every exposed and forwarded port of a run, so their number costs no process
/// each: with two exposed and three forwarded ports the run has one `sandy.exe` child, and the
/// program reaches each service outside through its own port.
#[test]
fn one_relay_serves_every_exposed_and_forwarded_port() {
    let fixture = Fixture::new("forward-many");
    let services: Vec<_> = (0..3).map(|_| one_shot_service()).collect();
    let inners: Vec<u16> = services.iter().map(|_| free_port()).collect();
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&[
        "--appcontainer",
        &appcontainer_name(),
        "--ip",
        "all",
    ]));
    for (inner, (service, _)) in inners.iter().zip(&services) {
        sandbox_args.extend(args(&[
            "--forward",
            &format!("{inner}=127.0.0.1:{service}"),
        ]));
    }
    for _ in 0..2 {
        let exposed = format!("127.0.0.1:{}={}", free_port(), free_port());
        sandbox_args.extend(args(&["--expose", &exposed]));
    }
    let addresses: Vec<String> = inners
        .iter()
        .map(|inner| format!("127.0.0.1:{inner}"))
        .collect();
    let mut actions = vec![("sleep", "1500")];
    actions.extend(
        addresses
            .iter()
            .map(|address| ("tcp-connect", address.as_str())),
    );
    let run = Command::new(sandy_path())
        .args(run_args(&sandbox_args, &actions))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // sandy starts the program only once the relay listens, so the relay runs during the sleep.
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
    assert_eq!(relays.len(), 1, "one relay for all ports");
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    for line in &lines[1..] {
        line.assert_ok();
    }
    for (service, received) in services {
        assert!(
            received.join().unwrap().is_some(),
            "the service on port {service} saw no connection"
        );
    }
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

/// A run that is killed cannot remove its socket directory. Each run holds a lock file in its
/// directory that only a live run can hold, so a later run removes what is left of dead ones.
#[test]
fn a_later_run_removes_the_socket_directory_of_a_killed_run() {
    let fixture = Fixture::new("forward-leftover");
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port();
    let inner = free_port();

    let mut killed = Command::new(sandy_path())
        .args(run_args(
            &forward_args(&fixture, inner, service_port),
            &[("sleep", "20000")],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let directory = loop {
        if let Some(socket) = forward_socket(inner) {
            break socket.parent().unwrap().to_path_buf();
        }
        assert!(killed.try_wait().unwrap().is_none(), "sandy ended early");
        assert!(Instant::now() < deadline, "no forward socket appeared");
        std::thread::sleep(Duration::from_millis(50));
    };
    killed.kill().unwrap();
    killed.wait().unwrap();
    assert!(
        directory.exists(),
        "a killed run is expected to leave its socket directory behind"
    );

    // Any later run with a forwarded port sweeps the base directory before it creates its own.
    let second = free_port();
    let lines = probe_inside(
        &forward_args(&fixture, second, service_port),
        &[("tcp-connect", &format!("127.0.0.1:{second}"))],
    );
    lines[0].assert_ok();
    assert!(
        !directory.exists(),
        "the socket directory of the killed run is still there: {}",
        directory.display()
    );
}

/// A run creates its socket directory first and its lock file next, so a directory without a
/// lock file may belong to a run that is starting. The sweep of another run must leave it, or
/// that run fails to create its lock file or loses its sockets.
#[test]
fn the_sweep_leaves_a_socket_directory_without_a_lock_file() {
    let fixture = Fixture::new("forward-starting");
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port();
    let starting = user_local_app_data()
        .join("sandy")
        .join("forward")
        .join(format!("starting-{}", std::process::id()));
    fs::create_dir_all(&starting).unwrap();

    // The forwarded port works, so the run swept the base directory before it served it.
    let inner = free_port();
    let lines = probe_inside(
        &forward_args(&fixture, inner, service_port),
        &[("tcp-connect", &format!("127.0.0.1:{inner}"))],
    );
    let kept = starting.exists();
    let _ = fs::remove_dir(&starting);
    lines[0].assert_ok();
    assert!(
        kept,
        "the sweep removed {}, which may belong to a run that is starting",
        starting.display()
    );
}

/// Handles of the `sandy.exe` processes whose parent is `parent`: the relays of that run.
fn relay_processes(parent: u32) -> Vec<std::os::windows::io::OwnedHandle> {
    child_processes(parent, "sandy.exe")
}

/// Handles of the processes named `executable` whose parent is `parent`.
fn child_processes(parent: u32, executable: &str) -> Vec<std::os::windows::io::OwnedHandle> {
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
        if entry.th32ParentProcessID == parent && name.eq_ignore_ascii_case(executable) {
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

/// `check` with the PATH the trusted locations are read from, so the result does not depend on
/// the account that runs the suite.
fn check_with_path(path: &str, writable: &str) -> std::process::Output {
    Command::new(sandy_path())
        .args([
            "check",
            "--appcontainer",
            &appcontainer_name(),
            "--read-write",
            writable,
        ])
        .env("PATH", path)
        .output()
        .unwrap()
}

/// A writable path that holds the Startup folder lets the program leave a program there that
/// Windows runs at the next logon, outside the sandbox: a file the program creates keeps the
/// user's own rights, including the right to execute it. `check` only reads state, so this is
/// safe on the real folder.
#[test]
fn refuses_a_writable_path_over_the_startup_folder() {
    let startup =
        user_profile().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    if !startup.exists() {
        return skip(
            "startup-folder",
            "this account has no Startup folder below its profile",
        );
    }
    let refused = check_with_path("C:\\Windows\\system32", startup.to_str().unwrap());
    let report = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(refused.status.code(), Some(EXIT_CONFLICT), "{report}");
    assert!(report.contains("runs outside the sandbox"), "{report}");
}

/// A junction or a directory symbolic link this test made with `mklink`. Dropping it removes the
/// link itself, never what it leads to.
struct DirectoryLink(PathBuf);

impl DirectoryLink {
    /// `kind` is `/J` for a junction or `/D` for a symbolic link. `None` when `mklink` fails, as
    /// `/D` does without the privilege to create symbolic links.
    fn new(kind: &str, link: &Path, target: &Path) -> Option<DirectoryLink> {
        let status = Command::new("cmd")
            .args(["/c", "mklink", kind])
            .arg(plain_path(link))
            .arg(plain_path(target))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        status.success().then(|| DirectoryLink(link.to_path_buf()))
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for DirectoryLink {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

/// A writable path spelled through a link is a second name of the folder the link leads to. The
/// resolver canonicalizes every policy path, and `canonicalize` follows junctions and symbolic
/// links, so rules 6 and 12 see the folder itself and refuse it as they refuse its own name.
/// The control is that name. `check` only reads state, so this is safe on the real folders.
/// Returns `false` when `mklink` could not make the link.
fn links_are_refused_like_their_targets(kind: &str) -> bool {
    let startup =
        user_profile().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    let system =
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join("Temp");
    // One fixture per kind: the tests of both kinds run at the same time in one process.
    let fixture = Fixture::new(&format!("link-protected-{}", &kind[1..]));
    for (name, target, reason) in [
        ("startup", &startup, "runs outside the sandbox"),
        ("system", &system, "system directory"),
    ] {
        let refused = check_with_path("C:\\Windows\\system32", target.to_str().unwrap());
        let report = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(refused.status.code(), Some(EXIT_CONFLICT), "{report}");
        assert!(report.contains(reason), "{report}");

        let Some(link) = DirectoryLink::new(kind, &fixture.path(name), target) else {
            return false;
        };
        let output = check_with_path("C:\\Windows\\system32", link.arg());
        let report = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(EXIT_CONFLICT),
            "{} passed: {report}",
            link.arg()
        );
        assert!(report.contains(reason), "{report}");
    }
    true
}

#[test]
fn a_writable_path_through_a_junction_is_refused_like_its_target() {
    let startup =
        user_profile().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    if !startup.exists() {
        return skip(
            "startup-folder",
            "this account has no Startup folder below its profile",
        );
    }
    assert!(
        links_are_refused_like_their_targets("/J"),
        "mklink /J failed"
    );
}

#[test]
fn a_writable_path_through_a_directory_symbolic_link_is_refused_like_its_target() {
    let startup =
        user_profile().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    if !startup.exists() {
        return skip(
            "startup-folder",
            "this account has no Startup folder below its profile",
        );
    }
    if !links_are_refused_like_their_targets("/D") {
        skip(
            "symbolic-links",
            "mklink /D failed: this session may not create symbolic links",
        );
    }
}

/// `sandy check` with the fixture's writable directory and `extra`.
fn check_with_writable(fixture: &Fixture, extra: &[&str]) -> std::process::Output {
    let mut all = vec!["check".to_string()];
    all.extend(platform_args());
    all.extend(["--read-write".to_string(), fixture.arg("rw")]);
    all.extend(args(extra));
    sandy(&all)
}

fn assert_refused(output: &std::process::Output, reason: &str) {
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "{stderr}");
}

/// Rule 4: a policy path resolved through a junction or a symbolic link inside a writable path
/// would lead wherever the program points that entry at the next start, so sandy refuses it, as
/// it refuses a symbolic link there on Linux and macOS. `check` refuses what `run` refuses and
/// grants nothing, so the links may lead to the secret directory. The same links outside the
/// writable path are the controls.
#[test]
fn refuses_a_policy_path_resolved_through_a_link_in_a_writable_path() {
    let fixture = Fixture::new("link-through");
    let probe = fixture.copy_probe("bin");
    let probe_name = Path::new(&probe).file_name().unwrap().to_str().unwrap();
    let inside = "inside writable path";
    for kind in ["/J", "/D"] {
        let link = |name: &str, target: &str| {
            let name = format!("{name}-{}", &kind[1..]);
            DirectoryLink::new(kind, &fixture.path(&name), &fixture.path(target))
        };
        let Some(outside) = link("secret-link", "secret") else {
            assert_ne!(kind, "/J", "mklink /J failed");
            skip(
                "symbolic-links",
                "mklink /D failed: this session may not create symbolic links",
            );
            continue;
        };
        let bin = link("bin-link", "bin").unwrap();
        let read = format!("{}\\file", outside.arg());
        let output = check_with_writable(&fixture, &["--read", &read]);
        assert!(output.status.success(), "{output:?}");
        let program = format!("{}\\{probe_name}", bin.arg());
        let output = check_with_writable(&fixture, &["--", &program]);
        assert!(output.status.success(), "{output:?}");

        let secret = link("rw/secret-link", "secret").unwrap();
        let bin = link("rw/bin-link", "bin").unwrap();
        for extra in [
            ["--read".to_string(), format!("{}\\file", secret.arg())],
            ["--read-write".to_string(), secret.arg().to_string()],
            ["--".to_string(), format!("{}\\{probe_name}", bin.arg())],
        ] {
            let output = check_with_writable(&fixture, &extra.each_ref().map(String::as_str));
            assert_refused(&output, inside);
        }
        // A chain: a link outside the writable path that leads through one inside it.
        let chain = link("chain", &format!("rw/secret-link-{}", &kind[1..])).unwrap();
        let read = format!("{}\\file", chain.arg());
        assert_refused(&check_with_writable(&fixture, &["--read", &read]), inside);
    }

    // A file symbolic link, and a relative one, which leads on from where it lies.
    let made = |target: &str, link: &str| {
        std::os::windows::fs::symlink_file(target, fixture.path(link)).is_ok()
    };
    if !made(&fixture.arg("ro/file"), "file-link") {
        return skip(
            "symbolic-links",
            "a file symbolic link failed: this session may not create symbolic links",
        );
    }
    assert!(made(&fixture.arg("ro/file"), "rw/file-link"));
    assert!(made("..\\ro\\file", "rw/relative-link"));
    let output = check_with_writable(&fixture, &["--read", &fixture.arg("file-link")]);
    assert!(output.status.success(), "{output:?}");
    for link in ["rw/file-link", "rw/relative-link"] {
        let output = check_with_writable(&fixture, &["--read", &fixture.arg(link)]);
        assert_refused(&output, inside);
    }
}

/// The policy file gets the checks of rules 3 and 4: a writable path must not reach it through a
/// junction and must hold no second name of it, as on Linux and macOS
/// (`escape::refuses_a_policy_file_reached_through_a_link_in_a_writable_path`). The program
/// would rewrite it there, and the next start would read what it wrote.
#[test]
fn refuses_a_policy_file_a_writable_path_reaches() {
    let fixture = Fixture::new("policy-reach");
    let policy = fixture.path("ro/policy.toml");
    let text = format!(
        "version = 1\n[filesystem]\nread_write = ['{}']\n",
        fixture.arg("rw")
    );
    fs::write(&policy, text).unwrap();
    let check = |file: &str| {
        let mut all = vec!["check".to_string()];
        all.extend(platform_args());
        all.extend(["--policy".to_string(), file.to_string()]);
        sandy(&all)
    };

    // Control: the policy file where it lies, outside the writable path.
    let output = check(&fixture.arg("ro/policy.toml"));
    assert!(output.status.success(), "{output:?}");

    // Named through a junction inside the writable path.
    let link = DirectoryLink::new("/J", &fixture.path("rw/j"), &fixture.path("ro"))
        .expect("mklink /J failed");
    let through = format!("{}\\policy.toml", link.arg());
    assert_refused(&check(&through), "writable path");
    drop(link);

    // Named where it lies, with a second name inside the writable path.
    fs::hard_link(&policy, fixture.path("rw/second.toml")).unwrap();
    assert_refused(&check(&fixture.arg("ro/policy.toml")), "writable path");
}

/// The same for sandy's own executable, which the program would replace for the next start
/// (`escape::refuses_a_sandy_executable_a_writable_path_reaches`). Windows reports the name sandy
/// was started under as its executable, so a junction on the way counts.
#[test]
fn refuses_a_sandy_executable_a_writable_path_reaches() {
    let fixture = Fixture::new("sandy-reach");
    let copy = fixture.path("bin/sandy.exe");
    copy_executable(sandy_path(), &copy);
    let check = |program: &Path| {
        let mut all = vec!["check".to_string()];
        all.extend(platform_args());
        all.extend(["--read-write".to_string(), fixture.arg("rw")]);
        run_copied(program, &all)
    };

    // Control: sandy outside the writable path.
    let output = check(&copy);
    assert!(output.status.success(), "{output:?}");

    // Started through a junction inside the writable path.
    let link = DirectoryLink::new("/J", &fixture.path("rw/j"), &fixture.path("bin"))
        .expect("mklink /J failed");
    let through = PathBuf::from(plain_path(&Path::new(link.arg()).join("sandy.exe")));
    assert_refused(&check(&through), "writable path");
    drop(link);

    // Started through a file symbolic link inside the writable path, where the session may
    // create one.
    let link = fixture.path("rw/sandy-link.exe");
    if std::os::windows::fs::symlink_file(&copy, &link).is_ok() {
        assert_refused(&check(&link), "writable path");
        fs::remove_file(&link).unwrap();
    } else {
        skip(
            "symbolic-links",
            "a file symbolic link failed: this session may not create symbolic links",
        );
    }

    // Started where it lies, with a second name inside the writable path.
    fs::hard_link(&copy, fixture.path("rw/sandy.exe")).unwrap();
    assert_refused(&check(&copy), "writable path");
}

/// A drive letter this test mapped to a share. Dropping it removes the mapping.
struct MappedDrive(String);

impl MappedDrive {
    /// Maps the first free letter from Z down to `share`, or `None` when `net use` fails.
    fn new(share: &str) -> Option<MappedDrive> {
        let letter = ('M'..='Z')
            .rev()
            .map(|letter| format!("{letter}:"))
            .find(|drive| !Path::new(&format!("{drive}\\")).exists())?;
        let status = Command::new("net")
            .args(["use", &letter, share])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        status.success().then_some(MappedDrive(letter))
    }
}

impl Drop for MappedDrive {
    fn drop(&mut self) {
        let _ = Command::new("net")
            .args(["use", &self.0, "/delete", "/y"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// A policy path through a network share is refused at every access level, also when a mapped
/// drive hides the share. The program could not open the share in its AppContainer, but the
/// entry sandy adds through it lands on the folder behind it, which the program then opens by
/// its local path; and the checks of rules 6 and 12 compared the share's spelling, so
/// `\\localhost\C$\Windows\Temp` passed rule 6 (docs/windows.md, "Links and identity"). The
/// control is the local path of the same folder. The administrative shares need an
/// administrator.
#[test]
fn network_and_share_paths_are_refused() {
    let fixture = Fixture::new("share-paths");
    let local = plain_path(&fixture.path("rw"));
    let check = |policy: &[&str]| {
        let mut check = vec!["check".to_string()];
        check.extend(platform_args());
        check.extend(args(policy));
        sandy(&check)
    };
    let output = check(&["--read-write", &local]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let share_of = |path: &str| format!(r"\\localhost\{}${}", &path[..1], &path[2..]);
    let share = share_of(&local);
    if !Path::new(&share).exists() {
        return skip(
            "administrative-share",
            "the administrative share of the system drive is not reachable",
        );
    }
    let system = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set"));
    let system_share = share_of(system.join("Temp").to_str().unwrap());
    let mapped = MappedDrive::new(&format!(r"\\localhost\{}$", &local[..1]))
        .expect("net use maps the administrative share");
    let through_drive = format!("{}{}", mapped.0, &local[2..]);
    for policy in [
        ["--read-write", share.as_str()],
        ["--read", share.as_str()],
        ["--read-exec", share.as_str()],
        ["--read-write", system_share.as_str()],
        ["--read-write", through_drive.as_str()],
    ] {
        let output = check(&policy);
        let report = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(EXIT_CONFLICT),
            "{policy:?}: {report}"
        );
        assert!(
            report.contains("network or share path"),
            "{policy:?}: {report}"
        );
    }

    let target = format!(r"{local}\file");
    let output = sandy(run_program(
        &args(&["--read", &share]),
        &probe_path(),
        &["read", &target],
    ));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    assert!(stderr.contains("network or share path"), "{stderr}");
}

/// sandy keeps the state of its runs below `%LOCALAPPDATA%\sandy`. A program that could write
/// there could rewrite the policy of its own AppContainer so that a run with another policy joins
/// it, or hold a lock that makes every later run wait. A writable path that reaches the folder is
/// refused by `check` and by `run`; a writable folder next to it is not.
#[test]
fn refuses_a_writable_path_into_sandys_state_folder() {
    let local = user_local_app_data();
    let state = local.join("sandy");
    let runs = state.join("runs");
    fs::create_dir_all(&runs).unwrap();
    let beside = local.join(format!("sandy-state-control-{}", std::process::id()));
    fs::create_dir_all(&beside).unwrap();

    let control = check_with_path("C:\\Windows\\system32", beside.to_str().unwrap());
    let _ = fs::remove_dir(&beside);
    assert_eq!(control.status.code(), Some(0), "{control:?}");
    for writable in [&state, &runs] {
        let refused = check_with_path("C:\\Windows\\system32", writable.to_str().unwrap());
        let report = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(refused.status.code(), Some(EXIT_CONFLICT), "{report}");
        assert!(report.contains("state of its runs"), "{report}");
    }
    let target = runs.join(format!("{}.probe", appcontainer_sid(&appcontainer_name())));
    let run = sandy(run_program(
        &args(&["--read-write", runs.to_str().unwrap()]),
        &probe_path(),
        &["write", target.to_str().unwrap()],
    ));
    let written = target.exists();
    let _ = fs::remove_file(&target);
    assert_eq!(run.status.code(), Some(EXIT_FAILURE), "{run:?}");
    assert!(!written, "the program wrote {}", target.display());
}

/// A directory on PATH inside a writable path lets the program leave a command there that the
/// user runs outside the sandbox by name. Such a policy is ordinary work, so sandy enforces it
/// and warns, naming the folder (README rule 8). The same writable path without that PATH entry
/// says nothing, and a writable folder below the user profile stays allowed.
#[test]
fn warns_about_a_writable_path_that_holds_a_directory_on_path() {
    let fixture = Fixture::new_in(&user_profile(), "trusted-path");
    fs::create_dir_all(fixture.path("rw/bin")).unwrap();
    let writable = fixture.arg("rw");

    let warned = check_with_path(
        &format!("{};C:\\Windows\\system32", fixture.arg("rw/bin")),
        &writable,
    );
    let report = String::from_utf8_lossy(&warned.stdout);
    let warnings = String::from_utf8_lossy(&warned.stderr);
    assert_eq!(warned.status.code(), Some(0), "{report}{warnings}");
    let names_it =
        |line: &str| line.starts_with("warning: ") && line.contains(&fixture.arg("rw/bin"));
    assert!(warnings.lines().any(names_it), "{warnings}");

    let quiet = check_with_path("C:\\Windows\\system32", &writable);
    let warnings = String::from_utf8_lossy(&quiet.stderr);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(!warnings.contains(&fixture.arg("rw/bin")), "{warnings}");
}

/// A warning names only a real overlap. A PATH entry that leads through a junction this session
/// may not follow cannot be identified: an elevated process does not traverse a junction that a
/// less trusted process made (`ERROR_UNTRUSTED_MOUNT_POINT`, measured on Windows 11 for a
/// junction that the sandboxed program made, as a package manager of the user makes them). A
/// PATH entry that does not exist leads nowhere. Neither reaches an unrelated writable path, so
/// `check` compares the canonical spellings and does not warn. The controls are the same kinds of
/// entry inside the writable path, through such a junction, through one this test made and one
/// that does not exist yet, which the program could create; all of them are warned about.
#[test]
fn warns_only_about_path_directories_a_writable_path_really_holds() {
    let fixture = Fixture::new("path-untrusted");
    for dir in [r"tools\1.0", "data", r"rw\1.0\bin"] {
        fs::create_dir_all(fixture.path(dir)).unwrap();
    }
    for (writable, version) in [("tools", r"tools\1.0"), ("rw", r"rw\1.0")] {
        let link = format!(
            "{}\u{1f}{}",
            fixture.arg(version),
            fixture.arg(&format!(r"{writable}\current"))
        );
        let made = probe_inside(
            &args(&["--read-write", &fixture.arg(writable)]),
            &[("junction", &link)],
        );
        made[0].assert_ok();
    }
    let _into = DirectoryLink::new("/J", &fixture.path("into"), &fixture.path("rw"))
        .expect("mklink /J failed");
    let entry = |relative: &str| plain_path(&fixture.path(relative));
    let warned = |entries: &[String], writable: &str| {
        let output = check_with_path(
            &format!("{};C:\\Windows\\system32", entries.join(";")),
            &fixture.arg(writable),
        );
        let warnings = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let named: Vec<bool> = entries
            .iter()
            .map(|entry| {
                warnings
                    .lines()
                    .any(|line| line.starts_with("warning: ") && line.contains(entry.as_str()))
            })
            .collect();
        (named, warnings)
    };

    let unrelated = [entry(r"tools\current\bin"), entry(r"missing\bin")];
    let (named, warnings) = warned(&unrelated, "data");
    assert_eq!(named, [false, false], "{warnings}");

    let inside = [
        entry(r"rw\current\bin"),
        entry(r"into\1.0\bin"),
        entry(r"rw\later\bin"),
    ];
    let (named, warnings) = warned(&inside, "rw");
    assert_eq!(named, [true, true, true], "{warnings}");
}

/// A writable path that holds a directory on PATH and a trusted location stays refused: the
/// warning never replaces the refusal. The folder on PATH does not have to exist, so this only
/// reads state, as the test above.
#[test]
fn refuses_a_writable_path_that_holds_a_directory_on_path_and_the_startup_folder() {
    let startup =
        user_profile().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    if !startup.exists() {
        return skip(
            "startup-folder",
            "this account has no Startup folder below its profile",
        );
    }
    let on_path = format!("{}\\bin", startup.display());
    let refused = check_with_path(
        &format!("{on_path};C:\\Windows\\system32"),
        startup.to_str().unwrap(),
    );
    let report = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(refused.status.code(), Some(EXIT_CONFLICT), "{report}");
    assert!(report.contains("runs outside the sandbox"), "{report}");
    // The folder on PATH is warned about as well, so the refusal did win over a warning.
    let warnings = String::from_utf8_lossy(&refused.stderr);
    let names_it = |line: &str| line.starts_with("warning: ") && line.contains(&on_path);
    assert!(warnings.lines().any(names_it), "{warnings}");
}

/// `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON`, the flag sandy sets
/// under `windows.win32k = "deny"`.
const WIN32K_SYSTEM_CALL_DISABLE: u64 = 1 << 28;

/// `STATUS_DLL_INIT_FAILED`: a DLL, here `user32.dll`, failed to load before the program ran.
const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;

/// Runs `program` outside the sandbox, with win32k system calls disabled when `lockdown` is set,
/// as sandy starts the program: its own console without a window, standard input from NUL.
/// Returns the exit code and standard output. This is the control that tells what the lockdown
/// costs a program from what the AppContainer costs it.
fn outside_with_lockdown(program: &str, program_args: &[&str], lockdown: bool) -> (u32, String) {
    use std::io::Read;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
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
    let null: OwnedHandle = fs::File::open("NUL").unwrap().into();
    for handle in [&write, &null] {
        // SAFETY: handle is valid; only its inherit flag changes.
        let ok = unsafe {
            SetHandleInformation(
                handle.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        };
        assert_ne!(ok, 0);
    }
    // Only these two handles reach the child, whatever other test threads hold inheritable.
    let inherited = [write.as_raw_handle(), null.as_raw_handle()];
    let mut size = 0usize;
    // SAFETY: a null list with a size pointer only asks for the size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
    let mut list = vec![0usize; size.div_ceil(size_of::<usize>())];
    let attributes = list.as_mut_ptr().cast();
    // SAFETY: the buffer is at least `size` bytes and pointer-aligned.
    let initialized = unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &mut size) };
    assert_ne!(initialized, 0);
    let set = |attribute: u32, value: *const std::ffi::c_void, size: usize| {
        // SAFETY: the list is initialized; value points to `size` bytes in the layout of the
        // attribute and outlives CreateProcessW below.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                attribute as usize,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    };
    set(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited.as_ptr().cast(),
        size_of_val(&inherited),
    );
    if lockdown {
        set(
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            (&WIN32K_SYSTEM_CALL_DISABLE as *const u64).cast(),
            size_of::<u64>(),
        );
    }

    let needs_quote = |arg: &str| arg.is_empty() || arg.contains([' ', '\t', '"']);
    let mut line = format!("\"{program}\"");
    for arg in program_args {
        if needs_quote(arg) {
            line.push_str(&format!(" \"{}\"", arg.replace('"', "\\\"")));
        } else {
            line.push_str(&format!(" {arg}"));
        }
    }
    let mut line: Vec<u16> = line.encode_utf16().chain([0]).collect();
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null.as_raw_handle();
    startup.StartupInfo.hStdOutput = write.as_raw_handle();
    startup.StartupInfo.hStdError = write.as_raw_handle();
    startup.lpAttributeList = attributes;
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: line is NUL-terminated and writable; startup, the attribute list and the values it
    // points to, and info outlive the call.
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let error = std::io::Error::last_os_error();
    // SAFETY: the list was initialized above.
    unsafe { DeleteProcThreadAttributeList(attributes) };
    assert_ne!(created, 0, "cannot start {program}: {error}");
    // SAFETY: CreateProcessW returned two new handles that this function owns.
    let (process, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    drop((write, null));
    // Drain the pipe on another thread, so a program whose output fills the pipe buffer does not
    // block while this thread waits for it to end.
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let _ = fs::File::from(read).read_to_string(&mut output);
        output
    });
    let mut code = 0u32;
    // SAFETY: process is valid; code is a writable u32.
    unsafe {
        WaitForSingleObject(process.as_raw_handle(), INFINITE);
        GetExitCodeProcess(process.as_raw_handle(), &mut code);
    }
    (code, reader.join().unwrap_or_default())
}

/// With `windows.win32k = "deny"` the program, every child it starts and its console host run
/// with win32k system calls disabled, and a win32k call fails; without it they do not.
///
/// The call is the system call stub of `NtGdiCreateCompatibleDC`, so the answer is the kernel's.
/// The outside control shows that the probe sees the lockdown: the same call works outside the
/// sandbox and fails there once the flag is set. Inside, the program can open its console host,
/// so the host must carry the flag too, or the program could make the calls through it.
#[test]
fn win32k_lockdown_reaches_the_program_its_children_and_its_console_host() {
    let probe = probe_path();
    let (code, output) = outside_with_lockdown(&probe, &["win32k-call", "x"], false);
    assert_eq!(code, 0, "{output}");
    parse_line(output.trim_end()).assert_ok();
    let (code, output) = outside_with_lockdown(&probe, &["win32k-call", "x"], true);
    assert_eq!(code, 0, "{output}");
    parse_line(output.trim_end()).assert_blocked();

    let children = !appcontainer_children_blocked();
    let child = format!("{probe}\u{1f}win32k-policy\u{1f}x");
    let mut actions = vec![
        ("win32k-policy", "x"),
        ("win32k-of", "conhost.exe"),
        ("win32k-call", "x"),
    ];
    if children {
        actions.push(("spawn-output", &child));
    }
    for (deny, flags) in [(true, "0x1"), (false, "0x0")] {
        let sandbox_args = if deny {
            args(&["--windows-win32k", "deny"])
        } else {
            Vec::new()
        };
        let lines = probe_inside(&sandbox_args, &actions);
        assert_eq!(lines[0].detail, format!("flags {flags}"), "{lines:?}");
        lines[1].assert_ok();
        assert!(
            lines[1]
                .detail
                .split(' ')
                .all(|host| host.ends_with(&format!("={flags}"))),
            "{lines:?}"
        );
        if children {
            assert!(
                lines[3].detail.contains(&format!("flags {flags}")),
                "{lines:?}"
            );
        }
        if deny {
            lines[2].assert_blocked();
        } else if lines[2].result != "ok" {
            skip(
                "win32k-in-appcontainer",
                &format!(
                    "this session refuses win32k calls of AppContainer processes also without the \
                     lockdown ({}), as over SSH (docs/windows.md limitation 13), so the call shows \
                     no difference",
                    lines[2].detail
                ),
            );
        }
    }
}

/// The relay runs in the program's AppContainer, where the program can open it, so it starts with
/// win32k system calls disabled too, and still relays. The program reads the flag of every relay
/// it can query: one, which serves the exposed and the forwarded port. Without the key the flag is
/// clear.
#[test]
fn the_relays_run_with_the_win32k_lockdown() {
    let fixture = Fixture::new("win32k-relays");
    for (deny, flags) in [(true, "0x1"), (false, "0x0")] {
        let (inner, outer) = (free_port(), free_port());
        let mut sandbox_args = fixture.access_args();
        sandbox_args.extend(args(&["--ip", "all", "--expose"]));
        sandbox_args.push(format!("127.0.0.1:{outer}={inner}"));
        sandbox_args.push("--forward".into());
        sandbox_args.push(format!("{}=127.0.0.1:{}", free_port(), free_port()));
        if deny {
            sandbox_args.extend(args(&["--windows-win32k", "deny"]));
        }
        let inner_address = format!("127.0.0.1:{inner}");
        let mut server = Command::new(sandy_path())
            .args(run_args(
                &sandbox_args,
                &[("win32k-of", "sandy.exe"), ("tcp-accept", &inner_address)],
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while server.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the server never accepted");
            let _ = TcpStream::connect_timeout(
                &format!("127.0.0.1:{outer}").parse().unwrap(),
                Duration::from_millis(500),
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let output = server.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let lines = parse(&output);
        lines[0].assert_ok();
        let relays: Vec<&str> = lines[0].detail.split(' ').collect();
        assert_eq!(relays.len(), 1, "{lines:?}");
        assert!(
            relays
                .iter()
                .all(|relay| relay.ends_with(&format!("={flags}"))),
            "{lines:?}"
        );
        lines[1].assert_ok();
    }
}

/// What the lockdown costs (docs/windows.md, "Win32k"): a program that loads `user32.dll`
/// cannot start, because the DLL calls win32k when it loads. Measured outside the sandbox, so
/// the AppContainer plays no part; the run in the sandbox shows a program that needs no win32k
/// working there with the key.
#[test]
fn win32k_lockdown_stops_programs_that_load_user32() {
    let system = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
    let program = |name: &str| system.join(name).to_str().unwrap().to_string();
    // Console programs that start with the lockdown (they load no GUI library), and ones that do
    // not (they load user32.dll, which calls win32k when it initializes). Every one runs without
    // the lockdown.
    let starting = [
        (program("cmd.exe"), vec!["/c", "echo", "ok"]),
        (program("tar.exe"), vec!["--version"]),
        (program("curl.exe"), vec!["--version"]),
        (program("hostname.exe"), vec![]),
    ];
    let stopped = [
        (
            program(r"WindowsPowerShell\v1.0\powershell.exe"),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output ok",
            ],
        ),
        (program("whoami.exe"), vec![]),
    ];
    let mut failures = Vec::new();
    let mut record = |path: &str, args: &[&str], lockdown: bool, want: u32| {
        let (code, output) = outside_with_lockdown(path, args, lockdown);
        if code != want {
            let name = Path::new(path).file_name().unwrap().to_string_lossy();
            let out = output.lines().next().unwrap_or("").trim();
            failures.push(format!(
                "{name} lockdown={lockdown}: exit {code:#x}, want {want:#x} [{out}]"
            ));
        }
    };
    for (path, program_args) in starting.iter().chain(&stopped) {
        record(path, program_args, false, 0);
    }
    for (path, program_args) in &starting {
        record(path, program_args, true, 0);
    }
    for (path, program_args) in &stopped {
        record(path, program_args, true, STATUS_DLL_INIT_FAILED);
    }
    assert!(failures.is_empty(), "\n---- win32k programs: {failures:?}");

    let output = sandy(run_program(
        &args(&["--windows-win32k", "deny"]),
        &program("cmd.exe"),
        &["/c", "echo", "ok"],
    ));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

// `ip = "private"`: the program's AppContainer without network capabilities and without the
// loopback exemption (docs/windows.md, "Private network").

/// `--ip private` for this test's AppContainer, which has no loopback exemption.
fn private_args(fixture: &Fixture) -> Vec<String> {
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&["--ip", "private"]));
    sandbox_args
}

/// This machine's IPv4 address on the route to other hosts, if it has one. Connecting a UDP
/// socket sends nothing; it picks the route and the source address.
fn lan_address() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified() && !address.is_loopback()).then_some(address)
}

/// The IPv4 gateway of the route to other hosts, if there is one. On the test VM that is the host
/// of its virtual network, which runs a DNS server on TCP and UDP port 53.
fn gateway() -> Option<std::net::Ipv4Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut route: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    // SAFETY: route is writable; the addresses are in network byte order.
    let error = unsafe { GetBestRoute(u32::from_ne_bytes([192, 0, 2, 1]), 0, &mut route) };
    let hop = std::net::Ipv4Addr::from(route.dwForwardNextHop.to_ne_bytes());
    (error == 0 && !hop.is_unspecified()).then_some(hop)
}

/// The directed broadcast address of the IPv4 subnet the gateway is on, if this machine has a
/// gateway on a subnet with room for one: the best route to the gateway is that subnet's.
fn subnet_broadcast() -> Option<std::net::Ipv4Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
    let gateway = gateway()?;
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut route: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    // SAFETY: route is writable; the address is in network byte order.
    let error = unsafe { GetBestRoute(u32::from_ne_bytes(gateway.octets()), 0, &mut route) };
    let mask = u32::from_be_bytes(route.dwForwardMask.to_ne_bytes());
    let subnet = u32::from_be_bytes(route.dwForwardDest.to_ne_bytes());
    (error == 0 && mask.leading_ones() < 31).then(|| std::net::Ipv4Addr::from(subnet | !mask))
}

/// The program and its own processes talk over loopback, IPv4 and IPv6: the reason for
/// `ip = "private"`.
#[test]
fn ip_private_connects_on_its_own_loopback() {
    let fixture = Fixture::new("private-self");
    let lines = controlled(
        &private_args(&fixture),
        &[("tcp-self", "127.0.0.1:0"), ("tcp-self", "[::1]:0")],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
}

/// Records the exceptions-table row (docs/DESIGN.md): with `ip = "none"` the program's own
/// processes in its AppContainer still reach each other over loopback, so a Windows release that
/// closed that would fail here and the exception could go. One process reaching its own loopback
/// listener stands in for two of the program's processes, which `children = "none"` would forbid.
#[test]
fn loopback_within_the_appcontainer_works_under_ip_none() {
    let fixture = Fixture::new("none-loopback");
    let lines = controlled(
        &fixture.access_args(),
        &[("tcp-self", "127.0.0.1:0"), ("tcp-self", "[::1]:0")],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
}

/// Nothing on this machine outside the AppContainer: a listener on 127.0.0.1, on ::1 and on the
/// machine's own address on the network, and a socket on 127.0.0.1 and ::1 that waits for a
/// datagram. Each works outside the sandbox.
#[test]
fn ip_private_reaches_nothing_on_this_machine_outside_the_appcontainer() {
    let fixture = Fixture::new("private-local");
    let private = private_args(&fixture);
    let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = TcpListener::bind("[::1]:0").unwrap();
    let mut targets = vec![
        v4.local_addr().unwrap().to_string(),
        v6.local_addr().unwrap().to_string(),
    ];
    let lan = lan_address().map(|address| TcpListener::bind((address, 0)).unwrap());
    match &lan {
        Some(listener) => targets.push(listener.local_addr().unwrap().to_string()),
        None => skip(
            "network-address",
            "this machine has no route to other hosts",
        ),
    }
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|target| ("tcp-connect", target.as_str()))
        .collect();
    for line in controlled(&private, &actions) {
        line.assert_blocked();
    }

    for bind in ["127.0.0.1:0", "[::1]:0"] {
        assert!(datagram_arrives(None, bind), "control on {bind}");
        assert!(
            !datagram_arrives(Some(&private), bind),
            "a datagram reached {bind}"
        );
    }
}

/// Whether a datagram that the probe sends to a socket of this process on `bind` arrives, with
/// the probe outside the sandbox when `sandbox_args` is `None`.
fn datagram_arrives(sandbox_args: Option<&[String]>, bind: &str) -> bool {
    let socket = std::net::UdpSocket::bind(bind).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = socket.local_addr().unwrap().to_string();
    let output = probe_command(sandbox_args, &[("udp-send", &target)])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut buffer = [0; 16];
    socket.recv_from(&mut buffer).is_ok()
}

/// Nothing on the network: the gateway, on the test VM the host of its virtual network, by TCP to
/// the DNS server it runs, by a DNS query over UDP and by ICMP echo. Each action that works
/// outside the sandbox is denied inside, and the connection with `ip = "all"` shows that the
/// denial comes from the missing network capability.
#[test]
fn ip_private_reaches_no_host_of_the_network() {
    let Some(gateway) = gateway() else {
        skip(
            "network-gateway",
            "this machine has no route to other hosts",
        );
        return;
    };
    let fixture = Fixture::new("private-network");
    let name = std::env::var("COMPUTERNAME").expect("COMPUTERNAME is set");
    let tcp = format!("{gateway}:53");
    let query = format!("{gateway}:53\u{1f}{name}");
    let icmp = gateway.to_string();
    let actions = [
        ("tcp-connect", tcp.as_str()),
        ("dns-query", query.as_str()),
        ("icmp-echo", icmp.as_str()),
    ];
    let outside = probe_outside(&actions);
    let inside = probe_inside(&private_args(&fixture), &actions);
    for (control, line) in outside.iter().zip(&inside) {
        if control.result == "ok" {
            line.assert_blocked();
        } else {
            skip(
                "network-gateway",
                &format!(
                    "{} {} fails outside the sandbox: {}",
                    control.action, control.target, control.detail
                ),
            );
        }
    }
    if outside[0].result == "ok" {
        let mut all = fixture.access_args();
        all.extend(args(&["--ip", "all"]));
        probe_inside(&all, &actions[..1])[0].assert_ok();
    }
}

/// The WFP events of the last datagrams to `port`, from `netsh wfp show netevents`, which needs
/// administrator rights. `None` when they cannot be read.
fn network_events(port: u16) -> Option<String> {
    let file =
        std::env::temp_dir().join(format!("sandy-netevents-{port}-{}.xml", std::process::id()));
    let shown = Command::new("netsh")
        .args(["wfp", "show", "netevents"])
        .arg(format!("remoteport={port}"))
        .arg(format!("file={}", file.display()))
        .output()
        .ok()?;
    let events = fs::read_to_string(&file).ok();
    let _ = fs::remove_file(&file);
    events.filter(|_| shown.status.success())
}

/// A datagram the program sends to another host is dropped before it leaves the machine, although
/// `sendto` reports success: Windows Firewall logs the drop at the connect layer, outbound, for
/// the program's AppContainer (docs/windows.md, "Private network"). The same datagram from
/// outside the sandbox leaves without a drop. Reading the firewall's events needs administrator
/// rights.
#[test]
fn ip_private_datagrams_to_the_network_are_dropped_before_they_leave() {
    let Some(gateway) = gateway() else {
        skip(
            "network-gateway",
            "this machine has no route to other hosts",
        );
        return;
    };
    let fixture = Fixture::new("private-datagram");
    let (outside_port, inside_port) = (free_port(), free_port());
    let to = |port: u16| format!("{gateway}:{port}");
    probe_outside(&[("udp-send", &to(outside_port))])[0].assert_ok();
    // sendto does not report the drop.
    probe_inside(&private_args(&fixture), &[("udp-send", &to(inside_port))])[0].assert_ok();

    let sid = appcontainer_sid(&appcontainer_name());
    // One event per header; other tests run at the same time and may log events of their own.
    let drops = |events: &str, port: u16| -> Vec<String> {
        events
            .split("<header>")
            .filter(|event| {
                event.contains("CLASSIFY_DROP")
                    && event.contains("MS_FWP_DIRECTION_OUT")
                    && event.contains(&format!("<remoteAddrV4>{gateway}<"))
                    && event.contains(&format!("<remotePort>{port}<"))
            })
            .map(str::to_string)
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let dropped = loop {
        let Some(events) = network_events(inside_port) else {
            skip(
                "wfp-events",
                "netsh cannot read the firewall's events without administrator rights",
            );
            return;
        };
        let dropped = drops(&events, inside_port);
        if !dropped.is_empty() || Instant::now() > deadline {
            break dropped;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    assert!(
        dropped.iter().any(|event| event.contains(&sid)
            && (event.contains("FWPM_LAYER_ALE_AUTH_CONNECT_V4")
                || event.contains("<layerId>48<"))),
        "no drop at the connect layer for {sid}: {dropped:?}"
    );
    let control = network_events(outside_port).unwrap_or_default();
    let control = drops(&control, outside_port);
    assert!(
        control.is_empty(),
        "the datagram from outside was dropped too: {control:?}"
    );
}

/// A name that only a DNS server knows does not resolve, while `localhost` still does, so the
/// resolver works and refuses only what needs the network. `SANDY_TEST_NETWORK_NAME` names the
/// host to resolve, `example.com` by default; the check is skipped where that name does not
/// resolve outside the sandbox.
#[test]
fn ip_private_resolves_no_network_name() {
    let name = std::env::var("SANDY_TEST_NETWORK_NAME").unwrap_or("example.com".to_string());
    let control = probe_outside(&[("resolve", &name)]);
    if control[0].result != "ok" {
        skip(
            "network-name",
            &format!(
                "{name} does not resolve outside the sandbox: {}",
                control[0].detail
            ),
        );
        return;
    }
    let fixture = Fixture::new("private-names");
    let lines = probe_inside(
        &private_args(&fixture),
        &[("resolve", "localhost"), ("resolve", &name)],
    );
    lines[0].assert_ok();
    lines[1].assert_blocked();
    let mut client = fixture.access_args();
    client.extend(args(&["--ip", "client"]));
    probe_inside(&client, &[("resolve", &name)])[0].assert_ok();
}

/// Starts the probe's `tcp-accept` on `listen`, outside the sandbox when `sandbox_args` is
/// `None`, and connects to each of `connect` from this process while it waits. Returns whether a
/// connection was made and the probe's report.
fn accepts_from_this_machine(
    sandbox_args: Option<&[String]>,
    listen: std::net::SocketAddr,
    connect: &[std::net::SocketAddr],
) -> (bool, ProbeLine) {
    let target = listen.to_string();
    let mut child = probe_command(sandbox_args, &[("tcp-accept", target.as_str())])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut connected = false;
    while !connected && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        connected = connect
            .iter()
            .any(|address| TcpStream::connect_timeout(address, Duration::from_millis(300)).is_ok());
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().unwrap();
    let mut lines = parse(&output);
    assert_eq!(lines.len(), 1, "{output:?}");
    (connected, lines.remove(0))
}

/// No process outside the AppContainer connects to a port the program listens on, at any
/// address of this machine, and no datagram from outside reaches it. The program listens on
/// every address, so only isolation keeps the connections out.
#[test]
fn ip_private_takes_no_connections_or_datagrams_from_outside() {
    let fixture = Fixture::new("private-in");
    let private = private_args(&fixture);
    let port = free_port();
    let mut v4: Vec<std::net::SocketAddr> = vec![(std::net::Ipv4Addr::LOCALHOST, port).into()];
    match lan_address() {
        Some(address) => v4.push((address, port).into()),
        None => skip(
            "network-address",
            "this machine has no route to other hosts",
        ),
    }
    let v6 = [(std::net::Ipv6Addr::LOCALHOST, port).into()];
    let any_v4 = (std::net::Ipv4Addr::UNSPECIFIED, port).into();
    let any_v6 = (std::net::Ipv6Addr::UNSPECIFIED, port).into();
    for (listen, connect) in [(any_v4, &v4[..]), (any_v6, &v6[..])] {
        let (connected, line) = accepts_from_this_machine(None, listen, connect);
        assert!(connected, "control on {listen}: {line:?}");
        line.assert_ok();
        let (connected, line) = accepts_from_this_machine(Some(&private), listen, connect);
        assert!(!connected, "connected to the program on {listen}: {line:?}");
        line.assert_blocked();
    }

    inbound_udp(None).assert_ok();
    inbound_udp(Some(&private)).assert_blocked();
}

/// `expose` reaches a program with `ip = "private"`: the relay runs in the program's
/// AppContainer, also without network capabilities.
#[test]
fn an_exposed_port_reaches_a_program_with_ip_private() {
    let fixture = Fixture::new("private-expose");
    let (inner, outer) = (free_port(), free_port());
    let mut sandbox_args = private_args(&fixture);
    sandbox_args.extend(args(&["--expose", &format!("127.0.0.1:{outer}={inner}")]));
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

/// `forward` works with `ip = "private"`: the program reaches the service outside through its
/// relay, and the same listener directly not.
#[test]
fn a_forwarded_port_works_with_ip_private() {
    let fixture = Fixture::new("private-forward");
    let (service, received) = one_shot_service();
    let inner = free_port();
    let mut sandbox_args = private_args(&fixture);
    sandbox_args.extend(args(&[
        "--forward",
        &format!("{inner}=127.0.0.1:{service}"),
    ]));
    let lines = probe_inside(
        &sandbox_args,
        &[
            ("tcp-connect", &format!("127.0.0.1:{service}")),
            ("tcp-send", &format!("127.0.0.1:{inner}")),
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_ok();
    assert_eq!(received.join().unwrap().as_deref(), Some(TCP_SEND_PAYLOAD));
}

/// An exempt AppContainer reaches 127.0.0.1 outside also without capabilities, so `check`
/// refuses `ip = "private"` there with the setup status (2), and `sandy setup` with the policy
/// takes the exemption away. Needs administrator rights, like `prepare_loopback_exemption`.
#[test]
fn setup_takes_the_loopback_exemption_from_a_private_network() {
    prepare_loopback_exemption();
    let name = appcontainer_loopback_name();
    let check = || sandy(["check", "--appcontainer", &name, "--ip", "private"]);
    let output = check();
    assert_eq!(output.status.code(), Some(EXIT_NEEDS_SETUP), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exempt"), "{stdout}");

    let setup = sandy(["setup", "--appcontainer", &name, "--ip", "private"]);
    assert!(setup.status.success(), "{setup:?}");
    let output = check();
    assert!(output.status.success(), "{output:?}");
}

/// Windows cannot hide paths from an AppContainer, so `view = "policy"` is refused and the
/// reason says why.
#[test]
fn the_policy_view_is_refused() {
    let output = sandy([
        "check",
        "--appcontainer",
        &appcontainer_name(),
        "--view",
        "policy",
    ]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_NOT_ENFORCEABLE),
        "{output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("administrator rights"), "{stdout}");
    assert!(stdout.contains("What the program can see"), "{stdout}");
}

// `network.egress`: the SOCKS5 broker, a separate `sandy __broker` process in an AppContainer of
// its own, reached from the program through the egress port over the forward path
// (docs/windows.md, "Egress broker").

/// `--ip private --egress PORT[=REACH]` for this test's AppContainer, which is not exempt.
fn egress_args(fixture: &Fixture, port: u16, reach: &str) -> Vec<String> {
    let egress = if reach.is_empty() {
        port.to_string()
    } else {
        format!("{port}={reach}")
    };
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&["--ip", "private", "--egress", &egress]));
    sandbox_args
}

/// Asks the broker on the egress port to connect to `destination`, and returns the probe's line.
fn through_broker(sandbox_args: &[String], port: u16, destination: &str) -> ProbeLine {
    let target = format!("127.0.0.1:{port}\u{1f}{destination}");
    let mut lines = probe_inside(sandbox_args, &[("socks5-connect", &target)]);
    lines.remove(0)
}

/// A bracketed form for an IPv6 address, plain for IPv4, with a port.
fn with_port(address: std::net::IpAddr, port: u16) -> String {
    std::net::SocketAddr::new(address, port).to_string()
}

/// With `reach = "public"` the broker connects to a public internet address. Skipped where this
/// host has no route to one.
#[test]
fn egress_reaches_an_allowed_public_destination() {
    let public = "1.1.1.1:443";
    if probe_outside(&[("tcp-connect", public)])[0].result != "ok" {
        skip("internet", "this host has no route to a public address");
        return;
    }
    let fixture = Fixture::new("egress-public");
    let port = free_port();
    let line = through_broker(&egress_args(&fixture, port, "public"), port, public);
    assert_eq!(line.detail, "reply 0", "{line:?}");
}

/// With `reach = "public"` the broker refuses this machine and the local network, in every form,
/// with reply 2, and connects to none of them.
#[test]
fn egress_under_public_refuses_this_machine_and_the_local_network() {
    let fixture = Fixture::new("egress-refuse");
    let port = free_port();
    let args = egress_args(&fixture, port, "public");
    let mut destinations = vec![
        "127.0.0.1:53".to_string(),
        "[::1]:53".to_string(),
        "0.0.0.0:53".to_string(),
        "[::ffff:127.0.0.1]:53".to_string(),
    ];
    if let Some(gateway) = gateway() {
        destinations.push(with_port(gateway.into(), 53));
    }
    if let Some(lan) = lan_address() {
        destinations.push(with_port(lan, 53));
    }
    for destination in destinations {
        let line = through_broker(&args, port, &destination);
        assert_eq!(line.detail, "reply 2", "{destination}: {line:?}");
    }
}

/// With `reach = "public-and-local"` the broker reaches the gateway (the host of the test VM's
/// network, which runs a resolver on port 53), but still refuses this machine itself, also by
/// the broadcast address of its subnet, which only the host's part of the check knows.
#[test]
fn egress_under_public_and_local_allows_the_gateway_but_not_this_machine() {
    let Some(gateway) = gateway() else {
        skip(
            "network-gateway",
            "this machine has no route to other hosts",
        );
        return;
    };
    let dest = with_port(gateway.into(), 53);
    if probe_outside(&[("tcp-connect", &dest)])[0].result != "ok" {
        skip("network-gateway", "the gateway runs no service on port 53");
        return;
    }
    let fixture = Fixture::new("egress-local");
    let port = free_port();
    let args = egress_args(&fixture, port, "public-and-local");
    assert_eq!(
        through_broker(&args, port, &dest).detail,
        "reply 0",
        "the gateway was refused under public-and-local"
    );
    // This machine stays refused even under public-and-local.
    assert_eq!(
        through_broker(&args, port, "127.0.0.1:53").detail,
        "reply 2"
    );
    if let Some(lan) = lan_address() {
        assert_eq!(
            through_broker(&args, port, &with_port(lan, 53)).detail,
            "reply 2"
        );
    }
    // Nor the broadcast address of the gateway's subnet, which is this machine's too.
    if let Some(broadcast) = subnet_broadcast() {
        assert_eq!(
            through_broker(&args, port, &with_port(broadcast.into(), 53)).detail,
            "reply 2",
            "{broadcast}"
        );
    }
}

/// The broker refuses a domain name with reply 8, so it resolves nothing for the program.
#[test]
fn egress_refuses_a_name() {
    let fixture = Fixture::new("egress-name");
    let port = free_port();
    let line = through_broker(
        &egress_args(&fixture, port, "public"),
        port,
        "example.com:80",
    );
    assert_eq!(line.detail, "reply 8", "{line:?}");
}

/// The broker is in the program's relay job, so it ends with the program, and sandy waits until
/// it is gone before it exits. Its process is a `sandy.exe` child of the run, like the relays.
#[test]
fn the_egress_broker_ends_with_the_program() {
    let fixture = Fixture::new("egress-end");
    let port = free_port();
    let run = Command::new(sandy_path())
        .args(run_args(
            &egress_args(&fixture, port, "public"),
            &[("sleep", "2000")],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let children = loop {
        let children = relay_processes(run.id());
        // The relay and the broker are both sandy.exe children.
        if children.len() >= 2 {
            break children;
        }
        assert!(Instant::now() < deadline, "the broker never started");
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    for child in &children {
        assert!(
            ends_within(child, Duration::ZERO),
            "the egress relay or the broker outlived sandy"
        );
    }
}

/// Rule 5 of "Forwarded ports": the egress port is free as soon as the run has ended, because
/// sandy ends its relays before it exits, so a run that starts right after gets the port.
#[test]
fn the_egress_port_is_free_as_soon_as_the_run_ends() {
    let fixture = Fixture::new("egress-free");
    let port = free_port();
    let args = egress_args(&fixture, port, "public");
    let line = through_broker(&args, port, "example.com:80");
    assert_eq!(line.detail, "reply 8", "{line:?}");
    let freed = TcpListener::bind(("127.0.0.1", port)).map(drop);
    assert!(freed.is_ok(), "{freed:?}");
    let line = through_broker(&args, port, "example.com:80");
    assert_eq!(line.detail, "reply 8", "the next run: {line:?}");
}

/// The runs of one policy share the broker's AppContainer, so its profile stays when a run ends,
/// like the program's: a run that removed it made a run that was starting at that moment fail
/// when it reduced the rights on the profile folder. `sandy setup --remove` removes it.
#[test]
fn the_egress_brokers_profile_outlives_the_run() {
    let fixture = Fixture::new("egress-profile");
    let broker = format!("{}.sandy-egress", appcontainer_name());
    let folder = user_local_app_data().join("Packages").join(&broker);
    delete_profile(&broker);
    assert!(!folder.exists(), "{}", folder.display());
    let port = free_port();
    probe_inside(&egress_args(&fixture, port, "public"), &[("sleep", "0")])[0].assert_ok();
    assert!(folder.exists(), "the run removed {}", folder.display());

    let removed = sandy(["setup", "--remove", "--appcontainer", &appcontainer_name()]);
    if removed.status.code() == Some(3) {
        skip(
            "administrator-rights",
            "sandy setup --remove needs administrator rights",
        );
        return;
    }
    assert!(removed.status.success(), "{removed:?}");
    assert!(!folder.exists(), "setup --remove left {}", folder.display());
}

/// Starts a run with egress whose program sleeps for 20 seconds, and returns it with its relays
/// once both the egress relay and the broker run.
fn egress_run_with_relays(fixture: &Fixture) -> (Child, Vec<std::os::windows::io::OwnedHandle>) {
    let mut run = Command::new(sandy_path())
        .args(run_args(
            &egress_args(fixture, free_port(), "public"),
            &[("sleep", "20000")],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut children = relay_processes(run.id());
    while children.len() < 2 {
        if Instant::now() > deadline {
            run.kill().unwrap();
            run.wait().unwrap();
            panic!("the broker never started");
        }
        std::thread::sleep(Duration::from_millis(50));
        children = relay_processes(run.id());
    }
    (run, children)
}

/// A killed run leaves no broker behind with its network capabilities: the relay job's
/// kill-on-close ends it when sandy dies, and so does the end of its standard input, whose other
/// end sandy holds (either alone passes this test).
#[test]
fn a_killed_run_leaves_no_egress_broker_behind() {
    let fixture = Fixture::new("egress-killed");
    let (mut run, children) = egress_run_with_relays(&fixture);
    // Control: they run while sandy does, so their end below is sandy's death.
    for child in &children {
        assert!(!ends_within(child, Duration::ZERO));
    }
    run.kill().unwrap();
    run.wait().unwrap();
    for child in &children {
        assert!(
            ends_within(child, END_TIMEOUT),
            "a relay or the broker outlived sandy"
        );
    }
}

/// The broker holds network capabilities the program must not have, so no process in another
/// AppContainer may open it, with any right. The probe stands in for the program, in an
/// AppContainer of its own with `ip = "private"`, because the broker's process ID is not known
/// when the program starts; the control outside opens the egress relay and the broker.
#[test]
fn another_appcontainer_cannot_open_the_egress_broker() {
    use windows_sys::Win32::System::Threading::GetProcessId;
    let stand_in = "sandy.egress-stand-in-test";
    delete_profile(stand_in);
    let fixture = Fixture::new("egress-open");
    let (mut run, children) = egress_run_with_relays(&fixture);
    let rights = [
        "vm-write",
        "vm-operation",
        "dup-handle",
        "create-thread",
        "set-information",
        "suspend-resume",
        "query-information",
        "all-access",
    ];
    let targets: Vec<(&str, String)> = children
        .iter()
        // SAFETY: each handle is a process handle this test owns.
        .map(|child| unsafe { GetProcessId(child.as_raw_handle()) })
        .flat_map(|pid| {
            [
                ("open-process-read", pid.to_string()),
                ("open-process-terminate", pid.to_string()),
            ]
            .into_iter()
            .chain(rights.map(|right| ("open-process-right", format!("{pid}\u{1f}{right}"))))
        })
        .collect();
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|(action, target)| (*action, target.as_str()))
        .collect();
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&["--ip", "private", "--appcontainer", stand_in]));
    let outside = probe_outside(&actions);
    let inside = probe_inside(&sandbox_args, &actions);
    run.kill().unwrap();
    run.wait().unwrap();
    delete_profile(stand_in);
    for (control, line) in outside.iter().zip(&inside) {
        control.assert_ok();
        line.assert_blocked();
    }
}

/// The broker's AppContainer must not be exempt from loopback isolation, or nothing below the
/// destination check keeps the broker off this machine. sandy refuses the broker's name for a
/// policy, so only an administrator can exempt it, by hand; `check` then names setup (status 2),
/// and `sandy setup` with the policy removes the exemption. Needs administrator rights.
#[test]
fn setup_takes_the_loopback_exemption_from_the_egress_broker() {
    let name = appcontainer_name();
    let broker = format!("{name}.sandy-egress");
    let sid = format!("-p={}", appcontainer_sid(&broker));
    let exemption = |change: &str| {
        Command::new("CheckNetIsolation")
            .args(["LoopbackExempt", change, &sid])
            .output()
            .unwrap()
    };
    if !exemption("-a").status.success() {
        skip(
            "administrator-rights",
            "CheckNetIsolation cannot exempt the broker's AppContainer",
        );
        return;
    }
    let port = free_port().to_string();
    let policy = [
        "--appcontainer",
        &name,
        "--ip",
        "private",
        "--egress",
        &port,
    ];
    let check = || sandy(["check"].iter().chain(&policy));
    let refused = check();
    let setup = sandy(["setup"].iter().chain(&policy));
    let checked = check();
    // Also when an assertion fails below.
    exemption("-d");
    assert_eq!(refused.status.code(), Some(EXIT_NEEDS_SETUP), "{refused:?}");
    let stdout = String::from_utf8_lossy(&refused.stdout);
    assert!(
        stdout.contains(&broker) && stdout.contains("exempt"),
        "{stdout}"
    );
    assert!(setup.status.success(), "{setup:?}");
    assert!(checked.status.success(), "{checked:?}");
}

/// The broker runs `sandy.exe` from an AppContainer of its own, which needs a grant of its own on
/// the file. For a `sandy.exe` whose permissions the user cannot change, setup adds both grants;
/// when only the relays' grant is there, from a setup without egress, `check` names setup
/// (status 2) as `run` refuses, and after setup with egress both pass. sandy runs under the token
/// UAC gives an administrator without elevation; setup needs administrator rights.
#[test]
fn check_names_setup_when_only_the_brokers_grant_is_missing() {
    let name = "sandy.broker-grant-test";
    delete_profile(name);
    let directory = PathBuf::from(std::env::var_os("ProgramFiles").expect("ProgramFiles is set"))
        .join(format!("sandy-broker-grant-{}", std::process::id()));
    if fs::create_dir(&directory).is_err() {
        skip(
            "administrator-rights",
            "this session cannot create a folder in Program Files",
        );
        return;
    }
    let sandy = directory.join("sandy.exe");
    fs::copy(sandy_path(), &sandy).unwrap();
    let sandy = sandy.to_str().unwrap().to_string();
    // Only administrators may change the file; every user may run it.
    let locked = Command::new("icacls")
        .arg(&sandy)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-3-4:(RX)",
            "*S-1-5-11:(RX)",
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
        ])
        .output()
        .unwrap();
    let port = free_port().to_string();
    let policy = args(&["--appcontainer", name, "--ip", "private"]);
    let with = |command: &[&str], extra: &[&str]| -> Vec<String> {
        let mut list = args(command);
        list.extend_from_slice(&policy);
        list.extend(args(extra));
        list
    };
    let egress = ["--egress", port.as_str()];
    let as_admin = |list: Vec<String>| Command::new(&sandy).args(list).output().unwrap();
    let limited = |list: Vec<String>| {
        executable_with_restricted_token(&sandy, windows_sys::Win32::Security::LUA_TOKEN, &list)
    };
    let forward_setup = as_admin(with(&["setup"], &["--forward", "1=127.0.0.1:2"]));
    let refused = limited(with(&["check"], &egress));
    let mut run = with(&["run"], &egress);
    run.extend(args(&[
        "--",
        &probe_path(),
        "socks5-connect",
        "127.0.0.1:1",
    ]));
    let run = limited(run);
    let egress_setup = as_admin(with(&["setup"], &egress));
    let checked = limited(with(&["check"], &egress));
    let removed = as_admin(with(&["setup", "--remove"], &egress));
    let _ = fs::remove_dir_all(&directory);
    delete_profile(name);

    assert!(locked.status.success(), "{locked:?}");
    assert!(forward_setup.status.success(), "{forward_setup:?}");
    assert_eq!(refused.0 as i32, EXIT_NEEDS_SETUP, "{}", refused.1);
    assert!(refused.1.contains("sandy setup"), "{}", refused.1);
    assert_eq!(run.0 as i32, EXIT_FAILURE, "{}", run.1);
    assert!(egress_setup.status.success(), "{egress_setup:?}");
    assert_eq!(checked.0, 0, "{}", checked.1);
    assert!(removed.status.success(), "{removed:?}");
}

/// The broker runs with the internetClient capability and no loopback exemption, so Windows
/// Firewall and loopback isolation stop it from reaching this machine at the kernel level, even
/// if the destination check (`sandy_core::destination`) ever let such an address through. The
/// probe stands in for the broker, whose destination check cannot be bypassed from outside, in
/// an AppContainer with that same capability and no exemption: a connect to a loopback listener
/// and to this machine's own address on the network is blocked, while the control outside the
/// sandbox connects.
#[test]
fn the_broker_appcontainer_cannot_reach_this_machine() {
    let fixture = Fixture::new("broker-isolation");
    let loopback = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut targets = vec![loopback.local_addr().unwrap().to_string()];
    let lan = lan_address().map(|address| TcpListener::bind((address, 0)).unwrap());
    match &lan {
        Some(listener) => targets.push(listener.local_addr().unwrap().to_string()),
        None => skip(
            "network-address",
            "this machine has no route to other hosts",
        ),
    }
    let actions: Vec<(&str, &str)> = targets
        .iter()
        .map(|target| ("tcp-connect", target.as_str()))
        .collect();
    // Without the loopback exemption: internetClient alone is the broker of reach = "public";
    // ip = "all" holds privateNetworkClientServer as the broker of "public-and-local" does, and
    // internetClientServer, which adds only connections in.
    for ip in ["client", "all"] {
        let mut sandbox_args = fixture.access_args();
        sandbox_args.extend(args(&["--ip", ip, "--appcontainer", &appcontainer_name()]));
        for line in controlled(&sandbox_args, &actions) {
            line.assert_blocked();
        }
    }
}

/// The program cannot create a named pipe in the global namespace, only in the one of its
/// AppContainer (docs/windows.md, "Unix sockets"). The control creates the same pipe
/// outside.
#[test]
fn a_named_pipe_can_be_created_only_in_the_appcontainer_namespace() {
    let fixture = Fixture::new("pipe-create");
    let global = format!("sandy-test-pipe-{}", std::process::id());
    probe_outside(&[("pipe-create", &global)])[0].assert_ok();
    let local = format!(r"LOCAL\{global}");
    let lines = probe_inside(
        &fixture.access_args(),
        &[("pipe-create", &global), ("pipe-create", &local)],
    );
    lines[0].assert_blocked();
    assert!(lines[0].detail.contains("os error 5"), "{:?}", lines[0]);
    lines[1].assert_ok();
}

/// `check` warns in session 0, where services and SSH sessions run and no window station admits
/// an AppContainer, and only there.
#[test]
fn check_warns_in_session_0() {
    let session = probe_outside(&[("session-id", ".")]);
    session[0].assert_ok();
    let mut args = vec!["check".to_string()];
    args.extend(platform_args());
    let output = sandy(&args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        stderr.contains("sandy runs in session 0"),
        session[0].detail == "session=0",
        "{:?}: {stderr}",
        session[0]
    );
}
