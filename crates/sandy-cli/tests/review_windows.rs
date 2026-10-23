//! Regression tests for the Windows security review.
//!
//! Like `escape_windows.rs`, they run `sandy-probe` inside the sandbox and, for every denial,
//! check a control run outside it, so a test cannot pass because the action was impossible
//! anyway. The review-specific AppContainer names start with `sandy.review.` so these runs never
//! share a container with the escape tests.
#![cfg(windows)]

mod common;

use std::path::PathBuf;

use common::*;

/// Review AppContainer names. A dedicated name per test keeps the profiles separate and lets the
/// test delete its own profile at the end.
const C_PERSIST: &str = "sandy.review.persist";
const C_COM: &str = "sandy.review.com";
const C_SYSSET: &str = "sandy.review.sysset";

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The `Temp` folder inside the AppContainer profile of `container`, which Windows points the
/// program's `TEMP` and `TMP` at. It lives under the user's own LocalAppData.
fn profile_temp(container: &str) -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set");
    PathBuf::from(local)
        .join("Packages")
        .join(container)
        .join("AC")
        .join("Temp")
}

/// Removes an AppContainer profile and its folder, so a repeated run starts clean. Best effort.
fn delete_profile(container: &str) {
    use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
    let wide: Vec<u16> = container.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: the name is NUL-terminated.
    unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
}

/// The AppContainer profile folder (`...\Packages\<name>\AC`, which holds `TEMP`/`TMP`) is an
/// always-present, persistent, writable store that the user can read from outside the sandbox,
/// for every policy, even one with no writable path at all. Windows cannot remove it. sandy
/// applies the "writable never executable" rule there: the program can write and read the folder
/// but cannot execute what it writes.
///
/// The execute vector is `load-library` (maps the image with `LoadLibraryExW`, needing
/// `FILE_EXECUTE`), which runs in the program's own process and so does not depend on starting a
/// child process. `exec` would, and AppContainer child processes are blocked on some hosts (see
/// `escape.rs::executes_only_executable_paths` and docs/windows.md limitation 11), which would
/// hide the result. A `read` of the same planted file is the control: read still works, so the
/// denial is specific to execution, not a general loss of access.
#[test]
fn profile_folder_is_a_persistent_writable_but_not_executable_store() {
    delete_profile(C_PERSIST);
    let temp = profile_temp(C_PERSIST);
    let planted = temp.join("planted.exe").to_str().unwrap().to_string();
    let marker = temp.join("marker.txt").to_str().unwrap().to_string();

    // A minimal policy: only `--appcontainer`, so the program gets read+exec on itself and no
    // writable path at all. Control that confinement is real: a non-policy path stays unwritable.
    let fixture = Fixture::new("persist");
    let blocked = fixture.arg("secret/blocked.bin");

    let lines = probe_inside(
        &args(&["--appcontainer", C_PERSIST]),
        &[
            ("write", &blocked),        // non-policy path: blocked (confinement control)
            ("copy-self", &planted),    // profile folder: writable
            ("write", &marker),         // profile folder: writable
            ("load-library", &planted), // profile folder: NOT executable
            ("read", &planted),         // control: read of the same file still works
        ],
    );
    lines[0].assert_blocked();
    lines[1].assert_ok();
    lines[2].assert_ok();
    lines[3].assert_blocked();
    lines[4].assert_ok();

    // A process outside the sandbox (this test, running as the user) can read AND load the
    // planted file: the folder is a persistent store, the image is loadable, and only the
    // sandbox denies execution.
    let outside = probe_outside(&[("read", &planted), ("load-library", &planted)]);
    outside[0].assert_ok();
    outside[1].assert_ok();

    // A later, independent run with its own minimal policy still reads the planted files (the
    // folder persists) and still cannot execute them (sandy re-applies the rule every run).
    let lines = probe_inside(
        &args(&["--appcontainer", C_PERSIST]),
        &[
            ("read", &planted),
            ("read", &marker),
            ("load-library", &planted),
        ],
    );
    lines[0].assert_ok();
    lines[1].assert_ok();
    lines[2].assert_blocked();

    delete_profile(C_PERSIST);
}

/// Held: a sandboxed program cannot activate an out-of-process COM service (here BITS, a
/// `CLSCTX_LOCAL_SERVER` server in a svchost), so it cannot use COM to start or drive a process
/// outside the AppContainer and the job. Outside the sandbox the activation succeeds, so the
/// denial is real. The block is access-denied where COM loads, and a failure to load ole32 in the
/// service-session case; either way the service is unreachable.
#[test]
fn out_of_process_com_service_activation_is_blocked() {
    delete_profile(C_COM);
    let lines = controlled(
        &args(&["--appcontainer", C_COM]),
        &[("com-activate", "bits")],
    );
    lines[0].assert_blocked();
    delete_profile(C_COM);
}

/// Held: the system set (what Windows grants ALL APPLICATION PACKAGES) exposes no user profile
/// data on a default install. These directories list outside the sandbox but not inside it.
#[test]
fn system_set_exposes_no_user_profile_data() {
    delete_profile(C_SYSSET);
    let lines = controlled(
        &args(&["--appcontainer", C_SYSSET]),
        &[
            ("list", r"C:\Users"),
            ("list", r"C:\Users\Public"),
            ("list", r"C:\ProgramData"),
        ],
    );
    for line in &lines {
        line.assert_blocked();
    }
    delete_profile(C_SYSSET);
}
