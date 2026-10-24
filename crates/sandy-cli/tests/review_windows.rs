//! Regression tests for the Windows security review.
//!
//! Like `escape_windows.rs`, they run `sandy-probe` inside the sandbox and, for every denial,
//! check a control run outside it, so a test cannot pass because the action was impossible
//! anyway. The review-specific AppContainer names start with `sandy.review.` so these runs never
//! share a container with the escape tests.
#![cfg(windows)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::*;

/// Review AppContainer names. A dedicated name per test keeps the profiles separate and lets the
/// test delete its own profile at the end.
const C_PERSIST: &str = "sandy.review.persist";
const C_COM: &str = "sandy.review.com";
const C_SYSSET: &str = "sandy.review.sysset";
const C_REGRANT: &str = "sandy.review.regrant";

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
/// denial is specific to execution, not a general loss of access. That an image in a path with
/// execute rights does map inside an AppContainer, so that such a denial is not vacuous, is the
/// positive control of `escape_windows.rs::read_write_paths_are_not_executable`.
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

/// The entry sandy 1.3.2 left on the profile folder: everything Windows grants there except
/// `FILE_EXECUTE`, so still `WRITE_DAC` and `WRITE_OWNER`.
const MASK_1_3_2: &str = "(OI)(CI)(R,W,D,WDAC,WO,DC)";

/// The program must not be able to put execute back on a file in its own profile folder. The
/// folder entry keeps the program out of `WRITE_DAC` and `WRITE_OWNER`, not only out of
/// `FILE_EXECUTE`: with either of those it could rewrite the file's own permissions and grant
/// `FILE_EXECUTE` to ALL APPLICATION PACKAGES, which it is a member of.
///
/// Two starting points. A profile sandy creates now, and one reduced the way sandy 1.3.2 did,
/// which keeps `WRITE_DAC`: the second checks that the run repairs an entry an earlier version
/// left behind instead of taking it for already reduced.
#[test]
fn the_program_cannot_grant_itself_execute_in_its_profile_folder() {
    delete_profile(C_REGRANT);
    let temp = profile_temp(C_REGRANT);
    let folder = temp.parent().unwrap().to_path_buf();
    let planted = temp.join("planted.exe").to_str().unwrap().to_string();
    let policy = args(&["--appcontainer", C_REGRANT]);

    // The planted file is the control for the probes below: outside the sandbox the image maps,
    // so a denial inside is the sandbox and not a broken file.
    probe_inside(&policy, &[("copy-self", &planted)])[0].assert_ok();
    probe_outside(&[("load-library", &planted)])[0].assert_ok();

    let attempt = |label: &str| {
        let lines = probe_inside(
            &policy,
            &[
                ("write-dac", folder.to_str().unwrap()),
                ("write-dac", &planted),
                ("grant-all-packages", &planted),
                ("load-library", &planted),
            ],
        );
        for (index, what) in [
            "open the profile folder for WRITE_DAC",
            "open the planted file for WRITE_DAC",
            "grant ALL APPLICATION PACKAGES full access to the planted file",
            "load the planted file",
        ]
        .iter()
        .enumerate()
        {
            assert_ne!(
                lines[index].result, "ok",
                "{label}: the program could {what}: {:?}",
                lines[index]
            );
        }
    };
    attempt("fresh profile");

    // Put the 1.3.2 entry back from outside the sandbox and check that the next run reduces it
    // again. Without that, every profile an earlier version created stays re-grantable.
    let restored = Command::new("icacls")
        .args([
            folder.to_str().unwrap(),
            "/grant:r",
            &format!("*{}:{MASK_1_3_2}", appcontainer_sid(C_REGRANT)),
        ])
        .output()
        .unwrap();
    assert!(restored.status.success(), "{restored:?}");
    attempt("profile reduced by 1.3.2");

    delete_profile(C_REGRANT);
}

/// Held: a sandboxed program cannot reach a COM service that runs outside the AppContainer, so
/// it cannot use COM to start or drive a process outside the job. Two services: BITS, activated
/// out of process, and the Schedule service, reached through `ITaskService::Connect` after the
/// in-process class is loaded. Outside the sandbox both answer, so the denial is real.
///
/// The denial must be `E_ACCESSDENIED`. A failure to load `ole32.dll` is not a denial by the
/// COM boundary: in a session without an interactive window station, user32 fails to
/// initialize in an AppContainer (limitation 13) and COM never gets to ask. The check is
/// skipped there instead of counted as a pass.
#[test]
fn com_services_outside_the_sandbox_are_unreachable() {
    const E_ACCESSDENIED: &str = "0x80070005";

    delete_profile(C_COM);
    for service in ["bits", "task-scheduler"] {
        let outside = Command::new(probe_path())
            .args([&"com-activate".to_string(), &service.to_string()])
            .output()
            .unwrap();
        let outside = &parse(&outside)[0];
        if outside.result != "ok" {
            skip(
                "com-outside",
                &format!(
                    "this session cannot reach {service} outside the sandbox either                      ({}), so a denial inside shows nothing",
                    outside.detail
                ),
            );
            continue;
        }
        let inside = probe_inside(
            &args(&["--appcontainer", C_COM]),
            &[("com-activate", service)],
        );
        if inside[0].detail.contains("ole32") {
            skip(
                "com-in-appcontainer",
                "COM does not load in an AppContainer in this session (docs/windows.md                  limitation 13), so the denial would not be the COM boundary",
            );
            continue;
        }
        assert_eq!(inside[0].result, "denied", "{service}: {:?}", inside[0]);
        assert!(
            inside[0].detail.contains(E_ACCESSDENIED),
            "{service}: expected {E_ACCESSDENIED}: {:?}",
            inside[0]
        );
    }
    delete_profile(C_COM);
}

/// `children = "none"` promises that the program makes no process appear outside its job. The
/// COM part of that promise rests on no COM server being reachable: DcomLaunch starts a server
/// whose launch permission admits ALL APPLICATION PACKAGES, and that process is outside the
/// job, which no policy key closes. The test counts such servers. On a default Windows 11 there
/// is none; a host where this fails has a server whose activation from inside the sandbox must
/// be measured before `children = "none"` can be trusted there.
#[test]
fn no_dcom_server_admits_all_application_packages() {
    let script = r#"
$hits = @()
Get-ChildItem 'HKLM:\SOFTWARE\Classes\AppID' -ErrorAction SilentlyContinue | ForEach-Object {
  $key = $_
  $permission = (Get-ItemProperty $key.PSPath -Name LaunchPermission -ErrorAction SilentlyContinue).LaunchPermission
  if ($permission) {
    try {
      $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor(,[byte[]]$permission)
      foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.SecurityIdentifier.Value -eq 'S-1-15-2-1' -and "$($ace.AceType)" -eq 'AccessAllowed') {
          $hits += $key.PSChildName
        }
      }
    } catch {}
  }
}
"count=$($hits.Count) " + (($hits | Select-Object -First 8) -join ' ')
"#;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        report.starts_with("count=0"),
        "DCOM servers that every AppContainer may launch: {report}"
    );
}

/// Recorded: the sandbox denies access, it does not hide paths. An existing file outside the
/// policy answers "access denied" and a name that does not exist answers "not found", so the
/// program can tell whether a path exists. DESIGN.md names hiding paths a non-goal; the test
/// pins the oracle so a change in it is noticed.
#[test]
fn an_existing_path_outside_the_policy_is_told_apart_from_a_missing_one() {
    let fixture = Fixture::new("visibility");
    let lines = probe_inside(
        &fixture.access_args(),
        &[
            ("read", &fixture.arg("secret/file")),
            ("read", &fixture.arg("secret/missing")),
            ("list", &fixture.arg("secret")),
            ("list", &fixture.arg("nosuchdirectory")),
        ],
    );
    // An existing file and an existing directory: ERROR_ACCESS_DENIED.
    assert_eq!(lines[0].result, "denied", "{:?}", lines[0]);
    assert_eq!(lines[2].result, "denied", "{:?}", lines[2]);
    // A name that does not exist: ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND.
    assert!(lines[1].detail.contains("os error 2"), "{:?}", lines[1]);
    assert!(lines[3].detail.contains("os error 3"), "{:?}", lines[3]);
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
