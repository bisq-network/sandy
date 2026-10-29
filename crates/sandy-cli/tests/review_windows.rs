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
const C_RELINK: &str = "sandy.review.relink";
const C_PROCLIST: &str = "sandy.review.proclist";
const C_WTS: &str = "sandy.review.wts";
const C_PIDORACLE: &str = "sandy.review.pidoracle";
const C_SESSION: &str = "sandy.review.session";
const C_BROKERLIST: &str = "sandy.review.brokerlist";

/// The executable names a minimal sandbox run shows in its own process list: the always-present
/// pid 0 placeholder, the program, its console host, and (with `expose`/`forward`) the relays,
/// which run `sandy.exe` in the same AppContainer. Everything else is another AppContainer's or
/// the rest of the machine's, which the AppContainer token filters out (measured on build 26200).
const OWN_PROCESS_NAMES: &[&str] = &[
    "[system process]",
    "sandy-probe.exe",
    "conhost.exe",
    "sandy.exe",
];

/// Parses a `list-processes` detail (`toolhelp=N enumproc=M ntqsi=K self=PID names=a.exe,b.exe`)
/// into the three counts and the lowercased set of names.
fn parse_process_list(detail: &str) -> ([usize; 3], Vec<String>) {
    let value = |key: &str| -> &str {
        detail
            .split(' ')
            .find_map(|token| token.strip_prefix(key))
            .unwrap_or("")
    };
    let counts = [
        value("toolhelp=").parse().unwrap_or(0),
        value("enumproc=").parse().unwrap_or(0),
        value("ntqsi=").parse().unwrap_or(0),
    ];
    // The names field is last and may itself hold spaces (the placeholder), so take everything
    // after "names=".
    let names = detail
        .split_once("names=")
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split(',')
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect();
    (counts, names)
}

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

/// A profile folder entry that lost only `FILE_EXECUTE`: everything Windows grants there except
/// `FILE_EXECUTE`, so still `WRITE_DAC` and `WRITE_OWNER`.
const MASK_WITHOUT_EXECUTE: &str = "(OI)(CI)(R,W,D,WDAC,WO,DC)";

/// The program must not be able to put execute back on a file in its own profile folder. The
/// folder entry keeps the program out of `WRITE_DAC` and `WRITE_OWNER`, not only out of
/// `FILE_EXECUTE`: with either of those it could rewrite the file's own permissions and grant
/// `FILE_EXECUTE` to ALL APPLICATION PACKAGES, which it is a member of.
///
/// Two starting points. A profile sandy creates now, and one whose entry lost only
/// `FILE_EXECUTE`, which keeps `WRITE_DAC`: the second checks that the run repairs a partly
/// reduced entry instead of taking it for already reduced.
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

    // Put that entry back from outside the sandbox and check that the next run reduces it
    // again. Without that, a profile whose entry someone widened stays re-grantable.
    let restored = Command::new("icacls")
        .args([
            folder.to_str().unwrap(),
            "/grant:r",
            &format!("*{}:{MASK_WITHOUT_EXECUTE}", appcontainer_sid(C_REGRANT)),
        ])
        .output()
        .unwrap();
    assert!(restored.status.success(), "{restored:?}");
    attempt("entry without FILE_EXECUTE only");

    delete_profile(C_REGRANT);
}

/// The run that reduces a widened profile entry re-propagates it over the folder, which the
/// program could write, so it first refuses a junction there, as `grant` does for a policy path.
/// Once the entry is reduced nothing propagates, and the same junction refuses nothing.
#[test]
fn reducing_a_widened_profile_entry_refuses_a_junction_in_the_folder() {
    delete_profile(C_RELINK);
    let fixture = Fixture::new("relink");
    let temp = profile_temp(C_RELINK);
    let folder = temp.parent().unwrap().to_path_buf();
    let link = temp.join("link");
    let policy = args(&["--appcontainer", C_RELINK]);
    let run = || {
        let mut run = vec!["run".to_string()];
        run.extend_from_slice(&policy);
        run.extend(["--".into(), probe_path(), "env".into(), "SystemRoot".into()]);
        sandy(&run)
    };

    probe_inside(&policy, &[("env", "SystemRoot")])[0].assert_ok();
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(fixture.path("secret"))
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    // Control: the folder is reduced, so the junction alone refuses nothing.
    let reduced = run();

    let restored = Command::new("icacls")
        .args([
            folder.to_str().unwrap(),
            "/grant:r",
            &format!("*{}:{MASK_WITHOUT_EXECUTE}", appcontainer_sid(C_RELINK)),
        ])
        .output()
        .unwrap();
    let old = run();
    // The junction itself, not the directory it leads to.
    std::fs::remove_dir(&link).unwrap();
    delete_profile(C_RELINK);

    assert!(reduced.status.success(), "{reduced:?}");
    assert!(restored.status.success(), "{restored:?}");
    assert_eq!(old.status.code(), Some(EXIT_FAILURE), "{old:?}");
    let stderr = String::from_utf8_lossy(&old.stderr);
    assert!(stderr.contains("junction"), "{stderr}");
    assert!(stderr.contains(link.to_str().unwrap()), "{stderr}");
    // The folder is no policy path, and listing the target in the policy would not help.
    assert!(!stderr.contains("policy"), "{stderr}");
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
                "COM does not load in an AppContainer in this session (docs/windows.md \
                 limitation 13), so the denial would not be the COM boundary",
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

/// Recorded: a program in the sandbox sees only its own processes. Three enumerators that each
/// read the whole system process list outside the sandbox (a Toolhelp snapshot, `EnumProcesses`
/// and `NtQuerySystemInformation(SystemProcessInformation)`) return, inside the AppContainer,
/// only the pid 0 placeholder and the program's own AppContainer processes (itself and its
/// console host). The AppContainer (low box) token filters the system process list, so this is
/// a narrower view than docs/windows.md once claimed ("a Toolhelp snapshot still lists them").
/// The control outside the sandbox lists the whole machine, so the filtering is the sandbox and
/// not an empty machine.
#[test]
fn the_sandbox_process_list_holds_only_its_own_processes() {
    delete_profile(C_PROCLIST);

    let outside = probe_outside(&[("list-processes", ".")]);
    let (out_counts, out_names) = parse_process_list(&outside[0].detail);
    // The control lists the whole machine: many processes, and names that are not the sandbox's
    // own, so the comparison below is meaningful.
    for count in out_counts {
        assert!(
            count > 10,
            "control listed too few processes: {:?}",
            outside[0]
        );
    }
    assert!(
        out_names
            .iter()
            .any(|name| !OWN_PROCESS_NAMES.contains(&name.as_str())),
        "control listed only sandbox-own names: {:?}",
        outside[0]
    );

    let inside = probe_inside(
        &args(&["--appcontainer", C_PROCLIST]),
        &[("list-processes", ".")],
    );
    let (in_counts, in_names) = parse_process_list(&inside[0].detail);
    // All three enumerators agree, and every name is one of the program's own processes.
    assert_eq!(
        in_counts[0], in_counts[1],
        "toolhelp and enumproc disagree: {:?}",
        inside[0]
    );
    assert_eq!(
        in_counts[0], in_counts[2],
        "toolhelp and ntqsi disagree: {:?}",
        inside[0]
    );
    assert!(in_counts[0] >= 1, "empty process list: {:?}", inside[0]);
    assert!(
        in_counts[0] <= OWN_PROCESS_NAMES.len(),
        "the sandbox listed more processes than its own: {:?}",
        inside[0]
    );
    for name in &in_names {
        assert!(
            OWN_PROCESS_NAMES.contains(&name.as_str()),
            "the sandbox listed a process that is not its own ({name}): {:?}",
            inside[0]
        );
    }
    assert!(
        in_names.iter().any(|name| name == "sandy-probe.exe"),
        "the program does not see its own process: {:?}",
        inside[0]
    );

    delete_profile(C_PROCLIST);
}

/// Held: with `network.egress` the program's process list holds its egress relay, a `sandy.exe`
/// in its AppContainer, but not the broker, which runs in an AppContainer of its own and starts
/// before the program. Toolhelp shows at most the placeholder, the program, its console host and
/// the relay.
#[test]
fn the_egress_broker_is_not_in_the_programs_process_list() {
    delete_profile(C_BROKERLIST);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let inside = probe_inside(
        &args(&[
            "--appcontainer",
            C_BROKERLIST,
            "--ip",
            "private",
            "--egress",
            &port,
        ]),
        &[("list-processes", ".")],
    );
    let (counts, names) = parse_process_list(&inside[0].detail);
    assert!(
        names.iter().any(|name| name == "sandy.exe"),
        "the program does not see its egress relay: {:?}",
        inside[0]
    );
    assert!(
        counts[0] <= OWN_PROCESS_NAMES.len(),
        "the program sees more than its own processes, the broker among them: {:?}",
        inside[0]
    );
    delete_profile(C_BROKERLIST);
    delete_profile(&format!("{C_BROKERLIST}.sandy-egress"));
}

/// Recorded: `WTSEnumerateProcessesW`, a route to the process list that does not go through
/// Toolhelp or the NT process information class, is filtered the same way. Inside the sandbox it
/// returns only the program's own processes; the control outside returns the whole machine. So
/// it is not a way around the filtering of the other enumerators.
#[test]
fn wts_process_enumeration_is_also_filtered() {
    delete_profile(C_WTS);

    let outside = probe_outside(&[("wts-processes", ".")]);
    let out = outside[0]
        .detail
        .strip_prefix("wts=")
        .and_then(|n| n.parse::<usize>().ok());
    let out = out.unwrap_or_else(|| panic!("control WTS count unreadable: {:?}", outside[0]));
    assert!(
        out > 10,
        "control listed too few processes over WTS: {:?}",
        outside[0]
    );

    let inside = probe_inside(&args(&["--appcontainer", C_WTS]), &[("wts-processes", ".")]);
    // Measured on build 26200: WTS answers with the filtered list, as the other enumerators do
    // (docs/windows.md). A denial would be no bypass either, but a change of the record.
    inside[0].assert_ok();
    let count = inside[0]
        .detail
        .strip_prefix("wts=")
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("sandbox WTS count unreadable: {:?}", inside[0]));
    assert!(
        (1..=OWN_PROCESS_NAMES.len()).contains(&count),
        "WTS listed other than the program's own processes: {:?}",
        inside[0]
    );

    delete_profile(C_WTS);
}

/// Recorded: the filtered process list does not hide whether a given process id exists. The
/// program cannot open a process outside its AppContainer, but `OpenProcess` tells "exists but
/// denied" (ERROR_ACCESS_DENIED, 5) apart from "no such process" (ERROR_INVALID_PARAMETER, 87),
/// so by guessing ids a program still learns which ones are live. This is the process analogue
/// of the path existence oracle (see
/// `an_existing_path_outside_the_policy_is_told_apart_from_a_missing_one`); sandy cannot close
/// it, because the answer is the kernel's, so it is recorded here. The outside control, which
/// owns the process, opens it, so the denial inside is the AppContainer boundary.
#[test]
fn a_guessed_process_id_still_tells_existence_apart_from_absence() {
    delete_profile(C_PIDORACLE);
    let existing = std::process::id().to_string(); // this test's own process, outside the sandbox
    let missing = "999996"; // no such process (a multiple of four well above the live ids)

    let outside = probe_outside(&[("open-process-read", &existing)]);
    outside[0].assert_ok();

    let inside = probe_inside(
        &args(&["--appcontainer", C_PIDORACLE]),
        &[
            ("open-process-read", &existing),
            ("open-process-read", missing),
        ],
    );
    // An existing process outside the AppContainer: access denied, not "missing".
    assert_eq!(inside[0].result, "denied", "{:?}", inside[0]);
    assert!(inside[0].detail.contains("os error 5"), "{:?}", inside[0]);
    // A process id that does not exist: a different error, so the two are distinguishable.
    assert!(inside[1].detail.contains("os error 87"), "{:?}", inside[1]);

    delete_profile(C_PIDORACLE);
}

/// Recorded: the sandbox does not move the program into a session of its own, so
/// `ProcessIdToSessionId` tells the program the session it shares with sandy. This leaks the
/// session number, nothing about other processes; the inside and outside answers match because
/// both run in the same session.
#[test]
fn the_sandbox_runs_in_sandys_session() {
    delete_profile(C_SESSION);
    let outside = probe_outside(&[("session-id", ".")]);
    outside[0].assert_ok();
    let inside = probe_inside(
        &args(&["--appcontainer", C_SESSION]),
        &[("session-id", ".")],
    );
    inside[0].assert_ok();
    assert_eq!(
        inside[0].detail, outside[0].detail,
        "the sandbox is in a different session than the control: {:?} vs {:?}",
        inside[0], outside[0]
    );
    delete_profile(C_SESSION);
}
