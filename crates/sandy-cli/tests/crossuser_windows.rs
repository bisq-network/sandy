//! Cross-user AppContainer sharing (docs/windows.md, "Other users of the machine").
//!
//! An AppContainer SID, its loopback exemption and its file/socket capability SIDs are derived
//! from the AppContainer name alone, so a process another user runs in an AppContainer of the
//! same name gets the same SID and capabilities. Windows still keeps that user out: loopback
//! isolation is per Terminal Services session, and the AppContainer access check also tests the
//! user's own access to a file or socket.
//!
//! With `SANDY_TEST_OTHER_USER` (and `SANDY_TEST_OTHER_PASSWORD`, only to confirm the account is
//! meant for the test) set to a second local standard account, this starts a victim run with
//! `ip = "private"`, a loopback listener, a `forward` relay and `egress`, and file grants, then
//! runs that account in an AppContainer of the same name through an S4U scheduled task (no
//! password) and checks what it reaches:
//!
//! - network (the private loopback listener, the `forward` relay, the `egress` port): the second
//!   user runs in a session of its own, so loopback isolation drops it and the connect times out.
//!   This is asserted only when the second user's session differs from the program's; the reach
//!   within one session (for example session-0 services) is the residual gap, recorded in the
//!   docs.
//! - a file under the first user's profile, and the `forward` AF_UNIX socket, with the derived
//!   capability in the token: denied, because Windows checks the user too. These are denials.
//!
//! Without `SANDY_TEST_OTHER_USER` it skips, so the normal suite needs no second account. It is
//! Windows-only, so other runners record no skip. Registering the S4U task needs `SeTcbPrivilege`,
//! which only `SYSTEM` holds, so the test drives it through a `SYSTEM` task; if that cannot run
//! (no administrator rights) or the account cannot be logged on, the test skips rather than fails.
#![cfg(windows)]

mod common;

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::*;

/// Field separator inside a `sandy-probe appcontainer-run` target.
const US: char = '\u{1f}';
/// AppContainer the victim uses; the second user names the same one.
const NAME: &str = "sandy.crossuser";
/// A different AppContainer name for the file and socket checks: the capability is injected, so
/// the name does not matter, and a different one shows the reach is the capability, not the name.
const OTHER: &str = "sandy.crossuser-ctl";

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn session_of_self() -> u32 {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let mut session = 0u32;
    // SAFETY: the current process id is valid and session is a valid out pointer.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    session
}

#[test]
fn another_user_cannot_reach_the_program_across_sessions() {
    let Some(user) = env("SANDY_TEST_OTHER_USER") else {
        skip(
            "cross-user",
            "set SANDY_TEST_OTHER_USER (and SANDY_TEST_OTHER_PASSWORD) to a second local account \
             to measure cross-user AppContainer sharing",
        );
        return;
    };

    let shared = match shared_dir() {
        Ok(shared) => shared,
        Err(reason) => {
            skip("cross-user-shared-dir", &reason);
            return;
        }
    };
    let local = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA");
    let profile_dir = Path::new(&local).join("sandy-crossuser-secret");
    let profile_file = profile_dir.join("granted.txt");
    let shared_file = shared.join("granted-shared.txt");
    let _ = fs::create_dir_all(&profile_dir);
    let _ = fs::write(&profile_file, b"SECRET-PROFILE");
    let _ = fs::write(&shared_file, b"SECRET-SHARED");

    let lport = free_port();
    let fport = free_port();
    let eport = free_port();
    let (backend, backend_hits) = backend_service();

    let mut victim = Command::new(sandy_path())
        .args([
            "run",
            "--appcontainer",
            NAME,
            "--ip",
            "private",
            "--forward",
            &format!("{fport}={backend}"),
            "--egress",
            &format!("{eport}=public"),
            "--read",
            shared_file.to_str().unwrap(),
            "--read-write",
            profile_dir.to_str().unwrap(),
            &probe_path(),
            "tcp-serve",
            &format!("127.0.0.1:{lport}{US}20"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the victim run");
    // The relays need a moment to listen; the program prints nothing, so wait and confirm it runs.
    thread::sleep(Duration::from_secs(5));
    assert!(
        victim.try_wait().unwrap().is_none(),
        "the victim run exited before the attacker connected"
    );

    // Positive control: a process of the first user in the program's own session reaches the
    // listener over loopback.
    let positive = probe_appcontainer(NAME, "", "tcp-connect", &format!("127.0.0.1:{lport}"));

    // The capabilities the program's run put on the objects, to inject into the second user's
    // token, and the forward socket it created.
    let cap_profile = capability_sid(&profile_file).unwrap_or_default();
    let cap_relay = find_forward_socket(fport)
        .and_then(|socket| capability_sid(&socket).map(|cap| (socket, cap)));

    // The attacker, run as the second user in an AppContainer of the same name, through S4U.
    let mut attacker = Attacker::new(&shared, &user);
    attacker.action(NAME, "", "session-id", "x", "session");
    attacker.action(
        NAME,
        "",
        "tcp-connect",
        &format!("127.0.0.1:{lport}"),
        "loopback",
    );
    attacker.action(
        NAME,
        "",
        "tcp-connect",
        &format!("127.0.0.1:{fport}"),
        "forward",
    );
    attacker.action(
        NAME,
        "",
        "tcp-connect",
        &format!("127.0.0.1:{eport}"),
        "egress",
    );
    attacker.action(
        OTHER,
        &cap_profile,
        "read",
        profile_file.to_str().unwrap(),
        "profile",
    );
    if let Some((socket, cap)) = &cap_relay {
        attacker.action(
            OTHER,
            cap,
            "afunix-connect",
            socket.to_str().unwrap(),
            "socket",
        );
    }
    let outcome = attacker.run();

    // Tidy up before asserting.
    kill_process(victim.id());
    let _ = victim.wait();
    delete_profiles(&[NAME, OTHER]);
    attacker.cleanup();
    let _ = fs::remove_dir_all(&profile_dir);
    let _ = fs::remove_dir_all(&shared);
    drop(backend_hits);

    let results = match outcome {
        Ok(results) => results,
        Err(reason) => {
            skip("cross-user-other-user", &reason);
            return;
        }
    };
    let result = |label: &str| -> ProbeLine {
        parse_line(results.get(label).map(String::as_str).unwrap_or_default())
    };

    assert_eq!(
        positive.result, "ok",
        "the first user did not reach its own listener in its own session: {}",
        positive.detail
    );

    // Files and the forward socket stay closed to the second user even with the capability.
    let profile = result("profile");
    assert_eq!(
        profile.result, "denied",
        "the second user opened a file under the first user's profile with the derived \
         capability: {profile:?}"
    );
    if cap_relay.is_some() {
        let socket = result("socket");
        assert_eq!(
            socket.result, "denied",
            "the second user connected to the forward socket with the derived capability: \
             {socket:?}"
        );
    }

    // Network reach is scoped to the session. Assert the block only when the second user really
    // ran in another session; record the same-session case rather than fail.
    let session = result("session");
    let other_session: u32 = session
        .detail
        .strip_prefix("session=")
        .and_then(|value| value.parse().ok())
        .unwrap_or(u32::MAX);
    if other_session != session_of_self() {
        for label in ["loopback", "forward", "egress"] {
            let line = result(label);
            assert_ne!(
                line.result, "ok",
                "the second user reached the program's {label} from another session ({}): \
                 {line:?}",
                session.detail
            );
        }
    } else {
        eprintln!(
            "note: the second user ran in the program's own session ({}); its same-named \
             AppContainer reaches the loopback routes there (the residual same-session gap)",
            session.detail
        );
    }
}

/// A loopback service that the forward relay connects to, kept alive by the returned handle.
fn backend_service() -> (String, std::sync::mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut held = Vec::new();
        loop {
            if stop_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    });
    (address, stop_tx)
}

/// Runs `sandy-probe appcontainer-run` directly (as this user, in this session) and returns the
/// child probe's result line.
fn probe_appcontainer(name: &str, caps: &str, action: &str, target: &str) -> ProbeLine {
    let arg = format!("{name}{US}{caps}{US}{action}{US}{target}");
    let output = Command::new(probe_path())
        .args(["appcontainer-run", &arg])
        .output()
        .expect("run sandy-probe");
    let text = String::from_utf8_lossy(&output.stdout);
    parse_line(text.lines().find(|line| line.contains('\t')).unwrap_or(""))
}

/// Builds and runs the second user's attacker actions in one S4U scheduled task.
struct Attacker {
    shared: PathBuf,
    user: String,
    script: String,
    labels: Vec<String>,
}

impl Attacker {
    fn new(shared: &Path, user: &str) -> Attacker {
        Attacker {
            shared: shared.to_path_buf(),
            user: user.to_string(),
            script: String::from("@echo off\r\n"),
            labels: Vec::new(),
        }
    }

    fn action(&mut self, name: &str, caps: &str, action: &str, target: &str, label: &str) {
        let arg = format!("{name}{US}{caps}{US}{action}{US}{target}");
        let out = self.shared.join(format!("{label}.out"));
        self.script.push_str(&format!(
            "\"{}\" appcontainer-run \"{arg}\" > \"{}\" 2>&1\r\n",
            probe_path(),
            out.display()
        ));
        self.labels.push(label.to_string());
    }

    /// Writes the attacker cmd, a COM script that registers and runs it as the user through S4U,
    /// and a SYSTEM task that runs the COM script (S4U registration needs SeTcbPrivilege). Returns
    /// each action's result line by label, or an error to skip on.
    fn run(&self) -> Result<std::collections::HashMap<String, String>, String> {
        let atk = self.shared.join("attacker.cmd");
        let done = self.shared.join("done.txt");
        let mut script = self.script.clone();
        script.push_str(&format!("echo done > \"{}\"\r\n", done.display()));
        fs::write(&atk, script).map_err(|e| format!("cannot write attacker.cmd: {e}"))?;

        let com = self.shared.join("register.ps1");
        fs::write(
            &com,
            format!(
                "$svc=New-Object -ComObject Schedule.Service; $svc.Connect(); $f=$svc.GetFolder('\\')\n\
                 $td=$svc.NewTask(0); $a=$td.Actions.Create(0); $a.Path='{atk}'\n\
                 $td.Settings.Enabled=$true; $td.Settings.ExecutionTimeLimit='PT3M'\n\
                 try {{ $f.RegisterTaskDefinition('sandy_xuser',$td,6,'{user}',$null,3,$null)|Out-Null }} catch {{ 'REGERR: '+$_.Exception.Message; exit 1 }}\n\
                 $t=$f.GetTask('sandy_xuser'); $t.Run($null)|Out-Null\n\
                 for($i=0;$i -lt 180;$i++){{ Start-Sleep -Milliseconds 500; if($t.State -ne 4){{break}} }}\n\
                 try{{$f.DeleteTask('sandy_xuser',0)}}catch{{}}\n",
                atk = atk.display(),
                user = self.user
            ),
        )
        .map_err(|e| format!("cannot write register.ps1: {e}"))?;

        let _ = fs::remove_file(&done);
        let create = schtasks(&[
            "/Create",
            "/TN",
            "sandy_xuser_sys",
            "/SC",
            "ONCE",
            "/ST",
            "23:59",
            "/RU",
            "SYSTEM",
            "/TR",
            &format!(
                "powershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                com.display()
            ),
            "/F",
        ]);
        if !create.status.success() {
            return Err(format!(
                "cannot register the SYSTEM task (administrator rights needed): {}",
                String::from_utf8_lossy(&create.stdout).trim()
            ));
        }
        let run = schtasks(&["/Run", "/TN", "sandy_xuser_sys"]);
        if !run.status.success() {
            let _ = schtasks(&["/Delete", "/TN", "sandy_xuser_sys", "/F"]);
            return Err(format!(
                "cannot run the SYSTEM task: {}",
                String::from_utf8_lossy(&run.stdout).trim()
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        while !done.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(500));
        }
        let _ = schtasks(&["/Delete", "/TN", "sandy_xuser_sys", "/F"]);
        if !done.exists() {
            return Err(format!(
                "the task as {:?} produced no result (S4U logon may be refused)",
                self.user
            ));
        }
        let mut results = std::collections::HashMap::new();
        for label in &self.labels {
            let text =
                fs::read_to_string(self.shared.join(format!("{label}.out"))).unwrap_or_default();
            let line = text
                .lines()
                .find(|line| line.contains('\t'))
                .unwrap_or("")
                .to_string();
            results.insert(label.clone(), line);
        }
        Ok(results)
    }

    /// Removes the second user's AppContainer profiles, created by its S4U runs, as that user.
    fn cleanup(&self) {
        let com = self.shared.join("cleanup.ps1");
        let names = [
            NAME.to_string(),
            OTHER.to_string(),
            format!("{NAME}.sandy-egress"),
        ];
        let deletes: String = names
            .iter()
            .map(|n| format!("[W.U]::DeleteAppContainerProfile('{n}')|Out-Null; "))
            .collect();
        if fs::write(
            &com,
            format!(
                "$svc=New-Object -ComObject Schedule.Service; $svc.Connect(); $f=$svc.GetFolder('\\')\n\
                 $td=$svc.NewTask(0); $a=$td.Actions.Create(0)\n\
                 $a.Path='powershell'; $a.Arguments='-NoProfile -Command \"Add-Type -Namespace W -Name U -MemberDefinition ''[DllImport(\\\"userenv.dll\\\",CharSet=CharSet.Unicode)] public static extern int DeleteAppContainerProfile(string n);''; {deletes}\"'\n\
                 $td.Settings.Enabled=$true\n\
                 try {{ $f.RegisterTaskDefinition('sandy_xuser_cl',$td,6,'{user}',$null,3,$null)|Out-Null; $f.GetTask('sandy_xuser_cl').Run($null)|Out-Null; Start-Sleep 3; $f.DeleteTask('sandy_xuser_cl',0) }} catch {{}}\n",
                user = self.user
            ),
        )
        .is_ok()
        {
            let created = schtasks(&[
                "/Create", "/TN", "sandy_xuser_cl_sys", "/SC", "ONCE", "/ST", "23:59", "/RU",
                "SYSTEM", "/TR",
                &format!("powershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"", com.display()),
                "/F",
            ]);
            if created.status.success() {
                let _ = schtasks(&["/Run", "/TN", "sandy_xuser_cl_sys"]);
                thread::sleep(Duration::from_secs(4));
                let _ = schtasks(&["/Delete", "/TN", "sandy_xuser_cl_sys", "/F"]);
            }
        }
    }
}

fn schtasks(args: &[&str]) -> std::process::Output {
    Command::new("schtasks")
        .args(args)
        .output()
        .expect("run schtasks")
}

/// The capability SID (`S-1-15-3-1024-...`) in the DACL of `path`, read with `icacls`.
fn capability_sid(path: &Path) -> Option<String> {
    let output = Command::new("icacls").arg(path).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.split(|c: char| c.is_whitespace() || c == ':')
        .find(|token| token.starts_with("S-1-15-3-1024-"))
        .map(|token| token.to_string())
}

/// The `forward` AF_UNIX socket named after `port` below `%LOCALAPPDATA%\sandy\forward`.
fn find_forward_socket(port: u16) -> Option<PathBuf> {
    let base = Path::new(&std::env::var("LOCALAPPDATA").ok()?)
        .join("sandy")
        .join("forward");
    for run in fs::read_dir(&base).ok()?.flatten() {
        let candidate = run.path().join(port.to_string());
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// A world-writable directory the second user's logon can read and write.
fn shared_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("sandy-xuser-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let granted = Command::new("icacls")
        .args([dir.to_str().unwrap(), "/grant", "*S-1-5-32-545:(OI)(CI)M"])
        .output()
        .map_err(|e| format!("cannot run icacls: {e}"))?;
    if !granted.status.success() {
        return Err(format!("cannot share {}", dir.display()));
    }
    Ok(dir)
}

/// Deletes the current user's AppContainer profiles for `names` and their egress brokers.
fn delete_profiles(names: &[&str]) {
    use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
    for name in names {
        for profile in [name.to_string(), format!("{name}.sandy-egress")] {
            let wide: Vec<u16> = profile.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: the name is NUL-terminated; the call does nothing when no profile exists.
            unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
        }
    }
}
