//! `filesystem.view = "policy"` on Linux: the program runs in a mount namespace that holds only
//! the policy paths, the system set and the links on the way to them (docs/linux.md, "File system
//! view"). Every check has a control: the same action with `view = "all"`, where the path exists.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::unix::{open_pty, with_terminal};
use common::*;

/// What `check` exits with when only `sandy setup` is missing.
const EXIT_NEEDS_SETUP: i32 = 2;

/// The plan line of the requirement.
const VIEW_LINE: &str = "paths outside the policy hidden";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn with_view(mut sandbox_args: Vec<String>) -> Vec<String> {
    sandbox_args.extend(args(&["--view", "policy"]));
    sandbox_args
}

fn has_errno(line: &ProbeLine, errno: i32) -> bool {
    line.result != "ok" && line.detail.contains(&format!("os error {errno})"))
}

/// Whether this host gives sandy the view, as `check` says; records a skip when not. Ubuntu 23.10
/// and newer refuse the user namespace to an unconfined sandy until `sandy setup` installs a
/// profile.
fn view_works() -> bool {
    let output = sandy(["check", "--view", "policy"]);
    if output.status.success() {
        return true;
    }
    skip(
        "user-namespaces",
        &format!(
            "this host gives sandy no user and mount namespace: {}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| line.contains(VIEW_LINE))
                .unwrap_or("check failed")
        ),
    );
    false
}

/// Every call that names a path outside the policy answers as for a path that does not exist:
/// `stat`, `access`, `readlink`, `open` and an inotify watch. Without the view the paths exist,
/// and only the open is denied.
#[test]
fn hidden_paths_look_missing() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-hidden");
    symlink("file", fixture.path("secret/link")).unwrap();
    let (secret, file, link) = (
        fixture.arg("secret"),
        fixture.arg("secret/file"),
        fixture.arg("secret/link"),
    );
    let actions = [
        ("lstat", file.as_str()),
        ("access-path", file.as_str()),
        ("readlink", link.as_str()),
        ("open", file.as_str()),
        ("inotify-watch", secret.as_str()),
        ("lstat", "/etc/passwd"),
    ];
    let all = probe_inside(&fixture.access_args(), &actions);
    for (index, line) in all.iter().enumerate() {
        match line.action.as_str() {
            "open" => line.assert_blocked(),
            _ if index == 5 && !std::path::Path::new("/etc/passwd").exists() => {}
            _ => line.assert_ok(),
        }
    }
    assert!(has_errno(&all[3], libc::EACCES), "{all:?}");
    for line in probe_inside(&with_view(fixture.access_args()), &actions) {
        assert!(has_errno(&line, libc::ENOENT), "{line:?}");
    }
}

/// docs/linux.md, "Metadata through open files": without the view a descriptor opened for
/// reading still changes the mode and the times of a file or a directory of a `read` or
/// `read_exec` path. In the view these paths are read-only mounts, where the same calls fail
/// with EROFS, so the exception does not apply there.
#[test]
fn a_read_only_descriptor_changes_no_metadata_in_the_view() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-fdmeta");
    let (file, directory, program) = (
        fixture.arg("ro/file"),
        fixture.arg("ro"),
        fixture.copy_probe("bin"),
    );
    let actions = [
        ("fchmod-ro", file.as_str()),
        ("utime-ro", file.as_str()),
        ("fchmod-ro", directory.as_str()),
        ("utime-ro", directory.as_str()),
        ("fchmod-ro", program.as_str()),
        ("utime-ro", program.as_str()),
    ];
    for line in probe_inside(&fixture.access_args(), &actions) {
        line.assert_ok();
    }
    for line in probe_inside(&with_view(fixture.access_args()), &actions) {
        assert!(has_errno(&line, libc::EROFS), "{line:?}");
    }
}

/// Executing is a right of its own: every path the policy does not make executable is mounted
/// without execute, so a file of a `read` or a writable path cannot be mapped as code, while a
/// file of a `read_exec` path can. Without the view all three map.
#[test]
fn code_maps_only_from_executable_paths() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-mmap");
    let program = fixture.copy_probe("bin");
    let (readable, writable) = (fixture.arg("ro/file"), fixture.arg("rw/file"));
    let actions = [
        ("mmap-exec", readable.as_str()),
        ("mmap-exec", writable.as_str()),
        ("mmap-exec", program.as_str()),
    ];
    for line in probe_inside(&fixture.access_args(), &actions) {
        line.assert_ok();
    }
    let view = probe_inside(&with_view(fixture.access_args()), &actions);
    assert!(has_errno(&view[0], libc::EPERM), "{view:?}");
    assert!(has_errno(&view[1], libc::EPERM), "{view:?}");
    view[2].assert_ok();
}

/// A dynamically linked program finds its loader and libraries in the system set, and a Python
/// script its interpreter, which `#!/usr/bin/python3` names through a link that the view
/// recreates, and the standard library.
#[test]
fn dynamic_programs_run_with_the_system_set() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-dynamic");
    let listing = sandy(
        [
            "run",
            "--view",
            "policy",
            "--read",
            &fixture.arg("ro"),
            "--",
            "/usr/bin/ls",
            &fixture.arg("ro"),
        ]
        .map(String::from),
    );
    assert!(listing.status.success(), "{listing:?}");
    assert_eq!(String::from_utf8_lossy(&listing.stdout), "file\n");

    let Ok(python) = fs::canonicalize("/usr/bin/python3") else {
        return skip("python3", "this host has no /usr/bin/python3");
    };
    let script = fixture.path("bin/list.py");
    fs::write(
        &script,
        format!(
            "#!/usr/bin/python3\nimport json, os\nprint(json.dumps(os.listdir({:?})))\n",
            fixture.arg("ro")
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let mut run = with_view(fixture.access_args());
    run.splice(
        0..0,
        args(&["run", "--read-exec", python.to_str().unwrap()]),
    );
    run.extend(args(&["--", script.to_str().unwrap()]));
    let output = sandy(&run);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "[\"file\"]\n");
}

/// On a merged `/usr`, `/lib64` and `/bin` are links into `/usr`. The view recreates the links
/// that the system set and the policy paths are named through, with the same text, so the
/// loader of a program and a path written as `/bin/true` resolve as on the host.
#[test]
fn the_links_of_a_merged_usr_work() {
    if !view_works() {
        return;
    }
    let outside = probe_outside(&[("readlink", "/lib64"), ("readlink", "/bin")]);
    if outside.iter().any(|line| line.result != "ok") {
        return skip(
            "merged-usr",
            &format!("/lib64 or /bin is no symbolic link here: {outside:?}"),
        );
    }
    let actions = [
        ("readlink", "/lib64"),
        ("readlink", "/bin"),
        ("exec", "/bin/true"),
    ];
    let view = probe_inside(
        &args(&["--view", "policy", "--read-exec", "/bin/true"]),
        &actions,
    );
    assert_eq!(view[0].detail, outside[0].detail, "{view:?}");
    assert_eq!(view[1].detail, outside[1].detail, "{view:?}");
    assert_eq!(view[2].detail, "exit exit status: 0", "{view:?}");
    // Without a policy path named through /bin, the view has no /bin.
    let without = probe_inside(&args(&["--view", "policy"]), &[("readlink", "/bin")]);
    assert!(has_errno(&without[0], libc::ENOENT), "{without:?}");
}

/// `/dev` of the view holds null, zero, full, random and urandom; the system set grants all but
/// full, and only null is writable. A device of the host outside that list does not exist, and
/// without a terminal neither does `/dev/tty`.
#[test]
fn dev_holds_the_minimal_devices() {
    if !view_works() {
        return;
    }
    let actions = [
        ("lstat", "/dev/null"),
        ("lstat", "/dev/zero"),
        ("lstat", "/dev/full"),
        ("lstat", "/dev/random"),
        ("lstat", "/dev/urandom"),
        ("write", "/dev/null"),
        ("open", "/dev/zero"),
        ("open", "/dev/random"),
        ("open", "/dev/urandom"),
        ("lstat", "/dev/kmsg"),
        ("lstat", "/dev/tty"),
    ];
    let outside = probe_outside(&actions);
    let view = probe_inside(&args(&["--view", "policy"]), &actions);
    for line in &view[..9] {
        line.assert_ok();
    }
    if outside[9].result == "ok" {
        assert!(has_errno(&view[9], libc::ENOENT), "{view:?}");
    }
    assert!(has_errno(&view[10], libc::ENOENT), "{view:?}");
}

/// With a terminal on a standard stream the view adds `/dev/tty` and a private devpts instance
/// with its `ptmx`, and the terminal the program got keeps working.
#[test]
fn a_terminal_works_when_one_is_attached() {
    if !view_works() {
        return;
    }
    let Some(pty) = open_pty() else {
        return skip("pty", "cannot open a pseudo-terminal");
    };
    let actions = [
        ("lstat", "/dev/tty"),
        ("lstat", "/dev/pts/ptmx"),
        ("readlink", "/dev/ptmx"),
        ("tiocgwinsz", "0"),
        ("open", "/dev/tty"),
    ];
    let mut command = Command::new(sandy_path());
    command.args(run_args(
        &args(&["--view", "policy", "--read-write", "/dev/tty"]),
        &actions,
    ));
    with_terminal(&pty)(&mut command);
    let output = command.stderr(Stdio::piped()).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    for line in &lines {
        line.assert_ok();
    }
    assert_eq!(lines[2].detail, "pts/ptmx", "{lines:?}");
}

/// `ip = "client"` keeps the resolver configuration of the system set: `/etc/resolv.conf` is
/// recreated as the link it is on the host, and names resolve inside as outside.
#[test]
fn names_resolve_under_client() {
    if !view_works() {
        return;
    }
    let actions = [
        ("readlink", "/etc/resolv.conf"),
        ("read", "/etc/resolv.conf"),
        ("resolve", "localhost:80"),
    ];
    let outside = probe_outside(&[("read", "/etc/resolv.conf"), ("resolve", "localhost:80")]);
    let view = probe_inside(&args(&["--view", "policy", "--ip", "client"]), &actions);
    match fs::read_link("/etc/resolv.conf") {
        Ok(target) => assert_eq!(view[0].detail, target.display().to_string(), "{view:?}"),
        Err(_) => assert!(view[0].result != "ok", "{view:?}"),
    }
    assert_eq!(view[1].detail, outside[0].detail, "{view:?}");
    assert_eq!(view[2].detail, outside[1].detail, "{view:?}");
}

/// The view with the other ways a run starts: `children = "contained"` (a forked child builds
/// the view), `--explain` (likewise, with sandy outside reading paths of the host) and
/// `end_with_parent`. Each needs what it needs without the view, signal isolation for two of them.
#[test]
fn the_view_works_with_the_process_modes() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-modes");
    let mut modes = vec![args(&["--explain"])];
    for mode in [
        args(&["--children", "contained", "--signals", "isolated"]),
        args(&["--end-with-parent", "--signals", "isolated"]),
    ] {
        let mut check = vec!["check".to_string()];
        check.extend(mode.iter().cloned());
        if sandy(&check).status.success() {
            modes.push(mode);
        } else {
            skip(
                "signal-isolation",
                &format!("this host cannot enforce {mode:?} even without the view"),
            );
        }
    }
    let file = fixture.arg("ro/file");
    let secret = fixture.arg("secret/file");
    let actions = [("read", file.as_str()), ("lstat", secret.as_str())];
    for mode in modes {
        let mut sandbox_args = with_view(fixture.access_args());
        sandbox_args.extend(mode.iter().cloned());
        let lines = probe_inside(&sandbox_args, &actions);
        lines[0].assert_ok();
        assert!(has_errno(&lines[1], libc::ENOENT), "{mode:?}: {lines:?}");
    }
}

/// The view together with `ip = "private"`: an exposed port reaches the program and a forwarded
/// port reaches a service outside, as without the view.
#[test]
fn the_view_works_with_a_private_network() {
    if !view_works() {
        return;
    }
    let private = sandy(["check", "--ip", "private", "--view", "policy"]);
    if !private.status.success() {
        return skip(
            "user-namespaces",
            "this host gives sandy no private network",
        );
    }
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_address = service.local_addr().unwrap();
    thread::spawn(move || {
        for mut stream in service.incoming().flatten() {
            let _ = std::io::Write::write_all(&mut stream, b"hi");
        }
    });
    let free = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (forward, inner, outer) = (free(), free(), free());
    let sandbox_args = args(&[
        "--view",
        "policy",
        "--ip",
        "private",
        "--forward",
        &format!("{forward}={service_address}"),
        "--expose",
        &format!("127.0.0.1:{outer}={inner}"),
    ]);
    let inner_address = format!("127.0.0.1:{inner}");
    let forward_address = format!("127.0.0.1:{forward}");
    let mut server = Command::new(sandy_path())
        .args(run_args(
            &sandbox_args,
            &[
                ("tcp-connect-read", forward_address.as_str()),
                ("tcp-accept", inner_address.as_str()),
            ],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let outer_address: SocketAddr = format!("127.0.0.1:{outer}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the server never accepted");
        let _ = TcpStream::connect_timeout(&outer_address, Duration::from_millis(500));
        thread::sleep(Duration::from_millis(100));
    }
    let output = server.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines = parse(&output);
    assert_eq!(lines.len(), 2, "{output:?}");
    assert_eq!(lines[0].detail, "2 bytes", "{lines:?}");
    lines[1].assert_ok();
}

/// Records a cost of the view (docs/linux.md, "File system view"): two writable paths are two
/// mounts, even on one file system, so a rename or a link between them fails with EXDEV. Without
/// the view the rename works.
#[test]
fn a_rename_between_writable_paths_fails_with_exdev() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-exdev");
    fs::create_dir(fixture.path("rw2")).unwrap();
    let mut sandbox_args = fixture.access_args();
    sandbox_args.extend(args(&["--read-write", &fixture.arg("rw2")]));
    let rename = format!("{}::{}", fixture.arg("rw/file"), fixture.arg("rw2/file"));
    let link = format!(
        "{}\u{1f}{}",
        fixture.arg("rw/file"),
        fixture.arg("rw2/link")
    );
    let actions = [("rename-in", rename.as_str())];
    probe_inside(&sandbox_args, &actions)[0].assert_ok();
    fixture.reset();
    fs::create_dir(fixture.path("rw2")).unwrap();
    let view = probe_inside(
        &with_view(sandbox_args),
        &[("rename-in", rename.as_str()), ("hardlink", link.as_str())],
    );
    assert!(has_errno(&view[0], libc::EXDEV), "{view:?}");
    assert!(has_errno(&view[1], libc::EXDEV), "{view:?}");
}

/// Records what the view leaves visible (DESIGN.md, the exceptions of `PathsHidden`): `statfs`
/// of a path in the view describes the host's file system there, the directories above a granted
/// path exist, and the link count of a granted file counts its names outside the view. A change
/// in the kernel that hides one of them makes this fail, and the exception can go.
#[test]
fn the_view_leaves_the_file_systems_the_parents_and_link_counts_visible() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-visible");
    fs::hard_link(fixture.path("ro/file"), fixture.path("secret/second-name")).unwrap();
    let (directory, file) = (fixture.arg("ro"), fixture.arg("ro/file"));
    let parent = fixture.root.to_str().unwrap().to_string();
    let actions = [
        ("statfs", directory.as_str()),
        ("lstat", parent.as_str()),
        ("link-count", file.as_str()),
    ];
    let outside = probe_outside(&actions);
    let view = probe_inside(&with_view(fixture.access_args()), &actions);
    assert_eq!(view[0].detail, outside[0].detail, "{view:?}");
    view[1].assert_ok();
    assert_eq!(view[2].detail, "2", "{view:?}");
}

/// Records the last exception of `PathsHidden`: with /proc granted, the mount table of the view
/// names the host's device of every bound path, the same source as outside.
#[test]
fn the_mount_table_names_the_hosts_devices() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-mounts");
    let mount = |path: &str| {
        let table = fs::read_to_string("/proc/self/mountinfo").unwrap();
        table
            .lines()
            .filter(|line| {
                let point = line.split(' ').nth(4).unwrap_or_default();
                std::path::Path::new(path).starts_with(point)
            })
            .filter_map(|line| line.split_once(" - ")?.1.split(' ').nth(1))
            .next_back()
            .unwrap()
            .to_string()
    };
    let source = mount(&fixture.arg("ro"));
    let directory = fixture.arg("ro");
    let mut sandbox_args = with_view(fixture.access_args());
    sandbox_args.extend(args(&["--read", "/proc"]));
    let view = probe_inside(&sandbox_args, &[("mount-source", directory.as_str())]);
    assert_eq!(view[0].detail, source, "{view:?}");
}

/// Without a PID namespace the view binds the /proc paths the policy grants from the host's
/// /proc, read-only also under a writable grant, so the program changes nothing there. Without
/// the view the same grant lets it write its own name.
#[test]
fn proc_is_bound_read_only() {
    if !view_works() {
        return;
    }
    let grant = args(&["--read-write", "/proc"]);
    let actions = [("write", "/proc/self/comm"), ("read", "/proc/self/status")];
    for line in probe_inside(&grant, &actions) {
        line.assert_ok();
    }
    let view = probe_inside(&with_view(grant), &actions);
    assert!(has_errno(&view[0], libc::EROFS), "{view:?}");
    view[1].assert_ok();
}

/// A directory on a standard stream was opened in the host's mount namespace, and through it the
/// program would reach the hidden paths by name, so the view refuses one.
#[test]
fn a_directory_on_a_standard_stream_is_refused() {
    if !view_works() {
        return;
    }
    let fixture = Fixture::new("view-stdin-dir");
    let directory = || Stdio::from(fs::File::open(fixture.path("secret")).unwrap());
    let run = |sandbox_args: &[String]| {
        Command::new(sandy_path())
            .args(run_args(sandbox_args, &[("pid", "-")]))
            .stdin(directory())
            .output()
            .unwrap()
    };
    let control = run(&fixture.access_args());
    assert!(control.status.success(), "{control:?}");
    let refused = run(&with_view(fixture.access_args()));
    assert_eq!(refused.status.code(), Some(EXIT_FAILURE), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("standard input is a directory"), "{stderr}");
}

/// `check` names the mechanism and warns about each exception that applies, the mount table
/// only with /proc granted, and no longer about the metadata of read-only descriptors.
#[test]
fn check_reports_the_view_and_what_stays_visible() {
    if !view_works() {
        return;
    }
    let output = sandy(["check", "--view", "policy", "--read", "/usr/share"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stdout
        .lines()
        .find(|line| line.contains(VIEW_LINE))
        .unwrap_or_default();
    assert!(
        line.starts_with("enforced") && line.contains("pivot_root"),
        "{stdout}"
    );
    for warning in [
        "statfs on a path",
        "the directories above",
        "the link count",
    ] {
        assert!(stderr.contains(warning), "{stderr}");
    }
    assert!(!stderr.contains("mountinfo"), "{stderr}");
    assert!(
        !stderr.contains("path_metadata = \"deny\" is enforced only in part"),
        "{stderr}"
    );
    let all = sandy(["check", "--read", "/usr/share"]);
    let all = String::from_utf8_lossy(&all.stderr);
    assert!(
        all.contains("path_metadata = \"deny\" is enforced only in part"),
        "{all}"
    );
    let with_proc = sandy(["check", "--view", "policy", "--read", "/proc"]);
    assert!(
        String::from_utf8_lossy(&with_proc.stderr).contains("mountinfo"),
        "{with_proc:?}"
    );
}

/// Ubuntu 23.10 and newer let an unconfined process create a user namespace but give it no
/// rights there, so the view needs `sandy setup`: check exits with status 2, and run refuses
/// with the same reason.
#[test]
fn check_needs_setup_under_the_apparmor_restriction() {
    let read = |path: &str| {
        fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    };
    let restricted = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1";
    let unconfined = read("/proc/self/attr/apparmor/current") == "unconfined";
    if !(restricted && unconfined) {
        return skip(
            "apparmor-userns-restriction",
            "this host does not restrict user namespaces of unconfined processes with AppArmor",
        );
    }
    let output = sandy(["check", "--view", "policy"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(EXIT_NEEDS_SETUP), "{stdout}");
    let line = stdout
        .lines()
        .find(|line| line.contains(VIEW_LINE))
        .unwrap_or_default();
    assert!(
        line.starts_with("UNAVAILABLE  ")
            && line.contains("cannot set up the file system view")
            && line.contains("`sandy setup`"),
        "{stdout}"
    );
    let output = sandy(run_args(&args(&["--view", "policy"]), &[("pid", "-")]));
    assert_eq!(output.status.code(), Some(EXIT_FAILURE), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("kernel.apparmor_restrict_unprivileged_userns = 1"),
        "{stderr}"
    );
}
