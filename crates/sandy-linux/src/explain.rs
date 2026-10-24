//! The diagnostic mode (`--explain`): sandy names the paths a run uses that its own rules do not
//! grant. It is off by default and changes nothing the sandbox enforces.
//!
//! A program that is denied a path often says nothing: it treats the file as missing and runs on
//! with less than it was built for. Without this mode the only way to find such a path is to
//! widen the policy until the program behaves differently.
//!
//! How it works:
//!
//! 1. sandy stays the parent of the program in this mode (as with `children = "contained"`),
//!    because only a parent may read the memory of its child on a host with Yama's restricted
//!    ptrace (`/proc/sys/kernel/yama/ptrace_scope` 1, the default on Debian and Ubuntu).
//! 2. The forked program installs one more seccomp filter as its last step before execve
//!    (`filter::observer`). It returns `SECCOMP_RET_USER_NOTIF` for the calls that take a path
//!    and that Landlock can deny, and allows everything else. The kernel hands the installer a
//!    descriptor for that filter, which the program sends to sandy over a socket pair.
//! 3. A thread of sandy reads one notification per such call, reads the path out of the calling
//!    process, answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and reports the path when no rule of
//!    this run grants what the call needs.
//!
//! Why observing is sound where deciding would not be: the kernel documents that the
//! notification must not be used to make a security decision, because the program can change the
//! path after the watcher has read it. Nothing here decides. The watcher always continues the
//! call, so the kernel carries it out with the program's own credentials and its own Landlock
//! domain, and Landlock gives the same answer it would give without the mode. A path the program
//! changed after the read makes the report wrong, never the sandbox weaker.
//!
//! What the mode cannot see is in `docs/linux.md`, "Diagnostic mode". The report says so too.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use landlock::{AccessFs, BitFlags};
use sandy_core::{SandboxError, StatusReport, canonical_location};
use seccompiler::BpfProgram;

use crate::contain::{SIGNALED, START_FAILED};
use crate::filter;
use crate::helper::pipe;
use crate::launch::ensure_single_thread;
use crate::plan::{LandlockConfig, PathRights};

/// Marks every line of the diagnostic mode on standard error. `run` prints nothing else there;
/// this output is the one exception and only with `--explain`.
const PREFIX: &str = "sandy explain: ";

/// What the mode reports when it starts, so that output which names paths is never mistaken for
/// a complete list of denials.
const BANNER: &str = "on. It names the paths of this run that the policy does not grant, and it \
                      does not see every denial (docs/linux.md, \"Diagnostic mode\").";

/// The longest path the watcher reads out of the program. Linux rejects a longer one with
/// ENAMETOOLONG before any Landlock check.
const PATH_MAX: usize = 4096;

/// The most paths the mode names in one run. The program decides how many paths it uses, and
/// the watcher keeps every one it named so that it names it only once, so the report stops
/// here.
const MOST_PATHS: usize = 1000;

/// Writes one line of the report. Not `eprintln!`, which panics when standard error is gone:
/// the watcher would end and every watched call of the program would fail with ENOSYS from
/// then on.
fn report(line: &str) {
    let _ = writeln!(std::io::stderr(), "{PREFIX}{line}");
}

/// What a watched call needs from Landlock, in the words of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Need {
    Read,
    List,
    Execute,
    Write,
    Truncate,
    Create,
    CreateDirectory,
    Remove,
    RemoveDirectory,
    Symlink,
    Device,
    Fifo,
    Socket,
}

impl Need {
    /// The Landlock right the kernel checks for this use.
    fn right(self) -> AccessFs {
        match self {
            Need::Read => AccessFs::ReadFile,
            Need::List => AccessFs::ReadDir,
            Need::Execute => AccessFs::Execute,
            Need::Write => AccessFs::WriteFile,
            Need::Truncate => AccessFs::Truncate,
            Need::Create => AccessFs::MakeReg,
            Need::CreateDirectory => AccessFs::MakeDir,
            Need::Remove => AccessFs::RemoveFile,
            Need::RemoveDirectory => AccessFs::RemoveDir,
            Need::Symlink => AccessFs::MakeSym,
            Need::Device => AccessFs::MakeChar,
            Need::Fifo => AccessFs::MakeFifo,
            Need::Socket => AccessFs::MakeSock,
        }
    }

    /// What the program did with the path, for the report.
    fn action(self) -> &'static str {
        match self {
            Need::Read => "read",
            Need::List => "list",
            Need::Execute => "execute",
            Need::Write => "write to",
            Need::Truncate => "truncate",
            Need::Create => "create",
            Need::CreateDirectory => "create the directory",
            Need::Remove => "remove",
            Need::RemoveDirectory => "remove the directory",
            Need::Symlink => "create a symbolic link at",
            Need::Device => "create a device at",
            Need::Fifo => "create a named pipe at",
            Need::Socket => "create a socket at",
        }
    }

    /// The policy grant that would allow it, if any does. sandy never lets a writable path hold
    /// a symbolic link, a device or a named pipe (see `plan::policy_rights`), so for those the
    /// report names no grant instead of advice that does not work.
    fn grant(self) -> Option<&'static str> {
        match self {
            Need::Read | Need::List => Some("read"),
            Need::Execute => Some("read_exec"),
            Need::Write
            | Need::Truncate
            | Need::Create
            | Need::CreateDirectory
            | Need::Remove
            | Need::RemoveDirectory => Some("read_write"),
            Need::Symlink | Need::Device | Need::Fifo => None,
            // Only with unix_sockets = "all"; `policy_rights` adds MakeSock then.
            Need::Socket => Some("read_write with unix_sockets = \"all\""),
        }
    }
}

/// How the arguments of a watched call say what it needs.
#[derive(Debug, Clone, Copy)]
enum Use {
    /// The open flags at this argument decide: an access mode, O_CREAT, O_TRUNC, O_DIRECTORY.
    Open(u8),
    /// A call that always needs the same right.
    Always(Need),
    /// unlinkat: AT_REMOVEDIR at this argument tells a directory from a file.
    Unlink(u8),
    /// mknod and mknodat: the file type in the mode at this argument.
    Node(u8),
}

/// A system call the observer watches: one that takes a path and that Landlock can deny.
/// Measured on Linux 7.2: stat, statx, access, readlink and chdir pass a path to the kernel but
/// are not denied by any Landlock right, so watching them would only cost two context switches
/// per call.
#[derive(Debug)]
struct Watched {
    call: i64,
    name: &'static str,
    /// Index of the path argument.
    path: u8,
    /// Index of the directory descriptor a relative path starts from. `None`: the path starts
    /// from the current directory of the calling process.
    directory: Option<u8>,
    purpose: Use,
}

const fn watched(
    call: i64,
    name: &'static str,
    path: u8,
    directory: Option<u8>,
    purpose: Use,
) -> Watched {
    Watched {
        call,
        name,
        path,
        directory,
        purpose,
    }
}

/// The watched calls that every architecture has.
const WATCHED: &[Watched] = &[
    watched(libc::SYS_openat, "openat", 1, Some(0), Use::Open(2)),
    watched(
        libc::SYS_execve,
        "execve",
        0,
        None,
        Use::Always(Need::Execute),
    ),
    watched(
        libc::SYS_execveat,
        "execveat",
        1,
        Some(0),
        Use::Always(Need::Execute),
    ),
    watched(
        libc::SYS_truncate,
        "truncate",
        0,
        None,
        Use::Always(Need::Truncate),
    ),
    watched(
        libc::SYS_mkdirat,
        "mkdirat",
        1,
        Some(0),
        Use::Always(Need::CreateDirectory),
    ),
    watched(libc::SYS_unlinkat, "unlinkat", 1, Some(0), Use::Unlink(2)),
    watched(libc::SYS_mknodat, "mknodat", 1, Some(0), Use::Node(2)),
    watched(
        libc::SYS_symlinkat,
        "symlinkat",
        2,
        Some(1),
        Use::Always(Need::Symlink),
    ),
];

/// The calls that only x86_64 has; arm64 has the `*at` forms only.
#[cfg(target_arch = "x86_64")]
const ARCH_WATCHED: &[Watched] = &[
    watched(libc::SYS_open, "open", 0, None, Use::Open(1)),
    watched(libc::SYS_creat, "creat", 0, None, Use::Always(Need::Create)),
    watched(
        libc::SYS_mkdir,
        "mkdir",
        0,
        None,
        Use::Always(Need::CreateDirectory),
    ),
    watched(
        libc::SYS_unlink,
        "unlink",
        0,
        None,
        Use::Always(Need::Remove),
    ),
    watched(
        libc::SYS_rmdir,
        "rmdir",
        0,
        None,
        Use::Always(Need::RemoveDirectory),
    ),
    watched(libc::SYS_mknod, "mknod", 0, None, Use::Node(1)),
    watched(
        libc::SYS_symlink,
        "symlink",
        1,
        None,
        Use::Always(Need::Symlink),
    ),
];

#[cfg(not(target_arch = "x86_64"))]
const ARCH_WATCHED: &[Watched] = &[];

/// The numbers of the watched calls, in the order the observer program compares them.
pub fn watched_calls() -> Vec<i64> {
    WATCHED
        .iter()
        .chain(ARCH_WATCHED)
        .map(|watched| watched.call)
        .collect()
}

fn watched_call(call: i64) -> Option<&'static Watched> {
    WATCHED
        .iter()
        .chain(ARCH_WATCHED)
        .find(|watched| watched.call == call)
}

/// The rules this run gives Landlock, which decide whether a path is granted.
#[derive(Debug)]
pub struct Rules {
    rules: Vec<PathRights>,
    /// The rights the ruleset handles. A right outside it is not checked at all, so a call that
    /// needs only such a right can never be denied.
    handled: BitFlags<AccessFs>,
}

impl Rules {
    pub fn of(landlock: &LandlockConfig) -> Rules {
        Rules {
            rules: landlock.rules.clone(),
            handled: landlock.handled_fs,
        }
    }

    /// The rules that cover `path`: the ones that are the path itself or an ancestor of it.
    /// Landlock grants a right when any of them grants it, and the deepest one is the rule a
    /// person would change.
    fn covering(&self, path: &Path) -> Vec<&PathRights> {
        let mut covering: Vec<&PathRights> = self
            .rules
            .iter()
            .filter(|rule| path.starts_with(&rule.path))
            .collect();
        covering.sort_by_key(|rule| std::cmp::Reverse(rule.path.as_os_str().len()));
        covering
    }

    /// The rights the rules grant for `path`.
    fn granted(&self, path: &Path) -> BitFlags<AccessFs> {
        self.covering(path)
            .iter()
            .fold(BitFlags::empty(), |all, rule| all | rule.access)
    }

    /// Why `need` on `path` is not granted, or `None` when it is. A right the ruleset does not
    /// handle is never checked, so it is never a gap.
    fn gap(&self, path: &Path, need: Need) -> Option<Gap> {
        let right = need.right();
        if !self.handled.contains(right) || self.granted(path).contains(right) {
            return None;
        }
        Some(Gap {
            path: path.to_path_buf(),
            need,
            covered_by: self.covering(path).first().map(|rule| rule.path.clone()),
        })
    }
}

/// A path of the run that the rules do not grant.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Gap {
    path: PathBuf,
    need: Need,
    /// The deepest rule that covers the path but not this use of it.
    covered_by: Option<PathBuf>,
}

impl Gap {
    fn line(&self, call: &str, pid: u32) -> String {
        let what = match &self.covered_by {
            Some(rule) => format!("the rule {} does not allow it", rule.display()),
            None => "no rule covers it".to_string(),
        };
        let advice = match self.need.grant() {
            Some(grant) => format!("grant it with {grant}"),
            None => "no grant of sandy allows that".to_string(),
        };
        format!(
            "cannot {} {}: {what}; {advice} ({call} in process {pid})",
            self.need.action(),
            self.path.display()
        )
    }
}

/// How `check --explain-path` answers for one path: what the rules of this run allow there.
/// The caller may spell the path relative to the current directory, which sandy does not
/// change, and name a path that does not exist yet.
pub fn explain_path(landlock: &LandlockConfig, path: &Path) -> String {
    let rules = Rules::of(landlock);
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical = canonical_location(&absolute);
    let Some(rule) = rules
        .covering(&canonical)
        .first()
        .map(|rule| rule.path.clone())
    else {
        return format!("{}: no rule covers it", canonical.display());
    };
    format!(
        "{}: the rule {} allows {}",
        canonical.display(),
        rule.display(),
        allowed_words(rules.granted(&canonical))
    )
}

/// The rights of a rule in the words of the policy. Only the three a policy can ask for: the
/// others always come with them.
fn allowed_words(access: BitFlags<AccessFs>) -> String {
    let mut words = Vec::new();
    if access.contains(AccessFs::ReadFile) || access.contains(AccessFs::ReadDir) {
        words.push("read");
    }
    if access.contains(AccessFs::WriteFile) {
        words.push("write");
    }
    if access.contains(AccessFs::Execute) {
        words.push("execute");
    }
    if words.is_empty() {
        return "nothing".to_string();
    }
    words.join(" and ")
}

/// The state of the diagnostic mode of one run. sandy creates it before it forks the program and
/// ends it when the program has ended.
#[derive(Debug)]
pub struct Explain {
    /// sandy's end of the socket pair. The watcher receives the notification descriptor on it.
    receive: Option<OwnedFd>,
    /// sandy's copy of the program's end. sandy drops it when the program is forked, so that the
    /// watcher sees the end of the socket when the program failed before it sent the descriptor.
    send: Option<OwnedFd>,
    rules: Arc<Rules>,
    /// The write end of the watcher's stop pipe. Dropping it ends the watcher, also while
    /// processes of the program still hold the filter.
    stop: Option<File>,
    watcher: Option<JoinHandle<Counts>>,
}

/// What the forked program needs to start the observer. It is kept apart from `Explain`, so that
/// the closure which runs in the child borrows nothing that sandy changes afterwards.
#[derive(Debug)]
pub struct Observer {
    /// The program's end of the socket pair, which `Explain` owns. Only the forked program uses
    /// it, before sandy drops its own copy of that end.
    send: RawFd,
    program: BpfProgram,
}

/// Prepares the diagnostic mode of this run: the socket pair for the notification descriptor and
/// the observer program. Fails before anything is started when the kernel's notification
/// interface is not the one sandy was built for.
pub fn prepare(landlock: &LandlockConfig) -> Result<(Explain, Observer), SandboxError> {
    check_notification_sizes()?;
    let (receive, send) = socket_pair()?;
    let observer = Observer {
        send: send.as_raw_fd(),
        program: filter::observer(&watched_calls()),
    };
    let explain = Explain {
        receive: Some(receive),
        send: Some(send),
        rules: Arc::new(Rules::of(landlock)),
        stop: None,
        watcher: None,
    };
    report(BANNER);
    Ok((explain, observer))
}

impl Observer {
    /// Runs in the forked program as the last step of `confine`: installs the observer filter
    /// and sends the descriptor the kernel returns to sandy. Every later call of the program
    /// that the filter names waits for sandy's answer, so this must be the last thing the
    /// program does before execve.
    pub fn install(&self) -> Result<(), SandboxError> {
        let listener = install_observer(&self.program)?;
        send_descriptor(self.send, listener.as_raw_fd())
            .map_err(|error| SandboxError::io("cannot pass the observer to sandy", error))
    }
}

impl Explain {
    /// Starts the watcher once the program is forked. It must run before sandy waits for
    /// anything the program does: the program's own execve is a watched call and waits for an
    /// answer.
    pub fn start(&mut self) -> Result<(), SandboxError> {
        drop(self.send.take());
        ignore_broken_report()?;
        let (stop_read, stop_write) = pipe("the watcher's stop pipe")?;
        self.stop = Some(stop_write);
        let receive = self.receive.take().expect("the watcher starts once");
        let rules = Arc::clone(&self.rules);
        self.watcher = Some(std::thread::spawn(move || {
            watch(&receive, &stop_read, &rules)
        }));
        Ok(())
    }

    /// Ends the watcher and reports what it saw. A process of the program that outlives sandy
    /// keeps the filter, and its watched calls then fail with ENOSYS, so the watcher is not
    /// waited for.
    pub fn finish(&mut self) {
        drop(self.stop.take());
        let Some(watcher) = self.watcher.take() else {
            return;
        };
        let counts = watcher.join().unwrap_or_default();
        report(&counts.summary());
    }
}

/// What the watcher saw, for the closing line of the report.
#[derive(Debug, Default)]
struct Counts {
    calls: u64,
    gaps: usize,
    /// Calls whose path the watcher could not read out of the program.
    unreadable: u64,
}

impl Counts {
    fn summary(&self) -> String {
        let paths = match self.gaps {
            0 => "no path the policy does not grant".to_string(),
            1 => "1 path the policy does not grant".to_string(),
            MOST_PATHS => {
                format!("{MOST_PATHS} paths the policy does not grant, the most one run names")
            }
            gaps => format!("{gaps} paths the policy does not grant"),
        };
        let unreadable = match self.unreadable {
            0 => String::new(),
            calls => format!(", {calls} whose path could not be read"),
        };
        format!("{paths}, from {} watched calls{unreadable}", self.calls)
    }
}

/// Reads notifications until the stop pipe is closed or no process holds the filter any more.
fn watch(receive: &OwnedFd, stop: &File, rules: &Rules) -> Counts {
    let mut counts = Counts::default();
    let Some(listener) = receive_descriptor(receive) else {
        return counts;
    };
    let mut reported = BTreeSet::new();
    while wait_for_call(&listener, stop) {
        let Some(notification) = receive_notification(&listener) else {
            continue;
        };
        counts.calls += 1;
        inspect(&listener, &notification, rules, &mut counts, &mut reported);
        answer_continue(&listener, notification.id);
    }
    counts
}

/// Reports the call of `notification` when the rules do not grant what it needs.
fn inspect(
    listener: &OwnedFd,
    notification: &Notification,
    rules: &Rules,
    counts: &mut Counts,
    reported: &mut BTreeSet<Gap>,
) {
    let Some(watched) = watched_call(i64::from(notification.data.nr)) else {
        return;
    };
    let pid = notification.pid;
    let Some(path) = read_path(pid, notification.data.args[usize::from(watched.path)]) else {
        counts.unreadable += 1;
        return;
    };
    let Some(path) = absolute(pid, watched, &notification.data.args, &path) else {
        counts.unreadable += 1;
        return;
    };
    let path = canonical_location(&path);
    let need = need_of(watched, &notification.data.args, &path);
    let Some(gap) = rules.gap(&path, need) else {
        return;
    };
    // The program can change the path after the watcher read it, which would make the report
    // name a path the kernel never saw. An invalid notification means the call is already gone,
    // so what was read about it says nothing.
    if !notification_valid(listener, notification.id) {
        return;
    }
    let line = gap.line(watched.name, pid);
    if reported.len() >= MOST_PATHS || !reported.insert(gap) {
        return;
    }
    counts.gaps += 1;
    report(&line);
}

/// What the call needs, from its arguments. A call that creates a file needs `MakeReg` only when
/// the file does not exist yet; on an existing one it is an ordinary open.
fn need_of(watched: &Watched, args: &[u64; 6], path: &Path) -> Need {
    let argument = |index: u8| args[usize::from(index)] as u32;
    match watched.purpose {
        Use::Always(need) => need,
        Use::Open(flags) => open_need(argument(flags), path),
        Use::Unlink(flags) => {
            if argument(flags) & libc::AT_REMOVEDIR as u32 != 0 {
                Need::RemoveDirectory
            } else {
                Need::Remove
            }
        }
        Use::Node(mode) => match argument(mode) & libc::S_IFMT {
            libc::S_IFCHR | libc::S_IFBLK => Need::Device,
            libc::S_IFIFO => Need::Fifo,
            libc::S_IFSOCK => Need::Socket,
            _ => Need::Create,
        },
    }
}

fn open_need(flags: u32, path: &Path) -> Need {
    let flag = |flag: libc::c_int| flags & flag as u32 != 0;
    let mode = flags & libc::O_ACCMODE as u32;
    let writing = mode == libc::O_WRONLY as u32 || mode == libc::O_RDWR as u32;
    if flag(libc::O_DIRECTORY) {
        Need::List
    } else if writing {
        Need::Write
    } else if flag(libc::O_CREAT) && !path.exists() {
        Need::Create
    } else if flag(libc::O_TRUNC) {
        Need::Truncate
    } else {
        Need::Read
    }
}

/// `path` as an absolute path, resolved as the kernel resolves it for process `pid`: against the
/// directory of the call's descriptor argument, or against the process's current directory.
fn absolute(pid: u32, watched: &Watched, args: &[u64; 6], path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(own_process(pid, path));
    }
    let empty = path.as_os_str().is_empty();
    let descriptor = watched
        .directory
        .map(|index| args[usize::from(index)] as i32);
    let directory = match descriptor {
        Some(descriptor) if descriptor != libc::AT_FDCWD => {
            format!("/proc/{pid}/fd/{descriptor}")
        }
        // An empty path without a descriptor names nothing, and the kernel answers ENOENT.
        _ if empty => return None,
        _ => format!("/proc/{pid}/cwd"),
    };
    let directory = std::fs::read_link(directory).ok()?;
    // An empty path with a descriptor is the descriptor itself (AT_EMPTY_PATH), which is how
    // fexecve executes a file it already has open.
    Some(if empty {
        directory
    } else {
        directory.join(path)
    })
}

/// `/proc/self` and `/proc/thread-self` lead to the directory of the process that uses them, so
/// sandy would resolve them to its own. The watcher names the calling process instead.
fn own_process(pid: u32, path: &Path) -> PathBuf {
    for name in ["/proc/self", "/proc/thread-self"] {
        if let Ok(rest) = path.strip_prefix(name) {
            return PathBuf::from(format!("/proc/{pid}")).join(rest);
        }
    }
    path.to_path_buf()
}

/// Reads the path at `address` out of process `pid`. The read stops at the end of the page the
/// address is in and continues on the next one, because a read that reaches into an unmapped
/// page fails as a whole.
fn read_path(pid: u32, address: u64) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let page = page_size();
    let mut path = Vec::new();
    let mut address = address;
    while path.len() < PATH_MAX {
        let to_page_end = page - (address as usize % page);
        let length = to_page_end.min(PATH_MAX - path.len());
        let mut buffer = vec![0u8; length];
        let read = read_memory(pid, address, &mut buffer)?;
        if let Some(end) = buffer[..read].iter().position(|&byte| byte == 0) {
            path.extend_from_slice(&buffer[..end]);
            return Some(PathBuf::from(std::ffi::OsString::from_vec(path)));
        }
        path.extend_from_slice(&buffer[..read]);
        address += read as u64;
    }
    None
}

fn page_size() -> usize {
    // SAFETY: sysconf takes a name and returns a number.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as usize } else { 4096 }
}

/// Reads `buffer.len()` bytes at `address` out of process `pid`. It needs the permission a
/// debugger needs, which sandy has for a process it forked, also with Yama's restricted ptrace.
fn read_memory(pid: u32, address: u64, buffer: &mut [u8]) -> Option<usize> {
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    // SAFETY: one local buffer this call owns and one address range of another process, which
    // the kernel checks itself.
    let read = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    (read > 0).then_some(read as usize)
}

/// Starts the program as a child of sandy and waits for it, so that the watcher can read the
/// paths out of it. Only the diagnostic mode uses this; without it sandy replaces itself with
/// the program, and with `children = "contained"` the supervising sandy of `contain` does it.
pub fn supervise(
    start: impl FnOnce() -> SandboxError,
    mut explain: Explain,
    status: &StatusReport,
) -> Result<i32, SandboxError> {
    ensure_single_thread()?;
    let (mut report, report_write) = pipe("the program's report pipe")?;
    // SAFETY: sandy is single-threaded (checked above), so the child may run any code. It leaves
    // only through execve or `_exit`, never by returning into sandy's code.
    let program = match unsafe { libc::fork() } {
        -1 => {
            return Err(SandboxError::io(
                "cannot fork the program",
                io::Error::last_os_error(),
            ));
        }
        0 => {
            drop(report);
            program_main(report_write, start)
        }
        pid => pid,
    };
    drop(report_write);
    // Before the report is read: the execve that ends the report pipe is a watched call and
    // waits for the watcher.
    explain.start()?;
    let mut message = Vec::new();
    report
        .read_to_end(&mut message)
        .map_err(|error| SandboxError::io("cannot read the program's report", error))?;
    if !message.is_empty() {
        explain.finish();
        return Err(SandboxError::new(String::from_utf8_lossy(&message)));
    }
    status.started(program as u32);
    let code = wait_for(program)?;
    explain.finish();
    match code {
        Ended::Exited(code) => {
            status.exited(code);
            Ok(code)
        }
        Ended::Signaled(signal) => {
            status.signaled(signal);
            Ok(SIGNALED + signal)
        }
    }
}

/// The forked program: confines itself and executes the target. Reports a failure over `report`.
fn program_main(mut report: File, start: impl FnOnce() -> SandboxError) -> ! {
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(start));
    let error = started.unwrap_or_else(|_| SandboxError::new("starting the program panicked"));
    let _ = report.write_all(error.to_string().as_bytes());
    // SAFETY: ends the child without running sandy's cleanup.
    unsafe { libc::_exit(START_FAILED) }
}

enum Ended {
    Exited(i32),
    Signaled(i32),
}

/// Waits until the program has ended. A stop of the program stops sandy too: both are in the
/// group the caller started, so the terminal signals reach both.
fn wait_for(program: libc::pid_t) -> Result<Ended, SandboxError> {
    loop {
        let mut status = 0;
        // SAFETY: waits for the forked program and writes its status into `status`.
        if unsafe { libc::waitpid(program, &mut status, 0) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SandboxError::io("cannot wait for the program", error));
        }
        if libc::WIFEXITED(status) {
            return Ok(Ended::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Ended::Signaled(libc::WTERMSIG(status)));
        }
    }
}

// The kernel's notification interface. The structures mirror `struct seccomp_notif` and
// `struct seccomp_notif_resp` of `linux/seccomp.h`; `prepare` checks their sizes against the
// kernel's own before the mode starts.

#[repr(C)]
#[derive(Debug, Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Default)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Default)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
struct NotificationSizes {
    notification: u16,
    response: u16,
    data: u16,
}

/// `_IOW` and `_IOWR` of the kernel's `linux/ioctl.h` for the seccomp magic number. The size is
/// part of the number, so a kernel whose structures differ answers ENOTTY instead of writing
/// into the wrong fields.
const fn ioctl_number(direction: u32, number: u32, size: usize) -> libc::c_ulong {
    const MAGIC: u32 = b'!' as u32;
    ((direction << 30) | ((size as u32) << 16) | (MAGIC << 8) | number) as libc::c_ulong
}

const WRITE: u32 = 1;
const READ_WRITE: u32 = 3;
const NOTIF_RECV: libc::c_ulong = ioctl_number(READ_WRITE, 0, mem::size_of::<Notification>());
const NOTIF_SEND: libc::c_ulong = ioctl_number(READ_WRITE, 1, mem::size_of::<Response>());
const NOTIF_ID_VALID: libc::c_ulong = ioctl_number(WRITE, 2, mem::size_of::<u64>());

/// Refuses the mode when the kernel's notification structures are not the ones above.
fn check_notification_sizes() -> Result<(), SandboxError> {
    let mut sizes = NotificationSizes::default();
    // SAFETY: SECCOMP_GET_NOTIF_SIZES writes three numbers into `sizes`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut NotificationSizes,
        )
    };
    if result != 0 {
        return Err(SandboxError::io(
            "this kernel has no seccomp notification, which --explain needs",
            io::Error::last_os_error(),
        ));
    }
    let expected = (
        mem::size_of::<Notification>(),
        mem::size_of::<Response>(),
        mem::size_of::<SeccompData>(),
    );
    let kernel = (
        usize::from(sizes.notification),
        usize::from(sizes.response),
        usize::from(sizes.data),
    );
    if kernel != expected {
        return Err(SandboxError::new(format!(
            "this kernel's seccomp notification is {kernel:?} bytes wide, not {expected:?}, so \
             --explain cannot read it"
        )));
    }
    Ok(())
}

/// Installs the observer filter on the calling thread and returns the descriptor the kernel
/// gives for it. Not with TSYNC, which this kernel rejects together with a new listener
/// (measured on Linux 7.2: EINVAL); the program is single-threaded here, and every thread it
/// starts later inherits the filter.
fn install_observer(program: &BpfProgram) -> Result<OwnedFd, SandboxError> {
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        // The two `sock_filter` definitions are the same C structure; seccompiler has its own
        // only because libc's lacks `Debug`.
        filter: program.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };
    // SAFETY: the kernel copies the program out of `filter` and returns a new descriptor.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &filter as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        return Err(SandboxError::io(
            "cannot install the observer filter",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(listener as RawFd) })
}

/// Waits until a notification is there. `false` when the watcher must end: the stop pipe is
/// closed, or no process holds the filter any more.
fn wait_for_call(listener: &OwnedFd, stop: &File) -> bool {
    let poll = |fd: RawFd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut polls = [poll(listener.as_raw_fd()), poll(stop.as_raw_fd())];
    loop {
        // SAFETY: polls two open descriptors.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if polls[1].revents != 0 {
            return false;
        }
        return polls[0].revents & libc::POLLIN != 0;
    }
}

/// One ioctl on the notification descriptor. Through the system call, because the libc wrapper
/// types the request number differently per target (`c_int` on musl, `c_ulong` on glibc).
/// `argument` must be the structure the request names; its size is part of the number, so a
/// kernel that expects another one answers ENOTTY.
fn notify<T>(listener: &OwnedFd, request: libc::c_ulong, argument: &mut T) -> libc::c_long {
    // SAFETY: the kernel reads or writes `argument` as the request says.
    unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            listener.as_raw_fd(),
            request,
            std::ptr::from_mut(argument),
        )
    }
}

fn receive_notification(listener: &OwnedFd) -> Option<Notification> {
    let mut notification = Notification::default();
    (notify(listener, NOTIF_RECV, &mut notification) == 0).then_some(notification)
}

/// Whether the call of `id` is still waiting. A call whose process was killed is gone, and what
/// was read about it may be from another process by now.
fn notification_valid(listener: &OwnedFd, id: u64) -> bool {
    let mut id = id;
    notify(listener, NOTIF_ID_VALID, &mut id) == 0
}

/// Lets the kernel carry out the call. This is the only answer the watcher ever gives: it adds
/// no result, no error and no descriptor, so the kernel and Landlock decide as they would
/// without the mode.
fn answer_continue(listener: &OwnedFd, id: u64) {
    let mut response = Response {
        id,
        value: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    notify(listener, NOTIF_SEND, &mut response);
}

/// Keeps a report that nobody reads from ending sandy. The program is already forked when this
/// runs, so it keeps the default action that `launch` restored for it; only sandy stops dying
/// of a standard error whose reader is gone.
fn ignore_broken_report() -> Result<(), SandboxError> {
    // SAFETY: setting the disposition of SIGPIPE has no memory safety requirements.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(SandboxError::io(
            "cannot ignore SIGPIPE for the diagnostic report",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// A close-on-exec socket pair: (sandy's end, the program's end).
fn socket_pair() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two new descriptors into `fds`.
    let created = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if created != 0 {
        return Err(SandboxError::io(
            "cannot create the socket pair of the diagnostic mode",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: both descriptors were just created and nothing else owns them.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// The control message of one descriptor, rounded up as the kernel expects it.
const CONTROL_SIZE: usize = {
    // SAFETY: CMSG_SPACE only computes a size.
    unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as usize }
};

fn send_descriptor(socket: RawFd, descriptor: RawFd) -> io::Result<()> {
    let mut body = [0u8; 1];
    let mut buffer = [0u8; CONTROL_SIZE];
    let mut iov = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    // SAFETY: msghdr is plain data; the fields below describe the buffers above, which live
    // until the call has returned.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    message.msg_controllen = buffer.len() as _;
    // SAFETY: the control buffer is large enough for one descriptor (CONTROL_SIZE), so
    // CMSG_FIRSTHDR returns a pointer into it.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header).cast::<RawFd>().write(descriptor);
    }
    // SAFETY: sends the message above over an open socket.
    let sent = unsafe { libc::sendmsg(socket, &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receives the notification descriptor. `None` when the program ended before it sent one.
fn receive_descriptor(socket: &OwnedFd) -> Option<OwnedFd> {
    let mut body = [0u8; 1];
    let mut buffer = [0u8; CONTROL_SIZE];
    let mut iov = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    // SAFETY: as in `send_descriptor`.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    message.msg_controllen = buffer.len() as _;
    loop {
        // SAFETY: receives into the buffers above.
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if received <= 0 {
            return None;
        }
        break;
    }
    // SAFETY: reads the control message the kernel wrote into the buffer.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return None;
        }
        let descriptor = libc::CMSG_DATA(header).cast::<RawFd>().read();
        Some(OwnedFd::from_raw_fd(descriptor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landlock::{ABI, Access, make_bitflags};

    const READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ReadFile | ReadDir});

    fn rule(path: &str, access: BitFlags<AccessFs>) -> PathRights {
        PathRights {
            path: PathBuf::from(path),
            is_dir: true,
            access,
        }
    }

    fn rules(rules: Vec<PathRights>) -> Rules {
        Rules {
            rules,
            handled: AccessFs::from_all(ABI::V5),
        }
    }

    fn gap(rules: &Rules, path: &str, need: Need) -> Option<String> {
        rules
            .gap(Path::new(path), need)
            .map(|gap| gap.line("openat", 7))
    }

    #[test]
    fn a_path_without_a_rule_is_a_gap() {
        let rules = rules(vec![rule("/a/b", READ)]);
        assert_eq!(gap(&rules, "/a/b/c", Need::Read), None);
        assert_eq!(gap(&rules, "/a/b", Need::Read), None);
        let line = gap(&rules, "/a/other", Need::Read).expect("no rule covers it");
        assert_eq!(
            line,
            "cannot read /a/other: no rule covers it; grant it with read (openat in process 7)"
        );
        // A rule is a prefix of whole names, not of the spelling.
        assert!(gap(&rules, "/a/bc", Need::Read).is_some());
    }

    #[test]
    fn a_rule_that_does_not_allow_the_use_is_named() {
        let rules = rules(vec![rule("/a", READ)]);
        let line = gap(&rules, "/a/b", Need::Write).expect("read does not allow writing");
        assert_eq!(
            line,
            "cannot write to /a/b: the rule /a does not allow it; grant it with read_write \
             (openat in process 7)"
        );
        // sandy grants no rule that allows a symbolic link, so the report names no option.
        let line = gap(&rules, "/a/b", Need::Symlink).expect("no rule allows a symbolic link");
        assert!(line.contains("no grant of sandy allows that"), "{line}");
    }

    /// Landlock checks only the rights the ruleset handles, so a call that needs another one is
    /// never denied and never a gap.
    #[test]
    fn a_right_the_ruleset_does_not_handle_is_no_gap() {
        let unhandled = Rules {
            rules: vec![rule("/a", READ)],
            handled: READ,
        };
        assert_eq!(gap(&unhandled, "/b", Need::Write), None);
        assert!(gap(&unhandled, "/b", Need::Read).is_some());
    }

    #[test]
    fn the_deepest_rule_decides_what_is_named() {
        let rules = rules(vec![
            rule("/a", READ),
            rule("/a/b", READ | AccessFs::Execute),
            rule("/a/b/c", READ),
        ]);
        let line = gap(&rules, "/a/b/c/d", Need::Write).expect("nothing allows writing");
        assert!(line.contains("the rule /a/b/c"), "{line}");
        // Landlock allows a right that any rule of the hierarchy grants.
        assert_eq!(gap(&rules, "/a/b/c/d", Need::Execute), None);
    }

    #[test]
    fn open_flags_say_what_the_call_needs() {
        let missing = Path::new("/sandy-explain-no-such-path");
        let read_only = libc::O_RDONLY as u32;
        assert_eq!(open_need(read_only, missing), Need::Read);
        assert_eq!(open_need(libc::O_WRONLY as u32, missing), Need::Write);
        assert_eq!(open_need(libc::O_RDWR as u32, missing), Need::Write);
        assert_eq!(
            open_need(read_only | libc::O_DIRECTORY as u32, missing),
            Need::List
        );
        assert_eq!(
            open_need(read_only | libc::O_CREAT as u32, missing),
            Need::Create
        );
        // An existing file is not created, whatever O_CREAT says.
        assert_eq!(
            open_need(read_only | libc::O_CREAT as u32, Path::new("/")),
            Need::Read
        );
        assert_eq!(
            open_need(read_only | libc::O_TRUNC as u32, missing),
            Need::Truncate
        );
    }

    #[test]
    fn arguments_say_what_the_other_calls_need() {
        let watched = |call: i64| watched_call(call).expect("a watched call");
        let mut args = [0u64; 6];
        let path = Path::new("/");
        assert_eq!(
            need_of(watched(libc::SYS_unlinkat), &args, path),
            Need::Remove
        );
        args[2] = libc::AT_REMOVEDIR as u64;
        assert_eq!(
            need_of(watched(libc::SYS_unlinkat), &args, path),
            Need::RemoveDirectory
        );
        args[2] = u64::from(libc::S_IFIFO);
        assert_eq!(need_of(watched(libc::SYS_mknodat), &args, path), Need::Fifo);
        args[2] = u64::from(libc::S_IFCHR);
        assert_eq!(
            need_of(watched(libc::SYS_mknodat), &args, path),
            Need::Device
        );
        assert_eq!(
            need_of(watched(libc::SYS_execveat), &args, path),
            Need::Execute
        );
    }

    /// Every watched call reads its path and its directory from an argument the kernel has, and
    /// the observer program compares each number once.
    #[test]
    fn the_watched_table_is_consistent() {
        let mut calls = watched_calls();
        let count = calls.len();
        calls.sort_unstable();
        calls.dedup();
        assert_eq!(calls.len(), count, "a call is watched twice");
        for watched in WATCHED.iter().chain(ARCH_WATCHED) {
            assert!(watched.path < 6, "{}", watched.name);
            assert!(
                watched.directory.is_none_or(|index| index < 6),
                "{}",
                watched.name
            );
        }
    }

    /// `execveat` with an empty path executes the descriptor itself, which is how `fexecve`
    /// works. The watcher must name the file of the descriptor, not the current directory.
    #[test]
    fn an_empty_path_names_the_descriptor() {
        use std::os::fd::AsRawFd;

        let watched = watched_call(libc::SYS_execveat).expect("execveat is watched");
        let file = File::open("/proc/self/stat").unwrap();
        let mut args = [0u64; 6];
        args[0] = file.as_raw_fd() as u64;
        // SAFETY: getpid has no preconditions.
        let own = unsafe { libc::getpid() } as u32;
        let path = absolute(own, watched, &args, Path::new("")).expect("the descriptor's file");
        assert_eq!(path, PathBuf::from(format!("/proc/{own}/stat")));
        // Without a descriptor an empty path names nothing.
        args[0] = libc::AT_FDCWD as u64;
        assert_eq!(absolute(own, watched, &args, Path::new("")), None);
    }

    /// `/proc/self` means the calling process, not sandy.
    #[test]
    fn the_watcher_resolves_proc_self_to_the_program() {
        let path = own_process(42, Path::new("/proc/self/maps"));
        assert_eq!(path, PathBuf::from("/proc/42/maps"));
        let path = own_process(42, Path::new("/proc/thread-self/comm"));
        assert_eq!(path, PathBuf::from("/proc/42/comm"));
        let other = Path::new("/proc/1/maps");
        assert_eq!(own_process(42, other), other);
        let selfish = Path::new("/proc/selfish/x");
        assert_eq!(own_process(42, selfish), selfish);
    }

    #[test]
    fn explain_path_names_the_rule_and_what_it_allows() {
        let landlock = LandlockConfig {
            abi: ABI::V5,
            handled_fs: AccessFs::from_all(ABI::V5),
            handled_net: BitFlags::empty(),
            scopes: BitFlags::empty(),
            rules: vec![
                rule("/sandy-explain-test/ro", READ),
                rule(
                    "/sandy-explain-test/rw",
                    READ | AccessFs::WriteFile | AccessFs::MakeReg,
                ),
            ],
        };
        let answer = |path: &str| explain_path(&landlock, Path::new(path));
        assert_eq!(
            answer("/sandy-explain-test/ro/file"),
            "/sandy-explain-test/ro/file: the rule /sandy-explain-test/ro allows read"
        );
        assert_eq!(
            answer("/sandy-explain-test/rw/file"),
            "/sandy-explain-test/rw/file: the rule /sandy-explain-test/rw allows read and write"
        );
        assert_eq!(
            answer("/sandy-explain-test/other"),
            "/sandy-explain-test/other: no rule covers it"
        );
    }

    /// The structures the watcher reads notifications into must be the kernel's own.
    #[test]
    fn the_kernels_notification_sizes_are_the_ones_sandy_expects() {
        check_notification_sizes().expect("Linux 5.0 and newer have the notification");
    }

    /// Which path calls a Landlock domain can deny. The watched set is exactly this answer, so
    /// a kernel that starts denying one of the calls in the second group would make the mode
    /// blind to those denials, and this test says so. Measured on Linux 7.2.
    #[test]
    fn landlock_denies_the_watched_calls_and_not_the_others() {
        use crate::host::HostCapabilities;
        use landlock::{PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};
        use std::ffi::CString;
        use std::os::unix::ffi::OsStringExt;

        let Ok(version) = HostCapabilities::detect().landlock else {
            eprintln!("skipped: no Landlock");
            return;
        };
        let abi = ABI::from(version);
        let root = std::env::temp_dir().join(format!("sandy-explain-{}", std::process::id()));
        let granted = root.join("granted");
        let denied = root.join("denied");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::create_dir_all(&denied).unwrap();
        std::fs::write(denied.join("file"), b"x").unwrap();
        std::os::unix::fs::symlink("file", denied.join("link")).unwrap();
        let path =
            |name: &str| CString::new(denied.join(name).into_os_string().into_vec()).unwrap();
        let (file, link, new) = (path("file"), path("link"), path("new"));
        let directory = CString::new(denied.clone().into_os_string().into_vec()).unwrap();
        // Each call on a path the domain does not grant, with the arguments the kernel needs.
        let calls: Vec<(&str, bool, libc::c_long)> = vec![
            ("open", true, libc::SYS_openat),
            ("mkdirat", true, libc::SYS_mkdirat),
            ("unlinkat", true, libc::SYS_unlinkat),
            ("truncate", true, libc::SYS_truncate),
            ("symlinkat", true, libc::SYS_symlinkat),
            ("newfstatat", false, libc::SYS_newfstatat),
            ("statx", false, libc::SYS_statx),
            ("faccessat", false, libc::SYS_faccessat),
            ("readlinkat", false, libc::SYS_readlinkat),
            ("chdir", false, libc::SYS_chdir),
        ];
        // The ruleset is built before the fork, so the child only applies it and makes the
        // calls: a child of this multithreaded test binary must not allocate.
        let ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(
                PathFd::new(&granted).unwrap(),
                AccessFs::from_all(abi),
            ))
            .unwrap();
        let (mut report, mut report_write) = pipe("the measurement pipe").unwrap();
        // SAFETY: the child applies the ruleset, makes the calls above and leaves through
        // `_exit`. It allocates nothing, because the test binary has more than one thread.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let mut answers = [0u8; 10];
            crate::launch::set_no_new_privs().expect("no_new_privs");
            crate::launch::restrict(ruleset).expect("the domain");
            for (answer, &(_, _, call)) in answers.iter_mut().zip(&calls) {
                let mut buffer = [0u8; 512];
                let out = buffer.as_mut_ptr();
                // SAFETY: every call gets the arguments of its own number; the buffers are
                // this function's own.
                let result = unsafe {
                    match call {
                        libc::SYS_openat => {
                            libc::syscall(call, libc::AT_FDCWD, file.as_ptr(), 0, 0)
                        }
                        libc::SYS_mkdirat => {
                            libc::syscall(call, libc::AT_FDCWD, new.as_ptr(), 0o700)
                        }
                        libc::SYS_unlinkat => libc::syscall(call, libc::AT_FDCWD, file.as_ptr(), 0),
                        libc::SYS_truncate => libc::syscall(call, file.as_ptr(), 0),
                        libc::SYS_symlinkat => {
                            libc::syscall(call, file.as_ptr(), libc::AT_FDCWD, new.as_ptr())
                        }
                        libc::SYS_newfstatat => {
                            libc::syscall(call, libc::AT_FDCWD, file.as_ptr(), out, 0)
                        }
                        libc::SYS_statx => {
                            libc::syscall(call, libc::AT_FDCWD, file.as_ptr(), 0, 0, out)
                        }
                        libc::SYS_faccessat => {
                            libc::syscall(call, libc::AT_FDCWD, file.as_ptr(), 4)
                        }
                        libc::SYS_readlinkat => {
                            libc::syscall(call, libc::AT_FDCWD, link.as_ptr(), out, 512)
                        }
                        _ => libc::syscall(call, directory.as_ptr()),
                    }
                };
                let denied =
                    result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
                *answer = u8::from(denied);
            }
            let _ = report_write.write_all(&answers);
            // SAFETY: ends the child without running the test harness's cleanup.
            unsafe { libc::_exit(0) }
        }
        drop(report_write);
        let mut answers = Vec::new();
        report.read_to_end(&mut answers).unwrap();
        let mut status = 0;
        // SAFETY: waits for the child created above.
        unsafe { libc::waitpid(child, &mut status, 0) };
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(answers.len(), calls.len(), "the child did not report");
        for (&(name, deniable, _), &denied) in calls.iter().zip(&answers) {
            assert_eq!(denied == 1, deniable, "Landlock and {name} disagree");
        }
    }
}
