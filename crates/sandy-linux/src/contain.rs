//! `process.children = "contained"`. sandy stays the parent of the program, so that it can end
//! every process the program starts:
//!
//! 1. sandy makes itself a child subreaper: a process whose parent ends is re-parented to sandy
//!    instead of init. It blocks the signals it forwards and waits for them with sigwaitinfo.
//! 2. It forks the guard. The guard creates a process group of its own and closes every
//!    descriptor except the read end of a pipe. sandy holds the write end; the forked program has
//!    a copy until execve closes it, so the pipe ends only once sandy is gone and the program
//!    has started or ended.
//! 3. It forks the program. The program joins the guard's group and then writes its own process
//!    ID into the pipe. The guard opens a pidfd for it and kills the group when the program ends
//!    or when the pipe ends, that is when sandy dies, also by SIGKILL. So the group ends with the
//!    program even while sandy is stopped. The program sends the ID itself, so the guard learns
//!    it even if sandy never runs again after the fork, and it sends it only once it is in the
//!    group, so a kill of the group reaches it from the moment the guard knows it. With exposed
//!    or forwarded ports the guard also holds a pidfd for the relay, and when the relay ends
//!    while the program runs, it tells sandy so over a pipe of its own and kills the group too.
//! 4. The program confines itself as in the exec model and executes the target; it reports a
//!    failure over a close-on-exec pipe. Its seccomp filter denies setsid and setpgid, so no
//!    process it starts can leave the group, and the Landlock signal scope (the policy requires
//!    `signals = "isolated"`) keeps it from signaling sandy or the guard.
//! 5. sandy forwards the signals it receives to the program and reaps re-parented processes. With
//!    a terminal it follows job control. The program's group gets the terminal only when the
//!    program stops because it used the terminal while sandy's job had it; another process of
//!    sandy's job that then uses the terminal gets it back. Any other stop of the program stops
//!    sandy too, so a shell sees the job stop; when sandy continues, it continues the group.
//! 6. When the program exits, sandy gives the terminal back, kills the group with SIGKILL, reaps
//!    the group, and exits with the program's exit status, or 128 plus the signal number if a
//!    signal ended it. If the guard reported that the relay ended first, sandy fails instead.
//!
//! The group's ID is the guard's process ID. sandy reaps neither the guard nor the program before
//! it has killed the group, so no other process can have these IDs while sandy may signal them.
//!
//! sandy makes itself undumpable before it forks the guard and the program, so that both start
//! undumpable and a program with a write grant on `/proc` never has a moment to raise the
//! `oom_score_adj` of sandy or the guard and have the kernel end them under memory pressure. The
//! kernel makes the program dumpable again when it executes the target.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;

use sandy_core::{SandboxError, StatusReport};

use crate::explain::Explain;
use crate::helper::{block_signals, close_descriptors_except, pipe, set_dumpable, set_undumpable};
use crate::launch::ensure_single_thread;

/// Shells report a program that a signal ended with this status plus the signal number.
pub(crate) const SIGNALED: i32 = 128;
/// The forked child's exit status when it cannot start the program. sandy reports the message
/// from the pipe instead.
pub(crate) const START_FAILED: i32 = 125;
/// What the guard writes to sandy when the relay ended while the program ran.
const RELAY_ENDED: u8 = b'r';

/// Starts the program in a process group that sandy ends when the program ends, and returns the
/// exit status for sandy. `start` runs in the forked child: it confines the child and executes
/// the target, and returns only on failure.
/// `ended` is the write end of the relay's pipe, if a relay runs: only the guard keeps it, so it
/// ends when the guard has ended the group. `relay` is a pidfd for the relay, which the guard
/// watches.
/// `explain` is the diagnostic mode, which watches the program from here because sandy is
/// already its parent.
pub fn run(
    start: impl FnOnce() -> SandboxError,
    ended: Option<File>,
    relay: Option<OwnedFd>,
    status: &StatusReport,
    mut explain: Option<&mut Explain>,
) -> Result<i32, SandboxError> {
    ensure_single_thread()?;
    set_child_subreaper()?;
    // Before the forks: a flag set after a fork would leave the child's program a moment to
    // raise the out-of-memory priority of the process that sets it.
    set_undumpable()?;
    let child_action = default_child_action()?;
    let signals = Signals::block()?;
    let mut group = Group::start(ended, relay)?;
    let (mut report, report_write) = pipe("the program's report pipe")?;
    // SAFETY: sandy is single-threaded (checked above), so the child may run any code. It leaves
    // only through execve or `_exit`, never by returning into sandy's code.
    match unsafe { libc::fork() } {
        -1 => {
            return Err(SandboxError::io(
                "cannot fork the program",
                io::Error::last_os_error(),
            ));
        }
        0 => {
            drop(report);
            let explained = explain.is_some();
            program_main(
                &group,
                &signals,
                &child_action,
                report_write,
                explained,
                start,
            )
        }
        pid => group.program = Some(pid),
    }
    drop(report_write);
    // Before the report is read: the execve that ends the report pipe is a watched call and
    // waits for the watcher.
    if let Some(explain) = &mut explain {
        explain.start()?;
    }
    let mut message = Vec::new();
    report
        .read_to_end(&mut message)
        .map_err(|error| SandboxError::io("cannot read the program's report", error))?;
    if !message.is_empty() {
        return Err(SandboxError::new(String::from_utf8_lossy(&message)));
    }
    // The program has started: the report pipe reached its end without a message, which only
    // execve does.
    status.started(group.program.expect("the program was started") as u32);
    let exited = group.supervise(&signals)?;
    group.end();
    if let Some(explain) = &mut explain {
        explain.finish();
    }
    Ok(match exited.code {
        libc::CLD_EXITED => {
            status.exited(exited.status);
            exited.status
        }
        _ => {
            status.signaled(exited.status);
            SIGNALED + exited.status
        }
    })
}

/// The program's process group, led by the guard. Dropping it ends the group, so a failure after
/// the guard started also ends everything sandy started.
struct Group {
    /// The guard's process ID, which is also the group's ID.
    leader: libc::pid_t,
    program: Option<libc::pid_t>,
    /// sandy's controlling terminal, if one of its standard descriptors is that terminal.
    terminal: Option<RawFd>,
    /// sandy gave the terminal to the program's group, and should give it again after a stop.
    program_has_terminal: bool,
    /// The write end of the guard's pipe. The forked program writes its process ID into it, and
    /// sandy holds it open, so that its close tells the guard that sandy is gone.
    guard: File,
    /// With a relay, the read end of the pipe over which the guard reports `RELAY_ENDED`.
    relay_report: Option<File>,
    ended: bool,
}

impl Group {
    fn start(ended: Option<File>, relay: Option<OwnedFd>) -> Result<Group, SandboxError> {
        let (guard_end, guard) = pipe("the guard's pipe")?;
        let (relay_report, guard_report) = match relay {
            Some(_) => {
                let (read, write) = pipe("the guard's report pipe")?;
                (Some(read), Some(write))
            }
            None => (None, None),
        };
        // SAFETY: sandy is single-threaded (checked in `run`). The guard leaves only through
        // `_exit`.
        let leader = match unsafe { libc::fork() } {
            -1 => {
                return Err(SandboxError::io(
                    "cannot fork the guard",
                    io::Error::last_os_error(),
                ));
            }
            0 => {
                drop(guard);
                drop(relay_report);
                guard_main(guard_end, ended, relay, guard_report)
            }
            pid => pid,
        };
        drop(guard_end);
        drop((ended, relay, guard_report));
        let group = Group {
            leader,
            program: None,
            terminal: controlling_terminal(),
            program_has_terminal: false,
            guard,
            relay_report,
            ended: false,
        };
        // The guard sets its group too. Setting it here as well means the group exists before
        // sandy continues, whichever process runs first.
        // SAFETY: setpgid takes two process IDs.
        if unsafe { libc::setpgid(leader, leader) } != 0 {
            return Err(SandboxError::io(
                "cannot create the program's process group",
                io::Error::last_os_error(),
            ));
        }
        Ok(group)
    }

    /// Forwards signals and follows the program until it exits. Returns how it ended.
    ///
    /// A relay that is gone leaves its ports to whatever binds them next, and a local user who
    /// binds the program's forward port receives what the program sends there, so the guard ends
    /// the program with it, and sandy reports that as its own failure. The guard reports before
    /// it kills the group, so the report is there once sandy sees the program or the guard end;
    /// the guard is in the group, so it can end before the program.
    fn supervise(&mut self, signals: &Signals) -> Result<ChildState, SandboxError> {
        let program = self.program.expect("the program was started");
        loop {
            let exited = self.reap_others(program);
            if !matches!(exited, Ok(None)) && self.relay_ended() {
                return Err(SandboxError::new(
                    "the relay of the exposed or forwarded ports ended before the program; the \
                     ports it served are gone and the program has been ended with it",
                ));
            }
            if let Some(exited) = exited? {
                return Ok(exited);
            }
            match signals.wait()? {
                libc::SIGCHLD => self.follow_program(program)?,
                libc::SIGCONT => self.resume(),
                // The kernel sends these to sandy's group when another process of sandy's job
                // uses the terminal while the program's group has it.
                libc::SIGTTIN | libc::SIGTTOU => self.return_terminal(),
                // SAFETY: kill takes a process ID; sandy has not reaped the program.
                signal => unsafe {
                    libc::kill(program, signal);
                },
            }
        }
    }

    /// Whether the guard ended the group because the relay ended while the program ran.
    fn relay_ended(&self) -> bool {
        let Some(report) = &self.relay_report else {
            return false;
        };
        let mut poll = libc::pollfd {
            fd: report.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, and a zero timeout does not block.
        if unsafe { libc::poll(&mut poll, 1, 0) } <= 0 {
            return false;
        }
        let mut byte = [0u8; 1];
        matches!((&*report).read(&mut byte), Ok(1) if byte[0] == RELAY_ENDED)
    }

    /// Reaps every exited child except the program and the guard. Returns the program's state
    /// once it has exited, without reaping it.
    fn reap_others(&self, program: libc::pid_t) -> Result<Option<ChildState>, SandboxError> {
        let program_exited = || {
            waitable(
                libc::P_PID,
                program as libc::id_t,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        while let Some(child) = waitable(libc::P_ALL, 0, libc::WEXITED | libc::WNOWAIT)? {
            if child.pid == program {
                return Ok(Some(child));
            }
            if child.pid == self.leader {
                // The guard ends with the group once the program has exited; it is older, so
                // waitid reports it first.
                return match program_exited()? {
                    Some(exited) => Ok(Some(exited)),
                    None => Err(SandboxError::new(
                        "the guard of the program's process group ended unexpectedly",
                    )),
                };
            }
            // SAFETY: reaps the exited child that waitid reported.
            unsafe { libc::waitpid(child.pid, ptr::null_mut(), libc::WNOHANG) };
        }
        Ok(None)
    }

    /// Follows a stop of the program, only with a terminal; without one there is no job control
    /// to follow. A program that stopped because it used the terminal while sandy's job had it
    /// gets the terminal and continues. Any other stop stops sandy too, so that a shell sees the
    /// job stop and takes the terminal; sandy continues when it receives SIGCONT. The guard ends
    /// the group when the program ends, also while sandy is stopped.
    fn follow_program(&mut self, program: libc::pid_t) -> Result<(), SandboxError> {
        let Some(terminal) = self.terminal else {
            return Ok(());
        };
        let Some(stopped) = waitable(libc::P_PID, program as libc::id_t, libc::WSTOPPED)?
            .filter(|child| child.code == libc::CLD_STOPPED)
        else {
            return Ok(());
        };
        let used_terminal = matches!(stopped.status, libc::SIGTTIN | libc::SIGTTOU);
        if used_terminal && self.give_terminal(terminal) {
            // SAFETY: kill takes a process group ID; see the module documentation.
            unsafe { libc::kill(-self.leader, libc::SIGCONT) };
        } else {
            self.take_terminal();
            // SAFETY: stops sandy itself.
            unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
        }
        Ok(())
    }

    /// sandy continued: it gives the terminal to the program's group again if the group had it,
    /// and continues the group.
    fn resume(&mut self) {
        if let (Some(terminal), true) = (self.terminal, self.program_has_terminal) {
            self.give_terminal(terminal);
        }
        // SAFETY: kill takes a process group ID; see the module documentation.
        unsafe { libc::kill(-self.leader, libc::SIGCONT) };
    }

    /// Another process of sandy's job used the terminal while the program's group had it, and
    /// the kernel stopped it. sandy takes the terminal back and continues its job. The program
    /// gets the terminal again when it next uses it.
    fn return_terminal(&mut self) {
        if self.take_terminal() {
            self.program_has_terminal = false;
            // SAFETY: continues sandy's own process group.
            unsafe { libc::kill(0, libc::SIGCONT) };
        }
    }

    /// Gives the terminal to the program's group if sandy's group is the foreground group.
    /// Returns whether the program's group has it now.
    fn give_terminal(&mut self, terminal: RawFd) -> bool {
        // SAFETY: tcgetpgrp, getpgrp and tcsetpgrp take a descriptor and process group IDs.
        let given = unsafe {
            libc::tcgetpgrp(terminal) == libc::getpgrp()
                && libc::tcsetpgrp(terminal, self.leader) == 0
        };
        self.program_has_terminal |= given;
        given
    }

    /// Gives the terminal back to sandy's group if the program's group has it. SIGTTOU is
    /// blocked, so sandy may do this from the background. Returns whether it did.
    fn take_terminal(&self) -> bool {
        let Some(terminal) = self.terminal else {
            return false;
        };
        // SAFETY: as in `give_terminal`.
        unsafe {
            libc::tcgetpgrp(terminal) == self.leader
                && libc::tcsetpgrp(terminal, libc::getpgrp()) == 0
        }
    }

    /// Kills the group, the guard and the program, and reaps the group.
    fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        self.take_terminal();
        // SAFETY: kill takes process and group IDs. sandy has reaped neither the guard nor the
        // program, so these IDs still belong to them. The guard and the program are killed by ID
        // as well, in case either never joined the group.
        unsafe {
            libc::kill(-self.leader, libc::SIGKILL);
            libc::kill(self.leader, libc::SIGKILL);
            if let Some(program) = self.program {
                libc::kill(program, libc::SIGKILL);
            }
        }
        // Every process the program started is in the group, and a member whose parent ends is
        // re-parented to sandy before that parent can be reaped, so ECHILD means the group is
        // gone. Other children of sandy (inherited across execve, or the relay when sandy's
        // caller made it a subreaper) are not waited for.
        loop {
            // SAFETY: waits for a child in the group; the status is not needed.
            if unsafe { libc::waitpid(-self.leader, ptr::null_mut(), 0) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.end();
    }
}

/// The guard: leads the program's process group and kills it when the program ends, sandy ends or
/// the relay ends. `ended`, the relay's pipe, closes when the guard dies with the group. `relay`
/// is a pidfd for the relay, and `report` the pipe that tells sandy the relay ended first.
fn guard_main(end: File, ended: Option<File>, relay: Option<OwnedFd>, report: Option<File>) -> ! {
    let mut keep = vec![end.as_raw_fd()];
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(relay.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(report.as_ref().map(AsRawFd::as_raw_fd));
    // SAFETY: setpgid takes process IDs.
    if unsafe { libc::setpgid(0, 0) } != 0 || close_descriptors_except(&keep).is_err() {
        // SAFETY: ends the guard without running sandy's cleanup. sandy kills the group by ID.
        unsafe { libc::_exit(1) };
    }
    if let Some(program) = read_program(&end) {
        let relay_fd = relay.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let mut polls = [end.as_raw_fd(), program, relay_fd].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: polls open descriptors, and poll skips a negative one; returns when sandy,
        // the program or the relay ends.
        while unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
        // A relay that ended in the same look as the program or sandy is the end of a run.
        let [sandy_ended, program_ended, relay_ended] = polls.map(|poll| poll.revents != 0);
        if relay_ended && !sandy_ended && !program_ended {
            // Before the kill, so that sandy finds the report once it sees the group end.
            if let Some(mut report) = report {
                let _ = report.write_all(&[RELAY_ENDED]);
            }
        }
    }
    // SAFETY: kill(0, ...) signals the caller's group, so it is used only after checking that the
    // guard leads its own group. The guard dies with the group.
    unsafe {
        if libc::getpgrp() == libc::getpid() {
            libc::kill(0, libc::SIGKILL);
        }
        libc::_exit(0)
    }
}

/// Reads the program's process ID from sandy and opens a pidfd for it. `None` when the pipe ends
/// first (sandy ended or failed) or the pidfd cannot be opened; the guard then ends the group at
/// once.
fn read_program(end: &File) -> Option<RawFd> {
    let mut id = [0u8; mem::size_of::<libc::pid_t>()];
    let mut filled = 0;
    while filled < id.len() {
        // SAFETY: reads into the rest of `id`.
        let read = unsafe {
            libc::read(
                end.as_raw_fd(),
                id[filled..].as_mut_ptr().cast(),
                id.len() - filled,
            )
        };
        match read {
            0 => return None,
            read if read > 0 => filled += read as usize,
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            _ => return None,
        }
    }
    // sandy has not reaped the program, so the ID still names it.
    // SAFETY: pidfd_open takes a process ID and flags.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::pid_t::from_ne_bytes(id), 0) };
    (pidfd >= 0).then_some(pidfd as RawFd)
}

/// The forked child: joins the group, tells the guard its process ID, restores the signal state
/// the caller gave sandy, confines itself and executes the target. Reports a failure over
/// `report`.
fn program_main(
    group: &Group,
    signals: &Signals,
    child_action: &libc::sigaction,
    mut report: File,
    explained: bool,
    start: impl FnOnce() -> SandboxError,
) -> ! {
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if explained && let Err(error) = set_dumpable() {
            return error;
        }
        // SAFETY: setpgid takes process IDs.
        if unsafe { libc::setpgid(0, group.leader) } != 0 {
            return SandboxError::io(
                "cannot join the program's process group",
                io::Error::last_os_error(),
            );
        }
        // The child reports its own ID, and only now that it is in the group: see step 3 of the
        // module documentation.
        // SAFETY: getpid has no preconditions.
        let id = unsafe { libc::getpid() }.to_ne_bytes();
        let mut guard = &group.guard;
        if let Err(error) = guard.write_all(&id) {
            return SandboxError::io("cannot reach the guard", error);
        }
        // SAFETY: restores the action that `default_child_action` returned.
        if unsafe { libc::sigaction(libc::SIGCHLD, child_action, ptr::null_mut()) } != 0 {
            return SandboxError::io("cannot restore SIGCHLD", io::Error::last_os_error());
        }
        if let Err(error) = signals.unblock() {
            return error;
        }
        start()
    }));
    let error = started.unwrap_or_else(|_| SandboxError::new("starting the program panicked"));
    let _ = report.write_all(error.to_string().as_bytes());
    // SAFETY: ends the child without running sandy's cleanup.
    unsafe { libc::_exit(START_FAILED) }
}

/// The signals that sandy blocks and waits for, and the mask it had before.
struct Signals {
    blocked: libc::sigset_t,
    previous: libc::sigset_t,
}

impl Signals {
    /// Blocks every signal except the faults and SIGPIPE. Blocked signals stay pending until
    /// sandy waits for them, also when their action is to ignore them. SIGPIPE stays ignored, as
    /// the Rust runtime set it: a write of sandy's own whose reader has gone raises it, the
    /// status record's for one, and blocked it would wait here and reach the program as a
    /// forwarded signal.
    fn block() -> Result<Signals, SandboxError> {
        let failed = |error| SandboxError::io("cannot block signals", error);
        let (mut blocked, previous) = block_signals().map_err(failed)?;
        // SAFETY: sigset_t is plain data; the calls initialize and change the two sets, and
        // sigprocmask reads one of them.
        unsafe {
            let mut pipe: libc::sigset_t = mem::zeroed();
            libc::sigemptyset(&mut pipe);
            libc::sigaddset(&mut pipe, libc::SIGPIPE);
            libc::sigdelset(&mut blocked, libc::SIGPIPE);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &pipe, ptr::null_mut()) != 0 {
                return Err(failed(io::Error::last_os_error()));
            }
        }
        Ok(Signals { blocked, previous })
    }

    /// Restores the mask sandy had before `block`. execve keeps the mask.
    fn unblock(&self) -> Result<(), SandboxError> {
        // SAFETY: sets the mask from a valid sigset_t.
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.previous, ptr::null_mut()) } != 0 {
            return Err(SandboxError::io(
                "cannot restore the signal mask",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Waits for one of the blocked signals.
    fn wait(&self) -> Result<libc::c_int, SandboxError> {
        loop {
            // SAFETY: waits for a signal of a valid set; the details are not needed.
            let signal = unsafe { libc::sigwaitinfo(&self.blocked, ptr::null_mut()) };
            if signal > 0 {
                return Ok(signal);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(SandboxError::io("cannot wait for signals", error));
            }
        }
    }
}

/// What waitid reports about a child.
struct ChildState {
    pid: libc::pid_t,
    /// `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED` or `CLD_STOPPED`.
    code: libc::c_int,
    /// The exit status, or the signal number.
    status: libc::c_int,
}

/// The state of a child that `flags` select, without blocking. `None` when no child is in that
/// state.
fn waitable(
    which: libc::idtype_t,
    id: libc::id_t,
    flags: libc::c_int,
) -> Result<Option<ChildState>, SandboxError> {
    loop {
        // SAFETY: siginfo_t is plain data; zero means "no child" when waitid returns nothing.
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        // SAFETY: waitid writes into `info`.
        if unsafe { libc::waitid(which, id, &mut info, flags | libc::WNOHANG) } != 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => Ok(None),
                _ => Err(SandboxError::io(
                    "cannot wait for the program's processes",
                    error,
                )),
            };
        }
        // SAFETY: waitid filled in a SIGCHLD siginfo, or left it zeroed.
        let (pid, status) = unsafe { (info.si_pid(), info.si_status()) };
        return Ok((pid != 0).then_some(ChildState {
            pid,
            code: info.si_code,
            status,
        }));
    }
}

fn set_child_subreaper() -> Result<(), SandboxError> {
    // SAFETY: PR_SET_CHILD_SUBREAPER only sets a process flag.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(SandboxError::io(
            "cannot become a child subreaper",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// sandy must be able to wait for its children, which an ignored SIGCHLD (inherited from the
/// caller) prevents. Returns the previous action, which the program gets back.
pub(crate) fn default_child_action() -> Result<libc::sigaction, SandboxError> {
    // SAFETY: sigaction is plain data; the call reads `action` and writes `previous`.
    unsafe {
        let mut action: libc::sigaction = mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        let mut previous: libc::sigaction = mem::zeroed();
        if libc::sigaction(libc::SIGCHLD, &action, &mut previous) != 0 {
            return Err(SandboxError::io(
                "cannot reset SIGCHLD",
                io::Error::last_os_error(),
            ));
        }
        Ok(previous)
    }
}

/// The first standard descriptor that is sandy's controlling terminal. tcgetpgrp fails for every
/// other descriptor.
fn controlling_terminal() -> Option<RawFd> {
    // SAFETY: tcgetpgrp takes a descriptor.
    (0..=2).find(|&fd| unsafe { libc::tcgetpgrp(fd) } > 0)
}
