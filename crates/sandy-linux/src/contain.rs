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
//!    group, so a kill of the group reaches it from the moment the guard knows it. The guard also
//!    holds a pidfd for each helper that serves the program (`Helper`: the relay of exposed or
//!    forwarded ports, the egress broker), and when one of them ends while the program runs, it
//!    tells sandy which over a pipe of its own and kills the group too.
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
//!    signal ended it. If the guard reported that a helper ended first, sandy fails instead.
//!
//! The group's ID is the guard's process ID. sandy reaps neither the guard nor the program before
//! it has killed the group, so no other process can have these IDs while sandy may signal them.
//!
//! sandy makes itself undumpable before it forks the guard and the program, so that both start
//! undumpable and a program with a write grant on `/proc` never has a moment to raise the
//! `oom_score_adj` of sandy or the guard and have the kernel end them under memory pressure. The
//! kernel makes the program dumpable again when it executes the target.
//!
//! Where the host gives sandy a user namespace (`plan`), the program also runs in a PID namespace
//! of its own, which ends every process in it when its first process, the init, ends:
//!
//! - The forked child enters the namespaces with `CLONE_NEWPID` and then forks twice (`Split`):
//!   first the init, which becomes PID 1, then the program, which becomes PID 2 and leads a
//!   process group of its own. The child tells the guard and sandy both process IDs and ends; as
//!   child subreaper sandy becomes the parent of both, so it follows the program's stops for job
//!   control as before. The program, not PID 1, gets the signals sandy forwards: a PID 1 ignores
//!   every signal it has no handler for.
//! - The init (`init_main`) reaps the namespace's orphans and ends when the program or sandy ends,
//!   through pidfds of both. The guard watches the program and sandy as before and kills the init
//!   through a pidfd, which ends the namespace.
//! - The guard is outside the program's group and outside the namespace, and so are sandy and its
//!   own group, so the program reaches none of them with a signal, by process ID or by group.
//!   That is what makes `signals = "isolated"` hold on kernels without the Landlock signal scope.
//! - The seccomp filter still denies setsid and setpgid, so every process of the program stays in
//!   its group, which takes the terminal's job control signals.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;

use sandy_core::{SandboxError, StatusReport};

use crate::explain::Explain;
use crate::helper::{
    block_signals, close_descriptors_except, pidfd_open, pipe, set_dumpable, set_undumpable,
};
use crate::launch::ensure_single_thread;
use crate::namespace;

/// Shells report a program that a signal ended with this status plus the signal number.
pub(crate) const SIGNALED: i32 = 128;
/// The forked child's exit status when it cannot start the program. sandy reports the message
/// from the pipe instead.
pub(crate) const START_FAILED: i32 = 125;

/// A helper process outside the sandbox that serves the program, which the guard watches: when
/// it ends while the program runs, the guard ends the group and sandy fails with `failure`.
pub struct Helper {
    pub pidfd: OwnedFd,
    pub failure: &'static str,
}

/// Starts the program in a process group that sandy ends when the program ends, and returns the
/// exit status for sandy. `start` runs in the forked child: it confines the child and executes
/// the target, and returns only on failure.
/// `ended` is the write end of the helpers' pipe, if a helper runs: only the guard keeps it, so
/// it ends when the guard has ended the group. The guard watches `helpers`.
/// `explain` is the diagnostic mode, which watches the program from here because sandy is
/// already its parent. With `pid_namespace` the forked child enters a PID namespace, and `start`
/// gets the `Split` that forks the init and the program into it.
pub fn run(
    start: impl FnOnce(Option<&Split>) -> SandboxError,
    ended: Option<File>,
    helpers: Vec<Helper>,
    status: &StatusReport,
    mut explain: Option<&mut Explain>,
    pid_namespace: bool,
) -> Result<i32, SandboxError> {
    ensure_single_thread()?;
    set_child_subreaper()?;
    // Before the forks: a flag set after a fork would leave the child's program a moment to
    // raise the out-of-memory priority of the process that sets it.
    set_undumpable()?;
    let child_action = default_child_action()?;
    let signals = Signals::block()?;
    let mut group = Group::start(ended, helpers, pid_namespace)?;
    let (mut report, report_write) = pipe("the program's report pipe")?;
    let split = match pid_namespace {
        true => {
            let (read, write) = pipe("the pipe of the program's process IDs")?;
            // SAFETY: getpid has no preconditions.
            let sandy = pidfd_open(unsafe { libc::getpid() }, "sandy")?;
            Some((read, write, sandy))
        }
        false => None,
    };
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
            let split = split.map(|(read, supervisor, sandy)| {
                drop(read);
                Split {
                    guard: &group.to_guard,
                    supervisor,
                    sandy,
                }
            });
            program_main(
                &group,
                &signals,
                &child_action,
                report_write,
                explained,
                split.as_ref(),
                start,
            )
        }
        // Without a PID namespace the forked child becomes the program.
        pid if split.is_none() => {
            // What the child needed is the child's now: a copy kept here would hold the
            // helpers' handover and factory sockets open after the child is gone.
            drop(start);
            group.program = Some(pid);
        }
        _ => drop(start),
    }
    drop(report_write);
    // Before the report is read: the execve that ends the report pipe is a watched call and
    // waits for the watcher.
    if let Some(explain) = &mut explain {
        explain.start()?;
    }
    if let Some((read, write, sandy)) = split {
        drop((write, sandy));
        // The child ends after it reported, or fails and reports why below.
        if let Some([program, init]) = read_ids(&read) {
            group.program = Some(program);
            group.init = Some(init);
            group.group = program;
        }
    }
    let mut message = Vec::new();
    report
        .read_to_end(&mut message)
        .map_err(|error| SandboxError::io("cannot read the program's report", error))?;
    if !message.is_empty() {
        return Err(SandboxError::new(String::from_utf8_lossy(&message)));
    }
    let Some(program) = group.program else {
        return Err(SandboxError::new(
            "the program's process ended before it reported its process ID",
        ));
    };
    // The program has started: the report pipe reached its end without a message, which only
    // execve does.
    status.started(program as u32);
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

/// The program's process group, and the guard. Dropping it ends the group, so a failure after the
/// guard started also ends everything sandy started.
struct Group {
    /// The guard's process ID.
    guard: libc::pid_t,
    /// The ID of the program's process group. Without a PID namespace the guard leads the group,
    /// so this is the guard's ID. In one the program leads a group of its own; until sandy knows
    /// the program, this is the guard's group, which holds the guard alone.
    group: libc::pid_t,
    program: Option<libc::pid_t>,
    /// The init of the program's PID namespace, whose end ends every process in it.
    init: Option<libc::pid_t>,
    /// sandy's controlling terminal, if one of its standard descriptors is that terminal.
    terminal: Option<RawFd>,
    /// sandy gave the terminal to the program's group, and should give it again after a stop.
    program_has_terminal: bool,
    /// The write end of the guard's pipe. The forked program writes its process ID into it, and
    /// sandy holds it open, so that its close tells the guard that sandy is gone.
    to_guard: File,
    /// With helpers, the read end of the pipe over which the guard reports the index of the
    /// one that ended first.
    helper_report: Option<File>,
    /// Why sandy fails when each of the helpers ended first, in the guard's order.
    helper_failures: Vec<&'static str>,
    ended: bool,
}

impl Group {
    fn start(
        ended: Option<File>,
        helpers: Vec<Helper>,
        pid_namespace: bool,
    ) -> Result<Group, SandboxError> {
        let (guard_end, to_guard) = pipe("the guard's pipe")?;
        let (helper_report, guard_report) = if helpers.is_empty() {
            (None, None)
        } else {
            let (read, write) = pipe("the guard's report pipe")?;
            (Some(read), Some(write))
        };
        let (pidfds, helper_failures): (Vec<OwnedFd>, Vec<&'static str>) = helpers
            .into_iter()
            .map(|helper| (helper.pidfd, helper.failure))
            .unzip();
        // SAFETY: sandy is single-threaded (checked in `run`). The guard leaves only through
        // `_exit`.
        let guard = match unsafe { libc::fork() } {
            -1 => {
                return Err(SandboxError::io(
                    "cannot fork the guard",
                    io::Error::last_os_error(),
                ));
            }
            0 => {
                drop(to_guard);
                drop(helper_report);
                guard_main(guard_end, ended, pidfds, guard_report, pid_namespace)
            }
            pid => pid,
        };
        drop(guard_end);
        drop((ended, pidfds, guard_report));
        let group = Group {
            guard,
            group: guard,
            program: None,
            init: None,
            terminal: controlling_terminal(),
            program_has_terminal: false,
            to_guard,
            helper_report,
            helper_failures,
            ended: false,
        };
        // The guard sets its group too. Setting it here as well means the group exists before
        // sandy continues, whichever process runs first.
        // SAFETY: setpgid takes two process IDs.
        if unsafe { libc::setpgid(guard, guard) } != 0 {
            return Err(SandboxError::io(
                "cannot create the program's process group",
                io::Error::last_os_error(),
            ));
        }
        Ok(group)
    }

    /// Forwards signals and follows the program until it exits. Returns how it ended.
    ///
    /// A helper that is gone takes what it served with it: a relay leaves its ports to whatever
    /// binds them next, and a local user who binds the program's forward port receives what the
    /// program sends there; the egress broker leaves the program without its way out. So the
    /// guard ends the program with it, and sandy reports that as its own failure. The guard
    /// reports before it kills the group, so the report is there once sandy sees the program or
    /// the guard end; the guard is in the group, so it can end before the program.
    fn supervise(&mut self, signals: &Signals) -> Result<ChildState, SandboxError> {
        let program = self.program.expect("the program was started");
        loop {
            let exited = self.reap_others(program);
            if !matches!(exited, Ok(None))
                && let Some(failure) = self.helper_ended()
            {
                return Err(SandboxError::new(failure));
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

    /// Why sandy fails, when the guard ended the group because a helper ended while the program
    /// ran.
    fn helper_ended(&self) -> Option<&'static str> {
        let report = self.helper_report.as_ref()?;
        let mut poll = libc::pollfd {
            fd: report.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, and a zero timeout does not block.
        if unsafe { libc::poll(&mut poll, 1, 0) } <= 0 {
            return None;
        }
        let mut index = [0u8; 1];
        match (&*report).read(&mut index) {
            Ok(1) => self.helper_failures.get(usize::from(index[0])).copied(),
            _ => None,
        }
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
            if child.pid == self.guard || Some(child.pid) == self.init {
                // The guard and the init end once the program has exited; both are older, so
                // waitid reports them first. They are not reaped before the group is killed.
                return match program_exited()? {
                    Some(exited) => Ok(Some(exited)),
                    None if child.pid == self.guard => Err(SandboxError::new(
                        "the guard of the program's process group ended unexpectedly",
                    )),
                    None => Err(SandboxError::new(
                        "the init of the program's PID namespace ended unexpectedly",
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
            unsafe { libc::kill(-self.group, libc::SIGCONT) };
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
        unsafe { libc::kill(-self.group, libc::SIGCONT) };
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
                && libc::tcsetpgrp(terminal, self.group) == 0
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
            libc::tcgetpgrp(terminal) == self.group
                && libc::tcsetpgrp(terminal, libc::getpgrp()) == 0
        }
    }

    /// Kills the group, the guard, the program and the init, and reaps them.
    fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        self.take_terminal();
        // SAFETY: kill takes process and group IDs. sandy has reaped none of the guard, the
        // program and the init, so these IDs still belong to them. The guard and the program are
        // killed by ID as well, in case either never joined the group.
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
            libc::kill(self.guard, libc::SIGKILL);
            for process in [self.program, self.init].into_iter().flatten() {
                libc::kill(process, libc::SIGKILL);
            }
        }
        // Every process the program started is in the group, and a member whose parent ends is
        // re-parented to sandy before that parent can be reaped, so ECHILD means the group is
        // gone. In a PID namespace they are re-parented to the init instead, and the kernel ends
        // them with it. Other children of sandy (inherited across execve, or the relay when
        // sandy's caller made it a subreaper) are not waited for.
        loop {
            // SAFETY: waits for a child in the group; the status is not needed.
            if unsafe { libc::waitpid(-self.group, ptr::null_mut(), 0) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
        // In a PID namespace neither the guard nor the init is in the program's group.
        let outside = [self.guard, self.init.unwrap_or(self.guard)];
        for process in outside.into_iter().filter(|_| self.group != self.guard) {
            // SAFETY: waits for a child killed above; the status is not needed.
            while unsafe { libc::waitpid(process, ptr::null_mut(), 0) } < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.end();
    }
}

/// The guard: kills the program's processes when the program ends, sandy ends or a helper ends.
/// Without a PID namespace it leads the program's process group and kills the group; in one it
/// kills the init, which ends the namespace. `ended`, the helpers' pipe, closes when the guard
/// dies. `helpers` are pidfds for the helpers, and `report` the pipe that tells sandy which of
/// them ended first.
fn guard_main(
    end: File,
    ended: Option<File>,
    helpers: Vec<OwnedFd>,
    report: Option<File>,
    pid_namespace: bool,
) -> ! {
    let mut keep = vec![end.as_raw_fd()];
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    keep.extend(helpers.iter().map(AsRawFd::as_raw_fd));
    keep.extend(report.as_ref().map(AsRawFd::as_raw_fd));
    // SAFETY: setpgid takes process IDs.
    if unsafe { libc::setpgid(0, 0) } != 0 || close_descriptors_except(&keep).is_err() {
        // SAFETY: ends the guard without running sandy's cleanup. sandy kills the group by ID.
        unsafe { libc::_exit(1) };
    }
    // sandy has reaped neither the program nor the init, so the IDs still name them.
    let program = read_ids::<1>(&end).and_then(|[program]| pidfd_open(program, "the program").ok());
    let init = match pid_namespace {
        true => read_ids::<1>(&end).and_then(|[init]| pidfd_open(init, "the init").ok()),
        false => None,
    };
    if let Some(program) = &program {
        let mut polls: Vec<libc::pollfd> = [end.as_raw_fd(), program.as_raw_fd()]
            .into_iter()
            .chain(helpers.iter().map(AsRawFd::as_raw_fd))
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: polls open descriptors; returns when sandy, the program or a helper ends.
        while unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
        // A helper that ended in the same look as the program or sandy is the end of a run.
        let ended: Vec<bool> = polls.iter().map(|poll| poll.revents != 0).collect();
        let helper = ended[2..].iter().position(|&ended| ended);
        if let (Some(index), false, false) = (helper, ended[0], ended[1]) {
            // Before the kill, so that sandy finds the report once it sees the group end.
            if let Some(mut report) = report {
                let _ = report.write_all(&[index as u8]);
            }
        }
    }
    if pid_namespace {
        if let Some(init) = init {
            // SAFETY: pidfd_send_signal takes a pidfd, a signal, no information and no flags.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    init.as_raw_fd(),
                    libc::SIGKILL,
                    ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
        }
        // SAFETY: ends the guard without running sandy's cleanup.
        unsafe { libc::_exit(0) }
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

/// Reads `N` process IDs from `pipe`. `None` when the pipe ends first: the writer ended or
/// failed.
fn read_ids<const N: usize>(pipe: &File) -> Option<[libc::pid_t; N]> {
    const SIZE: usize = mem::size_of::<libc::pid_t>();
    let mut bytes = [[0u8; SIZE]; N];
    for id in &mut bytes {
        let mut filled = 0;
        while filled < SIZE {
            // SAFETY: reads into the rest of `id`.
            let read = unsafe {
                libc::read(
                    pipe.as_raw_fd(),
                    id[filled..].as_mut_ptr().cast(),
                    SIZE - filled,
                )
            };
            match read {
                0 => return None,
                read if read > 0 => filled += read as usize,
                _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                _ => return None,
            }
        }
    }
    Some(bytes.map(libc::pid_t::from_ne_bytes))
}

/// The forked child: without a PID namespace it joins the group and tells the guard its process
/// ID; then it restores the signal state the caller gave sandy, and in `start` confines itself and
/// executes the target. In a PID namespace `start` splits it with `split` first. Reports a failure
/// over `report`.
fn program_main(
    group: &Group,
    signals: &Signals,
    child_action: &libc::sigaction,
    mut report: File,
    explained: bool,
    split: Option<&Split>,
    start: impl FnOnce(Option<&Split>) -> SandboxError,
) -> ! {
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if explained && let Err(error) = set_dumpable() {
            return error;
        }
        if split.is_none() {
            // SAFETY: setpgid takes process IDs.
            if unsafe { libc::setpgid(0, group.guard) } != 0 {
                return SandboxError::io(
                    "cannot join the program's process group",
                    io::Error::last_os_error(),
                );
            }
            // The child reports its own ID, and only now that it is in the group: see step 3 of
            // the module documentation.
            // SAFETY: getpid has no preconditions.
            if let Err(error) = write_ids(&group.to_guard, &[unsafe { libc::getpid() }]) {
                return SandboxError::io("cannot reach the guard", error);
            }
        }
        // SAFETY: restores the action that `default_child_action` returned.
        if unsafe { libc::sigaction(libc::SIGCHLD, child_action, ptr::null_mut()) } != 0 {
            return SandboxError::io("cannot restore SIGCHLD", io::Error::last_os_error());
        }
        if let Err(error) = signals.unblock() {
            return error;
        }
        start(split)
    }));
    let error = started.unwrap_or_else(|_| SandboxError::new("starting the program panicked"));
    let _ = report.write_all(error.to_string().as_bytes());
    // SAFETY: ends the child without running sandy's cleanup.
    unsafe { libc::_exit(START_FAILED) }
}

fn write_ids(mut pipe: &File, ids: &[libc::pid_t]) -> io::Result<()> {
    let bytes: Vec<u8> = ids.iter().flat_map(|id| id.to_ne_bytes()).collect();
    pipe.write_all(&bytes)
}

/// What the forked child needs to split itself into the init and the program of the PID namespace
/// it entered: the guard's pipe, the pipe to sandy for both process IDs, and a pidfd of sandy for
/// the init.
pub struct Split<'a> {
    guard: &'a File,
    supervisor: File,
    sandy: OwnedFd,
}

impl Split<'_> {
    /// Forks the init, which becomes PID 1 of the namespace this process entered with
    /// `CLONE_NEWPID`, and then the program, PID 2, which leads a process group of its own. This
    /// process tells the guard and sandy both IDs and ends, so sandy, the child subreaper, becomes
    /// the parent of both; the init learns from the end of its pipe that the program exists.
    /// Returns only in the program. The namespace's capabilities stay with the program, which
    /// builds the file system view and drops them later.
    pub fn run(&self) -> Result<(), SandboxError> {
        let (exists, exists_write) = pipe("the init's pipe")?;
        // SAFETY: this process has one thread (`Namespaces::enter` checked), so both children
        // may run any code; the init leaves only through `_exit`.
        let init = match unsafe { libc::fork() } {
            -1 => {
                return Err(SandboxError::io(
                    "cannot fork the init of the PID namespace",
                    io::Error::last_os_error(),
                ));
            }
            0 => {
                drop(exists_write);
                init_main(exists, &self.sandy)
            }
            init => init,
        };
        drop(exists);
        // SAFETY: as above.
        let program = match unsafe { libc::fork() } {
            -1 => {
                return Err(SandboxError::io(
                    "cannot fork the program into the PID namespace",
                    io::Error::last_os_error(),
                ));
            }
            0 => {
                drop(exists_write);
                // Out of sandy's group, which is its caller's job: the program's signals to its
                // own group must reach only its own processes.
                // SAFETY: setpgid takes process IDs.
                if unsafe { libc::setpgid(0, 0) } != 0 {
                    return Err(SandboxError::io(
                        "cannot create the program's process group",
                        io::Error::last_os_error(),
                    ));
                }
                return Ok(());
            }
            program => program,
        };
        // The guard first: it learns the IDs even if sandy never runs again.
        let ids = [program, init];
        if let Err(error) =
            write_ids(self.guard, &ids).and_then(|()| write_ids(&self.supervisor, &ids))
        {
            return Err(SandboxError::io(
                "cannot report the program's process IDs",
                error,
            ));
        }
        // SAFETY: ends this process without running sandy's cleanup; its children are re-parented
        // to sandy, and the init sees its pipe end.
        unsafe { libc::_exit(0) }
    }
}

/// PID 1 of the program's PID namespace. The kernel ends every process of the namespace when it
/// ends, so it stays until the program or sandy ends: it waits for its pipe to end, which means
/// the program exists or never will, and then polls pidfds of both. The kernel re-parents the
/// namespace's orphans to it, and with SIGCHLD ignored it reaps them as they end. A PID 1 receives
/// a signal from inside its namespace only through a handler, and from outside only SIGKILL and
/// SIGSTOP without one, so it installs none.
fn init_main(exists: File, sandy: &OwnedFd) -> ! {
    let started = || -> Result<(), SandboxError> {
        // Out of sandy's group, which is its caller's job.
        // SAFETY: setpgid takes process IDs.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(SandboxError::io("setpgid", io::Error::last_os_error()));
        }
        // Not in the old root, which a file system view detaches.
        std::env::set_current_dir("/").map_err(|error| SandboxError::io("chdir", error))?;
        close_descriptors_except(&[exists.as_raw_fd(), sandy.as_raw_fd()])?;
        default_signal_actions()?;
        namespace::drop_capabilities()?;
        set_undumpable()?;
        let mut byte = [0u8; 1];
        loop {
            match (&exists).read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(SandboxError::io("read", error)),
            }
        }
        // The program is PID 2: this process is PID 1, and the program is the next one forked.
        let program = pidfd_open(2, "the program")?;
        let mut polls = [sandy.as_raw_fd(), program.as_raw_fd()].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: polls two open descriptors; returns when sandy or the program ends.
        while unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
        Ok(())
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(started));
    // SAFETY: ends the init, and with it the namespace, without running sandy's cleanup.
    unsafe { libc::_exit(0) }
}

/// Every signal to its default action, SIGCHLD to ignored, so that ended children are reaped
/// without a wait, and an empty mask.
fn default_signal_actions() -> Result<(), SandboxError> {
    // SAFETY: sigaction and sigset_t are plain data; the calls only change this process's
    // signal state.
    unsafe {
        let mut action: libc::sigaction = mem::zeroed();
        for signal in 1..libc::SIGRTMAX() {
            if matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
                continue;
            }
            action.sa_sigaction = match signal {
                libc::SIGCHLD => libc::SIG_IGN,
                _ => libc::SIG_DFL,
            };
            // A number the C library keeps for itself fails; it has its own action.
            libc::sigaction(signal, &action, ptr::null_mut());
        }
        let mut empty: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut empty);
        if libc::sigprocmask(libc::SIG_SETMASK, &empty, ptr::null_mut()) != 0 {
            return Err(SandboxError::io("sigprocmask", io::Error::last_os_error()));
        }
    }
    Ok(())
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
