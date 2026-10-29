//! `process.children = "contained"`. sandy stays the parent of the program, so that it can end
//! every process the program starts:
//!
//! 1. sandy closes every descriptor it inherited except 0, 1 and 2, keeping only its own: the
//!    status record's and the helpers' pipe. It catches every signal that macOS would discard
//!    while it is blocked (those whose action is to ignore them, by default or set by the
//!    caller), blocks the signals it forwards and waits for them with sigwait.
//! 2. It forks the guard, which starts a process group of its own and forks the anchor. The
//!    anchor leads the program's process group and only waits to be killed; it is the guard's
//!    child, so the group's ID stays reserved until the guard reaps it. The guard keeps only its
//!    pipes from and to sandy and, with a relay or an egress broker, the write end of the pipe
//!    that tells them that the group has ended.
//! 3. It forks the program. The program joins the anchor's group and then sends its own process
//!    ID to the guard, so that the guard learns it even if sandy never runs again after the fork,
//!    and learns it only once the program is in the group, so a kill of the group reaches it from
//!    the moment the guard knows it. The program keeps a copy of the write end of that pipe until
//!    execve closes it, so the pipe ends only once sandy is gone and the program has started or
//!    ended. The guard watches the program and the pipe from sandy with kqueue. When the program
//!    ends or the pipe ends, that is when sandy dies, also by SIGKILL, or is done, the guard
//!    kills the group with SIGKILL until no live process is left in it. The guard is not in the
//!    group, so it can repeat the signal: on macOS a process forked while a group signal is
//!    delivered can escape one signal. So the group ends with the program also while sandy is
//!    stopped. Then it closes the helpers' pipe, waits until sandy is done, reaps the anchor and
//!    ends. The guard watches the relay and the egress broker too, and when one of them ends
//!    while the program runs, it tells sandy which and ends the group in the same way.
//! 4. The program applies the profile and executes the target with execve; it reports a failure
//!    over a close-on-exec pipe. The profile denies setpgid, setsid and posix_spawn, whose
//!    POSIX_SPAWN_SETSID and POSIX_SPAWN_SETPGROUP flags would change the group inside the
//!    kernel, so no process it starts can leave the group. With `signals = "isolated"` (which the
//!    policy requires) it cannot signal sandy, the guard or the anchor, which run outside the
//!    sandbox.
//! 5. sandy forwards the signals it receives to the program and reaps its exited children. With
//!    a terminal it follows job control. The program's group gets the terminal only when the
//!    program stops because it used the terminal while sandy's job had it; another process of
//!    sandy's job that then uses the terminal gets it back. Any other stop of the program stops
//!    sandy too, so a shell sees the job stop; when sandy continues, it continues the group.
//! 6. When the program exits, sandy gives the terminal back, kills the group with SIGKILL until
//!    no live process is left in it, tells the guard that it is done, reaps the guard and the
//!    program, and exits with the program's exit status, or 128 plus the signal number if a
//!    signal ended it. If the guard reported that a helper ended first, sandy fails instead.
//!
//! macOS has no child subreaper: launchd adopts a process whose parent ends, so neither sandy nor
//! the guard can wait for the processes of the group. Instead they repeat the SIGKILL until the
//! kernel finds no live process in the group (zombies do not count). The group's ID is the
//! anchor's process ID, and the guard reaps the anchor only after sandy is done or gone, so no
//! other group can have this ID while either may signal it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::Duration;

use sandy_core::{SandboxError, StatusReport};

use super::helper::{
    NO_EVENT, block_signals, close_all_except, new_queue, pipe, register, require_single_thread,
    wait_events,
};

/// Shells report a program that a signal ended with this status plus the signal number.
const SIGNALED: i32 = 128;
/// The forked child's exit status when it cannot start the program. sandy reports the message
/// from the pipe instead.
const START_FAILED: i32 = 125;
/// A helper of the program that the guard watches, the relay or the egress broker. Without it
/// the ports it served would be left to whatever binds them next.
#[derive(Debug, Clone, Copy)]
pub struct Helper {
    pub pid: libc::pid_t,
    /// What it is, for the message when it ends first.
    pub name: &'static str,
}
/// How long sandy waits between two SIGKILLs to the group while processes of it are left.
const KILL_POLL: Duration = Duration::from_millis(10);
/// Signals whose default action is to ignore them. macOS discards a signal on arrival while its
/// action is to ignore it, even when it is blocked, so sandy catches these and every signal that
/// the caller set to be ignored, to wait for them.
const DISCARDED_BY_DEFAULT: [libc::c_int; 5] = [
    libc::SIGCHLD,
    libc::SIGURG,
    libc::SIGIO,
    libc::SIGWINCH,
    libc::SIGINFO,
];
/// NSIG of macOS (`sys/signal.h`): signal numbers are 1 to 31.
const SIGNAL_COUNT: libc::c_int = 32;
/// Signals sandy never catches: SIGKILL and SIGSTOP cannot be caught, SIGCONT is never discarded,
/// SIGPIPE stays ignored (`Signals::block`), and the fault signals keep their action, so that a
/// fault ends sandy.
const NOT_CAUGHT: [libc::c_int; 11] = [
    libc::SIGKILL,
    libc::SIGSTOP,
    libc::SIGCONT,
    libc::SIGPIPE,
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
    libc::SIGSYS,
    libc::SIGABRT,
];

/// Starts the program in a process group that sandy ends when the program ends, and returns the
/// exit status for sandy. `start` runs in the forked child: it confines the child and executes
/// the target, and returns only on failure. `ended` is the write end of the helpers' pipe, if a
/// helper runs: the guard closes it once the group has ended. The guard watches the `helpers`.
pub fn run(
    start: impl FnOnce() -> SandboxError,
    ended: Option<File>,
    helpers: Vec<Helper>,
    status: &StatusReport,
) -> Result<i32, SandboxError> {
    require_single_thread()?;
    // sandy waits for the program as long as it runs, but needs nothing it inherited beyond the
    // standard descriptors, and neither the program nor the helpers get any of it. A socket that
    // the caller let sandy inherit would otherwise stay open with it, a port bound, until the
    // program ends.
    let mut keep = vec![0, 1, 2];
    keep.extend(status.descriptor());
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    close_all_except(&keep)
        .map_err(|error| SandboxError::io("cannot close the descriptors sandy inherited", error))?;
    let actions = CaughtSignals::catch()?;
    let signals = Signals::block()?;
    let mut group = Group::start(ended, helpers)?;
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
            program_main(&group, &signals, &actions, report_write, start)
        }
        pid => group.program = Some(pid),
    }
    drop(report_write);
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

/// The program's process group, led by the anchor, which the guard started. Dropping it ends the
/// group, so a failure after the guard started also ends everything sandy started.
struct Group {
    /// The group's ID: the anchor's process ID.
    id: libc::pid_t,
    guard: libc::pid_t,
    program: Option<libc::pid_t>,
    /// sandy's controlling terminal, if one of its standard descriptors is that terminal.
    terminal: Option<RawFd>,
    /// sandy gave the terminal to the program's group, and should give it again after a stop.
    program_has_terminal: bool,
    /// The write end of the pipe to the guard. The forked program writes its process ID into it;
    /// closing it tells the guard that sandy is done.
    to_guard: Option<File>,
    /// The read end of the pipe from the guard: the group's ID, then the index of a helper if the
    /// guard ended the group because that helper ended.
    from_guard: File,
    helpers: Vec<Helper>,
    ended: bool,
}

impl Group {
    fn start(ended: Option<File>, helpers: Vec<Helper>) -> Result<Group, SandboxError> {
        let watched: Vec<libc::pid_t> = helpers.iter().map(|helper| helper.pid).collect();
        let (guard_reads, to_guard) = pipe("the pipe to the guard")?;
        let (from_guard, guard_writes) = pipe("the pipe from the guard")?;
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
                drop(from_guard);
                guard_main(guard_reads, guard_writes, ended, &watched)
            }
            pid => pid,
        };
        drop(guard_reads);
        drop(guard_writes);
        drop(ended);
        let mut group = Group {
            id: 0,
            guard,
            program: None,
            terminal: controlling_terminal(),
            program_has_terminal: false,
            to_guard: Some(to_guard),
            from_guard,
            helpers,
            ended: false,
        };
        let mut id = [0u8; mem::size_of::<libc::pid_t>()];
        if group.from_guard.read_exact(&mut id).is_err() {
            return Err(SandboxError::new(
                "the guard could not create the program's process group",
            ));
        }
        group.id = libc::pid_t::from_ne_bytes(id);
        Ok(group)
    }

    /// Forwards signals and follows the program until it exits. Returns how it ended.
    ///
    /// A relay or a broker that is gone leaves its ports to whatever binds them next, and a local
    /// user who binds the program's forward or egress port receives what the program sends there,
    /// so the guard ends the program with it, and sandy reports that as its own failure.
    fn supervise(&mut self, signals: &Signals) -> Result<ChildState, SandboxError> {
        let program = self.program.expect("the program was started");
        loop {
            if let Some(exited) = self.reap_others(program)? {
                if let Some(helper) = self.helper_ended() {
                    return Err(SandboxError::new(format!(
                        "{} ended before the program; the ports it served are gone and the \
                         program has been ended with it",
                        helper.name
                    )));
                }
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

    /// The helper whose end made the guard end the group while the program ran, if one did. The
    /// guard reports it before it kills the group, so the report is there once sandy sees the
    /// program end.
    fn helper_ended(&self) -> Option<Helper> {
        let mut poll = libc::pollfd {
            fd: self.from_guard.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, and a zero timeout does not block.
        if unsafe { libc::poll(&mut poll, 1, 0) } <= 0 {
            return None;
        }
        let mut report = [0u8; 1];
        match (&self.from_guard).read(&mut report) {
            Ok(1) => self.helpers.get(usize::from(report[0])).copied(),
            _ => None,
        }
    }

    /// Reaps every exited child except the program and the guard. Returns the program's state
    /// once it has exited, without reaping it.
    ///
    /// macOS can answer these `WEXITED` queries with a child that only stopped: `CLD_STOPPED`
    /// with SIGTTIN for a program that read the terminal at once (measured on the macOS 15.7.9
    /// runner, in 3 of 150 runs of the children_macos tests). Such an answer is no exit. The stop
    /// reaches sandy as SIGCHLD, and `follow_program` handles it.
    fn reap_others(&self, program: libc::pid_t) -> Result<Option<ChildState>, SandboxError> {
        let program_exited = || {
            Ok(waitable(
                libc::P_PID,
                program as libc::id_t,
                libc::WEXITED | libc::WNOWAIT,
            )?
            .filter(ChildState::exited))
        };
        while let Some(child) = waitable(libc::P_ALL, 0, libc::WEXITED | libc::WNOWAIT)? {
            if !child.exited() {
                // The query answers with that child until it runs again, so ask for the program
                // by itself.
                return program_exited();
            }
            if child.pid == program {
                return Ok(Some(child));
            }
            if child.pid == self.guard {
                // The guard waits for sandy before it ends, so it ends early only when someone
                // killed it.
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
            unsafe { libc::kill(-self.id, libc::SIGCONT) };
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
        unsafe { libc::kill(-self.id, libc::SIGCONT) };
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
            libc::tcgetpgrp(terminal) == libc::getpgrp() && libc::tcsetpgrp(terminal, self.id) == 0
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
            libc::tcgetpgrp(terminal) == self.id && libc::tcsetpgrp(terminal, libc::getpgrp()) == 0
        }
    }

    /// Kills the group until no live process of it is left, tells the guard that sandy is done,
    /// and reaps the guard and the program.
    fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        self.take_terminal();
        if let Some(program) = self.program {
            // SAFETY: kill takes a process ID; sandy has not reaped the program, so the ID still
            // names it. It is killed by ID as well, in case it never joined the group.
            unsafe { libc::kill(program, libc::SIGKILL) };
        }
        if self.id > 0 {
            kill_group(self.id);
        }
        // The guard reaps the anchor, and with it frees the group's ID, only after this.
        drop(self.to_guard.take());
        for child in [Some(self.guard), self.program].into_iter().flatten() {
            // SAFETY: reaps a child of sandy that has ended or ends now; the status is not
            // needed.
            while unsafe { libc::waitpid(child, ptr::null_mut(), 0) } < 0
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.end();
    }
}

/// Sends SIGKILL to group `id` until no live process is left in it. kill fails with ESRCH when
/// the group has no process, and with EPERM when it has only zombies, for example a process whose
/// parent died a moment ago and that launchd has not reaped yet. A process forked while the signal
/// was delivered gets the next one. The caller must keep the group's ID reserved (the anchor
/// unreaped) during the call.
fn kill_group(id: libc::pid_t) {
    // SAFETY: kill takes a process group ID; see above.
    while unsafe { libc::kill(-id, libc::SIGKILL) } == 0 {
        std::thread::sleep(KILL_POLL);
    }
}

/// The guard: starts the anchor, which leads the program's group, and kills the group when the
/// program ends, sandy ends or a helper ends. `from_sandy` brings the program's process ID and
/// ends when sandy is done or gone; `to_sandy` takes the group's ID and the index of a helper
/// that ended; `ended` is the helpers' pipe, and `helpers` their process IDs.
fn guard_main(
    from_sandy: File,
    mut to_sandy: File,
    ended: Option<File>,
    helpers: &[libc::pid_t],
) -> ! {
    let mut keep = vec![from_sandy.as_raw_fd(), to_sandy.as_raw_fd()];
    keep.extend(ended.as_ref().map(AsRawFd::as_raw_fd));
    // A group of its own: the guard is in neither sandy's job nor the program's group.
    // SAFETY: setpgid takes process IDs.
    if unsafe { libc::setpgid(0, 0) } != 0 || close_all_except(&keep).is_err() {
        // SAFETY: ends the guard without running sandy's cleanup; sandy reports the failure.
        unsafe { libc::_exit(1) };
    }
    // SAFETY: the guard is single-threaded, as sandy was when it forked. The anchor leaves only
    // by being killed or through `_exit`.
    let anchor = match unsafe { libc::fork() } {
        0 => anchor_main(),
        -1 => {
            // SAFETY: as above.
            unsafe { libc::_exit(1) }
        }
        pid => pid,
    };
    // The anchor sets its group too. Setting it here as well means the group exists before
    // sandy learns its ID, whichever process runs first.
    // SAFETY: setpgid takes process IDs.
    let created = unsafe { libc::setpgid(anchor, anchor) } == 0;
    if !created || to_sandy.write_all(&anchor.to_ne_bytes()).is_err() {
        // SAFETY: kills and reaps the anchor, which leads no group sandy knows.
        unsafe {
            libc::kill(anchor, libc::SIGKILL);
            libc::waitpid(anchor, ptr::null_mut(), 0);
            libc::_exit(1)
        }
    }
    let helper_ended = watch_program(&from_sandy).and_then(|queue| wait_for_end(&queue, helpers));
    if let Some(index) = helper_ended {
        // Before the kill, so that sandy finds the report once it sees the program end.
        let _ = to_sandy.write_all(&[index]);
    }
    drop(to_sandy);
    kill_group(anchor);
    drop(ended);
    // sandy may still signal the group, so its ID stays reserved until sandy is done or gone.
    let mut rest = [0u8; 64];
    loop {
        match (&from_sandy).read(&mut rest) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    // SAFETY: reaps the anchor, which the group's SIGKILL ended, and ends the guard.
    unsafe {
        libc::waitpid(anchor, ptr::null_mut(), 0);
        libc::_exit(0)
    }
}

/// The anchor: leads the program's process group and waits, with every signal blocked as in the
/// guard, until the group's SIGKILL ends it.
fn anchor_main() -> ! {
    // SAFETY: setpgid takes process IDs; the guard sets the same group, so a failure here is
    // harmless when the guard succeeds, and reported by the guard otherwise.
    unsafe { libc::setpgid(0, 0) };
    let _ = close_all_except(&[]);
    loop {
        // SAFETY: pause only waits; no unblocked signal can arrive except SIGKILL.
        unsafe { libc::pause() };
    }
}

/// Reads the program's process ID from sandy and registers the end of the program and of the
/// pipe in a kqueue. `None` when the pipe ends first (sandy ended or failed) or the registration
/// fails, also because the program has already ended; the guard then ends the group at once.
fn watch_program(end: &File) -> Option<OwnedFd> {
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
    let program = libc::pid_t::from_ne_bytes(id);
    let queue = new_queue().ok()?;
    register(&queue, program as usize, libc::EVFILT_PROC, libc::NOTE_EXIT).ok()?;
    register(&queue, end.as_raw_fd() as usize, libc::EVFILT_READ, 0).ok()?;
    Some(queue)
}

/// Waits until the program ends, the pipe from sandy ends, or a helper ends. Returns the index
/// of the helper that ended while the program ran and sandy was there. A helper that cannot be
/// registered has ended already, or cannot be watched, and counts as ended.
fn wait_for_end(queue: &OwnedFd, helpers: &[libc::pid_t]) -> Option<u8> {
    let helper_of = |event: &libc::kevent| {
        helpers
            .iter()
            .position(|pid| event.filter == libc::EVFILT_PROC && event.ident == *pid as usize)
    };
    let unwatched = helpers.iter().position(|pid| {
        register(queue, *pid as usize, libc::EVFILT_PROC, libc::NOTE_EXIT).is_err()
    });
    let mut events = [NO_EVENT; 4];
    let ended = match unwatched {
        Some(index) => index,
        // Any event is an end: the program's exit, the end of the pipe, or a helper's exit.
        None => match wait_events(queue, &mut events, None) {
            Ok(count) if count > 0 && events[..count].iter().all(|e| helper_of(e).is_some()) => {
                helper_of(&events[0])?
            }
            _ => return None,
        },
    };
    // Once more, so that a program that ended together with a helper is the end of a run and
    // not a failure.
    let count = wait_events(queue, &mut events, Some(Duration::ZERO)).unwrap_or(0);
    if events[..count].iter().all(|e| helper_of(e).is_some()) {
        u8::try_from(ended).ok()
    } else {
        None
    }
}

/// The forked child: joins the group, tells the guard its process ID, restores the signal state
/// the caller gave sandy, confines itself and executes the target. Reports a failure over
/// `report`.
fn program_main(
    group: &Group,
    signals: &Signals,
    actions: &CaughtSignals,
    mut report: File,
    start: impl FnOnce() -> SandboxError,
) -> ! {
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: setpgid takes process IDs.
        if unsafe { libc::setpgid(0, group.id) } != 0 {
            return SandboxError::io(
                "cannot join the program's process group",
                io::Error::last_os_error(),
            );
        }
        // The child reports its own ID, and only now that it is in the group: see step 3 of the
        // module documentation.
        // SAFETY: getpid has no preconditions.
        let id = unsafe { libc::getpid() }.to_ne_bytes();
        let mut to_guard = group.to_guard.as_ref().expect("sandy is not done");
        if let Err(error) = to_guard.write_all(&id) {
            return SandboxError::io("cannot reach the guard", error);
        }
        if let Err(error) = actions.restore() {
            return error;
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
    /// sandy waits for them; `CaughtSignals` keeps macOS from discarding the ones it would
    /// ignore. SIGPIPE stays ignored, as the Rust runtime set it: a write of sandy's own whose
    /// reader has gone raises it, the status record's for one, and blocked it would wait here and
    /// reach the program as a forwarded signal.
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

    fn wait(&self) -> Result<libc::c_int, SandboxError> {
        loop {
            let mut signal = 0;
            // SAFETY: waits for a signal of a valid set and writes its number into `signal`.
            match unsafe { libc::sigwait(&self.blocked, &mut signal) } {
                0 => return Ok(signal),
                libc::EINTR => {}
                error => {
                    return Err(SandboxError::io(
                        "cannot wait for signals",
                        io::Error::from_raw_os_error(error),
                    ));
                }
            }
        }
    }
}

/// The signals sandy caught, with their actions before. A caught signal is blocked and its
/// handler never runs; sandy needs it only pending. Catching SIGCHLD also keeps an ignored
/// SIGCHLD, inherited from the caller, from reaping the program before sandy sees its status.
struct CaughtSignals(Vec<(libc::c_int, libc::sigaction)>);

impl CaughtSignals {
    /// Catches every signal that macOS would discard while it is blocked: those whose action is
    /// to ignore them, by default (`DISCARDED_BY_DEFAULT`) or set by the caller.
    fn catch() -> Result<CaughtSignals, SandboxError> {
        let mut caught = Vec::new();
        for signal in 1..SIGNAL_COUNT {
            if NOT_CAUGHT.contains(&signal) {
                continue;
            }
            // SAFETY: sigaction is plain data; a null new action only reads the current one.
            let current = unsafe {
                let mut current: libc::sigaction = mem::zeroed();
                if libc::sigaction(signal, ptr::null(), &mut current) != 0 {
                    return Err(SandboxError::io(
                        format!("cannot read the action of signal {signal}"),
                        io::Error::last_os_error(),
                    ));
                }
                current
            };
            let discarded = current.sa_sigaction == libc::SIG_IGN
                || (current.sa_sigaction == libc::SIG_DFL
                    && DISCARDED_BY_DEFAULT.contains(&signal));
            if !discarded {
                continue;
            }
            // SAFETY: as above. The handler does nothing, so it is async-signal-safe.
            unsafe {
                let mut action: libc::sigaction = mem::zeroed();
                action.sa_sigaction = pending_only as *const () as libc::sighandler_t;
                if libc::sigaction(signal, &action, ptr::null_mut()) != 0 {
                    return Err(SandboxError::io(
                        format!("cannot catch signal {signal}"),
                        io::Error::last_os_error(),
                    ));
                }
            }
            caught.push((signal, current));
        }
        Ok(CaughtSignals(caught))
    }

    /// Restores the actions the caller gave sandy, so that the program starts with them.
    fn restore(&self) -> Result<(), SandboxError> {
        for (signal, previous) in &self.0 {
            // SAFETY: restores an action that `catch` read.
            if unsafe { libc::sigaction(*signal, previous, ptr::null_mut()) } != 0 {
                return Err(SandboxError::io(
                    format!("cannot restore signal {signal}"),
                    io::Error::last_os_error(),
                ));
            }
        }
        Ok(())
    }
}

extern "C" fn pending_only(_: libc::c_int) {}

/// What waitid reports about a child.
struct ChildState {
    pid: libc::pid_t,
    /// `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED` or `CLD_STOPPED`.
    code: libc::c_int,
    /// The exit status, or the signal number.
    status: libc::c_int,
}

impl ChildState {
    /// Whether the child has ended, not only stopped.
    fn exited(&self) -> bool {
        matches!(
            self.code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        )
    }
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

/// The first standard descriptor that is sandy's controlling terminal. tcgetpgrp fails for every
/// other descriptor.
fn controlling_terminal() -> Option<RawFd> {
    // SAFETY: tcgetpgrp takes a descriptor.
    (0..=2).find(|&fd| unsafe { libc::tcgetpgrp(fd) } > 0)
}
