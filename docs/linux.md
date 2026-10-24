# Linux backend

The Linux backend restricts sandy's own process and then replaces it with the program
(`execve`). The program keeps sandy's process ID, signals and exit status. With
`process.children = "contained"` a forked child does this instead, and sandy stays its parent
(see "Contained child processes"). Three kernel features do the work:

- **Landlock** confines the file system, isolates the process from ptrace, and (from ABI 6)
  scopes signals and abstract Unix sockets.
- **Three seccomp filters** deny system calls that Landlock does not cover: socket families,
  io_uring, namespaces, System V IPC, metadata changes by path, and more.
- **no_new_privs** stops setuid programs and file capabilities from adding privileges.

The research behind the design is in [research/linux-mechanisms.md](research/linux-mechanisms.md).

## Launch sequence

`sandy run` first prepares everything that can fail on bad input:

1. Detect the host: the Landlock ABI, seccomp support, no_new_privs, user IDs and capabilities,
   and which paths of the minimal system set exist. Detection only reads state.
2. Plan: a pure function (`plan_for`) turns the policy and the host capabilities into the plan
   items and the exact configuration to apply. If any requirement is unavailable, sandy refuses.
3. Build the Landlock ruleset with all its rules, compile the seccomp filters, and build the
   `execve` arguments and environment as C strings. Change to the working directory if the
   policy sets one. Reset SIGPIPE to its default action, because the Rust runtime ignores it and
   an ignored signal stays ignored across `execve`.

Then sandy restricts itself, in this order:

4. Mark every descriptor above 2 close-on-exec (`close_range` with `CLOSE_RANGE_CLOEXEC`; before
   Linux 5.11 through the list in `/proc/self/fd`). Closing them now would also close the
   Landlock ruleset, which is still needed.
5. Set no_new_privs.
6. Verify that the process has exactly one thread (one entry in `/proc/self/task`), then
   `landlock_restrict_self`. sandy checks that the ruleset is fully enforced.
7. Install the allowlist filter, then the denylist filter, then the socket family filter, each
   with `SECCOMP_FILTER_FLAG_TSYNC`.
8. `execve`. Only this call remains after the filters are in place.

Landlock and seccomp restrict the calling thread. sandy starts no threads and verifies this before
step 6, the filters use TSYNC, and `execve` ends every other thread, so the program runs with
exactly these restrictions. Every child inherits them. sandy does not use Landlock's
`LANDLOCK_RESTRICT_SELF_TSYNC` (ABI 8): with a verified single thread it changes nothing, it exists
only on new kernels, and it would hide a thread that should not exist. If `/proc/self/task` cannot
be listed, the Landlock-based requirements are unavailable.

## Mechanism per requirement

| Requirement | Mechanism |
|---|---|
| FilesystemConfined | Landlock with every file system right of the ABI handled. The seccomp filter denies opening a file with access mode 3 and `openat2` (see "Access mode 3"). Before ABI 3 it also denies truncation without write access. |
| NoPrivilegeEscalation | no_new_privs. The filters deny namespaces, mounts, `bpf`, `perf_event_open`, io_uring, keyrings, `userfaultfd`, calls that need capabilities, setuid and setgid mode bits, unknown system calls and other CPU architectures. sandy refuses to run as root or with capabilities. |
| ProcessMemoryIsolated | Landlock: a domain cannot ptrace, open `/proc/<pid>/mem` or `environ`, or use `process_vm_readv` on processes outside it (all ABIs). The denylist also denies `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise`, System V IPC and POSIX message queues, and changes of the limits, priority and CPU affinity of other processes. |
| InheritedHandlesClosed | Close-on-exec on every descriptor above 2. |
| EnvironmentControlled | `execve` with exactly the policy environment. The backend adds no variables. |
| IpNetworkDenied | The socket family allowlist has no `AF_INET`, `AF_INET6` or `AF_NETLINK`; io_uring is denied. From ABI 4, Landlock also denies TCP bind and connect. |
| UnixSocketsDenied | The allowlist has no `AF_UNIX`, and socket pairs are limited to stream and seqpacket. From ABI 6, Landlock scopes abstract sockets; from ABI 9 it denies connections to pathname sockets. |
| SignalsIsolated | Landlock signal scope (ABI 6) and the denylist, which denies `setpgid` into a process group that exists and the terminal ioctls `TIOCSPGRP` and `TIOCSWINSZ` (see "Signals and the terminal"). Unavailable on older ABIs. |
| MetadataConfined | The denylist denies the metadata calls that take a path (see "Metadata"). |
| ChildProcessesDenied | The denylist denies `fork`, `vfork` and `clone` without `CLONE_THREAD`; `clone3` fails with `ENOSYS` (see "Child processes"). |
| ChildProcessesContained | sandy stays the parent and ends the program's process group; the denylist denies `setsid` and `setpgid` (see "Contained child processes"). |
| EndsWithParent | A watcher process outside the sandbox ends the program when sandy's parent ends (see "Ending with the parent"). |
| ExposedPortsRelayed, ForwardedPortsRelayed | One relay process outside the program's sandbox, confined by its own Landlock domain and seccomp filters (see "Exposed and forwarded ports"). |

## Exposed and forwarded ports

Both are pairs of a loopback address that the relay listens on and a loopback address it connects
to. `network.expose` listens on `listen` outside and connects to the program's port.
`network.forward` listens on the program's loopback port and connects to `to`, a service outside.
One relay process serves all pairs. sandy starts it before it confines itself:

1. sandy binds every listen address (for `forward` the program's own loopback port, which is
   therefore taken before the program starts) and opens a pidfd for its own process ID. The
   program keeps this ID after `execve`, so the pidfd refers to the program. With
   `process.children = "contained"` it refers to the supervising sandy, which ends after the
   program's process group has ended (see "Contained child processes").
2. sandy verifies that it has one thread and forks twice. The intermediate process exits at once,
   so the relay is not a child of the program and the program's `wait` never reaps it. The relay
   is a fork of sandy, not a new program; a single-threaded parent makes this safe. It starts a
   session of its own and blocks every signal except the fault signals, so that no process group
   or terminal signal (for example Ctrl+C) ends it while the program runs (see "Ending with the
   parent" for why these signals matter).
3. The relay points 0, 1 and 2 at `/dev/null` and closes every descriptor except its listeners,
   the pidfd, those three and a readiness pipe. It then confines itself:
   - no_new_privs;
   - Landlock with every file system right of the ABI handled and no rule, so it cannot open,
     create or execute any file; from ABI 4 TCP bind is denied and TCP connect is allowed only to
     the target ports of the pairs (Landlock TCP rules match the port, not the address); from
     ABI 6 the signal and abstract socket scopes;
   - the shared allowlist filter and a relay filter that allows only TCP sockets, `accept`,
     `connect`, reading and writing, polling, memory calls, thread creation without namespace
     flags, `timer_settime` for the watchdog below, `rt_sigtimedwait` and `FIONBIO`. Every other call fails with
     `EPERM`; `clone3` fails with `ENOSYS`.
4. The relay starts and joins one test thread (so a filter that blocks threads fails here) and
   reports "ready" over the pipe. sandy reads the report and continues only on success. Any
   failure of the relay is reported back, and sandy refuses to run. The relay then polls the
   pidfd and its listeners and relays every accepted connection in its own threads, up to
   `sandy_relay::MAX_CONNECTIONS` per listener at the same time. Before it confines itself it
   raises its soft limit of open descriptors so that they fit.
5. When the pidfd becomes readable, that is when the program ends (also by SIGKILL), the relay
   accepts the connections reported in the same round, closes its listeners, waits while accepted
   connections deliver their data, at most one second, and exits (DESIGN.md rule 5 of "Forwarded
   ports"), resetting the connections that are still open. A program that connects, writes and
   exits at once therefore does not lose its data, and the relay never outlives the program by
   more than one second. With `contained` the pidfd is sandy's; the relay also polls a pipe whose
   write end only the guard holds, which ends when the guard dies with the program's group, so
   the relay ends with the group also while sandy is stopped. If sandy fails after starting the
   relay, sandy's process ends and the relay with it.
6. No process can block SIGSTOP, so with the default `signals = "any"` the program can stop its
   relay. A stopped relay neither sees the program end nor accepts anything, while the kernel
   keeps completing handshakes for its listeners; once someone continues it, it would relay
   connections that were made after the program ended. The relay therefore arms a timer that
   asks the kernel for SIGKILL two seconds later, and re-arms it on every turn of its poll loop,
   which waits at most 250 ms. A stopped relay is killed within those two seconds and its ports
   are released. The timer is created before the relay confines itself, so only `timer_settime`
   has to pass the filter. A relay that the host does not schedule for two seconds is killed as
   well, and its connections then end with a normal close instead of the reset of rule 5. The
   relay also sees a stop exactly: the helper blocks SIGCONT like every other signal, so the
   kernel continues the process and leaves SIGCONT pending, and the poll loop takes it from the
   pending set on every turn. When the turn that finds the program ended also finds that the
   relay was continued, it closes its listeners without accepting what the backlog collected
   while it was stopped, because those connections may have been made after the program ended.

The listeners and the pidfd are close-on-exec, and sandy closes its copies before it confines
itself, so the program never holds them. The relay has `/dev/null` as its standard descriptors,
as on macOS, so it holds nothing of the caller's: a caller that waits for the end of sandy's
output sees it end with the program, not with the relay. A relay that panics after it reported
readiness therefore leaves no message; a failure before that is reported over the readiness pipe.

The relay runs in its own Landlock domain, a sibling of the program's domain, so neither can
ptrace the other. With `signals = "any"` the program can kill or stop the relay; a kill ends the
relayed connections at once, and a stop ends the relay within two seconds (step 6 above). Any local process can
connect to the relay's listeners, like to any loopback port. Through an exposed port it reaches
the program, which is what an exposed port is for: the program's own listener is reachable
directly anyway, so the relay checks nobody there.

A forwarded port is different. It exists for the program alone, and the relay reaches `to` as
sandy's user, so a connection of another user would pass an owner rule of the packet filter or a
peer credential check in that service. The relay therefore asks the kernel who owns the other
end of every connection it accepts on a forwarded port, and closes it unless the owner is
sandy's user. It asks over a `NETLINK_SOCK_DIAG` socket that sandy opens before the relay
confines itself, with an exact lookup of the connection's four addresses
(`SOCK_DIAG_BY_FAMILY`), and it compares the answer with what it asked, so a lookup that matched
a listening socket instead, or that reports no owner, is refused like any other failure. Every
failure closes the connection, and sandy checks the lookup on a connection of its own before it
starts the relay, so a kernel without `inet_diag` refuses the run instead of refusing every
connection later. Two limits are inherent: the owner is the user that created the socket, so a
process of sandy's own user that acts for someone else still passes, and a descriptor passed
between processes keeps the owner of its creator. macOS has no such check; on Windows only the
program's AppContainer reaches the forward listener.


## Contained child processes

With `process.children = "contained"` the program may start processes, and sandy ends all of them
when the program ends. sandy does not replace itself with the program:

1. After it has started the relay, if any, sandy makes itself a child subreaper
   (`PR_SET_CHILD_SUBREAPER`): a process whose parent ends is re-parented to sandy instead of
   init. sandy sets `SIGCHLD` to its default action, so that it can wait for children even if
   its caller ignored the signal, and blocks every signal except the fault signals.
2. sandy forks the guard. The guard creates a process group of its own and closes every
   descriptor except the read end of a pipe. sandy holds the write end; the forked program in
   step 3 has a copy only until `execve` closes it.
3. sandy forks the program and writes its process ID into the guard's pipe. The guard opens a
   pidfd for the program and polls it and the pipe. When the program ends, or when the pipe ends
   because sandy died (also by `SIGKILL`), the guard checks that it leads its group and kills the
   group with `SIGKILL`. The group therefore ends with the program even while sandy is stopped.
4. The forked program joins the guard's group, restores `SIGCHLD` and the signal mask that sandy's
   caller set, and then runs steps 4 to 8 of the launch sequence. The denylist filter names the
   child's process ID. If a step fails, the child writes the error into a close-on-exec pipe and
   exits; sandy reads the pipe until `execve` closes it, and refuses with that error.
5. sandy waits for signals with `sigwaitinfo`. It forwards every signal to the program except
   `SIGCHLD`, `SIGCONT`, `SIGTTIN` and `SIGTTOU`, reaps processes that were re-parented to it,
   and refuses to continue if the guard ends before the program. With a terminal (one of sandy's
   standard descriptors is its controlling terminal), sandy follows job control:
   - The program's group starts in the background. When the program stops because it read or
     wrote the terminal (`SIGTTIN`, `SIGTTOU`) and sandy's group is the foreground group, sandy
     gives the terminal to the program's group and continues it. Then Ctrl+C and Ctrl+Z reach the
     program and every process it started.
   - When another process of sandy's job (for example `less` in `sandy run ... | less`) uses the
     terminal while the program's group has it, the kernel stops it and sends `SIGTTIN` or
     `SIGTTOU` to sandy's group. sandy takes the terminal back and continues its job.
   - Any other stop of the program stops sandy too, after it has taken the terminal back, so that
     the shell sees the job stop. `SIGCONT` to sandy gives the terminal to the program's group
     again if it had it, and continues that group.
6. When the program has exited, sandy gives the terminal back to its own group, kills the group
   with `SIGKILL`, kills the guard and the program by process ID as well, and waits for the
   members of the group (`waitpid` with the negative group ID) until none is left. Other children
   of sandy, for example processes its caller started before it executed sandy, are not waited
   for. sandy exits with the program's exit status, or 128 plus the signal number if a signal
   ended the program.

Two rules keep every process the program starts inside the group. The denylist denies `setsid`
and `setpgid`, the only system calls that move a process to another group. The policy must have
`signals = "isolated"`, so the Landlock signal scope keeps the program from signaling sandy and the
guard, which are outside its domain. The guard, not sandy, ends the group when the program ends,
so the program cannot keep its processes alive by stopping sandy (with a terminal it can make
sandy stop, see step 5). sandy reaps neither the guard nor the program before it has killed the
group, so the group ID (the guard's process ID) cannot belong to another process while sandy can
still signal it. Killing a process group with `SIGKILL` reaches every member in one operation; the
kernel lets no member fork a new process past it. A member whose parent ends is re-parented to
sandy before that parent can be reaped, so waiting for the group's members ends only when none is
left.

Costs and differences from the exec model:

- The program has another process ID than sandy. The caller's process handle refers to sandy,
  which forwards signals and reports the exit status.
- A signal death becomes the exit status 128 plus the signal number, which a caller cannot tell
  from a program that exits with that status.
- Programs that call `setsid` or `setpgid` get `EPERM`: programs that turn themselves into
  daemons, and shells with job control, which then run without it.
- Without a terminal, sandy does not stop when the program stops. There is no job control to
  follow, and a stopped sandy cannot forward signals.
- With a terminal, the program can stop sandy: it stops itself, and one of its processes continues
  it. sandy then stays stopped until it receives `SIGCONT` (a shell's `fg`). The guard still ends
  the group when the program ends.
- Only one process group can own a terminal. While the program's group has it, the rest of
  sandy's job gets it back only when it uses the terminal (see step 5). Two processes that read
  the terminal at the same time pass it back and forth.
- sandy and the guard hold no descriptor of the program except standard input, output and error,
  which sandy keeps until it exits, that is after the group has ended.
- If both sandy and the guard are killed with `SIGKILL`, nothing ends the group. Both run sandy's
  command line, so `pkill -9 -f sandy` does this. Killing sandy alone is safe.

## Ending with the parent

With `process.end_with_parent = true` a watcher process ends the program when the process that
started sandy ends:

1. sandy reads its parent's process ID (`getppid`) as the first step of `main`. With
   `--parent-pid`, the caller names its own process ID, and sandy refuses when its parent is
   another process, for example because the caller has already ended and sandy was re-parented.
   Without `--parent-pid`, a parent that ends before this first step cannot be detected: sandy
   then already has another parent, the process it was re-parented to. "Parent" is always the
   direct parent; a wrapper such as `sh -c`, `timeout` or `systemd-run` between the application
   and sandy is the parent instead.
2. Before it starts the watcher, sandy opens a pidfd for that process ID and checks that
   `getppid` still returns it. If it does not, the parent ended in between, and sandy refuses to
   start the program. A process ID that another process got in between fails this check too.
3. sandy opens a pidfd for its own process ID. The program keeps this ID after `execve`; with
   `children = "contained"` it stays the supervising sandy's.
4. sandy starts the watcher like the relay: it forks twice, so the watcher is not a child of the
   program, and continues only after the watcher has reported that it is confined. The watcher
   starts a session of its own (`setsid`) and blocks every signal except the fault signals. It
   keeps only the two pidfds, the readiness pipe and `/dev/null` as its standard descriptors,
   and confines itself with no_new_privs,
   Landlock without file access and without TCP (from ABI 6 also the abstract socket scope), and
   a seccomp filter that allows only polling, `pidfd_send_signal`, the readiness report, ending,
   and the memory and clock calls of the Rust runtime. It has no Landlock signal scope: it must
   signal the program, which runs in another Landlock domain. The filter allows
   `pidfd_send_signal` only through the program's descriptor and only with SIGTERM, SIGCONT and
   SIGKILL, so the watcher cannot reach the process that started sandy, whose pidfd it also
   holds.
5. The watcher polls both pidfds. When the program ends first, the watcher ends. When the parent
   ends, the watcher sends SIGTERM and SIGCONT through the program's pidfd (SIGCONT, so that a
   stopped program gets the request), waits at most 5 seconds for the program to end, and then
   sends SIGKILL. A pidfd always names the same process, so a reused process ID cannot redirect
   the signals. If polling fails, the watcher ends the program the same way, because it can no
   longer see the parent.

With `contained`, the supervising sandy forwards SIGTERM to the program and ends the group when the
program ends; SIGKILL to the supervising sandy makes the guard end the group.

Two rules keep the program from stopping the watcher. The policy requires `signals = "isolated"`,
so the program cannot signal the watcher, which is outside its Landlock domain. And the watcher is
in a session and process group of its own with its signals blocked: the kernel sends some signals
to a whole process group or to a terminal's foreground group (Ctrl+C, a hangup, SIGTTIN,
SIGWINCH, SIGHUP and SIGCONT to an orphaned group with a stopped member) without the permission
check that Landlock hooks, and the program can cause some of them (see "Signals and the
terminal"). The relay starts the same way for the same reason.

The watcher, the supervising sandy and its guard make themselves undumpable (`PR_SET_DUMPABLE`
0), which gives their `/proc/<pid>` files to root. Without that, a program with a write grant on
`/proc` could set their `oom_score_adj` to 1000 and let the out-of-memory killer end them first,
which would take away the guarantee they stand for (measured: the write succeeded before this).
The kernel clears the flag when the program executes the target, so the program itself is
unaffected. The relay stays dumpable on purpose: it is the process that holds the relayed ports,
and only a dumpable process can be attributed to a listening socket (`ss -ltnp`). A relay that
the killer ends only closes those ports, which is the safe direction.

Residual risk: if the watcher itself is killed from outside the sandbox, for example by the
out-of-memory killer or by `pkill -f sandy`, which matches it, nothing ends the program with its
parent. The watcher uses about 2 MB, so the killer chooses it only after larger processes. An
unprivileged process can lower its own `oom_score_adj` only down to the value it inherited, so
the watcher cannot take itself out of reach of the killer.

## Landlock

### ABI

sandy reads the ABI from the kernel each time (`landlock_create_ruleset` with the VERSION flag).
It never infers the ABI from the kernel version, because distributions backport Landlock. It uses
the lower of the kernel ABI and ABI 9, the newest ABI that the `landlock` crate (0.4.7) knows. The
crate runs with `CompatLevel::HardRequirement`, so a right that the kernel does not support is an
error, not a silent omission. ABI 10 adds only UDP rights, which sandy does not need because the
seccomp filter denies IP sockets.

| ABI | Linux | What changes in sandy |
|---|---|---|
| none | | Refused. The reason names the fix: RHEL 9 needs 9.6 or newer; SLES 15 and openSUSE Leap 15 need `landlock` in the `lsm=` boot parameter; RHEL 8 has no Landlock. |
| 1 | 5.13 | Renaming or linking a file into another directory fails with `EXDEV`, also inside writable paths. |
| 1, 2 | | Landlock cannot restrict truncation. The denylist denies `truncate` and `open`/`openat` with `O_TRUNC` on a read-only open. |
| 3 | 6.2 | Truncation is a Landlock right. |
| 4 | 6.7 | TCP bind and connect are denied when IP is denied (a second layer). |
| 1 to 4 | | Device ioctls are not checked by Landlock; the program can only open the devices of the policy and the system set. |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` is handled. |
| 1 to 5 | | `signals = "isolated"` is refused. |
| 6 | 6.12 | Signal and abstract socket scopes. |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` is handled when `unix_sockets = "none"`. |

### Rights per access level

| Policy access | Landlock rights |
|---|---|
| `read` | read file, read directory |
| `read_exec` | read file, read directory, execute |
| `read_write` | read file, read directory, write file, truncate, remove file, remove directory, make directory, make regular file, refer (move between writable directories), device ioctl; make socket only with `unix_sockets = "all"` |

A writable path never gets these rights:

- **Execute.** The policy rule against writable and executable paths.
- **Make symbolic link.** A process outside the sandbox that later writes a file in the writable
  directory (for example a configuration file that it writes before every start) would follow a
  planted link to any file of the user.
- **Make named pipe.** A planted FIFO blocks a process outside the sandbox that opens the path.
- **Make character or block device.** Never needed; it also needs `CAP_MKNOD`.
- **Make socket** when Unix sockets are denied. Binding a pathname socket needs an `AF_UNIX`
  socket, which the filter denies anyway.
- **Resolve Unix socket.** With `unix_sockets = "none"`, no path grants it. With `"all"`, the
  right is not handled at all, so `"all"` means every socket the user can reach on every kernel.

### Device ioctls and the terminal

From ABI 5 sandy handles `LANDLOCK_ACCESS_FS_IOCTL_DEV` and grants it only in writable paths.
Landlock decides the ioctl right when a file is opened. Standard input, output and error were
opened before the sandbox, so a terminal on them keeps working (`TIOCGWINSZ`, `tcsetattr`). The
filter still denies `TIOCSTI`, `TIOCLINUX` and `TIOCSETD` on every descriptor; the tests
`terminal_input_injection_is_denied` and `the_terminal_line_discipline_cannot_change` check
them. Cost: tools that attach a line discipline, such as `ldattach`, fail with `EPERM`; they
need privileges anyway.

### Access mode 3

Linux accepts the access mode 3 (`O_RDWR | O_WRONLY`) in `open`. It means "check read and write
permission, then return a descriptor that can neither read nor write, only use ioctl". Landlock
derives the rights it checks at open time from the read and write modes of the descriptor, so it
checks no right for such an open. This is a limitation of Landlock, and sandy closes it with
seccomp.

Tested on Linux 7.2 with ABI 9 enforced: `open(path, 3)` on a file outside the policy succeeded,
and `fchmod` and `fsetxattr` on that descriptor changed the file. On ABI 1 to 4 such a descriptor
would also allow device ioctls on any device the user can open (derived from the kernel source,
not tested). The denylist therefore denies `open` and `openat` with access mode 3, and `openat2`
fails with `ENOSYS`, because seccomp cannot read its flags.

## Seccomp

### Structure

sandy installs three filters, built with `seccompiler` from `libc::SYS_*` numbers:

1. **Allowlist.** Every number of the reviewed table is allowed: the Linux 7.2 table, on x86_64
   0 to 336 and 424 to 471, on arm64 0 to 243, 260 to 294 and 424 to 471. Every other number
   fails with `ENOSYS`: system calls of newer kernels until sandy reviews them, x32 numbers,
   `clone3` and `openat2`. A system call of another architecture (for example `int 0x80` on
   x86_64) kills the process.
2. **Denylist.** Rules with argument checks return `EPERM`.
3. **Socket families.** `socket` with a family the policy denies returns `EAFNOSUPPORT`.

The kernel applies the stricter result of the three, and among equal results the one of the
filter installed last, which is why the family filter comes after the denylist. Programs treat
`ENOSYS` like an older kernel: glibc falls back from `clone3` to `clone`, and callers of
`openat2` fall back to `openat`. They treat `EAFNOSUPPORT` like a kernel without the family, so
a program that probes for IPv6 or for AF_UNIX falls back instead of ending; `EPERM` reads like a
temporary failure. `socketpair` keeps `EPERM`, because its denials are about the socket type,
not the family. Arguments of type int (socket family, ioctl command, clone flags, open flags)
are compared on their low 32 bits only, because the kernel ignores the high bits.

### Denylist

The rules return `EPERM`, except where the table says otherwise.

| System calls | Rule | Reason |
|---|---|---|
| `socket` (`EAFNOSUPPORT`) | family not in the allowlist | `AF_UNIX` only with `unix_sockets = "all"`. `AF_INET`, `AF_INET6` and `AF_NETLINK` with protocol `NETLINK_ROUTE` only with `ip = "all"`. A denylist would miss families that reach TCP, for example `AF_SMC`. Route netlink lets the C library list interfaces (`getifaddrs`, `getaddrinfo`); other netlink protocols expose, for example, every socket of the host (`sock_diag`). `AF_VSOCK`, `AF_ALG`, `AF_PACKET` and the rest are always denied. |
| `socketpair` | other family than `AF_UNIX`; datagram or raw type when `unix_sockets = "none"` | A datagram socket can send to any address, also from a pair. `AF_UNIX` treats `SOCK_RAW` as `SOCK_DGRAM`. Stream and seqpacket pairs stay allowed. |
| `ioctl` | `TIOCSTI`, `TIOCLINUX`, `TIOCSETD`, and the file system ioctls that change a file; with `signals = "isolated"` also `TIOCSPGRP` and `TIOCSWINSZ` | `TIOCSTI` and `TIOCLINUX` can inject input into the terminal of the user. `TIOCSETD` changes its line discipline, and the kernel loads the module of a discipline on demand when `dev.tty.ldisc_autoload` is 1, which is kernel attack surface. For the file system ioctls see "Metadata", for the two others "Signals and the terminal". |
| `fcntl` | `F_SETLEASE` with anything but `F_UNLCK`, `F_SETDELEG` | A lease or a delegation needs only a read descriptor of a file or directory the user owns, and Landlock does not cover `fcntl`. While the program holds one, a process outside that opens the file for writing, or creates, renames or removes an entry in the directory, waits until `/proc/sys/fs/lease-break-time` passes (45 seconds by default; measured: 48 seconds). Giving one up stays allowed. |
| `clone` | any `CLONE_NEW*` flag | Namespaces expose kernel interfaces that are otherwise reserved for root. |
| `unshare` | any `CLONE_NEW*` flag, including `CLONE_NEWTIME` | Same. `unshare(CLONE_FILES)` stays allowed. |
| `setns` | always | Same. |
| `personality` | other values than 0, 0x8, 0x20000, 0x20008, 0x40000, 0x40008, 0x60000, 0x60008, 0xffffffff | The values Docker allows, and `ADDR_NO_RANDOMIZE` (0x40000) alone and with those flags, which `setarch -R`, `rr` and the thread sanitizer need; it weakens address space randomization only inside the sandbox. The rest are old exploit helpers, for example `READ_IMPLIES_EXEC`. |
| `open`, `openat` | access mode 3; before ABI 3 also `O_TRUNC` with read-only access | See "Access mode 3" and the ABI table. |
| `truncate` | before ABI 3 | Landlock cannot check it. |
| io_uring (3 calls) | always | io_uring operations bypass seccomp, including socket creation. |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise` | always | Second layer to Landlock. Debuggers do not work inside the sandbox. |
| System V IPC (12 calls), POSIX message queues (6 calls) | always | These objects belong to all processes of the user and Landlock does not cover them. `shmat` would give access to the memory of processes outside the sandbox. |
| `mount`, `umount2`, `pivot_root`, `chroot`, new mount API, `open_tree_attr`, `mount_setattr` | always | Second layer; Landlock denies mounts already. |
| `statmount`, `listmount`, `listns` | always | They show the mount and namespace topology of the host, which leaving out `/proc` otherwise hides (`/proc/self/mountinfo`, `/proc/*/ns`). |
| `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` | always | They show which security modules the host runs and the program's own security attributes, which leaving out `/proc` and `/sys/kernel/security` otherwise hides, and `lsm_set_self_attr` changes them. |
| `bpf`, `perf_event_open`, `userfaultfd` | always | Kernel attack surface. |
| `keyctl`, `add_key`, `request_key` | always | The keyrings of the user are shared by all its processes. |
| `kexec_*`, module calls, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `open_by_handle_at`, `settimeofday`, `clock_settime`; on x86_64 `iopl`, `ioperm`, `modify_ldt`, `uselib` | always | They need capabilities, which sandy never passes on. A second layer. |
| metadata calls by path | with `linux.path_metadata = "deny"` | See "Metadata". |
| `clone`; on x86_64 also `fork`, `vfork` | with `process.children = "none"`: `clone` without `CLONE_THREAD`, `fork` and `vfork` always | See "Child processes". |
| `setsid`, `setpgid` | with `process.children = "contained"`: always | See "Contained child processes". |
| `setpgid` | with `signals = "isolated"`: a process group other than 0 | See "Signals and the terminal". |
| `fchmod`; with `path_metadata = "allow"` also `chmod`, `fchmodat`, `fchmodat2` | mode with `S_ISUID` or `S_ISGID` | A file with these bits runs with the rights of this user when another local user runs it. See "Setuid and setgid bits". |
| `prlimit64`, `sched_setaffinity`, `sched_setscheduler`, `sched_setparam`, `sched_setattr` | process ID other than 0 and the target's own | See "Other processes". |
| `setpriority`, `ioprio_set` | a process group or user, or a process ID other than 0 and the target's own | Same. |

### Metadata

Landlock does not restrict `chmod`, `chown`, `utimensat` or extended attributes. With the default
`linux.path_metadata = "deny"`, the denylist denies:

- `fchmodat`, `fchmodat2`, `fchownat`, `setxattr`, `lsetxattr`, `removexattr`, `lremovexattr`,
  `setxattrat`, `removexattrat`, `file_setattr`, and `utimensat` with a path;
- on x86_64 also `chmod`, `chown`, `lchown`, `utime`, `utimes` and `futimesat`.

`fchmodat`, `fchmodat2` and `fchownat` are denied completely, because they accept an `O_PATH`
descriptor with `AT_EMPTY_PATH`, and `O_PATH` opens need no Landlock right. `fchmod`, `fchown`,
`fsetxattr`, `fremovexattr` and `utimensat` without a path stay allowed. They reject `O_PATH`
descriptors, and access mode 3 is denied, so they only reach files that Landlock let the program
open for reading or writing, also read-only (see "Known limitations"). Programs that change
metadata by path, for example `tar`, `cp -p` and `install`, need `path_metadata = "allow"`; then
the program can change the metadata of every file the user owns.

Under every policy the denylist also denies the file system ioctls that change a file or a
directory. Landlock checks ioctls only on device files, so they reach every descriptor the
program holds, also one of a file in a `read` path (measured on Linux 7.2):

- `FS_IOC_SETFLAGS`, its 32-bit form and `FS_IOC_FSSETXATTR` change inode flags and attributes,
  which is metadata like `chmod`. Only `chattr` and tools that set `NOCOW` use them, and they
  have no counterpart that the metadata calls on a descriptor need.
- `FS_IOC_SETVERSION` and its 32-bit form change the version a file carries, which is metadata
  that the policy denies when the call takes a path.
- `FS_IOC_ENABLE_VERITY` makes the content of a file permanently read-only (measured on btrfs
  with a descriptor opened read-only).
- `FS_IOC_SET_ENCRYPTION_POLICY` encrypts what the user later writes into an empty directory,
  with a key the program chose. `FS_IOC_REMOVE_ENCRYPTION_KEY` and its all-users form lock
  encrypted directories the user has unlocked, which reaches files outside the policy.
- The btrfs ioctls that create, snapshot and delete subvolumes, or make them read-only, change
  directories without the Landlock checks for creating and removing entries.

The reading forms (`FS_IOC_GETFLAGS`, `FS_IOC_FSGETXATTR`, `FS_IOC_MEASURE_VERITY`) stay
allowed. The test `file_system_ioctls_cannot_change_readable_files` checks the denials.

### Setuid and setgid bits

Under every policy, `fchmod` fails with `EPERM` when the mode has `S_ISUID` or `S_ISGID`. With
`path_metadata = "allow"`, `chmod`, `fchmodat` and `fchmodat2` get the same check; with the
default `"deny"` they are denied anyway. Otherwise the program could mark a file in a writable
path setuid to the user, and another local user who can reach the file would run it with this
user's rights.

Creating a file with these bits (`open` with `O_CREAT` and mode 4755, `mknod`) stays allowed.
Tested on Linux 7.2: `write` and `ftruncate` (which `mmap` writes need first) clear both bits, so
such a file stays empty or loses the bits. Programs that set the setgid bit on directories, for
example `git init --shared`, fail.

### Child processes

With `process.children = "none"` the denylist allows `clone` only when its flags contain
`CLONE_THREAD`, and on x86_64 it denies `fork` and `vfork`. The flags are the first argument of
`clone` on x86_64 and arm64, and the filter compares their low 32 bits, which the kernel uses.
`clone3` fails with `ENOSYS` in every policy, so the C library creates threads with `clone` and
`CLONE_THREAD`, and `posix_spawn` falls back to `clone` with `CLONE_VM | CLONE_VFORK`, which is
denied. Threads therefore keep working, and so does `execve`, which replaces the program's own
image. Programs that start helpers, shells or other programs fail with `EPERM`. The relay of
exposed and forwarded ports is forked before the program's filter exists, so it is not affected.

### Signals and the terminal

The Landlock signal scope checks the system calls that send a signal. The kernel also signals
whole process groups for terminal job control, and those signals skip that check: `SIGTTIN` and
`SIGTTOU` for a background group that reads the terminal or changes it, and `SIGWINCH` for the
foreground group when the window size changes. Without further rules a program with
`signals = "isolated"` could stop other jobs of the user's terminal session, for example an
editor the user suspended in the same shell (measured on Linux 7.2):

- It joins the job's process group with `setpgid(0, group)` and then reads the terminal. The
  kernel stops every process of the group, including the job.
- It takes the terminal with `TIOCSPGRP`. The job that had the foreground stops as soon as it
  reads the terminal again.
- It changes the window size with `TIOCSWINSZ`, which sends `SIGWINCH` to the foreground group.

With `signals = "isolated"` the denylist therefore allows `setpgid` only with process group 0,
which makes the caller a group leader, and denies `TIOCSPGRP` and `TIOCSWINSZ`. seccomp cannot
compare two arguments, so `setpgid(pid, pid)` is denied as well; a program that wants its own
group uses `setpgid(0, 0)` or `setsid`, which stay allowed. The three routes are checked by
`other_jobs_of_the_terminal_cannot_be_stopped`,
`the_terminal_cannot_be_taken_from_the_foreground_job` and
`terminal_resize_cannot_signal_outside`.

Cost: a shell inside the sandbox has no job control, because it cannot put a pipeline in a group
of its own and cannot hand the terminal to it. Programs that resize their terminal (`stty rows`,
`resize`) fail with `EPERM`. What stays open: the program's own reads from the terminal still
stop its own group, and `SIGTTIN` reaches no process outside it.

### Other processes

`prlimit64`, `setpriority`, `ioprio_set`, `sched_setaffinity`, `sched_setscheduler`,
`sched_setparam` and `sched_setattr` can change other processes of the user: lower their
resource limits, priority or I/O priority, or pin them to one CPU. The denylist allows them only
with process ID 0 (the caller), and with `children = "none"` or `"contained"` also with the
target's own process ID, which it keeps from sandy after `execve`. With `children = "allowed"` a
process the program started can outlive it, and once another process of the user has that ID,
the exemption would cover it; there only 0 works. For `setpriority` and `ioprio_set` it also denies the process group and user forms,
because sandy's process group can contain processes outside the sandbox.

These are system calls. The out-of-memory priority of a process is not set by a call but by a
write to `/proc/<pid>/oom_score_adj`, which the denylist cannot see. A policy with a write grant
on `/proc` therefore lets the program raise the out-of-memory priority of every process of the
user, and lower its own down to the value sandy inherited. sandy's own processes are out of
reach, because they are undumpable (see "Ending with the parent"); other processes of the user
are not. Grant `/proc` writable only to programs you would also run without a sandbox.

Costs: children of the program cannot use these calls on each other, and a thread ID other than
the one of the main thread counts as another process. For example,
`pthread_setaffinity_np` and `pthread_setschedparam` fail for threads other than the main
thread, and `nice` works only for the calling thread through ID 0.

## Minimal system set

`system = "minimal"` adds these paths when they exist. sandy resolves symbolic links first, so
`/lib` on a merged-`/usr` system becomes `/usr/lib`. Nothing in the set holds user data. Only
`/dev/null` is writable.

| Path | Access | When | Reason |
|---|---|---|---|
| `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` | read | always | Shared libraries, gconv modules and the locale archive. A library is mapped with `PROT_EXEC` after a normal read open, which Landlock does not check as execute. |
| `/lib64/ld-linux-x86-64.so.2`, `/lib/ld-musl-x86_64.so.1` (arm64: `/lib/ld-linux-aarch64.so.1`, `/lib/ld-musl-aarch64.so.1`) | read, execute | always | The kernel opens the dynamic loader of a program for execution during `execve`. Only the loader file is executable, not the library directories. |
| `/etc/ld.so.cache` | read | always | The library search cache of the glibc loader. |
| `/etc/ld.so.preload` | read | always | The system-wide preload list. Without it the program would start differently than outside the sandbox. |
| `/etc/ld-musl-x86_64.path` (arm64: `-aarch64`) | read | always | The library path of the musl loader. |
| `/etc/localtime`, `/usr/share/zoneinfo` | read | always | Time zone data. |
| `/etc/ssl/openssl.cnf`, `/etc/pki/tls/openssl.cnf`, `/etc/pki/tls/openssl.d`, `/etc/crypto-policies/back-ends`, `/usr/share/crypto-policies` | read | always | OpenSSL configuration and the system crypto policy it includes on Fedora and RHEL (the back-ends are symbolic links into `/usr/share/crypto-policies`, and Landlock checks the target). OpenSSL drops an include it cannot read without an error and then runs with weaker built-in defaults; Node.js does not start when the configuration exists but cannot be read. |
| `/dev/null` | read, write | always | Programs redirect output to it. Writes are discarded. No ioctl right. |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | read | always | Zero and random sources for programs that do not use `getrandom`. |
| `/sys/devices/system/cpu/online`, `/sys/devices/system/cpu/possible` | read | always | The number of CPUs for glibc, Go and Java. |
| `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/gai.conf`, `/etc/services`, `/etc/protocols` | read | `ip = "all"` | Name resolution. |
| `/etc/ssl/certs`, `/usr/share/ca-certificates`, `/etc/pki/tls/certs`, `/etc/pki/ca-trust/extracted`, `/etc/ca-certificates/extracted`, `/var/lib/ca-certificates` | read | `ip = "all"` | CA certificates for TLS on Debian, Ubuntu, Fedora, RHEL, Arch and openSUSE. |

Left out on purpose:

- `/proc` (see below), `/tmp`, `/dev/shm`, `/run`, `/var`, `/home`.
- `/dev/tty` and `/dev/pts`: a program whose standard streams are redirected could otherwise open
  the terminal of the user.
- `/etc/passwd` and `/etc/group`: not needed to start, and they list the accounts of the host.
  `ls -l` shows numeric owners.
- `/usr/bin` and other program directories: the program file is executable by policy rule 4.
  A program that starts other programs needs `--read-exec` for them.
- `/usr/local/lib`: add it to the policy if a program needs libraries from there.

Distributions outside the FHS layout (for example NixOS) need their store paths in the policy.

### /proc

`/proc` is not in the set. Landlock rules bind to inodes, and `/proc/self` resolves to the
directory of one process ID, so a rule cannot give each process only its own entry: a child of
the program gets `EACCES`. A policy can add `--read /proc`. The program can then read
`/proc/<pid>/cmdline`, `status` and `stat` of every process of the host, which can contain
secrets passed on command lines, and `/proc/net` of the network namespace. `/proc/<pid>/mem` and
`environ` of processes outside the sandbox stay denied by the Landlock ptrace check (tested). Without `/proc`, `std::env::current_exe` and similar calls fail; common runtimes
(glibc, Rust, Python, Go, Java, Node.js) still start.

## Links and the mount table

Landlock binds a rule to the inode behind a path when sandy starts, and it checks the path a
call uses. One file under two names, or one directory under two paths, would otherwise get the
rights of both, so the resolver compares files before it builds the rules.

- **Bind mounts.** sandy reads `/proc/self/mountinfo` and works out where each path lies inside
  its file system: the root of the mount that holds it plus the rest of the path, together with
  the device. A bind mount of a subdirectory of a writable path, given as `read_exec`, is
  refused this way. Comparing the identity of the path and of its parent directories does not
  see that case, because such an alias has no parent directory in common with the writable path.
  sandy refuses the policy when it cannot read the table. Nothing is lost by that: sandy needs
  `/proc` before Landlock anyway, to check that it is single-threaded. Each btrfs subvolume has
  its own device number, so two subvolumes are compared as two file systems, as the kernel
  reports them. sandy picks the mount by the longest mount point that is a prefix of the path
  and lies on the same file system; a mount that a later mount over one of its parents hides is
  the one case where that can pick the wrong one.
- **Hard links.** `read_exec` files, the program file, sandy's own executable and the policy
  file must have no second name inside a writable path. sandy checks `st_nlink` first and then
  walks the writable trees, which costs one `lstat` per file there; it walks the `read_exec`
  trees only when the writable trees hold a file with more than one name, which is rare. A
  directory the user may not list is skipped: the program runs as the same user and cannot list
  it either.
- A file outside the policy that has a second name inside a writable path stays writable through
  that name, and two names that a passthrough FUSE mount shows for one file have different
  identities and stay unseen. See "Links and file identity" in [DESIGN.md](DESIGN.md).

## Refusals

`sandy check` shows the reason for each unavailable requirement. A policy that breaks one of the
path rules is refused before that, with exit code 125 and the paths it compared.

- No Landlock: FilesystemConfined, ProcessMemoryIsolated and SignalsIsolated are unavailable.
- No seccomp filter support, or a CPU architecture other than x86_64 and arm64: every requirement
  that uses the filter is unavailable.
- Running as root (real, effective or saved user ID 0), or with any effective, permitted or
  ambient capability: NoPrivilegeEscalation is unavailable. no_new_privs removes nothing that is
  already held, and Landlock does not restrict `chmod`, so root could, for example, set the
  setuid bit on a shell.
- A writable policy path that overlaps the minimal system set, with `system = "minimal"`:
  FilesystemConfined is unavailable. The path contains an entry of the set, or lies inside one of
  its directories. Entries that do not exist on this host count too (their location with the
  symbolic links of the existing part resolved), because the program could create them, for
  example `/etc/ld.so.preload`. A symbolic link counts where it is and where it points, also when
  its target is missing, as `/etc/resolv.conf` can be before the resolver starts. Only
  `/dev/null` is exempt. Otherwise the program could change the
  dynamic loader, shared libraries, the loader configuration or files such as `/etc/hosts`, which
  the next start and programs outside the sandbox use. File permissions usually forbid this
  anyway, because these files belong to root and sandy refuses to run as root; the check keeps
  the guarantee independent of them.

## Known limitations

- **Paths outside the policy are visible.** `stat`, `access`, `readlink`, `getxattr`,
  `getxattrat`, `listxattrat`, `file_getattr`, `name_to_handle_at`, `inotify` watches and
  unprivileged `fanotify` marks (`FAN_REPORT_FID` and related flags) work on every path the user
  can reach (tested: an inotify watch and a fanotify mark on a directory outside the policy
  succeeded). The program can learn which files exist, their sizes, times and attributes, and
  when other programs touch them. It cannot open them: `open_by_handle_at` needs a capability.
- **Abstract socket names with `ip = "all"`.** The program can bind one end of a socket pair to
  a free abstract name, because the filter cannot tell a socket's family from its descriptor and
  the Landlock scope checks connect and send, not bind. A service outside that binds the same
  name later then fails to start. With `unix_sockets = "none"` that is all it can do: the pair
  is a stream or seqpacket pair, which is connected already and cannot listen, so a client that
  reaches the name gets a refused connection. With `unix_sockets = "all"` the program can take
  the name of a service and serve it: a datagram pair end that binds the name and then
  disconnects with `connect(AF_UNSPEC)` receives what clients send to it (measured on Linux
  7.2), and an ordinary AF_UNIX socket can listen. With `ip = "none"` and
  `unix_sockets = "none"` the filter denies `bind`, `listen`, `connect` and `accept`, which no
  socket pair needs.
- **System information.** `uname`, `sysinfo` and `statfs` stay allowed. They show the kernel
  version, load and memory, and file system statistics. The mount and namespace listing calls
  and the security module calls (`lsm_list_modules`, `lsm_get_self_attr`, `lsm_set_self_attr`)
  are denied, like the `/proc` and `/sys` files that hold the same facts.
- **Metadata through open files.** `fchmod`, `fchown`, `fsetxattr`, `fremovexattr` and
  `futimens` work on every file the program may open, also on a descriptor of a file in a `read`
  path, except for setuid and setgid bits. seccomp sees only the descriptor number, not how the
  file was opened, and Landlock has no metadata right, so the only remaining fix is a helper
  outside the sandbox that performs these calls after checking the descriptor. With `fsetxattr`
  this includes ACLs and, on a host with SELinux, the security label. The file system ioctls of
  the same kind are denied (see "Metadata"). The test
  `metadata_calls_on_a_read_only_descriptor_still_work` records this.
- **Locks on readable files.** `flock` and POSIX and open file description locks need only a
  read descriptor, and seccomp cannot tell a descriptor's access mode. While the program holds
  one on a file in a `read` path, processes outside that lock the same file wait or fail. Read
  locks are what SQLite readers use, so they stay allowed. Leases and delegations, which stall
  outside writers for a fixed time without any cooperation, are denied (see "Denylist").
- **Signals.** With `signals = "any"` the program can kill other processes of the user. With
  `"isolated"` its own reads from the terminal still stop its own process group, which is the
  behaviour of any background job.
- **Processes that outlive the program.** With `process.children = "allowed"` (the default) a
  process the program starts can outlive it. `none` and `contained` prevent this for processes the
  program starts itself or through its children. Both need `unix_sockets = "none"`, because
  through a Unix socket the program could ask a service of the user, for example the systemd user
  manager over D-Bus, to start a process outside the sandbox. A service that starts processes on
  requests over TCP is still reachable with `ip = "all"` or through a `forward` target; such
  processes are not the program's and are not covered.
- **The terminal.** If standard input or output is the user's terminal, the program can read
  input, write escape sequences and change terminal modes. `TIOCSTI`, `TIOCLINUX` and `TIOCSETD`
  are always denied, and with `signals = "isolated"` also `TIOCSPGRP` and `TIOCSWINSZ`.
- **`unix_sockets = "all"`** gives every Unix socket the user can reach, including the D-Bus
  session bus. Through the systemd user manager on that bus, the program can start commands
  outside the sandbox. Use it only for programs that are trusted with this.
- **Replaced files.** Landlock rules bind to the inode that existed when sandy started. A file
  that is later replaced by rename (for example `/etc/resolv.conf` after a network change)
  becomes unreadable for a running program.
- **Hard links made outside.** The link check runs at the start. A process outside the sandbox
  can link a file into a writable path while the program runs, and the program can then change
  that file. The program cannot do it itself: it gets no `refer` right out of its writable paths
  and no execute right inside them.
- **What fails inside the sandbox:** 32-bit programs (killed), user namespace sandboxes of
  browsers (they fall back or fail), io_uring, debuggers, System V IPC, datagram socket pairs,
  `mkfifo` and symbolic links in writable paths, metadata changes by path with the default
  setting, `chattr` and the other file system ioctls that change a file, file leases, `ldattach`,
  job control in a shell and terminal resizing with `signals = "isolated"`, and system calls
  newer than the reviewed table (`ENOSYS`).
- **Landlock errata.** sandy does not check the errata bitmask. A kernel without the fix for
  erratum 3 lets rights widen through renames of directories that a bind mount disconnected.
  The program cannot mount, and `refer` is granted only inside writable paths, so the practical
  risk is low. Whether a supported stable kernel lacks the fix is not verified.
- Kernel bugs in allowed system calls are out of scope. The filters reduce the reachable kernel
  code, but they are not a full allowlist per program.

## Testing

`crates/sandy-cli/tests/escape_linux.rs` holds the Linux escape tests; the shared ones are in
`escape.rs`. Every denial has a control run outside the sandbox. Checks that need a host feature
(a session bus, a pseudo-terminal, ptrace or `/proc/<pid>/mem` under Yama `ptrace_scope` 1 or
higher, a socket family) print why they skip.
Checks that depend on the Landlock ABI read it from the kernel: below ABI 6, the signal test
expects sandy to refuse `signals = "isolated"`. The unit tests in `crates/sandy-linux` cover the
planning function with invented host capabilities, and the filter decisions with a small BPF
interpreter that applies both filters with the kernel's precedence.

Static test binaries for another host, for example a test VM:

```sh
cargo build --release --target x86_64-unknown-linux-musl -p sandy-cli --bins
cargo test --no-run --target x86_64-unknown-linux-musl -p sandy-cli \
    --test escape --test escape_linux
```

The second command prints the paths of the test executables
(`target/x86_64-unknown-linux-musl/debug/deps/escape-<hash>` and `escape_linux-<hash>`). Copy
them and `target/x86_64-unknown-linux-musl/release/sandy` and `sandy-probe` to the host, put
`sandy` and `sandy-probe` in one directory, and run each test executable with
`SANDY_TEST_BIN_DIR` set to that directory.
