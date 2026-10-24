# sandy design

sandy runs a program inside an operating system sandbox. A policy lists what the program may do;
everything else is denied. sandy supports Linux, macOS and Windows.

## Goals

- Contain a program that may be compromised, for example through a memory safety bug in code that
  parses untrusted input. After the compromise, the program must not be able to read or change
  user files outside its policy, gain privileges, or leave the sandbox through another process.
- One policy model and one command line on all supported platforms.
- Fail closed. If the host cannot enforce any restriction the policy requests, sandy does not
  start the program. There is no best-effort mode.
- Unprivileged use. `sandy run` needs no root or administrator rights. One-time host preparation
  that needs admin rights is allowed (`sandy setup`, for example the Windows loopback exemption).

## Non-goals

- Limiting where the program connects on the network. IP networking is all or nothing.
- Protecting the program from the user, or protecting secrets the program itself holds.
- Resource limits (memory, CPU, process count). They can come later.
- Containers, images or a separate root file system.

## Threat model

The sandboxed program and all its child processes are under attacker control. The attacker can run
arbitrary code with the program's user account and can make any system call. sandy itself, its
policy and the files it reads before the sandbox is applied are trusted. They must not be writable
by the sandboxed program, otherwise the next start runs attacker code outside the sandbox. The
writable-and-executable rule below enforces part of this; the integrator must store sandy and its
policy outside every writable path.

## Policy

```toml
version = 1

[filesystem]
system = "minimal"            # "minimal" | "none"
read = ["/opt/app/share"]     # read files, list directories
read_exec = ["/opt/app/bin"]  # read, list, execute
read_write = ["/var/lib/app"] # read, list, create, change, delete; never execute

[network]
ip = "none"                   # "none" | "all"; IPv4 and IPv6 including loopback
unix_sockets = "none"         # "none" | "all"; "none" reaches no socket outside read_write
expose = [{ listen = "127.0.0.1:18080", port = 8080 }]  # relay into the program's port 8080
forward = [{ port = 18081, to = "127.0.0.1:8081" }]     # relay out to a local service

[process]
signals = "any"               # "any" | "isolated"
children = "allowed"          # "allowed" | "none" | "contained"; see rule 9
end_with_parent = false       # end the program when sandy's parent ends; see rule 11

[environment]
pass = ["LANG"]               # copied from sandy's environment if present
set = { HOME = "/var/lib/app" }

[linux]
path_metadata = "deny"        # "deny" | "allow"; chmod, chown, utimensat, setxattr by path

[windows]
appcontainer_name = "example.app"  # required on Windows
```

Command line options extend the policy file (`sandy --help`): path options add paths, and every
other option replaces the file's value, also with a weaker one. The caller is trusted, so sandy
obeys, but `sandy check` names every option that replaced a stricter value of the file in a
`warning:` line on standard error, together with the settings of the policy that give up part of
the isolation (`ResolvedPolicy::warnings`) and what the backend found on this host that makes
the program behave differently inside the sandbox (`Backend::notes`). Warnings do not change
what sandy enforces or its exit status; `sandy run` prints none, because its standard error
belongs to the program.

sandy's own executable and the policy file get the checks of rules 3 and 4: sandy refuses to
start when a writable path contains one of them, reaches one through a link or an alias, or
holds a second name of one, because the program could then change what the next start runs or
reads. The name sandy was started under counts next to the file it leads to, because that name
can be a link inside a writable path.

Rules:

1. Paths must be absolute and must exist. sandy resolves symbolic links before it builds the
   sandbox, so all backends see the same object.
2. A rule applies to the path and everything beneath it.
3. No path may be both writable and executable, also not through nesting. sandy rejects such a
   policy. The program could otherwise drop an executable that a process outside the sandbox
   later runs. The rule holds per file, not per name: a file that has a second name inside a
   writable path is writable, so an executable path, or the program file, that leads to the same
   file is refused as well (see "Links and file identity").
4. No policy path may lie inside a writable path, and none may be resolved through an entry
   inside one, such as a symbolic link in a writable directory that points elsewhere. sandy
   resolves symbolic links at every start, so the program could replace such an entry with a
   link and widen its access at the next start. For the same reason the integrator must keep the
   parent directories of policy paths out of the program's reach. Rules 3 and 4 compare files,
   not only paths, so one directory reachable under two paths counts as one (see "Links and file
   identity").
5. The program file itself gets read and execute access automatically.
6. `system = "minimal"` adds a backend-defined read-only set of system paths that programs need to
   start: shared libraries, loader configuration, time zone data, random devices. Each backend
   documents its set and the reason for every entry. The set never contains user data. No
   writable policy path may overlap the set: contain one of its entries (also one that does not
   exist yet, such as `/etc/ld.so.preload`) or lie inside one of its directories. The entries are
   code and configuration that the next start and programs outside the sandbox trust, so rules 3
   and 4 apply to them as to policy paths, including how they compare paths: another name of a
   directory of the set counts as that directory (see "Links and file identity"). The only
   exception is `/dev/null`, which the set makes writable. The backend checks this, because only
   it knows its set; with `system = "none"` it adds nothing, and every writable path is the
   policy's own choice. Rule 12 holds in that case too.
7. The environment of the program contains only `pass` and `set` variables, plus variables a
   backend must add for any process to start (documented per backend).
8. `unix_sockets = "all"` allows every Unix socket the user can reach, independent of the
   filesystem rules, on every platform and kernel version. Linux before 7.1 cannot restrict
   connections to pathname sockets by path, and the meaning of a policy must not depend on the
   kernel version.

   **WARNING:** `unix_sockets = "all"` gives up most of the isolation. The program can reach every
   local service that listens on a Unix socket. On Linux that includes the D-Bus session bus,
   through which the systemd user manager starts arbitrary commands outside the sandbox. On macOS
   it includes mDNSResponder, so even with `ip = "none"` the program can send data out in DNS
   queries. Use it only for programs you would also run without a sandbox.
9. Children of the program inherit the sandbox on every platform. `process.children` decides
   whether the program may start processes and whether they may outlive it:
   - `allowed` (the default): the program may start processes. On Linux and macOS they can
     outlive the program. On Windows the program's job ends them when the program ends.
   - `none`: the program cannot create processes at all (threads stay allowed, and so does
     replacing its own program image with `execve`), so nothing it starts can outlive it.
   - `contained`: the program may start processes, and sandy ends every one of them when the
     program ends, also when sandy itself is killed. On Linux and macOS, sandy then stays the
     program's parent instead of replacing itself with it (see "Process model"). On macOS the
     program cannot use `posix_spawn` then: its flags move the new process out of the group
     inside the kernel, where no profile rule sees them, so the profile denies the call as a
     whole. `fork`, `vfork` and `execve` keep working.

   `none` and `contained` cover the processes the program starts itself or through its
   children. Both need `unix_sockets = "none"`: through a Unix socket the program could ask a
   service of the user (for example the systemd user manager over D-Bus) to start a process,
   which is not its child. A service that starts processes on requests over TCP stays reachable
   with `ip = "all"` or through a `forward` target, and its processes are not covered.
   `contained` also needs `signals = "isolated"`: otherwise the program could kill sandy and the
   process that ends the group. sandy rejects the policy when either condition is missing.
10. `linux.path_metadata = "deny"` (the default) requires that permissions, owner, timestamps and
   extended attributes of files outside the policy paths cannot change. Landlock does not
   control these calls, so the Linux backend denies the path-based variants (`chmod`, `chown`,
   `utimensat` with a path, `setxattr` and relatives) everywhere, also inside writable paths. The
   calls on an open file (`fchmod`, `futimens`, `fsetxattr`) keep working, which is why `cp -p`
   needs nothing. `allow` removes the requirement for programs that change metadata by path
   (`install`, `cp -a`, `rsync -a`, `git`); they can then change the metadata of every file the
   user owns. macOS and Windows protect metadata outside the writable paths in every case.
11. `process.end_with_parent = true` ends the program when the process that started sandy
   ends, for example when the application that runs a helper in the sandbox crashes. The program
   gets a request to end (SIGTERM on Linux and macOS) and is killed if it has not ended 5 seconds
   later; Windows ends the program's job at once. With `children = "allowed"` on Linux and macOS,
   processes the program started can outlive it, as with any end of the program; use
   `children = "contained"` to end them too. The option needs `signals = "isolated"`, so that
   the program cannot kill the process that ends it. Without `--parent-start`, "parent" means
   sandy's direct parent: a wrapper between the application and sandy (`sh -c 'a; sandy ...'`,
   `timeout`, `systemd-run`) is the parent instead. sandy reads the parent's process ID as its
   first step; a parent that ends before that cannot be detected. The caller closes the first gap
   with `--parent-pid` and its own process ID: sandy then refuses when its parent is another
   process. `--parent-start` closes both: the caller adds when its own process started, which no
   other process can have and which nothing but a new start changes, so sandy checks the identity
   of the named process instead of asking whether it is its own parent. The form is
   platform-specific (field 22 of `/proc/PID/stat`, the recorded start time, the creation time).
   sandy also refuses when it sees that the process it would watch has already ended, and on
   macOS when that process is launchd, which has no end to wait for.
12. No writable policy path may reach a location of this user whose content other programs read
   or execute later: the home directory (which it may not contain), the shell startup files,
   autostart entries and user services, `~/.ssh`, and per platform `~/Library/LaunchAgents`, the
   Startup folders, the PowerShell profile folders and `WindowsApps`. A file the program leaves
   in one of them runs outside the sandbox with the user's rights at the next login or the next
   shell, which would make the whole policy pointless. The backend checks this, because only it
   knows the locations of its platform, and it compares paths as rules 3 and 4 do. A path below
   the home directory stays writable: only the locations themselves and the trees of those that
   hold code are protected.

   A directory on sandy's `PATH` is **warned about, not refused**. The escape is the same, a
   file the program leaves there runs when the user next types its name, but a writable path
   that holds one is often what the caller means (a package cache whose `bin` directory is on
   `PATH`, or `/usr/local`), so refusing it would turn away ordinary work. The warning names the
   directory, and the answers are to grant the subdirectories the program needs or to start
   sandy with a `PATH` that does not reach into the writable path.

   The set is a heuristic. No list knows which files the programs of a user trust, and the set
   covers the usual shell and desktop setups only. It also does not depend on the policy:
   `system = "none"` changes nothing about it. The home directory comes from the password
   database or the known-folder API and from the environment, because a program that starts
   sandy with a minimal environment sets neither; when no source names one, only the locations
   that do not depend on it are checked.

13. The standard streams stay the caller's choice, except for the sockets among them. sandy
   passes descriptors 0, 1 and 2 on as it received them and closes every other one, because a
   program reads its input and writes its output through them. Nothing inside the sandbox can
   take rights away from what is already open, so a socket on a standard stream keeps the access
   it was created with, whatever the policy says about networking. `run` therefore looks at the
   three streams before it applies the sandbox and refuses with status 125, naming the stream
   and the socket, when one carries a socket the policy denies: an IP socket or one of another
   family with `ip = "none"`, and an unconnected, datagram or listening Unix socket with
   `unix_sockets = "none"`. A connected Unix stream or seqpacket socket is accepted, because it
   talks only to the peer it already has, which is how a parent passes a pipe (libuv, journald,
   `ssh` without a terminal); what that peer is stays the caller's choice, as with a file. A
   service that is handed its connection on standard input, inetd-style or with systemd
   `Accept=yes`, needs `ip = "all"`. `check` cannot report this: the streams it is given are not
   the streams of the later `run`.

## Links and file identity

A path names a way to a file, not the file itself. Rules 3, 4, 6 and 12 therefore compare more
than the spelling of a path. The resolver compares the policy paths with each other; the
backends compare them with their system set and with the trusted locations of rule 12, through
the same functions (`PathIdentity`, `ProtectedPath`), so one policy is refused for the same
reason whichever check sees it first. A location of a backend counts twice: where it lies and
where its symbolic links lead, because whoever can write the one can repoint it and whoever can
write the other changes what programs read.

- **Two paths, one directory.** sandy compares the identity (device and inode) of a writable
  path with the path it checks and with each of that path's parent directories, so an alias of
  the writable path or of one of its parents counts as the same directory. On Linux it also
  compares where both paths lie inside their file system, which is the mount root from
  `/proc/self/mountinfo` plus the rest of the path. That sees a bind mount of a subdirectory of
  a writable path, which shares no parent directory with it. sandy refuses the policy when it
  cannot read the mount table, because it could not tell the two apart then; the Linux backend
  needs `/proc` anyway. Windows compares paths only (see docs/windows.md).
- **Two names, one file.** A hard link gives one file a second name. The kernels check the name
  a call uses, so a file that is executable under one name and writable under another is both.
  At the start sandy looks for a second name inside the writable paths of every file that must
  not be writable: the files and trees of `read_exec` paths, the program file, its own
  executable and the policy file. It walks the writable trees first, because a file with more
  than one name is rare there, and the executable trees only when it found one. A directory
  the user may not list is skipped: the program runs as the same user and cannot list it
  either. Windows does not compare the names of a file yet, as above.
- **What stays open.** A hard link between a writable path and a file that no rule names, or
  that only a `read` rule names, is allowed: the program can change that file through the
  writable name. Refusing it would stop the package managers that fill a project from a shared
  cache with hard links, so the policy decides what a writable path may hold. The entries of the
  system set and the locations of rule 12 are compared as paths and directories, not for second
  names: a hard link of a shell startup file inside a writable path stays writable through that
  name. Two names that different file systems show for one file, as a passthrough FUSE mount
  does, have different identities and stay unseen. The check runs at the start, so a link that a
  process outside the sandbox makes while the program runs is not covered. The program cannot
  make one itself: it gets no link right out of its writable paths and no execute access inside
  them.

## Exposed ports

`network.expose` makes a loopback port of the program reachable from outside the sandbox.
sandy listens on `listen` (a loopback address) and relays every connection to `port` on the
loopback address of the same family, where the program listens. The relay copies bytes and never
interprets them.

Windows needs this: it blocks every inbound loopback connection into an AppContainer, with or
without the loopback exemption. A relay inside the same AppContainer can reach the program over
loopback, and a listening socket that sandy creates outside the container accepts connections from
outside. Linux and macOS relay the same way, so a policy means the same on every platform.

Rules:

1. `listen` must be a loopback address and must differ from the program's own address.
2. The program needs `ip = "all"` to listen in this version.
3. The relay ends with the program. On Windows the job object ends it; on Linux and macOS the
   relay watches the program's process.
4. The relay is confined as tightly as the platform allows: on Windows it runs in the program's
   AppContainer and job; on Linux and macOS it runs outside the program's sandbox in its own
   sandbox with no file access.
5. Each exposed or forwarded port relays at most `sandy_relay::MAX_CONNECTIONS` connections at
   the same time, so clients of one port cannot take the connections of another.

## Forwarded ports

`network.forward` is the mirror of `expose`: it lets the program reach a loopback service outside
the sandbox. The program connects to `port` on the loopback address of the same family as `to`;
sandy relays each connection to `to`.

Windows needs this: an AppContainer cannot connect to loopback services outside it unless an
administrator installs a loopback exemption. A relay inside the AppContainer accepts the
program's connection over loopback (allowed inside one AppContainer) and passes it to sandy
outside through a Unix domain socket, which the loopback isolation does not filter; sandy then
connects to `to`. No administrator step is needed. Linux and macOS relay through the same kind of
confined relay process as `expose`, so a policy means the same on every platform.

Rules:

1. `to` must be a loopback address; the program's address (`port`) must differ from it.
2. The program needs `ip = "all"` to connect in this version.
3. No address may be used by two relays (`expose` or `forward`), and `to` must not lead back into
   the sandbox (an exposed address).
4. The relay ends with the program and is confined like the `expose` relay.
5. Lifetime of both relays: when the program ends, the relay closes its listeners at once, gives
   connections it already accepted at most one second to deliver their remaining data, and then
   ends. A program that connects, writes and exits immediately therefore does not lose its data,
   and no relay outlives the program by more than one second, except when the program stopped it
   (below). Connections still open when that second ends close with a reset, so no peer takes a
   cut stream for a complete one. With `process.children = "contained"` on Linux and macOS, the
   relay watches the supervising sandy instead, which ends after the program's process group,
   and also a pipe that only the guard holds, so it ends with the group also while sandy is
   stopped.

   With `signals = "any"` the program can also send SIGSTOP, which no process can block, and a
   stopped relay sees nothing. On Linux the relay has a watchdog for that: the kernel kills it
   two seconds after its poll loop last ran, so the bound for a stopped relay is two seconds
   instead of one (docs/linux.md, "Exposed and forwarded ports"). Windows is not affected: sandy
   terminates the relay's job object from outside the sandbox. On macOS a stopped process cannot
   wake itself, so there the bound holds only with `signals = "isolated"` (docs/macos.md).
6. Who may connect: an exposed port is meant for other processes, including those of other
   users, and the program's own listener is reachable directly on Linux and macOS anyway, so
   the relay serves every connection there. A forwarded port is for the program alone, and the
   relay reaches `to` as sandy's user. On Linux it therefore refuses connections whose other end
   belongs to another user, and refuses the run when the kernel cannot tell it the owner
   (docs/linux.md). On macOS it cannot ask, so a forwarded port is reachable by every local user
   (docs/macos.md). On Windows only the program's AppContainer reaches it.
7. The relay passes the end of a stream on as it came: a normal end as a half close, and a reset,
   or data the relay cannot deliver, as a reset of the other side. After one direction of a
   connection has ended, the other ends when it stays idle for `sandy_relay::HALF_CLOSED_IDLE`
   (60 seconds), so a peer that never sends again cannot hold the connection and its slot.

## Requirements and the enforcement plan

`ResolvedPolicy::requirements` derives the guarantees a policy needs:

| Requirement | When |
|---|---|
| `FilesystemConfined` | always |
| `NoPrivilegeEscalation` | always |
| `ProcessMemoryIsolated` | always |
| `InheritedHandlesClosed` | always |
| `EnvironmentControlled` | always |
| `IpNetworkDenied` | `network.ip = "none"` |
| `UnixSocketsDenied` | `network.unix_sockets = "none"` |
| `SignalsIsolated` | `process.signals = "isolated"` |
| `MetadataConfined` | `linux.path_metadata = "deny"` (default) |
| `ExposedPortsRelayed` | `network.expose` is not empty |
| `ForwardedPortsRelayed` | `network.forward` is not empty |
| `ChildProcessesDenied` | `process.children = "none"` |
| `ChildProcessesContained` | `process.children = "contained"` |
| `EndsWithParent` | `process.end_with_parent = true` |

A requirement is a lower bound. A backend may deny more, but never less. For example,
`UnixSocketsDenied` guarantees that the program cannot connect to Unix sockets outside the paths
it may write; Linux and macOS deny connections to every Unix socket, while Windows checks access
to a socket through its file and therefore allows the sockets in the `read_write` paths and in
the program's private AppContainer folder (docs/windows.md).
(On Linux with `ip = "all"` a socket pair can still take a free abstract name; see
`docs/linux.md`.)

The backend reports each requirement as enforced (naming the mechanism) or unavailable (naming the
reason). `EnforcementPlan::new` treats a requirement without a report as unavailable, so a backend
cannot weaken the sandbox by omission. `sandy check` prints the plan. `sandy run` starts the
program only when every requirement is enforced, and the backend's `run` must fail rather than
continue if any mechanism fails while it is applied.

`plan` changes nothing on the host, so some reasons for `run` to refuse are invisible to it: a
port of a relay that another process holds, for example. `check` therefore also calls the
backend's `verify`, which may touch the host as long as it leaves it as it found it; its reports
join the plan, where an unavailable report wins. `run` does not call `verify`: it finds out while
it applies the sandbox, and it stays the authoritative answer, because a trial bind can be stale
a moment later.

## Process model

- Linux and macOS: sandy restricts itself, then calls `execve` on the program. The program keeps
  sandy's process ID, so the caller's process handle, signals and exit status refer to the program
  directly.
- Linux and macOS with `process.children = "contained"`: sandy forks the program and stays its
  parent. sandy forwards every signal it receives to the program, except `SIGCHLD`, `SIGCONT`,
  `SIGTTIN`, `SIGTTOU` and the fault signals, which it cannot wait for, and `SIGKILL` and
  `SIGSTOP`, which cannot be caught at all. It exits with the program's exit status, or 128
  plus the signal number when a signal ended the program. With a terminal, sandy follows job
  control: the program's process group gets the terminal when the program uses it, and the rest
  of sandy's job gets it back when it uses it; any other stop of the program stops sandy, and
  `SIGCONT` to sandy continues the group.
- Windows: there is no `execve`. sandy creates the program inside the AppContainer and a job
  object with kill-on-close, waits, and exits with the program's exit code. If sandy dies, the job
  closes and the program dies with it.

## Mechanisms (each backend section is owned by its backend)

### Linux

Details, the minimal system set and the known limitations are in [linux.md](linux.md).

- Order: mark descriptors above 2 close-on-exec, `PR_SET_NO_NEW_PRIVS`, check that the process
  has one thread, Landlock `restrict_self`, up to four seccomp filters (TSYNC), `execve`.
  Everything that can fail on bad input is prepared before the first step. Landlock restricts
  the calling thread, so the thread check is what makes the domain cover the whole process.
- Landlock (ABI 1 or newer, read from the kernel at run time) handles every file system right of
  the ABI. Writable paths never get execute, symbolic link, named pipe or device rights. ABI 6
  scopes signals (required for `signals = "isolated"`) and abstract Unix sockets; ABI 9 denies
  pathname Unix sockets when `unix_sockets = "none"`; ABI 4 denies TCP when `ip = "none"`.
- Seccomp allowlist: the reviewed system call table of Linux 7.2; every other number, x32 numbers,
  `clone3`, `openat2` and `fanotify_init` fail with `ENOSYS`; other CPU architectures are killed.
- Seccomp socket family filter: `socket` with a family outside the policy (an allowlist) fails
  with `EAFNOSUPPORT`, so that programs fall back as they would on a kernel without the family.
- Seccomp extended attribute filter: with `path_metadata = "deny"`, the reads that take a path
  fail with `ENOTSUP`, the error of a file system without extended attributes, so that programs
  skip them instead of failing.
- Seccomp denylist (`EPERM`): datagram socket pairs when Unix sockets are denied, io_uring,
  ptrace and `process_vm_*`, System V IPC, POSIX message queues, namespaces, mounts, `bpf`,
  `perf_event_open`, `userfaultfd`, keyrings, the security module calls,
  `TIOCSTI`/`TIOCLINUX`/`TIOCSETD`, the file system ioctls that change a file through a
  read-only descriptor (inode flags, fs-verity, fscrypt policies, btrfs subvolumes), file leases
  and delegations (`F_SETLEASE`, `F_SETDELEG`), with `signals = "isolated"` also `TIOCSPGRP`,
  `TIOCSWINSZ` and `setpgid` into a process group that exists, calls that need capabilities,
  `open` with access mode 3 (Landlock does not check it), the path-based metadata calls when
  `path_metadata = "deny"`, setuid and setgid mode bits, changes of the limits, priority and CPU
  affinity of other processes, and before Landlock ABI 3 `truncate` for every path and
  `O_TRUNC` on a read-only open.
- `process.children = "none"`: the seccomp denylist allows `clone` only with `CLONE_THREAD` and
  denies `fork` and `vfork`; `clone3` fails with `ENOSYS`, so threads use `clone`.
- `process.children = "contained"`: sandy becomes a child subreaper and forks a guard process,
  which leads a new process group, and then the program, which joins that group and confines
  itself as above. The seccomp denylist denies `setsid` and `setpgid`, and the Landlock signal
  scope keeps the program from signaling sandy or the guard, so no process the program starts can
  leave the group. The guard watches the program with a pidfd and sandy through a pipe, and kills
  the group when either ends, so the group ends with the program even while sandy is stopped. The
  program writes its own process ID into that pipe, after it has joined the group, so the guard
  learns it without sandy running again after the fork and never before a kill of the group would
  reach the program. sandy also kills the group when the program exits and waits until the group
  is gone.
- `process.end_with_parent`: a watcher process, forked twice like the relay, polls pidfds for
  sandy's parent and for the program (with `contained`: the supervising sandy). When the parent
  ends, it sends SIGTERM and SIGCONT and, 5 seconds later, SIGKILL. Like the relay, it runs in a
  session of its own with every signal except the fault signals blocked, so no process group or
  terminal signal reaches it. It confines itself with no_new_privs, Landlock without file access
  or TCP, and a seccomp filter limited to polling, `pidfd_send_signal`, the readiness report,
  ending and the memory and clock calls of the Rust runtime; it has no Landlock signal scope,
  because it must signal the program. Its filter allows the signal only through the program's
  descriptor. It is also undumpable, so a program with a write grant on `/proc` cannot make the
  out-of-memory killer end it first; the supervising sandy and its guard do the same. With
  `--parent-start` sandy checks field 22 of `/proc/PID/stat` of the named process after
  `pidfd_open` instead of asking whether it is its own parent; a caller can also let the kernel
  do the whole job with `clone3(CLONE_PIDFD_AUTOKILL | CLONE_AUTOREAP | CLONE_NNP)` on Linux 7
  (see docs/linux.md).
- - Exposed and forwarded ports: one relay, forked twice from the single-threaded sandy before it
  confines itself, so it is not a child of the program. It watches the program with a pidfd and
  ends at most one second after it (rule 5 of "Forwarded ports"), or two seconds when the program
  stopped it, which a timer the relay re-arms takes care of. It confines itself with
  no_new_privs, Landlock without file access (TCP connect only to the relay targets from ABI 4)
  and a seccomp filter limited to TCP, copying, threads and that timer. A forwarded port serves
  only sandy's own user (rule 6 of "Forwarded ports").
- Refused: no Landlock (the reason names the fix), no seccomp, root or any capability, a writable
  path that overlaps the minimal system set (rule 6), a program whose ELF loader no executable
  path covers (the kernel opens it during `execve`).

### macOS

- A Seatbelt profile (SBPL) generated from the policy: deny by default, then the policy paths, the
  minimal system set, a list of readable sysctls, and networking when the policy allows it. Every
  path is a profile parameter, so no character in a path can change the profile.
- sandy applies the profile to itself with `sandbox_init_with_parameters`, loaded at run time from
  `libsandbox` with `dlopen`, and checks with `sandbox_check` that it took effect. Then
  `posix_spawn` with `POSIX_SPAWN_SETEXEC` replaces sandy with the target, like `execve`.
  `POSIX_SPAWN_CLOEXEC_DEFAULT` makes the kernel close every descriptor except 0, 1 and 2.
- No Mach or XPC service. This closes LaunchServices, Apple events, launchd jobs and the
  pasteboard, through which another process could act for the target.
- Setuid and setgid files never execute. The root of a writable path cannot be deleted or
  replaced, so the target cannot redirect the next run with a symbolic link.
- Hard links are denied; clones (`std::fs::copy`) work only into writable paths and only from
  files the target may read. ptrace attach is denied (Seatbelt checks it as `system-debug`).
- dyld needs the root directory itself (only the names in `/`) to find the shared cache, so the
  minimal system set contains it; with `system = "none"` no program can start on macOS, so the
  backend refuses that unless a policy path covers "/".
- Name resolution is part of `ip = "all"`: the profile allows exactly the Unix socket of
  mDNSResponder, so DNS does not need `unix_sockets = "all"`.
- Metadata (mode, owner, flags, times, extended attributes, ACLs) can change only on `read_write`
  paths, through paths and open descriptors alike. `linux.path_metadata = "allow"` only drops the
  requirement; the profile is the same.
- Exposed and forwarded ports: sandy binds the listeners, forks one relay twice so that launchd
  adopts it (it is not the program's child), and the relay watches the program's process ID with
  kqueue (`NOTE_EXIT`). The relay has its own profile: accept on its listeners, connect only to
  the targets (the program's ports for `expose`, `to` for `forward`), no files, no Mach services.
  Like the watcher below, it runs in a session of its own with every signal except the fault
  signals blocked. sandy execs only after the relay reports ready.
- `process.children = "none"`: the profile denies `process-fork`, which Seatbelt checks for
  `fork`, `vfork` and `posix_spawn`; threads and `execve` stay allowed.
- `process.children = "contained"`: sandy forks a guard process outside the program's group,
  which forks an anchor that leads a new process group, and then the program, which joins that
  group, writes its own process ID into the pipe to the guard, applies the profile and executes
  the target with `execve` after marking every descriptor above 2 close-on-exec. As on Linux, the
  program sends the ID itself, and only once it is in the group, so the guard learns it without
  sandy running again after the fork and never before a kill of the group would reach the
  program. The profile denies `setpgid`, `setsid` and `posix_spawn` with
  `syscall-unix` rules (the flags `POSIX_SPAWN_SETSID` and `POSIX_SPAWN_SETPGROUP` change the
  group inside `posix_spawn`, which no rule can inspect), and the signal rule keeps the program
  from signaling sandy, the guard or the anchor, which run outside the sandbox. The guard watches
  the program and a pipe from sandy with kqueue and, when either ends, sends SIGKILL to the group
  until no live process is left: on macOS a process being forked can miss one signal for its
  group. sandy does the same after the program exits. The guard reaps the anchor, which keeps the
  group's ID reserved, only after sandy is done or gone.
- `process.end_with_parent`: a watcher process, forked twice like the relay, registers
  `NOTE_EXIT` for sandy's parent and for the program (with `contained`: the supervising sandy)
  and then applies its own profile (no files, no network, no Mach services, signals allowed).
  sandy checks after the watcher is ready that its parent is unchanged, so the registration names
  the real parent. When the parent ends, the watcher sends SIGTERM and SIGCONT and, 5 seconds
  later, SIGKILL. macOS has no pidfd: the watcher signals by process ID and checks for the
  program's end right before each signal. With `--parent-start` sandy checks the named
  process's recorded start time instead of `getppid`, before and after the registration. It
  refuses process 1: macOS has no child subreaper, so launchd is the parent of every orphan.
- `sandy check` compiles the profile without applying it, so it reports operations or filters that
  this macOS does not know.
- Refused: sandy running through Rosetta, and on Apple silicon a program without arm64 code, or
  a script whose interpreter has none; Rosetta cannot load its runtime inside the sandbox.
- `docs/macos.md` describes the profile, the system set with a reason per entry, and the known
  limitations.

### Windows

Details, limitations and sources: `docs/windows.md`.

- Requires Windows 10 1809 (build 17763) or later; `IpNetworkDenied` also requires the fix for
  CVE-2021-41338. `sandy.exe` starts on older builds and the plan names the reason.

- AppContainer named by `windows.appcontainer_name`; sandy creates its profile on first use.
  While a program runs, a second run under the same name with a different policy is refused,
  because processes in one AppContainer can reach and control each other (see "Local servers in the
  sandbox" in `docs/windows.md`). One policy per AppContainer while runs overlap, coordinated
  through a lock file of the user and keyed on the AppContainer SID, because Windows derives the
  SID from the name without regard to case.
- File grants: one capability per policy path (named after the AppContainer, the level and the
  file ID), with one inheritable ACE on the path. The program starts with the capabilities of the
  current policy only, so grants of older policies grant nothing. sandy never removes grants and
  serializes its DACL changes with a lock file of the user, so concurrent runs do not conflict.
  Read and read-write never contain `FILE_EXECUTE`; read levels contain no right that changes
  metadata. sandy refuses to propagate a grant through junctions or symbolic links. The system
  set is what Windows grants ALL APPLICATION PACKAGES; `system = "none"` is unavailable.
- Network capabilities `internetClientServer` and `privateNetworkClientServer` only with
  `ip = "all"`. Connections from the program to loopback listeners outside need the loopback
  exemption, which `sandy setup` installs (administrator rights); connections from outside to
  the program are always blocked. An exempt AppContainer reaches loopback without capabilities,
  so `ip = "none"` refuses it.
- `UnixSocketsDenied` through the file ACL: AF_UNIX connect needs write access to the socket
  file, which the program has only in read-write paths and its profile folder.
- The AppContainer profile folder (`...\Packages\<name>\AC`, which holds `TEMP`) is private,
  writable scratch space that Windows always creates and sandy cannot remove. sandy reduces the
  AppContainer's allow entry on it to the rights of a `read_write` path, so the entry loses
  `FILE_EXECUTE`, `WRITE_DAC` and `WRITE_OWNER`: the program can neither execute what it writes
  there (the writable-never-executable rule) nor rewrite the permissions to grant execute back.
  A deny entry would not help: the AppContainer access check ignores a deny ACE for the package
  SID. The folder holds no user data and persists across runs.
- Writable paths (rules 3 and 6): the plan refuses a `read_write` path that overlaps the Windows
  or a program files directory, or where ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION
  PACKAGES, the policy's AppContainer or one of its network capabilities may execute files, also
  only files created later. When sandy adds the grant it walks the tree and refuses a file below
  the path whose own permissions say the same.
- sandy sets `SystemRoot` and `LOCALAPPDATA`; without the latter Windows refuses to create an
  AppContainer process. Windows sets `LOCALAPPDATA`, `TEMP` and `TMP` to the profile folder.
- Job object with kill-on-close, no breakaway and all UI restrictions. The program is created
  suspended and assigned before it runs. Inside an outer job with UI restrictions Windows cannot
  nest this job, so the plan refuses; sandy never breaks away from an outer job.
- `network.expose`: sandy binds the listening socket outside the AppContainer and starts
  `sandy.exe __relay` in the program's AppContainer and a job of its own before the program. The
  relay has no network capability and only read and execute on `sandy.exe`; the program can
  control the relay, which gives it nothing beyond the exposed listener. The plan refuses when
  `sandy.exe` cannot be granted or lies in a read-write path; `sandy setup` with the policy adds
  the grant.
- `network.forward`: `sandy.exe __forward` in the program's AppContainer and the relay job
  creates the program's listener itself and passes each connection over an AF_UNIX socket that
  only the relays may open to sandy, which connects to the target. No loopback exemption is
  needed. The plan also refuses when AF_UNIX is missing or the socket paths exceed 107 bytes.
- `process.children = "none"`: the program's job has an active-process limit of 1, which the
  program cannot change; its console host is not counted. The relays always run without a
  console and with `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`, so the program cannot start
  processes through them.
- `process.children = "contained"` needs nothing beyond the job: every child joins the program's
  job (no breakaway), sandy ends the job when the program exits, and kill-on-close ends it when
  sandy dies. `allowed` behaves the same on Windows.
- `process.end_with_parent`: sandy finds its parent in a process snapshot, opens it and checks
  that it was created before sandy (Windows records only the parent's process ID, which another
  process can have once the parent has ended). With `--parent-start` it requires that exact
  creation time instead, which a clock change cannot alter and a reused process ID cannot have.
  sandy waits for the program and the parent, and ends the program's job when the parent ends.
- Relay lifetime (rule 5): when the program exits, sandy ends its job at once and closes the
  relays' standard input; the relays accept what already waits in the backlog, close their
  listeners, drain for at most one second and end; sandy ends the relay job one second after
  the program's end.
- Handle inheritance limited to the standard handles with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
  The program gets its own console and never a console handle of sandy; sandy relays its console
  through pipes and ends the job on Ctrl+C.

## Exit status

| Status | Meaning |
|---|---|
| program's status | `sandy run` started the program |
| 128 + signal number | Linux and macOS with `process.children = "contained"`: a signal ended the program |
| 125 | sandy failed or refused (invalid policy, unenforceable policy, a socket on a standard stream the policy denies, setup failure) |
| 0 / 1 | `sandy check`: enforceable / not enforceable |

The caller sees sandy's process ID where sandy stays the parent, and 125 means both "sandy
refused" and "the program exited with 125". These are additions, not changes: `--status-fd`
carries the program's process ID and how it ended on a descriptor of the caller's choosing,
which sandy makes close-on-exec and keeps out of what the program inherits. The lines are
`pid N`, then `exited N` or `signaled N`, or `failed` when sandy itself failed. See README.md,
"The status record". No exit status changes meaning, because callers parse the documented ones.

## Testing

`sandy-probe` (in `sandy-cli`) performs one action per argument pair and reports `ok`, `denied`
or `error`. The escape tests in `crates/sandy-cli/tests/escape.rs` run it inside the sandbox. Each
denial is checked against a control run outside the sandbox, so a test cannot pass because the
action was impossible anyway. The same tests run on every platform; platform-specific escape
routes get additional tests. `check.rs` holds the agreement tests: for every case where `run`
refuses a policy, `sandy check` must refuse it too.

## Dependencies

sandy has seven direct dependencies: `landlock` and `seccompiler` on Linux, `windows-sys` on
Windows, `libc` on Unix, and `lexopt`, `serde` and `toml` everywhere. `deny.toml` turns that into
a rule the `audit` workflow enforces: only the crates listed there may be in the tree, at any
version, and only from crates.io. A crate that appears, an advisory, a yanked version or an
unexpected license fails the check. Advisories that report a crate as unmaintained or unsound
count as errors, not as notes.

### seccompiler

seccompiler's standalone repository is archived. Work continues in the rust-vmm monorepo, which
has published nothing newer on crates.io, so 0.5.0 of 2025-03-07 is the last release. sandy keeps
it, pinned by the lock file, for these reasons:

- It is a leaf crate, and its only dependency is `libc`.
- sandy uses a narrow part of it: `SeccompFilter`, `SeccompRule`, `SeccompCondition` with the
  `Dword` compares, the `Allow` and `Errno` actions, and `apply_filter_all_threads`. It assembles
  BPF and decides nothing.
- The system call numbers are sandy's own, taken from `libc::SYS_*`, so a stale table in
  seccompiler cannot reach the filters.
- `compiled_programs_match_the_snapshot` in `crates/sandy-linux/src/filter.rs` pins the compiled
  programs against `crates/sandy-linux/snapshots/x86_64.txt`, and the interpreter tests beside it
  check what those programs decide. A version of seccompiler that compiles the same rules
  differently is a diff to read, not a silent change.

No advisory against seccompiler exists today, so `deny.toml` has nothing to silence. If one
appears, the answer is a decision and not a quiet `ignore` entry: either replace the crate, or
write here why it stays and name the advisory in `deny.toml` with that reason. The other things
that would change the decision are a bug in its code generation and a filter sandy needs that it
cannot express. The replacement would not be another crate but a generator inside sandy, a few
hundred lines against the same `libc` constants, which the interpreter tests would then test
directly.

## Release integrity

The `release` workflow builds every target from a tag with `--locked`, keeps the path of the
checkout and of `CARGO_HOME` out of the binary, and packs the archives with sorted entries, a
fixed time and no owner. A second job builds one target in two directories and compares the
binaries, so a change that ties the output to the machine that built it is noticed.

Every archive gets a GitHub build provenance attestation, which names the workflow, the commit
and the run that produced it. The job verifies the attestations before it creates the draft, so a
release never carries an archive that cannot be checked. A user checks a download with `gh
attestation verify <archive> --repo <owner>/<repo>`.

`SHA256SUMS` says that the archives belong together, not who made them. A maintainer signature of
that file would say it, and there is none yet. The macOS binaries carry only the linker's ad-hoc
signature, and `sandy.exe` has no Authenticode signature; the workflow holds both steps, skipped
until the certificates exist.

## Code layout

| Crate | Role | May depend on |
|---|---|---|
| `sandy-core` | policy, validation, requirements, plan, backend trait | nothing platform-specific |
| `sandy-linux`, `sandy-macos`, `sandy-windows` | one backend each; empty on other platforms | `sandy-core`, `sandy-relay` |
| `sandy-relay` | byte relay behind `expose` and `forward` | nothing platform-specific |
| `sandy-cli` | command line, backend selection, test probe | all of the above |
