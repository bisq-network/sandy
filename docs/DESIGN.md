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

Command line options extend the policy file (`sandy --help`).

Rules:

1. Paths must be absolute and must exist. sandy resolves symbolic links before it builds the
   sandbox, so all backends see the same object.
2. A rule applies to the path and everything beneath it.
3. No path may be both writable and executable, also not through nesting. sandy rejects such a
   policy. The program could otherwise drop an executable that a process outside the sandbox
   later runs.
4. No policy path may lie inside a writable path. sandy resolves symbolic links at every start,
   so the program could replace such a path with a link and widen its access at the next start.
   For the same reason the integrator must keep the parent directories of policy paths out of the
   program's reach.
5. The program file itself gets read and execute access automatically.
6. `system = "minimal"` adds a backend-defined read-only set of system paths that programs need to
   start: shared libraries, loader configuration, time zone data, random devices. Each backend
   documents its set and the reason for every entry. The set never contains user data.
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
     program ends, also when sandy itself is killed. On Linux, sandy then stays the program's
     parent instead of replacing itself with it (see "Process model"). macOS cannot enforce it
     yet, so sandy refuses there.

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
   calls on an open file (`fchmod`, `futimens`, `fsetxattr`) keep working. `allow` removes the
   requirement for programs that change metadata by path (`tar`, `cp -p`, `install`); they can
   then change the metadata of every file the user owns. macOS and Windows protect metadata
   outside the writable paths in every case.
11. `process.end_with_parent = true` ends the program when the process that started sandy ends,
   for example when the application that runs a helper in the sandbox crashes. The program gets a
   request to end (SIGTERM on Linux) and is killed if it has not ended 5 seconds later; Windows
   ends the program's job at once. With `children = "allowed"` on Linux, processes the program
   started can outlive it, as with any end of the program; use `children = "contained"` to end
   them too. The option needs `signals = "isolated"`, so that the program cannot kill the process
   that ends it. "Parent" means sandy's direct parent: a wrapper between the application and
   sandy (`sh -c 'a; sandy ...'`, `timeout`, `systemd-run`) is the parent instead. sandy reads
   the parent's process ID as its first step; a parent that ends before that cannot be
   detected. The caller closes this gap with `--parent-pid` and its own process ID: sandy then
   refuses when its parent is another process. sandy also refuses when it sees that its parent
   has already ended. macOS cannot enforce the option yet, so sandy refuses there.

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
5. At most `sandy_relay::MAX_CONNECTIONS` connections are relayed at the same time.

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
   and no relay outlives the program by more than one second. With
   `process.children = "contained"` on Linux, the relay watches the supervising sandy instead,
   which ends after the program's process group.

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
`UnixSocketsDenied` guarantees that the program cannot connect to Unix sockets outside its
`read_write` paths; Linux and macOS deny Unix sockets completely, while Windows allows sockets
inside `read_write` paths, because Windows checks access to a socket through its file.

The backend reports each requirement as enforced (naming the mechanism) or unavailable (naming the
reason). `EnforcementPlan::new` treats a requirement without a report as unavailable, so a backend
cannot weaken the sandbox by omission. `sandy check` prints the plan. `sandy run` starts the
program only when every requirement is enforced, and the backend's `run` must fail rather than
continue if any mechanism fails while it is applied.

## Process model

- Linux and macOS: sandy restricts itself, then calls `execve` on the program. The program keeps
  sandy's process ID, so the caller's process handle, signals and exit status refer to the program
  directly.
- Linux with `process.children = "contained"`: sandy forks the program and stays its parent. sandy
  forwards every signal it receives to the program, except `SIGCHLD`, `SIGCONT`, `SIGTTIN`,
  `SIGTTOU` and the fault signals, and exits with the program's exit status, or 128 plus the signal number when a signal
  ended the program. With a terminal, sandy follows job control: the program's process group gets
  the terminal when the program uses it, and the rest of sandy's job gets it back when it uses
  it; any other stop of the program stops sandy, and `SIGCONT` to sandy continues the group.
- Windows: there is no `execve`. sandy creates the program inside the AppContainer and a job
  object with kill-on-close, waits, and exits with the program's exit code. If sandy dies, the job
  closes and the program dies with it.

## Mechanisms (initial plan; each backend section is owned by its backend)

### Linux

Details, the minimal system set and the known limitations are in [linux.md](linux.md).

- Order: mark descriptors above 2 close-on-exec, `PR_SET_NO_NEW_PRIVS`, Landlock
  `restrict_self`, two seccomp filters (TSYNC), `execve`. Everything that can fail on bad input
  is prepared before the first step.
- Landlock (ABI 1 or newer, read from the kernel at run time) handles every file system right of
  the ABI. Writable paths never get execute, symbolic link, named pipe or device rights. ABI 6
  scopes signals (required for `signals = "isolated"`) and abstract Unix sockets; ABI 9 denies
  pathname Unix sockets when `unix_sockets = "none"`; ABI 4 denies TCP when `ip = "none"`.
- Seccomp allowlist: the reviewed system call table of Linux 7.2; every other number, x32 numbers,
  `clone3` and `openat2` fail with `ENOSYS`; other CPU architectures are killed.
- Seccomp denylist (`EPERM`): socket families outside the policy (an allowlist), datagram socket
  pairs when Unix sockets are denied, io_uring, ptrace and `process_vm_*`, System V IPC, POSIX
  message queues, namespaces, mounts, `bpf`, `perf_event_open`, `userfaultfd`, keyrings,
  `TIOCSTI`/`TIOCLINUX`, calls that need capabilities, `open` with access mode 3 (Landlock does
  not check it), the path-based metadata calls when `path_metadata = "deny"`, setuid and setgid
  mode bits, changes of the limits, priority and CPU affinity of other processes, and before
  Landlock ABI 3 truncation without write access.
- `process.children = "none"`: the seccomp denylist allows `clone` only with `CLONE_THREAD` and
  denies `fork` and `vfork`; `clone3` fails with `ENOSYS`, so threads use `clone`.
- `process.children = "contained"`: sandy becomes a child subreaper and forks a guard process,
  which leads a new process group, and then the program, which joins that group and confines
  itself as above. The seccomp denylist denies `setsid` and `setpgid`, and the Landlock signal
  scope keeps the program from signaling sandy or the guard, so no process the program starts can
  leave the group. The guard watches the program with a pidfd and sandy through a pipe, and kills
  the group when either ends, so the group ends with the program even while sandy is stopped.
  sandy also kills the group when the program exits and waits until the group is gone.
- `process.end_with_parent`: a watcher process, forked twice like the relay, polls pidfds for
  sandy's parent and for the program (with `contained`: the supervising sandy). When the parent
  ends, it sends SIGTERM and SIGCONT and, 5 seconds later, SIGKILL. Like the relay, it runs in a
  session of its own with every signal except the fault signals blocked, so no process group or
  terminal signal reaches it. It confines itself with no_new_privs, Landlock without file access
  or TCP, and a seccomp filter limited to polling, `pidfd_send_signal`, the readiness report,
  ending and the memory and clock calls of the Rust runtime; it has no Landlock signal scope,
  because it must signal the program.
- Exposed and forwarded ports: one relay forked twice before sandy confines itself, so it is not
  a child of the program. It watches the program with a pidfd and ends at most one second after
  it (rule 5 of "Forwarded ports"). It confines itself with no_new_privs, Landlock without file
  access (TCP connect only to the relay targets from ABI 4) and a seccomp filter limited to TCP,
  copying and threads.
- Refused: no Landlock (the reason names the fix), no seccomp, root or any capability, a writable
  path that contains the dynamic loader.

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
  minimal system set contains it; with `system = "none"` no program can start on macOS.
- Name resolution is part of `ip = "all"`: the profile allows exactly the Unix socket of
  mDNSResponder, so DNS does not need `unix_sockets = "all"`.
- Metadata (mode, owner, flags, times, extended attributes, ACLs) can change only on `read_write`
  paths, through paths and open descriptors alike. `linux.path_metadata = "allow"` only drops the
  requirement; the profile is the same.
- Exposed and forwarded ports: sandy binds the listeners, forks one relay twice so that launchd
  adopts it (it is not the program's child), and the relay watches the program's process ID with
  kqueue (`NOTE_EXIT`). The relay has its own profile: accept on its listeners, connect only to
  the targets (the program's ports for `expose`, `to` for `forward`), no files, no Mach services.
  sandy execs only after the relay reports ready.
- `process.children = "none"`: the profile denies `process-fork`, which Seatbelt checks for
  `fork`, `vfork` and `posix_spawn`; threads and `execve` stay allowed.
- `process.children = "contained"` is not implemented: sandy replaces itself with the program, so
  nothing would end the processes the program leaves behind. The plan reports it unavailable, and
  sandy refuses.
- `process.end_with_parent` is not implemented: no process of sandy watches the parent. The plan
  reports it unavailable, and sandy refuses.
- `sandy check` compiles the profile without applying it, so it reports operations or filters that
  this macOS does not know.
- `docs/macos.md` describes the profile, the system set with a reason per entry, and the known
  limitations.

### Windows

Details, limitations and sources: `docs/windows.md`.

- Requires Windows 10 1809 (build 17763) or later; `IpNetworkDenied` also requires the fix for
  CVE-2021-41338. `sandy.exe` starts on older builds and the plan names the reason.

- AppContainer named by `windows.appcontainer_name`; sandy creates its profile on first use.
  While a program runs, a second run under the same name with a different policy is refused,
  because processes in one AppContainer can reach and control each other (see "Local servers in the
  sandbox" in `docs/windows.md`).
- File grants: one capability per policy path (named after the AppContainer, the level and the
  file ID), with one inheritable ACE on the path. The program starts with the capabilities of the
  current policy only, so grants of older policies grant nothing. sandy never removes grants and
  serializes its DACL changes with a named mutex, so concurrent runs do not conflict. Read and read-write never contain `FILE_EXECUTE`; read levels
  contain no right that changes metadata. sandy refuses to propagate a grant through junctions or
  symbolic links. The system set is what Windows grants ALL APPLICATION PACKAGES; `system =
  "none"` is unavailable.
- Network capabilities `internetClientServer` and `privateNetworkClientServer` only with
  `ip = "all"`. Connections from the program to loopback listeners outside need the loopback
  exemption, which `sandy setup` installs (administrator rights); connections from outside to
  the program are always blocked. An exempt AppContainer reaches loopback without capabilities,
  so `ip = "none"` refuses it.
- `UnixSocketsDenied` through the file ACL: AF_UNIX connect needs write access to the socket
  file, which the program has only in read-write paths and its profile folder.
- The AppContainer profile folder (`...\Packages\<name>\AC`, which holds `TEMP`) is private,
  writable scratch space that Windows always creates and sandy cannot remove. sandy removes
  `FILE_EXECUTE` from the AppContainer's allow entry on it every run, so the program cannot
  execute what it writes there (the writable-never-executable rule). A deny entry would not help:
  the AppContainer access check ignores a deny ACE for the package SID. The folder holds no user
  data and persists across runs.
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
  process can have once the parent has ended). sandy waits for the program and the parent, and
  ends the program's job when the parent ends.
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
| 128 + signal number | Linux with `process.children = "contained"`: a signal ended the program |
| 125 | sandy failed or refused (invalid policy, unenforceable policy, setup failure) |
| 0 / 1 | `sandy check`: enforceable / not enforceable |

## Testing

`sandy-probe` (in `sandy-cli`) performs one action per argument pair and reports `ok`, `denied`
or `error`. The escape tests in `crates/sandy-cli/tests/escape.rs` run it inside the sandbox. Each
denial is checked against a control run outside the sandbox, so a test cannot pass because the
action was impossible anyway. The same tests run on every platform; platform-specific escape
routes get additional tests.

## Code layout

| Crate | Role | May depend on |
|---|---|---|
| `sandy-core` | policy, validation, requirements, plan, backend trait | nothing platform-specific |
| `sandy-linux`, `sandy-macos`, `sandy-windows` | one backend each; empty on other platforms | `sandy-core`, `sandy-relay` |
| `sandy-relay` | byte relay behind `expose` and `forward` | nothing platform-specific |
| `sandy-cli` | command line, backend selection, test probe | all of the above |
