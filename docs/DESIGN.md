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

[process]
signals = "any"               # "any" | "isolated"

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
9. Children of the program inherit the sandbox on every platform.
10. `linux.path_metadata = "deny"` (the default) requires that permissions, owner, timestamps and
   extended attributes of files outside the policy paths cannot change. Landlock does not
   control these calls, so the Linux backend denies the path-based variants (`chmod`, `chown`,
   `utimensat` with a path, `setxattr` and relatives) everywhere, also inside writable paths. The
   calls on an open file (`fchmod`, `futimens`, `fsetxattr`) keep working. `allow` removes the
   requirement for programs that change metadata by path (`tar`, `cp -p`, `install`); they can
   then change the metadata of every file the user owns. macOS and Windows protect metadata
   outside the writable paths in every case.

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
- `sandy check` compiles the profile without applying it, so it reports operations or filters that
  this macOS does not know.
- `docs/macos.md` describes the profile, the system set with a reason per entry, and the known
  limitations.

### Windows

Details, limitations and sources: `docs/windows.md`.

- AppContainer named by `windows.appcontainer_name`; sandy creates its profile on first use.
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
- `unix_sockets = "none"` is unavailable with read-write paths: AF_UNIX connect needs only write
  access to the socket file.
- Job object with kill-on-close, no breakaway and all UI restrictions. The program is created
  suspended and assigned before it runs.
- Handle inheritance limited to the standard handles with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
  The program gets its own console and never a console handle of sandy; sandy relays its console
  through pipes and ends the job on Ctrl+C.

## Exit status

| Status | Meaning |
|---|---|
| program's status | `sandy run` started the program |
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
| `sandy-linux`, `sandy-macos`, `sandy-windows` | one backend each; empty on other platforms | `sandy-core` |
| `sandy-cli` | command line, backend selection, test probe | all of the above |
