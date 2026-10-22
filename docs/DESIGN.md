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
unix_sockets = "none"         # "none" | "all"

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

- `PR_SET_NO_NEW_PRIVS` against privilege escalation.
- Landlock for the filesystem rules (and ptrace isolation, which every Landlock domain gets).
- A seccomp-bpf filter: deny `socket(AF_UNIX)` unless allowed (Landlock does not cover connecting
  to pathname Unix sockets, and the D-Bus session bus allows starting arbitrary commands through
  systemd), deny `socket(AF_INET/AF_INET6)` unless allowed, deny `ptrace`, `process_vm_*`,
  namespace, mount, `bpf`, `keyctl`, `io_uring` and `TIOCSTI`/`TIOCLINUX`, block foreign
  system call architectures.
- Landlock ABI 6 scoping for signals and abstract Unix sockets where available.
- Close every inherited file descriptor except 0, 1 and 2.
- Hosts without Landlock: refused when the policy needs filesystem confinement (it always does in
  version 1). See `docs/research/linux-mechanisms.md` for the availability analysis.

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
- Setuid and setgid files never execute. Policy paths cannot be deleted or replaced, so the target
  cannot redirect the next run with a symbolic link.
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

- AppContainer with a stable profile name. Access to policy paths through access control entries
  for the AppContainer SID. Read access excludes `FILE_EXECUTE`.
- Network capabilities only when `ip = "all"`; loopback traffic with processes outside the
  container needs an exemption, which `sandy setup` installs with admin rights.
- Job object with kill-on-close. Handle inheritance limited to standard handles with
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.

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
