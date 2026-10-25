# macOS backend

The macOS backend confines the target with Seatbelt, the macOS sandbox (Sandbox.kext). sandy
generates a profile in the Sandbox Profile Language (SBPL) from the policy, applies it to its own
process, and then replaces itself with the target. The target keeps sandy's process ID, and every
process it starts inherits the sandbox.

Status: the pure parts (profile generation and planning) are unit tested on every platform. The
parts that call macOS run in the tests on the macOS 15 CI runner (arm64) and on macOS 26 and 27
(arm64); see [Verification](#verification). The x86_64 build has not run on an Intel Mac, and
does not work through Rosetta (see "Known limitations"). An older macOS may reject an
operation or filter in the profile; `sandy check` then reports it and sandy refuses to run.

## What `sandy run` does

1. sandy-core resolves the policy. All paths are canonical, so `/tmp/x` arrives as `/private/tmp/x`.
2. `profile::generate` builds the profile text and its parameters.
3. sandy loads `/usr/lib/libsandbox.1.dylib` with `dlopen` (flag `RTLD_GLOBAL`) and resolves the
   functions it uses with `dlsym(RTLD_DEFAULT, ...)`. `sandbox_init_with_parameters`,
   `sandbox_free_error` and `sandbox_check` live in `libsystem_sandbox`, which libSystem
   re-exports; the compiler functions live in `libsandbox`.
4. sandy changes to the `--cwd` directory, if one is given.
5. `sandbox_init_with_parameters` compiles the profile and applies it to the sandy process.
   `sandbox_check(getpid(), NULL, 0)` must then report that the process is sandboxed.
6. `posix_spawn` with `POSIX_SPAWN_SETEXEC` replaces sandy with the target, like `execve`.
   `argv[0]` is the program name as the caller gave it (`TargetCommand::arg0`).

Before step 5, sandy starts the relay of exposed and forwarded ports and the watcher of
`process.end_with_parent`, if the policy needs them. With `process.children = "contained"`, a
forked child performs steps 5 and 6, with `execve` instead of `posix_spawn` (see
[Contained child processes](#contained-child-processes)).

If any step fails, `run` returns an error and sandy exits with status 125. The target never starts
with a weaker sandbox.

`sandy check` performs steps 2 and 3, asks `sandbox_check` whether sandy already runs in a sandbox,
checks whether the program would run through Rosetta (see "Known limitations"), and compiles the
profile with `sandbox_compile_string` without applying it. The plan reports every requirement that
depends on the profile as unavailable when a function is missing, when sandy is already sandboxed
(macOS ignores a second profile and returns an error, see `sandbox.h`), when the code would run
through Rosetta, or when this macOS rejects the profile (with the compiler's message).
`plan_for(policy, &HostCapabilities)` contains this decision and is pure; only the detection does
I/O.

A profile that compiles can still be refused when it is applied, so `check` also applies it. It
does that in a helper process (`Backend::verify`), because `check` must leave its own process
unsandboxed: the helper applies the program's profile and ends right after. It executes nothing,
because only a `read_exec` path grants `process-exec*` and the profile would refuse the exec. If
the helper cannot apply the profile, every requirement that the profile enforces is reported as
unavailable with the message the kernel gave. A missing Seatbelt and a sandbox around sandy are
already in the plan, so the trial stays silent about them. `check` also binds the listeners of
exposed and forwarded ports for a moment, so a port another process holds is reported instead of
making `run` fail.

## Why in-process `sandbox_init_with_parameters` and not `sandbox-exec`

Both use the same compiler and the same kernel policy. `/usr/bin/sandbox-exec -p PROFILE -D
NAME=VALUE -- PROGRAM` applies the profile to itself and then calls `execvp` (its error messages
name `execvp()`).

| | `sandbox_init_with_parameters` | `/usr/bin/sandbox-exec` |
|---|---|---|
| Status | private: not in the SDK headers; declared and used by Chromium (`sandbox/mac/seatbelt.cc`) | public tool; its man page says "The sandbox-exec command is DEPRECATED" |
| Process ID | the target keeps sandy's process ID | also kept |
| Function missing on a future macOS | `dlsym` fails, `sandy check` reports it, sandy refuses | the exec of `sandbox-exec` fails at run time |
| Descriptors and environment | sandy performs the final exec and controls both | `sandbox-exec` performs the final exec |
| Plan check | sandy compiles the profile without applying it | only by running it |
| Extra trusted binary | none | `/usr/bin/sandbox-exec` (on the sealed system volume) |

sandy uses `sandbox_init_with_parameters` because sandy then performs the final exec itself: it
closes inherited descriptors and sets the environment in the same system call that starts the
target. A missing function also becomes a plan item instead of a failure at run time. The cost:
the functions are private and can change without notice; the public `sandbox.h` says "This header
is deprecated and may be removed in a future release". A change would make `dlsym` or the
compiler fail, and sandy fails closed.

## Mechanisms per requirement

| Requirement | Mechanism |
|---|---|
| `FilesystemConfined` | Profile: `(deny default)`, and every path outside the policy answers `ENOENT`; `file-read*` for every policy path and the system set; `file-write*` only for `read_write` paths; `process-exec*` and `file-map-executable` only for `read_exec` paths, the program and system code. No hard links; clones only into `read_write` paths and only from files the target may read. No Mach or XPC service, so no other process acts on files for the target. Policy paths cannot be deleted or replaced. |
| `NoPrivilegeEscalation` | Only policy paths execute. Sandbox.kext refuses to execute setuid or setgid files from any sandboxed process, and the profile also denies `process-exec*` for files with mode bit `#o4000` or `#o2000`. No Mach service (authorization, privileged helpers, launchd). |
| `ProcessMemoryIsolated` | Profile: `process-info*` (allowed by default) is denied with `ESRCH` and then allowed only for `(target self)`; task ports are denied (`mach-priv*`, `mach-task-name`, `mach-task-read`, `mach-task-inspect`); `ptrace` attach, which Seatbelt checks as `system-debug`, is denied. |
| `InheritedHandlesClosed` | `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`; descriptors 0, 1 and 2 are named with `posix_spawn_file_actions_addinherit_np`. The kernel closes every other descriptor during the exec. With `children = "contained"` the forked target, a single thread, marks every descriptor above 2 close-on-exec (`PROC_PIDLISTFDS`) right before `execve`. |
| `EnvironmentControlled` | `posix_spawn` (with `children = "contained"`: `execve`) receives exactly `command.env`. The backend adds no variable. |
| `IpNetworkDenied` | Profile: no `network-*` rule for IP, and the NECP calls are denied. The name resolver is unreachable unless `unix_sockets = "all"`. |
| `IpNetworkPrivate` | Profile: TCP only, `network-outbound` only to `(remote tcp "localhost:P")` for each forwarded port and `network-bind` and `network-inbound` only on `(local tcp "localhost:E")` for each exposed port, and the NECP calls are denied. The relay binds the forwarded ports at the wildcard addresses without listening. The name resolver is unreachable unless `unix_sockets = "all"`. See [The private network](#the-private-network). |
| `EgressBrokered` | Unavailable: the macOS backend has no egress broker yet, so `run` refuses `network.egress`. |
| `PathsHidden` | Profile: the rule of step 3 of [The generated profile](#the-generated-profile), which every profile has. Unavailable with `unix_sockets = "all"`. See [The file system view](#the-file-system-view). |
| `InboundIpDenied` | Profile: `network-outbound` and `network-bind` for IP sockets, `network-inbound` only for UDP sockets, so `listen` and `accept` fail for TCP (see [Networking](#networking)). |
| `UnixSocketsDenied` | Profile: no `network-bind` or `network-outbound` for Unix sockets. With `ip = "client"` or `ip = "all"`, the resolver socket is the one exception. |
| `SignalsIsolated` | Profile: `(allow signal (target self) (target same-sandbox))` instead of `(allow signal)`, and `(deny system-fcntl (fcntl-command 6))`, which closes `F_SETOWN`, one of the ways to have the kernel send SIGIO to any process. The other ways, through ioctls on sockets and pipes, and the kernel's job control signals stay outside it (see [Signals the profile does not cover](#signals-the-profile-does-not-cover)). |
| `ChildProcessesDenied` | Profile: no `(allow process-fork)`, and an explicit `(deny process-fork)` at the end. Seatbelt checks `fork`, `vfork` and `posix_spawn` without `POSIX_SPAWN_SETEXEC` as `process-fork`; all three fail with `EPERM` (CI run 39857337279 logged `deny(1) process-fork` for each). Threads are no operation, and `execve` of an allowed program, which replaces the image without creating a process, stays covered by `process-exec*`. sandy's own final `posix_spawn` with `POSIX_SPAWN_SETEXEC` is not a `process-fork`, and the relay is forked before the profile applies, so both still work. |
| `EndsWithParent` | A watcher process outside the sandbox with its own profile; see [Ending with the parent](#ending-with-the-parent). |
| `ChildProcessesContained` | sandy stays the target's parent; a guard process leads the target's process group; the profile denies `setpgid`, `setsid` and `posix_spawn`. See [Contained child processes](#contained-child-processes). |
| `MetadataConfined` | Profile: `file-write*`, which includes `file-write-mode`, `-owner`, `-flags`, `-times`, `-xattr`, `-acl` and `-setugid`, is denied explicitly and allowed again only on `read_write` paths. XNU runs the same MAC check for the path and the descriptor variant of each call (`chmod_vnode`, `vn_chown_internal`, `setutimes` and `vn_setxattr` serve both), so descriptors do not bypass the rule, and unlike on Linux the target keeps full metadata access inside writable paths. `linux.path_metadata = "allow"` only drops the requirement; the profile is the same. |

### Inherited descriptors

macOS has no `close_range`. Instead of enumerating the descriptor table, sandy asks the kernel to
close everything: with `POSIX_SPAWN_CLOEXEC_DEFAULT`, "all pre-existing file descriptors in the
parent process are treated as if they had been marked close-on-exec", and
`posix_spawn_file_actions_addinherit_np` keeps 0, 1 and 2 (only those that are open). Together with
`POSIX_SPAWN_SETEXEC` this happens in the system call that starts the target. No descriptor can
appear between a scan and the exec, and a descriptor above the current `RLIMIT_NOFILE` is closed
too. Chromium starts all its child processes on macOS with the same two calls
(`base/process/launch_mac.cc`).

Descriptors 0, 1 and 2 keep what they were opened with, because the target reads its input and
writes its output through them. Before it applies the profile, `run` therefore looks at the three
streams and accepts a socket only when the policy lets the program create one like it. Otherwise it
refuses with exit code 125, naming the stream and the socket: an IP socket with `ip = "none"`, an
unconnected, datagram or listening Unix socket with `unix_sockets = "none"`, and a socket of any
other family under every policy, because the profile allows `system-socket` for AF_UNIX only and
Seatbelt checks the creation of every family but AF_INET and AF_INET6 (see "Networking"). With
`ip = "none"` the program can create an IP socket but cannot bind, connect or send with it, so an
inherited one, which may be connected already, counts as denied. A raw IP socket is refused under
every policy: only root can create one, and sandy refuses an inherited one also when it runs as
root, so that a policy means the same on every platform. An ICMP datagram socket, which an ordinary
user can create (measured), follows `ip`. sandy reads the type with `SO_TYPE` and the family from
`proc_pidfdinfo` (`PROC_PIDFDSOCKETINFO`), because macOS has no `SO_DOMAIN` and `getsockname` fails
for some families: `EINVAL` for AF_ROUTE and `EOPNOTSUPP` for AF_SYSTEM (measured on macOS 26.5),
and both can be created without privileges. A connected Unix stream socket is accepted, because it
reaches only the peer it already has; macOS has no AF_UNIX seqpacket socket. macOS also has no
`SO_ACCEPTCONN` (`getsockopt` answers ENOPROTOOPT for every socket), so the message names a
listening socket by what the kernel does tell about it: it has no peer. `sandy check` cannot report
any of this, because the streams it is given are not the streams of the later `run`. The test is
`a_socket_of_another_family_on_standard_input_is_refused` (AF_ROUTE and AF_SYSTEM).

With `signals = "isolated"` `run` also refuses the master side of a pseudo-terminal on a standard
stream, with exit code 125, naming the stream and saying to pass the slave side or a pipe
instead. Writing Ctrl+C, Ctrl+\ or Ctrl+Z into a master makes the kernel send SIGINT, SIGQUIT or
SIGTSTP to the foreground group of the other side, and the profile's signal rule never sees it
(measured on macOS 26.5: a process outside the sandbox on the other side received each, also
with `children = "contained"`). A write cannot be told from any other. The kernel numbers its
drivers as it starts, so sandy knows a master by the major number of `/dev/ptmx`, of which every
master is a clone; the slaves `/dev/ttys*` have another. The legacy BSD masters `/dev/pty*` cannot
be opened by an ordinary user (`EAGAIN`, measured), and sandy does not look for them. The slave
side, which a program gets when it runs in a terminal, is accepted. The test is
`a_pseudo_terminal_master_on_a_standard_stream_needs_signals_any`.

### Inherited Mach port rights

Mach port rights are not file descriptors, and the profile cannot close them: every lookup
through the inherited bootstrap port is a `mach-lookup`, which the profile denies, but a right
the task already holds needs no lookup. The kernel copies the task's exception ports when it
creates a task and keeps them across `exec`, so a caller with a crash reporter (Crashpad,
Sentry, a debugger) would hand the program a send right to its handler, which the program could
use for forged exception messages. Before it applies the profile, sandy therefore sets the
handler of every machine-independent exception (`EXC_MASK_ALL`, as Chromium's launcher does),
of the crash port (`EXC_MASK_CRASH`) and of the corpse notification (`EXC_MASK_CORPSE_NOTIFY`)
to `MACH_PORT_NULL`. The crash port is not part of `EXC_MASK_ALL`, and it is the one Crashpad's
handler takes. It happens before the relay and the watcher are forked, so they drop the ports
too.

A program that is started by a caller with its own crash reporter loses that reporter, which is
the point. Measured on macOS 26.5: a task starts with a handler for `EXC_MASK_RESOURCE` even
without a crash reporter, the handler survives `exec`, and after the reset the exec'd program
finds none. Neither a login over SSH nor a launchd job has a handler for the crash port, so
only a caller's own crash reporter puts one there. A caller that installs `EXC_MASK_CRASH`,
`EXC_MASK_RESOURCE` and `EXC_MASK_GUARD`, as Crashpad does, and keeps the receive right in a
process of its own handed the program a live send right for the crash port until it was reset
too (`inherited_mach_exception_ports_are_reset`).

Every task has a corpse notification handler, which gets the task of a crashed program. Measured
on macOS 26.5, a process started over SSH has one that leads to the user's ReportCrash agent, a
service outside the sandbox, and a caller can install its own, which then received the crashed
program's task. Without the reset the program would keep a send right to either of them. After
it, the kernel hands a crash to the host's handler, the ReportCrash daemon that runs as root,
which still writes the crash report, but to `/Library/Logs/DiagnosticReports` instead of the
user's `~/Library/Logs/DiagnosticReports`. That directory and its reports are readable only by
root and the group `_analyticsusers`: on the test Mac the administrator account was a member and
the standard account was not. So a standard user cannot read the crash reports of a program
that sandy runs, and the user's own ReportCrash agent does not see the crash. Measured again on
macOS 27.0.1: the report of a program that crashed under `sandy run` went to
`/Library/Logs/DiagnosticReports`, readable only by root and `_analyticsusers`, and the standard
user had no `~/Library/Logs/DiagnosticReports`.

What stays: the host name port, which every process inherits (see "Information the target can
still read").

### SIGPIPE

The Rust runtime of sandy ignores SIGPIPE. `POSIX_SPAWN_SETSIGDEF` with SIGPIPE resets it to the
default action for the target, as `std::process::Command` does for its children. Other signal
dispositions and the signal mask pass through unchanged.

## The generated profile

`profile::generate` writes the sections below in this order. When several rules match an
operation, the later one wins (libsandbox's `sbpl1.scm`: "later class definitions take precedence
of earlier definitions"), so the protections come last. The unit test
`expected_text_for_the_strictest_policy` contains a complete example.

1. `(version 1)` and `(deny default)`.
2. `(deny process-info* file-map-executable file-ioctl file-write*)`. `(deny default)` does not
   cover every operation: Chromium's `renderer.sb` says process-info "operations are allowed by
   default", and Apple's own strict profiles deny `file-map-executable` explicitly. No public
   source lists all such operations, so the profile also denies `file-write*` here. The next
   sections allow these operations again narrowly.
3. Paths and processes outside the policy: `(deny file-read* file-test-existence (with errno
   ENOENT))` and `(deny process-info* (with errno ESRCH))`. `(deny default)` does not cover
   `file-test-existence` either, and it is the only check of `access`, `statfs`, `chdir` and of
   the path that `getattrlist` returns (`ATTR_CMN_FULLPATH`), so those calls answered for every
   path, `statfs` with the device and the directory the volume is mounted on, and the other calls
   answered an existing path (`EPERM`, `EACCES` or `EEXIST`) differently from a missing one
   (`ENOENT`). Now every call on a path outside the policy answers `ENOENT`, as for a path that
   does not exist, also through `/.vol/<dev>/<inode>`, and `proc_pidinfo`, `proc_pidpath` and
   `proc_listallpids` answer `ESRCH` for every other process, as for a process that does not
   exist (measured on macOS 27.0.1). Both rules come before every allow, so the policy's own
   rules win. Writes keep `EPERM` from step 2, so a write to a `read` path does not say that the
   path is missing; outside the policy a write answers `ENOENT` anyway, because the path lookup
   fails first. With `unix_sockets = "all"` the profile allows `file-test-existence` again (see
   [Networking](#networking)).
4. Processes: `(allow process-fork)` unless `process.children = "none"`,
   `(allow process-info* (target self))`, and signals: `(allow signal)` or
   `(allow signal (target self) (target same-sandbox))`. With `children = "none"` the protections
   at the end also contain `(deny process-fork)`.
5. ioctls: `(allow file-ioctl (ioctl-command N) ...)` for `FIONBIO` and `FIOASYNC` (XNU issues
   them for `fcntl(F_SETFL)`, and `vn_ioctl` checks every request) and for `TIOCGETA` and
   `TIOCGWINSZ` (they only read terminal state, so `isatty` and stdio line buffering work). The
   numbers are written as numbers because older compilers do not know the symbols; a compile-time
   assertion compares them with the libc crate.
6. Readable sysctls (see below).
7. The system set, if `system = "minimal"`.
8. Policy paths. A directory uses `subpath`, a file uses `literal`, so a file rule never covers
   the entries of a directory that later replaces the file.

   | Access | Operations |
   |---|---|
   | `read` | `file-read*`, `file-test-existence` |
   | `read_exec` and the program | the above, `file-map-executable`, `process-exec*` |
   | `read_write` | `file-read*`, `file-test-existence`, `file-write*`, `file-clone` |

   `file-test-existence` is a separate operation (used by `access(2)`), not part of `file-read*`.
   `file-clone` is not part of `file-write*` either; without it `clonefile(2)` and therefore
   Rust's `std::fs::copy` (which tries `fclonefileat` first and does not fall back on `EPERM`)
   fail. XNU passes both the source and the destination to the single MAC check of a clone, and
   Apple does not document which one the filter matches. The escape test
   `clones_and_links_stay_inside_the_policy` measures it on every macOS host that runs the
   suite: copies and clones inside a `read_write` path and from a `read` path into it work; a
   clone of a file outside the policy into a `read_write` path, and a clone out of a
   `read_write` path to a place that is not writable, are denied.

9. Networking (see below).
10. Ancestors of every granted path: `file-read-metadata` and `file-test-existence` on each
    directory above it, so `realpath`, `getcwd` and `mkdir -p` can reach the granted path. This
    reveals no directory contents, because listing a directory needs `file-read-data`.
11. Paths spelled through the links of the system set: `(allow file-test-existence (subpath
    ...))` for `/etc`, `/tmp` and `/var`, where the profile grants the link. Seatbelt checks
    `file-test-existence` for the path as the program spelled it, such as `/etc/hosts`, and again
    for the path the link leads to, `/private/etc/hosts`. Measured on macOS 27.0.1 with only the
    real paths allowed: `/etc/hosts`, `/etc/localtime`, the resolver socket
    `/var/run/mDNSResponder`, every path below `$TMPDIR` (which lies below `/var/folders`) and the
    links inside the time zone database, which point to `/var/db/timezone/...`, answered
    `ENOENT`. Because the real path is checked as well, the rule grants nothing that the rules
    for the real paths do not: `access("/etc/passwd")` still answers `ENOENT`
    (`paths_through_the_system_links_reach_only_granted_files`).
12. Protections:
    - Anchors: `(deny file-write-unlink file-write-create (literal ...))` for the root of every
      `read_write` path. Without it the target could delete the root and put a symbolic link in
      its place. The next `sandy run` resolves symbolic links, so it would grant access to the
      link's target, for example the home directory. The OpenAI Codex CLI found and fixed the same
      problem (commit f6950546e5). Policy paths inside writable paths need no rule: sandy-core
      rejects them for the same reason.
    - `(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read
      mach-task-inspect system-debug)`. `file-link` is not part of `file-write*`, and Apple's
      `maild.sb` denies it explicitly after `(deny default)`. A hard link to a file outside the
      policy would make it reachable through a writable path, so links are denied everywhere.
      Links that already exist are a start-time check of the resolver: a `read_exec` file, the
      program, sandy's own executable or the policy file must have no second name inside a
      writable path (see "Links and file identity" in [DESIGN.md](DESIGN.md)).
    - `(deny syscall-unix (syscall-number 427) (syscall-number 217) (syscall-number 479)
      (syscall-number 225))`: `fsgetpath`, `fsgetpath_ext`, `openbyid_np` and `searchfs` find a
      file by volume id and inode number. `fsgetpath` builds the path in the kernel without
      reaching any Seatbelt file operation, so the target could learn the path of any file on the
      data volume from its device and inode number (a finding of the macOS security review;
      contents stayed protected). Seatbelt allows `syscall-unix` by default and filters it by
      number (WebKit's profiles use the same operation). The numbers come from XNU's
      `bsd/kern/syscalls.master`, because older profile compilers do not know every `SYS_` name.
      dyld or libSystem calls `fsgetpath` once while a program starts; the call fails, the
      Sandbox log records `deny(1) syscall-unix 427`, and the program starts normally (CI run
      39767043700).
    - `(deny syscall-unix (syscall-number 142))`: `gethostuuid` returns the hardware UUID, an
      identifier of the machine that every user and every reinstall share. IOKit would give the
      same value (`IOPlatformUUID`) only with `iokit-get-properties`, which the profile denies.
    - `(deny syscall-unix (syscall-number 18) (syscall-number 347))`: `getfsstat` and
      `getfsstat64` list every mounted volume and the directory it is mounted on. The call takes
      no path, so no file rule reaches it, and the list names the disks of the system, including
      any attached external disks. No documented guarantee needs it and no common program reads
      it at startup (measured on macOS 26.5: a shell, Python, git and curl start and run with it
      denied). Number 347 is the 64-bit inode variant that libc calls; 18 is the legacy call.
      `statfs` and `fstatfs`, which take a path the sandbox checks, stay allowed.
    - `(deny syscall-unix (syscall-number 100) (syscall-number 151) (syscall-number 310))`:
      `getpriority`, `getpgid` and `getsid` answer for every process ID with its priority,
      process group and session, and no profile operation covers them. A `syscall-unix` rule sees
      only the number, so the program cannot ask about itself either. Measured on macOS 27.0.1:
      `sh`, `bash` (also on a terminal), `zsh`, Python, git, make, clang (also with modules) and
      swiftc run without them. A program that calls one of them gets `EPERM`, for example
      Python's `os.getpgid`, `os.getsid` and `os.getpriority`.
    - With `ip = "none"` and `ip = "private"`: `(deny syscall-unix (syscall-number 460)
      (syscall-number 490) (syscall-number 501) (syscall-number 502) (syscall-number 522)
      (syscall-number 523))`, the NECP calls (see [Networking](#networking)).
    - With `process.children = "contained"`: `(deny syscall-unix (syscall-number 82)
      (syscall-number 147) (syscall-number 244))`, that is `setpgid`, `setsid` and `posix_spawn`
      (see [Contained child processes](#contained-child-processes)).
    - `(deny file-ioctl (ioctl-command TIOCSTI))`: also covered by step 2, written out so that no
      later change can allow it by accident.
    - Setuid and setgid files (see [Privilege escalation](#privilege-escalation)).
    - `(deny system-fcntl (fcntl-command 80 110))`: `F_MAKECOMPRESSED` and `F_TRANSFEREXTENTS`
      change a file through a read-only descriptor, and `(deny default)` does not stop them (Codex
      CLI commit 04e4d2b40f). In XNU, `F_MAKECOMPRESSED` checks only Unix permissions and calls
      `VNOP_IOCTL` directly, so the `file-ioctl` check does not run.
    - `(deny mach-lookup (xpc-service-name-prefix ""))`: XPC services, also the services inside
      application bundles, as the Codex CLI does.

### Paths are parameters

The profile text contains no path. Each path is the value of a parameter, and the text refers to
it as `(param "READ_0")`. The parameters reach libsandbox as a separate array of C strings; the
profile interpreter treats a parameter value as a string and never parses it as SBPL. A path that
contains `"`, `)` or a newline therefore cannot change the profile. The unit tests check that the
text contains no `/` at all, that every parameter is used exactly once, and that paths with hostile
characters produce exactly the same text as plain paths.

Constants in the text (sysctl names, ioctl numbers, comments) are fixed in sandy. A unit test
checks that the sysctl names contain only letters, digits, dots and underscores.

## The minimal system set

`system = "minimal"` adds the paths below (`system::MINIMAL`). All are real paths, because the
sandbox matches the path after resolving symbolic links. None contains user data: no path below
`/Users`, `~/Library` or a keychain.

No writable policy path may overlap the set: the plan reports FilesystemConfined as unavailable
when a writable path contains an entry, or lies inside a directory entry (`ReadTree`,
`CodeTree`). The resolver files of `ip = "all"` (`/private/etc/hosts` and the mDNSResponder
socket) count as entries. `/dev/null` and the links `/etc`, `/tmp` and `/var` (only their own
metadata is readable) are exempt. Most entries are on the sealed system volume or belong to root,
so file permissions forbid writing them anyway; the check keeps the guarantee independent of
that.

Paths are compared by what they lead to, as for rules 3 and 4 (see "Links and file identity" in
[DESIGN.md](DESIGN.md)): sandy compares the identity of each entry with the writable path and
with its parent directories. A second name of a directory of the set therefore counts as that
directory. The spelling through the data volume, `/System/Volumes/Data/private/etc` for
`/private/etc`, is such a name: a firmlink is no symbolic link, so `canonicalize` keeps it as
written and a comparison of path prefixes would let a writable path on it pass.

| Path | Access | Reason |
|---|---|---|
| `/` (the directory itself) | read | dyld opens the root directory while libignition locates the cryptex with the shared cache (macOS 13 and later); without it dyld aborts in `ignition_halt` before libSystem loads. This lists the names in `/`, nothing below. |
| `/usr/lib` | read, map executable | dyld itself (`/usr/lib/dyld`) and system libraries outside the shared cache |
| `/System/Library/dyld` | read, map executable | dyld shared cache on macOS 11 and 12 |
| `/System/Volumes/Preboot/Cryptexes/OS` | read, map executable | dyld shared cache since macOS 13; listed in Apple's `dyld-support.sb` |
| `/System/Cryptexes/OS` | read, map executable | mounted view of the same cryptex; listed in Apple's `dyld-support.sb` |
| `/private/etc/localtime` | read (the link only) | symbolic link that names the local time zone (`tzset`) |
| `/private/var/db/timezone` | read | time zone database that `/etc/localtime` points into |
| `/usr/share/zoneinfo.default` | read | time zone database shipped with the system |
| `/usr/share/locale` | read | locale data for `setlocale` |
| `/dev/null` | read, write data | discarding output; standard streams redirected to it |
| `/dev/fd` | read, write data (the tree) | the program's own open descriptors as paths (`/dev/fd/N`) |
| `/dev/stdin`, `/dev/stdout`, `/dev/stderr` | metadata of the link | links into `/dev/fd`; programs take them as file names |
| `/dev/zero` | read | zero bytes |
| `/dev/random`, `/dev/urandom` | read | random numbers |
| `/etc`, `/tmp`, `/var` | metadata of the link | symbolic links to `/private/...`; programs use paths such as `/etc/localtime` and `/var/run/...`, and the path lookup must read the link |

Not in the set, on purpose:

- `/System/Library/Frameworks` and `/System/Library/PrivateFrameworks`. Their code is in the dyld
  shared cache, so the C runtime does not read them. Programs that need framework resources or ICU
  data (`/usr/share/icu`) need `--read` for those paths.
- `/private/etc/passwd`, preferences (`/Library/Preferences`), `/System/Library/CoreServices`. The
  C runtime starts without them.
- The App cryptex (`/System/Cryptexes/App`), which holds the shared cache of Safari's frameworks.
- `/dev/tty`, pseudo-terminals, `/dev/dtracehelper`.

`/dev/fd` is the one tree of the set that the program may write to. It widens nothing:
`/dev/fd/N` is another name for a descriptor the program already holds, and opening it
duplicates that descriptor instead of opening the file again. XNU's `dupfdopen` refuses a mode
the original lacks, measured on macOS 26.5 and 27.0.1 in the escape test
`a_descriptor_path_grants_no_more_than_the_descriptor`: `open("/dev/fd/0", O_WRONLY)` on a
read-only standard input gives `EACCES` inside the sandbox and outside it, and so does
`truncate("/dev/fd/0")`. `chmod`, `utimes`, `chflags` and `setattrlist` on `/dev/fd/N` do reach
the file behind the descriptor, whatever mode it was opened with, but Seatbelt judges them by
the path of that file and not by `/dev/fd`, so they follow the policy for that file
(`a_descriptor_path_changes_no_metadata`). A program that takes `/dev/stdin` as a file name
therefore works, as it does on Linux.

The set is smaller than the sets of Chromium (`common.sb`) and the Codex CLI
(`seatbelt_read_only_platform_defaults.sbpl`), which serve programs with Cocoa, preferences and
Mach services.

### Readable sysctls

The profile allows reading the sysctls in `system::SYSCTL_NAMES` and the prefixes `hw.optional.`
(CPU features) and `hw.perflevel` (performance levels). They describe the hardware and the
operating system; libSystem (`sysconf`, `uname`), dyld and language runtimes read them. The list is
Chromium's `common.sb` list plus `hw.logicalcpu`, `hw.physicalcpu`, `hw.pagesize` and `kern.argmax`
from the Codex CLI. No `kern.proc.*` name is readable, so the target cannot list processes or read
their arguments and environment.

## Trusted user locations

Rule 12 of [DESIGN.md](DESIGN.md): a writable policy path may not reach a location of this user
that other programs read or execute later. The locations every Unix has are in
`sandy_core::trust`, the same list as on Linux; those of macOS alone are in `trust::locations`:

| Location | Protected | Why |
|---|---|---|
| the home directory | itself | holds the locations below; a writable path below it stays allowed |
| `Library/LaunchAgents` | the tree | launchd starts the agents of this user at the next login (macOS) |
| `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout`, `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile` | the file | zsh is the login shell of macOS, bash is installed, and Terminal.app starts login shells |
| `.bash_aliases`, `.bashrc.d` | the file, the tree | the usual `.bashrc` files of Debian and Fedora source them |
| `<config>/fish` | the tree | the startup files of the fish shell |
| `.gitconfig`, `<config>/git` | the file, the tree | `core.fsmonitor`, `core.sshCommand`, `core.pager` and `!` aliases run commands at the next git command |
| `.cargo/config.toml`, `.cargo/config`, and both in `CARGO_HOME` | the file | `build.rustc`, `build.rustc-wrapper` and target runners name programs that the next cargo command runs |
| `.ssh` | the tree | `ProxyCommand` and `LocalCommand` in the configuration run programs, and `authorized_keys` admits logins |
| `.gnupg` | the tree | `pinentry-program` and `photo-viewer` name programs that gpg runs |

`<config>` is `XDG_CONFIG_HOME` and `~/.config`, so `--read-write ~/.config` is refused, as on
Linux. cargo's files count in `CARGO_HOME` and in `~/.cargo`, so `--read-write ~/.cargo` is
refused; a program that downloads crates needs `~/.cargo/registry` and `~/.cargo/git`. A
location that does not exist counts, because the program could create it, and each counts where
it lies and where its symbolic links lead.

The home directory comes from the password database (`getpwuid_r`) and from `HOME`, because a
program that starts sandy with a minimal environment sets no `HOME`. When neither names one,
sandy cannot tell whether a writable path reaches these locations, so it refuses a policy with a
writable path (FilesystemConfined is unavailable) and says to start sandy with `HOME` set to the
home directory; a policy without a writable path is not affected.

Every absolute directory on sandy's `PATH` is such a location too, and so are the directories the
usual shell setups put on the user's `PATH`, whether or not sandy's own `PATH` holds them:
`~/.local/bin`, `~/bin`, `bin` in `CARGO_HOME` and in `~/.cargo`, `/usr/local/bin` and
`/usr/local/sbin`, and on macOS Homebrew's `/opt/homebrew/bin` and `/opt/homebrew/sbin`, which
belong to the user who installed it (`trust::path_locations`). A service or a desktop application
that starts sandy passes a shorter `PATH` than the user's shell has, and the escape works through
the shell's. Rule 12 warns about these directories instead of refusing them, because a writable path
that holds one is ordinary work: `--read-write ~/tools` with `~/tools/bin` on `PATH`, or
`--read-write /usr/local`. `sandy check` exits 0 and prints a `warning:` line on standard error that
names the writable path and the directory (`plan::notes`). What removes the risk is a policy that
keeps the directory out of every writable path, by granting only the subdirectories the program
needs; starting sandy with another `PATH` silences the warning for a directory that is not one of
the usual ones, and leaves the risk. A directory below one of them is on no `PATH` and says nothing,
and a writable path that reaches a refused location as well stays refused.

The profile could deny these paths inside a writable path instead of refusing the policy,
because a later deny rule overrides an earlier allow. sandy refuses, so that one policy means
the same on every platform: Landlock rules are allow-only, so the Linux backend cannot carve a
file out of a writable tree.

The list is a heuristic and can never be complete: no list knows which files the programs of
this user trust. It also does not see a hard link that already gives one of these files a
second name inside a writable path.

sandy does not check the loader variables of its own environment (`DYLD_INSERT_LIBRARIES`,
`DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`). The release binaries are unsigned, so dyld honours
them, and a caller that points them into a writable path runs that code as sandy, with no
sandbox. An integrator who signs sandy with the hardened runtime, as notarization requires,
gets them ignored unless the binary carries the `allow-dyld-environment-variables` entitlement.

## Networking

- Creating a socket (`system-socket`) is a separate operation from binding and connecting it.
  `socket(AF_UNIX)` is always allowed, so `socketpair` works; binding and connecting follow
  `unix_sockets`.
- Seatbelt never checks the creation of `AF_INET` and `AF_INET6` sockets: with `ip = "none"` a
  program can still create one, but it cannot bind, listen, connect or send with it (finding 1.2
  of the review). An explicit `(deny system-socket (socket-domain AF_INET))` has no effect; CI run
  39767043700 created the socket anyway and logged no denial. All other families (routing,
  kernel control, raw link layer, key management) are checked and stay denied by `(deny default)`.
- `ip = "all"`: `(allow network-outbound (remote ip))` and `(allow network-bind network-inbound
  (local ip))`. `ip` covers IPv4 and IPv6 (SBPL has `ip4` and `ip6` for one family), including
  loopback. Apple's `appsandbox-common.sb` uses the same bare `(remote ip)`.
- `ip = "client"`: `(allow network-outbound (remote ip))`, `(allow network-bind (local ip))` and
  `(allow network-inbound (local udp))`. Measured on macOS 27.0.1, in a profile that allowed
  everything but networking and in `sandy run`: Seatbelt checks `listen`, also on an unbound
  socket, and `accept` as `network-inbound`, so with it denied for TCP both fail with `EPERM`,
  while `connect` and a connected UDP socket need only `network-outbound`. It checks as
  `network-inbound` too every datagram that a socket which is not connected receives: without
  the UDP rule `recvfrom` failed with `EPERM` after a `sendto`, and the answer of the peer was
  lost. Clients that receive that way (QUIC, DNS and NTP clients, Rust's
  `UdpSocket::bind("0.0.0.0:0")` with `send_to`) need it, so the profile allows it for UDP. Allowing
  `network-inbound` also allows `network-bind`. `network-bind` itself covers only `bind`: a
  connect or a first send that picks a port needs no rule. A filter on port 0 does not exist:
  `(local ip "*:0")` does not compile ("invalid port in network address"), so the profile cannot
  limit binds to a port the kernel chooses, as Linux does.

  What stays open, an exception of DESIGN.md: a UDP socket that is not connected receives
  datagrams from every sender, not only from the addresses it sent to, at any port the program
  binds it to. Seatbelt cannot tell a reply from any other datagram. `sandy check` warns about it,
  and `ip_client_datagrams_from_others` records it: a datagram from a third party reached the
  socket that had sent to another peer, and one reached a port the program had bound itself.
- `ip = "private"`: `(allow network-outbound (remote tcp "localhost:P"))` for each forwarded port
  and `(allow network-bind network-inbound (local tcp "localhost:E"))` for each exposed port of
  the program, and nothing else of IP. Seatbelt's `localhost` is every address of the Mac, so
  the relay holds the forwarded ports at the other addresses; see
  [The private network](#the-private-network).
- `unix_sockets = "all"`: `(allow network-outbound (remote unix-socket))` and `(allow network-bind
  network-inbound (local unix-socket))`. This allows every Unix socket the user can reach,
  independent of the filesystem rules, as on every platform. A connect looks the socket's path up
  first, which Seatbelt checks as `file-test-existence` before the kernel knows that the path is
  a socket, and no filter tells a socket from a file there: `(vnode-type SOCKET)` does not match
  (measured on macOS 27.0.1). So the profile also allows `file-test-existence` for every path,
  and whether a path outside the policy exists answers again (see
  [Information the target can still read](#information-the-target-can-still-read)).
- NECP, the kernel's network policy layer: Network.framework, and URLSession through it, opens a
  NECP client descriptor (`necp_open`) for every connection and asks it how to reach the
  destination. `(deny default)` does not stop its calls: `necp_match_policy`, `necp_open`,
  `necp_client_action`, `necp_session_open`, `necp_session_action`, and `netagent_trigger`,
  which starts a network agent, such as a VPN on demand, in another process (numbers from
  `sys/syscall.h` of the macOS 27 SDK). With `ip = "none"` and `ip = "private"` the profile
  denies them by number, and `necp_open` fails with `EPERM`; a plain TCP connection to a
  forwarded port works without them. With `ip = "client"` and `ip = "all"` they stay allowed:
  with them denied, URLSession answered "The Internet connection appears to be offline" and a
  Network.framework connection "Network is down" for a listener on 127.0.0.1, while curl, which
  uses plain sockets, kept working (measured on macOS 27.0.1). The test is `necp_follows_ip`.
- A socket on a standard stream was created before the profile, and the profile covers only part
  of what such a socket still gives. Measured on macOS 26.5 with `ip = "none"`: `sendto` on an
  inherited unconnected UDP socket was denied, because `network-outbound` is checked per
  operation and not at creation; but `accept` on an inherited listening TCP socket succeeded and
  the program took a connection from a client outside, and reading an inherited connected TCP
  socket works like reading any other descriptor. `run` refuses a socket the policy denies on a
  standard stream before it applies the profile (see "Inherited descriptors"), so for the
  outbound case the profile is a second layer and for the inbound case the refusal is the only
  one.

### Name resolution

`getaddrinfo` on macOS does not send DNS queries itself. Libinfo's mdns module calls
`DNSServiceCreateConnection`, and the client library connects to the Unix socket
`/var/run/mDNSResponder` (real path `/private/var/run/mDNSResponder`). mDNSResponder also offers
the Mach service `com.apple.dnssd.service`, which Network.framework uses; the profile does not
allow it, so only `getaddrinfo` and the dns_sd API work.

- `ip = "all"` and `ip = "client"`: the profile allows connecting to exactly this socket (and
  testing its existence, because the connect looks its path up), reading `/private/etc/hosts`,
  and passing through the `/var` link. Name resolution is part of IP networking, so it does not
  require `unix_sockets = "all"`. Through the resolver the target can only do what IP networking
  already allows (queries, service registration on the local network, port mappings on the
  router). The plan names this exception for `UnixSocketsDenied`.
- `ip = "none"` or `ip = "private"`, and `unix_sockets = "none"`: the resolver is unreachable,
  and `getaddrinfo` resolves no name, `localhost` included (measured on macOS 27.0.1).
- `ip = "none"` or `ip = "private"`, and `unix_sockets = "all"`: the resolver is reachable like
  every other Unix socket. The target cannot reach the network over IP, but it can make
  mDNSResponder send DNS queries, and a DNS query can carry data out. This is a consequence of
  `unix_sockets = "all"`, the same as on Linux, where a resolver or proxy daemon can listen on a
  Unix socket too. The plan says so for `IpNetworkDenied` and `IpNetworkPrivate`.

## Exposed and forwarded ports

`network.expose` makes a loopback port of the program reachable from outside, and
`network.forward` is the mirror: it lets the program reach a loopback service outside (see
"Exposed ports" and "Forwarded ports" in `DESIGN.md`). On macOS one relay process serves both. It
works on pairs of a listen address and a target (`profile::relay_pairs`):

| Kind | The relay listens on | and connects to |
|---|---|---|
| `expose` | `listen`, reachable from outside | the program's loopback `port` |
| `forward` | the program's loopback `port` | `to`, the service outside |

The relay is a process of its own, outside the program's sandbox and confined by its own profile:

1. sandy binds every listen address before it applies the program's profile, and with
   `ip = "private"` also each forwarded port at the wildcard addresses (see
   [The private network](#the-private-network)).
2. sandy checks that it runs a single thread (`proc_pidinfo(PROC_PIDTASKINFO)`), because only then
   is `fork` safe, and forks twice. The intermediate process exits at once, so launchd adopts the
   relay. The program takes over sandy's process ID after the exec; the relay is not its child,
   so the program can neither reap it with `wait` nor receive `SIGCHLD` for it.
3. The relay starts a new session (no terminal signals), blocks every signal except the fault
   signals, points 0, 1 and 2 at `/dev/null`, and closes every other descriptor except its
   listeners and the readiness pipe (`PROC_PIDLISTFDS`). The watcher of
   [Ending with the parent](#ending-with-the-parent) starts the same way.
4. It registers `EVFILT_PROC` with `NOTE_EXIT` for sandy's process ID in a kqueue, before its
   profile denies process information about others.
5. It applies its own Seatbelt profile (`profile::relay_profile`): deny by default,
   `network-inbound` only on its listen ports, `network-outbound` only to the target ports, the
   `FIONBIO` and `FIOASYNC` ioctls, and the same closing denials as the program's profile. It
   needs no file at all, because it keeps running the code sandy already loaded and executes
   nothing.
6. Only then does it report over the readiness pipe that it is ready, with its process ID, or
   why it did not start.
   sandy waits for the report (10 seconds at most) and refuses to start the program without a
   ready report. sandy closes its own copies of the listeners before the exec, and
   `POSIX_SPAWN_CLOEXEC_DEFAULT` would close them anyway.
7. The relay waits on the same kqueue for new connections (`EVFILT_READ` on each listener) and
   for the end of the program (with `contained` also for the end of the guard's pipe), and relays
   each accepted connection with `sandy_relay::relay` in a thread of its own, up to
   `sandy_relay::MAX_CONNECTIONS` per listener. Before it applies its profile it raises its soft
   limit of open descriptors to fit them: macOS starts processes with 256, enough for only about
   125 connections. When the program ends, also after `SIGKILL`, the relay closes its listeners
   at once, gives the connections it already accepted at most one second to deliver what is
   left, and exits (rule 5 of "Forwarded ports" in `DESIGN.md`), resetting the connections that
   are still open. A program that connects, writes and exits immediately therefore does not lose
   its data.

`sandy check` compiles the relay's profile together with the program's.

### Who may connect, and who may stop the relay

Any local process can connect to the relay's listeners, like to any loopback port. Through an
exposed port it reaches the program, which is what an exposed port is for: the program's own
listener is reachable directly on macOS anyway. A forwarded port is different. It exists for the
program alone, and the relay reaches `to` as sandy's user, so a connection of another user would
pass an owner rule of a packet filter or a peer credential check in that service. On Linux the
relay asks the kernel who owns the other end and refuses the rest; macOS has no equivalent of
`SO_PEERCRED` for TCP and no checked way to read the owner of another socket, so it serves every
local process, of any user (`a_forwarded_port_serves_a_process_outside_the_sandbox` records it
for a process of sandy's own user). Looking through the program's own processes for the socket
cannot take the place of that check (see
[Looking for the program's socket](#looking-for-the-programs-socket)). Forward only to services
that authenticate their clients. `sandy check` prints this as a warning for every policy with a
forwarded port.

With the default `signals = "any"` the program can also stop the relay with `SIGSTOP`, which no
process can block. A stopped relay keeps its listen ports bound until someone continues or kills
it, so it can outlive the program by more than the one second of rule 5, without any bound at
all. macOS has no timer that kills a process that is not running (the Linux relay uses one), so
only `signals = "isolated"`, which keeps the program from signalling the relay at all, holds
that bound here. `sandy check` warns about it for every policy with exposed or forwarded ports
and `signals = "any"`.

A continued relay serves what its listeners collected while it was stopped. The kqueue reports
a listener once when it becomes ready, and the relay then accepts its whole backlog, so when
the program's own connection made the listener ready before the program ended, a connection
made after the end is accepted with it. Measured on macOS 26.5 and 27.0.1
(`a_continued_relay_serves_a_connection_made_after_the_program_ended`): the program connects
through a forwarded port while its relay is stopped and ends, a client connects after the end,
and once the relay is continued the forwarded service receives both connections. Without a
stop the same can happen to a connection that arrives in the moment between the program's end
and the relay's accept. What it costs is a violation of the relay's lifetime, not an escape: a
forwarded port serves one more connection after the operator believes the run ended, and an
exposed port can answer once more, served by whatever now holds the program's address.
With `process.children = "contained"` the program cannot stop its relay, because `contained`
requires `signals = "isolated"`, and sandy ends the program when the relay is gone (see
[Contained child processes](#contained-child-processes)).

### Looking for the program's socket

The relay cannot ask who owns the other end of a connection, but it can read the descriptors of
processes of its own user. `proc_pidinfo(PROC_PIDLISTFDS)` lists them, and
`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` gives the addresses and the TCP state of a socket among
them. A relay that knows the program's processes (in the exec model the program's process ID and
its descendants, which `proc_listchildpids` names; with `contained` the program's process group)
could look there for a TCP socket whose local address is the connection's peer and whose remote
address is the listener, and refuse the connection when there is none. A prototype did this for
every connection it accepted on a forwarded port, looking through the process the relay watches
and its descendants. Measured on macOS 27.0.1 on an 8-core Mac mini, it found every connection
the program held open, also in 100 child processes, and refused a connection that another user
(`workstation`) held open and one that a process of sandy's own user outside the sandbox held
open. Reading a process of another user fails with `EPERM`, so the relay learns nothing about it.
Inside the relay's profile a lookup took 3 microseconds for a program of one process with a few
descriptors, 130 with 100 other sockets, and 14 milliseconds for a chain of 100 processes, about
140 microseconds per process, most of it in listing its children. sandy does not use it, for two
reasons.

It finds only a socket that is still open, and a program that connects and closes is always
ahead of the relay: the kernel completes the handshake by itself, and the relay wakes, accepts
and looks only after that. One run of a program making 100 connections through a forwarded
port, counted at the service outside, with the relay refusing every connection it found no
socket for, three runs each in the exec model and with `contained`, idle and with 16 busy loops
on the 8 cores:

| program | idle | loaded |
| --- | --- | --- |
| connect and close, one process | 0 of 100 | 0 of 100 |
| connect, write and close, one process | 0 to 9 of 100 | 0 to 4 of 100 |
| connect and exit, 100 processes | 0 of 100 | 0 to 2 of 100 |
| connect, write and exit, 100 processes | 0 of 100 | 0 to 1 of 100 |
| connect and read the answer, one process or 100 | 100 of 100 | 100 of 100 |

So the relay would have to serve a connection it finds no socket for, as the Linux relay serves
one the kernel names no owner for. On Linux that is safe because only a closed socket loses its
owner, and a closed socket cannot read the answer. Here "no socket found" also means a socket
that any process outside the program holds open, of another user or of sandy's own, and serving
those is no check at all. A relay could instead pass such a connection in one direction only: the
client's bytes reach the service and nothing comes back. That costs a closed socket nothing, and
a peer that holds its socket open could deliver a blind write but not read the answer, which is
the residual of Linux without its race. It would break a program whose open connection is held by
a process the relay does not find, such as a descendant whose parent exited in the exec model,
which launchd adopts.

The relay's profile would also have to allow `process-info-listpids`, `process-info-pidinfo` and
`process-info-pidfdinfo`, and no filter limits them to the program. `(target children)` matches
only the relay's children and `(target same-sandbox)` only its own sandbox, `(target others)`
matched no process in the measurement, sandboxed or not, and `(target pgrp)` matches the relay's
own process group, which the program is not in. `(target-attribute is-sandboxed)`, the narrowest
filter found that matches every program, matches any sandboxed process, and 314 of the 389
processes of the logged-in user ran sandboxed, among them `secd`, `cloudd` and `tccd`. `process-info-pidinfo` also answers `kern.procargs2`,
which holds the arguments and the environment of a process, and `proc_pidpath`;
`process-info-pidfdinfo` gives the addresses of every socket. The relay would gain the
environment of almost every process of the user, which is far more than the check needs. The
kernel's own list of TCP connections (`net.inet.tcp.pcblist64`), which names the user of a closed
socket as well, shows a program without Apple's private `com.apple.private.network.statistics`
entitlement only its own sockets, and the relay's profile denies it anyway.

## The private network

`ip = "private"` asks for a loopback of the program's own (DESIGN.md, "Private network and
egress"). macOS has none: XNU has no network namespaces, and a profile cannot give a process an
address of its own. The profile is therefore relay only. The program may:

- connect over TCP to each forwarded port: `(allow network-outbound (remote tcp
  "localhost:P"))`;
- bind, listen and accept over TCP on each exposed port of the program: `(allow network-bind
  network-inbound (local tcp "localhost:E"))`.

Nothing else of IP: no other port, no UDP, no ICMP, no name resolution and no NECP calls (see
[Networking](#networking) and [Name resolution](#name-resolution)), and, as under every policy,
no Mach service, the networking ones included. The egress broker of `network.egress` does not
exist on macOS yet, so the plan reports `EgressBrokered` as unavailable and `run` refuses it.

`localhost` is every address of the Mac. SBPL knows two hosts in a network address, `*` and
`localhost`, and has no filter for an address or an interface. Measured on macOS 27.0.1,
`localhost` matches 127.0.0.1, ::1, 0.0.0.0, ::, ::ffff:127.0.0.1, the address on the local
network, the unique local and link-local IPv6 addresses, fe80::1%lo0 and the link-local addresses
of the VPN interfaces, but not 127.0.0.2, which lo0 does not carry, and not the IPv4-mapped form
of the local network address. So the rules above let the program reach a forwarded port, and
listen on an exposed port, at every address the Mac has.

For each forwarded port the relay therefore binds `0.0.0.0:P` and `[::]:P` (IPv6 only) with
`SO_REUSEADDR`, never listens on them, and keeps them until it ends (`macos::holder`). A
connection to the port at an address where nothing more specific listens finds one of these
sockets, and a socket that does not listen never answers. Measured on macOS 27.0.1 with
`--ip private --forward P=127.0.0.1:T`:

| The program connects at port P to | Without the holder | With it |
|---|---|---|
| 127.0.0.1, 0.0.0.0, ::ffff:127.0.0.1 | the relay | the relay |
| ::1, :: | refused | no answer |
| the local network, unique local and en1 link-local addresses, fe80::1%lo0 | refused | no answer |
| the link-local addresses of utun0 and awdl0 | no answer | no answer |
| 127.0.0.2, the IPv4-mapped local network address | `EPERM` | `EPERM` |
| any address at another port, or UDP at P | `EPERM` | `EPERM` |

"Refused" means that a process listening there would have received the connection. While the
holder runs, another socket cannot bind `0.0.0.0:P` or `[::]:P`, also not with `SO_REUSEADDR`,
`SO_REUSEPORT` or both (measured). By XNU's `in_pcbbind` (`bsd/netinet/in_pcb.c`) a process of
another user cannot bind P at any address either, because a socket of a different user holds
the wildcard address; that part is not measured, because the test Mac has no second standard
user. A socket
that already listens on a wildcard address of P makes the bind fail, and `run` refuses with
"cannot hold port P at 0.0.0.0:P for ip = "private""; `check` tries the same binds and reports
the failure for `IpNetworkPrivate`. Without `SO_REUSEADDR`, a connection of an earlier run that
the relay accepted at 127.0.0.1:P and that waits in `TIME_WAIT` would make the bind fail for 30
seconds (measured). The tests are `the_relay_holds_the_forwarded_ports_at_the_wildcard_addresses`
and `a_wildcard_listener_on_a_forwarded_port_refuses_a_private_network`.

What stays open with `forward`, an exception of DESIGN.md:

- A process of sandy's own user that listens on a forwarded port at an address of the Mac other
  than the relay's, the other loopback family included, before or after sandy starts, receives
  the program's connections to that address. Measured on macOS 27.0.1: such binds at the local
  network, unique local, link-local and ::1 address succeed next to the holder with
  `SO_REUSEADDR` (`a_process_of_the_same_user_takes_a_forwarded_port_at_another_address`). The
  program has to connect to that address on purpose, so the route serves a program and a process
  outside that work together, or reaches a service that listens at exactly such an address and
  port.
- Once the relay has ended, its holder sockets and its listener are gone, and the forwarded port
  reaches whatever binds it next, at any address
  (`a_forwarded_port_reaches_whatever_binds_it_once_the_relay_has_ended`). With
  `signals = "any"` the program can end its relay itself; with `children = "contained"` sandy
  ends the program together with its relay (rule 5 of "Forwarded ports" in DESIGN.md).
- Every local user reaches the forwarded service through the relay, as with `ip = "all"` (see
  [Who may connect, and who may stop the relay](#who-may-connect-and-who-may-stop-the-relay)).

`sandy check` warns about the first two for every private network with a forwarded port, and
about the third for every forwarded port.

What stays open with `expose`, an exception of DESIGN.md: the program can listen on its exposed
ports at every address of the Mac, 0.0.0.0 included, and there every local process and other
hosts reach it without the relay. Measured on macOS 27.0.1: the program listened at 127.0.0.1,
::1, 0.0.0.0, ::, the local network, unique local and link-local addresses, while another port,
and UDP at the exposed port, were denied, and a connection from another host on the local
network reached the program's listener at 0.0.0.0
(`the_program_listens_on_its_exposed_port_at_every_address`). A holder cannot keep the program
off those addresses, because the program runs as sandy's user and may bind one specific address
next to it. `sandy check` warns about it for every private network with an exposed port.

Compared with Linux, a private network gives less on macOS:

- The program's processes cannot talk to each other over IP. They may connect only to the
  forwarded ports, not to a port that one of them listens on, also not to an exposed port, so a
  program whose processes use other loopback ports among themselves does not work under
  `ip = "private"` on macOS. Socket pairs still work, and Unix sockets with
  `unix_sockets = "all"`.
- Names do not resolve, `localhost` included: connect to 127.0.0.1 or ::1.
- Network.framework and URLSession fail, because NECP is denied.
- A connection to a forwarded port at another address of the Mac, the other loopback family
  included, waits until it times out instead of being refused.

## Signals the profile does not cover

`signals = "isolated"` is `(allow signal (target self) (target same-sandbox))`. It covers the
`signal` operation, which is `kill` and its relatives, and the scope is one sandbox instance:
the escape test `isolated_signals_do_not_cross_sandbox_instances` showed that a second sandy run
with the same policy cannot signal the first. Two paths reach a process outside the sandbox
without that check, because the kernel sends those signals itself:

- SIGIO. `F_SETOWN` names the process that gets SIGIO when a socket or a pipe becomes ready,
  and XNU sends it with no check behind it that `signal` covers. Measured on macOS 26.5: a
  program with isolated signals delivered SIGIO to a process outside the sandbox. A profile
  cannot filter the owner, so with `signals = "isolated"` the command itself is denied. That
  closes one way of naming the owner, not all of them: the ioctls `FIOSETOWN` (sockets and
  pipes), `SIOCSPGRP` (sockets) and `TIOCSPGRP` (pipes) set the same owner, and Seatbelt checks
  `file-ioctl`, and with it the ioctl allowlist, only for files and devices. No operation of the
  profile language reaches them all: `socket-ioctl` stops only `SIOCSPGRP` on an IP socket, where
  `FIOSETOWN` still works, and never an ioctl on a Unix socket. With an `ioctl-command` filter it
  matched nothing on macOS 26.5; on macOS 27.0.1 the filter matches, but still only `SIOCSPGRP`
  on an IP socket, so it closes no route. Measured on macOS 26.5 and 27.0.1, each of the four
  delivers SIGIO to a process outside the sandbox under `signals = "isolated"`
  (`sigio_through_owner_ioctls_follows_no_signal_policy`). The owner may
  belong to another user: the kernel sends SIGIO across the user boundary with no owner check, so
  that reach is a macOS kernel behaviour outside sandy's reach. Measured on macOS 26.5 and 27.0.1
  with a second account: from `sandy run --signals isolated` as one user (uid 502), SIGIO reached a
  process of another user (uid 501) that handled it, through each owner ioctl, by process id and
  by negative process group; `F_SETOWN` stayed denied. SIGURG was measured within one user only,
  and a target owned by root was not tested. The same owner
  gets SIGURG when urgent data arrives on a TCP socket, which with `ip = "all"` or
  `ip = "client"` the program can send itself over loopback; measured the same way. Not even the
  `ioctl` system call as a whole can be denied: a `syscall-unix` rule for its number has no
  effect, while the same rule stops
  `fsgetpath` (measured on macOS 26.5 and 27.0.1). The program cannot choose the signal, and the
  default action of SIGIO and SIGURG is to discard it, so only a process that handles them
  notices; a negative owner names a process group, so one ioctl reaches every such process of a
  group. With the default `signals = "any"` the program may signal every process anyway, so the
  `F_SETOWN` rule is only added for `isolated`.
- Job control. The kernel stops a whole process group when one of its processes reads a terminal
  in the background, and that send has no check behind it either. A program can join the process
  group of another job of the terminal session it was started in: `setpgid` cannot be filtered by
  its argument in SBPL, so denying it under `isolated` would mean no process groups at all inside
  the sandbox, and `posix_spawn` with `POSIX_SPAWN_SETPGROUP` would still put a child in a
  foreign group, because the kernel changes the group itself where no rule sees it. Both routes
  are measured in `a_program_can_join_a_process_group_outside_the_sandbox`, and
  `a_background_read_stops_another_job_of_the_terminal` shows what it costs: a program with
  isolated signals joins the group of another job of its terminal session, reads the terminal,
  and the kernel stops that job with it. The ioctls that aim such a signal, `TIOCSPGRP` (take
  the terminal) and `TIOCSWINSZ` (SIGWINCH to the foreground group), are outside the ioctl
  allowlist and denied in every mode (`the_terminal_signal_ioctls_are_denied`).

  `process.children = "contained"` closes both routes: it denies `setpgid`, `setsid` and
  `posix_spawn`, so no process of the sandbox can leave the group that sandy ends. It requires
  `signals = "isolated"`. Linux can express the narrow rule that macOS cannot: there `setpgid` is
  allowed only with 0 as its second argument, so a program may lead a group of its own but not
  join one.

`sandy check` prints both routes as warnings for a policy with `signals = "isolated"`: SIGIO
always, SIGURG with `ip = "client"` or `ip = "all"`, and the job control route without
`children = "contained"`.
The interrupt characters typed into a pseudo-terminal master are one more such route; `run`
refuses a master on a standard stream instead (see [Inherited descriptors](#inherited-descriptors)).

## Contained child processes

`process.children = "contained"` ends every process the target starts when the target ends, also
when sandy itself is killed. sandy then stays the target's parent instead of replacing itself
(`crates/sandy-macos/src/macos/contain.rs`):

1. sandy catches, with a handler that does nothing, every signal whose action is to ignore it:
   those ignored by default (`SIGCHLD`, `SIGURG`, `SIGIO`, `SIGWINCH`, `SIGINFO`) and those that
   its caller set to be ignored, for example `SIGINT` and `SIGQUIT` after `&` in a script or
   `SIGHUP` under `nohup`. macOS discards a signal on arrival while its action is to ignore it,
   even when it is blocked, so without the handler sandy would never see these signals and could
   not forward them. Then it blocks every signal except the fault signals and SIGPIPE and waits
   for them with `sigwait`. The target gets the caller's actions back before it starts. SIGPIPE
   stays ignored, as sandy's Rust runtime set it: a write of sandy's own whose reader has gone,
   the record of `--status-fd` for one, raises it, and caught it would be forwarded and end the
   target with status 141. A SIGPIPE sent to sandy is therefore not passed on. The target starts
   with the default action for SIGPIPE.
2. It forks the guard. The guard starts a process group of its own (it is in neither sandy's job
   nor the target's group) and forks the anchor, which starts the target's process group and only
   waits to be killed. The guard keeps two pipes to and from sandy and, with exposed or
   forwarded ports, the write end of the relay's pipe and the relay's process ID; the anchor
   keeps no descriptor.
3. sandy learns the group's ID (the anchor's process ID) from the guard and forks the target into
   that group. Once the target has reported its process ID (step 4), the guard registers the
   target's `NOTE_EXIT` and the pipe from sandy in a kqueue, and with exposed or forwarded ports
   also the relay's `NOTE_EXIT`. When one reports, that is when the target ends, sandy is done or
   gone (also killed by SIGKILL), or the relay ends, the guard kills the group until no live
   process is left in it, closes the relay's pipe, waits until sandy is done or gone, reaps the
   anchor and ends.
4. The forked target joins the group and then writes its own process ID into the pipe to the
   guard, in that order. The guard therefore learns the ID even if sandy never runs again after
   the fork, for example because it was stopped or killed in that moment, and it never learns it
   while a kill of the group would still miss the target. A failed write means the guard is gone,
   and the target refuses to start. The target keeps its copy of that write end until `execve`
   closes it, so the pipe ends only once sandy is gone and the target has started or ended. Then
   it restores the signal actions and the mask, applies the profile, marks every descriptor above
   2 close-on-exec and executes the target with `execve`. It reports a failure over a
   close-on-exec pipe.
5. sandy forwards the signals it receives to the target and follows job control with a terminal,
   as on Linux (see "Process model" in `DESIGN.md`).
6. When the target exits, sandy kills the group until no live process is left in it, closes its
   pipe to the guard, reaps the guard and the target, and exits with the target's exit status, or
   128 plus the signal number.
7. When the relay ends while the target runs, the guard tells sandy so over its pipe before it
   kills the group. sandy then exits with status 125 and the reason on standard error, and
   `--status-fd` records `failed` instead of `exited` or `signaled`. A dead forward relay frees
   the target's forward port, and any local user can then bind it and receive what the target
   sends there for `to`: its requests, credentials and data. Ending the target closes that, as on
   Linux. When the relay's end is the only event, the guard looks at the target and the pipe
   from sandy once more without waiting, so a relay that ended together with the target is the
   normal end of a run and not a failure. In a normal run the relay cannot end first: it ends
   when sandy ends or when the guard closes the relay's pipe, and both happen only after the
   guard has seen the target end. A relay that has already ended when the guard registers it
   counts as ended.

The caller sees sandy's process ID and that exit status, not the target's ID and not how it
really ended. `--status-fd` reports both without changing any exit status: sandy writes `pid N`
once the target runs, then `exited N` or `signaled N`, or `failed` when sandy itself failed or
refused, which tells its exit status 125 from a target that exits with 125. The descriptor is
made close-on-exec, so the target never has it. In the exec model the record ends after `pid`,
because sandy becomes the target and the caller's own wait status is the target's.

So the group ends with the target also while sandy is stopped (by its caller, or by the target
through the terminal), when sandy is killed, and when the watcher of `end_with_parent` kills
sandy. The relay of exposed and forwarded ports polls the relay's pipe besides sandy's process
ID, so it ends with the group, also while sandy is stopped and therefore does not end.

No process may leave the group. The profile denies `setpgid` (82) and `setsid` (147) with
`syscall-unix` rules, as it denies the lookups by file ID. That is not enough: `posix_spawn` with
the flag `POSIX_SPAWN_SETSID` or `POSIX_SPAWN_SETPGROUP` puts the new process into a session or
group of its own inside the kernel, without calling either system call, and tests on macOS 26
and 27.0.1 moved a process out of the group this way with both calls denied. A profile rule sees
only the system call number of `posix_spawn` (244), not its flags, so the profile denies
`posix_spawn` as a whole. `fork`, `vfork` and `execve` stay allowed, and so does `process-fork`.
The sandbox also cannot reach launchd or other services that would start a process for it (see
[Mach services and other IPC](#mach-services-and-other-ipc)).

Programs that start processes with `posix_spawn` therefore get `EPERM`: Rust's
`std::process::Command` (it falls back to `fork` only when `pre_exec` is set), Java's
`ProcessBuilder`, Node.js (libuv) and `system()` and `popen()` of libSystem. Programs that use
`fork` and `exec`, such as shells, work. The target's own start uses `execve` for the same reason.
`sandy check` warns about this for every policy with `children = "contained"`.

Other ways to find the target's processes again were tested and rejected: macOS has no child
subreaper, so a process whose parent ends is adopted by launchd; `sandbox_check` on another
process's ID returns the same answer for every process to an unprivileged caller, so it cannot
tell which processes run in this sandbox; and `NOTE_TRACK` of kqueue, which followed forks, is no
longer supported.

Killing the group: on macOS a process that is being forked while a signal for its group is
delivered is not in the group yet, and its parent finishes `fork` before the signal ends it, so
one SIGKILL can miss a process; a program that forks in a loop leaves survivors almost every time
(measured on macOS 26). So whoever ends the group repeats the signal every 10 milliseconds while
`kill(-group, SIGKILL)` returns 0. It returns `EPERM` when only zombies are left (measured) and
`ESRCH` when nothing is left. The guard can repeat the signal because it is not in the group. The
group's ID is the anchor's process ID, and the guard reaps the anchor only after sandy is done or
gone, so no other group can have the ID while sandy or the guard signals it.

If both sandy and the guard are killed with `SIGKILL`, nothing ends the group. sandy, the
guard and the anchor are forks of one process and all carry sandy's command line, so
`pkill -9 -f sandy` does exactly that. Killing sandy alone is safe, as on Linux: the guard ends
the group.

The relay of exposed and forwarded ports watches sandy's process ID, which is the supervising
sandy here, so it ends after the group (rule 5 of "Forwarded ports" in `DESIGN.md`). The guard
watches the relay in turn (step 7). Without `contained` nothing watches the relay: when something
outside the sandbox kills it, the target keeps running and its forward port is free for others
to bind.

## Ending with the parent

`process.end_with_parent = true` ends the target when the process that started sandy ends
(`crates/sandy-macos/src/macos/watch.rs`):

1. sandy reads its parent's process ID as its first step, or checks the one named with
   `--parent-pid`, and checks that this process is still its parent. With `--parent-start` it
   checks the start time of the named process instead, so that process need not be sandy's own
   parent (see "Naming the caller" below). Process 1 is refused in both cases: macOS has no
   child subreaper, so launchd is the parent of every process whose parent has ended, and
   waiting for launchd to end says nothing.
2. It starts the watcher like the relay: forked twice, so launchd adopts it and the target never
   sees it as a child; in a session of its own with every signal except the fault signals blocked;
   0, 1 and 2 on `/dev/null` and no other descriptor of sandy's.
3. The watcher registers `NOTE_EXIT` for the parent and for sandy's process ID (the target after
   the exec; with `contained`, the supervising sandy, which forwards the signals and ends the
   group). Then it applies its own profile (`profile::watcher_profile`): deny by default, signals
   allowed, nothing else; it executes nothing and keeps running the code sandy loaded.
4. After the watcher reports ready, sandy checks again that its parent is unchanged, or that the
   start time still matches. A process whose parent ends is adopted by launchd at once, so an
   unchanged answer means that the watcher's registration names the real parent, not a later
   process with the same ID.
5. When the target ends first, the watcher ends. When the parent ends, the watcher sends SIGTERM
   and SIGCONT (so that a stopped target gets the request), waits at most 5 seconds for the
   target's end, then sends SIGKILL, and ends.

macOS has no pidfd, so the watcher signals the target by its process ID. Right before each signal
it checks the kqueue for the target's end. The ID could name another process only if the target
ended between that check and the signal and macOS gave the ID to a new process in that moment.
The target can make the process IDs wrap around quickly (processes that fork in a loop went
through all 99999 IDs in about 10 seconds on macOS 26), so the remaining window is the moment
between the check and the signal, and another process of the user would have to get the ID in
it.

The policy requires `signals = "isolated"`, so the target cannot signal the watcher. `sandy check`
compiles the watcher's profile together with the target's.

### Naming the caller

`--parent-pid` alone is a process ID, which another process can have once the caller has ended,
so sandy accepts it only when it is sandy's own parent. `--parent-start` adds when that process
started: `pbi_start_tvsec` and `pbi_start_tvusec` of `proc_pidinfo(PROC_PIDTBSDINFO)`, in
microseconds since the epoch. macOS records the value once when the process starts, so a later
change of the system clock does not alter it, and two processes with the same ID would have to
start in the same microsecond to share it. `p_uniqueid` of `PROC_PIDUNIQIDENTIFIERINFO` would
be stronger, but it is not in the public SDK headers; sandy uses one undocumented interface
(Seatbelt) and does not need a second.

With the token the named process need not be sandy's parent, so a wrapper between the caller and
sandy (`sh -c`, `open`, a launcher) is allowed. sandy refuses when the process is gone or its
start time differs. `tests/common/mod.rs`, `start_token`, is the recipe a caller follows.

Residual risk: if the watcher itself is ended from outside the sandbox, for example by `pkill -f
sandy`, which matches it because it keeps sandy's command line, or by jetsam under memory
pressure, nothing ends the target with its parent, and nothing reports that. The Linux watcher
has one more route into it, through a writable `/proc`, which it closes by making itself
undumpable (docs/linux.md); macOS has no `/proc`, so the target cannot change the watcher's
standing with the memory pressure killer.

## Mach services and other IPC

`(deny default)` denies `mach-lookup`, and the profile allows no service. On macOS this closes the
routes through which another, unsandboxed process would act for the target:

| Route | What it would allow | Closed by |
|---|---|---|
| LaunchServices (`open -a Terminal`) | start any application outside the sandbox | `mach-lookup` of the LaunchServices daemon; `lsopen` |
| Apple events (`osascript`) | make Terminal or another app run commands | `mach-lookup` of the Apple event server; `appleevent-send` |
| launchd (`launchctl submit`, `bootstrap`) | run a job outside the sandbox | launchd checks the `job-creation` operation of the caller |
| XPC services, also of app bundles | services with their own rights | `mach-lookup`, and the explicit XPC deny |
| Pasteboard | read and write the clipboard | `mach-lookup` of the pasteboard server |
| Distributed notifications, `notifyd` | covert channels | `mach-lookup` |
| Authorization, privileged helpers | run code as root | `mach-lookup` |

Apple's deny-default profiles allow `lsopen` and `job-creation` explicitly when they need them
(`application.sb`, `kernelmanagerd.sb`), which shows that `(deny default)` covers both.

Other IPC that the profile does not allow: POSIX and System V shared memory and semaphores
(`ipc-*`), IOKit user clients (`iokit-open`), preferences (`user-preference-*`).

Consequences: `getpwuid` and similar directory lookups fail (no `opendirectoryd`), system logging
through `os_log` is dropped, and CoreFoundation preferences work only in direct mode.

## Privilege escalation

A setuid or setgid program can only run if it is executable under the policy. The system set is
not executable, so `/usr/bin/sudo`, `/usr/bin/login` and the other setuid programs of the system
are out of reach unless a `read_exec` path contains them. Two independent mechanisms cover that
case:

1. Sandbox.kext refuses to execute a setuid or setgid file from a sandboxed process. The exec fails
   with `EPERM` and the kernel logs `deny(1) forbidden-exec-sugid`. This is a platform rule, not an
   SBPL operation; a profile cannot allow it (only `(with no-sandbox)` in Apple's own profiles
   starts a program outside the sandbox, and sandy never uses it). XNU itself only clears the
   setuid bit for traced processes and `nosuid` mounts.
2. The profile adds `(deny process-exec* (file-mode #o4000) (file-mode #o2000))`. `file-mode`
   matches when all given bits are set (Apple Sandbox Guide), and Apple's `application.sb` uses it
   with `process-exec`. This keeps the guarantee if the platform rule ever changes.

Other routes to privileges need a Mach service (authorization, `security_authtrampoline`,
privileged helper tools, `sudo` through launchd jobs), which the profile denies. The escape test
`setuid_programs_do_not_start` executes `/usr/bin/sudo` with the policy allowing it, and expects
a refusal.

The target can set the setuid bit on its own files in a `read_write` path
(`file-write-setugid` is part of `file-write*`); the profile does not deny the bits, as the
Linux denylist does. The bit gives the target nothing: it runs as this user already, and
nothing in a writable path is executable inside the sandbox. It is a gift to another local user
who can reach the file, because outside the sandbox the file runs with this user's rights. That
is the threat Linux denies the mode bits for (docs/linux.md, "Setuid and setgid bits").

## The file system view

`filesystem.view = "policy"` asks that every path outside the policy and the system set look
missing (DESIGN.md, "The file system view"). Every profile has done that since 2.0.0: step 3 of
[The generated profile](#the-generated-profile) answers `ENOENT` to every call on such a path,
and the plan reports `PathsHidden` as enforced by that rule, so the view changes nothing else
for a program. With `unix_sockets = "all"` the profile allows the existence check for every path
again, so the plan reports `PathsHidden` as unavailable and `run` refuses the view.

What stays visible, an exception of DESIGN.md:

- The names in the root directory. dyld opens it, so the system set lets the program read it,
  and `readdir` returns every name. A bulk listing (`getattrlistbulk`) returns only the entries
  that the program may look up, unless it asks for the type of each entry (`ATTR_CMN_OBJTYPE`):
  then it returns every entry of `/` with the owner, mode and times it asks for, while every
  other call answers `ENOENT` for them (measured on macOS 27.0.1). The root directory is the one
  directory outside the policy that the program can read; a granted directory holds only policy
  paths.
- The directories above each policy path and each path of the system set exist, with their
  metadata, because `realpath`, `getcwd` and `mkdir -p` walk through them.
- `statfs` of a policy path names its volume and the directory that volume is mounted on.

`sandy check` warns about these. The tests are `the_view_hides_every_path_outside_the_policy`
and `the_view_leaves_the_root_names_the_ancestors_and_the_volume_visible`.

## Information the target can still read

These are known and accepted, because they reveal no file contents, no other process's data and
no privilege, and closing them would break ordinary programs:

- The hardware and operating system facts in the readable sysctls, including the host name.
- The names in the root directory `/` (dyld needs to open it) and the metadata of the
  directories above each granted path.
- Machine-wide statistics through the host name port: `mach_host_self()` is a special port that
  every process inherits, and `host_statistics64` (free, active and wired page counts) and
  similar non-privileged host routines work on it (finding 1.3 of the review). Seatbelt could deny
  the routines with `syscall-mig`, but runtimes use them for memory heuristics (for example the
  JVM and libuv's `uv_get_free_memory`), so the profile leaves them open, as Chromium's and the
  Codex CLI's profiles do. The privileged host port stays denied (`mach-priv*`).
- With `unix_sockets = "all"`, whether a path outside the policy exists, and its path. The
  profile allows `file-test-existence` for every path there, because a socket outside the policy
  can be reached no other way (see [Networking](#networking)), so `access`, `statfs` (with the
  device and the directory the volume is mounted on), `chdir` and `getattrlist` with
  `ATTR_CMN_FULLPATH` answer for every path, as they did under every policy before 2.0.0. With a
  `/.vol/<dev>/<inode>` path `getattrlist` turns an inode number into a path, the disclosure that
  the `fsgetpath` denial closed. No path rule can close it here: Seatbelt checks the lookup of a
  `/.vol` path against the file's real path, so a denial of `/.vol` does not reach it (measured
  on macOS 27.0.1). Every other call still answers `ENOENT`, and contents, metadata and listings
  stay unreadable (`unix_sockets_all_reaches_sockets_and_tests_paths_outside_the_policy`).
  `sandy check` warns about it.
  Without `unix_sockets = "all"` every path outside the policy looks missing to every call
  (`metadata_outside_the_policy_looks_missing` and the tests next to it), and `getattrlist`
  returns the path only inside the policy, which `realpath(3)` needs
  (`getattrlist_does_not_disclose_paths_outside_the_policy`).
- Which process ids exist. `kill(pid, 0)` only asks for permission: with isolated signals a live
  process outside the sandbox answers `EPERM` and an unused process id `ESRCH`
  (`process_ids_outside_the_sandbox_stay_countable`). A `(with errno ESRCH)` on the signal rule
  does not change that answer, and denying `kill` by number would take every signal away, also
  to the program's own children. macOS answers the same way for a process of another user
  outside any sandbox. Nothing else about another process answers: `proc_pidinfo`,
  `proc_pidpath` and `proc_listallpids` answer `ESRCH` as for a process that does not exist
  (`other_processes_look_gone`), and `getpriority`, `getpgid` and `getsid` are denied
  (`priority_group_and_session_queries_are_denied`). The program's own children are hidden the
  same way; Seatbelt refused their information before as well (`EPERM`), and `waitpid` and
  kqueue's `EVFILT_PROC` keep working for them (measured on macOS 27.0.1).
- The metadata of the entries of the root directory, through `getattrlistbulk` on `/`, which
  the program may open: of every entry when the call asks for the type of each, otherwise only of
  the entries the program may look up (see [The file system view](#the-file-system-view);
  `bulk_listing_reaches_only_the_root_directory`). A directory the policy does not grant cannot
  be opened, so the call cannot reach it.

## Diagnostic mode

`run --explain` is not available on macOS: sandy refuses the option here instead of reporting
nothing, which would read as "nothing was denied". The question it answers, "which grant does
this program need", is in [DESIGN.md](DESIGN.md), "Diagnostic mode", and the Linux
implementation is in [linux.md](linux.md).

What a sandboxed process can learn about its own denials on macOS, measured on macOS 26.5 as
the standard user `mini`:

- Seatbelt denials go to the unified log, and nothing else records them. `log show` answers
  `Could not open local log store: Operation not permitted`, and `log stream` answers `Must be
  admin to run 'stream' command`. A process cannot even read back the denials of its own
  sandbox without administrator rights, which a diagnostic must not need.
- The profile cannot ask for a report of its own: a profile with `(deny default (with report))`
  is rejected at compile time with `report modifier does not apply to deny action`.
- There are no readable violation reports: `~/Library/Logs/DiagnosticReports` does not exist and
  `/Library/Logs/DiagnosticReports` is not readable for the user.
- Seatbelt's `(trace "FILE")` profile directive is not a candidate either. It is a profile that
  collects operations instead of denying them, so it would replace the sandbox rather than
  observe it, which the diagnostic mode must never do. In the measurement the traced process
  could not even start (`execvp() ... Operation not permitted`).

`check --explain-path` is Linux only as well. The profile that decides a path here is SBPL text,
not a rule list sandy keeps, so the macOS backend would have to answer from a second source
that can disagree with the profile it generates. A wrong answer about a path is worse than
none, so the backend answers nothing and sandy refuses the option.

## Known limitations

- The Seatbelt functions are private API (see above). A man page of a macOS 27 SDK, quoted on the
  OpenSSH developer list, says that the named built-in profiles (`kSBXProfile*`) "must not be used
  when building against macOS SDK >= 27.0. Processes opting into them will be killed". sandy uses
  its own profile, not a named one. Whether the restriction will extend to custom profiles is
  unknown; Chromium uses custom profiles in every release.
- `file-ioctl` allows only four requests. Programs that change terminal modes (raw mode, echo) or
  use other device ioctls fail. The reason: `TIOCSTI` on the controlling terminal would let the
  target type commands into the shell that started sandy. Job control fails for the same reason:
  `TIOCSPGRP` is not allowed either, so a shell inside the sandbox cannot give the terminal to a
  job. Escape sequences are ordinary writes and still reach the terminal emulator, which acts on
  some of them, for example by setting the clipboard (DESIGN.md, "Non-goals").
- With `signals = "isolated"`, `fcntl(F_SETOWN)` fails, and the program can still have the
  kernel send SIGIO to a process outside the sandbox, including one of another user, through an
  ioctl on a socket or a pipe (see
  [Signals the profile does not cover](#signals-the-profile-does-not-cover)).
- Standard input, output and error keep what they were opened with, so a file outside the policy
  on a standard stream can be read and written. A socket the policy denies is refused at the
  start, and so is a pseudo-terminal master with `signals = "isolated"` (see
  [Inherited descriptors](#inherited-descriptors)); a connected Unix stream socket is
  accepted, and the program then reaches whatever its peer is, so pass one only from a process
  that is the peer itself.
- The program can lock a file it may only read (`flock`, or a shared `fcntl` lock), and a
  process outside that locks the same file then waits or fails; macOS makes the two kinds
  conflict. The locks are advisory and give no access (measured on macOS 27.0.1, test
  `a_lock_on_a_readable_file_holds_off_other_processes`).
- `link(2)` fails everywhere (see the hard link rule above).
- With `system = "none"` no program starts on macOS: every program is linked dynamically, and dyld
  itself needs the root directory and the shared cache from the system set. sandy refuses such a
  policy unless a policy path covers "/", which is the only way a policy can bring those paths
  itself (measured: `run --system none --read / -- /usr/bin/true` works).
- A program that needs a framework resource, ICU data, a Mach service or user lookups does not work
  with `system = "minimal"` alone. Add the paths with `--read`; there is no way to allow Mach
  services.
- A script needs its interpreter in a `read_exec` path, because the interpreter is executed too.
  `sandy check` reads the `#!` line of the program and reports FilesystemConfined as unavailable
  when no `read_exec` path covers the interpreter, so it does not report a policy as enforced
  that `run` then refuses. The system set grants `file-map-executable` for the dynamic loader but
  no `process-exec*`, so only `read_exec` paths execute. sandy follows one `#!` line; XNU follows
  more (measured on macOS 26: a script whose interpreter is a script runs), so sandy never names
  an interpreter the kernel would not reach.
- A file the program writes can be executed outside the sandbox. The program gets no
  `process-exec*` in a writable path, but a file it writes keeps the mode it gives it, and a
  process of the user outside the sandbox can run it. The trusted-location check keeps the
  writable paths out of the places where other programs run or read files on their own (see
  "Trusted user locations"); whether a user runs a file from a writable path stays the user's
  decision.
- A `read_write` path itself cannot be deleted or replaced, and a writable file cannot be replaced
  by renaming another file over it. Programs must write such a file in place.
- A path outside the policy answers "No such file or directory" (`ENOENT`), not "Operation not
  permitted", so a denial no longer looks like one, and macOS has no `--explain` (see
  [Diagnostic mode](#diagnostic-mode)). dyld says "no such file" instead of "blocked by sandbox"
  for a library outside the policy. A program that fails on a file it cannot find may need a
  grant for it. Programs that treat a missing optional file as normal gain from it: under
  `EPERM`, LibreSSL stopped `curl` at startup on `/private/etc/ssl/openssl.cnf`, and under
  `ENOENT` it starts (measured on macOS 27.0.1). A write to a `read` path still answers `EPERM`
  (`writes_to_a_read_path_stay_refused`).
- `getcwd` fails when the working directory is outside the policy, and so do programs that save
  the working directory before they work: `cp -R` stops with "cp: current working directory: No
  such file or directory" (measured on macOS 27.0.1; before 2.0.0 it worked). Start such a
  program in a directory of the policy (`--cwd`).
- `getpriority`, `getpgid` and `getsid` fail with `EPERM`, also when the program asks about
  itself (see the protections of [The generated profile](#the-generated-profile)). After a
  compiler crash, clang and swift do not detect their stale module cache lock and wait until
  their lock timeout: LLVM's lock file code asks `getsid` whether the lock's owner still runs
  (unverified, read from the code).
- A policy path spelled through the data volume, such as `/System/Volumes/Data/private/tmp/x`
  for `/private/tmp/x`, grants nothing. A firmlink is no symbolic link, so `canonicalize` keeps
  that spelling, while Seatbelt matches the path through the firmlink: measured on macOS 26.5
  and 27.0.1, a program with that `read_write` path could write neither under it nor under
  `/private/tmp/x`. Give the path without the prefix, and let the program use that spelling too:
  Seatbelt checks the existence of a path as the program spells it, and the profile grants it
  only for the plain spelling, so `/System/Volumes/Data/private/tmp/x/file` looks missing
  (measured on macOS 27.0.1; before 2.0.0 the program could use either spelling).
- sandy cannot run inside another Seatbelt sandbox; `sandy check` reports this.
- x86_64 code does not run in the sandbox on Apple silicon. Rosetta loads its runtime
  (`libRosettaRuntime`) into every translated process, and the profile does not allow it, so the
  program would abort with "rosetta error: Failed to open libRosettaRuntime" (measured on macOS
  26 and 27.0.1). A translated process executes universal programs such as `/bin/echo` as x86_64
  too. The plan therefore refuses, before anything starts, when sandy itself runs translated
  (`sysctl.proc_translated`), and on Apple silicon (`hw.optional.arm64`) when the file the kernel
  would load has no arm64 code (`binary::has_arm64_code` reads its header). For a script that is
  the interpreter of the `#!` line, one level deep, as for the `read_exec` check. A program that
  later executes an x86_64-only program still meets the error, and so does `arch -x86_64` or an
  interpreter that `/usr/bin/env` finds on the PATH, because sandy judges only the file the
  kernel loads first. An arm64e slice counts as arm64 code: measured on macOS 26.5, a third
  party arm64e program built with the Command Line Tools runs, and in a file with an x86_64 and
  an arm64e slice the kernel picks arm64e. Measured on macOS 27.0.1 with `sandbox-exec` and the
  profile sandy generates: a small x86_64 C program ran once the profile also allowed reading and
  mapping as executable `/Library/Apple/usr/libexec/oah`, where `libRosettaRuntime` lies. It
  needed no Mach service, no write to the translation cache and nothing in
  `/usr/libexec/rosetta`. Larger programs may need more; sandy grants none of it.
- With `ip = "private"` the program's processes cannot talk to each other over IP, names do not
  resolve, Network.framework fails, the program can listen on its exposed ports at every address
  of the Mac, and a process of sandy's user can take a forwarded port at another address (see
  [The private network](#the-private-network)).
- With `process.children = "contained"` the target cannot use `posix_spawn`, so programs that
  start processes through it (Rust's `std::process::Command`, Java, Node.js, `system()`,
  `popen()`) fail to start them (see [Contained child processes](#contained-child-processes)).
- The watcher of `process.end_with_parent` signals the target by process ID, not through a
  pidfd (see [Ending with the parent](#ending-with-the-parent)).
- With `signals = "any"`, the target can signal every process of the user, as on other platforms.
- Open question that the escape tests do not answer: whether `(deny default)` covers every other
  operation that the profile never mentions. Chromium and WebKit name a few exceptions, and the
  profile denies all of those explicitly. The ones measured that it does not cover are denied
  now: `file-test-existence`, the only check of `access`, `statfs`, `chdir` and of the path from
  `getattrlist` (step 3 of the profile), and the system calls `getfsstat`, `getpriority`,
  `getpgid`, `getsid` and, with `ip = "none"` and `ip = "private"`, the NECP calls (see the
  protections above).

## Verification

Unit tests (`cargo test -p sandy-macos`, every platform): expected profile text, parameters cover
all paths, hostile path characters, rule order, network and signal variants, anchors, the ioctl
allowlist, the system set, and the plan with fake host capabilities (missing
`sandbox_init_with_parameters`, rejected profile, already sandboxed).

macOS only:

- `macos::tests` compiles every combination of `system`, `ip`, `unix_sockets` and `signals`, plus
  the `children` and `end_with_parent` variants, the relay rules of a private network, and the
  relay and watcher profiles, with the host's Seatbelt compiler, without applying it, and checks
  that the plan is enforceable. `macos::holder::tests` checks the holder binds.
- `crates/sandy-cli/tests/check.rs` checks that `check` reports what `run` refuses: a busy relay
  port, a script whose interpreter is not executable, `system = "none"`, and that the trial that
  applies the profile does not refuse a policy that runs.
- `crates/sandy-cli/tests/escape.rs` and `escape_macos.rs` run the probe inside the sandbox, with a
  control run outside for every denial. The `open`, `osascript` and `launchctl` tests need a
  logged-in GUI session.
- `children.rs` and `children_macos.rs` test `process.children`: the group cannot be left
  (`setsid`, `setpgid`, `posix_spawn`), `fork` still works, the target cannot signal sandy, the
  guard ends the group when sandy is killed, signals and the exit status pass through, only 0, 1
  and 2 are inherited, and job control with a pseudo-terminal. `parent.rs` tests
  `process.end_with_parent`, also with `contained` and against signals to the caller's process
  group.
- `review_macos.rs` holds the checks the security reviews added, the denials they led to (the
  by-id calls, `getfsstat`, paths and processes outside the policy, the process queries), and
  the measurements that record what the sandbox does where it cannot stop something: the paths
  that `unix_sockets = "all"` lets the program test, process ids, SIGIO and the process groups
  of the terminal session, and what the file system view leaves visible.
- `private_macos.rs` tests `ip = "private"`: what the program reaches, the holder binds, and the
  routes that stay open at the other addresses of the Mac. A check that this host cannot run
  reports a skip, and
  `macos-26-arm.txt` and `macos-27-arm.txt` in `tests/expected-skips/` list the ones that are
  expected.

To see what the sandbox denies on a Mac, from an administrator account (a standard user gets
no log, see [Diagnostic mode](#diagnostic-mode)):

```sh
log stream --style compact --predicate 'sender == "Sandbox"'
```

Every sandboxed start logs a few denials that are expected and harmless: dyld reads the sysctls
`kern.bootargs` and `security.mac.lockdown_mode_state` and opens `/dev/dtracehelper`, and libSystem
tries to connect to `/private/var/run/syslog`. The program starts without them.

### What CI measured

On the macOS 15.7 runner (arm64), these results came from the escape tests and from a diagnostic
step that ran sandy and the probe directly:

- Before the root directory was readable, dyld aborted in `ignition_halt` (CI of commit
  597cb90); with it, `/usr/bin/true` and the probe start (run 39759350954).
- `ptrace(PT_ATTACHEXC)` from the probe to a process signed with `get-task-allow` works outside
  the sandbox and fails with `EPERM` inside it; the Sandbox log names the operation:
  `deny(1) system-debug pgrp [victim(4208)]` (run 39760116281). Without `get-task-allow`, macOS
  refuses the attach even outside the sandbox.
- Clones and copies behave as described above (run 39759350954).

## Sources

- Chromium, `sandbox/mac/seatbelt.cc` and `seatbelt.h`: declarations of
  `sandbox_init_with_parameters`, `sandbox_compile_string`, `sandbox_create_params`,
  `sandbox_set_param`, `sandbox_check`; the parameter array "[key1,val1,key2,val2,nullptr]".
  https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/mac/
- Chromium, `sandbox/policy/mac/common.sb` (base profile, sysctl list, dyld cryptex paths "From
  /System/Library/Sandbox/Profiles/dyld-support.sb"), `network.sb` (mDNSResponder socket, `(remote
  tcp)`), `renderer.sb` (process-info "allowed by default").
  https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/policy/mac/
- Chromium, `base/process/launch_mac.cc`: `POSIX_SPAWN_CLOEXEC_DEFAULT` with
  `posix_spawn_file_actions_addinherit_np`.
- OpenAI Codex CLI, `codex-rs/sandboxing/src/seatbelt.rs` and `seatbelt_*.sbpl`; commits f6950546e5
  (writable root anchors), 02de49f718 (root binding), 04e4d2b40f (mutating fcntls), 78245b47af (XPC
  service lookups); `codex-rs/cli/src/debug_sandbox.rs` (`(ioctl-command N)` for TIOCSTI).
  https://github.com/openai/codex
- Apple profiles from `/System/Library/Sandbox/Profiles` of macOS 12 (`application.sb`,
  `appsandbox-common.sb`, `system.sb`, `maild.sb`, `kernelmanagerd.sb`), as mirrored in
  https://github.com/corecryptics/MacOSReports, and libsandbox's `sbpl1.scm` in
  https://github.com/knightsc/sandbox_profiles
- Operation and filter names of macOS 15.1: https://gist.github.com/bdash/ccbfb773ad57484532a74a982fe4f571
- macOS SDK `.tbd` stubs (`libsandbox.1.tbd`, `libsystem_sandbox.tbd`) and `sandbox.h` (26.5):
  https://github.com/alexey-lysiuk/macos-sdk
- Man pages: sandbox-exec(1), sandbox_init(3), sandbox(7)
  (https://leancrew.com/all-this/man/), posix_spawnattr_setflags(3) and
  posix_spawn_file_actions_addclose(3) (https://keith.github.io/xcode-man-pages/).
- "Apple Sandbox Guide v1.0" (`file-mode` semantics, network filter syntax):
  https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
- Setuid refusal (`forbidden-exec-sugid`): https://developer.apple.com/forums/thread/689303
- XNU `bsd/kern/kern_exec.c` (setuid handling), `bsd/vfs/vfs_vnops.c` (`vn_ioctl`),
  `bsd/kern/kern_descrip.c` (`F_MAKECOMPRESSED`), `bsd/vfs/vfs_syscalls.c` and `vfs_xattr.c`
  (metadata MAC checks): https://github.com/apple-oss-distributions/xnu
- Libinfo `lookup.subproj/mdns_module.c` and mDNSResponder `dnssd_ipc.h`
  (`MDNS_UDS_SERVERPATH "/var/run/mDNSResponder"`): https://github.com/apple-oss-distributions
- macOS SDK 27 note on named profiles:
  https://lists.mindrot.org/pipermail/openssh-unix-dev/2026-August/042690.html
