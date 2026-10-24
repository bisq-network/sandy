# macOS backend

The macOS backend confines the target with Seatbelt, the macOS sandbox (Sandbox.kext). sandy
generates a profile in the Sandbox Profile Language (SBPL) from the policy, applies it to its own
process, and then replaces itself with the target. The target keeps sandy's process ID, and every
process it starts inherits the sandbox.

Status: the pure parts (profile generation and planning) are unit tested on every platform. The
parts that call macOS run in the tests on the macOS 15 CI runner (arm64) and on macOS 26 (arm64);
see [Verification](#verification). The x86_64 build has not run on an Intel Mac, and does not
work through Rosetta (see "Known limitations"). An older macOS may reject an
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
| `FilesystemConfined` | Profile: `(deny default)`; `file-read*` for every policy path and the system set; `file-write*` only for `read_write` paths; `process-exec*` and `file-map-executable` only for `read_exec` paths, the program and system code. No hard links; clones only into `read_write` paths and only from files the target may read. No Mach or XPC service, so no other process acts on files for the target. Policy paths cannot be deleted or replaced. |
| `NoPrivilegeEscalation` | Only policy paths execute. Sandbox.kext refuses to execute setuid or setgid files from any sandboxed process, and the profile also denies `process-exec*` for files with mode bit `#o4000` or `#o2000`. No Mach service (authorization, privileged helpers, launchd). |
| `ProcessMemoryIsolated` | Profile: `process-info*` (allowed by default) is denied and then allowed only for `(target self)`; task ports are denied (`mach-priv*`, `mach-task-name`, `mach-task-read`, `mach-task-inspect`); `ptrace` attach, which Seatbelt checks as `system-debug`, is denied. |
| `InheritedHandlesClosed` | `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`; descriptors 0, 1 and 2 are named with `posix_spawn_file_actions_addinherit_np`. The kernel closes every other descriptor during the exec. With `children = "contained"` the forked target, a single thread, marks every descriptor above 2 close-on-exec (`PROC_PIDLISTFDS`) right before `execve`. |
| `EnvironmentControlled` | `posix_spawn` (with `children = "contained"`: `execve`) receives exactly `command.env`. The backend adds no variable. |
| `IpNetworkDenied` | Profile: no `network-*` rule for IP. The name resolver is unreachable unless `unix_sockets = "all"`. |
| `UnixSocketsDenied` | Profile: no `network-bind` or `network-outbound` for Unix sockets. With `ip = "all"`, the resolver socket is the one exception. |
| `SignalsIsolated` | Profile: `(allow signal (target self) (target same-sandbox))` instead of `(allow signal)`. |
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

Mach port rights are not file descriptors. Every lookup through the inherited bootstrap port is a
`mach-lookup`, which the profile denies.

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
3. Processes: `(allow process-fork)` unless `process.children = "none"`,
   `(allow process-info* (target self))`, and signals: `(allow signal)` or
   `(allow signal (target self) (target same-sandbox))`. With `children = "none"` the protections
   at the end also contain `(deny process-fork)`.
4. ioctls: `(allow file-ioctl (ioctl-command N) ...)` for `FIONBIO` and `FIOASYNC` (XNU issues
   them for `fcntl(F_SETFL)`, and `vn_ioctl` checks every request) and for `TIOCGETA` and
   `TIOCGWINSZ` (they only read terminal state, so `isatty` and stdio line buffering work). The
   numbers are written as numbers because older compilers do not know the symbols; a compile-time
   assertion compares them with the libc crate.
5. Readable sysctls (see below).
6. The system set, if `system = "minimal"`.
7. Policy paths. A directory uses `subpath`, a file uses `literal`, so a file rule never covers
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
   `clones_and_links_stay_inside_the_policy` measured it on macOS 15.7: copies and clones inside a
   `read_write` path and from a `read` path into it work; a clone of a file outside the policy
   into a `read_write` path, and a clone out of a `read_write` path to a place that is not
   writable, are denied.

8. Networking (see below).
9. Ancestors of every granted path: `file-read-metadata` and `file-test-existence` on each
   directory above it, so `realpath`, `getcwd` and `mkdir -p` can reach the granted path. This
   reveals no directory contents, because listing a directory needs `file-read-data`.
10. Protections:
    - Anchors: `(deny file-write-unlink file-write-create (literal ...))` for the root of every
      `read_write` path. Without it the target could delete the root and put a symbolic link in
      its place. The next `sandy run` resolves symbolic links, so it would grant access to the
      link's target, for example the home directory. The OpenAI Codex CLI found and fixed the same
      problem (commit f6950546e5). Policy paths inside writable paths need no rule: sandy-core
      rejects them for the same reason.
    - `(deny file-link nvram* iokit-get-properties mach-priv* mach-task-name mach-task-read
      mach-task-inspect system-debug)`. `file-link` is not part of `file-write*`, and Apple's `maild.sb` denies
      it explicitly after `(deny default)`. A hard link to a file outside the policy would make it
      reachable through a writable path, so links are denied everywhere.
    - `(deny syscall-unix (syscall-number 427) (syscall-number 217) (syscall-number 479)
      (syscall-number 225))`: `fsgetpath`, `fsgetpath_ext`, `openbyid_np` and `searchfs` find a
      file by volume id and inode number. `fsgetpath` builds the path in the kernel without
      reaching any Seatbelt file operation, so the target could learn the path of any file on the
      data volume from its device and inode number (a finding of the macOS security review;
      contents stayed protected). Seatbelt allows
      `syscall-unix` by default and filters it by number (WebKit's profiles use the same
      operation). The numbers come from XNU's `bsd/kern/syscalls.master`, because older profile
      compilers do not know every `SYS_` name. dyld or libSystem calls `fsgetpath` once while a
      program starts; the call fails, the Sandbox log records `deny(1) syscall-unix 427`, and the
      program starts normally (CI run 39767043700).
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
- `/dev/tty`, `/dev/fd`, pseudo-terminals, `/dev/dtracehelper`.

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
- `unix_sockets = "all"`: `(allow network-outbound (remote unix-socket))` and `(allow network-bind
  network-inbound (local unix-socket))`. This allows every Unix socket the user can reach,
  independent of the filesystem rules, as on every platform.

### Name resolution

`getaddrinfo` on macOS does not send DNS queries itself. Libinfo's mdns module calls
`DNSServiceCreateConnection`, and the client library connects to the Unix socket
`/var/run/mDNSResponder` (real path `/private/var/run/mDNSResponder`). mDNSResponder also offers
the Mach service `com.apple.dnssd.service`, which Network.framework uses; the profile does not
allow it, so only `getaddrinfo` and the dns_sd API work.

- `ip = "all"`: the profile allows connecting to exactly this socket, reading `/private/etc/hosts`,
  and passing through the `/var` link. Name resolution is part of IP networking, so it does not
  require `unix_sockets = "all"`. Through the resolver the target can only do what IP networking
  already allows (queries, service registration on the local network, port mappings on the
  router). The plan names this exception for `UnixSocketsDenied`.
- `ip = "none"` and `unix_sockets = "none"`: the resolver is unreachable.
- `ip = "none"` and `unix_sockets = "all"`: the resolver is reachable like every other Unix socket.
  The target cannot open IP sockets, but it can make mDNSResponder send DNS queries, and a DNS query
  can carry data out. This is a consequence of `unix_sockets = "all"`, the same as on Linux, where
  a resolver or proxy daemon can listen on a Unix socket too. The plan says so for
  `IpNetworkDenied`.

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

1. sandy binds every listen address before it applies the program's profile.
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
   `FIONBIO` and `FIOASYNC` ioctls, and the same closing denials as the program's profile. It needs no file at all, because it keeps running the code sandy already
   loaded and executes nothing.
6. Only then does it report over the readiness pipe that it is ready, or why it did not start.
   sandy waits for the report (10 seconds at most) and refuses to start the program without a
   ready report. sandy closes its own copies of the
   listeners before the exec, and `POSIX_SPAWN_CLOEXEC_DEFAULT` would close them anyway.
7. The relay waits on the same kqueue for new connections (`EVFILT_READ` on each listener) and
   for the end of the program, and relays each accepted connection with `sandy_relay::relay` in
   a thread of its own. When the program ends, also after `SIGKILL`, the relay closes its
   listeners at once, gives the connections it already accepted at most one second to deliver
   what is left, and exits (rule 5 of "Forwarded ports" in `DESIGN.md`). A program that connects,
   writes and exits immediately therefore does not lose its data.

`sandy check` compiles the relay's profile together with the program's.

## Contained child processes

`process.children = "contained"` ends every process the target starts when the target ends, also
when sandy itself is killed. sandy then stays the target's parent instead of replacing itself
(`crates/sandy-macos/src/macos/contain.rs`):

1. sandy catches `SIGCHLD`, `SIGURG`, `SIGWINCH` and `SIGINFO` with a handler that does nothing.
   macOS discards a signal on arrival while its action is to ignore it, even when it is blocked,
   so without the handler sandy would never see these signals. Then it blocks every signal except
   the fault signals and waits for them with `sigwait`.
2. It forks the guard, which creates a process group of its own and keeps only the read end of a
   pipe from sandy.
3. It forks the target into the guard's group and sends the target's process ID through the pipe.
   The guard registers the target's `NOTE_EXIT` and the pipe in a kqueue and kills its group when
   either reports: when the target ends, or when sandy dies, also by SIGKILL.
4. The forked target restores the signal actions and the mask, applies the profile, marks every
   descriptor above 2 close-on-exec and executes the target with `execve`. It reports a failure
   over a close-on-exec pipe.
5. sandy forwards the signals it receives to the target and follows job control with a terminal,
   as on Linux (see "Process model" in `DESIGN.md`).
6. When the target exits, sandy kills the group with SIGKILL, repeats that until the kernel finds
   no live process in the group, reaps the guard and the target, and exits with the target's exit
   status, or 128 plus the signal number.

No process may leave the group. The profile denies `setpgid` (82) and `setsid` (147) with
`syscall-unix` rules, as it denies the lookups by file ID. That is not enough: `posix_spawn` with
the flag `POSIX_SPAWN_SETSID` or `POSIX_SPAWN_SETPGROUP` puts the new process into a session or
group of its own inside the kernel, without calling either system call, and a test on macOS 26
moved a process out of the group this way with both calls denied. A profile rule sees only the
system call number of `posix_spawn` (244), not its flags, so the profile denies `posix_spawn` as a
whole. `fork`, `vfork` and `execve` stay allowed, and so does `process-fork`. The sandbox also
cannot reach launchd or other services that would start a process for it (see
[Mach services and other IPC](#mach-services-and-other-ipc)).

Programs that start processes with `posix_spawn` therefore get `EPERM`: Rust's
`std::process::Command` (it falls back to `fork` only when `pre_exec` is set), Java's
`ProcessBuilder`, Node.js (libuv) and `system()` and `popen()` of libSystem. Programs that use
`fork` and `exec`, such as shells, work. The target's own start uses `execve` for the same reason.

Other ways to find the target's processes again were tested and rejected: macOS has no child
subreaper, so a process whose parent ends is adopted by launchd; `sandbox_check` on another
process's ID returns the same answer for every process to an unprivileged caller, so it cannot
tell which processes run in this sandbox; and `NOTE_TRACK` of kqueue, which followed forks, is no
longer supported.

Killing the group: `kill(-group, SIGKILL)` returns 0 while a live process is in the group,
`EPERM` when only zombies are left (measured on macOS 26), and `ESRCH` when nothing is left.
sandy repeats the signal every 10 milliseconds while it returns 0, so a process forked while the
signal was delivered gets the next one. The group's ID is the guard's process ID; sandy reaps the
guard and the target only after that, so no other process or group can have these IDs while
sandy signals them.

The relay of exposed and forwarded ports watches sandy's process ID, which is the supervising
sandy here, so it ends after the group (rule 5 of "Forwarded ports" in `DESIGN.md`).

## Ending with the parent

`process.end_with_parent = true` ends the target when the process that started sandy ends
(`crates/sandy-macos/src/macos/watch.rs`):

1. sandy reads its parent's process ID as its first step, or checks the one named with
   `--parent-pid`, and checks that this process is still its parent.
2. It starts the watcher like the relay: forked twice, so launchd adopts it and the target never
   sees it as a child; in a session of its own with every signal except the fault signals blocked;
   0, 1 and 2 on `/dev/null` and no other descriptor of sandy's.
3. The watcher registers `NOTE_EXIT` for the parent and for sandy's process ID (the target after
   the exec; with `contained`, the supervising sandy, which forwards the signals and ends the
   group). Then it applies its own profile (`profile::watcher_profile`): deny by default, signals
   allowed, nothing else; it executes nothing and keeps running the code sandy loaded.
4. After the watcher reports ready, sandy checks again that its parent is unchanged. A process
   whose parent ends is adopted by launchd at once, so an unchanged parent means that the
   watcher's registration names the real parent, not a later process with the same ID.
5. When the target ends first, the watcher ends. When the parent ends, the watcher sends SIGTERM
   and SIGCONT (so that a stopped target gets the request), waits at most 5 seconds for the
   target's end, then sends SIGKILL, and ends.

macOS has no pidfd, so the watcher signals the target by its process ID. Right before each signal
it checks the kqueue for the target's end. The ID could name another process only if the target
ended between that check and the signal and macOS gave the ID to a new process in that moment,
which it does only after the process IDs wrapped around.

The policy requires `signals = "isolated"`, so the target cannot signal the watcher. `sandy check`
compiles the watcher's profile together with the target's.

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
privileged helper tools, `sudo` through launchd jobs), which the profile denies. The target can set
the setuid bit on its own files in a `read_write` path (`file-write-setugid` is part of
`file-write*`), but such a file belongs to the user, grants no privilege, and is not executable in
the sandbox. The escape test `setuid_programs_do_not_start` executes `/usr/bin/sudo` with the policy
allowing it, and expects a refusal.

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

## Known limitations

- The Seatbelt functions are private API (see above). A man page of a macOS 27 SDK, quoted on the
  OpenSSH developer list, says that the named built-in profiles (`kSBXProfile*`) "must not be used
  when building against macOS SDK >= 27.0. Processes opting into them will be killed". sandy uses
  its own profile, not a named one. Whether the restriction will extend to custom profiles is
  unknown; Chromium uses custom profiles in every release.
- `file-ioctl` allows only four requests. Programs that change terminal modes (raw mode, echo) or
  use other device ioctls fail. The reason: `TIOCSTI` on the controlling terminal would let the
  target type commands into the shell that started sandy.
- `link(2)` fails everywhere (see the hard link rule above).
- With `system = "none"` no program starts on macOS: every program is linked dynamically, and dyld
  itself needs the root directory and the shared cache from the system set.
- A program that needs a framework resource, ICU data, a Mach service or user lookups does not work
  with `system = "minimal"` alone. Add the paths with `--read`; there is no way to allow Mach
  services.
- A script needs its interpreter in a `read_exec` path, because the interpreter is executed too.
- A `read_write` path itself cannot be deleted or replaced, and a writable file cannot be replaced
  by renaming another file over it. Programs must write such a file in place.
- `getcwd` fails when the working directory is outside the policy.
- sandy cannot run inside another Seatbelt sandbox; `sandy check` reports this.
- x86_64 code does not run in the sandbox on Apple silicon. Rosetta loads its runtime
  (`libRosettaRuntime`) into every translated process, and the profile does not allow it, so the
  program would abort with "rosetta error: Failed to open libRosettaRuntime" (measured on macOS
  26). A translated process executes universal programs such as `/bin/echo` as x86_64 too. The
  plan therefore refuses, before anything starts, when sandy itself runs translated
  (`sysctl.proc_translated`), and on Apple silicon (`hw.optional.arm64`) when the program is a
  Mach-O file without arm64 code (`binary::has_arm64_code` reads its header). A program that
  later executes an x86_64-only program still meets the error. Allowing Rosetta would need its
  runtime, its translation cache and probably its Mach service in the profile, which has not been
  evaluated.
- With `process.children = "contained"` the target cannot use `posix_spawn`, so programs that
  start processes through it (Rust's `std::process::Command`, Java, Node.js, `system()`,
  `popen()`) fail to start them (see [Contained child processes](#contained-child-processes)).
- The watcher of `process.end_with_parent` signals the target by process ID, not through a
  pidfd (see [Ending with the parent](#ending-with-the-parent)).
- With `signals = "any"`, the target can signal every process of the user, as on other platforms.
- Open questions that the escape tests do not answer:
  - Apple does not document whether `(target same-sandbox)` means the same sandbox instance or any
    process with the same profile. In the second case, two sandy runs with the same policy could
    signal each other.
  - Whether `(deny default)` covers every other operation that the profile never mentions. Chromium
    and WebKit name a few exceptions, and the profile denies all of those explicitly.

## Verification

Unit tests (`cargo test -p sandy-macos`, every platform): expected profile text, parameters cover
all paths, hostile path characters, rule order, network and signal variants, anchors, the ioctl
allowlist, the system set, and the plan with fake host capabilities (missing
`sandbox_init_with_parameters`, rejected profile, already sandboxed).

macOS only:

- `macos::tests` compiles every combination of `system`, `ip`, `unix_sockets` and `signals` with the
  host's Seatbelt compiler, without applying it, and checks that the plan is enforceable.
- `crates/sandy-cli/tests/escape.rs` and `escape_macos.rs` run the probe inside the sandbox, with a
  control run outside for every denial. The `open`, `osascript` and `launchctl` tests need a
  logged-in GUI session.
- `children.rs` and `children_macos.rs` test `process.children`: the group cannot be left
  (`setsid`, `setpgid`, `posix_spawn`), `fork` still works, the target cannot signal sandy, the
  guard ends the group when sandy is killed, signals and the exit status pass through, only 0, 1
  and 2 are inherited, and job control with a pseudo-terminal. `parent.rs` tests
  `process.end_with_parent`, also with `contained` and against signals to the caller's process
  group.

To see what the sandbox denies on a Mac:

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
