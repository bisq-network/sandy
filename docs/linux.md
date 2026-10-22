# Linux backend

The Linux backend restricts sandy's own process and then replaces it with the program
(`execve`). The program keeps sandy's process ID, signals and exit status. Three kernel features
do the work:

- **Landlock** confines the file system, isolates the process from ptrace, and (from ABI 6)
  scopes signals and abstract Unix sockets.
- **Two seccomp filters** deny system calls that Landlock does not cover: socket families,
  io_uring, namespaces, System V IPC, metadata changes by path, and more.
- **no_new_privs** stops setuid programs and file capabilities from adding privileges.

The research behind the design is in [research/linux-mechanisms.md](research/linux-mechanisms.md).

## Launch sequence

`sandy run` first prepares everything that can fail on bad input:

1. Detect the host: the Landlock ABI, seccomp support, no_new_privs, user IDs and capabilities,
   and which paths of the minimal system set exist. Detection only reads state.
2. Plan: a pure function (`plan_for`) turns the policy and the host capabilities into the plan
   items and the exact configuration to apply. If any requirement is unavailable, sandy refuses.
3. Build the Landlock ruleset with all its rules, compile both seccomp filters, and build the
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
7. Install the allowlist filter and then the denylist filter, both with `SECCOMP_FILTER_FLAG_TSYNC`.
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
| SignalsIsolated | Landlock signal scope (ABI 6). Unavailable on older ABIs. |
| MetadataConfined | The denylist denies the metadata calls that take a path (see "Metadata"). |
| ChildProcessesDenied | The denylist denies `fork`, `vfork` and `clone` without `CLONE_THREAD`; `clone3` fails with `ENOSYS` (see "Child processes"). |
| ExposedPortsRelayed, ForwardedPortsRelayed | One relay process outside the program's sandbox, confined by its own Landlock domain and seccomp filters (see "Exposed and forwarded ports"). |

## Exposed and forwarded ports

Both are pairs of a loopback address that the relay listens on and a loopback address it connects
to. `network.expose` listens on `listen` outside and connects to the program's port.
`network.forward` listens on the program's loopback port and connects to `to`, a service outside.
One relay process serves all pairs. sandy starts it before it confines itself:

1. sandy binds every listen address (for `forward` the program's own loopback port, which is
   therefore taken before the program starts) and opens a pidfd for its own process ID. The
   program keeps this ID after `execve`, so the pidfd refers to the program.
2. sandy verifies that it has one thread and forks twice. The intermediate process exits at once,
   so the relay is not a child of the program and the program's `wait` never reaps it. The relay
   is a fork of sandy, not a new program; a single-threaded parent makes this safe.
3. The relay closes every descriptor except its listeners, the pidfd, standard error and a
   readiness pipe. It then confines itself:
   - no_new_privs;
   - Landlock with every file system right of the ABI handled and no rule, so it cannot open,
     create or execute any file; from ABI 4 TCP bind is denied and TCP connect is allowed only to
     the target ports of the pairs (Landlock TCP rules match the port, not the address); from
     ABI 6 the signal and abstract socket scopes;
   - the shared allowlist filter and a relay filter that allows only TCP sockets, `accept`,
     `connect`, reading and writing, polling, memory calls, thread creation without namespace
     flags and `FIONBIO`. Every other call fails with `EPERM`; `clone3` fails with `ENOSYS`.
4. The relay starts and joins one test thread (so a filter that blocks threads fails here) and
   reports "ready" over the pipe. sandy reads the report and continues only on success. Any
   failure of the relay is reported back, and sandy refuses to run. The relay then polls the
   pidfd and its listeners and relays every accepted connection in its own threads, up to
   `sandy_relay::MAX_CONNECTIONS` at the same time.
5. When the pidfd becomes readable, that is when the program ends (also by SIGKILL), the relay
   accepts the connections reported in the same round, closes its listeners, waits while accepted
   connections deliver their data, at most one second, and exits (DESIGN.md rule 5 of "Forwarded
   ports"). A program that connects, writes and exits at once therefore does not
   lose its data, and the relay never outlives the program by more than one second. If sandy
   fails after starting the relay, sandy's process ends and the relay with it.

The listeners and the pidfd are close-on-exec, and sandy closes its copies before it confines
itself, so the program never holds them. The relay keeps standard error to report errors; a
caller that waits for the end of that stream waits until the relay has exited, at most one
second after the program ends.

The relay runs in its own Landlock domain, a sibling of the program's domain, so neither can
ptrace the other. With `signals = "any"` the program can kill the relay. Any local process can
connect to the relay's listeners, like to any loopback port: through an exposed port it reaches
the program, through a forwarded port it reaches `to`, which it could reach directly.


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
filter still denies `TIOCSTI` and `TIOCLINUX` on every descriptor; the test
`terminal_input_injection_is_denied` checks both.

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

sandy installs two filters, built with `seccompiler` from `libc::SYS_*` numbers:

1. **Allowlist.** Every number of the reviewed table is allowed: the Linux 7.2 table, on x86_64
   0 to 336 and 424 to 471, on arm64 0 to 243, 260 to 294 and 424 to 471. Every other number
   fails with `ENOSYS`: system calls of newer kernels until sandy reviews them, x32 numbers,
   `clone3` and `openat2`. A system call of another architecture (for example `int 0x80` on
   x86_64) kills the process.
2. **Denylist.** Rules with argument checks return `EPERM`.

The kernel applies the stricter result of the two. Programs treat `ENOSYS` like an older kernel:
glibc falls back from `clone3` to `clone`, and callers of `openat2` fall back to `openat`.
Arguments of type int (socket family, ioctl command, clone flags, open flags) are compared on
their low 32 bits only, because the kernel ignores the high bits.

### Denylist

| System calls | Rule | Reason |
|---|---|---|
| `socket` | family not in the allowlist | `AF_UNIX` only with `unix_sockets = "all"`. `AF_INET`, `AF_INET6` and `AF_NETLINK` with protocol `NETLINK_ROUTE` only with `ip = "all"`. A denylist would miss families that reach TCP, for example `AF_SMC`. Route netlink lets the C library list interfaces (`getifaddrs`, `getaddrinfo`); other netlink protocols expose, for example, every socket of the host (`sock_diag`). `AF_VSOCK`, `AF_ALG`, `AF_PACKET` and the rest are always denied. |
| `socketpair` | other family than `AF_UNIX`; datagram or raw type when `unix_sockets = "none"` | A datagram socket can send to any address, also from a pair. `AF_UNIX` treats `SOCK_RAW` as `SOCK_DGRAM`. Stream and seqpacket pairs stay allowed. |
| `ioctl` | `TIOCSTI`, `TIOCLINUX` | Both can inject input into the terminal of the user. |
| `clone` | any `CLONE_NEW*` flag | Namespaces expose kernel interfaces that are otherwise reserved for root. |
| `unshare` | any `CLONE_NEW*` flag, including `CLONE_NEWTIME` | Same. `unshare(CLONE_FILES)` stays allowed. |
| `setns` | always | Same. |
| `personality` | other values than 0, 0x8, 0x20000, 0x20008, 0xffffffff | The values Docker allows; others are old exploit helpers. |
| `open`, `openat` | access mode 3; before ABI 3 also `O_TRUNC` with read-only access | See "Access mode 3" and the ABI table. |
| `truncate` | before ABI 3 | Landlock cannot check it. |
| io_uring (3 calls) | always | io_uring operations bypass seccomp, including socket creation. |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise` | always | Second layer to Landlock. Debuggers do not work inside the sandbox. |
| System V IPC (12 calls), POSIX message queues (6 calls) | always | These objects belong to all processes of the user and Landlock does not cover them. `shmat` would give access to the memory of processes outside the sandbox. |
| `mount`, `umount2`, `pivot_root`, `chroot`, new mount API, `open_tree_attr`, `mount_setattr` | always | Second layer; Landlock denies mounts already. |
| `statmount`, `listmount`, `listns` | always | They show the mount and namespace topology of the host, which leaving out `/proc` otherwise hides (`/proc/self/mountinfo`, `/proc/*/ns`). |
| `bpf`, `perf_event_open`, `userfaultfd` | always | Kernel attack surface. |
| `keyctl`, `add_key`, `request_key` | always | The keyrings of the user are shared by all its processes. |
| `kexec_*`, module calls, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `open_by_handle_at`, `settimeofday`, `clock_settime`; on x86_64 `iopl`, `ioperm`, `modify_ldt`, `uselib` | always | They need capabilities, which sandy never passes on. A second layer. |
| metadata calls by path | with `linux.path_metadata = "deny"` | See "Metadata". |
| `clone`; on x86_64 also `fork`, `vfork` | with `process.children = "none"`: `clone` without `CLONE_THREAD`, `fork` and `vfork` always | See "Child processes". |
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
open for reading or writing. Programs that change metadata by path, for example `tar`, `cp -p`
and `install`, need `path_metadata = "allow"`; then the program can change the metadata of every
file the user owns.

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

### Other processes

`prlimit64`, `setpriority`, `ioprio_set`, `sched_setaffinity`, `sched_setscheduler`,
`sched_setparam` and `sched_setattr` can change other processes of the user: lower their
resource limits, priority or I/O priority, or pin them to one CPU. The denylist allows them only
with process ID 0 (the caller) or the target's own process ID, which it keeps from sandy after
`execve`. For `setpriority` and `ioprio_set` it also denies the process group and user forms,
because sandy's process group can contain processes outside the sandbox.

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
| `/etc/ssl/openssl.cnf`, `/etc/pki/tls/openssl.cnf`, `/etc/crypto-policies/back-ends` | read | always | OpenSSL configuration and the crypto policy files it includes on Fedora and RHEL. Node.js does not start when the configuration exists but cannot be read. |
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

## Refusals

`sandy check` shows the reason for each unavailable requirement.

- No Landlock: FilesystemConfined, ProcessMemoryIsolated and SignalsIsolated are unavailable.
- No seccomp filter support, or a CPU architecture other than x86_64 and arm64: every requirement
  that uses the filter is unavailable.
- Running as root (real, effective or saved user ID 0), or with any effective, permitted or
  ambient capability: NoPrivilegeEscalation is unavailable. no_new_privs removes nothing that is
  already held, and Landlock does not restrict `chmod`, so root could, for example, set the
  setuid bit on a shell.
- A writable policy path that contains the dynamic loader: FilesystemConfined is unavailable,
  because the loader would be writable and executable.

## Known limitations

- **Paths outside the policy are visible.** `stat`, `access`, `readlink`, `getxattr`,
  `getxattrat`, `listxattrat`, `file_getattr` and `inotify` watches work on every path the user
  can reach (tested: an inotify watch on a directory outside the policy succeeded). The program
  can learn which files exist, their sizes, times and attributes, and when other programs touch
  them.
- **System information.** `uname`, `sysinfo`, `statfs` and `lsm_list_modules` stay allowed. They
  show the kernel version, load and memory, file system statistics, and the active security
  modules (which `/sys/kernel/security/lsm` shows to every user). The mount and namespace listing
  calls are denied.
- **Metadata through open files.** `fchmod`, `fchown`, `fsetxattr` and `futimens` work on every
  file the program may open, also in `read` paths, except for setuid and setgid bits.
- **Signals.** With `signals = "any"` the program can kill other processes of the user.
- **Processes started for the program.** `process.children = "none"` stops the program from
  creating processes. With `unix_sockets = "all"` it can still ask a service of the user, for
  example the systemd user manager over D-Bus, to start one outside the sandbox; such a process is
  not its child and can outlive it.
- **The terminal.** If standard input or output is the user's terminal, the program can read
  input, write escape sequences and change terminal modes. Only `TIOCSTI` and `TIOCLINUX` are
  denied.
- **`unix_sockets = "all"`** gives every Unix socket the user can reach, including the D-Bus
  session bus. Through the systemd user manager on that bus, the program can start commands
  outside the sandbox. Use it only for programs that are trusted with this.
- **Replaced files.** Landlock rules bind to the inode that existed when sandy started. A file
  that is later replaced by rename (for example `/etc/resolv.conf` after a network change)
  becomes unreadable for a running program.
- **What fails inside the sandbox:** 32-bit programs (killed), user namespace sandboxes of
  browsers (they fall back or fail), io_uring, debuggers, System V IPC, datagram socket pairs,
  `mkfifo` and symbolic links in writable paths, metadata changes by path with the default
  setting, and system calls newer than the reviewed table (`ENOSYS`).
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
