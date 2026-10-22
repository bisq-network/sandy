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
6. `landlock_restrict_self`. sandy checks that the ruleset is fully enforced.
7. Install the allowlist filter and then the denylist filter, both with `SECCOMP_FILTER_FLAG_TSYNC`.
8. `execve`. Only this call remains after the filters are in place.

Landlock and seccomp restrict the calling thread. sandy starts no threads, the filters use TSYNC,
and `execve` ends every other thread, so the program runs with exactly these restrictions. Every
child inherits them.

## Mechanism per requirement

| Requirement | Mechanism |
|---|---|
| FilesystemConfined | Landlock with every file system right of the ABI handled. The seccomp filter denies opening a file with access mode 3 and `openat2` (see "Access mode 3"). Before ABI 3 it also denies truncation without write access. |
| NoPrivilegeEscalation | no_new_privs. The filters deny namespaces, mounts, `bpf`, `perf_event_open`, io_uring, keyrings, `userfaultfd`, calls that need capabilities, unknown system calls and other CPU architectures. sandy refuses to run as root or with capabilities. |
| ProcessMemoryIsolated | Landlock: a domain cannot ptrace, open `/proc/<pid>/mem` or `environ`, or use `process_vm_readv` on processes outside it (all ABIs). The denylist also denies `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise`, System V IPC and POSIX message queues. |
| InheritedHandlesClosed | Close-on-exec on every descriptor above 2. |
| EnvironmentControlled | `execve` with exactly the policy environment. The backend adds no variables. |
| IpNetworkDenied | The socket family allowlist has no `AF_INET`, `AF_INET6` or `AF_NETLINK`; io_uring is denied. From ABI 4, Landlock also denies TCP bind and connect. |
| UnixSocketsDenied | The allowlist has no `AF_UNIX`, and socket pairs are limited to stream and seqpacket. From ABI 6, Landlock scopes abstract sockets; from ABI 9 it denies connections to pathname sockets. |
| SignalsIsolated | Landlock signal scope (ABI 6). Unavailable on older ABIs. |
| MetadataConfined | The denylist denies the metadata calls that take a path (see "Metadata"). |

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
permission, then return a descriptor for ioctl only". Landlock requires no right for such an
open. Tested on Linux 7.2 with ABI 9 enforced: `open(path, 3)` on a file outside the policy
succeeded, and `fchmod` and `fsetxattr` on that descriptor changed the file. On ABI 1 to 4 the
descriptor would also give device ioctls on any device the user can open (derived from the
kernel source, not tested). The denylist therefore
denies `open` and `openat` with access mode 3, and `openat2` fails with `ENOSYS` because seccomp
cannot read its flags. This should be reported to the Landlock maintainers.

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
| `bpf`, `perf_event_open`, `userfaultfd` | always | Kernel attack surface. |
| `keyctl`, `add_key`, `request_key` | always | The keyrings of the user are shared by all its processes. |
| `kexec_*`, module calls, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `open_by_handle_at`, `settimeofday`, `clock_settime`; on x86_64 `iopl`, `ioperm`, `modify_ldt`, `uselib` | always | They need capabilities, which sandy never passes on. A second layer. |
| metadata calls by path | with `linux.path_metadata = "deny"` | See "Metadata". |

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

- **Paths outside the policy are visible.** `stat`, `access`, `readlink` and `inotify` watches
  work on every path the user can reach (tested: an inotify watch on a directory outside the
  policy succeeded). The program can learn which files exist, their sizes and times, and when
  other programs touch them.
- **Metadata through open files.** `fchmod`, `fchown`, `fsetxattr` and `futimens` work on every
  file the program may open, also in `read` paths. They can set the setuid or setgid bit on a
  file in a writable path, which another local user could then run as this user if the
  directory is reachable.
- **Other processes of the user.** The program can lower their priority (`setpriority`,
  `ioprio_set`), pin them to CPUs (`sched_setaffinity`) and lower their resource limits
  (`prlimit64`). With `signals = "any"` it can kill them.
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
(a session bus, a pseudo-terminal, ptrace under Yama, a socket family) print why they skip.
Checks that depend on the Landlock ABI read it from the kernel: below ABI 6, the signal test
expects sandy to refuse `signals = "isolated"`. The unit tests in `crates/sandy-linux` cover the
planning function with invented host capabilities, and the filter decisions with a small BPF
interpreter that applies both filters with the kernel's precedence.

Static test binaries: `cargo test --target x86_64-unknown-linux-musl` builds static test
executables. With `SANDY_TEST_BIN_DIR` pointing to a directory with static `sandy` and
`sandy-probe` (`cargo build --release --target x86_64-unknown-linux-musl -p sandy-cli --bins`),
they run on another host, for example a test VM.
