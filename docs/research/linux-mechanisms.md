# Linux sandbox mechanisms for sandy

Research date: 2026-10-22. This document supports the Linux backend described in
[`docs/DESIGN.md`](../DESIGN.md). It answers seven questions: the value of the cloudflare/sandbox
approach, where the kernel features exist, what Landlock can do, what to do without Landlock, how
to build the seccomp filter, how CI can detect Landlock, and whether sandy should use bubblewrap.

## Method

- Sources are linked inline. Kernel facts come from the mainline source at release tags, from
  man pages and from the kernel documentation.
- Some facts were tested on one host: Fedora 44, kernel 7.2, glibc 2.43,
  Landlock ABI 10, Yama `ptrace_scope=0`. The test programs were small C and Rust programs in a
  scratch directory. They are not part of the repository. Each test result says "tested".
- A claim that I could not confirm from a source or a test is marked **unverified**.

## Key findings

1. **Landlock controls pathname Unix sockets since Linux 7.1.** The access right is
   `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (ABI 9). Tested: a process that handles this right, with no
   rule that allows it, gets `EACCES` from `connect()` to `/run/user/1000/bus`. The same process
   without this right in `handled_access_fs` connects successfully. This explains the earlier
   Fedora result. It also makes rule 7 of `DESIGN.md` ("Linux cannot restrict connections to
   pathname sockets by path") out of date for kernels 7.1 and newer. The planned seccomp rule on
   `socket(AF_UNIX)` is still required on older kernels, which includes every LTS distribution
   kernel in section 2.
2. **Landlock does not stop metadata changes outside the policy.** Tested: in a domain that
   handles every filesystem right and has no rules, `chmod(path, 0644)`, `utimensat(path)` and
   `setxattr(path, "user.x")` on a private file of the user all succeeded. `stat` and `chdir` also
   succeed. The [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
   lists these as current limitations. This conflicts with the design goal "must not be able to
   read or change user files outside its policy". Section 3.4 lists the options.
3. **cloudflare/sandbox does not make sandboxing work on more distributions.** It uses the same
   kernel feature as the planned launcher (seccomp). Its preload mode adds conditions under which
   the filter is silently not applied. Its ptrace mode needs `CAP_SYS_ADMIN`. Section 1 has the
   details.
4. **Denying only `AF_INET` and `AF_INET6` does not deny IP networking.** Tested: an unprivileged
   process created an `AF_SMC` socket (the kernel loaded the `smc` module on demand) and connected
   to an ordinary TCP server through the SMC fallback to TCP. The filter must allow a fixed list of
   socket families and deny all others.
5. **Landlock already isolates process memory.** Tested: inside a Landlock domain, `ptrace` attach,
   `open("/proc/<pid>/mem")`, reading `/proc/<pid>/environ` and `process_vm_readv` against a
   process of the same user outside the domain all fail. This has worked since ABI 1.
6. **x32 system calls are reachable on three targets.** Ubuntu 22.04 GA, Arch `linux` and WSL2
   enable x32 support. A seccomp denylist keyed on system call numbers is bypassable there
   (section 5.2).
7. **bubblewrap is not a better base.** It hides paths and processes better, but it needs
   unprivileged user namespaces (restricted on Ubuntu 24.04 and in default Docker containers),
   changes the process model, and cannot start inside a Landlock domain (tested). Section 7
   recommends Landlock and seccomp only.

## 1. cloudflare/sandbox

### 1.1 What it enforces

[cloudflare/sandbox](https://github.com/cloudflare/sandbox) installs one seccomp-bpf filter that
it builds from environment variables
([`sandbox.c`](https://github.com/cloudflare/sandbox/blob/master/sandbox.c)):

- `SECCOMP_SYSCALL_ALLOW=a:b:c` builds an allowlist. Any other system call kills the process.
- `SECCOMP_SYSCALL_DENY=a:b:c` builds a denylist. A listed call kills the process. It is used only
  when `SECCOMP_SYSCALL_ALLOW` is not set.
- `SECCOMP_DEFAULT_ACTION=log` replaces "kill" with "log and allow".
- Without either list it installs nothing and the program runs unrestricted.

It filters system call numbers only. The README states that argument filtering and custom error
codes are not supported. The maintainer said in
[issue 15](https://github.com/cloudflare/sandbox/issues/15) (2021) that argument filtering is not
planned. It has no file system, network or IPC policy of its own. It cannot express "deny
`socket(AF_UNIX)` but allow `socket(AF_INET)`", because that needs an argument check.

### 1.2 How it is delivered

- **`libsandbox.so` with `LD_PRELOAD`.** An ELF constructor
  ([`preload.c`](https://github.com/cloudflare/sandbox/blob/master/preload.c)) calls
  `setup_seccomp_filter()`. libseccomp sets `no_new_privs` before it loads the filter, because
  `SCMP_FLTATR_CTL_NNP` defaults to on
  ([seccomp_attr_set(3)](https://man7.org/linux/man-pages/man3/seccomp_attr_set.3.html)).
- **`patchelf --add-needed libsandbox.so`.** The library becomes a `DT_NEEDED` dependency of the
  binary. Then the loader refuses to start the program if the library is missing.
- **`sandboxify` for static binaries**
  ([`sandboxify.c`](https://github.com/cloudflare/sandbox/blob/master/sandboxify.c)). The process
  forks. The child attaches to the parent with `ptrace` and sets `PTRACE_O_SUSPEND_SECCOMP`. The
  parent installs the filter and calls `execvp`. At the exec event the child clears the option and
  detaches. The ptrace step exists only so that the filter can deny `execve` itself: the suspended
  filter does not block the `execvp` call. The kernel allows this option only with
  `CONFIG_CHECKPOINT_RESTORE`, only for a tracer with `CAP_SYS_ADMIN` in the initial user
  namespace, and only for a tracer that has no seccomp filter itself
  ([kernel/ptrace.c](https://github.com/torvalds/linux/blob/v7.3/kernel/ptrace.c),
  [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)).

### 1.3 Maintenance state

- 11 commits. The last code change is from July 2020. Later commits only change the README (2025)
  and add a Semgrep file (2024). Checked with the GitHub API on 2026-10-22.
- Open pull requests are not merged, for example
  [#32](https://github.com/cloudflare/sandbox/pull/32) (October 2026), which fixes lost signals in
  `sandboxify`.
- The README build instructions use libseccomp 2.4.3 (2020). The current libseccomp release is
  [2.6.1](https://github.com/seccomp/libseccomp/releases) (July 2026).
- In [issue 11](https://github.com/cloudflare/sandbox/issues/11) (2020) Cloudflare said it used
  the tool in production. Current use is **unverified**.

Conclusion: the project is dormant, not archived.

### 1.4 Comparison with the launcher approach

The launcher approach is: sandy sets `no_new_privs`, applies Landlock and seccomp to itself, closes
inherited descriptors, then calls `execve`. Seccomp filters are inherited by children and kept
across `execve` ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)).

| Property | `LD_PRELOAD` / `patchelf` | `sandboxify` (ptrace) | sandy launcher |
|---|---|---|---|
| Static binaries | Not covered. Tested: a static musl binary run with `LD_PRELOAD` showed `Seccomp: 0` and printed no warning. | Covered | Covered |
| Code that runs before the filter | Tested with glibc 2.43: the program's `.preinit_array` and the constructor of a `DT_NEEDED` library ran before the preload constructor. IFUNC resolvers and the dynamic loader also run first. | None of the target's code | None of the target's code |
| Library cannot be loaded | Tested: glibc prints "cannot be preloaded ... ignored" and runs the program without the filter (fail open). This is [issue 1](https://github.com/cloudflare/sandbox/issues/1). `patchelf` fixes this but modifies the binary. | Not applicable | Not applicable. sandy itself fails and exits with 125. |
| Setuid or file-capability target | In secure-execution mode the loader ignores preload paths with a slash ([ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)). The program runs privileged and unfiltered. | `no_new_privs` is set before exec, so no privileges are gained | Same as `sandboxify` |
| Target strips `LD_PRELOAD` or re-executes itself | No effect once the filter is loaded, because the filter is inherited. Removing the variable only matters before load. | No effect | No effect |
| Children | Inherit the filter | Inherit the filter | Inherit the filter |
| Threads created before the filter | Not covered. libseccomp does not synchronize threads by default (`SCMP_FLTATR_CTL_TSYNC` is off). A library constructor that starts a thread leaves it unfiltered. | Single thread at install | Single thread at install |
| Foreign architecture | The library must match the program's ELF class and libc. A mismatch should fall into the "cannot be preloaded ... ignored" case (**unverified**, not tested). | Any | Any |
| Privileges needed | None | `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE` when Yama is strict. Fails inside a container or service that already has a seccomp filter. | None |
| What it can enforce | Syscall numbers only | Syscall numbers only | Landlock and seccomp, with argument checks |

The one advantage of the preload mode is a smaller allowlist. The filter starts after the C
runtime is initialized, so a per-application allowlist does not need the startup system calls
([blog post](https://blog.cloudflare.com/sandboxing-in-linux-with-zero-lines-of-code/)). This
helps an operator who writes a tight allowlist for one known service. It does not help sandy,
which runs unknown programs and cannot use a per-program allowlist.

### 1.5 Does it work on more distributions?

No. Seccomp-bpf filters exist on every kernel in section 2, and both approaches use the same
kernel interface. The cloudflare tool appears to work "everywhere" because it only filters system
call numbers. It does not need Landlock or user namespaces because it does not confine the file
system. If sandy enforced only system call numbers, the sandy launcher would run on exactly the
same hosts. The delivery method of cloudflare/sandbox adds conditions instead of removing them:
the preload mode needs a dynamic program with a compatible libc, and `sandboxify` needs root
privileges.

### 1.6 What sandy should adopt

- **Do not adopt the delivery.** `LD_PRELOAD` and `patchelf` break the fail-closed rule, and the
  ptrace mode breaks the unprivileged-use goal.
- **Adopt the self-check idea.** The README checks `Seccomp: 2` in `/proc/<pid>/status`. The
  escape tests can assert `NoNewPrivs: 1` and `Seccomp: 2` (and `Seccomp_filters`) inside the
  sandbox.
- **Adopt a diagnostic mode only in a form that keeps enforcement.** The cloudflare log mode
  allows every call. sandy must not offer that. Landlock ABI 7 has
  `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, and seccomp has `SECCOMP_FILTER_FLAG_LOG`. Both log
  denials while they still deny. A `--log-denials` option can use them to help users write
  policies.

## 2. Availability matrix

### 2.1 Table

Method: most values come from the kernel `.config` files shipped in the distribution packages
(Ubuntu `linux-headers`, Debian `linux` source, AlmaLinux `kernel-core`, Arch headers packages)
or from the distribution's config tree in git. I re-checked the `CONFIG_LSM` lines of the Ubuntu,
Debian, AlmaLinux, Arch, Fedora, SUSE and WSL2 configs myself. "ABI" is the upstream ABI of the
kernel version unless the row says "stated" (read in the distribution's Landlock source) or
"observed" (returned by a running kernel). Landlock is active only when it is built
(`CONFIG_SECURITY_LANDLOCK=y`) and listed in `CONFIG_LSM` (or added with `lsm=` at boot).

| Target | Default kernel | Landlock active by default | ABI | Unprivileged user namespaces | x32 syscalls reachable |
|---|---|---|---|---|---|
| Ubuntu 22.04 GA | 5.15 | yes | 1 (no backport found, **unverified**) | allowed | **yes** (`CONFIG_X86_X32=y`) |
| Ubuntu 22.04 HWE | 6.8 | yes | 4 (observed on the 6.8 Azure kernel) | allowed | no |
| Ubuntu 24.04 GA | 6.8 | yes | 4 | restricted by AppArmor | no |
| Ubuntu 24.04 HWE | 6.17, now 7.0 (24.04.5) | yes | 7 (6.17), 8 (7.0), observed on runners | restricted | no |
| Ubuntu 26.04 | 7.0 | yes | 8 | restricted, plus `kernel.apparmor_restrict_unprivileged_unconfined=1` | no |
| Debian 12 | 6.1 | yes | 2 (**unverified** backports) | allowed (`kernel.unprivileged_userns_clone=1`) | no: built but off unless `syscall.x32=y` |
| Debian 13 | 6.12 | yes | 6 | allowed | no (same as Debian 12) |
| RHEL 8, AlmaLinux 8, Rocky 8 | 4.18 | **no** (not built) | none | allowed (**unverified** default; the DISA STIG asks admins to set 0) | no |
| RHEL 9.0 to 9.5 | 5.14 | **no** (built, not in `CONFIG_LSM`) | none | allowed (**unverified**) | no |
| RHEL 9.6 | 5.14 | yes | 5 (stated) | allowed (**unverified**) | no |
| RHEL 9.7, 9.8 | 5.14 | yes | 6 (stated) | allowed (**unverified**) | no |
| RHEL 10.0 to 10.2 | 6.12 | yes | 6 (stated) | allowed (**unverified**) | no |
| Fedora 43, 44 | 7.2 | yes | 10 (observed on Fedora 44) | allowed | no |
| openSUSE Leap 15.6, SLES 15 SP6 | 6.4 | **no** (built, not in `CONFIG_LSM`) | (3 if enabled with `lsm=`) | no restriction found (**unverified**) | no |
| SLES 15 SP7 | 6.4 | **no** (built, not in `CONFIG_LSM`) | (6 backported, if enabled with `lsm=`) | no restriction found (**unverified**) | no |
| openSUSE Leap 16.0, SLES 16.0 | 6.12 | yes | 6 | no restriction found (**unverified**) | no; i386 emulation also off by default |
| Arch `linux` | 7.2 | yes | 10 | allowed | **yes** (`CONFIG_X86_X32_ABI=y`) |
| Arch `linux-hardened` | 7.2 | yes | 10 | **denied** | no |
| Linux Mint 22, 22.1 | 6.8 | yes | 4 | restricted (uses Ubuntu's AppArmor package) | no |
| Linux Mint 22.2, 22.3 | 6.14 (HWE) | yes | 6 | restricted | no |
| LMDE 7 | 6.12 (Debian 13) | yes | 6 | allowed | no |
| ChromeOS Crostini (Termina VM) | 6.6 | yes (Kconfig default list, derived) | 3 (**unverified** backports) | **unverified** | no |
| WSL2 (Microsoft kernel) | 6.18 | yes | 7 | allowed (derived) | **yes** (`CONFIG_X86_X32_ABI=y`) |
| GitHub `ubuntu-22.04` runner | 6.8 Azure | yes | 4 (observed) | allowed | no |
| GitHub `ubuntu-24.04` runner | 6.17 or 7.0 Azure | yes | 7 or 8 (observed, varies by host) | restricted | no |

Seccomp filters (`CONFIG_SECCOMP_FILTER=y`) are enabled on every target. RHEL 9 and 10 default to
`kernel.io_uring_disabled=2` (CentOS Stream source); RHEL 8 has no io_uring.

### 2.2 Sources and notes

- **Ubuntu.** Every extracted config (5.15.0-25, 5.15.0-199, 6.8, 6.17, 7.0) has
  `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`; the 7.0 kernels add `bpf`. Kernels
  before 5.15.0-17 lacked Landlock in the list
  ([LP#1953192](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1953192)), but that was
  fixed before the 22.04 release. Packages: [linux](http://archive.ubuntu.com/ubuntu/pool/main/l/linux/),
  [linux-hwe-6.8](http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.8/),
  [linux-hwe-7.0](http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-7.0/), and the
  [26.04 kernel announcement](https://discourse.ubuntu.com/t/26-04-lts-resolute-raccoon-shipping-with-the-final-7-0-linux-kernel/80838).
- **Ubuntu user namespace restriction.** The kernel option
  `CONFIG_SECURITY_APPARMOR_RESTRICT_USERNS` is not set. The apparmor package sets
  `kernel.apparmor_restrict_unprivileged_userns = 1` in `/usr/lib/sysctl.d/10-apparmor.conf`
  (24.04 and 26.04). An unconfined process can still create a user namespace, but it then runs
  under the `unprivileged_userns` profile, which denies all capabilities, so mounts inside fail.
  A program with an AppArmor profile that contains `userns,` is exempt
  ([Ubuntu Discourse](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)).
  Qualys published three bypasses of this restriction in 2025
  ([advisory](https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt)).
- **Debian.** Both releases carry the patch
  `add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch` with default value 1
  (allowed). x32 is compiled in with `CONFIG_X86_X32_DISABLED=y`
  ([source pool](http://deb.debian.org/debian/pool/main/l/linux/)).
- **RHEL.** `CONFIG_LSM` is `"yama,integrity,selinux,bpf"` in AlmaLinux 8,
  `"landlock,lockdown,yama,integrity,selinux,bpf"` in AlmaLinux 9.8 and
  `"lockdown,yama,integrity,selinux,bpf,landlock"` in AlmaLinux 10. In CentOS Stream 9,
  `LANDLOCK_ABI_VERSION` is 1 and Landlock is missing from `CONFIG_LSM` at `kernel-5.14.0-503.el9`
  (9.5); it is 5 and listed at `-570.el9` (9.6); it is 6 at `-611.el9` (9.7)
  ([CentOS Stream 9 kernel](https://gitlab.com/redhat/centos-stream/src/kernel/centos-stream-9/-/blob/kernel-5.14.0-687.el9/security/landlock/syscalls.c),
  [CentOS Stream 10 kernel](https://gitlab.com/redhat/centos-stream/src/kernel/centos-stream-10/-/blob/kernel-6.12.0-211.el10/security/landlock/syscalls.c)).
  Rocky Linux configs differ from AlmaLinux only in drivers.
- **SUSE.** `CONFIG_LSM="integrity,apparmor,selinux,bpf"` in
  [SLE15-SP7](https://github.com/openSUSE/kernel-source/blob/SLE15-SP7/config/x86_64/default)
  and SP6; `"landlock,lockdown,yama,integrity,selinux,bpf"` in
  [SL-16.0](https://github.com/openSUSE/kernel-source/blob/SL-16.0/config/x86_64/default). An
  administrator can activate Landlock on SLES 15 with an `lsm=` boot parameter that lists the
  current modules plus `landlock`. **unverified**: whether any SUSE default adds it.
- **Arch.** `CONFIG_LSM="landlock,lockdown,yama,integrity,bpf"` in both kernels.
  [linux-hardened](https://github.com/anthraxx/linux-hardened/blob/v7.2.10-hardened1/init/Kconfig)
  sets `USER_NS_UNPRIVILEGED` to off by default.
- **Linux Mint.** Uses Ubuntu's kernel and AppArmor packages; release notes for
  [22](https://linuxmint.com/rel_zena_cinnamon.php) and later list the kernels.
- **Crostini.** The Termina board sets `kernel-6_6`
  ([overlay](https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/refs/heads/main/project-termina/profiles/base/make.defaults));
  its [config](https://chromium.googlesource.com/chromiumos/third_party/kernel/+/refs/heads/chromeos-6.6/chromeos/config/termina/base.config)
  sets `CONFIG_SECURITY_LANDLOCK=y` and inherits the default LSM list, which starts with
  `landlock`. The [Landlock news](https://landlock.io/news/3/) also lists Termina and WSL2 as
  enabled. **unverified**: the kernel on stable ChromeOS milestones and the running LSM list.
- **WSL2.** [config-wsl](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.54.1/arch/x86/configs/config-wsl)
  of 6.18.54.1 has Landlock first in `CONFIG_LSM` and `CONFIG_X86_X32_ABI=y`.

### 2.3 What the matrix means for sandy

- Landlock is active by default on every target except RHEL 8, RHEL 9.0 to 9.5, SLES 15 and
  Leap 15.6. RHEL 9 users on a current minor release (9.6 or newer) have it.
- Every LTS kernel in the matrix has ABI 8 or lower, so none has
  `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`. Only Fedora and Arch (7.2) have it today. The seccomp rule on
  `socket(AF_UNIX)` stays necessary for years.
- ABI 6 (signal and abstract socket scoping) is missing on Ubuntu 22.04 (GA and HWE), Ubuntu
  24.04 GA, Debian 12, RHEL 9.6, Linux Mint 22 and 22.1, Crostini and the GitHub `ubuntu-22.04`
  runners.
- ABI 1 or 2 (no truncation control) remains on Ubuntu 22.04 GA and Debian 12.
- x32 system calls are reachable on Ubuntu 22.04 GA, Arch `linux` and WSL2. The seccomp filter
  must handle them (section 5.2).
- Unprivileged user namespaces are restricted on Ubuntu 24.04 and newer, Linux Mint 22,
  the GitHub `ubuntu-24.04` runners and `linux-hardened`. This matters for sections 4 and 7.

## 3. Landlock

### 3.1 ABI versions

Each row was checked against `security/landlock/syscalls.c` and `include/uapi/linux/landlock.h`
at the release tag in the [mainline repository](https://github.com/torvalds/linux), and against
the [Landlock user documentation](https://docs.kernel.org/userspace-api/landlock.html).

| ABI | First kernel | Adds |
|---|---|---|
| 1 | 5.13 | File system rights: execute, read and write file, read directory, remove, make char/dir/reg/sock/fifo/block/sym. Linking and renaming across directories is always denied. Ptrace scoping. |
| 2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER`: controlled link and rename across directories |
| 3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | 6.7 | `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` (per port) |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV`: ioctl on character and block devices |
| 6 | 6.12 | `scoped`: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` |
| 7 | 6.15 | Audit logging flags: `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`, `..._LOG_NEW_EXEC_ON`, `..._LOG_SUBDOMAINS_OFF`. The errata query `LANDLOCK_CREATE_RULESET_ERRATA` also appeared in this cycle. |
| 8 | 7.0 | `LANDLOCK_RESTRICT_SELF_TSYNC`: apply the domain to all threads |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`: `connect()` and `sendmsg()` with an address to pathname Unix sockets |
| 10 | 7.2 | `LANDLOCK_ACCESS_NET_BIND_UDP`, `LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP`; "quiet" flags to suppress logs for marked objects |
| 11 | 7.3 | `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS`: set `no_new_privs` only if the restriction succeeds |

Linux 7.3 was tagged on 2026-10-18. On 2026-10-22 the mainline `master` branch has the same UAPI
header as 7.3, so no ABI 12 exists yet.

Distribution kernels can contain backports, so the kernel version alone does not prove the ABI.
sandy must ask the kernel (section 6).

### 3.2 Pathname Unix sockets

- Merged as `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` in commit
  [`ae97330d1bd6`](https://github.com/torvalds/linux/commit/ae97330d1bd6) "landlock: Control
  pathname UNIX domain socket resolution by path", first released in Linux 7.1 (ABI 9).
- It covers `connect(2)` and `sendmsg(2)` with an explicit address. A denial returns `EACCES`.
- It applies only to server sockets created outside the domain. A socket server that the
  sandboxed program creates inside its own domain stays reachable. This matches the semantics of
  the `LANDLOCK_SCOPE_*` flags (UAPI header comment).
- It is a file system right, so a rule can allow one socket path. sandy v1 only needs "all" or
  "none", but a later policy version could allow selected sockets on 7.1 and newer.
- It does not cover abstract sockets. `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6) does.
- It does not cover Unix socket descriptors that are already open. sandy closes inherited
  descriptors, so this does not matter.

### 3.3 Ptrace and `/proc/<pid>`

Landlock registers the `ptrace_access_check` and `ptrace_traceme` LSM hooks since ABI 1
([`security/landlock/ptrace.c` in 5.13](https://github.com/torvalds/linux/blob/v5.13/security/landlock/ptrace.c),
now [`task.c`](https://github.com/torvalds/linux/blob/v7.3/security/landlock/task.c)). A process
may only trace a process in the same domain or in a nested domain. The kernel uses the same check
for `/proc/<pid>/mem`, `/proc/<pid>/environ`, `process_vm_readv` and `process_vm_writev`.

Tested on kernel 7.2. A child process created a domain that handles only
`LANDLOCK_ACCESS_FS_MAKE_SOCK` (so file rules did not block `/proc`). Against a sibling process of
the same user outside the domain:

| Action | Before Landlock | Inside the domain |
|---|---|---|
| `open("/proc/<pid>/environ")` and `read` | ok | `EACCES` |
| `open("/proc/<pid>/mem")` | ok | `EACCES` |
| `process_vm_readv` | ok | `EPERM` |
| `ptrace(PTRACE_ATTACH)` | ok | `EPERM` |
| `kill(pid, 0)` with `LANDLOCK_SCOPE_SIGNAL` | ok | `EPERM` |

So `ProcessMemoryIsolated` holds with any Landlock ABI. Denying `ptrace` and `process_vm_*` in
seccomp is still useful as a second layer.

### 3.4 Gaps that matter for sandy

- **Metadata changes.** The [documentation](https://docs.kernel.org/userspace-api/landlock.html)
  says Landlock cannot restrict `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`,
  `fcntl` and `access`. Tested on 7.2 (see key finding 2). Proposals for chmod and chown rights
  exist ([2022](https://kernsec.org/pipermail/linux-security-module-archive/2022-August/033530.html),
  [April 2026](https://kernsec.org/pipermail/linux-security-module-archive/2026-April/056770.html))
  but are not in mainline as of 7.3. Consequences for sandy:
  - A sandboxed program can `chmod 0644` a private key of the user, which makes it readable by
    other local users. It can also `chmod 000` files to break other programs, change time stamps
    and set `user.*` extended attributes.
  - It can test whether any path exists and read its size, owner and time stamps.
  - Options: (a) deny the path-based variants in seccomp (`chmod`, `fchmodat`, `fchmodat2`,
    `chown`, `lchown`, `fchownat`, `utime`, `utimes`, `futimesat`, `utimensat` with a non-NULL
    path, `setxattr`, `lsetxattr`, `removexattr`, `lremovexattr`, `setxattrat`, `removexattrat`,
    `file_setattr`) and allow only the descriptor-based variants (`fchmod`, `fchown`, `fsetxattr`,
    `futimens`), which work only on files that Landlock let the program open. This breaks
    programs that call `chmod(path)` inside writable directories, for example `chmod +x`, `tar`,
    `cp -p` and `install`. (b) Accept the gap and document it as a limitation. (c) Treat it as a
    requirement that Linux cannot enforce and refuse to run, which would refuse every host.
    Option (a) needs a decision by the project owner. **unverified**: the full list of programs
    that (a) breaks; it needs testing.
  - `O_PATH` descriptors are a second route. Tested on 7.2 in a domain with no rules:
    `open(path, O_PATH)` on a file outside the policy succeeds. With that descriptor,
    `fchmodat2(fd, "", mode, AT_EMPTY_PATH)`, `fchownat(fd, "", -1, -1, AT_EMPTY_PATH)`,
    `utimensat(fd, "", NULL, AT_EMPTY_PATH)` and `chmod("/proc/self/fd/<fd>")` all succeed.
    `fchmod`, `fchown`, `fsetxattr` and `utimensat(fd, NULL, ...)` fail with `EBADF` on an
    `O_PATH` descriptor. So option (a) must deny `fchmodat`, `fchmodat2` and `fchownat`
    completely, not only some flags. With that, the tested routes are closed.
- **Truncation before ABI 3.** Without `LANDLOCK_ACCESS_FS_TRUNCATE`, `truncate(path)` is not
  checked, and `open(O_RDONLY | O_TRUNC)` needs only the read right. Linux truncates the file in
  that case if the user has write permission (`build_open_flags` adds `MAY_WRITE` for `O_TRUNC`
  in [fs/open.c](https://github.com/torvalds/linux/blob/v7.3/fs/open.c)). So with ABI 1 or 2, a
  program can empty files that are outside the policy or in `read` paths. Tested by simulation on
  7.2: a ruleset that handles exactly the ABI 2 rights (no `TRUNCATE`) let
  `open(O_RDONLY | O_TRUNC)` empty a file in a read-only path and let `truncate()` empty a file
  outside every rule. A real ABI 2 kernel behaves the same way unless it has a backport
  (**unverified** on a real ABI 2 kernel). Two ways to handle it:
  - Require ABI 3. This is simpler, but it excludes the default kernels of Ubuntu 22.04 GA and
    Debian 12 (section 2).
  - Add seccomp rules when the ABI is 1 or 2: deny `truncate` (and `truncate64` where it exists),
    deny `open` and `openat` when `flags & (O_ACCMODE | O_TRUNC) == O_TRUNC` (a masked compare),
    and return `ENOSYS` for `openat2`, whose flags seccomp cannot read. `creat` and writable opens
    already need the write right. io_uring is denied anyway. The cost: `truncate(path)` also fails
    inside `read_write` paths, where programs normally use `ftruncate` instead.
- **`REFER` before ABI 2.** With ABI 1 every rename or link across directories fails with
  `EXDEV` (`hook_path_rename` in
  [5.13 fs.c](https://github.com/torvalds/linux/blob/v5.13/security/landlock/fs.c)). This is
  safe. Tools such as `mv` treat `EXDEV` as "different file system" and fall back to copy and
  delete, but programs that rename a temporary file from one directory into another fail.
- **Execute right.** `LANDLOCK_ACCESS_FS_EXECUTE` controls `execve`. It does not control
  `mmap(PROT_EXEC)` of a readable file or running a file through the dynamic loader
  (`ld.so /path/file`). The threat model already gives the attacker arbitrary code inside the
  sandbox, so this does not widen the attacker's power. It means "never execute" in a
  `read_write` path is a rule about `execve`, not a security property.
- **Errata.** `LANDLOCK_CREATE_RULESET_ERRATA` returns a bitmask of fixes. Erratum 3 fixes a way
  to widen rights through rename or link of disconnected directories after bind mounts
  ([errata/abi-1.h](https://github.com/torvalds/linux/blob/v7.3/security/landlock/errata/abi-1.h)).
  The kernel documentation says most programs should not check errata. sandy grants `REFER` only
  inside `read_write` paths, and the sandboxed program cannot mount, so the practical risk is low.
  **unverified**: whether any supported stable kernel lacks this fix.

## 4. Fallbacks when Landlock is missing

### 4.1 User namespace and mount namespace

This is the bubblewrap model. Section 7 evaluates bubblewrap itself.

- **How it works.** The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, writes the uid and
  gid maps, builds a new root from bind mounts (read-only and `noexec` where needed), calls
  `pivot_root`, drops capabilities and runs the program. Paths outside the new root do not exist
  for the program.
- **Kernel requirement.** `CONFIG_USER_NS` and permission for unprivileged users to create user
  namespaces. The feature is old (Linux 3.8); the permission is the problem.
- **Blocked by default.** Ubuntu 24.04 and newer (AppArmor restriction, details in section 2),
  inside the default Docker seccomp profile (`unshare` and namespace flags of `clone` need
  `CAP_SYS_ADMIN`, read in
  [default.json](https://github.com/moby/profiles/blob/main/seccomp/default.json)), inside
  Flatpak (its filter denies `CLONE_NEWUSER`), and on hosts where an administrator set
  `user.max_user_namespaces=0` or `kernel.unprivileged_userns_clone=0`. Section 2 has the
  distribution defaults.
- **Complexity.** High. In bubblewrap 0.13.1, `bubblewrap.c` alone has 3,570 lines of C, plus
  helper files for bind mounts and safe path resolution. The hard parts are
  symlink-safe path resolution while building the root, mount propagation, `/proc` and `/dev`,
  `setgroups`, and the uid and gid maps.
- **Pitfalls.**
  - Symlinks during setup: bubblewrap followed attacker-controlled symlinks while creating
    directories in the new root until 0.12.0
    ([CVE-2026-87766](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx)).
  - The program runs inside a user namespace and can create nested ones unless a seccomp filter
    stops it. This exposes kernel code that is otherwise reachable only by root. Canonical cites a
    Google report that 44% of observed kernel exploits needed unprivileged user namespaces
    ([Canonical](https://canonical.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)).
  - A PID namespace needs a PID 1 process, so the program is no longer the process that sandy's
    caller started. This conflicts with the `execve` process model in `DESIGN.md`.
- **Security record.** Six CVEs in bubblewrap itself (section 7.1). Many kernel privilege
  escalations need unprivileged user namespaces, which is why Ubuntu restricts them.

### 4.2 Seccomp user notification with `SECCOMP_IOCTL_NOTIF_ADDFD`

- **How it works.** The filter returns `SECCOMP_RET_USER_NOTIF` for file system calls. A
  supervisor process reads the arguments from the target's memory, checks the path against the
  policy, opens the file itself and installs the descriptor in the target with
  `SECCOMP_IOCTL_NOTIF_ADDFD`.
- **Kernel requirement.** `SECCOMP_RET_USER_NOTIF` since Linux 5.0
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)), `NOTIF_ADDFD` since 5.9,
  `SECCOMP_ADDFD_FLAG_SEND` since 5.14
  ([seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)).
- **Blocked by default.** Not blocked anywhere I found. It needs a supervisor process that lives
  as long as the program, which changes the `execve` process model.
- **Complexity.** Very high. The supervisor must emulate every system call that takes a path:
  the `open`, `stat`, `access`, `readlink`, `rename`, `link`, `unlink`, `mkdir`, `mknod`, `chmod`,
  `chown`, `utime`, `truncate` and `xattr` families, `inotify_add_watch`, `fanotify_mark`,
  `bind` and `connect` on Unix sockets, `name_to_handle_at`, `statfs`, and every new one the kernel
  adds. It must resolve paths against the target's current directory and directory descriptors,
  handle symlinks and `/proc/self` magic links, and handle signals that interrupt a waiting call.
- **Pitfalls.** `execve` and `chdir` cannot be emulated. They must continue in the target with
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The man page says this mechanism "must not be used to make
  security policy" decisions because of the time-of-check to time-of-use race: another thread of
  the target can change the path after the check. Every read from target memory must be followed
  by a `SECCOMP_IOCTL_NOTIF_ID_VALID` check. Each file system call costs two context switches.
- **Security record.** Syd (sydbox) uses this design. Its documentation accepts the race for
  `exec` and `chdir`, and its history contains fixed escapes through pointer modification and
  through `symlink` targets ([commit](https://git.omada.cafe/mirrors/syd/commit/934e7730011f176cdfdda2f941c154686a6f5b06)).
  I found no CVE entries (**unverified** that none exist).

### 4.3 Other options

| Option | Why it does not fit sandy v1 |
|---|---|
| ptrace supervisor (as `proot` does) | Same race as 4.2, slow, conflicts with Yama and with debuggers. Not a security boundary. |
| setuid-root helper (old bubblewrap setuid mode, firejail) | Breaks the unprivileged-use goal. bubblewrap removed setuid support in 0.12.0 after [CVE-2026-41163](https://github.com/containers/bubblewrap/security/advisories/GHSA-xq78-7hw4-5jvp). Firejail had a root escalation through its setuid binary ([CVE-2022-31214](https://nvd.nist.gov/vuln/detail/CVE-2022-31214)). |
| AppArmor or SELinux profile installed by `sandy setup` | Profiles are static and loaded by root. sandy's policy changes per run. Each distribution uses a different LSM. |
| Virtual machine | Needs `/dev/kvm` and a guest image. Different product. |
| Newer kernel | The realistic fix for most hosts: for example the Ubuntu HWE kernel, or a newer distribution release (section 2). |

### 4.4 Recommendation

sandy v1 should implement no fallback and refuse to run when Landlock is missing. Reasons:

- Only four targets in section 2 lack Landlock: RHEL 8, RHEL 9.0 to 9.5, SLES 15 and Leap 15.6.
  - RHEL 9: the current minor releases (9.6 and newer) have Landlock. Only hosts that stay on an
    old minor release (for example with extended update support) are affected.
  - SLES 15 and Leap 15.6: the kernel has Landlock built in. An administrator can activate it
    with an `lsm=` boot parameter. `sandy check` can print this advice. This is one-time host
    preparation with admin rights, which `DESIGN.md` allows.
  - RHEL 8: no Landlock and no way to add it. RHEL 8 is in its maintenance phase.
- The user namespace fallback (4.1) would work on exactly these hosts, because none of them
  restricts user namespaces by default. That is the honest case for it. Against it: it is a
  second large mechanism with different semantics (hidden paths instead of denied paths, a
  different process model), it adds kernel attack surface, and it would serve a shrinking set of
  hosts. Programs and tests would behave differently per host.
- The other options are not safe as a security policy (4.2, ptrace) or need root (setuid, MAC
  profiles).

Revisit this decision if RHEL 8 or SLES 15 users become important. Then the fallback should be a
namespace layer that sandy owns (section 7.4, option b), not one of the other options.

## 5. Seccomp filter for the launcher

### 5.1 What other sandboxes do

| Project | Structure | Default for an unlisted call | Notes |
|---|---|---|---|
| Chromium ([baseline_policy.cc](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/linux/seccomp-bpf-helpers/baseline_policy.cc)) | Allowlist | `SIGSYS` trap that crashes the process | `clone3` returns `ENOSYS` so libc uses `clone`. Arguments of `clone`, `ioctl`, `kill`, `socket`, `mmap`, `prctl` are checked. The policy compiler kills on a wrong arch and on a wrong x32 bit ([policy_compiler.cc](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/linux/bpf_dsl/policy_compiler.cc)). |
| Firefox ([SandboxFilter.cpp](https://github.com/mozilla-firefox/firefox/blob/main/security/sandbox/linux/SandboxFilter.cpp)) | Allowlist on Chromium's compiler | Trap, then crash report | File system calls trap and go to a broker process. `clone3` returns `ENOSYS`. |
| Flatpak ([flatpak-run.c](https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c)) | Denylist | Allow | `EPERM` for `unshare`, `setns`, `mount`, `keyctl` family, `chroot` and others. `ENOSYS` for `clone3` and the new mount API. `clone` with `CLONE_NEWUSER` denied. `ioctl` `TIOCSTI` and `TIOCLINUX` denied with a 32-bit masked compare. `socket()` allows only `AF_UNSPEC`, `AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK` (plus optional `AF_CAN`, `AF_BLUETOOTH`); other families get `EAFNOSUPPORT`. Foreign arches are killed by libseccomp's default. |
| bubblewrap ([bwrap.xml](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)) | None built in | Not applicable | Loads a compiled filter from `--seccomp FD` or `--add-seccomp-fd FD` as the last step before `execve`. |
| systemd ([systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html), [seccomp-util.c](https://github.com/systemd/systemd/blob/main/src/shared/seccomp-util.c)) | Allowlist or `~` denylist with groups (`@mount`, `@privileged`, `@debug`, `@module`, `@raw-io`, `@reboot`, `@swap`, `@keyring`, `@obsolete`, `@cpu-emulation`, `@clock`) | Kill with `SIGSYS`, or the errno in `SystemCallErrorNumber=` | In allowlist mode, system calls newer than systemd's own table return `ENOSYS`. `SystemCallArchitectures=native` blocks other ABIs. `RestrictAddressFamilies=` does not affect `socketpair()`, io_uring, or 32-bit x86. |
| Docker / moby ([default.json](https://github.com/moby/profiles/blob/main/seccomp/default.json)) | Allowlist | `EPERM` | Never allows `keyctl`, `add_key`, `request_key`, `userfaultfd`, `kexec_load`, `io_uring_*` (removed [in 2023](https://github.com/moby/moby/commit/891241e7e74d4aae6de5f6125574eb994f25e169)). Namespace calls, `bpf`, `perf_event_open` and `mount` need `CAP_SYS_ADMIN`. `clone` is allowed only without namespace flags (`flags & 0x7E020000 == 0`); `clone3` returns `ENOSYS` because glibc falls back only on `ENOSYS` ([commit](https://github.com/moby/moby/commit/9f6b562dd12ef7b1f9e2f8e6f2ab6477790a6594)). Socket families became an allowlist [in August 2026](https://github.com/moby/profiles/commit/f8d7350408f650ab0c693ce77087e808997840c5); `AF_ALG` and `AF_VSOCK` are blocked. |

Lessons from these projects:

- Flatpak's denylist missed the new mount API and allowed an escape
  ([CVE-2021-41133](https://nvd.nist.gov/vuln/detail/CVE-2021-41133)). A denylist without a guard
  against unknown system calls fails open when the kernel adds a system call.
- Flatpak's first `TIOCSTI` rule compared all 64 bits. Setting the upper 32 bits bypassed it
  ([CVE-2019-10063](https://nvd.nist.gov/vuln/detail/CVE-2019-10063)). `ioctl` takes an
  `unsigned int cmd`, so the filter must compare only the low 32 bits.
- Moby tried to block `socketcall` to stop 32-bit programs from bypassing the `AF_ALG` rule, then
  [reverted it](https://github.com/moby/profiles/commit/3c28324314729dbade8287e868eef6338c42807a)
  because it broke x86 programs.
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) and the
  [kernel documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html) say a filter
  must check `seccomp_data.arch` before it interprets the system call number.

### 5.2 Architectures

- **x86_64.** Native calls arrive with `AUDIT_ARCH_X86_64`. 32-bit calls through `int 0x80`
  arrive with `AUDIT_ARCH_I386` and other numbers. x32 calls also arrive with
  `AUDIT_ARCH_X86_64` but have bit `0x40000000` (`__X32_SYSCALL_BIT`) set. A denylist on the
  number alone is bypassable with x32 numbers on a kernel with `CONFIG_X86_X32_ABI`
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)). The Fedora test host has
  `CONFIG_X86_X32_ABI` unset and `CONFIG_IA32_EMULATION=y`. Section 2 lists other distributions.
- **aarch64.** AArch32 tasks arrive with `AUDIT_ARCH_ARM` when the kernel has `CONFIG_COMPAT`.
- **socketcall.** On i386 and 32-bit ARM, `socketcall(2)` hides the address family behind a
  pointer, so seccomp cannot check it. i386 has direct `socket` calls since Linux 4.3, but 32-bit
  programs still use `socketcall`.

Recommendation: allow only the native arch. Kill the process (`SECCOMP_RET_KILL_PROCESS`) for any
other arch. This is the default in libseccomp and seccompiler, and it matches Chromium and
systemd's recommended `SystemCallArchitectures=native`. It removes the `socketcall` problem. x32
numbers arrive with the native arch value; the allowlist of section 5.4 does not contain them, so
they get `ENOSYS` and never run. A separate x32 check that kills (as Chromium and libseccomp do) is
also fine. The cost: 32-bit programs cannot run under sandy v1. sandy can check the ELF class of the
program before `execve` and refuse with a clear message. A 32-bit child started later is killed.

### 5.3 Return actions

| Case | Action | Reason |
|---|---|---|
| Foreign arch | `KILL_PROCESS` | No supported program uses them. A clear failure is better than odd errors. |
| x32 number on x86_64 | `ERRNO(ENOSYS)` through the allowlist, or `KILL_PROCESS` | Either way the call does not run. |
| Policy denial (socket family, `ptrace`, `keyctl`, ...) | `ERRNO(EPERM)`, or `EAFNOSUPPORT` for socket families | Programs probe optional features. Killing them on a probe breaks normal programs. |
| Call whose arguments cannot be checked but that has a libc fallback (`clone3`) | `ERRNO(ENOSYS)` | glibc and other runtimes fall back to `clone` only on `ENOSYS`. |
| System call that is not in sandy's reviewed table | `ERRNO(ENOSYS)` | Fails closed for system calls added after the sandy build. It looks like an older kernel, which programs handle. |

Do not use `SECCOMP_RET_USER_NOTIF` for policy decisions; the man page forbids it (section 4.2).
`SECCOMP_RET_TRAP` adds nothing for unknown programs, and the program can catch `SIGSYS`.
`SECCOMP_FILTER_FLAG_LOG` can log denials for a diagnostic option without allowing them.

When filters are stacked, the kernel returns the action with the highest precedence. Among equal
actions, the data of the most recently installed filter wins
([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)).

### 5.4 Allowlist or denylist

A full allowlist (Chromium, Firefox, Docker) is the safest structure. For "run any program" it
must contain almost every system call, because sandy cannot know what the program needs. A pure
denylist (Flatpak, cloudflare/sandbox deny mode) is simpler but fails open for new system calls.

Recommended structure: an allowlist of every system call that sandy has reviewed, plus a
denylist with argument checks. In practice this is two stacked filters:

1. Filter A: the native arch only (kill otherwise). Every reviewed system call of the arch is
   allowed without conditions, except `clone3`. Anything else returns `ENOSYS`. This covers new
   system calls, x32 numbers (they are not in the table) and `clone3`.
2. Filter B, installed after A: the rules of section 5.5 return `EPERM` (or the listed errno).
   Everything else is allowed.

For a call such as `keyctl`, A returns `ALLOW` and B returns `ERRNO(EPERM)`; `ERRNO` has the
higher precedence, so the call fails with `EPERM`.

A simpler guard "number greater than the highest known number returns `ENOSYS`" is not enough.
runc uses such a guard and documents its weakness
([enosys_linux.go](https://github.com/opencontainers/runc/blob/main/libcontainer/seccomp/patchbpf/enosys_linux.go)).
The x86_64 table in Linux 7.3 shows why: `uretprobe` (335) and `uprobe` (336) were added after
the shared numbering from 424 upward started, but below it
([syscall_64.tbl](https://github.com/torvalds/linux/blob/v7.3/arch/x86/entry/syscalls/syscall_64.tbl)).
Linux 7.3 also added `fchroot` (472), for which a table allowlist returns `ENOSYS` until sandy
reviews it. `listns` (470) and `rseq_slice_yield` (471) are in the 7.2 table that sandy has
reviewed, so the allowlist passes them; `listns` is denied by the denylist instead.

Costs: every new kernel system call needs a sandy release before programs can use it. Programs
handle `ENOSYS` like an older kernel, so this is usually invisible. Since Linux 5.11 the kernel
caches, per system call, whether the whole filter stack always allows it; a new filter "must be
as restrictive as the last" (`seccomp_cache_prepare_bitmap` in
[kernel/seccomp.c](https://github.com/torvalds/linux/blob/v7.3/kernel/seccomp.c)). Calls that
both filters allow without conditions skip the BPF code. Calls with argument checks (`ioctl`,
`socket`, `clone`) run it every time.

### 5.5 Rules

| System calls | Action | Reason |
|---|---|---|
| `socket` with a family outside the allowed set | `EAFNOSUPPORT` | Allowed set: `AF_UNIX` if `unix_sockets = "all"`; `AF_INET`, `AF_INET6`, `AF_NETLINK` if `ip = "all"`. Everything else is denied, including `AF_SMC` (tested TCP fallback, key finding 4), `AF_VSOCK` (host services in VMs), `AF_ALG` ([CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)), `AF_PACKET`, `AF_XDP`. `socketpair` stays allowed. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | `EPERM` | io_uring operations such as `IORING_OP_SOCKET` and `IORING_OP_CONNECT` do not pass through seccomp, so they bypass the socket rules ([LWN](https://lwn.net/Articles/1054225/)). Google reported that 60% of kCTF exploit submissions used io_uring and disabled it on ChromeOS and production servers ([Google](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html)). `EPERM` is what a host with `kernel.io_uring_disabled=2` returns. |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp` | `EPERM` | Landlock already blocks these against processes outside the domain (section 3.3). This is a second layer. It also stops debuggers inside the sandbox. |
| `unshare`, `setns`; `clone` with any `CLONE_NEW*` flag (mask `0x7E020000`); `clone3` | `EPERM`; `clone3` gets `ENOSYS` | User namespaces expose interfaces that are normally limited to root. Canonical cites a Google report that 44% of observed exploits needed unprivileged user namespaces ([Canonical](https://canonical.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)). Programs that build their own namespace sandbox lose it and must use their fallback. |
| `mount`, `umount2`, `pivot_root`, `chroot`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`, `open_tree_attr`, `mount_setattr` | `EPERM` (Flatpak returns `ENOSYS` for the new mount API) | Landlock already denies `mount` and `pivot_root` for a domain with file rules, but not `chroot`. These need privileges that sandy never grants. Second layer at no compatibility cost. |
| `bpf`, `perf_event_open`, `userfaultfd` | `EPERM` | Kernel attack surface and exploit helpers. Docker denies them for unprivileged containers. |
| `keyctl`, `add_key`, `request_key` | `EPERM` | The user keyring is shared by all processes of the user and is not tied to the sandbox. Docker and Flatpak deny these. |
| `ioctl` with `TIOCSTI` or `TIOCLINUX` (low 32 bits only) | `EPERM` | `TIOCSTI` injects input into the terminal of the user ([CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226)). `TIOCLINUX` can do the same on virtual consoles ([CVE-2023-28100](https://nvd.nist.gov/vuln/detail/CVE-2023-28100)). sandy keeps the terminal on descriptors 0 to 2 and cannot use `setsid()`, because that would break terminal signals for interactive programs. |
| `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `iopl`, `ioperm`, `open_by_handle_at`, `uselib`, `settimeofday`, `clock_settime` | `EPERM` | All need capabilities. Second layer. |
| `personality` except `0`, `0x8`, `0x20000`, `0x20008`, `0xffffffff` (the values Docker allows); `modify_ldt` | `EPERM` | Old exploit helpers. Flatpak denies `modify_ldt`; Docker allows it on x86. |
| Path-based metadata calls and `fchmodat`, `fchmodat2`, `fchownat` (section 3.4, option a) | `EPERM` | Recommended default; needs the project owner's decision. |
| `truncate`, `truncate64`; `open` and `openat` with `O_TRUNC` in read-only mode; `openat2` (`ENOSYS`) | `EPERM` | Only when the kernel's Landlock ABI is 1 or 2 (section 3.4). |

Root and capabilities: `no_new_privs` stops `execve` from adding privileges, but it does not
remove privileges that sandy already has. If a user runs sandy as root, the program keeps root
capabilities, and the "second layer" rules above become the only layer. Clearing all capability
sets is not enough for uid 0: inside the paths that the policy allows, the program can still
change files that only root may change, and on kernels without Landlock signal scoping it can
signal every process of uid 0. sandy v1 should refuse to run
with effective uid 0 or with any effective, permitted or ambient capability, unless a later
design adds a switch to an unprivileged uid.

Launcher order. Landlock and seccomp apply to the calling thread only, so the launcher must be
single-threaded when it applies them (or use `LANDLOCK_RESTRICT_SELF_TSYNC` and
`SECCOMP_FILTER_FLAG_TSYNC`). A workable order: build the ruleset, set `no_new_privs`, call
`landlock_restrict_self`, close the ruleset descriptor, call
`close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` so every descriptor above 2 closes at `execve`,
install the seccomp filter, then call `execve`. Landlock needs Linux 5.13, so `close_range`
(5.9) and `CLOSE_RANGE_CLOEXEC` (5.11) are always present. Installing seccomp last means the
filter does not have to allow the launcher's own setup calls. If `execve` fails, sandy is still
running and reports the error itself.

### 5.6 Rust crate

| | [seccompiler](https://crates.io/crates/seccompiler) | [libseccomp](https://crates.io/crates/libseccomp) (bindings to C libseccomp) |
|---|---|---|
| Language | Pure Rust | Rust wrapper around C, LGPL-2.1 C library |
| Static musl build | Works with the normal Rust musl target | Needs `libseccomp.a` built for each musl target (`LIBSECCOMP_LINK_TYPE=static`); Alpine ships `libseccomp-static`. Static linking of LGPL code has license obligations (**unverified** how they apply to sandy's license). |
| Architectures | x86_64, aarch64, riscv64; one arch per filter | All major arches; several arches in one filter |
| Arch check | Built in, kills on mismatch | Built in (`SCMP_FLTATR_ACT_BADARCH`, default kill) |
| x32 bit | Not checked (read in the 0.5.0 source). An allowlist filter covers it, because x32 numbers are not in the list. A denylist filter alone would be bypassable. | Handled |
| `socketcall` | Not handled | Rewrites socket rules for `socketcall` |
| Argument checks | `Dword` (low 32 bits) and `Qword` compare, `MaskedEq` and other operators | Full, with explicit 32-bit compare macros |
| Actions | One match action and one mismatch action per filter; stack filters for more | Any action per rule |
| Maintenance | Used by Firecracker. Last release 0.5.0 (2025-03-07). The standalone repository is archived; work continues in the [rust-vmm monorepo](https://github.com/rust-vmm/rust-vmm/tree/main/seccompiler) (syscall tables for kernel 6.18 added 2026-09-25). | C library active (2.6.1, 2026-07-01). Rust crate 0.4.0 (2025-04-05), only CI updates since. |

Recommendation: seccompiler. sandy needs one native arch per build and kills the others, so the
multi-arch features of libseccomp are not needed. It keeps the launcher a pure Rust static
binary. How to use it:

- Build filter A (allowlist, match action `Allow`, mismatch action `Errno(ENOSYS)`) and filter B
  (denylist with conditions, match action `Errno(EPERM)`, mismatch action `Allow`) as two
  `SeccompFilter`s and install A first. An empty rule list for a system call means "match without
  conditions" (read in the 0.5.0 source). About 370 entries at roughly five BPF instructions each
  stay below the kernel limit of 4,096 instructions per filter.
- Use the numbers from `libc::SYS_*` for the rules. Then sandy owns the reviewed system call table
  and does not depend on seccompiler's tables being current.
- Test the compiled filters in CI on both arches: every rule, an x32 number on x86_64, and a
  32-bit program that must be killed.

If seccompiler stops being maintained, the filter is small enough to generate by hand with
`libc` constants. Chromium and OpenSSH generate their BPF without libseccomp.

## 6. Detecting Landlock in CI

### 6.1 Probe

Call `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` (system call 444 on
x86_64 and aarch64). The man page requires `attr = NULL` and `size = 0` with this flag
([landlock_create_ruleset(2)](https://man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html)).

| Result | Meaning |
|---|---|
| A number >= 1 | Highest supported ABI |
| `ENOSYS` | The kernel has no such system call: older than 5.13 or built without `CONFIG_SECURITY_LANDLOCK`. A seccomp filter of a container runtime can also return `ENOSYS` or `EPERM` for unknown calls. |
| `EOPNOTSUPP` | Built in but not enabled at boot (`landlock` is missing from the active LSM list) |

The same call with `LANDLOCK_CREATE_RULESET_ERRATA` returns the errata bitmask (added in Linux
6.15; the test host returned `0xf`). `/sys/kernel/security/lsm` shows the active LSM list, but
`securityfs` may not be mounted in containers, so the system call is the reliable test.

In Rust with the `libc` crate:

```rust
// SAFETY: attr is NULL and size is 0, as required with this flag; the kernel reads no memory.
let abi = unsafe {
    libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<libc::c_void>(), 0usize, 1u32)
};
// abi >= 1: supported ABI; -1 with errno ENOSYS or EOPNOTSUPP: unavailable
```

`sandy check` already prints the enforcement plan. CI can run it and fail the job when the
plan is not enforceable on a runner that is expected to support Landlock. The escape tests should
not skip silently when Landlock is missing; they should fail unless the job explicitly declares
"no Landlock expected".

The default Docker seccomp profile allows `landlock_create_ruleset`, `landlock_add_rule` and
`landlock_restrict_self` (read in
[default.json](https://github.com/moby/profiles/blob/main/seccomp/default.json)), so the probe
also works in container jobs when the host kernel supports Landlock.

### 6.2 GitHub-hosted runners

Landlock is enabled on both GitHub-hosted Ubuntu runner images. The ABI depends on the host:

- **`ubuntu-22.04`**: kernel 6.8.0 Azure
  ([image README](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2204-Readme.md)).
  The Landlock Rust crate's CI asserts the kernel ABI and passed with ABI 4
  ([job](https://github.com/landlock-lsm/rust-landlock/actions/runs/39645344773/job/119379376903)).
  These images have been deprecated since 2026-09-17
  ([runner-images#14254](https://github.com/actions/runner-images/issues/14254)).
- **`ubuntu-24.04`**: the README lists kernel 6.17.0 Azure, but newer hosts run 7.0. One job
  logged `Linux version 6.17.0-1022-azure` and "Expected Landlock ABI V8 whereas the current ABI is
  V7" ([job](https://github.com/landlock-lsm/rust-landlock/actions/runs/39642108142/job/119368336281)).
  Another job passed with ABI 8
  ([job](https://github.com/landlock-lsm/rust-landlock/actions/runs/39640817459/job/119363601346)).
  The crate then removed these tests because "Not all GitHub servers with Ubuntu 24 are running
  the same kernel" ([commit 037725764c5f](https://github.com/landlock-lsm/rust-landlock/commit/037725764c5f),
  2026-10-21).
- **`ubuntu-26.04`**: kernel 7.0 Azure with Landlock in `CONFIG_LSM`; ABI 8 expected, not observed
  (**unverified**). `ubuntu-latest` moves to 26.04 in November 2026
  ([runner-images#14748](https://github.com/actions/runner-images/issues/14748)).
- User namespaces are restricted on `ubuntu-24.04`
  ([runner-images#10443](https://github.com/actions/runner-images/issues/10443)); a job can lift
  the restriction with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

Consequences for sandy's CI:

- Never hard-code the expected ABI per runner label. Print it, and assert only a minimum.
- No GitHub-hosted runner has ABI 9 or newer, so the `RESOLVE_UNIX` path cannot be tested there.
  A self-hosted runner or a VM job with a Fedora or Arch kernel is needed for it.
- Lower ABIs can be tested on a new kernel: a ruleset that handles only the rights of ABI N
  behaves like ABI N for those rights (this is how the truncation test in section 3.4 was done).
  A test-only setting that caps the ABI sandy uses lets CI cover the ABI 1, 3, 4 and 6 code paths
  on any runner. It does not reproduce other differences of an old kernel (for example missing
  errata fixes), so one job on an old kernel (for example a Debian 12 VM with 6.1) is still
  useful.

## 7. bubblewrap

### 7.1 What it enforces

[bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) builds a sandbox from command
line arguments. The [README](https://github.com/containers/bubblewrap) says it "is not a complete,
ready-made sandbox with a specific security policy". The caller decides everything:

- **Namespaces.** A user namespace (implied when not root), plus optional mount, PID, network,
  IPC, UTS and cgroup namespaces (`--unshare-all` or one by one). `--disable-userns` stops the
  program from creating nested user namespaces.
- **File system view.** An empty root on tmpfs, filled with `--bind`, `--ro-bind`, `--dev-bind`,
  `--tmpfs`, `--proc`, `--dev`, `--symlink` and overlay mounts. Paths that are not mounted do not
  exist in the sandbox.
- **`--unshare-net`.** A new network namespace with only a loopback device. The program has no
  IP network, but it has a private loopback and a private abstract Unix socket namespace.
- **`--new-session`.** Calls `setsid()`, so `TIOCSTI` cannot reach the caller's terminal.
- **`--die-with-parent`.** `PR_SET_PDEATHSIG(SIGKILL)` on the sandboxed process.
- **`no_new_privs`.** bubblewrap always sets it (`bubblewrap.c`).
- **Seccomp.** None built in. The caller passes compiled BPF with `--seccomp FD` or
  `--add-seccomp-fd FD` ([bwrap.xml](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)).
- **Process model.** bubblewrap clones the sandboxed process and stays as a monitor parent. The
  monitor handles only `SIGCHLD`; bubblewrap 0.13.1 contains no code that forwards `SIGTERM` or
  `SIGINT` to the sandboxed program (read in `bubblewrap.c` at tag `v0.13.1`).
- **Setuid mode.** Deprecated in 0.11.2 and removed in
  [0.12.0](https://github.com/containers/bubblewrap/releases/tag/v0.12.0) (2026-08-26).
- **Landlock.** Not used.

Maintenance: active. Releases 0.11.1 (2026-03), 0.11.2 (2026-04), 0.12.0 (2026-08), 0.13.0
(2026-09) and 0.13.1 (2026-10-14); 92 commits in the last 12 months (GitHub API, 2026-10-22).
Flatpak and many desktop components depend on it.

Security record of bubblewrap itself ([NVD](https://nvd.nist.gov/), GitHub advisories):

| CVE | Problem |
|---|---|
| [CVE-2016-8659](https://nvd.nist.gov/vuln/detail/CVE-2016-8659) | Dumpable process allowed privilege escalation (before 0.1.3) |
| [CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226) | `TIOCSTI` escape; led to `--new-session` |
| [CVE-2019-12439](https://nvd.nist.gov/vuln/detail/CVE-2019-12439) | Misuse of `/tmp` mount points (before 0.3.3) |
| [CVE-2020-5291](https://nvd.nist.gov/vuln/detail/CVE-2020-5291) | Root escalation in setuid mode |
| [CVE-2026-41163](https://nvd.nist.gov/vuln/detail/CVE-2026-41163) | Root escalation in setuid mode through ptrace |
| [CVE-2026-87766](https://nvd.nist.gov/vuln/detail/CVE-2026-87766) | Symlinks followed to the host during setup; fixed only in 0.12.0 |

Several other CVEs were caused by programs that called bubblewrap with incomplete arguments, for
example WebKitGTK without `CLONE_NEWUSER` and `TIOCSTI` filters
([CVE-2020-13753](https://nvd.nist.gov/vuln/detail/CVE-2020-13753)) and Flatpak argument injection
([CVE-2024-32462](https://nvd.nist.gov/vuln/detail/CVE-2024-32462)). This matches the README: the
protection depends entirely on the caller.

### 7.2 Where it is blocked or limited

bubblewrap needs unprivileged user namespaces with capabilities inside them. Where that is
restricted:

- **Ubuntu 24.04 and Linux Mint 22.** The apparmor package ships no enabled profile for
  `/usr/bin/bwrap`; `bwrap-userns-restrict` is only in `apparmor-profiles` under
  `/usr/share/apparmor/extra-profiles/`. An update that enabled it broke Flatpak applications and
  was reverted ([LP#2072811](https://bugs.launchpad.net/bugs/2072811)).
  Flatpak works through `profile flatpak /usr/bin/flatpak flags=(unconfined) { userns, }`. A
  direct call of `bwrap` by an unconfined program such as sandy therefore falls under the
  `unprivileged_userns` profile, gets no capabilities in the new namespace, and cannot mount
  (derived from the shipped profiles; not tested on an Ubuntu host).
- **Ubuntu 25.04, 25.10 and 26.04.** `/etc/apparmor.d/bwrap-userns-restrict` is shipped and
  enabled. Read in the 26.04 package (`apparmor 5.0.2-0ubuntu1~26.04.1`): `profile bwrap
  /usr/bin/bwrap` allows `capability`, `userns`, `mount`, `umount` and `pivot_root`. Every program
  that bubblewrap starts runs under `unpriv_bwrap`, which has `audit deny capability`. So
  bubblewrap works, and the sandboxed program has no capabilities, also not in nested namespaces.
  26.04 also ships `glycin.bwrap`.
- **Debian 12 and 13, RHEL 8 to 10, Fedora, Arch `linux`, SUSE.** The defaults do not block it
  (section 2; RHEL and SUSE defaults **unverified**).
- **Arch `linux-hardened`.** Blocked: unprivileged user namespaces are off.
- **Inside containers.** The default Docker profile allows `unshare` and namespace flags of
  `clone` only with `CAP_SYS_ADMIN`
  ([default.json](https://github.com/moby/profiles/blob/main/seccomp/default.json)), so
  bubblewrap fails in a default Docker container. The same profile allows the three Landlock
  system calls. Inside Flatpak, its seccomp filter denies `CLONE_NEWUSER` (section 5.1).
  Podman and Snap: **unverified**.
- **GitHub `ubuntu-24.04` runners.** Restricted, as on Ubuntu 24.04
  ([runner-images#10443](https://github.com/actions/runner-images/issues/10443)).
- **WSL2.** User namespaces are allowed and AppArmor is not the active major LSM, so it should
  work (derived from the kernel config, **unverified** on a running system). **Crostini:**
  **unverified**.

Installed by default:

- Ubuntu desktop: yes (0.6.1 in 22.04.5, 0.9.0 in 24.04.5, 0.11.1 in 26.04.1 ISO manifests),
  because `nautilus`, `xdg-desktop-portal` and `libgnome-desktop` depend on it. Ubuntu server and
  cloud images: no.
- Debian: pulled in by GNOME and Flatpak packages; priority optional, so probably absent on
  servers (**unverified**).
- Fedora Workstation: yes (`flatpak`, `glycin-loaders` and `gnome-desktop3` require it). Fedora
  Server and Cloud: **unverified**.
- Arch base: no. RHEL, SUSE, Mint, Crostini, WSL distributions and GitHub runner images:
  **unverified**.

Versions in the distributions ([Repology API](https://repology.org/project/bubblewrap/versions),
2026-10-22): AlmaLinux and Rocky 8: 0.4.0; 9: 0.6.3; CentOS Stream 10: 0.10.0; Ubuntu 22.04:
0.6.1; 24.04: 0.9.0; 26.04: 0.11.1; Debian 12: 0.8.0; 13: 0.12.0; openSUSE Leap 15.6: 0.8.0 and
0.11.0; Fedora 43 and 44: 0.12.0; Arch: 0.13.1. Only 0.12.0 and newer contain the upstream fix for
CVE-2026-87766. Distribution backports exist for some releases (Debian and Fedora announcements are
linked from the advisory); **unverified** for the others. `--disable-userns` needs 0.8.0, so it is
missing on Ubuntu 22.04 and all RHEL 8 and 9 rebuilds.

### 7.3 Guarantee by guarantee

Entries marked "tested" come from a probe program on the Fedora host with bubblewrap 0.12.0. The
probe ran with no sandbox (control), under `bwrap --unshare-user --ro-bind / /`, under
`bwrap --unshare-all` with only `/usr`, `/proc`, `/dev` and the probe mounted, and under Landlock.
Its targets were a process of the same user outside the sandbox, `~/.ssh`, the session bus and a
test abstract socket. The control run succeeded for every action. "Landlock + seccomp" is the
planned sandy launcher; its seccomp part was not built for this test.

| Guarantee | bubblewrap (`--unshare-all`, minimal binds) | sandy: Landlock + seccomp + `no_new_privs` |
|---|---|---|
| File confinement | Unmounted paths do not exist. Tested: `stat ~/.ssh` gives `ENOENT`. | Access is denied, but the path is visible. Tested: `stat ~/.ssh` succeeds. `chmod`, `utimensat`, `setxattr` on files outside the policy succeed unless seccomp blocks them (section 3.4). |
| Read versus execute | `noexec` on bind mounts | `LANDLOCK_ACCESS_FS_EXECUTE` |
| Pathname Unix sockets | Unreachable unless the socket's directory is mounted. Tested: session bus gives `ENOENT`. | All or nothing with seccomp on kernels before 7.1; per path with `RESOLVE_UNIX` on 7.1 and newer. |
| Abstract Unix sockets | Isolated only with `--unshare-net`, because the abstract namespace belongs to the network namespace. Tested: `ECONNREFUSED` for an abstract socket that exists on the host. With the host network shared, abstract sockets (for example X11) stay reachable. | Seccomp denies all of `AF_UNIX`, or Landlock ABI 6 scoping isolates abstract sockets independent of IP networking. |
| IP networking none | Private network namespace with its own loopback. Socket families that ignore network namespaces are not covered. `AF_VSOCK` namespace support was merged in January 2026 only for vhost-vsock and loopback, not for the guest transports (virtio, Hyper-V, VMCI) ([patch series](https://lkml.iu.edu/2601.2/10207.html)). So inside a VM guest such as WSL2, a cloud VM or Crostini, a bubblewrap sandbox without a seccomp filter can probably still reach host services over `AF_VSOCK` (**unverified**, not tested). | Seccomp family allowlist. No loopback at all, also not inside the sandbox. `AF_VSOCK` is denied. |
| IP networking all | Shares the host network namespace | Allows `AF_INET`, `AF_INET6`, `AF_NETLINK` |
| Signals | PID namespace: outside processes are invisible. Tested: `kill` gives `ESRCH`. | Landlock ABI 6 scoping. Tested: `EPERM`. Needs Linux 6.12 or a backport (RHEL 9.7). |
| Process visibility and `/proc` | New procfs shows only the sandbox's processes | Landlock cannot allow "own `/proc/self`" for each process: tested, a rule on `/proc/self` works for the process that created it but its child gets `EACCES`. So the system set must allow all of `/proc` or none of it. With `/proc` allowed, tested: `/proc/<pid>/cmdline` and `status` of an outside process are readable (command line secrets leak); `environ` is denied. |
| ptrace, `/proc/<pid>/mem`, `process_vm_readv` | Outside processes are invisible with a PID namespace. Tested without a PID namespace: denied, because the program is in a child user namespace (`cap_ptrace_access_check` in [commoncap.c](https://github.com/torvalds/linux/blob/v7.3/security/commoncap.c)). | Denied by Landlock scoping (section 3.3), plus seccomp |
| Terminal injection | `--new-session` (breaks terminal job control signals) | Seccomp `ioctl` filter, terminal stays usable |
| Kernel attack surface | Larger: the program runs in a user namespace and can create nested ones unless `--disable-userns` or a caller-supplied filter stops it. No io_uring, `keyctl` or `bpf` filtering by default. | Smaller: seccomp denies namespaces, io_uring, `keyctl`, `bpf` and more (section 5.5) |
| Process model | Monitor parent; the program gets another PID; signals to the monitor are not forwarded | `execve` in place; same PID, signals and exit status |
| Kernel coverage | Any kernel with unprivileged user namespaces | Landlock (5.13+, enabled at boot); features grow with the ABI |

### 7.4 Recommendation

Options:

- **(a) sandy runs the system `bwrap` when present.** Rejected. The guarantees would depend on
  whether `bwrap` is installed and on its version (0.4.0 to 0.13.1 across the matrix). Under the
  fail-closed rule, any guarantee that only `bwrap` provides would make sandy refuse on every host
  without it. Landlock cannot be applied before `bwrap`, because a Landlock domain forbids the
  `mount` calls that `bwrap` needs. Tested: bubblewrap 0.12.0 started inside a Landlock domain
  that allows every file access fails with "Failed to make / slave: Operation not permitted".
  sandy would need a second stage inside the sandbox to add Landlock and seccomp. The monitor
  process breaks the `execve` process model and does not forward signals. It also adds a
  dependency on an external binary with its own CVE history.
- **(b) sandy implements its own namespace layer in Rust.** Not for v1. It is a large,
  security-sensitive component (see the setup symlink CVE). It works only where unprivileged user
  namespaces work. That excludes default Docker containers and Ubuntu 24.04 and newer, unless
  `sandy setup` installs an AppArmor profile with `userns,` for the sandy binary (allowed host
  preparation, but it widens what sandy itself may do). As a fallback it would reach the hosts
  without Landlock (RHEL 8, RHEL 9.0 to 9.5, SLES 15), because they allow user namespaces by
  default. Section 4.4 explains why that small set does not justify it in v1. As an extra layer
  on top of Landlock, it is the right tool for a later "hide paths" policy option.
- **(c) Landlock + seccomp only.** Recommended for v1. It has one semantics on every host, works
  without user namespaces (Ubuntu 24.04+, containers with the default Docker profile, hardened
  hosts), keeps the `execve` process model, and keeps the kernel attack surface small.

Where sandy (option c) is weaker than a well-configured bubblewrap:

- Paths outside the policy are visible (`stat`, existence, size, times).
- Metadata changes outside the policy need extra seccomp rules (section 3.4).
- `/proc` is all or nothing; with `/proc` allowed, command lines of the user's other processes
  leak.
- No private loopback network when `ip = "none"`.
- Signal isolation needs Landlock ABI 6 (Linux 6.12).
- Per-path Unix socket rules need Linux 7.1.
- Programs that start their own namespace sandbox (for example a library that runs image
  decoders through `bwrap`) fail inside sandy, because both the seccomp rules and the Landlock
  domain forbid namespaces and mounts. They must use their non-sandboxed fallback, if they have
  one. bubblewrap with a caller-supplied filter has the same conflict for nested user namespaces.

Where sandy is stronger:

- Works where user namespaces are blocked.
- Smaller kernel attack surface, because no user namespace is created and the seccomp filter is
  built in, not optional.
- Abstract Unix sockets can be isolated while IP networking stays on (ABI 6, or seccomp).
- `TIOCSTI` blocked without `setsid()`, so interactive programs keep terminal signals.
- Same process, same PID, signals and exit status pass through.

A later sandy version could add an optional policy setting such as "hide paths outside the
policy" that requires a namespace layer and makes sandy refuse when user namespaces are not
available. That keeps the fail-closed rule, because the extra requirement exists only when the
policy asks for it.

## Recommendations for sandy v1

1. Keep the planned design: `no_new_privs`, Landlock and seccomp applied by sandy to itself, then
   `execve`. Do not use `LD_PRELOAD`, ptrace, the system `bwrap` or a namespace layer in v1
   (sections 1, 4 and 7).
2. Refuse to run when Landlock is unavailable (RHEL 8, RHEL 9.0 to 9.5, SLES 15, Leap 15.6).
   `sandy check` should name the fix: update to RHEL 9.6 or newer, or add `landlock` to the `lsm=`
   boot parameter on SLES 15.
3. Read the Landlock ABI from the kernel at run time; never infer it from the kernel version.
   Accept ABI 1 and newer. Below ABI 3, add seccomp rules against truncation (section 3.4) so
   that Ubuntu 22.04 GA and Debian 12 are covered. Require ABI 6 only when
   `signals = "isolated"`.
4. Keep the seccomp rule on `socket(AF_UNIX)` for `unix_sockets = "none"`; no LTS kernel has
   `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (Linux 7.1). Also handle that right and the ABI 6 scopes when
   the kernel has them, as a second layer. Update rule 7 of `DESIGN.md`.
5. Build the seccomp filter as two stacked filters: an allowlist of reviewed system calls for
   the native arch (other arches killed, unknown numbers and x32 get `ENOSYS`), and a denylist
   with argument checks that returns `EPERM` (section 5.5). x32 is reachable on Ubuntu 22.04 GA,
   Arch and WSL2.
6. Allow socket families by list, never deny them by list (`AF_SMC` reaches TCP). Deny io_uring,
   namespaces (`clone3` gets `ENOSYS`), `keyctl`, `bpf`, `userfaultfd` and `TIOCSTI`/`TIOCLINUX`
   (32-bit compare).
7. Close the Landlock metadata gap: by default deny the path-based `chmod`, `chown`, `utime` and
   `xattr` calls and `fchmodat`, `fchmodat2`, `fchownat` completely (section 3.4, option a), and
   measure which programs break. This needs a decision by the project owner.
8. Decide the `/proc` entry of the `minimal` system set explicitly. Landlock cannot grant each
   process its own `/proc/self`. Allowing `/proc` exposes other processes' command lines, which
   other local users can usually read too; `environ` and `mem` stay protected.
9. Refuse to run as uid 0 or with any capability, because `no_new_privs` does not remove
   existing privileges. Apply Landlock and seccomp while single-threaded, and mark inherited
   descriptors close-on-exec with `close_range`.
10. Use `seccompiler` with `libc::SYS_*` numbers. In CI, print the ABI and assert a minimum, test
    lower ABIs by capping the handled rights, add a job with a 7.1 or newer kernel for
    `RESOLVE_UNIX`, and assert `NoNewPrivs: 1` and `Seccomp: 2` inside the sandbox.
