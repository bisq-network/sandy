# sandy 1.2.0 Release Notes

sandy 1.2.0 aligns what a policy allows across Linux, macOS and Windows, adds `filesystem.symlinks` for tools that need symbolic links in writable paths, lets the egress broker explain its refusals with `--explain` on every platform, fixes the egress broker behind WireGuard and other TUN adapters on Windows, and stops walking the trees below policy paths at each start.

## Scope

These notes describe the release `v1.2.0` of `bisq-network/sandy`. They cover the 47 commits of `main` after `v1.1.0` (`f0d4765`) up to `3166628`, merged in #22 to #26 and #28, plus the commit that sets the version to 1.2.0. The commit of the tag is given with the published release. `Cargo.toml` declares version `1.2.0`, and policies keep the format `version = 1`. The notes were checked against the README, the platform documents and the commit messages. The tree of `3166628` passed CI on every runner (Ubuntu 22.04 and 24.04, Ubuntu 24.04 on arm64, macOS 15, Windows Server 2022 and 2025), and the work merged in #23 and #24 also passed the suites on Linux 7.2, macOS 27.0.1 and Windows 11 build 26200, and on Windows 10 build 19044 apart from one test that needs a network of the Private category.

## Upgrade and Integration Notes

- **Policies:** most policies of 1.1.0 work unchanged, but some are now refused, mostly on macOS and Windows, where a program could do what Linux already refused. Run `sandy check` with each policy before upgrading; the refusals are listed under "Policies That May Now Be Refused" below. A policy that sets the new key `filesystem.symlinks`, or a command line with `--symlinks`, needs 1.2.0, because 1.1.0 refuses unknown keys and options.
- **macOS links in writable paths:** a program can no longer create symbolic links there by default. A policy for npm, pnpm, `python3 -m venv` or a git checkout with links sets `filesystem.symlinks = "allow"`.
- **Windows status record:** the exit code is written unsigned, `exited 3221225786` instead of `exited -1073741510` for `0xC000013A`. A reader that parses it as a signed 32-bit number must accept the larger value. sandy's own exit code keeps the same 32 bits.
- **Windows `check`:** `check` now refuses with status 125 what `run` refuses about the program and the parent: a `.bat` or `.cmd` program, and with `end_with_parent` a `--parent-pid` that is not sandy's parent or has ended.
- **Windows helpers:** a run whose relay or egress broker ends while the program runs now ends the program and exits with 125, with any policy, as on Linux and macOS.
- **Status record and `check --json`:** a refusal before sandy chooses a level writes no `level` line, and `check --json` prints nothing on standard output for it.
- **`--explain`:** on macOS and Windows, which name no denied paths, `--explain` is accepted for a policy with `network.egress` and refused for one without it ("--explain is not available here"). On Linux it is accepted as before.

## Notable Changes

### Policies That May Now Be Refused

- **macOS:** the profile denies creating symbolic links, named pipes and devices in writable paths, as Landlock does on Linux. A rename, swap or clone of an existing link or named pipe also creates one and fails with `EPERM`; deleting one still works. `clonefile(2)` of a directory into a writable path is denied, because Seatbelt checks only the directory it creates and the clone brought links and named pipes along (measured on macOS 27.0.1); `cp -R`, `cp -cR` and `ditto` copy entry by entry and keep working.
- **Every platform:** a writable path over the directory `GNUPGHOME` names or the file `GIT_CONFIG_GLOBAL` names, when set, is refused like one over the default GnuPG and git configuration. A variable that names a device or a named pipe, such as `GIT_CONFIG_GLOBAL=/dev/null`, protects the directory it lies in as an entry instead. A refusal names the variable.
- **Windows:** a writable path over the git and GnuPG configuration is refused: `.gitconfig`, `.config\git`, `XDG_CONFIG_HOME\git`, `.gnupg` and `%APPDATA%\gnupg` below each profile folder and below `HOME`, `Git` below `%PROGRAMDATA%` (libgit2 reads a configuration there that the user owns), and `.gitconfig` below `HOMEDRIVE`+`HOMEPATH`.
- **Windows:** a `read_exec` path or the program file that the AppContainer may write is a conflict. Windows always lets the AppContainer write its profile folder, so a program there could copy itself into an executable path and start the copy (measured on Windows 11 build 26200).
- **Windows:** grant checks ignore deny entries for the AppContainer, its capabilities and the two package groups, as the AppContainer side of the access check does (measured). A DACL that denies a right before it allows it to one of them now counts as granting it, so a path that only such a deny entry kept apart is refused where 1.1.0 passed it.
- **Windows:** the program can no longer delete, rename or move a `read_write` path itself, the directory or file that the policy names, as on Linux, where removing an entry is a right on its parent, and on macOS, whose profile denies it. The grant gave `DELETE` on the path, so the program could remove an empty writable directory and move a writable directory or file into another writable path (measured on Windows 11 build 26200). The path itself now lacks `DELETE`, and an inherit-only entry gives it to everything below, which stays fully writable. A tool that saves a file by renaming a new copy over it fails on a file that the policy names directly, as it already did on Linux and macOS; grant the directory instead. A grant of an earlier version is replaced at the next run.
- **Linux:** with `filesystem.view = "policy"`, a working directory that no policy path holds is in the view as an empty directory, so the program starts there instead of `/`, cannot list it, and a relative path finds nothing. A working directory on an ungranted `/proc` refuses the run.
- **Linux:** the egress broker looks up the route of a destination with TCP, the destination port, its own user and mark 0, as its connect does (kernel 4.17 and newer). An address that a policy routing rule sends to the local table only for TCP or for one port is now refused as this host (reply 2).

### Policies That Are No Longer Refused

- **Every platform:** a hard link that gives a `read_exec` file or the program a second name inside a writable path is no longer refused. Such a link comes from the host or from an earlier run that could write both names, and which trees a policy makes executable is its author's choice. sandy still refuses a second name of its own executable or of the policy file inside a writable path, which a program could use to change what the next start runs. Windows lists the names of a file (`FindFirstFileNameW`); Linux and macOS walk the writable trees only when one of the two files has more than one name, and only on the file systems of those files.
- **Windows:** a junction or symbolic link below a policy path, and a file below it with permission entries of its own, no longer stop a run, and sandy no longer walks the tree below a path before it grants it. The grant does not follow a link below the path (tested on Windows 10 build 19044 and Windows 11 build 26200), so the program reaches nothing through one. Permission entries that other software put below a policy path stay the host's.

### New

- **`filesystem.symlinks = "deny" | "allow"`** (`--symlinks deny|allow`), default `deny`. With `allow`, Linux grants Landlock's right to make symbolic links on `read_write` paths, and the macOS profile leaves symbolic links out of its create rule. Named pipes, devices and directory clones stay denied. Windows refuses an AppContainer every symbolic link, so the setting changes nothing there. The warning `symlinks-followed-outside` says that a process outside the sandbox may follow a link the program left. A fallback level cannot set the key.
- **`--explain` for the egress broker** on Linux, macOS and Windows: one line for each connection the broker refuses or cannot make, with the destination, the SOCKS5 reply, the reason (with the subnet that makes an address the local network) and whether `reach = "public-and-local"` would allow it. Each distinct line appears once, at most 1000 in a run. On Windows the relay in front of the broker also names a connection it closes because 1000 are open.

### Fixes

- **Windows, egress broker behind a VPN:** Wintun, the adapter of WireGuard and of the TUN mode of many VPNs and proxies, declares a virtual adapter with broadcast access, so the broker took its on-link routes for the local network. A TUN client that splits the default route into `0.0.0.0/1` and `128.0.0.0/1` then made every public IPv4 address local, and under `reach = "public"` the broker refused all of them with reply 2. An adapter without a link layer (`NdisMediumIP`) now counts as a tunnel; the prefix of its own address stays the local network.
- **Windows, helpers that end:** sandy waits for the relays and the broker next to the program, and a helper that ends first ends the program with status 125 instead of leaving its ports free for any local process. A helper that ends before the program starts stops the start before the program's first instruction and names the helper.
- **Windows, resets across the relay:** a connection through the relay, forwarded, exposed or to the egress broker, could stay open after one end reset it. The relay waited for data with a read under a receive timeout, and Windows leaves a socket whose receive timed out in an indeterminate state: a reset that arrived as the timeout ran out could be lost, on an AF_UNIX hop for good (measured on Windows 11 build 26200). The relay now waits with `WSAPoll` and reads only once data, an end or an error is there, so the reset always reaches the other end. It costs one more system call per read on Windows; Linux and macOS are unchanged.
- **Windows, egress port:** the relay serves the egress port with the broker's limit of 1000 connections, as on Linux and macOS, instead of 256.
- **Windows, egress broker start:** the broker reports ready like the relay, so a broker that cannot start stops the run with its own error and status 125, and the program never runs.
- **Windows, loopback exemptions:** Windows keeps one exemption list for the machine and replaces it whole. sandy processes of a user now change it one at a time and read it back after the write, repeating until the change is there.
- **Linux, `--explain`:** the report is written from a queue on a thread of its own, so a standard error that nobody reads no longer holds up the program's watched calls and the end of sandy. Lines that do not fit are dropped and counted. With `children = "contained"`, the last lines are now written also when the program cannot start.
- **Linux, eCryptfs bind mounts:** a program can now list a granted bind mount of an eCryptfs subdirectory, such as a folder of an encrypted home bound elsewhere. sandy finds its lower directory through the mount of the whole eCryptfs file system, by inode, or, without name encryption, by its names, and grants it only when it lies on the lower file system and has the inode of the bind's point.
- **macOS:** listing the mount points for the second-name search no longer resolves the path of a network mount, which could wait on a server that does not answer.

### Performance

- No walk of the trees below policy paths at each start, except the search for a second name of sandy's own executable or the policy file described above. The mount table is read once per mount namespace.
- The egress broker keeps the host's addresses and networks until the system reports a change: a netlink socket on Linux, a routing socket on macOS (which caches only the routing table, because macOS sends no message for some address changes) and change notifications on Windows. The route of a connect is still looked up for each connection. Where a broker cannot watch for changes, it reads everything for every connection, as before.

### Platforms

Unchanged from 1.1.0: Linux 5.13 or newer with Landlock, macOS with native code only (tested on macOS 15 and 27, arm64), Windows 10 1809 or newer and Windows Server 2019 or newer. The release has archives for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`, listed in `SHA256SUMS`, which `SHA256SUMS.asc` signs with the release key.

Details: [README.md](../../README.md), [docs/DESIGN.md](../../docs/DESIGN.md), [docs/linux.md](../../docs/linux.md), [docs/macos.md](../../docs/macos.md) and [docs/windows.md](../../docs/windows.md).

## Known Issues

- On Windows, sandy reads and writes a DACL in two calls with nothing to compare and swap, so a change which `icacls` or another program makes to the same junction or policy path between the two is lost. sandy's lock serializes only its own runs.
- On Windows, a tool outside sandy that writes the loopback exemption list from an older read, after sandy has read it back, can still take sandy's change back.
- On Windows, the egress broker sees a change of the network once Windows reports it; a connection made in between still sees the old networks.
- On Linux and macOS, the second-name search treats a mount that a later mount over one of its parents covers as still present.
- On Linux, a granted directory on eCryptfs whose lower directory sandy does not find still cannot be listed; `check` names it in the `ecryptfs-unlisted` warning. That is a bind mount of an eCryptfs subdirectory with encrypted names whose whole eCryptfs mount the mount namespace does not see, as in a container that sees only the bind, and a lower file system that reports no ID.
- On Linux, `/proc` is not readable by default, and GNU tar cannot extract an archive which holds a directory in the sandbox; `bsdtar` can.
- On Windows, `view = "policy"` is refused, because Windows cannot hide paths from an AppContainer.
- What stays visible from inside the sandbox differs by platform. Each platform document lists these limitations.
