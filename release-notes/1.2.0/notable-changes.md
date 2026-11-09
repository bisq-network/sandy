# sandy 1.2.0 Notable Changes

Based on the 47 commits of `main` after `v1.1.0` up to `3166628`. See the [full release notes](full-release-notes.md) for integration notes and known issues.

## Policies That May Now Be Refused or Behave Differently

- **macOS:** a program can no longer create symbolic links, named pipes or devices in its writable paths, as on Linux, and a clone of a directory into a writable path fails with `EPERM`. Tools that make links there, such as npm and pnpm `.bin` links, `python3 -m venv`, Emacs lock files and git checkouts with links, need `filesystem.symlinks = "allow"` (`--symlinks allow`). Named pipes and devices stay refused.
- **Every platform:** a writable path over `GNUPGHOME` or `GIT_CONFIG_GLOBAL`, when they are set, is refused like one over the default GnuPG and git configuration.
- **Windows:** a writable path over the git and GnuPG configuration is refused, as on Linux and macOS: `.gitconfig`, `.config\git`, `XDG_CONFIG_HOME\git`, `.gnupg`, `%APPDATA%\gnupg`, `Git` below `%PROGRAMDATA%`, also below `HOME` and `HOMEDRIVE`+`HOMEPATH`.
- **Windows:** a `read_exec` path or program file that the AppContainer may write is a conflict.
- **Windows:** the program can no longer delete, rename or move a `read_write` path itself, as on Linux and macOS: the directory or file that the policy names stays in place, while everything below a directory stays fully writable. A tool that saves a file by renaming a new copy over it fails on a file that the policy names directly, as it already did on Linux and macOS; grant the directory instead. Grants of earlier versions are replaced at the next run.
- **Linux:** with `filesystem.view = "policy"`, the program starts in its `--cwd` outside the policy instead of `/`, and a working directory on an ungranted `/proc` refuses the run.
- **Linux:** the egress broker looks up the route of a destination with TCP, the destination port and its own user, as its connect does, so an address that a policy routing rule sends to the local table only for TCP or for one port is refused as this host (reply 2) where it was allowed before.
- **Linux:** `--explain` writes its report from a queue; lines that standard error does not take in time are dropped and counted in a line of the report.

## Policies That Are No Longer Refused

- **Every platform:** a hard link that gives a `read_exec` file or the program a second name inside a writable path is no longer refused. Which trees a policy makes executable is its author's choice: such a link comes from the host or from an earlier run that could write both names. A second name of sandy's own executable or of the policy file is still refused.
- **Windows:** a junction or symbolic link below a policy path, and a file below with permission entries of its own, no longer stop a run. The grant does not follow a link, so the program reaches nothing through one.

## New

- `filesystem.symlinks = "deny" | "allow"` (`--symlinks`), default `deny`, with the warning `symlinks-followed-outside`.
- `--explain` names the connections the egress broker refuses or cannot make, on Linux, macOS and Windows, for a policy with `network.egress`.

## Fixes

- **Windows:** the egress broker treats an adapter without a link layer (`NdisMediumIP`), such as Wintun for WireGuard and many VPN and proxy TUN modes, as a tunnel. A TUN client that splits the default route no longer makes every public IPv4 address local under `reach = "public"`.
- **Windows:** a reset of a forwarded, exposed or egress connection always reaches the other end; a reset that arrived as the relay's read timed out could be lost before.
- **Windows:** a run ends cleanly when a relay or the egress broker ends before the program, and sandy changes the machine's loopback exemptions one process at a time and checks the result.
- **Linux:** with `children = "contained"`, `--explain` now prints its last lines when the program cannot start.
- **Linux:** a program can list a granted bind mount of an eCryptfs subdirectory, where 1.1.0 left it unlisted with the `ecryptfs-unlisted` warning, when the mount of the whole eCryptfs file system is visible or the mount does not encrypt names.

## Performance

- sandy no longer walks the trees below policy paths at each start, except to look for a second name of its own executable or the policy file, and that search stays on the file systems of those two files.
- The egress broker keeps the host's addresses and networks until the system reports a change, instead of reading them for every connection.

## Integration Requirements

- **Windows:** the status record writes the exit code unsigned, for example `exited 3221225786` for `0xC000013A`; a reader that parses it as a signed 32-bit number must accept the larger value.
- **Windows:** `check` refuses a `--parent-pid` that is not sandy's parent or has ended, and a `.bat` or `.cmd` program, as `run` does. A run whose relay or egress broker ends while the program runs now exits with 125 with any policy.
- **Windows:** the egress port serves up to 1000 connections at a time, as on Linux and macOS.
- A refusal before sandy chooses a level writes no `level` line to the status record, and `check --json` prints nothing on standard output for it.
- `--explain` on macOS and Windows, which name no denied paths, is accepted for a policy with `network.egress` and refused for one without it ("--explain is not available here").
- A policy that sets `filesystem.symlinks`, or a command line with `--symlinks`, needs 1.2.0. Policies keep the format `version = 1`; `filesystem.symlinks` is not a key of a fallback level.
