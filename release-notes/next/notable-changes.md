# sandy (next release) Notable Changes

Draft for the release after 1.1.0. It lists what a user or an integrator may notice; the full release notes follow the structure of the earlier ones when the version is tagged.

## Policies that may now be refused or behave differently

- **macOS:** a program can no longer create symbolic links, named pipes or devices in its writable paths, as on Linux, and a clone of a directory into a writable path fails with `EPERM`. Tools that make links there, such as npm and pnpm `.bin` links, `python3 -m venv`, Emacs lock files and git checkouts with links, need `filesystem.symlinks = "allow"` (`--symlinks allow`). Named pipes and devices stay refused.
- **Every platform:** a writable path over `GNUPGHOME`, `GIT_CONFIG_GLOBAL` or `GIT_CONFIG_SYSTEM`, when they are set, is refused like one over the default GnuPG and git configuration.
- **Windows:** a writable path over the git and GnuPG configuration is refused, as on Linux and macOS: `.gitconfig`, `.config\git`, `XDG_CONFIG_HOME\git`, `.gnupg`, `%APPDATA%\gnupg`, `Git` below `%PROGRAMDATA%`, also below `HOME` and `HOMEDRIVE`+`HOMEPATH`.
- **Windows:** a `read_exec` path or program file that the AppContainer may write is a conflict.
- **Windows:** the root of a `read_write` path can no longer be deleted or moved by the program, and a `read_write` file can no longer be deleted. Grants of earlier versions are replaced at the next run.
- **Linux:** with `filesystem.view = "policy"`, the program starts in its `--cwd` outside the policy instead of `/`, and a working directory on an ungranted `/proc` refuses the run.
- **Linux:** the egress broker looks up the route of a destination with TCP, the destination port and its own user, as its connect does, so an address that a policy routing rule sends to the local table only for TCP or for one port is refused as this host (reply 2) where it was allowed before.
- **Linux:** `--explain` writes its report from a queue; lines that standard error does not take in time are dropped and counted in a line of the report.

## Policies that are no longer refused

- **Every platform:** a hard link that gives a `read_exec` file or the program a second name inside a writable path is no longer refused, and sandy no longer walks the writable trees at each start to find one, unless sandy's own executable or the policy file has more than one name. Which trees a policy makes executable is its author's choice: such a link comes from the host or from an earlier run that could write both names. A second name of sandy's own executable or of the policy file is still refused.
- **Windows:** a junction or symbolic link below a policy path, and a file below with permission entries of its own, no longer stop a run, and sandy no longer walks the tree below a path before it grants it. The grant does not follow a link (measured), so the program reaches nothing through one.

## New

- `filesystem.symlinks = "deny" | "allow"` (`--symlinks`), default `deny`, with the warning `symlinks-followed-outside`.

## Integration Requirements

- **Windows:** the status record writes the exit code unsigned, for example `exited 3221225786` for `0xC000013A`; a reader that parses it as a signed 32-bit number must accept the larger value.
- **Windows:** `check` refuses a `--parent-pid` that is not sandy's parent or has ended, and a `.bat` or `.cmd` program, as `run` does. A run whose relay or egress broker ends while the program runs now exits with 125 with any policy.
- **Windows:** the egress port serves up to 1000 connections at a time, as on Linux and macOS.
- A refusal before sandy chooses a level writes no `level` line to the status record, and `check --json` prints nothing on standard output for it.
- Policies keep the format `version = 1`; `filesystem.symlinks` is not a key of a fallback level.
