# sandy

sandy runs a program inside the sandbox of the operating system. A small policy says which paths
the program may read, execute or write, whether it may use the network, and which environment
variables it gets. Everything else is denied. The same policy works on Linux, macOS and Windows.

sandy fails closed. If the host cannot enforce every restriction of the policy, sandy does not
start the program and says why.

```sh
sandy run \
  --read /srv/app/share \
  --read-exec /srv/app/bin \
  --read-write /srv/app/data \
  --ip all \
  -- /srv/app/bin/server --port 8080
```

Version 2.4.0. Policies use format `version = 1`.

## Contents

- [When to use sandy](#when-to-use-sandy)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Commands](#commands)
- [Policy reference](#policy-reference)
- [Platform notes](#platform-notes)
- [Using sandy from another program](#using-sandy-from-another-program)
- [Security model](#security-model)
- [Building and testing](#building-and-testing)
- [Documentation](#documentation)
- [License](#license)

## When to use sandy

Use sandy for a program that handles untrusted input and might be compromised, for example a
network daemon, a file converter or a parser. If an attacker takes over the program, sandy keeps
the attacker away from the user's other files, from other processes and from the network, as far
as the policy says.

sandy is not a container. There is no separate root file system, no image and no daemon. The
program sees the normal file system, but it can open only what the policy allows.

## How it works

| Platform | Mechanism |
|---|---|
| Linux | Landlock (file access, TCP and UDP ports, scopes), up to four seccomp-bpf filters, `no_new_privs`, closing inherited descriptors, then `execve` |
| macOS | A Seatbelt profile generated from the policy, applied with `sandbox_init_with_parameters`, then `execve` |
| Windows | An AppContainer with one capability per policy path, a job object with UI restrictions, and a list of inherited handles |

On Linux and macOS, sandy confines itself and then replaces itself with the program, so the
program keeps sandy's process ID; with `children = "contained"` sandy stays the program's parent
instead (see [Processes](#processes)). On Windows, sandy starts the program and waits for it; when
sandy exits, the job object ends the program.

For every policy, sandy derives a list of requirements, for example "filesystem confined to policy
paths" or "IP networking denied". The platform backend reports for each requirement how it
enforces it on this host, or why it cannot. `sandy check` prints that list. `sandy run` starts the
program only when every requirement is enforced.

## Install

There are no published packages yet. Build sandy from source:

```sh
git clone <repository> sandy
cd sandy
cargo build --release -p sandy-cli --bin sandy
```

The binary is `target/release/sandy` (`sandy.exe` on Windows). It has no runtime dependencies
besides the operating system. The pinned Rust toolchain in `rust-toolchain.toml` installs itself
through rustup.

For a fully static Linux binary:

```sh
cargo build --release --target x86_64-unknown-linux-musl -p sandy-cli --bin sandy
```

Release archives for each platform are built with `scripts/release-build.sh`, by the `release`
workflow or by hand (see [Building and testing](#building-and-testing) and below). The sizes of
the 2.2.1 release:

| Target | Binary | Archive |
|---|---|---|
| `x86_64-unknown-linux-musl` (static PIE) | 1.6 MiB | 806 KiB |
| `aarch64-unknown-linux-musl` (static, not position-independent) | 1.3 MiB | 744 KiB |
| `aarch64-apple-darwin` | 963 KiB | 503 KiB |
| `x86_64-apple-darwin` | 1.1 MiB | 563 KiB |
| `x86_64-pc-windows-msvc` (static C runtime) | 1.2 MiB | 563 KiB |
| `aarch64-pc-windows-msvc` (built, not tested) | 1015 KiB | 514 KiB |

**Verifying a download.** `SHA256SUMS` in the release lists the SHA-256 sum of every archive,
and `SHA256SUMS.asc` signs it with the project's OpenPGP key, the key that also signs the release
tags (fingerprint `E850 152C 47E1 3655 DDF3  A62B 4CE3 8D03 67B5 3CC5`):

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

An archive that the release workflow built also carries a GitHub build provenance attestation,
which names the workflow, the commit and the run that built it
(`gh attestation verify sandy-2.4.0-x86_64-unknown-linux-musl.tar.gz --repo <owner>/sandy`). The
archives of 2.2.1 to 2.4.0 were built outside the workflow, so they have none.

**Building a release binary again.** Every release binary is built with
`scripts/release-build.sh TARGET` from a checkout of the release tag, so anyone can build it again
and compare it with the binary in the archive:

```sh
git checkout v2.4.0
scripts/release-build.sh x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/sandy
```

The script removes from the binary what would tie it to the machine that built it: the directory
of the checkout and of `CARGO_HOME`, and the time of the build. The Linux binaries are linked with
the linker of the Rust toolchain, so they depend only on the source and on the toolchain that
`rust-toolchain.toml` pins. The macOS and Windows binaries also depend on the version of Apple's
linker and of the Microsoft linker, which the release notes name. The script refuses a toolchain
that rustup did not install from the pinned archives (see "The supply chain checks" below). The
`reproducible` job of the release workflow builds every target twice, in two directories, and
compares the binaries.

The macOS binaries are not signed or notarized, and `sandy.exe` has no Authenticode signature.
macOS refuses a copy that a browser downloaded, because it is not notarized, and SmartScreen
warns about a freshly downloaded `sandy.exe`. A program that ships sandy inside a signed macOS
app signs it together with the app.

**Where to install sandy.** Put the `sandy` binary, and your policy files, where the sandboxed
program cannot write: not inside any `read_write` path of any policy. A compromised program
could otherwise replace sandy or its policy, and the next start would run without a sandbox.
sandy checks this at every start and refuses the policy, but only for the binary and the policy
file it is using, so the rule stays yours to keep.

## Quick start

See how this host enforces the default policy:

```console
$ sandy check
backend: linux
enforced     filesystem confined to policy paths: Landlock ABI 9; ...
enforced     no privilege escalation: no_new_privs; seccomp denies namespaces, mounts ...
enforced     other processes cannot be debugged or read: Landlock ptrace scope; ...
enforced     only standard input, output and error inherited: close-on-exec on every descriptor above 2 ...
enforced     environment limited to policy: execve with only the policy environment
enforced     IP networking denied: seccomp socket family allowlist ...
enforced     Unix sockets outside writable paths denied: seccomp denies AF_UNIX sockets ...
enforced     metadata of files outside policy paths protected: seccomp denies chmod, chown ...
warning: signals = "any" lets the program signal every process of this user ...
```

Warnings go to standard error, requirements to standard output. Every default policy warns
about `signals = "any"`, which lets the program signal processes outside the sandbox.

Run a program that may read one directory and write another, without network:

```console
$ mkdir -p ~/demo/in ~/demo/out ~/demo/secret
$ echo hello > ~/demo/in/a.txt
$ echo secret > ~/demo/secret/key

$ sandy run --read ~/demo/in --read-write ~/demo/out -- /usr/bin/cp ~/demo/in/a.txt ~/demo/out/
$ cat ~/demo/out/a.txt
hello

$ sandy run --read ~/demo/in -- /usr/bin/cat ~/demo/secret/key
cat: /home/user/demo/secret/key: Permission denied
```

The program path must be absolute. Paths in the policy must be absolute and must exist. The shell
expands `~`, so the examples pass absolute paths.

## Examples

The examples use Linux paths. On macOS and Windows the options are the same; only the paths of
the programs differ. On Windows, every run also needs `--appcontainer NAME` (see
[Windows](#windows)).

### A file converter without network

The converter may read its input directory and write its output directory. It may not use the
network and gets no environment variables except the ones passed.

```sh
sandy run \
  --read /srv/convert/inbox \
  --read-write /srv/convert/outbox \
  --pass-env LANG \
  -- /usr/bin/convert-tool --in /srv/convert/inbox --out /srv/convert/outbox
```

### A network client

`--ip client` lets the program connect out over IPv4 and IPv6 and resolve names, but not listen
for or accept connections, so a compromised client cannot open a port for others. On Linux it
also adds the files for name resolution and the CA certificates to the system set.

```console
$ sandy run -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://example.org
curl: (6) Could not resolve host: example.org
000
$ sandy run --ip client -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://example.org
200
```

With `--ip client` or `--ip all` the program can connect to any address; sandy does not filter
destinations. `--ip all` also lets it listen. On Linux and macOS a UDP socket that is not
connected still receives datagrams from every sender under `--ip client`, and on Windows the
program reaches no host of a network that Windows counts as a private network (see
[Network](#network)).

### A local server that others connect to

A server in the sandbox listens on a loopback port. `--expose ADDRESS=PORT` makes it reachable from
outside the sandbox: sandy listens on `ADDRESS` and relays every connection to the program's
loopback `PORT`.

```console
$ mkdir -p ~/site && echo '<h1>hi</h1>' > ~/site/index.html
$ sandy run \
    --read ~/site --read /etc/mime.types --cwd ~/site \
    --ip all --expose 127.0.0.1:18000=8000 \
    -- /usr/bin/python3 -m http.server 8000 --bind 127.0.0.1 &
$ curl -s http://127.0.0.1:18000/index.html
<h1>hi</h1>
```

Clients use the outer port (18000). On Linux and macOS the inner port (8000) is also reachable
directly, but on Windows it never is: Windows blocks every inbound loopback connection into an
AppContainer. Always use the exposed port, so the setup works the same on every platform.

The relay ends when the program ends. On Linux and macOS it runs as a separate process with its
own sandbox and no file access; on Windows it runs in the program's AppContainer.

This example also shows a typical first problem: Python's web server reads `/etc/mime.types`,
which is not in the minimal system set. Without `--read /etc/mime.types`, each request fails with
`PermissionError`. When a program fails inside the sandbox, look for "Permission denied" (Linux),
"No such file or directory" and the sandbox log (macOS, where every path outside the policy looks
missing; the log from an administrator account: `log show --last 5m --predicate
'sender == "Sandbox"'`) or "Access is denied" (Windows), and add exactly the path it needs.

### A policy file

Options can come from a TOML file. Path options on the command line add to the file's paths;
every other option replaces the file's value, also with a weaker one.

```toml
# /etc/sandy/convert.toml
version = 1

[filesystem]
system = "minimal"
read = ["/srv/convert/inbox"]
read_write = ["/srv/convert/outbox"]

[network]
ip = "none"
unix_sockets = "none"

[environment]
pass = ["LANG"]
set = { HOME = "/srv/convert/outbox" }
```

```sh
sandy check --policy /etc/sandy/convert.toml -- /usr/bin/convert-tool
sandy run   --policy /etc/sandy/convert.toml -- /usr/bin/convert-tool --in /srv/convert/inbox
```

### A long-running service with a data directory and exposed ports

A daemon keeps state in a data directory, reads its configuration, uses the network, and offers a
local control port. Its binaries live in a directory that the daemon cannot write.

```toml
# /etc/sandy/daemon.toml
version = 1

[filesystem]
read = ["/etc/daemon"]
read_exec = ["/opt/daemon/bin"]
read_write = ["/var/lib/daemon"]

[network]
ip = "all"
expose = [
  { listen = "127.0.0.1:18080", port = 8080 },
  { listen = "127.0.0.1:18081", port = 8081 },
]

[process]
signals = "isolated"

[windows]
appcontainer_name = "example.daemon"
```

The daemon listens on 127.0.0.1:8080 and 127.0.0.1:8081 inside the sandbox; clients connect to
18080 and 18081. If the daemon starts helper programs, they must lie in a `read_exec` path, and
they inherit the sandbox. `signals = "isolated"` needs Linux 6.12 or newer; on older kernels
sandy refuses this policy, so leave it out there.

### Policies sandy refuses

sandy rejects policies that would let a compromised program widen its own access:

```console
$ sandy run --read-write ~/demo/out --read-exec ~/demo/out -- /usr/bin/true
sandy: writable path /home/user/demo/out overlaps executable path /home/user/demo/out; a path must not be both writable and executable

$ sandy run --read-write ~/demo/out --read ~/demo/out/sub -- /usr/bin/true
sandy: policy path /home/user/demo/out/sub lies inside writable path /home/user/demo/out; the program could replace it with a symbolic link before the next start

$ sandy run -- true
sandy: path must be absolute: true
```

All three exit with status 125, and the program does not start.

## Commands

```text
sandy run [OPTIONS] [--] PROGRAM [ARGS...]   run PROGRAM inside the sandbox
sandy check [OPTIONS] [[--] PROGRAM]         show how this host enforces the policy (needs
                                             PROGRAM when the policy has fallback levels)
sandy setup [OPTIONS]                        prepare the host (needs admin rights on Windows,
                                             and on Linux under Ubuntu's AppArmor restriction)
sandy setup --remove [OPTIONS]               take back what setup and the runs of the policy
                                             left on the host
```

`sandy run` starts the program only if every requirement is enforced. Everything after `--` (or
after the first argument that is not an option) belongs to the program.

`sandy check` prints one line per requirement: `enforced` with the mechanism, or `UNAVAILABLE`
with the reason. Pass the program if the policy should include it. A requirement that this
platform gives only in part is printed as `enforced` too, because `run` starts the program with
it, and a warning names what stays open. Two more kinds of line make `check` exit with status
125 instead of 1, because they say nothing about what this host can do: `UNDECIDED`, when a
probe failed for a reason that can pass (out of memory or processes, a timeout, a service that
is starting) and sandy cannot tell now, and `CONFLICT`, when the policy contradicts itself or
this host's layout, for example a writable path that reaches a startup file. For a policy with
[fallback levels](#fallback-levels), `check` prints a `[NAME]` line before the plan of each
level it tried, and last `level: NAME`, the level that `run` takes, or `level: none`.
`check --json` prints the same as one JSON object instead (see [Fallback levels](#fallback-levels)).

Four kinds of finding get a `warning:` line on standard error: a setting that gives up part of the
isolation (`unix_sockets = "all"`, `signals = "any"`, `path_metadata = "allow"`), an option that
replaced a stricter value of the policy file, a guarantee of the policy that this platform gives
only in part (for example `signals = "isolated"` on macOS, which leaves SIGIO open; the list is in
[docs/DESIGN.md](docs/DESIGN.md), "Requirements and the enforcement plan"), and a fact about this
host that makes the program behave differently inside the sandbox (a directory of your `PATH` or a
usual `bin` directory inside a writable path, on Linux an OpenSSL include the policy does not cover
or a cgroup limit the program cannot see). Warnings change neither the exit status nor the one line
per requirement on standard output, so a caller that reads it is not affected. `sandy run` prints
no warnings: its standard error belongs to the program.

`sandy setup` does the one-time host preparation that needs administrator rights:

- **Windows**: the loopback exemption of the policy's AppContainer, and with relays a grant on
  `sandy.exe` (see [Windows](#windows)).
- **Linux**, on Ubuntu 23.10 and newer, where AppArmor restricts the user namespaces of
  unconfined programs: an AppArmor profile that lets sandy use them, which `ip = "private"` needs.
  A profile gives that right to whatever file is at its path, so setup, run as root, prepares
  only a sandy whose file and directories up to `/` only root can change, as a package installs
  it. It refuses any other sandy with status 3. `sandy setup --install-copy` installs a
  root-owned copy of the running sandy as `/usr/local/libexec/sandy/VERSION/sandy` and prepares
  that copy instead; a sandy of that version elsewhere then hands its `run` and `check` over to
  the copy, which still checks the first sandy's file against the policy: the variable
  `SANDY_STARTED_AS` carries its names, and sandy removes it before the program starts. Where
  user namespaces are disabled altogether, a profile cannot help, and setup exits with status 3.
  Elsewhere on Linux setup has nothing to do. See
  [docs/linux.md](docs/linux.md), "Setup on Ubuntu", also for packaging scripts.
- **macOS**: nothing to do.

For a policy with fallback levels, `sandy setup` prepares every level in turn, or only the one
`--level` names.

`sandy setup --elevate` asks for those rights instead of needing them: through `pkexec` on Linux,
whose authentication agent asks for an administrator's password, and through the UAC prompt on
Windows. It never runs a file with the rights that someone without them can change: on Linux it
runs sandy's own file only when only root can change it, and otherwise, with `--install-copy`,
only system tools and the root-owned copy, which it makes from the image of the running sandy;
on Windows it asks only when only administrators can change `sandy.exe` and its directories.
Otherwise it refuses with status 3. Where nothing is to do, it asks for nothing. With
`--elevate`, `--policy` needs an absolute path, and cannot be `-`.

`sandy setup --remove`, with the same policy, takes that preparation back, together with what
the runs of the policy left on the host: on Windows the loopback exemption, the access control
entries of the policy paths and the AppContainer profile; on Linux the profile of the running
sandy, and with `--install-copy` also the copy and its profile. It removes only what sandy
wrote. The entry on the program file goes only when the removal names the program as a
`read_exec` path (see docs/windows.md). It is idempotent, takes `--elevate` too, and on macOS
it does nothing.

| Setup option | Meaning |
|---|---|
| `--install-copy` | On Linux, install a root-owned copy of the running sandy as `/usr/local/libexec/sandy/VERSION/sandy` and prepare the host for it, for a sandy whose own file is not root-owned. |
| `--elevate` | Ask for the administrator rights setup needs: `pkexec` on Linux, UAC on Windows. |

### Options

| Option | Meaning | Default |
|---|---|---|
| `--policy FILE` | Read the policy from a TOML file (at most one). Path options add to it; the other options replace its values, but not one that a [fallback level](#fallback-levels) sets, which is an error. With `-`, read it from standard input; the program then gets the null device as its standard input. A policy may be at most 1 MiB long. | none |
| `--level NAME` | Use only this level of the policy: `base` or the name of a fallback level. `run` refuses when this host cannot enforce it, instead of taking another. | |
| `--json` | `check` only: print the result as one JSON object (see [Fallback levels](#fallback-levels)). | off |
| `--read PATH` | Allow reading files and listing directories below `PATH`. | |
| `--read-exec PATH` | Allow reading and executing below `PATH`. | |
| `--read-write PATH` | Allow reading, creating, changing and deleting below `PATH`. Never executing. | |
| `--system minimal\|none` | Add the minimal set of system paths programs need to start. | `minimal` |
| `--view all\|policy` | `policy` makes every path outside the policy look missing. See [The file system view](#the-file-system-view). | `all` |
| `--ip all\|client\|private\|none` | IPv4 and IPv6 networking, including loopback. `client` connects out but cannot listen or accept. `private` keeps the program on a loopback of its own. | `none` |
| `--unix-sockets all\|none` | Unix domain sockets. Read the warning below before using `all`. | `none` |
| `--signals any\|isolated` | Whether the program may signal processes outside its sandbox. | `any` |
| `--end-with-parent` | End the program when the process that started sandy ends. Needs `--signals isolated`. See [Processes](#processes). | off |
| `--parent-pid PID` | With `--end-with-parent`: the caller's own process ID. sandy refuses to start if its parent is another process. | |
| `--parent-start TOKEN` | With `--parent-pid`: when that process started, so sandy can tell the caller from a process that got its ID later. The caller may then start sandy through a wrapper. See [Processes](#processes). | |
| `--status-fd N` | Report the program's process ID and how it ended on descriptor `N` (on Windows: an inherited handle). `run` only. See [Exit status](#exit-status). | |
| `--explain` | Name the paths of the run that the policy does not grant, on standard error. `run` only, Linux only. See [Finding the grants a program needs](#finding-the-grants-a-program-needs). | off |
| `--explain-path PATH` | Say what the policy allows for `PATH` and which rule decides it. `check` only, Linux only. | |
| `--children allowed\|none\|contained` | Whether the program may start other processes, and whether they may outlive it. See [Processes](#processes). | `allowed` |
| `--expose ADDRESS=PORT` | Relay connections on the loopback `ADDRESS` to the program's loopback `PORT`. Needs `--ip all` or `--ip private`. | |
| `--forward PORT=ADDRESS` | Relay the program's connections to its loopback `PORT` to the loopback `ADDRESS` outside the sandbox. Needs `--ip private`, `client` or `all`. | |
| `--egress PORT[=REACH]` | A SOCKS5 broker on the program's `127.0.0.1:PORT` that connects out only to `REACH`: `public` or `public-and-local`, never to this host. Needs `--ip private`. | `public` |
| `--linux-path-metadata deny\|allow` | On Linux, whether `chmod`, `chown`, `utimensat` and `setxattr` by path are allowed. | `deny` |
| `--macos-mach-service NAME` | On macOS, let the program look up the Mach service `NAME`. sandy takes only `com.apple.trustd.agent`, the certificate verifier of the system. Repeatable; needs `--ip client` or `all`. See [macOS](#macos). | |
| `--macos-relays dual-stack\|ipv4` | On macOS, how the program reaches its forwarded and egress ports. `ipv4` closes a route to hosts of the local network through IPv6 link-local addresses and denies IPv6 sockets to those ports, so Java needs `-Djava.net.preferIPv4Stack=true`. `ipv4` needs `--ip private`. See [macOS](#macos). | `dual-stack` |
| `--pass-env NAME` | Copy the variable `NAME` into the program's environment, if it is set. | |
| `--set-env NAME=VALUE` | Set a variable in the program's environment. Overrides `--pass-env`. | |
| `--appcontainer NAME` | The AppContainer name (Windows; required there). | |
| `--windows-win32k allow\|deny` | On Windows, whether the program may make the system calls of win32k (the GUI part of the kernel). `deny` stops many programs that load `user32.dll`. | `allow` |
| `--cwd DIR` | Working directory of the program. | sandy's |

The options that take a path or a variable can be repeated.

### Finding the grants a program needs

A program that is denied a path often says nothing about it. It treats the file as missing and
runs on with less than it was built for: without its country database, without its
configuration, with built-in defaults instead of yours. Nothing in the output says so, and the
program's own logs say nothing either.

Two options answer the question "which grant does this program need". Both are Linux only
today; the platform documents say what the other two hosts can and cannot report.

`sandy check --explain-path PATH` says what the policy allows for one path and which rule
decides it, without running anything:

```console
$ sandy check --policy convert.toml --explain-path /usr/share/data/table
backend: linux
enforced     filesystem confined to policy paths: Landlock ABI 10 ...
/usr/share/data/table: no rule covers it
```

`sandy run --explain PROGRAM` watches the run and names every path it uses that the policy does
not grant:

```console
$ sandy run --read /srv/in --explain -- /usr/bin/convert /srv/in/x
sandy explain: on. It names the paths of this run that the policy does not grant, and it does
not see every denial (docs/linux.md, "Diagnostic mode").
sandy explain: cannot read /usr/share/data/table: no rule covers it; grant it with read
(openat in process 4711)
sandy explain: 1 path the policy does not grant, from 812 watched calls
```

The mode is off by default and changes nothing the sandbox enforces: it adds a seccomp filter
that only reports, and sandy's watcher always lets the kernel carry the call out, so Landlock
decides as it would without the mode. It is meant for working out a policy, not for production:
it slows every watched call down (measured: about 25 microseconds each), sandy stays the
program's parent while it runs, and a process that outlives sandy loses the watcher. Read
"Diagnostic mode" in [docs/linux.md](docs/linux.md) before you trust its silence: it reports
the paths a call uses, not what the kernel answered, and several kinds of denial never reach
it.

### Exit status

| Status | Meaning |
|---|---|
| the program's status | `sandy run` started the program |
| 128 + signal number | Linux and macOS with `children = "contained"`, and Linux with `--explain`: a signal ended the program |
| 125 | sandy failed or refused: invalid policy, a requirement this host cannot enforce, a socket on a standard stream that the policy denies, a pseudo-terminal master on one with `signals = "isolated"`, a setup error; with `children = "contained"` or `--explain` also a failure while sandy supervises the program. For `sandy check`: sandy cannot tell now whether this host enforces the policy (an `UNDECIDED` line, or a relay port that another process holds), or the policy conflicts with this host (a `CONFLICT` line) |
| 0 / 1 | `sandy check`: the policy, or one of its levels, is enforceable / none is |
| 2 | `sandy check`: no level is enforceable, but `sandy setup`, run once with administrator rights, would make one so |
| 0 | `sandy setup`, with or without `--remove`: done, or nothing to do |
| 3 | `sandy setup`, with or without `--remove`: not done, and nothing changed: the rights were not given (no administrator rights and no `--elevate`; with `--elevate`, a dismissed prompt, no authentication agent, not authorized), setup is not allowed for this binary, or on Linux user namespaces are disabled on this host |

A program that starts sandy can act on these without reading text. On status 2 from `check`, it
runs `sandy setup --elevate` with the same policy, adding `--install-copy` on Linux when it
ships sandy outside a root-only path. On 0 it runs `check` again; on 3 it does without what
setup prepares, best with a [fallback level](#fallback-levels) that needs no setup (on Linux,
without `ip = "private"`), which `check` then selects; 125 means setup failed. A refusal also
names the command that does it without `--elevate`, such as `sudo`. Status 125 from `check`
means "try again later or fix the policy", never "use a weaker policy": sandy itself never
moves to a weaker level for it.

On Windows the program's 32-bit exit code is passed through unchanged.

### The status record

The exit status leaves two things open. With `children = "contained"`, with `--explain`, and
always on Windows, sandy stays the parent, so the caller holds sandy's process ID and not the
program's; and 125 means both "sandy refused" and "the program exited with 125". `--status-fd N` answers both
without changing any exit status. sandy writes short lines to the descriptor, in this order:

| Line | When |
|---|---|
| `level NAME` | first, for a policy with fallback levels: the level that runs |
| `pid N` | the program runs; `N` is its process ID |
| `exited N` | sandy saw the program exit with status `N` |
| `signaled N` | sandy saw signal `N` end the program (Linux and macOS with `contained`, Linux with `--explain`) |
| `failed` | sandy itself failed or refused; without a `pid` line the program never ran |

In the exec model (Linux and macOS without `contained` and without `--explain`) sandy becomes
the program, so the record ends after `pid` and the caller's own wait status is the program's. sandy writes that
line right before it confines itself and replaces itself with the program, so a `failed` line
after it means that applying the sandbox or the `execve` failed. sandy makes the descriptor close-on-exec, and on Windows it keeps the
handle out of what the program inherits, so the program never has it. Writing is best effort: a
caller that closed the read end gets no record, and the program keeps running. An empty record
with status 125 means that sandy stopped before it took the descriptor, at a usage error for
example.

## Policy reference

```toml
version = 1                     # required; the only version so far

[filesystem]
system = "minimal"              # "minimal" | "none"
read = ["/path"]                # read files, list directories
read_exec = ["/path"]           # read, list, execute
read_write = ["/path"]          # read, list, create, change, delete; never execute
view = "all"                    # "all" | "policy"; policy hides paths outside the policy

[network]
ip = "none"                     # "none" | "private" | "client" | "all"
unix_sockets = "none"           # "none" | "all"
expose = [{ listen = "127.0.0.1:18080", port = 8080 }]
forward = [{ port = 18081, to = "127.0.0.1:8081" }]
egress = { port = 1080, reach = "public" }  # needs ip = "private"; "public" | "public-and-local"

[process]
signals = "any"                 # "any" | "isolated"
children = "allowed"            # "allowed" | "none" | "contained"
end_with_parent = false         # end the program when sandy's parent ends

[environment]
pass = ["LANG"]                 # copied from sandy's environment, if set
set = { HOME = "/path" }        # fixed values; override pass

[linux]
path_metadata = "deny"          # "deny" | "allow"

[macos]
relays = "dual-stack"           # "dual-stack" | "ipv4"; ipv4: forwarded and egress ports over IPv4
mach_services = []              # ["com.apple.trustd.agent"]: the certificate verifier

[windows]
appcontainer_name = "example.app"
win32k = "allow"                # "allow" | "deny"; deny blocks win32k system calls
```

The block names every key; it is not a policy that runs as written, because `expose` needs
`ip = "all"` or `"private"`, `forward` needs any `ip` but `"none"`, `egress` and
`relays = "ipv4"` need `ip = "private"`, `mach_services` needs `ip = "client"` or `"all"`, and one
path cannot be both `read_exec` and `read_write`. Unknown keys are errors, so a misspelled key
never becomes a silent default.

A policy may be at most 1 MiB long and may nest arrays and inline tables at most 32 levels deep;
a longer or deeper one is refused before it is parsed. Real policies are a few KiB and nest a
few levels. The depth limit is what keeps a malformed policy from overflowing the stack of the
TOML parser, whose own limit malformed input can get past.

The platforms limit the number of forwarded ports. On Windows one relay serves all exposed and
forwarded ports, and its command line holds about 1200 forwarded ports. On macOS `ip = "private"`
holds each forwarded port at every address of the Mac, so the 10240 open files of a process allow
about 600 on a Mac with 16 addresses. A run beyond the limit fails before the program starts.

### Rules

1. **Absolute, existing paths.** sandy resolves symbolic links before it builds the sandbox. A
   rule applies to the path and everything below it. On Windows a path must be local: sandy
   refuses a network or share path (`\\server\share`, `\\localhost\C$`, a mapped network
   drive) and asks for the local path instead.
2. **Never writable and executable.** No path may be both writable and executable, also not
   through nesting (a `read_write` directory inside a `read_exec` directory, or the reverse).
   The rule compares files, not names: a hard link that gives an executable file a second name
   inside a `read_write` path is refused too.
3. **Nothing inside a writable path.** No policy path may lie inside a `read_write` path, or be
   reached through a symbolic link (on Windows also a junction) inside one. The program could
   replace it with a symbolic link, and the next start would follow the link. sandy's own
   executable and the policy file get the same check: a `read_write` path must not contain
   them, lead to them through a link or an alias, or hold a second name of them.
4. **The program file** gets read and execute access automatically. It must not lie inside a
   `read_write` path, and must have no second name in one.
5. **The minimal system set** (`system = "minimal"`) adds, read-only, what programs need to start:
   shared libraries, the dynamic loader, time zone data, `/dev/null` and the random devices. It
   never contains user data. Each platform documents its exact list. Programs that need more
   (locale files, configuration in `/etc`, framework resources) need `--read` for those paths.
   No writable path may overlap this set (for example `--read-write /etc`); sandy refuses such a
   policy. The comparison is the one of rules 2 and 3: another name of a directory of the set, a
   bind mount for example, counts as that directory.
6. **The environment** contains only `pass` and `set` variables, plus what a platform must add
   for any program to start (on Windows `SystemRoot` and `LOCALAPPDATA`).
7. **Children inherit the sandbox.** A program that starts other programs needs them in a
   `read_exec` path; they run with the same restrictions. A script needs its interpreter there
   too, because the kernel executes the interpreter; `sandy check` reads the `#!` line and says
   so instead of letting the program fail to start.
8. **No writable path over a trusted user location.** A writable path gives the program your
   write rights there, and a file it leaves behind runs with your rights, outside the sandbox.
   sandy refuses a writable path that reaches a location whose content another program reads or
   runs later: your home directory, the startup files of bash, zsh and fish (`~/.bashrc`,
   `~/.profile`, `~/.config/fish`), the git configuration, cargo's configuration
   (`~/.cargo/config.toml`), `~/.ssh`; on Linux also autostart entries, user services and the
   KDE Plasma login scripts, on macOS also `~/Library/LaunchAgents`, on Windows the Startup
   folders, the PowerShell profile folders, `WindowsApps` and sandy's own state folder. Each
   platform documents its list. A directory below your home directory stays writable, but not
   one that holds such a location: `--read-write ~/.cargo` is refused, and a program that
   downloads crates needs `~/.cargo/registry` and `~/.cargo/git` instead. When sandy cannot find
   your home directory (`HOME` unset and no entry in the password database), it cannot check
   this rule and refuses a policy with a writable path; start it with `HOME` set.

   A directory on your `PATH` gets a warning instead, naming it, because a writable path that
   holds one is often what you mean: `--read-write ~/tools` with `~/tools/bin` on `PATH`, or
   `--read-write /usr/local`. On Linux and macOS sandy also warns about the directories the
   usual shell setups put on `PATH` (`~/.local/bin`, `~/bin`, `~/.cargo/bin`, `/usr/local/bin`,
   `/usr/local/sbin`, and Homebrew's on macOS) when its own `PATH` lacks them, because a service
   or a desktop application starts sandy with a shorter `PATH` than your shell has. The escape is
   real, a file the program leaves there runs when you next type its name. Only a policy that
   keeps the directory out of every writable path removes it: make only the subdirectories the
   program needs writable. Starting sandy with another `PATH` can silence the warning, but leaves
   the risk. A directory below a directory on `PATH` is on no `PATH` and says nothing.

   sandy cannot know which of your files other programs trust, so the list is a heuristic and
   can never be complete. Keep the writable paths of a policy as narrow as the program needs,
   and do not make a directory writable that holds files other programs run or read as
   configuration.

### Network

- `ip = "none"` denies IPv4 and IPv6, including loopback. `ip = "all"` allows every destination
  and listening.
- `ip = "private"` gives the program a loopback of its own: it may listen and connect there, but
  reaches nothing outside the sandbox, not the host, not the local network, not the internet,
  except through `expose`, `forward` and `egress`. `egress = { port = 1080 }` adds a SOCKS5
  broker on the program's `127.0.0.1:1080`. The program asks it for a destination by IPv4 or IPv6
  address (names are refused), and sandy connects only when the destination is a public internet
  address, or with `reach = "public-and-local"` also one of the local network, and never an
  address of this host. Point the program's SOCKS5 proxy option there (for example curl's
  `--socks5 127.0.0.1:1080` or `ALL_PROXY=socks5://127.0.0.1:1080`). A program without such an
  option gets no way out. See docs/DESIGN.md, "Private network and egress", and the platform
  notes for what each platform gives.
- `ip = "client"` lets the program connect and send to every destination, loopback included,
  resolve names and receive the answers, but not listen for or accept a connection. On Linux
  `listen` and `accept` fail with `EPERM` for every socket, Unix sockets too (`check` warns when
  `unix_sockets = "all"`), and from kernel 6.7 (Landlock ABI 4) a TCP socket binds only to a port
  the kernel chooses, from Landlock ABI 10 a UDP socket too. On macOS `listen` fails. On Windows
  the program may listen, but no connection or datagram of another process or host that it did
  not ask for reaches it. What stays open, and `sandy check` names with a warning: on Linux and
  macOS a UDP socket that is not connected receives datagrams from every sender, not only from
  the addresses it sent to, at the port the kernel chose for it, and on macOS and Linux before
  Landlock ABI 10 at any port the program binds it to. On Windows `client` reaches no host of a
  network that Windows counts as private or domain network, such as a printer on the local
  network, because Windows has no capability for connections out into such a network alone;
  names still resolve there, and `ip = "all"` reaches those hosts.
- `unix_sockets = "none"` guarantees that the program cannot connect to Unix sockets outside the
  paths it may write. Linux and macOS deny connections to every Unix socket; Windows checks
  socket access through the socket file, so it allows the sockets in the `read_write` paths and
  in the program's private AppContainer folder.
- **WARNING:** `unix_sockets = "all"` gives up most of the isolation. The program can reach every
  local service on a Unix socket. On Linux that includes the D-Bus session bus, through which the
  systemd user manager starts arbitrary commands outside the sandbox. On macOS it includes the DNS
  resolver, so even with `ip = "none"` the program can send data out in DNS queries. Use it only
  for programs you would also run without a sandbox.
- A socket on standard input, output or error keeps the access it was created with: it exists
  before the sandbox, and no sandbox can take rights from what is already open. sandy therefore
  accepts such a socket only when the policy lets the program create one like it, and else refuses
  to start the program, with status 125 and the stream and the socket named. It refuses an IP
  socket under `ip = "none"` and under `ip = "private"`, where it would belong to the host's
  network, an unconnected, datagram or listening Unix socket under `unix_sockets = "none"`, and
  under every policy a raw IP socket, which only a privileged process can create, an IP socket of
  a protocol other than TCP, UDP, ICMP and MPTCP (SCTP, for example), and a socket of any other
  family, for example a netlink socket that lists the sockets of the host. An ICMP datagram socket counts as an IP socket, because an unprivileged program can create
  one where the system allows it. On Linux `ip = "all"` and `ip = "client"` also accept a route
  netlink socket, which the program may create. A connected Unix stream or seqpacket socket is
  accepted: that is how a parent passes a pipe. Under `ip = "client"` only a connected TCP socket
  is accepted: a listening socket would let the program take connections, and a datagram socket,
  also a connected one, datagrams from every sender. A service that is handed its connection on
  standard input (inetd-style, systemd `Accept=yes`) needs `ip = "client"`, one that is handed a
  listening socket `ip = "all"`. `sandy check` cannot report this, because its own
  streams are not the streams of the later `run`.
- `expose` entries: `listen` must be a loopback address, must differ from the program's own
  address, and may appear only once. They need `ip = "all"` or `ip = "private"`: the program
  listens for the relay's connections, which `ip = "client"` denies, so sandy refuses `expose`
  with it. At most 256 connections per port are relayed at the same time. A connection that is
  still open when the relay ends, one second after the program, is reset, so a cut stream never
  looks complete.
  With `signals = "any"` the program may stop its own relay. On Linux a stopped relay is killed
  two seconds later and its ports are released; on macOS nothing bounds it, so only
  `signals = "isolated"` keeps the bound there. A relay that is continued before that can serve
  one more connection, made after the program ended, on whatever now holds the address it
  forwards to. `signals = "isolated"`, which `process.children = "contained"` requires, closes
  that: the program cannot stop its relay then, and the Linux relay has no timer, so a busy host
  does not kill it either (docs/linux.md).
- `forward` entries: on Linux the relay closes a connection whose other end the kernel names as
  another local user's, so it never reaches the service. A socket its process has closed has no
  owner for the kernel to name, and such a connection is served, because it is the program's
  own in any ordinary run, unless the kernel still names another user for it, as Linux 6.17 and
  newer do for a moment. Another local user can therefore still deliver a blind write, on
  Linux 6.8 usually on the first attempt, by writing and closing at once, but never read the
  answer (docs/linux.md). Under `ip = "private"` on Linux the forward port is in the sandbox's
  own network namespace, which no other user reaches. On macOS every connection is served.
  Forward only to services that authenticate their clients.
- A dead relay frees the program's forward port, and any local user can then bind it and
  receive what the program sends there. With `children = "contained"` on Linux and macOS, sandy
  therefore ends the program when its relay dies, and exits with status 125. Without it nothing
  watches the relay.
- A port another process already holds makes `sandy run` refuse with status 125. `sandy check`
  binds the same listeners for a moment and reports `UNAVAILABLE` for such a port, so it gives
  the same answer. Between the two the port can change hands, so `run` is the final word.

### Processes

- `signals = "isolated"` limits signals to processes in the same sandbox. On Linux this needs
  Landlock ABI 6 (kernel 6.12 or newer), or with `children = "contained"` a PID namespace, which
  sandy creates where unprivileged user namespaces work; otherwise sandy refuses such a policy. The kernel also
  signals whole process groups for terminal job control, without that check, so on Linux the
  program can then neither join another job's process group nor take the terminal from the
  foreground job nor resize it, nor signal the other side of a pseudo-terminal with `TIOCSIG`.
  A shell inside the sandbox therefore has no job control. On Linux and macOS, sandy also
  refuses to start a program that gets the master side of a pseudo-terminal on a standard
  stream: typing Ctrl+C into a master signals the processes on the other side. The
  program's reads from the terminal still stop the job that sandy runs in, including processes
  of that job outside the sandbox, as they would without a sandbox. On macOS a profile cannot
  filter the arguments of `setpgid`, so the program can still join
  another job's process group of its terminal session and have the kernel stop that job; taking
  the terminal and resizing it are denied there in every mode, and `children = "contained"`
  closes the rest. A program on macOS can also still have the kernel send SIGIO to a process
  outside the sandbox, including one of another user, through an ioctl on a socket or a pipe; the
  macOS kernel sends it with no owner check, so this is outside sandy's reach, and a process that
  does not handle SIGIO ignores it (see [docs/macos.md](docs/macos.md)).
- `children` decides whether the program may start processes:
  - `allowed` (the default): yes. On Linux and macOS these processes can outlive the program; on
    Windows they end with it.
  - `none`: the program cannot start processes at all. Threads still work.
  - `contained`: the program may start processes, and sandy ends all of them when the program
    ends, also when sandy itself is killed. Use it for a program that starts helpers, so that no
    helper keeps running after the program has stopped. On Linux and macOS, sandy then stays the
    parent of the program instead of becoming the program: it forwards signals, gives the program
    the terminal when the program uses it, and exits with the program's status (128 plus the
    signal number if a signal ended the program). Processes in the sandbox cannot call `setsid` or
    `setpgid`. On Linux, where unprivileged user namespaces work, the program also runs as process
    2 in a PID namespace of its own, below an init of sandy, and the namespace ends with the
    program or sandy, also when sandy and its guard are both killed; inside, the program's
    parent and process group have no process ID, so `getppid` returns 0, and files of root and
    of other users show the owner 65534. On macOS they cannot call `posix_spawn` either, because its flags can move the new
    process out of the group as well: programs that start processes with `fork` and `exec` (for
    example shells) work, but programs that use `posix_spawn` get `EPERM` when they start one.
    Among them are Rust's `std::process::Command` (unless it sets `pre_exec`), Java's
    `ProcessBuilder`, Node.js, and `system()` and `popen()` in C.

  `none` and `contained` need `unix_sockets = "none"`, and `contained` also needs
  `signals = "isolated"`; otherwise the program could have a process started outside the sandbox,
  or kill sandy before sandy ends its processes. To allow only some programs, give `read_exec`
  to those files instead of their whole directory:

  ```toml
  [filesystem]
  read = ["/opt/app/bin"]                      # libraries and data next to the programs
  read_exec = ["/opt/app/bin/app", "/opt/app/bin/helper"]

  [process]
  signals = "isolated"
  children = "contained"
  ```

  On Linux, a program can also start a readable file through the dynamic loader, so there this
  limits which files can be executed directly, not which code runs. Every process stays in the
  sandbox either way.
- `end_with_parent = true` ends the program when the process that started sandy ends, for
  example when your application crashes while its helper runs in the sandbox. sandy asks the
  program to end (SIGTERM on Linux and macOS) and kills it 5 seconds later if it is still
  running; on Windows it ends the program at once. Unlike a program's own check of its parent,
  this works also when the program is compromised. It needs `signals = "isolated"`. Combine it
  with `children = "contained"` so that the processes the program started end too.

  Tell sandy which process you are. `--parent-pid` is your process ID, which sandy accepts only
  when it is sandy's own parent, so start sandy from your application itself and not through a
  shell or another wrapper. `--parent-start` adds when your process started, which only you can
  know, so sandy can tell you from a process that got your ID after you ended. With both, a
  wrapper between you and sandy is allowed, and a crash in the moment sandy starts makes sandy
  refuse instead of going unnoticed. The value is platform-specific: field 22 of
  `/proc/PID/stat` on Linux ([docs/linux.md](docs/linux.md)), the recorded start time on macOS
  ([docs/macos.md](docs/macos.md)), the creation time on Windows
  ([docs/windows.md](docs/windows.md)).
- Debugging and reading the memory of processes outside the sandbox are always denied, and the
  program can never gain privileges, for example through setuid programs.

### The file system view

- `view = "all"`, the default, shows the program every path as the host has it; the sandbox
  denies access to the ones outside the policy, but the program can tell that they exist.
- `view = "policy"` makes every path outside the policy paths and the system set look missing:
  `stat`, `access`, `readlink`, `open` and a directory watch answer as for a path that does not
  exist. On Linux the program then runs in a view of the file system that holds only those paths
  (a mount namespace), and every path the policy does not make executable is mounted without
  execute, so a `read` or writable path also cannot hold code that the program maps. A rename or
  a link between two writable paths fails there with `EXDEV`, and files of other users show the
  owner 65534. On macOS every path outside the policy looks missing under every policy already,
  so the setting changes nothing there, except that sandy refuses it with
  `unix_sockets = "all"`. Windows cannot hide paths and refuses the setting. See
  docs/DESIGN.md, "The file system view".

### Linux metadata

Landlock does not control `chmod`, `chown`, `utimensat` and `setxattr`. With the default
`path_metadata = "deny"`, sandy denies these calls when they take a path, everywhere, also inside
writable paths, and the owner and extended attribute calls on an open file (`fchown`, `fsetxattr`)
too. The mode and time calls on an open file (`fchmod`, `futimens`) keep working, also on a file
the program may only read, which `sandy check` warns about; with `view = "policy"` such a file is
on a read-only mount, where they fail. The file system ioctls that change a
file the same way, and fs-verity, fscrypt, deduplication and btrfs subvolume ioctls, are denied
under every policy. Tools that change metadata by path (`install`, `cp -a` on a directory,
`rsync -a`, `unzip`, `git`) need `"allow"`; then the program can change the metadata of every file
the user owns. `cp -p`, and `cp -a` on a single file, work under `"deny"`, because they set the
metadata through the descriptor they wrote.

### Fallback levels

A program that runs on many hosts cannot know which hardening each of them supports: an older
kernel without the newest Landlock, Ubuntu's restriction of user namespaces, a platform that
cannot hide paths. A policy can list, after its base, weaker levels in order, and `check` and
`run` take the first one this host can enforce:

```toml
version = 1

[filesystem]
read_exec = ["/opt/example/bin"]
read_write = ["/var/lib/example"]
view = "policy"

[network]
ip = "private"
egress = { port = 1080 }

[process]
signals = "isolated"
end_with_parent = true

[windows]
appcontainer_name = "example.app"

[[fallback]]
name = "contained"
filesystem.view = "all"
process.children = "contained"
windows.appcontainer_name = "example.app.contained"

[[fallback]]
name = "host-network"
network.ip = "all"
network.egress = "none"
filesystem.view = "all"
process.signals = "any"
process.end_with_parent = false
windows.appcontainer_name = "example.app.host"
```

- **Each level is the base plus its own keys.** Levels do not build on each other, so each one
  reads alone; `host-network` above does not contain the program's children. The base is named
  `base`; a level name is 1 to 32 characters of `a-z`, `0-9` and `-`.
- **A level sets only the keys that choose how strongly the program is isolated:**
  `filesystem.view`, `network.ip`, `network.unix_sockets`, `network.egress` (a table, or `"none"`
  for no broker), `process.signals`, `process.children`, `process.end_with_parent`,
  `linux.path_metadata`, `macos.relays`, `windows.win32k` and `windows.appcontainer_name`. The
  paths, `system`, the environment, `expose`, `forward` and `macos.mach_services` are the same in
  every level, so the program finds the same files and ports in each. Any other key in a level is an
  error.
- **Every level is checked as a policy of its own on every host**, so a level that could never
  run (for example `children = "contained"` with `signals = "any"`) is an error everywhere, not
  a surprise on the one host that reaches it.
- **Every level needs an AppContainer name of its own** once one of them names one, because on
  Windows levels that shared a name would share its loopback exemption and its profile folder.
- **A level is skipped only for a lasting shortfall of the host**: a kernel, a platform or a
  build that lacks what the level needs, or something `sandy setup` would prepare. A probe that
  fails for a reason that can pass (`UNDECIDED`), a conflict between the policy and the host
  (`CONFLICT`), a relay port another process holds, a socket on a standard stream: each of these
  stops sandy with status 125 instead, because a weaker level chosen for it would let a passing
  condition, or another user of the host, pick how weakly the program runs. The last level is
  the floor; nothing weaker runs. docs/DESIGN.md, "Fallback levels", has the rules.
- `run` that takes a level other than `base` says so on standard error, before the program
  starts: `warning: running fallback level contained: this host cannot enforce level base (...)`.
  `--level NAME` pins a level: `run` then refuses with status 125 when this host cannot enforce
  it. A program that configures itself per level, for example writes another configuration file
  for a level without the egress broker, runs `check` first and then `run --level` with the level
  `check` named, so a host that changed in between makes `run` refuse rather than start the
  program with the configuration of another level.
- An option that sets a key some level sets (`--ip` when a level sets `network.ip`) is an error,
  because it would be unclear which levels it changes. Other options apply to every level.
- `check` of a policy with levels needs the program, because whether a level can run can depend
  on it.

`sandy check --json` prints one JSON object on one line on standard output, and nothing there
when it exits with status 125:

```json
{"backend":"linux","selected":"contained","setup_would_help":false,
 "levels":[{"name":"base","enforceable":false,"needs_setup":false,
            "enforced":[{"requirement":"filesystem-confined","mechanism":"..."}],
            "missing":[{"requirement":"signals-isolated","status":"unavailable","reason":"..."}],
            "warnings":["..."]},
           {"name":"contained","enforceable":true,"needs_setup":false,
            "enforced":[...],"missing":[],"warnings":[]}],
 "warnings":[]}
```

| Key | Meaning |
|---|---|
| `backend` | `linux`, `macos` or `windows` |
| `selected` | the level `run` takes, or `null` when none is enforceable |
| `setup_would_help` | no level is enforceable, but `sandy setup` would make one so (exit status 2) |
| `levels` | the levels `check` planned, in order, up to the selected one |
| `levels[].name` | `base` or the name of the fallback level |
| `levels[].enforceable` | the host enforces every requirement of the level |
| `levels[].needs_setup` | only something `sandy setup` prepares is missing |
| `levels[].enforced` | each requirement this host enforces, with `requirement` and `mechanism` |
| `levels[].missing` | each requirement it does not, with `requirement`, `status` (`unavailable` or `needs-setup`) and `reason` |
| `levels[].warnings` | the `warning:` lines of the level |
| `warnings` | warnings that concern every level, such as an option that widens the policy file |

The requirement names (`filesystem-confined`, `ip-network-private`, `signals-isolated`, ...)
and the keys stay stable; the `mechanism`, `reason` and warning texts are for people and can
change. A policy without levels has one entry in `levels`, named `base`.

## Platform notes

### Linux

- **Kernel.** sandy needs Landlock enabled (Linux 5.13 or newer, and `landlock` in the active
  security modules) and seccomp. It runs on Ubuntu 22.04 and newer, Debian 12 and newer, Fedora,
  Arch, RHEL 9.6 and newer, and openSUSE Leap and SLES 16. It refuses to run on RHEL 8, RHEL 9.0
  to 9.5, and SLES 15 or Leap 15.6 unless Landlock is enabled with the `lsm=` boot parameter.
  `sandy check` names the reason and the fix.
- **Not as root.** sandy refuses to run as root or with any capability, because those rights
  would survive the sandbox.
- **`/proc` is not readable** by default. Landlock cannot limit it to the program's own entries,
  and `/proc` shows the command lines of every process. Add `--read /proc` only if the program
  needs it.
- **GNU tar cannot extract** an archive that holds a directory. It opens each directory with
  `openat2`, which sandy denies because seccomp cannot read that call's flags and therefore
  cannot reject the open mode that gets past Landlock, and tar does not fall back. Creating and
  listing archives work, and so does `bsdtar` ([docs/linux.md](docs/linux.md)).
- **`ip = "private"`** runs the program in a user and network namespace of its own, so it needs
  unprivileged user namespaces. Ubuntu 23.10 and newer restrict them for programs without an
  AppArmor profile; there `sandy check` exits with status 2 until `sandy setup` installs one for
  sandy. That works for a sandy that only root can change, such as a packaged one; for a
  portable sandy, `sandy setup --install-copy` (or `--elevate --install-copy`) installs a
  root-owned copy that the portable sandy hands over to ([docs/linux.md](docs/linux.md), "Setup
  on Ubuntu"). Inside, files of other users and of root show the owner 65534, and `ping` does not work.
  Other users cannot reach the program's ports, but your own processes can enter the namespace,
  for example with `nsenter`, and `sandy check` warns about that
  ([docs/linux.md](docs/linux.md), "Private network"). With `egress`, a broker in the host's
  network namespace connects for the program. Other users cannot reach its port either, and with
  `children = "contained"` sandy ends the program when the broker dies, as when its relay dies
  ([docs/linux.md](docs/linux.md), "Egress broker").
- **`view = "policy"`** runs the program in a mount namespace that holds only its policy paths
  and the system set, so it needs unprivileged user namespaces as `ip = "private"` does (on
  Ubuntu 23.10 and newer `sandy check` exits with status 2 until `sandy setup`), and a kernel with
  the fix of Landlock erratum 3. A rename between two writable paths fails with `EXDEV`, a file
  outside a `read_exec` path cannot be mapped as code, `/proc` is read-only, and `sandy check`
  warns about what the view still shows: the host's file systems through `statfs`, the
  directories above granted paths, link counts, and with `/proc` the mount tables, also the
  host's ([docs/linux.md](docs/linux.md), "File system view").
- **Name resolution across network changes.** A Landlock rule binds a file, so a file the
  system replaces by rename is lost to a program that is already running. With `--ip all` or
  `--ip client`, sandy grants systemd-resolved's directory, so name resolution keeps working when
  the network changes. Where `/etc/resolv.conf` is a plain file or leads elsewhere, a long-running
  program needs a restart after the system replaces it ([docs/linux.md](docs/linux.md)).
- **Tested** on Fedora 44 (kernel 7.2), Ubuntu 22.04 (6.8), Ubuntu 25.10 (6.17) and the GitHub
  Ubuntu 22.04, 24.04 and 24.04-arm runners. The code paths of older Landlock ABIs are tested on
  a newer kernel with the test harness `sandy-abi-cap`, which lowers the ABI sandy reads (see
  [docs/linux.md](docs/linux.md)).
- Details, the exact system set and all limitations: [docs/linux.md](docs/linux.md).

### macOS

- **Tested** on macOS 15 (arm64) through GitHub Actions, and on macOS 26 and 27 (arm64).
- **Not through Rosetta:** x86_64 code cannot run in the sandbox on Apple silicon, because Rosetta
  cannot load its runtime there. sandy refuses a program without arm64 code on Apple silicon,
  and for a script the interpreter of its `#!` line, which is what the kernel loads. Its x86_64
  build refuses every program there. Use the arm64 build and arm64 or universal programs. The
  x86_64 build has not run on an Intel Mac yet.
- sandy uses `sandbox_init_with_parameters`, which Apple does not document. Chromium uses the
  same function.
- `system = "none"` cannot start any program on macOS, because every program needs the dynamic
  loader and the system library cache. sandy refuses it there unless a policy path covers "/".
- No Mach services are reachable from the sandbox, so programs that need them (for example to open
  other apps, use the pasteboard or read preferences) do not work. The one exception a policy can
  make is the certificate verifier: `mach_services = ["com.apple.trustd.agent"]` under `[macos]`
  (`--macos-mach-service com.apple.trustd.agent`) lets programs verify TLS servers through the
  system, as Go programs and every program that uses Security.framework do; without it they fail
  with `OSStatus -26276`. It needs `ip = "client"` or `"all"`, because the verifier fetches the URLs
  that a certificate names from outside the sandbox. `sandy check` warns what else the service
  gives the program; it cannot make a certificate trusted (docs/macos.md, "Mach services and other
  IPC"). sandy refuses every other service name, and Linux and Windows say that the key allows
  nothing there.
- Every path outside the policy looks missing: calls answer "No such file or directory", not
  "Operation not permitted". With `unix_sockets = "all"`, `access`, `statfs` and `chdir` still
  tell whether a path exists, because reaching a socket needs that check. A program that saves
  its working directory first, such as `cp -R`, fails when it starts in a directory outside the
  policy. Other processes look gone, and the program cannot read the priority, group or session
  of any process, its own included. The names in `/` and the directories above the policy paths
  stay visible, also with `view = "policy"`.
- `ip = "private"` has no loopback of its own on macOS: the program may only connect to its
  forwarded ports and the egress port and listen on its exposed ports, so its own processes
  cannot talk to each other over IP, names resolve only from `/etc/hosts`, and Network.framework
  and URLSession programs cannot use those ports. A forwarded or egress port needs
  `--signals isolated` there. The program can listen on its exposed ports at every address of
  the Mac, where other hosts reach it, every local user can connect out through the egress
  broker, a process of your user can take a forwarded or egress port at an address the Mac
  gains while sandy runs, and the program can connect to those ports at a link-local address of
  the Mac on another link, where another host may have it, such as a router at `fe80::1`;
  `sandy check` warns about each.
- `macos.relays = "ipv4"` (`--macos-relays ipv4`) closes that link-local route: the program then
  reaches its forwarded and egress ports from IPv4 sockets only. An IPv6 socket gets "Operation
  not permitted" there, also one that connects to 127.0.0.1 as `::ffff:127.0.0.1`, which is how
  Java and .NET connect to an IPv4 address by default; start Java with
  `-Djava.net.preferIPv4Stack=true` and .NET with `DOTNET_SYSTEM_NET_DISABLEIPV6=1`. With the key
  sandy refuses a forward to an IPv6 address, and without `ip = "private"` it refuses the key.
  On Linux and Windows the key changes nothing but these refusals.
- The system writes the crash report of a program that sandy runs to
  `/Library/Logs/DiagnosticReports`, which administrators can read and standard users cannot,
  instead of the user's `~/Library/Logs/DiagnosticReports`.
- Terminal programs that change terminal modes fail; only a few terminal requests are allowed.
- With `children = "contained"`, the program cannot use `posix_spawn` (see
  [Processes](#processes)).
- Details: [docs/macos.md](docs/macos.md).

### Windows

- **Versions.** Windows 10 1809 or newer, or Windows Server 2019 or newer, with the fix for
  CVE-2021-41338 (an AppContainer firewall bypass). Tested on Windows 11 and on Windows Server
  2022 and 2025; Windows 10 is expected to work but is not tested.
- **AppContainer name.** Every run needs `--appcontainer NAME` or `windows.appcontainer_name`.
  The name identifies the AppContainer profile; file grants and the loopback exemption belong to
  it. Use one name per policy. sandy refuses to start a second program under a name while another
  program with a different policy runs under it, because programs in one AppContainer can control
  each other.
- **One-time setup.** Run as administrator, once per machine and policy:

  ```bat
  sandy setup --policy C:\ProgramData\example\policy.toml
  ```

  It adds the loopback exemption when the policy has `ip = "client"` or `ip = "all"` (removes it
  otherwise), so the program can connect to services on 127.0.0.1, and with `expose` it grants
  the relay access to `sandy.exe` if your user cannot. `--elevate` asks for the rights with the
  UAC prompt, when only administrators can change `sandy.exe` and its directories, for example
  below `C:\Program Files`. The elevated sandy's messages do not reach the caller, only its exit
  status does. Without administrator rights and without `--elevate`, setup and `setup --remove`
  change nothing and exit with status 3.
- **Inbound loopback.** Windows blocks every connection from outside into an AppContainer, also
  on 127.0.0.1. Use `expose` for programs that accept connections.
- **Private network.** `ip = "private"` runs the program in its AppContainer without network
  capabilities and without the loopback exemption: its processes and the relays of `expose` and
  `forward` talk over loopback, and nothing else on this machine or the network reaches the
  program or is reached by it. Names do not resolve, and a datagram the program sends out is
  dropped although the send reports success. `sandy setup` removes the exemption for it, as for
  `ip = "none"`.
- **Egress broker.** `egress` adds a SOCKS5 broker that the program reaches on its loopback. On
  Windows it runs as a separate `sandy` process in an AppContainer of its own, with only the
  capability it needs to connect out, reached from the program over the same AF_UNIX path as
  `forward`. It ends with the program. It connects only where `reach` allows and never to this
  host, and its own AppContainer isolation keeps it off this machine even if that check were
  wrong. See [docs/windows.md](docs/windows.md), "Egress broker".
- **No hidden paths.** `view = "policy"` is refused: Windows cannot hide paths from an
  AppContainer without administrator rights, so the program can tell an existing path outside
  the policy from a missing one.
- **File grants.** sandy grants access by adding entries to the access control lists of the
  policy paths. These entries stay; they grant nothing to programs outside this AppContainer.
  `docs/windows.md` explains how to remove them and the profile.
- **Private folder.** Windows gives every AppContainer a private folder (its `TEMP`). The program
  can always write there, but sandy makes sure it cannot execute anything it writes there.
- **Console.** The program gets its own hidden console; sandy relays standard input and output.
  Ctrl+C ends the program.
- **Win32k lockdown.** `win32k = "deny"` starts the program (and its children and relays) with
  the system calls of win32k, the GUI part of the Windows kernel, disabled. It cuts a large
  attack surface, but a program that loads `user32.dll` ends at startup, so turn it on only for a
  program you have checked starts with it (see [docs/windows.md](docs/windows.md)).
- Details and limitations: [docs/windows.md](docs/windows.md).

## Using sandy from another program

sandy is a command line tool, so any language can use it. Start sandy instead of the program:

```text
[ "/opt/example/sandy", "run", "--policy", "/opt/example/policy.toml", "--", "/opt/example/bin/daemon", "--flag" ]
```

Recommendations:

1. **Call `sandy check` first** and show its output when the exit status is 1, so users learn
   why the program cannot run on their host. Its standard output has one line per requirement;
   the `warning:` lines on standard error are advice about the policy and do not change the exit
   status. `check --json` gives the same to a program (see [Fallback levels](#fallback-levels)).
2. **Put the weaker variants of the policy into the policy, as fallback levels**, instead of
   retrying with another policy when `check` fails: sandy knows which hardening each host
   supports, and it never moves to a weaker level for a reason that can pass. When the program
   needs to know the level, for example to write its own configuration for it, run
   `check --json`, configure the program for the `selected` level, and start it with
   `run --level` and that name.
3. **Pass the policy on standard input** (`--policy -`) when it ships inside the calling program,
   for example as a resource: there is then no policy file to place where the program cannot
   write it, none is left behind, and nothing can change it between writing and reading. It does
   not protect against other processes of the same user, which can change the caller or sandy
   just as well. The program then reads the null device on its standard input, so this suits
   programs that need no input.
4. **Treat exit status 125 as "not started".** sandy prints the reason on standard error. Two
   exceptions: a program can exit with 125 itself, and with `children = "contained"` or
   `--explain` sandy can fail while it supervises a running program, for example when the relay
   of its ports died (its message is `sandy: run failed: ...`). Pass `--status-fd` when you need to tell these apart, or need the
   program's process ID (see [The status record](#the-status-record)).
5. **Keep sandy, the policy and the program's binaries out of every writable path.** Use separate
   directories for binaries (`read_exec`) and data (`read_write`). A program that can rewrite its
   own binary or library directory can escape at the next start.
6. **Treat everything the program writes as untrusted input**, including files in its data
   directory and everything it sends over exposed ports.
7. **Do not pass secrets in arguments or the environment** unless the program needs them.
8. **Run `sandy setup` during installation**, with administrator rights: on Windows, with a
   stable AppContainer name per policy; on Linux, for `ip = "private"` under Ubuntu's AppArmor
   restriction, as in the packaging scripts of [docs/linux.md](docs/linux.md). A program without
   an installer runs `sandy setup --elevate` when `check` exits with 2 (see
   [Exit status](#exit-status)).
9. **Give the program pipes, files or a terminal on its standard streams.** sandy passes
   descriptors 0, 1 and 2 on as it got them, so a socket among them would keep its access; sandy
   refuses to start the program then. The connected Unix stream socket that most runtimes pass
   for a pipe (libuv, and so Node.js) is accepted. With `signals = "isolated"` sandy also refuses
   the master side of a pseudo-terminal, which a terminal emulator or `expect` holds, because
   the program could type Ctrl+C into it and so signal the processes on the other side. Pass
   the slave side, the terminal a program normally runs in, or a pipe.
10. **Do not give an untrusted program your terminal.** What the program writes to a terminal
   reaches the terminal emulator, which acts on some escape sequences, for example to set the
   clipboard, and on Linux the program can also change the terminal's modes. These are ordinary
   writes, which no system call filter can tell apart, so sandy cannot stop them. Redirect the
   program's output to a file or a pipe, and show it to a person only through a filter that
   removes control sequences. A later option could have sandy relay the terminal and filter it.

## Security model

The sandboxed program and all its children are assumed to be under the attacker's control. They
can run any code and make any system call. sandy, its policy, and the files sandy reads before the
sandbox applies are trusted.

sandy protects:

- the user's files outside the policy (their contents, and their metadata against changes),
- other processes of the user (memory, debugging; signals with `signals = "isolated"`, on Linux
  including the terminal's job control signals),
- the user's privileges (no setuid, no capabilities, no elevation),
- the network, as far as `ip` and `unix_sockets` deny it,
- the host's local services on Unix sockets.

sandy does not protect:

- secrets the program itself holds, and the data in its `read_write` paths,
- network traffic the program may send with `ip = "client"` or `ip = "all"`,
- the terminal the program writes to (recommendation 8 above),
- the availability of the machine (CPU, memory, disk use), and of files the program may read: a
  lock it holds on such a file stalls programs outside that lock the same file, and on Windows
  also those that read or write it,
- against bugs in the operating system kernel.

What remains visible from inside the sandbox differs by platform; for example, on Linux the
program can see which paths exist outside the policy, but not their contents, while on macOS
every path outside the policy looks missing (with `unix_sockets = "all"` a few calls still tell
whether it exists) and every other process looks gone. Each platform document lists these
limitations.

Independent reviews tried to escape the sandbox on every platform. Their findings were fixed, or
are written down as limitations in the platform documents. Either way a test holds the result
(`crates/sandy-cli/tests/review_*.rs`).

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The escape tests in `crates/sandy-cli/tests/` run a probe program (`sandy-probe`) inside the
sandbox. Each test tries an action, first outside the sandbox (it must work there) and then inside
(it must fail), so a test cannot pass because the action was impossible anyway. Platform tests
are in `escape_linux.rs`, `escape_macos.rs` and `escape_windows.rs`; `check.rs` checks that
`sandy check` reports what `sandy run` refuses, and the tests from the reviews are in
`review_*.rs`.

To run the tests on another machine, build the test executables, copy them together with `sandy`
and `sandy-probe` into one directory there, and set `SANDY_TEST_BIN_DIR` to that directory:

```sh
cargo test --no-run --target x86_64-unknown-linux-musl -p sandy-cli
SANDY_TEST_BIN_DIR=/path/to/dir ./escape-<hash>
```

### Checks that cannot run on a host

Some checks need something the host has to offer: a pseudo-terminal, a session bus, a Landlock
right of a newer kernel, AppContainer processes that may start child processes. libtest has no
outcome between ok and failed, so such a check would report ok like a check that ran. These
variables keep that visible:

| Variable | Effect |
|---|---|
| `SANDY_TEST_SKIP_LOG` | File every skipped check is appended to: binary, test, feature, reason. |
| `SANDY_TEST_RUNNER` | The name of this runner. `crates/sandy-cli/tests/expected-skips/<runner>.txt` holds the checks it is expected to skip. |
| `SANDY_TEST_REQUIRE` | Features that must be checkable here, separated by commas, or `all`. Skipping one fails that test. |
| `SANDY_TEST_MIN_LANDLOCK_ABI` | The lowest Landlock ABI this runner must report (Linux). |
| `SANDY_TEST_LOCAL_PEER` | `ADDRESS:PORT` of another host of the local network that takes TCP connections there, as an SSH server does. The test of `egress` with `reach = "public-and-local"` reaches it (Linux); without it that test skips `local-network-peer`. |

After a run, `cargo test -p sandy-cli --test runner -- --ignored --exact
skips_match_the_expected_list` compares the log with the list of the runner and fails on a skip
that is not in the list, and on a listed skip that did not happen. A check that quietly stops
running is then a diff to review, not a silent pass. A runner without a list fails that
comparison and prints the list to commit. A run for another target is a runner of its own, named
`<runner>-<target>` as in CI, because what it can check differs: the static musl build, for
example, has no loader to check (`fedora-44-x86_64-unknown-linux-musl.txt`).

### The snapshot of the compiled seccomp filters

`compiled_programs_match_the_snapshot` in `crates/sandy-linux/src/filter.rs` compares the
compiled Linux BPF programs with `crates/sandy-linux/snapshots/x86_64.txt`. Each section of that
file names one program, its instruction count, a checksum of its instructions, and the action it
returns for every system call number. A change to a rule, to the reviewed system call table or to
seccompiler's code generation makes the test fail.

Update it deliberately. The failure prints the new text; write it to the file, then read the diff
of the file and check that every line that changed is a line you meant to change. The snapshot is
x86_64's, because arm64 has its own system call numbers and its file would have to be written on
an arm64 Linux host.

### The supply chain checks

What goes into a build is pinned in this repository, and the builds check it:

- **Crates.** `Cargo.lock` holds the SHA-256 sum of every crate, and cargo checks each download
  against it. Every cargo command of CI and of the release build runs with `--locked`, so a lock
  file that no longer matches `Cargo.toml` fails the command instead of being resolved again.
- **The crates that may be in the tree.** `deny.toml` lists them. A crate that is not in the list,
  an advisory, a yanked version, an unexpected license or a source other than crates.io fails
  `cargo deny`. [docs/DESIGN.md](docs/DESIGN.md) says why `seccompiler` stays although its
  standalone repository is archived.
- **Who vouches for each crate version.** `supply-chain/` holds the records of
  [cargo-vet](https://mozilla.github.io/cargo-vet/). Every crate version of `Cargo.lock` must be
  covered by an audit imported from Mozilla, Google, the Bytecode Alliance, Zcash or ISRG
  (`supply-chain/imports.lock` keeps the audits that apply), by an audit of this repository or a
  trusted publisher (`supply-chain/audits.toml`), or by an exemption (`supply-chain/config.toml`).
  The notes of each audit of this repository say who reviewed the crate, what they checked and
  what they found. Today every crate version is covered by audits, with no trusted publishers and
  no exemptions. A trusted publisher entry, if one is added, names the organizations that trust
  that publisher for that crate and ends after a year; an exemption is a crate version that nobody
  audited, and its notes say why sandy uses it anyway. `scripts/check-audits.sh` fails on a crate
  version without cover, on an entry that nothing needs any more, and on an audit, exemption or
  trusted publisher without notes.
- **The toolchain.** `rust-toolchain.toml` pins the Rust release, and `rust-toolchain.sha256` the
  SHA-256 sum of its channel manifest, which lists the sum of every archive of that release.
  `scripts/verify-toolchain.sh` downloads the manifest, checks it against the pinned sum, and
  checks that rustup installed the toolchain in use from archives that the manifest lists. CI
  runs it before anything is built, and `scripts/release-build.sh` before every release build.
- **The tools of the checks.** `scripts/install-tool.sh` builds a tool such as cargo-deny from
  the crate with the sum that the workflow names, so the crates.io index of the day does not
  decide which code runs.

The `audit` workflow runs these, and so does:

```sh
scripts/verify-toolchain.sh
scripts/install-tool.sh cargo-deny 0.20.2 e528dfcbe739af7ce37a77d3d6df1b29dd6887b1c701d888820c0f16b864f737
cargo deny --locked check all
scripts/install-tool.sh cargo-vet 0.10.2 dd93790018205cbbfa161f078ca4631afa8ed57fc8f32482268bcfdf0c0d7499
scripts/check-audits.sh
```

**When a dependency changes.** Run `cargo vet`: it fetches the audits of the imported
organizations again and names every crate version that is still not covered. `cargo vet suggest`
lists the audits that would cover them, with their size. Then record, for each one, an audit you
did (`cargo vet certify`), a publisher to trust (`cargo vet trust CRATE PUBLISHER --notes ...`,
only when the imported organizations trust it for that crate), or an exemption with notes in
`supply-chain/config.toml`. Finish with `cargo vet prune --no-imports` and
`scripts/check-audits.sh`, and add a new crate to `deny.toml` as well. Before a trusted publisher
entry ends, check that the organizations still trust that publisher and move its `end` date,
which is at most a year away; the weekly run fails once an entry has ended.

**Pinning a new toolchain.** Change `channel` in `rust-toolchain.toml`. Then download the channel
manifest of that release with its signature, check the signature with the Rust release key, and
write the sum of the manifest:

```sh
v=1.98.1
curl -fsSO https://static.rust-lang.org/dist/channel-rust-$v.toml
curl -fsSO https://static.rust-lang.org/dist/channel-rust-$v.toml.asc
gpg --verify channel-rust-$v.toml.asc channel-rust-$v.toml
sha256sum channel-rust-$v.toml > rust-toolchain.sha256
```

`gpg` must report a good signature by the primary key
`108F 6620 5EAE B0AA A8DD  5E1C 85AB 96E6 FA1B E5FE` (Rust Language (Tag and Release Signing Key)
<rust-key@rust-lang.org>), which `https://static.rust-lang.org/rust-key.gpg.ascii` publishes.
Write the sum only after that.

### What CI runs

The tests run on Ubuntu 22.04 and 24.04 (x86_64) and 24.04 (arm64), macOS 15, and Windows Server
2022 and 2025. On Ubuntu 24.04 they run a second time for the musl target of the Linux release
on that architecture, because musl and glibc differ in constants that sandy builds its filters
from. Each runner names the features it must be able to check and, on Linux, the lowest
Landlock ABI it must report; after the suite, CI compares the skips with the runner's list. Every
job that builds checks the toolchain first, with `scripts/verify-toolchain.sh`. The `audit`
workflow runs `cargo deny` and `scripts/check-audits.sh`, weekly as well, because an advisory can
appear, and a trusted publisher entry can end, without a push. The `release` workflow builds
archives for Linux, macOS and Windows on x86_64 and arm64 when a tag `v<version>` is pushed,
attests their build provenance, verifies the attestations, and creates a draft release with
`SHA256SUMS`. It also builds one target twice from two directories and compares the binaries. The
arm64 Windows build is compiled but not tested.

### Code layout

| Crate | Role |
|---|---|
| `sandy-core` | Policy, validation, requirements, enforcement plan, backend contract |
| `sandy-linux`, `sandy-macos`, `sandy-windows` | One backend each |
| `sandy-relay` | The byte relay behind `expose` |
| `sandy-cli` | The `sandy` command, backend selection, the test probe and harnesses, and the escape tests |

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): goals, threat model, policy rules, requirements
- [docs/linux.md](docs/linux.md), [docs/macos.md](docs/macos.md),
  [docs/windows.md](docs/windows.md): mechanisms, system sets, limitations, sources
- [docs/research](docs/research): background research (Linux mechanisms, Windows 10 support)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
