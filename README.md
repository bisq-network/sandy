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

Status: under development. The interfaces may still change.

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
| Linux | Landlock (file access, TCP ports, scopes), two seccomp-bpf filters, `no_new_privs`, closing inherited descriptors, then `execve` |
| macOS | A Seatbelt profile generated from the policy, applied with `sandbox_init_with_parameters`, then `execve` |
| Windows | An AppContainer with one capability per policy path, a job object with UI restrictions, and a list of inherited handles |

On Linux and macOS, sandy confines itself and then replaces itself with the program, so the
program keeps sandy's process ID. On Windows, sandy starts the program and waits for it; when
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

Release archives for each platform are built by the `release` workflow (see
[Building and testing](#building-and-testing)). Approximate binary sizes:

| Target | Size |
|---|---|
| Linux x86_64, static musl | 0.9 MB |
| Linux arm64, static musl | 0.8 MB |
| Windows x86_64 | 0.8 MB |
| macOS arm64 and x86_64 | see the release archives |

**Where to install sandy.** Put the `sandy` binary, and your policy files, where the sandboxed
program cannot write: not inside any `read_write` path of any policy. Otherwise a compromised
program could replace sandy or its policy, and the next start would run without a sandbox.

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
```

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

`--ip all` allows IPv4 and IPv6. On Linux it also adds the files for name resolution and the CA
certificates to the system set.

```console
$ sandy run -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://example.org
curl: (6) Could not resolve host: example.org
000
$ sandy run --ip all -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://example.org
200
```

IP networking is all or nothing: with `--ip all` the program can connect to any address. sandy
does not filter destinations.

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
the sandbox log (macOS: `log show --last 5m --predicate 'sender == "Sandbox"'`) or "Access is
denied" (Windows), and add exactly the path it needs.

### A policy file

Options can come from a TOML file. Command line options extend the file.

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
they inherit the sandbox.
`signals = "isolated"` needs Linux 6.12 or newer; on older kernels sandy refuses this policy, so
leave it out there.

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
sandy check [OPTIONS] [[--] PROGRAM]         show how this host enforces the policy
sandy setup [OPTIONS]                        prepare the host (needs admin rights on Windows)
```

`sandy run` starts the program only if every requirement is enforced. Everything after `--` (or
after the first argument that is not an option) belongs to the program.

`sandy check` prints one line per requirement: `enforced` with the mechanism, or `UNAVAILABLE`
with the reason. Pass the program if the policy should include it.

`sandy setup` does the one-time host preparation that needs administrator rights. Today this
matters only on Windows (see [Windows](#windows)); on Linux and macOS it does nothing.

### Options

| Option | Meaning | Default |
|---|---|---|
| `--policy FILE` | Read the policy from a TOML file. The other options extend it. | none |
| `--read PATH` | Allow reading files and listing directories below `PATH`. | |
| `--read-exec PATH` | Allow reading and executing below `PATH`. | |
| `--read-write PATH` | Allow reading, creating, changing and deleting below `PATH`. Never executing. | |
| `--system minimal\|none` | Add the minimal set of system paths programs need to start. | `minimal` |
| `--ip all\|none` | IPv4 and IPv6 networking, including loopback. | `none` |
| `--unix-sockets all\|none` | Unix domain sockets. Read the warning below before using `all`. | `none` |
| `--signals any\|isolated` | Whether the program may signal processes outside its sandbox. | `any` |
| `--expose ADDRESS=PORT` | Relay connections on the loopback `ADDRESS` to the program's loopback `PORT`. Needs `--ip all`. | |
| `--linux-path-metadata deny\|allow` | On Linux, whether `chmod`, `chown`, `utimensat` and `setxattr` by path are allowed. | `deny` |
| `--pass-env NAME` | Copy the variable `NAME` into the program's environment, if it is set. | |
| `--set-env NAME=VALUE` | Set a variable in the program's environment. Overrides `--pass-env`. | |
| `--appcontainer NAME` | The AppContainer name (Windows; required there). | |
| `--cwd DIR` | Working directory of the program. | sandy's |

The options that take a path or a variable can be repeated.

### Exit status

| Status | Meaning |
|---|---|
| the program's status | `sandy run` started the program |
| 125 | sandy failed or refused: invalid policy, a requirement this host cannot enforce, a setup error |
| 0 / 1 | `sandy check`: the policy is enforceable / not enforceable |

On Windows the program's 32-bit exit code is passed through unchanged.

## Policy reference

```toml
version = 1                     # required; the only version so far

[filesystem]
system = "minimal"              # "minimal" | "none"
read = ["/path"]                # read files, list directories
read_exec = ["/path"]           # read, list, execute
read_write = ["/path"]          # read, list, create, change, delete; never execute

[network]
ip = "none"                     # "none" | "all"
unix_sockets = "none"           # "none" | "all"
expose = [{ listen = "127.0.0.1:18080", port = 8080 }]

[process]
signals = "any"                 # "any" | "isolated"

[environment]
pass = ["LANG"]                 # copied from sandy's environment, if set
set = { HOME = "/path" }        # fixed values; override pass

[linux]
path_metadata = "deny"          # "deny" | "allow"

[windows]
appcontainer_name = "example.app"
```

Unknown keys are errors, so a misspelled key never becomes a silent default.

### Rules

1. **Absolute, existing paths.** sandy resolves symbolic links before it builds the sandbox. A
   rule applies to the path and everything below it.
2. **Never writable and executable.** No path may be both writable and executable, also not
   through nesting (a `read_write` directory inside a `read_exec` directory, or the reverse).
3. **Nothing inside a writable path.** No policy path may lie inside a `read_write` path. The
   program could replace it with a symbolic link, and the next start would follow the link.
4. **The program file** gets read and execute access automatically. It must not lie inside a
   `read_write` path.
5. **The minimal system set** (`system = "minimal"`) adds, read-only, what programs need to start:
   shared libraries, the dynamic loader, time zone data, `/dev/null` and the random devices. It
   never contains user data. Each platform documents its exact list. Programs that need more
   (locale files, configuration in `/etc`, framework resources) need `--read` for those paths.
6. **The environment** contains only `pass` and `set` variables, plus what a platform must add
   for any program to start (on Windows `SystemRoot` and `LOCALAPPDATA`).
7. **Children inherit the sandbox.** A program that starts other programs needs them in a
   `read_exec` path; they run with the same restrictions.

### Network

- `ip = "none"` denies IPv4 and IPv6, including loopback. `ip = "all"` allows every destination.
- `unix_sockets = "none"` guarantees that the program cannot connect to Unix sockets outside its
  `read_write` paths. Linux and macOS deny Unix sockets completely; Windows allows sockets inside
  `read_write` paths, because it checks socket access through the socket file.
- **WARNING:** `unix_sockets = "all"` gives up most of the isolation. The program can reach every
  local service on a Unix socket. On Linux that includes the D-Bus session bus, through which the
  systemd user manager starts arbitrary commands outside the sandbox. On macOS it includes the DNS
  resolver, so even with `ip = "none"` the program can send data out in DNS queries. Use it only
  for programs you would also run without a sandbox.
- `expose` entries: `listen` must be a loopback address, must differ from the program's own
  address, and may appear only once. They need `ip = "all"` in this version. At most 256
  connections are relayed at the same time.

### Processes

- `signals = "isolated"` limits signals to processes in the same sandbox. On Linux this needs
  Landlock ABI 6 (kernel 6.12 or newer); older kernels refuse such a policy.
- Debugging and reading the memory of processes outside the sandbox are always denied, and the
  program can never gain privileges, for example through setuid programs.

### Linux metadata

Landlock does not control `chmod`, `chown`, `utimensat` and `setxattr`. With the default
`path_metadata = "deny"`, sandy denies these calls when they take a path, everywhere, also inside
writable paths. The calls on an open file (`fchmod`, `futimens`, `fsetxattr`) keep working. Tools
that change metadata by path (`tar`, `cp -p`, `install`, `git checkout`) need `"allow"`; then the
program can change the metadata of every file the user owns.

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
- **Tested** on Fedora 44 (kernel 7.2), Ubuntu 22.04 (6.8), Ubuntu 25.10 (6.17) and the GitHub
  Ubuntu 22.04 and 24.04 runners.
- Details, the exact system set and all limitations: [docs/linux.md](docs/linux.md).

### macOS

- **Tested** on macOS 15 (arm64) through GitHub Actions.
- sandy uses `sandbox_init_with_parameters`, which Apple does not document. Chromium and WebKit
  use the same function.
- `system = "none"` cannot start any program on macOS, because every program needs the dynamic
  loader and the system library cache.
- No Mach services are reachable from the sandbox, so programs that need them (for example to open
  other apps, use the pasteboard or read preferences) do not work.
- Terminal programs that change terminal modes fail; only a few terminal requests are allowed.
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

  It adds the loopback exemption when the policy has `ip = "all"` (removes it otherwise), so the
  program can connect to services on 127.0.0.1, and with `expose` it grants the relay access to
  `sandy.exe` if your user cannot.
- **Inbound loopback.** Windows blocks every connection from outside into an AppContainer, also
  on 127.0.0.1. Use `expose` for programs that accept connections.
- **File grants.** sandy grants access by adding entries to the access control lists of the
  policy paths. These entries stay; they grant nothing to programs outside this AppContainer.
  `docs/windows.md` explains how to remove them and the profile.
- **Private folder.** Windows gives every AppContainer a private folder (its `TEMP`). The program
  can always write there, but sandy makes sure it cannot execute anything it writes there.
- **Console.** The program gets its own hidden console; sandy relays standard input and output.
  Ctrl+C ends the program.
- Details and limitations: [docs/windows.md](docs/windows.md).

## Using sandy from another program

sandy is a command line tool, so any language can use it. Start sandy instead of the program:

```text
[ "/opt/example/sandy", "run", "--policy", "/opt/example/policy.toml", "--", "/opt/example/bin/daemon", "--flag" ]
```

Recommendations:

1. **Call `sandy check` first** and show its output when the exit status is 1, so users learn
   why the program cannot run on their host.
2. **Treat exit status 125 as "not started".** sandy prints the reason on standard error.
3. **Keep sandy, the policy and the program's binaries out of every writable path.** Use separate
   directories for binaries (`read_exec`) and data (`read_write`). A program that can rewrite its
   own binary or library directory can escape at the next start.
4. **Treat everything the program writes as untrusted input**, including files in its data
   directory and everything it sends over exposed ports.
5. **Do not pass secrets in arguments or the environment** unless the program needs them.
6. **On Windows**, choose a stable AppContainer name per policy, and run `sandy setup` with
   administrator rights during installation.

## Security model

The sandboxed program and all its children are assumed to be under the attacker's control. They
can run any code and make any system call. sandy, its policy, and the files sandy reads before the
sandbox applies are trusted.

sandy protects:

- the user's files outside the policy (contents and metadata),
- other processes of the user (memory, debugging; signals with `signals = "isolated"`),
- the user's privileges (no setuid, no capabilities, no elevation),
- the network, as far as `ip` and `unix_sockets` deny it,
- the host's local services on Unix sockets.

sandy does not protect:

- secrets the program itself holds, and the data in its `read_write` paths,
- network traffic the program may send with `ip = "all"`,
- the availability of the machine (CPU, memory, disk use),
- against bugs in the operating system kernel.

What remains visible from inside the sandbox differs by platform; for example, on Linux the
program can see which paths exist outside the policy, but not their contents. Each platform
document lists these limitations.

Independent reviews tried to escape the sandbox on every platform; none succeeded. The reviews,
their tests and the fixes that followed are in [docs/reviews](docs/reviews).

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The escape tests in `crates/sandy-cli/tests/` run a probe program (`sandy-probe`) inside the
sandbox. Each test tries an action, first outside the sandbox (it must work there) and then inside
(it must fail), so a test cannot pass because the action was impossible anyway. Platform tests
are in `escape_linux.rs`, `escape_macos.rs` and `escape_windows.rs`; the tests from the reviews are
in `review_*.rs`.

To run the tests on another machine, build the test executables, copy them together with `sandy`
and `sandy-probe` into one directory there, and set `SANDY_TEST_BIN_DIR` to that directory:

```sh
cargo test --no-run --target x86_64-unknown-linux-musl -p sandy-cli
SANDY_TEST_BIN_DIR=/path/to/dir ./escape-<hash>
```

CI runs the tests on Ubuntu 22.04 and 24.04, macOS 15, and Windows Server 2022 and 2025. The
`release` workflow builds archives for Linux, macOS and Windows on x86_64 and arm64 when a tag
`v<version>` is pushed, and creates a draft release with `SHA256SUMS`. The arm64 Windows build is
compiled but not tested.

### Code layout

| Crate | Role |
|---|---|
| `sandy-core` | Policy, validation, requirements, enforcement plan, backend contract |
| `sandy-linux`, `sandy-macos`, `sandy-windows` | One backend each |
| `sandy-relay` | The byte relay behind `expose` |
| `sandy-cli` | The `sandy` command, backend selection, the test probe and the escape tests |

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): goals, threat model, policy rules, requirements
- [docs/linux.md](docs/linux.md), [docs/macos.md](docs/macos.md),
  [docs/windows.md](docs/windows.md): mechanisms, system sets, limitations, sources
- [docs/research](docs/research): background research (Linux mechanisms, Windows 10 support)
- [docs/reviews](docs/reviews): independent security reviews

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
