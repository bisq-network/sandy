# sandy 1.0.0 Release Notes

sandy 1.0.0 is the first public release of sandy. sandy runs a program inside the sandbox of the operating system, as a small policy allows, with the same policy on Linux, macOS and Windows. It fails closed: if the host cannot enforce every restriction of the policy, sandy does not start the program and says why.

## Scope

These notes describe the release `v1.0.0` of `bisq-network/sandy` at commit `e755aeb1a5dd0ffe9a83845128bfb1a0b8bcd3e8`. `Cargo.toml` declares version `1.0.0`, and policies use the format `version = 1`. Development versions before the public release were numbered up to 2.5.0; commit `dcf02492` reset the version to 1.0.0 for the first public release. `main` at `9e321238` has one change after the release, which is listed under "Known Issues". The notes were checked against the README and the platform documents at the release commit.

## Upgrade and Integration Notes

- **From a development version:** 1.0.0 has the command line options and the policy format (`version = 1`) of the development versions 2.4.1 and 2.5.0, so a program which used one of them can keep its policies. The version number is lower, so a caller which compares versions must accept 1.0.0 as newer than 2.5.0. Compared with 2.4.1, 1.0.0 warns about a policy path which holds the user's terminals and accepts policy paths inside a writable devpts (both from 2.5.0). Compared with 2.5.0, it fixes two failures of contained programs on macOS and builds reproducible release archives.
- **Install location:** install the `sandy` binary and the policy files outside every `read_write` path of every policy. sandy checks this at every start for the binary and the policy file which it uses, and refuses the policy otherwise.
- **Callers:** a program which starts sandy should call `sandy check` first, put weaker variants of its policy into the policy as fallback levels, pass the policy on standard input (`--policy -`), and treat exit status 125 as "not started", with two exceptions: the program can exit with 125 itself, and with `children = "contained"` or `--explain` sandy can fail while it supervises a running program. A caller which must tell these apart passes `--status-fd` or `--status-file`; without a `pid` line in the record the program never ran. `check --json` and `run --level` let a caller configure the program for the level which sandy selected.
- **Setup:** on Windows, `sandy setup` with administrator rights adds the loopback exemption of the AppContainer, once per machine and policy. On Ubuntu 23.10 and newer, `sandy setup` installs an AppArmor profile which `ip = "private"` needs. On macOS, setup has nothing to do. An uninstaller runs `sandy setup --remove` with the same policy.
- **Root on Linux:** sandy refuses to run as root or with any capability, because those rights would survive the sandbox. Run the program as an unprivileged user.

## Notable Changes

### Commands

- `sandy run` starts the program only if the host enforces every requirement of the policy. Exit status 125 means that sandy failed or refused, and the program did not run, unless the program exited with 125 itself or sandy failed while it supervised the program (`children = "contained"` or `--explain`).
- `sandy check` prints one line per requirement with the mechanism which enforces it, or `UNAVAILABLE` with the reason. `UNDECIDED` and `CONFLICT` lines exit with 125, because they do not describe what the host can do. `check --json` gives the same result to a program.
- `sandy setup` prepares the host where that needs administrator rights. `--elevate` asks for the rights through `pkexec` on Linux or UAC on Windows, and only for a sandy file which only administrators can change. `--install-copy` installs a root-owned copy on Linux. `sandy setup --remove` takes back what setup and the runs of the policy left on the host.
- `--status-fd` and `--status-file` report the process ID of the program, so a caller can tell a refusal of sandy from a program which exits with 125 itself. Where sandy supervises the program (`children = "contained"`, `--explain`, and always on Windows), the record also says how the program ended. Otherwise sandy replaces itself with the program on Linux and macOS, the record ends after `pid`, and the caller's own wait status is the program's. A status file lies outside every writable path, so the program cannot change it.
- `--explain` and `--explain-path` (Linux) name the paths which a run needed but the policy does not grant, and the rule which decides a path.

### Policy

- File access: `read`, `read_exec` and `read_write` paths, a minimal set of system paths (`system = "minimal"`), and `view = "policy"`, which makes every path outside the policy look missing.
- Network: `ip` is `none`, `client`, `private` (a loopback of its own) or `all`. `expose` relays connections into the program, `forward` relays the program's connections to the host loopback, and `egress` adds a SOCKS5 broker which connects only to public addresses, or with `reach = "public-and-local"` also to addresses of the local network, and never to the host itself. Unix sockets are denied unless `unix_sockets = "all"`.
- Processes: `signals = "isolated"` keeps the program from signalling processes outside the sandbox. `end_with_parent`, with `--parent-pid` and `--parent-start`, ends the program with its caller. `children` is `allowed`, `none` or `contained`; with `contained` the child processes end with the program.
- Environment: the program gets only the variables which `pass_env` and `set_env` give it.
- Platform options: the AppContainer name and win32k access on Windows, path metadata changes on Linux, and on macOS the Mach service `com.apple.trustd.agent`, the certificate verifier of the system, as the only service which a policy can allow.
- Fallback levels: a policy lists weaker levels after its base. `check` and `run` take the first level which the host can enforce. sandy never moves to a weaker level for a reason that can pass, such as a timeout or a port which another process holds.

### Changes Since the Development Version 2.5.0

- macOS, `children = "contained"`: macOS can report a child which only stopped, for example on SIGTTIN after it read the terminal, to a query for exited children. sandy took such a report for the end of the program. It now takes only an exit as the end.
- macOS, `children = "contained"`: two processes created the process group of the program at the same time, and macOS could fail one of them with EPERM, which failed the run. Only one process creates the group now.
- Linux, arm64: the release binary is a static position-independent executable, which the kernel loads at a random address (since 2.5.0).
- Warnings: a policy path which holds the user's terminals (`/dev/pts`, or `/dev` or `/` above it) gets a warning, because read access lets the program read what the user types into other terminals (since 2.5.0).
- Release build: the macOS binaries are linked with rust-lld against declared libSystem symbols, the Windows binaries with lld-link against pinned Microsoft libraries, and the archives are packed by a tool of the repository. Build paths and build times are kept out of the binaries and archives.

### Platforms

| Platform | Mechanism | Requirements |
| --- | --- | --- |
| Linux | Landlock, up to four seccomp-bpf filters, `no_new_privs`, then `execve` | Linux 5.13 or newer with Landlock enabled. Runs on Ubuntu 22.04 and newer, Debian 12 and newer, Fedora, Arch, RHEL 9.6 and newer, openSUSE Leap and SLES 16. |
| macOS | A Seatbelt profile generated from the policy | Native code only; x86_64 code cannot run in the sandbox through Rosetta. Tested on macOS 26 and 27 (arm64). |
| Windows | An AppContainer with one capability per policy path, a job object and a list of inherited handles | Windows 10 1809 or newer, or Windows Server 2019 or newer. Every run needs an AppContainer name. |

### Security Model

The sandboxed program and all its children are assumed to be under the attacker's control. sandy protects the user's files outside the policy, other processes of the user, the user's privileges, the network as far as the policy denies it, and the host's local services on Unix sockets. sandy does not protect secrets which the program holds, the data in its `read_write` paths, the network traffic which `client` or `all` allows, the terminal which the program writes to, the availability of the machine, or against bugs of the operating system kernel. Independent reviews tried to escape the sandbox on every platform. Their findings were fixed or are documented as limitations, and a test holds each result (`crates/sandy-cli/tests/review_*.rs`).

### Release Archives and Verification

- The release has archives for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static PIE), `x86_64-apple-darwin`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` (static C runtime).
- `SHA256SUMS` lists every archive, and `SHA256SUMS.asc` signs it. The v1.0.0 release is signed by Alejandro García with the key `B493 3191 06CC 3D1F 252E 19CB F806 F422 E222 AA02`. Archives which the release workflow built carry a GitHub build provenance attestation.
- The archives are reproducible. `XWIN_ACCEPT_LICENSE=true scripts/reproduce.sh v1.0.0 DIRECTORY` builds all six archives of the tag in a pinned container, byte for byte as in the release. The variable accepts the license of the Visual Studio Build Tools, whose libraries the Windows archives link against; `scripts/reproduce.sh` and `scripts/check-release.sh` refuse to run without it. `scripts/check-release.sh` checks the signature, downloads the archives, builds them again and compares them. The `verify-release` workflow does the same on GitHub.
- The macOS binaries are not signed or notarized, and `sandy.exe` has no Authenticode signature. A program which ships sandy inside a signed macOS app signs it together with the app.

### Supply Chain and CI

- `Cargo.lock` pins every crate by its SHA-256 hash, and every cargo command of CI and the release build runs with `--locked`. `cargo deny` checks the allowed crates, advisories and licenses, and `cargo vet` requires an audit or an exemption for every crate version. The Rust toolchain is pinned by `rust-toolchain.toml` and checked before every build.
- CI runs the tests on Ubuntu 22.04 and 24.04 (x86_64), Ubuntu 24.04 (arm64), macOS 15, and Windows Server 2022 and 2025. The escape tests try each action outside the sandbox first, so a test cannot pass because the action was impossible anyway.
- The release workflow builds every target twice from two directories and compares the binaries, runs the suite against the packaged binaries, and attests their build provenance.

Details: [README.md](../../README.md), [docs/DESIGN.md](../../docs/DESIGN.md), [docs/linux.md](../../docs/linux.md), [docs/macos.md](../../docs/macos.md) and [docs/windows.md](../../docs/windows.md).

## Known Issues

- `scripts/check-release.sh` of v1.0.0 pins the key `F5F1 2A8E 8EC8 DDAD F770 9748 0047 60E7 7F75 3090`, but the release is signed by `B493 3191 06CC 3D1F 252E 19CB F806 F422 E222 AA02`, so the script refuses the release. Pass the key with `--key` (`XWIN_ACCEPT_LICENSE=true scripts/check-release.sh --key B493319106CC3D1F252E19CBF806F422E222AA02 v1.0.0`), or use the script of `main`, which pins the right key since `b0dd58f0`.
- On Linux, `/proc` is not readable by default, and GNU tar cannot extract an archive which holds a directory in the sandbox; `bsdtar` can.
- On Windows, `view = "policy"` is refused, because Windows cannot hide paths from an AppContainer.
- What stays visible from inside the sandbox differs by platform. Each platform document lists these limitations.

## Verification of These Notes

The notes were checked against the README, the platform documents and the scripts at the release commit, and against the commits of `main` after it. No build or test was run while writing them.
