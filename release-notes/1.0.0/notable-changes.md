# sandy 1.0.0 Notable Changes

Based on the release `v1.0.0` at `e755aeb1a5dd0ffe9a83845128bfb1a0b8bcd3e8`, the first public release. See the [full release notes](full-release-notes.md) for integration notes and known issues.

## Sandbox

- sandy runs a program in the sandbox of the operating system: Landlock and seccomp on Linux, Seatbelt on macOS, an AppContainer with a job object on Windows. One policy works on all three.
- sandy fails closed. `sandy run` starts the program only if the host enforces every requirement of the policy, and exits with 125 otherwise.
- A policy controls file access, an optional hidden view of other paths, the network (`none`, `client`, `private` or `all`), relays into and out of the program, a SOCKS5 egress broker to public addresses (optionally also the local network), Unix sockets, signals, child processes and the environment.
- Fallback levels let one policy run on hosts with different hardening. sandy takes the first level which the host can enforce, and never a weaker level for a reason that can pass.

## Commands

- `sandy check` names, for each requirement, the mechanism which enforces it or the reason why the host cannot. `check --json` gives the same to a program.
- `sandy setup` prepares the host where that needs administrator rights: the loopback exemption on Windows, an AppArmor profile on Ubuntu 23.10 and newer. `sandy setup --remove` takes it back.
- `--status-fd` and `--status-file` tell a caller whether the program ran, and, where sandy supervises the program, how it ended. `--explain` names the paths which a Linux run needed but did not get.

## Changes Since the Development Version 2.5.0

- Contained programs on macOS no longer end the run early when they stop on a terminal signal, and no longer fail on a race when their process group is created.
- The release archives are reproducible from the tag, also in a pinned container.

## Release and Supply Chain

- The release has archives for Linux, macOS and Windows on x86_64 and arm64. `SHA256SUMS` is signed by the release key `B493 3191 06CC 3D1F 252E 19CB F806 F422 E222 AA02`, and the workflow archives carry build provenance attestations.
- Crates are pinned by hash and checked with `cargo deny` and `cargo vet`. The Rust toolchain is pinned.

## Integration Requirements

- Install sandy and its policies outside every writable path of a policy.
- On Linux, run sandy as an unprivileged user without capabilities.
- On Windows, give every run an AppContainer name, and run `sandy setup` once per machine and policy with administrator rights.
- A caller which compares versions must treat 1.0.0 as newer than the development versions up to 2.5.0.
- To check the release with `scripts/check-release.sh` of v1.0.0, run `XWIN_ACCEPT_LICENSE=true scripts/check-release.sh --key B493319106CC3D1F252E19CBF806F422E222AA02 v1.0.0`.
