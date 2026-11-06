# sandy 1.1.0 Release Notes

sandy 1.1.0 adds stable IDs to every warning with options to hide accepted ones, makes policy paths named through symbolic links work on macOS and through junctions on Windows, lets programs list granted directories on eCryptfs on Linux, and hardens how releases are built and checked.

## Scope

These notes describe the release `v1.1.0` of `bisq-network/sandy`. They cover the fourteen commits of `main` after `v1.0.0` (`e755aeb1`) up to `e60d1289`, plus the commit that sets the version to 1.1.0. The commit of the tag is given with the published release. `Cargo.toml` declares version `1.1.0`, and policies keep the format `version = 1`. The notes were checked against the README, the platform documents and the commit messages. No build or test was run while writing them.

## Upgrade and Integration Notes

- **Policies:** every policy of 1.0.0 works unchanged. A policy which sets the new key `windows.junctions` needs 1.1.0, because 1.0.0 refuses unknown keys. The same holds for a command line with `--hide-warning`, `--show-warning`, `--no-warnings` or `--windows-junctions`.
- **Warning lines:** each `warning:` line now names its ID in brackets, `warning: [ID] text`. This includes the line which `run` prints when it takes a fallback level: `warning: [fallback-level] running fallback level ...`. A caller which matches warning text on standard error must accept the ID. `check --json` keeps the `warnings` texts without prefix and ID, and adds `warning_ids` beside each `warnings` array, in the same order. The IDs stay stable; the texts can change.
- **Windows junctions:** by default (`windows.junctions = "grant"`), sandy now adds one read entry to each junction of this user on the way to a directory policy path, so that the program can open the directory under the junction's name. The entry has no write right and grants nothing below the junction. `sandy setup --remove` takes these entries back, as it does the entries on policy paths. A caller which must not change any junction sets `windows.junctions = "refuse"` (or `--windows-junctions refuse`); a directory policy path which would need the entry is then a conflict, `check` reports it, and `run` refuses with status 125.
- **Linux eCryptfs:** on an encrypted home directory (eCryptfs, as Linux Mint and Ubuntu make it), sandy now adds a Landlock rule with only the right to read a directory for the lower directory of each granted directory the program may list. `check --explain-path` names such a rule as one that allows "list". Where sandy finds no lower directory, `check` warns with the new `ecryptfs-unlisted` warning.
- **macOS symbolic links:** a policy path named through a symbolic link now works. The program can read the link's own metadata and target text, and the metadata of the directories above it. Keep the directories which hold such links out of reach of other processes, as for the parents of policy paths.
- **Checking a release:** `scripts/check-release.sh` now pins the key which signs `SHA256SUMS`, `B493 3191 06CC 3D1F 252E 19CB F806 F422 E222 AA02`, so `--key` is no longer needed. It also requires a `GOODSIG`, fails on an expired, revoked or bad signature, and refuses a `SHA256SUMS` entry beyond the six archives. `gh attestation verify` should name the workflow, the tag and the commit of the release, with gh 2.102.0 or newer; the README shows the command.

## Notable Changes

### Warnings

- Every warning carries a stable ID, such as `signals-any`, `writable-home` or `fallback-level`. The README lists all IDs with their platforms.
- `--hide-warning ID` (repeatable) leaves out the warnings which a caller has accepted. Every other warning still shows, also one which a later release adds.
- `--no-warnings` leaves out every warning, and `--show-warning ID` (repeatable) keeps the named ones despite it, so `--no-warnings --show-warning fallback-level` prints only the fallback level line.
- An ID given to both `--hide-warning` and `--show-warning` is an error, and so is an unknown ID. The IDs of every platform are accepted on every platform, so one command line serves all of them.
- The options apply to `run` and `check`. Hiding changes nothing which sandy enforces, and `check --json` keeps every warning with its ID.

### Windows: Junctions on the Way to Directory Policy Paths

- Windows checks the access which a program asks for on a junction itself when the path ends at it. A directory policy path named through a junction therefore could not be listed or opened under that name, while files below it opened.
- For each junction which the policy's names pass and which leads to a directory policy path or into one, also each one of a chain, sandy adds one `FILE_GENERIC_READ` entry without inheritance on the junction object, for the capability `sandy.junction.r.<volume>.<file ID>.<AppContainer>`. The capability differs from that of a path grant on purpose, because a directory turned into a junction keeps its file ID.
- sandy opens the junction itself (`FILE_FLAG_OPEN_REPARSE_POINT`), checks its reparse tag and identity, and reads and writes the DACL on that handle. The program cannot change the junction's data, attributes, owner or DACL, delete it or repoint it, and the target's permissions still decide what lies below it, also when a process outside repoints the junction during the run.
- sandy adds no entry to a junction without a DACL, one which every AppContainer may read already, one with entries it cannot evaluate, one with a deny entry for the user or one of its groups which takes listing away, or one of another owner. Only junctions owned by the token's user or default owner are changed. A junction left closed keeps only its name closed, as before, and `check` names it in the new `junction-closed` warning with the reason and a remedy.
- New option: `windows.junctions = "grant" | "refuse"` in the policy, `--windows-junctions grant|refuse` on the command line. The default is `grant`.
- Tests compare the whole DACL in SDDL before a grant, after it and after the removal, for a junction and for a directory policy path: inherited entries, protection, automatic inheritance, a conditional entry and a non-canonical order stay as they were.

### Linux: Granted Directories on eCryptfs

- eCryptfs opens the lower directory of a directory with the credentials of the process which opens it, and Landlock checks that open against the lower path, which no rule names. A program could therefore read and create files in a granted directory on an encrypted home directory but not list it: `ls` failed with `EACCES`, and a program which checks its directory before it starts refused to run.
- sandy now adds a rule with the right to read a directory, and no other right, for the lower directory of every granted directory which the program may list: the policy path itself when it lies on eCryptfs, and the root of every eCryptfs mount beneath it. The rule shows the program the entries it already lists, under their encrypted names, and none of the lower files' contents. The file system view does not show the lower directory.
- sandy finds the lower directory by inode, starting at the mount's source. On an encrypted home the source is a link inside the home, which a program granted the home could repoint, so sandy uses the directory it leads to only when it lies on the file system whose ID eCryptfs reports and has the inode of the mount's root. A file system which reports no ID is never trusted.
- Where sandy finds no lower directory, for example for a bind mount of an eCryptfs subdirectory, it adds no rule, and `check` warns (`ecryptfs-unlisted`).
- CI installs ecryptfs-utils on the `ubuntu-24.04` runner and requires the test, so a lost mount fails the job instead of being skipped.

### macOS: Policy Paths Named Through Symbolic Links

- A policy path named through a symbolic link, such as a data directory reached through a link, answered `ENOENT` for every path below it. sandy grants the canonical path, and Seatbelt also checks the lookup of the path as the program spells it.
- The generated profile now allows `file-read-metadata` and `file-test-existence` on the links which the policy's names pass, and `file-test-existence` below them for the spelled paths. These links count as granted for the ancestor rule, so `realpath` works through them.
- Access still follows the real path. A file next to a granted one, a link which the policy does not pass, and a target which a link is repointed to during the run still look missing. No rule allows a write on a link, and the resolver keeps refusing a policy path resolved through an entry inside a writable path, so the program cannot delete, rename or replace one. Each such change is tested against a control outside the sandbox.

### Release Build and Supply Chain

- **Windows libraries fetched apart from the build.** xwin and its dependencies are not reviewed, so the release build no longer runs them. `scripts/windows-sdk.sh` has the commands `fetch`, `check` and `unpack`; `scripts/release-build.sh` only runs `check` against `link/windows-sdk.sha256`. In CI a job of its own (`windows-sdk.yml`) fetches the libraries, and `scripts/reproduce.sh` fetches them in a container of its own. `WINDOWS_SDK_FETCH=true` lets a local build fetch them on the same machine; CI refuses it.
- **Builds without network.** `scripts/release-fetch.sh` fetches the toolchain manifest and the crates first; the release builds then run without network, in CI through a network namespace and in `scripts/reproduce.sh` in a container with `--network none` and read-only inputs. `scripts/release-env.sh` runs the build and pack scripts with an allowlisted environment and refuses a cargo `config.toml` outside the repository.
- **Toolchain.** `scripts/verify-toolchain.sh` installs a missing toolchain and checks it before rustc runs once. `scripts/check-toolchain-signature.sh` checks the pinned manifest against the committed Rust release key (`keys/rust-release-key.asc`). CI installs rustup from the sums in `rustup-init.sha256` instead of the rustup of the runner image.
- **Pinned inputs documented.** `scripts/reproduce.Dockerfile` records where the digest of the Debian base image comes from, and pins the sums of the snapshot's `InRelease` files. The README explains how to check the signature of the Visual Studio manifest which the Windows libraries come from.
- **Release workflow.** The release job needs the `audit` workflow to pass and a reviewer of the `release` environment to approve, requires exactly the six archives, checks each archive against the SHA-256 sum which its build job reported, and verifies the attestations in the strict form. `verify-release.yml` fails on extra release assets.
- **cargo-vet 0.10.3.** cargo-vet moved from 0.10.2 to 0.10.3 (RUSTSEC-2026-0381, RUSTSEC-2026-0068), and the review step of the README uses `--mode=local`, so a review reads the files which cargo builds.
- **Dependency updates.** Dependabot opens pull requests for security updates only. Other updates stay manual, one pull request per new crate version, once it has been out for a week unless it fixes a RustSec advisory.

### Fixes

- `scripts/check-release.sh` pins the key which signs `SHA256SUMS` and fetches it from GitHub and keys.openpgp.org. The script of v1.0.0 refused every release without `--key`.

### Platforms

Unchanged from 1.0.0: Linux 5.13 or newer with Landlock, macOS with native code only (tested on macOS 26 and 27, arm64), Windows 10 1809 or newer and Windows Server 2019 or newer. The release has archives for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`, listed in `SHA256SUMS`, which `SHA256SUMS.asc` signs with the release key.

Details: [README.md](../../README.md), [docs/DESIGN.md](../../docs/DESIGN.md), [docs/linux.md](../../docs/linux.md), [docs/macos.md](../../docs/macos.md) and [docs/windows.md](../../docs/windows.md).

## Known Issues

- On Windows, sandy reads and writes a DACL in two calls with nothing to compare and swap, so a change which `icacls` or another program makes to the same junction or policy path between the two is lost. sandy's lock serializes only its own runs.
- On Windows, the security API sets the flag of automatic inheritance (`AI`) on every list it writes, so a junction or policy path whose list lacks it gains it with sandy's first entry and keeps it after the removal. It does not change who may open the object.
- On Linux, a granted directory on eCryptfs whose lower directory sandy does not find, such as a bind mount of an eCryptfs subdirectory, still cannot be listed; `check` names it in the `ecryptfs-unlisted` warning. Where the lower file system is mounted read-only, eCryptfs does not retry a file open with its own credentials, and sandy's rule grants only listing, so such files still fail to open.
- On Linux, `/proc` is not readable by default, and GNU tar cannot extract an archive which holds a directory in the sandbox; `bsdtar` can.
- On Windows, `view = "policy"` is refused, because Windows cannot hide paths from an AppContainer.
- What stays visible from inside the sandbox differs by platform. Each platform document lists these limitations.
