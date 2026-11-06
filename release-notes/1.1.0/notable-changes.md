# sandy 1.1.0 Notable Changes

Based on the fourteen commits of `main` after `v1.0.0` up to `e60d1289`. See the [full release notes](full-release-notes.md) for integration notes and known issues.

## Warnings

- Every `warning:` line names a stable ID in brackets: `warning: [ID] text`.
- `--hide-warning ID` hides warnings a caller has accepted, while every other one, also one a later release adds, still shows. `--no-warnings` hides all, and `--show-warning ID` keeps the named ones despite it.
- `check --json` keeps every warning and adds `warning_ids` beside each `warnings` array.

## Windows

- A directory policy path named through a junction now opens under that name. sandy adds one read entry, without inheritance and without any write right, to each junction of this user on the way, and `sandy setup --remove` takes it back.
- `windows.junctions = "refuse"` (or `--windows-junctions refuse`) keeps sandy from changing any junction and makes such a policy path a conflict. The new `junction-closed` warning names a junction which sandy leaves closed.

## Linux

- A program can now list a granted directory on eCryptfs, such as an encrypted home directory, instead of getting `EACCES`. sandy adds only the right to read the lower directory, and the new `ecryptfs-unlisted` warning names a directory whose lower directory it does not find.

## macOS

- A policy path named through a symbolic link now works instead of answering `ENOENT`. Access still follows the real path, and the program cannot change the link.

## Release and Supply Chain

- The Windows libraries are fetched apart from the build, and the release builds run without network and with an allowlisted environment.
- The release job needs a passing audit and an approved `release` environment, accepts only archives whose sums match their build job, and verifies the attestations strictly.
- `scripts/check-release.sh` pins the key which signs `SHA256SUMS` and requires a good signature.
- cargo-vet moves to 0.10.3, and Dependabot opens pull requests for security updates only.

## Integration Requirements

- A caller which matches warning text on standard error must accept the `[ID]` after `warning:`.
- A policy which sets `windows.junctions`, or a command line with the new options, needs 1.1.0.
- Policies keep the format `version = 1`; every 1.0.0 policy works unchanged.
