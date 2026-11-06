# sandy 1.1.0 Highlights

## Warnings With Stable IDs

Every warning now names a stable ID. A caller which has accepted a warning hides it with `--hide-warning ID` and still sees every other one, also those a later release adds.

## Links and Junctions in Policy Paths

A policy path named through a symbolic link on macOS, or through a junction on Windows, now works under that name. Access still follows the real path, and the program cannot change the link or the junction.

## Encrypted Home Directories on Linux

A program can now list a granted directory on eCryptfs, as Linux Mint and Ubuntu use for an encrypted home directory. Before, it could read and create files there but `ls` failed.

## Harder Release Builds

The Windows libraries are fetched apart from the build, the builds run without network, and a release needs a passing audit and an approved reviewer. `scripts/check-release.sh` checks the right release key without `--key`.

## Before Upgrading

Warning lines now read `warning: [ID] text`. On Windows, sandy adds a read entry to the user's junctions on the way to directory policy paths unless the policy sets `windows.junctions = "refuse"`.

See [notable changes](notable-changes.md) and [full release notes](full-release-notes.md) for details.
