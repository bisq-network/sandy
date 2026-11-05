#!/bin/sh
# Downloads everything that scripts/release-build.sh and scripts/release-pack.sh need, so that
# they can then run without network: the toolchain and its channel manifest
# (scripts/verify-toolchain.sh) and the crates of sandy and of tools/pack. Only the pinned toolchain
# and cargo run here, no code of a crate: cargo fetch runs no build script. The Windows libraries
# come apart from this (scripts/windows-sdk.sh).
#
#   scripts/release-fetch.sh
#
# The release workflows and scripts/reproduce.sh run this with network, then the build without
# (scripts/without-network.sh, or a container with --network none), so that no build script or
# procedural macro can fetch more code or send anything out while it runs.
set -eu

cd "$(dirname "$0")/.."

scripts/verify-toolchain.sh
cargo fetch --locked
cargo fetch --locked --manifest-path tools/pack/Cargo.toml
