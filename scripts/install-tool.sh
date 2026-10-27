#!/bin/sh
# Installs a cargo tool that the checks of this repository run, built with the pinned toolchain from
# the crate whose SHA-256 sum is given, with the dependencies its own lock file pins.
#
#   scripts/install-tool.sh NAME VERSION SHA256
#
# `cargo install --locked NAME@VERSION` would check the crate only against the sum that the
# crates.io index serves at the time; the sum given here is the one recorded when the version was
# chosen.
set -eu

name=${1:?usage: scripts/install-tool.sh NAME VERSION SHA256}
version=${2:?usage: scripts/install-tool.sh NAME VERSION SHA256}
expected=${3:?usage: scripts/install-tool.sh NAME VERSION SHA256}
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
crate=$name-$version.crate
curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$crate" "https://static.crates.io/crates/$name/$crate"
sum=sha256sum
command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"
echo "$expected  $crate" > "$tmp/pin"
(cd "$tmp" && $sum --check --status pin) || { echo "install-tool: $crate does not have the sum $expected" >&2; exit 1; }
tar -xzf "$tmp/$crate" -C "$tmp"
cargo install --locked --path "$tmp/$name-$version"
