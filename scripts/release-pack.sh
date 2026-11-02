#!/bin/sh
# Packs the release archive of TARGET from the binary that scripts/release-build.sh built: the
# binary, README.md and the two license files in a directory sandy-VERSION-TARGET, as
# dist/sandy-VERSION-TARGET.tar.gz, or .zip for Windows.
#
#   scripts/release-pack.sh TARGET
#
# tools/pack writes the archive, with sorted entries, the time of the commit on every entry, owner
# 0 and fixed permissions, compressed by the pure Rust deflate of flate2. Its output depends only
# on the files and the time, not on the host or its archive tools, so a release archive can be
# built again byte for byte.
set -eu

target=${1:?usage: scripts/release-pack.sh TARGET}
cd "$(dirname "$0")/.."

version=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
name=sandy-$version-$target
case "$target" in
  *-windows-*) exe=sandy.exe ext=zip ;;
  *) exe=sandy ext=tar.gz ;;
esac
# The time of the commit, as for the binary; a source archive without the history of the tag gives
# it as SOURCE_DATE_EPOCH.
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

cargo build --quiet --release --locked --manifest-path tools/pack/Cargo.toml
mkdir -p dist
tools/pack/target/release/sandy-pack "dist/$name.$ext" "$name" "$epoch" \
  "target/$target/release/$exe" README.md LICENSE-MIT LICENSE-APACHE
echo "dist/$name.$ext"
