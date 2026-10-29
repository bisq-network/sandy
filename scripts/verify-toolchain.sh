#!/bin/sh
# Checks that the Rust toolchain in use is the one rust-toolchain.toml pins, installed by rustup from
# the archives that the pinned channel manifest names. rust-toolchain.sha256 holds the SHA-256 sum
# of that manifest; README.md ("The supply chain checks") says how to pin a new toolchain.
#
#   scripts/verify-toolchain.sh
#
# rustup checks every archive it installs against the hashes of the channel manifest it downloads,
# and keeps a copy of that manifest in the toolchain. This script downloads the manifest again,
# checks it against the pinned sum, and checks that every archive hash of rustup's copy is one the
# pinned manifest names. A toolchain that rustup installed from any other manifest fails, and so
# does a rustc that rustup did not install.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "verify-toolchain: $*" >&2
  exit 1
}

channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
manifest=channel-rust-$channel.toml
grep -q "  $manifest\$" rust-toolchain.sha256 || fail "rust-toolchain.sha256 does not pin $manifest"

rustc=${RUSTC:-rustc}
release=$("$rustc" -vV | sed -n 's/^release: //p')
[ "$release" = "$channel" ] || fail "$rustc is $release, rust-toolchain.toml pins $channel"
sysroot=$("$rustc" --print sysroot)
if command -v cygpath > /dev/null 2>&1; then
  sysroot=$(cygpath -u "$sysroot")
fi
installed=$sysroot/lib/rustlib/multirust-channel-manifest.toml
[ -f "$installed" ] || fail "rustup did not install the toolchain in $sysroot"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$manifest" "https://static.rust-lang.org/dist/$manifest"
sum=sha256sum
command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"
grep "  $manifest\$" rust-toolchain.sha256 > "$tmp/pin"
(cd "$tmp" && $sum --check --status pin) || fail "$manifest does not match rust-toolchain.sha256"

# The archive hashes of a manifest, one line each with the table they belong to. rustup writes its
# copy in its own layout and leaves some keys out, so lines are compared, not files.
hashes() {
  awk '{ sub(/\r$/, "") } /^\[/ { table = $0 } /^(xz_|zst_)?hash = / { print table, $0 }' "$1" | LC_ALL=C sort
}
hashes "$tmp/$manifest" > "$tmp/pinned"
hashes "$installed" > "$tmp/installed"
[ -s "$tmp/installed" ] || fail "$installed lists no archives"
unknown=$(LC_ALL=C comm -23 "$tmp/installed" "$tmp/pinned" | wc -l | tr -d ' ')
[ "$unknown" = 0 ] || fail "rustup installed the toolchain from a manifest other than the pinned $manifest ($unknown archive hashes differ)"

echo "verify-toolchain: Rust $channel, installed from the pinned $manifest"
