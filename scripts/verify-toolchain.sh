#!/bin/sh
# Checks that the Rust toolchain in use is the one rust-toolchain.toml pins, installed by rustup from
# the archives that the pinned channel manifest names. rust-toolchain.sha256 holds the SHA-256 sum
# of that manifest; README.md ("The supply chain checks") says how to pin a new toolchain.
#
#   scripts/verify-toolchain.sh
#
# rustup checks every archive it installs against the hashes of the channel manifest it downloads,
# and keeps a copy of that manifest in the toolchain. This script installs the toolchain if it is
# missing, checks the manifest against the pinned sum, and checks that every archive hash of
# rustup's copy is one the pinned manifest names. A toolchain that rustup installed from any other
# manifest fails, and so does a rustc that rustup did not install. Nothing of the toolchain runs
# before these checks pass: rustup locates it without starting it, so a rustc that rewrites the
# manifest copy on its first start does not get the chance.
#
# The checked manifest is kept in target/toolchain, so a later run needs no network: the pinned sum
# decides, not where the file came from.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "verify-toolchain: $*" >&2
  exit 1
}

channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
manifest=channel-rust-$channel.toml
grep -q "  $manifest\$" rust-toolchain.sha256 || fail "rust-toolchain.sha256 does not pin $manifest"
# A RUSTC of the caller would be the compiler cargo runs, and it cannot be located without running it.
[ -z "${RUSTC:-}" ] || fail "RUSTC is set; unset it, so that cargo runs the toolchain of rustup"
command -v rustup > /dev/null 2>&1 || fail "needs rustup"

sum=sha256sum
command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"
pinned=$(sed -n "s/^\([0-9a-f]\{64\}\)  $manifest\$/\1/p" rust-toolchain.sha256)
copy=target/toolchain/$manifest
mkdir -p target/toolchain
if [ ! -f "$copy" ] || [ "$($sum < "$copy" | cut -c1-64)" != "$pinned" ]; then
  curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$copy.part" "https://static.rust-lang.org/dist/$manifest"
  [ "$($sum < "$copy.part" | cut -c1-64)" = "$pinned" ] || fail "$manifest does not match rust-toolchain.sha256"
  mv "$copy.part" "$copy"
fi

# The rustup proxies would install a missing toolchain on their own and start it at once; this
# installs it explicitly, with the components and targets of rust-toolchain.toml, and starts
# nothing. Installing from rust-toolchain.toml needs rustup 1.28 or later.
RUSTUP_AUTO_INSTALL=0
export RUSTUP_AUTO_INSTALL
if ! rustup which --toolchain "$channel" rustc > /dev/null 2>&1; then
  version=$(rustup --version 2> /dev/null | sed -n '1s/^rustup \([0-9.]*\).*/\1/p')
  [ "$(printf '%s\n' 1.28.0 "$version" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" = 1.28.0 ] ||
    fail "rustup $version is older than 1.28.0; update it with rustup self update"
  rustup toolchain install >&2
fi
rustc=$(rustup which --toolchain "$channel" rustc) || fail "rustup has no toolchain $channel"
if command -v cygpath > /dev/null 2>&1; then
  rustc=$(cygpath -u "$rustc")
fi
sysroot=$(dirname "$(dirname "$rustc")")
installed=$sysroot/lib/rustlib/multirust-channel-manifest.toml
[ -f "$installed" ] || fail "rustup did not install the toolchain in $sysroot"

# The archive hashes of a manifest, one line each with the table they belong to. rustup writes its
# copy in its own layout and leaves some keys out, so lines are compared, not files.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
hashes() {
  awk '{ sub(/\r$/, "") } /^\[/ { table = $0 } /^(xz_|zst_)?hash = / { print table, $0 }' "$1" | LC_ALL=C sort
}
hashes "$copy" > "$tmp/pinned"
hashes "$installed" > "$tmp/installed"
[ -s "$tmp/installed" ] || fail "$installed lists no archives"
unknown=$(LC_ALL=C comm -23 "$tmp/installed" "$tmp/pinned" | wc -l | tr -d ' ')
[ "$unknown" = 0 ] || fail "rustup installed the toolchain from a manifest other than the pinned $manifest ($unknown archive hashes differ)"

# Only now the toolchain runs, and it must be the pinned release.
release=$("$rustc" -vV | sed -n 's/^release: //p')
[ "$release" = "$channel" ] || fail "$rustc is $release, rust-toolchain.toml pins $channel"

echo "verify-toolchain: Rust $channel, installed from the pinned $manifest"
