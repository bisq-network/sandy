#!/bin/sh
# Checks that the channel manifest which rust-toolchain.sha256 pins is signed by the Rust release
# key, keys/rust-release-key.asc (primary key 108F 6620 5EAE B0AA A8DD  5E1C 85AB 96E6 FA1B E5FE),
# so that the pin was taken from a genuine manifest. The audit workflow runs it; with --write, after
# a change of channel in rust-toolchain.toml, it writes the sum of the newly signed manifest
# into rust-toolchain.sha256 (README.md, "Pinning a new toolchain").
#
#   scripts/check-toolchain-signature.sh [--write]
#
# gpgv accepts only the keys of the keyring it is given, so no key of the user's own keyring can
# make the signature good. Needs curl and gpgv (with gpg to read the armored key).
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "check-toolchain-signature: $*" >&2
  exit 1
}

write=false
case "${1:-}" in
  "") ;;
  --write) write=true ;;
  *) fail "usage: scripts/check-toolchain-signature.sh [--write]" ;;
esac
for tool in curl gpg gpgv; do
  command -v "$tool" > /dev/null 2>&1 || fail "needs $tool"
done
sum=sha256sum
command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"

channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
manifest=channel-rust-$channel.toml

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for file in "$manifest" "$manifest.asc"; do
  curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$file" "https://static.rust-lang.org/dist/$file"
done
gpg --quiet --dearmor < keys/rust-release-key.asc > "$tmp/rust.gpg"
status=$(gpgv --status-fd 1 --keyring "$tmp/rust.gpg" "$tmp/$manifest.asc" "$tmp/$manifest" 2> /dev/null) ||
  fail "$manifest is not signed by the Rust release key"
printf '%s\n' "$status" | grep -q '^\[GNUPG:\] VALIDSIG .* 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE$' ||
  fail "$manifest is not signed by the Rust release key"

actual=$($sum < "$tmp/$manifest" | cut -c1-64)
if [ "$write" = true ]; then
  echo "$actual  $manifest" > rust-toolchain.sha256
  echo "check-toolchain-signature: $manifest is signed by the Rust release key; wrote its sum to rust-toolchain.sha256"
  exit 0
fi
grep -qx "$actual  $manifest" rust-toolchain.sha256 ||
  fail "rust-toolchain.sha256 does not pin the signed $manifest, whose sum is $actual"
echo "check-toolchain-signature: the pinned $manifest is signed by the Rust release key"
