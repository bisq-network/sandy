#!/bin/sh
# Installs rustup from the rustup-init that rustup-init.sha256 pins for this host, with no
# toolchain: scripts/verify-toolchain.sh installs the one rust-toolchain.toml pins. CI runs this
# instead of using the rustup of the runner image, whose version and origin this repository does
# not check; scripts/reproduce.Dockerfile takes the same pin.
#
#   RUSTUP_HOME=DIR CARGO_HOME=DIR scripts/install-rustup.sh
#
# rustup publishes no signature of rustup-init, only a sum next to it, so the pin is the sum as it
# was when the version was chosen.
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "install-rustup: $*" >&2
  exit 1
}

: "${RUSTUP_HOME:?set RUSTUP_HOME}" "${CARGO_HOME:?set CARGO_HOME}"
# The runner's own names first: Git Bash on an arm64 Windows runner may itself run emulated.
os=${RUNNER_OS:-$(uname -s)}
arch=${RUNNER_ARCH:-$(uname -m)}
case "$arch" in
  X64 | x86_64 | amd64) arch=x86_64 ;;
  ARM64 | aarch64 | arm64) arch=aarch64 ;;
  *) fail "no rustup-init for the architecture $arch" ;;
esac
case "$os" in
  Linux) triple=$arch-unknown-linux-gnu ;;
  macOS | Darwin) triple=$arch-apple-darwin ;;
  Windows | MINGW* | MSYS*) triple=$arch-pc-windows-msvc ;;
  *) fail "no rustup-init for the system $os" ;;
esac

line=$(grep "/$triple/" rustup-init.sha256) || fail "rustup-init.sha256 pins no rustup-init for $triple"
expected=${line%%  *}
path=${line#*  }
file=${path##*/}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$file" "https://static.rust-lang.org/rustup/archive/$path"
sum=sha256sum
command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"
actual=$($sum < "$tmp/$file" | cut -c1-64)
[ "$actual" = "$expected" ] || fail "$path has the sum $actual, rustup-init.sha256 pins $expected"
chmod +x "$tmp/$file"
"$tmp/$file" -y --no-modify-path --profile minimal --default-toolchain none >&2
# rustup would otherwise replace itself with its newest version on the first toolchain install.
"$CARGO_HOME/bin/rustup" set auto-self-update disable >&2
echo "install-rustup: rustup from the pinned $path"
