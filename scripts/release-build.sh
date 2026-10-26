#!/bin/sh
# Builds the release binary of sandy for TARGET from this checkout, the way every release binary
# is built, so that anyone can build it again and compare: the release workflow runs this, and so
# can you from a checkout of the release tag.
#
#   scripts/release-build.sh TARGET
#
# The output is target/TARGET/release/sandy (sandy.exe on Windows). It depends on the source, the
# Rust toolchain of rust-toolchain.toml, and on macOS and Windows on the version of the platform's
# linker, which the release notes name. It does not depend on the directory of the checkout, the
# location of CARGO_HOME, the time of the build or the linker of a Linux host.
set -eu

target=${1:?usage: scripts/release-build.sh TARGET}
cd "$(dirname "$0")/.."

# The time of the commit, for anything that would otherwise record the time of the build. A
# source archive without the history of the tag gives it as SOURCE_DATE_EPOCH.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH

# Paths of the build machine must not end up in the binary: the checkout, and CARGO_HOME, from
# which the dependencies are compiled and whose path the locations of their panic messages keep.
# Git Bash on Windows names them as /c/..., rustc as C:\..., which is what the prefixes must match.
root=$PWD
cargo_home=${CARGO_HOME:-$HOME/.cargo}
if command -v cygpath > /dev/null 2>&1; then
  root=$(cygpath -w "$root")
  cargo_home=$(cygpath -w "$cargo_home")
fi
flags="--remap-path-prefix=$root=/sandy --remap-path-prefix=$cargo_home=/cargo"
case "$target" in
  *-linux-musl)
    # The linker of the Rust toolchain instead of the host's cc, whose version would change the
    # binary. The musl targets link their C runtime from the toolchain too.
    flags="$flags -C linker=rust-lld"
    ;;
  *-apple-darwin)
    # Apple's linker derives the UUID of the binary from the paths of the object files in its
    # debug map, which strip removes afterwards but the UUID keeps. Without the prefix, the binary
    # differs with the directory of the checkout.
    flags="$flags -C link-arg=-Wl,-oso_prefix,$root/"
    ;;
  *-windows-msvc)
    # The C runtime linked in, so that sandy.exe needs no Visual C++ redistributable, and no
    # time stamp of the link in the image (/Brepro).
    flags="$flags -C target-feature=+crt-static -C link-arg=/Brepro"
    ;;
esac
RUSTFLAGS="$flags"
export RUSTFLAGS

cargo build --release --locked --target "$target" -p sandy-cli --bin sandy
