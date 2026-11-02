#!/bin/sh
# Builds the release binary of sandy for TARGET from this checkout, the way every release binary
# is built, so that anyone can build it again and compare: the release workflow runs this, and so
# can you from a checkout of the release tag.
#
#   scripts/release-build.sh TARGET
#
# The output is target/TARGET/release/sandy (sandy.exe on Windows). It depends on the source, the
# Rust toolchain of rust-toolchain.toml, the host triple that runs it (README.md, "Building a
# release binary again"), and on Windows on the version of the platform's linker, which the
# release notes name. It does not depend on the directory of the checkout, the location of
# CARGO_HOME, the time of the build or the linker or SDK of the host.
set -eu

target=${1:?usage: scripts/release-build.sh TARGET}
cd "$(dirname "$0")/.."

scripts/verify-toolchain.sh

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
  aarch64-unknown-linux-musl)
    # rust-lld as below, through a script that links a static position-independent executable,
    # which rustc links by itself only for x86_64 (see the script).
    flags="$flags -C linker=$root/scripts/link-static-pie.sh -C linker-flavor=ld.lld"
    ;;
  *-linux-musl)
    # The linker of the Rust toolchain instead of the host's cc, whose version would change the
    # binary. The musl targets link their C runtime from the toolchain too.
    flags="$flags -C linker=rust-lld"
    ;;
  *-apple-darwin)
    # rust-lld instead of Apple's linker, whose version would change the binary and which only
    # the Command Line Tools or Xcode provide. It links against link/MacOSX.sdk, which declares
    # the symbols of libSystem that sandy uses, instead of Apple's SDK. rustc would record the
    # deployment target as the version of the SDK too; the second -platform_version, which
    # rust-lld takes over the first, records the SDK that the declarations follow, as Apple's
    # linker would. macOS keeps some old behaviour of its libraries for a binary built against an
    # older SDK, so this version is part of what the binary does.
    #
    # rust-lld derives the UUID of the binary from its contents, the debug map included, which
    # names object files by their path in the checkout. strip removes the map afterwards but keeps
    # the UUID. Without -S, which links no debug map, the binaries differ with the directory of the
    # checkout.
    min=$(rustc --print deployment-target --target "$target" | sed 's/^.*=//')
    flags="$flags -C linker=rust-lld -C linker-flavor=ld64.lld -C link-arg=-S"
    flags="$flags -C link-arg=-platform_version -C link-arg=macos -C link-arg=$min -C link-arg=27.0"
    # A search path, not SDKROOT, which would also reach the links of the build scripts on a Mac.
    # rust-lld searches it before the SDK that rustc names on a Mac; elsewhere there is no SDK,
    # and rustc warns that xcrun is missing.
    flags="$flags -L native=$root/link/MacOSX.sdk/usr/lib"
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
