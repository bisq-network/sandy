#!/bin/sh
# Builds and packs every release archive of REF (a tag or commit, HEAD by default) in containers,
# the way the release workflow does, and writes them with their SHA256SUMS to DIRECTORY, by
# default dist/reproduced/COMMIT of this checkout, which git ignores. The archives have the names
# and the bytes of the ones the release of that commit publishes, and SHA256SUMS the form of the
# release's file, so every line matches when the release was built from the same commit;
# scripts/check-release.sh does that comparison.
#
#   XWIN_ACCEPT_LICENSE=true scripts/reproduce.sh [REF [DIRECTORY]]
#
# Needs git and Docker; the container is an x86_64 Linux host (scripts/reproduce.Dockerfile), the
# triple that every release binary is built on, emulated on other hosts. The Windows archives link
# against Microsoft's libraries, which come under the license of the Visual Studio Build Tools:
# XWIN_ACCEPT_LICENSE=true accepts it (scripts/windows-sdk.sh). The source is that of REF as git
# holds it, without changes of the working tree.
set -eu

ref=${1:-HEAD}
# A directory given relative to where the script was started from.
out=${2:-}
case "$out" in
  "" | /*) ;;
  *) out=$PWD/$out ;;
esac
cd "$(dirname "$0")/.."

fail() {
  echo "reproduce: $*" >&2
  exit 1
}

[ "${XWIN_ACCEPT_LICENSE:-}" = true ] ||
  fail "set XWIN_ACCEPT_LICENSE=true to accept the license of the Visual Studio Build Tools"
commit=$(git rev-parse --verify --quiet "$ref^{commit}") || fail "$ref is not a commit"
epoch=$(git log -1 --format=%ct "$commit")
git cat-file -e "$commit:scripts/release-pack.sh" 2> /dev/null ||
  fail "$ref has no scripts/release-pack.sh, so its archives cannot be packed this way"

# A local tag is compared with the tag of that name on the project's remote: a clone can hold a
# tag of the same name for another commit, and would build the wrong code.
# scripts/check-release.sh fetches the tag from the remote instead, and passes a commit.
if git show-ref --verify --quiet "refs/tags/$ref"; then
  repo=${SANDY_REPOSITORY:-bisq-network/sandy}
  remote=$(git remote -v | awk -v repo="$repo" '$2 ~ "[:/]" repo "(\\.git)?$" { print $1; exit }')
  if [ -z "$remote" ]; then
    echo "reproduce: no remote of $repo to compare the local tag $ref with" >&2
  elif theirs=$(git ls-remote "$remote" "refs/tags/$ref"); then
    theirs=$(printf '%s\n' "$theirs" | cut -f1)
    if [ -z "$theirs" ]; then
      echo "reproduce: $remote has no tag $ref; building the local one" >&2
    else
      [ "$theirs" = "$(git rev-parse "refs/tags/$ref")" ] ||
        fail "the local tag $ref is not the tag $ref of $remote ($theirs); fetch it with git fetch $remote tag $ref --force"
    fi
  else
    echo "reproduce: could not reach $remote to compare the local tag $ref" >&2
  fi
fi

# The image of this checkout's Dockerfile, toolchain and rustup pin, named by their sum so that a
# change builds a new one. SANDY_REPRODUCE_NO_CACHE=true builds it without Docker's cache, so that
# no layer of an earlier build is taken over; scripts/check-release.sh sets it.
sha256=sha256sum
command -v sha256sum > /dev/null 2>&1 || sha256="shasum -a 256"
context="scripts/reproduce.Dockerfile rust-toolchain.toml rustup-init.sha256"
# shellcheck disable=SC2086
sum=$(cat $context | $sha256 | cut -c1-16)
image=sandy-reproduce:$sum
no_cache=
[ "${SANDY_REPRODUCE_NO_CACHE:-}" != true ] || no_cache=--no-cache
# shellcheck disable=SC2086
tar -cf - $context |
  docker build $no_cache --platform linux/amd64 -f scripts/reproduce.Dockerfile -t "$image" - >&2

out=${out:-$PWD/dist/reproduced/$commit}
# Only archives of this run and their sums in it, not those of an earlier one.
mkdir -p "$out"
rm -f "$out"/sandy-*.tar.gz "$out"/sandy-*.zip "$out/SHA256SUMS"

# The source goes in and the archives come out as tar streams, without a directory shared with the
# host: everything is built in the container's own file system, which keeps names that differ only
# in case apart (scripts/windows-sdk.sh needs that) also where the host's file system does not, as
# on macOS. HOME and CARGO_HOME are the container's, and the release build keeps their paths out of
# the binaries.
#
# What is fetched comes from containers of its own, through volumes that the builds mount
# read-only:
# - The Windows libraries, fetched by xwin, whose code is not reviewed. The build checks every
#   file against link/windows-sdk.sha256.
# - The crates and the toolchain manifest, fetched by scripts/release-fetch.sh, where only the
#   pinned toolchain and cargo run. The builds then run without network (--network none), so no
#   build script or procedural macro can fetch more code or send anything out.
# All six targets are built in one container, one after the other, and the toolchain of the image,
# owned by root, is checked to be out of reach of the user the build runs as. Code that runs while
# one target is built could still change what a later one is built from, but only into archives
# that differ from those of the release workflow, which builds each target on a runner of its own:
# a false "differs", never a hidden change. A commit from before these splits fetches what its own
# scripts fetch, in the build container and with network.
volumes=
trap 'for volume in $volumes; do docker volume rm -f "$volume" > /dev/null; done' EXIT
run() {
  git archive "$commit" |
    docker run -i --rm --platform linux/amd64 --user 65534:65534 \
      -e HOME=/tmp -e CARGO_HOME=/tmp/cargo "$@"
}
set -- -e XWIN_ACCEPT_LICENSE=true
if git show "$commit:scripts/windows-sdk.sh" | grep -q 'windows-sdk.sh fetch'; then
  sdk=$(docker volume create)
  volumes="$volumes $sdk"
  run -e XWIN_ACCEPT_LICENSE=true -v "$sdk:/windows-sdk" "$image" sh -euc '
    mkdir /tmp/sandy && tar -x -C /tmp/sandy && cd /tmp/sandy
    for arch in x86_64 aarch64; do
      dir=$(scripts/windows-sdk.sh fetch "$arch")
      mkdir "/windows-sdk/$arch"
      tar -c -C "$dir" crt/lib sdk/lib | tar -x -C "/windows-sdk/$arch"
    done
  ' >&2
  set -- -v "$sdk:/windows-sdk:ro"
fi
if git cat-file -e "$commit:scripts/release-fetch.sh" 2> /dev/null; then
  deps=$(docker volume create)
  volumes="$volumes $deps"
  run -v "$deps:/deps" "$image" sh -euc '
    mkdir /tmp/sandy && tar -x -C /tmp/sandy && cd /tmp/sandy
    scripts/release-fetch.sh
    cp -R /tmp/cargo/registry target/toolchain /deps/
  ' >&2
  set -- "$@" -v "$deps:/deps:ro" --network none -e CARGO_NET_OFFLINE=true
fi
run -e SOURCE_DATE_EPOCH="$epoch" "$@" "$image" sh -euc '
    writable=$(find "$RUSTUP_HOME" /usr/local/cargo -writable -print -quit)
    [ -z "$writable" ] || { echo "reproduce: the build can write $writable of the toolchain" >&2; exit 1; }
    mkdir /tmp/sandy && tar -x -C /tmp/sandy && cd /tmp/sandy
    if [ -d /deps/registry ]; then
      mkdir -p /tmp/cargo target
      cp -R /deps/registry /tmp/cargo/
      cp -R /deps/toolchain target/
    fi
    if [ -d /windows-sdk/x86_64 ]; then
      mkdir -p target/windows-sdk
      ln -s /windows-sdk/x86_64 /windows-sdk/aarch64 target/windows-sdk/
    fi
    for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
      x86_64-apple-darwin aarch64-apple-darwin \
      x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
      scripts/release-build.sh "$target" >&2
      scripts/release-pack.sh "$target" >&2
    done
    tar -c -C dist .
  ' | tar -x -C "$out"
# A pipe does not pass on the exit status of the container, so the archives are counted.
[ "$(ls "$out" | grep -c -e '^sandy-.*\.tar\.gz$' -e '^sandy-.*\.zip$')" = 6 ] ||
  fail "the build in the container did not make all six archives (its output is above)"
# The form of the release's SHA256SUMS.
(cd "$out" && $sha256 ./sandy-*.tar.gz ./sandy-*.zip | sed 's| \./| |' > SHA256SUMS)
cat "$out/SHA256SUMS"
echo "reproduce: the archives of $commit are in $out" >&2
