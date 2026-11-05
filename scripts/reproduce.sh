#!/bin/sh
# Builds and packs every release archive of REF (a tag or commit, HEAD by default) in a container,
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

# The image of this checkout's Dockerfile and toolchain, named by their sum so that a change
# builds a new one.
sha256=sha256sum
command -v sha256sum > /dev/null 2>&1 || sha256="shasum -a 256"
sum=$(cat scripts/reproduce.Dockerfile rust-toolchain.toml | $sha256 | cut -c1-16)
image=sandy-reproduce:$sum
tar -cf - scripts/reproduce.Dockerfile rust-toolchain.toml |
  docker build --platform linux/amd64 -f scripts/reproduce.Dockerfile -t "$image" - >&2

out=${out:-$PWD/dist/reproduced/$commit}
# Only archives of this run and their sums in it, not those of an earlier one.
mkdir -p "$out"
rm -f "$out"/sandy-*.tar.gz "$out"/sandy-*.zip "$out/SHA256SUMS"

# The source goes in and the archives come out as tar streams, without a bind mount: everything is
# built in the container's own file system, which keeps names that differ only in case apart
# (scripts/windows-sdk.sh needs that) also where the host's file system does not, as on macOS. The
# targets are those of the release workflow; HOME and CARGO_HOME are the container's, and the
# release build keeps their paths out of the binaries.
#
# The Windows libraries are fetched by xwin, whose code is not reviewed, so it runs in a container
# of its own, which ends before the build starts and leaves only the libraries, in a volume. The
# build mounts the volume read-only and checks every file against link/windows-sdk.sha256. A
# commit from before this split fetches them in the build container, with xwin.
if git show "$commit:scripts/windows-sdk.sh" | grep -q 'windows-sdk.sh fetch'; then
  volume=$(docker volume create)
  trap 'docker volume rm -f "$volume" > /dev/null' EXIT
  git archive "$commit" |
    docker run -i --rm --platform linux/amd64 --user 65534:65534 \
      -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e XWIN_ACCEPT_LICENSE=true \
      -v "$volume:/windows-sdk" "$image" sh -euc '
        mkdir /tmp/sandy && tar -x -C /tmp/sandy && cd /tmp/sandy
        for arch in x86_64 aarch64; do
          sdk=$(scripts/windows-sdk.sh fetch "$arch")
          mkdir "/windows-sdk/$arch"
          tar -c -C "$sdk" crt/lib sdk/lib | tar -x -C "/windows-sdk/$arch"
        done
      ' >&2
  set -- -v "$volume:/windows-sdk:ro"
else
  set -- -e XWIN_ACCEPT_LICENSE=true
fi
git archive "$commit" |
  docker run -i --rm --platform linux/amd64 --user 65534:65534 \
    -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e SOURCE_DATE_EPOCH="$epoch" "$@" \
    "$image" sh -euc '
      mkdir /tmp/sandy && tar -x -C /tmp/sandy && cd /tmp/sandy
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
