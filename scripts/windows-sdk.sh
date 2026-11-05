#!/bin/sh
# Fetches and checks the libraries that scripts/release-build.sh links the Windows binaries
# against: the static C runtime of MSVC and the import libraries of the Windows SDK, both from
# Microsoft's package manifest of Visual Studio, which link/windows-sdk.sha256 pins.
#
#   XWIN_ACCEPT_LICENSE=true scripts/windows-sdk.sh fetch ARCH      (x86_64 or aarch64)
#   scripts/windows-sdk.sh unpack ARCH ARCHIVE
#   scripts/windows-sdk.sh check ARCH
#
# Each puts or expects the libraries in target/windows-sdk/ARCH and prints that directory.
#
# fetch runs xwin, which it installs into target/windows-sdk from the crate whose sum it names:
# xwin downloads the packages, checks each one against the sum the manifest gives it and unpacks
# the libraries. xwin and its dependencies are not reviewed, so fetch is meant to run apart from
# the build, in a container or CI job of its own whose only output is the libraries
# (scripts/reproduce.sh, .github/workflows/windows-sdk.yml). The release build only runs check,
# which needs neither xwin nor the network: it checks every library file and link against the
# pinned sum of the architecture, so the machine that fetched them need not be trusted.
#
# unpack extracts a gzipped tar of crt/lib and sdk/lib, as the CI job uploads it, refusing
# members that would land outside the directory (Python's tarfile "data" filter), then checks it.
#
# The packages are Microsoft's and come under the license of the Visual Studio Build Tools, which
# xwin shows without XWIN_ACCEPT_LICENSE; setting it accepts that license. Nothing of them is
# part of this repository.
#
# Pinning another version: change the manifest or the versions below, run fetch, and put the sums
# it reports into link/windows-sdk.sha256.
set -eu

cd "$(dirname "$0")/.."

# Visual Studio 18.11.3 (build 18.11.12328.437): the package manifest that its channel names. The
# sum in the URL is Microsoft's and is not the sum of the file; link/windows-sdk.sha256 holds that.
manifest_url=https://download.visualstudio.microsoft.com/download/pr/5f474104-723f-4007-bf4c-92e42a23dcc6/6feafaf09375b7a7534a79845739c8af4a61041fa2cf4b2d86b56a764c734b7f/VisualStudio.vsman
manifest_id=6feafaf09375b7a7534a79845739c8af4a61041fa2cf4b2d86b56a764c734b7f
manifest_version=18.11.12328.437
crt_version=14.51
sdk_version=10.0.26100
xwin_version=0.10.0
xwin_sum=e3ae2ef8d627ac8d97b3aeb67e4b711520154edca5cc80fbec551415c7b671ef

usage="usage: scripts/windows-sdk.sh fetch ARCH | unpack ARCH ARCHIVE | check ARCH"

fail() {
  echo "windows-sdk: $*" >&2
  exit 1
}

command=${1:-}
arch=${2:-}
case "$command" in
  fetch | check) [ $# = 2 ] || fail "$usage" ;;
  unpack) [ $# = 3 ] || fail "$usage" ;;
  *) fail "$usage" ;;
esac
case "$arch" in
  x86_64 | aarch64) ;;
  *) fail "no Windows libraries for $arch" ;;
esac
# xwin adds a link for each spelling of a file name that the libraries are looked up by, which a
# file system that ignores case cannot hold, so the sums hold on Linux only.
[ "$(uname -s)" = Linux ] || fail "handles the Windows libraries on Linux only"

pinned() {
  sed -n "s/^\([0-9a-f]\{64\}\)  $1\$/\1/p" link/windows-sdk.sha256
}

# One line per library file, with its sum, and per link, with its target, in a fixed order.
listing() {
  (cd "$1" && find crt/lib sdk/lib \( -type f -o -type l \) | LC_ALL=C sort | while read -r file; do
    if [ -L "$file" ]; then
      echo "link $file $(readlink "$file")"
    else
      echo "$(sha256sum < "$file" | cut -c1-64) $file"
    fi
  done) | sha256sum | cut -c1-64
}

dir=$PWD/target/windows-sdk
out=$dir/$arch
expected=$(pinned "$arch")
[ -n "$expected" ] || fail "link/windows-sdk.sha256 pins no libraries for $arch"

# Fails unless $out holds exactly the pinned libraries. The listing covers files and links only,
# so anything else in the tree, which no fetch makes, is refused too.
check() {
  [ -d "$out/crt/lib" ] && [ -d "$out/sdk/lib" ] ||
    fail "no $arch libraries in $out; fetch them with scripts/windows-sdk.sh fetch $arch"
  other=$(cd "$out" && find crt/lib sdk/lib ! -type f ! -type l ! -type d | head -n 1)
  [ -z "$other" ] || fail "$out/$other is neither a file, a link nor a directory"
  actual=$(listing "$out")
  [ "$actual" = "$expected" ] ||
    fail "the $arch libraries have the sum $actual, link/windows-sdk.sha256 pins $expected"
}

case "$command" in
  check)
    check
    echo "$out"
    exit 0
    ;;
  unpack)
    archive=$3
    [ -f "$archive" ] || fail "no archive $archive"
    rm -rf "$out"
    mkdir -p "$out"
    python3 -I -c 'import sys, tarfile; tarfile.open(sys.argv[1], "r:gz").extractall(sys.argv[2], filter="data")' \
      "$archive" "$out" || fail "could not unpack $archive"
    check
    echo "$out"
    exit 0
    ;;
esac

[ "${XWIN_ACCEPT_LICENSE:-}" = true ] ||
  fail "set XWIN_ACCEPT_LICENSE=true to accept the license of the Visual Studio Build Tools"
xwin=$dir/bin/xwin
"$xwin" --version 2> /dev/null | grep -qx "xwin $xwin_version" ||
  CARGO_INSTALL_ROOT=$dir scripts/install-tool.sh xwin "$xwin_version" "$xwin_sum" >&2
if [ -d "$out" ] && [ "$(listing "$out")" = "$expected" ]; then
  echo "$out"
  exit 0
fi

# The package manifest, checked here, where xwin finds it: xwin cannot check it itself, because
# the sum the channel gives for it is not the sum of the file.
mkdir -p "$dir/cache/dl"
vsman=$dir/cache/dl/pkg_manifest_$manifest_id.vsman
curl -fsS --proto '=https' --tlsv1.2 --retry 3 -o "$vsman.part" "$manifest_url"
sum=$(sha256sum < "$vsman.part" | cut -c1-64)
[ "$sum" = "$(pinned VisualStudio.vsman)" ] ||
  fail "the package manifest has the sum $sum, link/windows-sdk.sha256 pins another"
mv "$vsman.part" "$vsman"
# The channel manifest that names it, which is all xwin reads of a channel.
cat > "$dir/channel.json" << EOF
{"channelItems": [{"id": "Microsoft.VisualStudio.Manifests.VisualStudio",
  "version": "$manifest_version", "type": "Manifest", "payloads": [{"fileName": "VisualStudio.vsman",
  "sha256": "$manifest_id", "size": 0, "url": "$manifest_url"}]}]}
EOF

rm -rf "$out"
"$xwin" --log-level warn --cache-dir "$dir/cache" --manifest "$dir/channel.json" --arch "$arch" \
  --crt-version "$crt_version" --sdk-version "$sdk_version" splat --output "$out" >&2
check
echo "$out"
