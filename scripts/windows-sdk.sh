#!/bin/sh
# Fetches the libraries that scripts/release-build.sh links the Windows binaries against: the
# static C runtime of MSVC and the import libraries of the Windows SDK, both from Microsoft's
# package manifest of Visual Studio, which link/windows-sdk.sha256 pins. xwin, which this script
# installs into target/windows-sdk from the crate whose sum it names, downloads the packages,
# checks each one against the sum the manifest gives it and unpacks the libraries; this script
# then checks every library file and link it made against the pinned sum of the architecture, and
# prints the directory that holds them.
#
#   XWIN_ACCEPT_LICENSE=true scripts/windows-sdk.sh ARCH       (x86_64 or aarch64)
#
# The packages are Microsoft's and come under the license of the Visual Studio Build Tools, which
# xwin shows without XWIN_ACCEPT_LICENSE; setting it accepts that license. Nothing of them is
# part of this repository.
#
# Pinning another version: change the manifest or the versions below, run the script, and put
# the sums it reports into link/windows-sdk.sha256.
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

fail() {
  echo "windows-sdk: $*" >&2
  exit 1
}

arch=${1:?usage: scripts/windows-sdk.sh x86_64|aarch64}
case "$arch" in
  x86_64 | aarch64) ;;
  *) fail "no Windows libraries for $arch" ;;
esac
# xwin adds a link for each spelling of a file name that the libraries are looked up by, which a
# file system that ignores case cannot hold, so the sums hold on Linux only.
[ "$(uname -s)" = Linux ] || fail "fetches the Windows libraries on Linux only"
[ "${XWIN_ACCEPT_LICENSE:-}" = true ] ||
  fail "set XWIN_ACCEPT_LICENSE=true to accept the license of the Visual Studio Build Tools"

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
xwin=$dir/bin/xwin
"$xwin" --version 2> /dev/null | grep -qx "xwin $xwin_version" ||
  CARGO_INSTALL_ROOT=$dir scripts/install-tool.sh xwin "$xwin_version" "$xwin_sum" >&2
expected=$(pinned "$arch")
[ -n "$expected" ] || fail "link/windows-sdk.sha256 pins no libraries for $arch"
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
actual=$(listing "$out")
[ "$actual" = "$expected" ] ||
  fail "the $arch libraries have the sum $actual, link/windows-sdk.sha256 pins $expected"
echo "$out"
