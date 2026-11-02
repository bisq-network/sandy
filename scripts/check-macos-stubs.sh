#!/bin/sh
# Checks on a Mac that every symbol link/MacOSX.sdk/usr/lib/libSystem.tbd declares for an
# architecture is one that the libSystem of Apple's SDK exports for it. scripts/release-build.sh
# links the macOS binaries against that file instead of the SDK, so a symbol declared there that
# libSystem does not have would link, and fail only when the binary starts. Apple's linker is the
# judge: it must find each symbol, given with -u, in the SDK's libSystem.
#
#   scripts/check-macos-stubs.sh
set -eu

cd "$(dirname "$0")/.."

[ "$(uname -s)" = Darwin ] || {
  echo "check-macos-stubs: needs macOS, for the SDK and Apple's linker" >&2
  exit 1
}

sdk=$(xcrun --sdk macosx --show-sdk-path)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The symbols of each architecture, one per line: an exports entry names its targets, then its
# symbols, possibly over several lines, up to the closing bracket.
symbols() {
  awk -v want="$1-macos" -v quote="'" '
    /^ *- targets:/ { listed = index($0, want) > 0 }
    /^ *symbols:/ { reading = 1; sub(/^ *symbols: *\[/, "") }
    reading {
      line = $0
      done = sub(/\].*$/, "", line)
      gsub(/ /, "", line)
      gsub(quote, "", line)
      n = split(line, names, ",")
      for (i = 1; i <= n; i++) if (listed && names[i] != "") print names[i]
      if (done) reading = 0
    }
  ' link/MacOSX.sdk/usr/lib/libSystem.tbd
}

failed=0
for arch in arm64 x86_64; do
  symbols "$arch" > "$tmp/$arch"
  count=$(wc -l < "$tmp/$arch" | tr -d ' ')
  [ "$count" -gt 0 ] || { echo "check-macos-stubs: no symbols for $arch" >&2; exit 1; }
  set --
  while read -r name; do
    set -- "$@" -u "$name"
  done < "$tmp/$arch"
  if ld -arch "$arch" -platform_version macos 11.0 0 -syslibroot "$sdk" -dylib -lSystem \
    -o "$tmp/$arch.dylib" "$@" 2> "$tmp/$arch.err"; then
    echo "check-macos-stubs: $count $arch symbols, all exported by the libSystem of $sdk"
  else
    cat "$tmp/$arch.err" >&2
    failed=1
  fi
done
exit "$failed"
