#!/bin/sh
# Checks the cargo-vet records in supply-chain/: every crate version of Cargo.lock is covered by
# an imported audit, an audit of this repository, a trusted publisher or an exemption, no entry is
# left that nothing needs, and every audit, exemption and trusted publisher has notes.
#
#   scripts/check-audits.sh
#
# It uses the imported audits of supply-chain/imports.lock and fetches no new ones.
set -eu

cd "$(dirname "$0")/.."

cargo vet --locked

# What cargo vet prune would remove is an entry that nothing needs any more. The prune runs on a
# copy, so the checkout stays as it is.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R supply-chain "$tmp/"
cargo vet prune --locked --no-imports --store-path "$tmp/supply-chain" > /dev/null
if ! diff -ru supply-chain "$tmp/supply-chain"; then
  echo "check-audits: the entries above are no longer needed; remove them with cargo vet prune --no-imports" >&2
  exit 1
fi

awk '
  function check() {
    if (entry != "" && !notes) {
      print "check-audits: " file ": " entry " has no notes" > "/dev/stderr"
      bad = 1
    }
    entry = ""
  }
  FNR == 1 { check(); file = FILENAME }
  /^\[\[(audits|exemptions|trusted)\./ { check(); entry = $0; notes = 0; next }
  /^\[/ { check(); next }
  /^notes = / { notes = 1 }
  END { check(); exit bad }
' supply-chain/config.toml supply-chain/audits.toml

echo "check-audits: every crate is covered, and every audit, exemption and trusted publisher has notes"
