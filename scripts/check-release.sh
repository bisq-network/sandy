#!/bin/sh
# Checks that a published release of sandy is built from its tag: it checks the signature of the
# release's SHA256SUMS, builds every archive of TAG again with scripts/reproduce.sh and compares it
# byte for byte with the archive published in the release, then gives a verdict.
#
#   XWIN_ACCEPT_LICENSE=true scripts/check-release.sh [--key FINGERPRINT] TAG
#
# SHA256SUMS.asc must be signed by the key that signs the releases, B493 3191 06CC 3D1F 252E  19CB
# F806 F422 E222 AA02 (alejandrogarcia83), or by the key whose full fingerprint --key gives, for a
# key that changed before this script did. The key is fetched from GitHub and keys.openpgp.org;
# only its fingerprint decides. The tag only names the commit to build: its signature is not checked.
#
# Run it in a clone of bisq-network/sandy, or anywhere else, where it offers to clone one into
# ./sandy. It leaves the clone as it was, apart from the objects of the tag and FETCH_HEAD: the tag
# is fetched into FETCH_HEAD, not into the clone's tags, the build runs in a temporary worktree of
# the tag with the tag's own scripts, and the signature is checked with a temporary GnuPG home
# that holds only the fetched key, so the user's keyring is not used either. Needs git, curl, gpg
# and Docker (scripts/reproduce.sh says why XWIN_ACCEPT_LICENSE=true is needed). Exits 0 when every
# archive is reproduced, else 1. SANDY_REPOSITORY=OWNER/NAME checks a release of a fork instead.
set -eu

repo=${SANDY_REPOSITORY:-bisq-network/sandy}
url=https://github.com/$repo
# The key that signs SHA256SUMS of the releases (README.md).
fingerprint=B493319106CC3D1F252E19CBF806F422E222AA02
key_urls="https://github.com/alejandrogarcia83.gpg https://keys.openpgp.org/vks/v1/by-fingerprint/"
targets="aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-apple-darwin
x86_64-unknown-linux-musl aarch64-pc-windows-msvc x86_64-pc-windows-msvc"

fail() {
  echo "check-release: $*" >&2
  exit 1
}

say() {
  echo "check-release: $*" >&2
}

usage="usage: XWIN_ACCEPT_LICENSE=true scripts/check-release.sh [--key FINGERPRINT] TAG"
if [ "${1:-}" = --key ]; then
  fingerprint=$(printf '%s' "${2:?$usage}" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
  shift 2
fi
printf '%s' "$fingerprint" | grep -Eqx '[0-9A-F]{40}' || fail "$fingerprint is not a full key fingerprint"
tag=${1:?$usage}
case "$tag" in
  v[0-9]*) version=${tag#v} ;;
  *) fail "$tag is not a release tag such as v1.0.0" ;;
esac
[ "${XWIN_ACCEPT_LICENSE:-}" = true ] ||
  fail "set XWIN_ACCEPT_LICENSE=true to accept the license of the Visual Studio Build Tools"
for tool in git curl gpg docker; do
  command -v "$tool" > /dev/null 2>&1 || fail "needs $tool"
done
sha256=sha256sum
command -v sha256sum > /dev/null 2>&1 || sha256="shasum -a 256"

# A clone with a remote of bisq-network/sandy, under any URL form or host alias.
remote=
if git rev-parse --git-dir > /dev/null 2>&1; then
  remote=$(git remote -v | awk -v repo="$repo" '$2 ~ "[:/]" repo "(\\.git)?$" { print $1; exit }')
fi
if [ -z "$remote" ]; then
  [ -e sandy ] && fail "this is not a clone of $repo, and ./sandy exists; run this in a clone"
  printf 'check-release: this is not a clone of %s. Clone it into ./sandy? [y/N] ' "$repo" > /dev/tty
  read -r answer < /dev/tty || answer=
  case "$answer" in
    y | Y | yes) git clone --quiet "$url" sandy ;;
    *) fail "nothing cloned" ;;
  esac
  cd sandy
  remote=origin
fi
cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
worktree=$work/tree
cleanup() {
  git worktree remove --force "$worktree" > /dev/null 2>&1 || true
  rm -rf "$work"
  git worktree prune
}
trap cleanup EXIT INT TERM

# The commit of the tag as the remote has it.
say "fetching $tag from $remote"
git fetch --quiet --no-tags "$remote" "refs/tags/$tag" || fail "$remote has no tag $tag"
object=$(git rev-parse FETCH_HEAD)
[ "$(git cat-file -t "$object")" = tag ] || fail "$tag is not an annotated tag"
commit=$(git rev-parse "$object^{commit}")
say "$tag is commit $commit"

# The published archives and their sums.
mkdir "$work/release"
for name in SHA256SUMS SHA256SUMS.asc; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/release/$name" "$url/releases/download/$tag/$name" ||
    rm -f "$work/release/$name"
done
[ -f "$work/release/SHA256SUMS" ] || fail "the release $tag has no SHA256SUMS"
[ -f "$work/release/SHA256SUMS.asc" ] || fail "the release $tag has no SHA256SUMS.asc"

# The signature of SHA256SUMS, by the key with that fingerprint and no other. VALIDSIG carries the
# fingerprint of the primary key last, also for a signing subkey.
mkdir -m 700 "$work/gnupg"
for key_url in $key_urls; do
  case "$key_url" in */by-fingerprint/) key_url=$key_url$fingerprint ;; esac
  curl -fsS --proto '=https' --tlsv1.2 "$key_url" 2> /dev/null |
    GNUPGHOME=$work/gnupg gpg --quiet --import 2> /dev/null || true
done
signer=$(GNUPGHOME=$work/gnupg gpg --status-fd 1 --verify "$work/release/SHA256SUMS.asc" \
  "$work/release/SHA256SUMS" 2> /dev/null | awk '$2 == "VALIDSIG" { print $NF }')
[ "$signer" = "$fingerprint" ] || fail "SHA256SUMS of $tag is not signed by the key $fingerprint"
say "SHA256SUMS is signed by the key $fingerprint"
for target in $targets; do
  case "$target" in *-windows-*) ext=zip ;; *) ext=tar.gz ;; esac
  name=sandy-$version-$target.$ext
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/release/$name" "$url/releases/download/$tag/$name" ||
    fail "the release $tag has no $name"
done

# The archives built again from the tag, with the tag's own scripts.
git worktree add --quiet --detach "$worktree" "$commit"
[ -x "$worktree/scripts/reproduce.sh" ] ||
  fail "$tag has no scripts/reproduce.sh; check it with the verify-release workflow instead"
say "building every archive of $tag again; this takes a while"
"$worktree/scripts/reproduce.sh" "$commit" > /dev/null
rebuilt=$worktree/dist/reproduced/$commit

# The verdict: each archive against SHA256SUMS and against the one built again.
failed=0
printf '\n%-52s %-12s %s\n' ARCHIVE SHA256SUMS "BUILT AGAIN"
for target in $targets; do
  case "$target" in *-windows-*) ext=zip ;; *) ext=tar.gz ;; esac
  name=sandy-$version-$target.$ext
  published=$($sha256 < "$work/release/$name" | cut -c1-64)
  listed=$(awk -v name="$name" '$2 == name { print $1 }' "$work/release/SHA256SUMS")
  again=$($sha256 < "$rebuilt/$name" | cut -c1-64)
  [ "$published" = "$listed" ] && in_sums=matches || { in_sums=DIFFERS; failed=1; }
  [ "$published" = "$again" ] && same=identical || { same=DIFFERS; failed=1; }
  printf '%-52s %-12s %s\n' "$name" "$in_sums" "$same"
done
echo
echo "SHA256SUMS of $tag: signed by the key $fingerprint"
if [ "$failed" = 0 ]; then
  echo "VERDICT: REPRODUCIBLE. Every archive of $tag is built byte for byte from commit $commit."
else
  echo "VERDICT: NOT REPRODUCIBLE. See the archives marked DIFFERS above."
fi
exit "$failed"
