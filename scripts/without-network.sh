#!/bin/sh
# Runs COMMAND as the calling user in a network namespace of its own, which has no interface but
# a loopback that is down, so that the build cannot reach any host. Linux only, and needs sudo
# without a password, as on GitHub's runners; the namespace is made as root because Ubuntu keeps
# unprivileged users from making one. CARGO_NET_OFFLINE=true makes cargo say so instead of
# trying the network.
#
#   scripts/without-network.sh COMMAND [ARGUMENT...]
set -eu

[ $# -gt 0 ] || { echo "usage: scripts/without-network.sh COMMAND [ARGUMENT...]" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "without-network: Linux only" >&2; exit 1; }
# sudo keeps the environment with --preserve-env but sets PATH and HOME its own way.
exec sudo -n --preserve-env unshare --net -- \
  setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- \
  env "PATH=$PATH" "HOME=$HOME" CARGO_NET_OFFLINE=true "$@"
