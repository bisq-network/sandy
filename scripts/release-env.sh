# Sourced by scripts/release-build.sh and scripts/release-pack.sh: runs the calling script again
# with only the variables a release build may depend on, and refuses a cargo configuration file
# outside this repository. cargo honours many variables (CARGO_ENCODED_RUSTFLAGS over RUSTFLAGS,
# RUSTC_WRAPPER, CARGO_BUILD_*, CARGO_TARGET_<TRIPLE>_*, CARGO_PROFILE_*) and the config.toml of
# CARGO_HOME and of every parent directory, and any of them would change or wrap the compiler
# without a trace in the build. The environment of the caller cannot be checked as a whole, so it
# is dropped instead; the configuration files cannot be dropped, so they are refused.
#
#   . "$(dirname "$0")/release-env.sh"; release_env "$0" "$1"     (before any cd)

release_env() {
  if [ "${SANDY_RELEASE_ENV:-}" != 1 ]; then
    script=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
    arg=$2
    set --
    for name in PATH HOME TMPDIR CARGO_HOME RUSTUP_HOME SOURCE_DATE_EPOCH XWIN_ACCEPT_LICENSE \
      WINDOWS_SDK_FETCH CI CARGO_NET_OFFLINE http_proxy https_proxy no_proxy all_proxy \
      HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY SSL_CERT_FILE SSL_CERT_DIR \
      SYSTEMROOT WINDIR TEMP TMP USERPROFILE APPDATA LOCALAPPDATA PATHEXT COMSPEC; do
      eval "[ -z \"\${$name+set}\" ] || set -- \"\$@\" \"$name=\${$name}\""
    done
    exec env -i SANDY_RELEASE_ENV=1 "$@" "$script" "$arg"
  fi
  cargo_home=${CARGO_HOME:-$HOME/.cargo}
  # cargo looks from the checkout, where the scripts run it, up to the root.
  dir=$(cd "$(dirname "$1")/.." && pwd)
  for file in "$cargo_home/config" "$cargo_home/config.toml"; do
    [ ! -e "$file" ] || release_env_fail "$file would change the build; move it away for a release build"
  done
  while :; do
    for file in "$dir/.cargo/config" "$dir/.cargo/config.toml"; do
      [ ! -e "$file" ] || release_env_fail "$file would change the build; move it away for a release build"
    done
    [ "$dir" != / ] && [ "$dir" != . ] || break
    dir=$(dirname "$dir")
  done
}

release_env_fail() {
  echo "release-env: $*" >&2
  exit 1
}
