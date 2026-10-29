#!/bin/sh
# The linker of the aarch64-unknown-linux-musl release binary (scripts/release-build.sh). It runs
# the linker of the Rust toolchain, rust-lld, with the link of a static position-independent
# executable, so that the kernel loads sandy at a random address, as it loads the x86_64 binary.
#
# rustc links a static PIE for x86_64-unknown-linux-musl by itself. Its aarch64-unknown-linux-musl
# target does not declare that it supports one, so rustc links that binary at a fixed address,
# whatever -C relocation-model asks for. The code is position-independent all the same, and the
# toolchain ships the start file of a static PIE, rcrt1.o, which relocates the image before musl
# starts. This script turns rustc's link into the one rustc runs for x86_64: rcrt1.o, crtbeginS.o
# and crtendS.o instead of crt1.o, crtbegin.o and crtend.o, and -pie, --no-dynamic-linker and
# -z text after -static. With -z text the link fails if any code is not position-independent.
#
# It stops when rustc's command line does not have that shape, for example when a later rustc
# links the static PIE by itself and this script is no longer needed.
set -eu

changed=0
for arg do
  shift
  case $arg in
    */self-contained/crt1.o)
      arg=${arg%crt1.o}rcrt1.o
      changed=$((changed + 1))
      ;;
    */self-contained/crtbegin.o)
      arg=${arg%crtbegin.o}crtbeginS.o
      changed=$((changed + 1))
      ;;
    */self-contained/crtend.o)
      arg=${arg%crtend.o}crtendS.o
      changed=$((changed + 1))
      ;;
    -static)
      set -- "$@" -static -pie --no-dynamic-linker -z text
      changed=$((changed + 1))
      continue
      ;;
    @*)
      echo "$0: cannot change the arguments in the response file $arg" >&2
      exit 1
      ;;
  esac
  set -- "$@" "$arg"
done
if [ "$changed" -ne 4 ]; then
  echo "$0: rustc's link of a static executable has changed ($changed of 4 expected arguments" \
    "found); check whether this script is still needed" >&2
  exit 1
fi
exec rust-lld "$@"
