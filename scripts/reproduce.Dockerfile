# The build environment of scripts/reproduce.sh: an x86_64 Linux host, the triple every release
# binary is built on, with the Rust toolchain of rust-toolchain.toml. Every input is pinned: the
# Debian image by digest, its packages by a dated snapshot of the Debian archive, rustup-init by
# its SHA-256 sum. scripts/release-build.sh checks the toolchain against rust-toolchain.sha256
# before every build and checks the Windows libraries, which another container fetches into
# /windows-sdk (scripts/reproduce.sh).
#
# Built by scripts/reproduce.sh, with a context of this file and rust-toolchain.toml.

FROM --platform=linux/amd64 debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# The packages as the Debian archive held them at this time. apt still checks them against the
# archive keys of the image; snapshots are served over plain HTTP, which the signatures make safe,
# and their Release files have expired, which the date makes expected.
ARG DEBIAN_SNAPSHOT=20261101T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT/" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT/" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/snapshot.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# rustup and, through it, the toolchain of rust-toolchain.toml with its components and targets.
# gcc above links only the build scripts and procedural macros that run during the build; the
# release binaries are linked by the toolchain's rust-lld.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
COPY rust-toolchain.toml /usr/local/share/sandy/
RUN curl -fsS --proto '=https' --tlsv1.2 -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init \
 && cd /usr/local/share/sandy && rustup toolchain install \
 && chmod -R a+rX "$RUSTUP_HOME" "$CARGO_HOME"

# The mount point of the volume that scripts/reproduce.sh passes the Windows libraries in. A new
# volume takes the owner of the directory it is mounted on, and the containers run as 65534.
RUN install -d -o 65534 -g 65534 /windows-sdk
