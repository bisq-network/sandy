# The build environment of scripts/reproduce.sh: an x86_64 Linux host, the triple every release
# binary is built on, with the Rust toolchain of rust-toolchain.toml. Every input is pinned: the
# Debian image by digest, its packages by a dated snapshot of the Debian archive and the sums of
# its signed indexes, rustup-init by the sum in rustup-init.sha256. scripts/release-build.sh checks
# the toolchain against rust-toolchain.sha256 before every build and checks the Windows libraries,
# which another container fetches into /windows-sdk (scripts/reproduce.sh).
#
# Built by scripts/reproduce.sh, with a context of this file, rust-toolchain.toml and
# rustup-init.sha256.

FROM --platform=linux/amd64 debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# The packages as the Debian archive held them at this time. apt checks them against the archive
# keys of the image; snapshots are served over plain HTTP, which the signatures make safe, and
# their Release files have expired, which the date makes expected. With the expiry check off, apt
# would also take any older signed index that a network attacker serves, so the sums of the three
# InRelease files of the snapshot are pinned too. Moving DEBIAN_SNAPSHOT needs new sums: fetch the
# files over HTTPS from snapshot.debian.org, check them with gpgv against the image's
# /usr/share/keyrings/debian-archive-keyring.gpg, and write their sums here.
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
 && cd /var/lib/apt/lists \
 && printf '%s  %s\n' \
      0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675 \
      "snapshot.debian.org_archive_debian_${DEBIAN_SNAPSHOT}_dists_trixie_InRelease" \
      941f8837aeb81f81e01edcb533004a886814a9a472e14c4cf707aad04ac6a2d6 \
      "snapshot.debian.org_archive_debian_${DEBIAN_SNAPSHOT}_dists_trixie-updates_InRelease" \
      cb4c3601d733578e1fc7c70a6601e65dd0f3b8bb1d11c9d0ed0d2221c37ac596 \
      "snapshot.debian.org_archive_debian-security_${DEBIAN_SNAPSHOT}_dists_trixie-security_InRelease" \
    | sha256sum --check --strict - \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# rustup and, through it, the toolchain of rust-toolchain.toml with its components and targets.
# gcc above links only the build scripts and procedural macros that run during the build; the
# release binaries are linked by the toolchain's rust-lld. The toolchain stays owned by root, so
# the builds, which run as 65534, cannot change it (scripts/reproduce.sh checks that).
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
COPY rust-toolchain.toml rustup-init.sha256 /usr/local/share/sandy/
RUN cd /usr/local/share/sandy \
 && line=$(grep /x86_64-unknown-linux-gnu/ rustup-init.sha256) \
 && curl -fsS --proto '=https' --tlsv1.2 -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${line#*  }" \
 && echo "${line%%  *}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init \
 && rustup set auto-self-update disable \
 && rustup toolchain install \
 && chmod -R a+rX "$RUSTUP_HOME" "$CARGO_HOME"

# The mount points of the volumes that scripts/reproduce.sh passes the Windows libraries and the
# fetched crates in. A new volume takes the owner of the directory it is mounted on, and the
# containers run as 65534.
RUN install -d -o 65534 -g 65534 /windows-sdk /deps
