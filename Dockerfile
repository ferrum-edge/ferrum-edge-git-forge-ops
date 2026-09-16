FROM ferrumedge/ferrum-edge:latest@sha256:fb0f05b0392a272ba36a493584bced171655ce8ebd36b2ae0818bb5c3c25ef2d AS ferrum-edge

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
# Override verification needs only Git's built-in local inspection commands.
# Reuse the reviewed builder's Git and its complete ELF dependency closure,
# including its loader, so Bookworm libraries never mix with Trixie's libc.
# No network helpers, templates, package installs, or new image inputs.
RUN set -eu; \
    mkdir -p /opt/override-git/lib; \
    cp /usr/bin/git /opt/override-git/git; \
    ldd /usr/bin/git > /tmp/git-libraries; \
    if grep -q 'not found' /tmp/git-libraries; then exit 1; fi; \
    awk '$2 == "=>" && substr($3, 1, 1) == "/" {print $3}' /tmp/git-libraries \
        | xargs -r -I '{}' cp -L '{}' /opt/override-git/lib/; \
    loader=$(awk '$1 ~ /ld-linux/ {print $1}' /tmp/git-libraries); \
    test -n "$loader"; \
    cp -L "$loader" /opt/override-git/loader; \
    /opt/override-git/loader --library-path /opt/override-git/lib \
        /opt/override-git/git --version
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
RUN cargo build --release --locked

# Debian point-release security updates for the runtime stage, pinned by exact
# version and SHA-256 instead of pulled through `apt-get`. The runtime base
# digest below (Debian 13.6, built 2026-08-24) predates the fixes for
# CVE-2026-8376, CVE-2026-42496 and CVE-2026-13221 (perl-base, an Essential
# package that cannot be purged), CVE-2026-11822 and CVE-2026-11824
# (libsqlite3-0), CVE-2026-41992 (gzip), and CVE-2026-86145 and
# CVE-2026-89161 (libpcre2-8-0), and CVE-2026-5450 and CVE-2026-5928 (glibc:
# libc6 and libc-bin). Each package is fetched from its immutable
# pool path and refused unless its digest matches the reviewed value here, so
# the same source commit still produces the same runtime bytes and no mutable
# package index is ever consulted. Remove this stage once a rebuilt
# `debian:trixie-slim` digest carries these versions (issue #228).
ARG TARGETARCH
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    mkdir -p /opt/runtime-security-updates; \
    cd /opt/runtime-security-updates; \
    case "$arch" in \
      amd64) printf '%s  %s\n' \
        b795464137a0f4d443fc9284f4b93e883fb83883cb533adf300ac660807a352a perl-base_5.40.1-6+deb13u1_amd64.deb \
        0a459adaffd901109f7811ab65f58e7a957b4907d05539cf3d1184efdcde0468 libsqlite3-0_3.46.1-7+deb13u2_amd64.deb \
        74cf12212beee4ab8d473bdc0107abf9e8cef737492198e2f4944a19f142b0ac gzip_1.13-1+deb13u1_amd64.deb \
        1252b96a5bc44bb5db982bef8eb18e54f5047cede2aff641bce4f8e1edb91c3e libpcre2-8-0_10.46-1~deb13u2_amd64.deb \
        967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9 libc6_2.41-12+deb13u4_amd64.deb \
        dc8c79647fe3a5f37f72a400414f70263d0212f010ff2c09f990e30d91e38d1c libc-bin_2.41-12+deb13u4_amd64.deb \
        > SHA256SUMS ;; \
      arm64) printf '%s  %s\n' \
        4cee6f6b5b4b501d82118c56aa31bbefc2491415bc03a00e21bdacff2406b288 perl-base_5.40.1-6+deb13u1_arm64.deb \
        5b09efca71cb7a16d67f5453af3989ae1a84fe6b68c6dd3913de527cb0ca23aa libsqlite3-0_3.46.1-7+deb13u2_arm64.deb \
        02f83e5b4351ab4caa54f0405a334943dcd4986fdce740072bbda7b3c844e1f6 gzip_1.13-1+deb13u1_arm64.deb \
        e7d2c997dac145c16457be0fed3d084c98cd030bec7633eec7e5bde6dbb97712 libpcre2-8-0_10.46-1~deb13u2_arm64.deb \
        8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc libc6_2.41-12+deb13u4_arm64.deb \
        3aba9182d6989d7c512178defdcb9d02b6906816bc8b2778a82a6c39582c880c libc-bin_2.41-12+deb13u4_arm64.deb \
        > SHA256SUMS ;; \
      *) echo "unsupported target architecture: $arch" >&2; exit 1 ;; \
    esac; \
    while read -r digest file; do \
      case "$file" in \
        perl-base_*) pool=pool/main/p/perl ;; \
        libsqlite3-0_*) pool=pool/main/s/sqlite3 ;; \
        gzip_*) pool=pool/main/g/gzip ;; \
        libpcre2-8-0_*) pool=pool/main/p/pcre2 ;; \
        libc6_*|libc-bin_*) pool=pool/main/g/glibc ;; \
        *) echo "unexpected package: $file" >&2; exit 1 ;; \
      esac; \
      curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --retry-connrefused \
        "https://deb.debian.org/debian/$pool/$file" --output "$file"; \
    done < SHA256SUMS; \
    sha256sum --check --strict SHA256SUMS; \
    rm SHA256SUMS

# Slim Debian runtime rather than distroless: the image is meant to be run
# directly (`docker run ... gitforgeops plan`) and in contexts that expect a
# usable /bin/sh, and several of its code paths shell out — `validate` execs
# `ferrum-edge`, overrides inspect Git, delivery execs `age`. Trixie matches
# the glibc of the upstream ferrum-edge image so the copied binary links cleanly.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
# Install the reviewed point-release packages before apt is purged. `dpkg
# --install` consumes only bytes the builder stage already verified against the
# digests above; it performs no network access.
COPY --from=builder /opt/runtime-security-updates /tmp/runtime-security-updates
RUN DEBIAN_FRONTEND=noninteractive dpkg --install /tmp/runtime-security-updates/*.deb \
    && rm -rf /tmp/runtime-security-updates
# Keep the release build a function of reviewed digests. `apt-get update` or
# `upgrade` here would execute mutable repository state and make the same
# source commit produce different runtime bytes over time. The digest-pinned
# Rust builder already carries a CA bundle, so copy those reviewed bytes.
# Neither Rust binary links OpenSSL. Remove apt and its otherwise-unused TLS
# stack from the pinned base so a package-manager-only vulnerability cannot
# become part of the runtime image. `dpkg --purge` consumes only bytes already
# present in the reviewed base digest; it performs no network access.
RUN dpkg --purge --force-depends \
    apt \
    libapt-pkg7.0 \
    libssl3t64 \
    openssl-provider-legacy
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /opt/override-git /opt/override-git
# Scope the private loader/library path to Git; the gateway and CLI continue
# to use the runtime's libraries. No safe.directory wildcard or root-only path.
RUN printf '%s\n' '#!/bin/sh' \
    'exec /opt/override-git/loader --library-path /opt/override-git/lib /opt/override-git/git "$@"' \
    > /usr/local/bin/git && chmod 0755 /usr/local/bin/git

COPY --from=ferrum-edge /app/ferrum-edge /app/ferrum-edge
COPY --from=builder /build/target/release/gitforgeops /app/gitforgeops

ENV PATH="/app:${PATH}"
WORKDIR /repo

LABEL org.opencontainers.image.title="gitforgeops" \
      org.opencontainers.image.description="GitOps CLI for Ferrum Edge gateway configuration" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge-git-forge-ops"

ENTRYPOINT ["/app/gitforgeops"]
