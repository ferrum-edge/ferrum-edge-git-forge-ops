FROM ferrumedge/ferrum-edge:v0.9.10@sha256:430d6a7d41361de5ad12562786481f97f1e97fef72a0b5f1a0699eced7cdd4cc AS ferrum-edge

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder
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
# `gitforgeops doctor` compiles the settings auditor into the binary
# (`include_str!`) so it never executes a checkout-controlled copy.
COPY .github/scripts/audit_settings.py .github/scripts/audit_settings.py
RUN cargo build --release --locked

# Debian point-release security update for CVE-2026-103111 (HIGH): the pinned
# runtime base still carries libpcre2-8-0 10.46-1~deb13u2, while 10.46-1~deb13u3
# fixes the out-of-bounds write. Pin the .deb by version and SHA-256 from its
# content-immutable security pool path; never consult a mutable package index
# here. The security pool drops a version once a newer update supersedes it;
# the build then fails closed (404) and the base-image pin canary reports it.
ARG TARGETARCH
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    mkdir -p /opt/runtime-security-updates; \
    cd /opt/runtime-security-updates; \
    case "$arch" in \
      amd64) printf '%s  %s\n' \
        e226f661d918f04daf38cdbc4806b7ed7d6ef95c7eb0ade692fc350e31970040 libpcre2-8-0_10.46-1~deb13u3_amd64.deb \
        > SHA256SUMS ;; \
      arm64) printf '%s  %s\n' \
        1a02b7129990690ea095fd35d7ace6853742923d158019e1fb4ef27efd2c51a7 libpcre2-8-0_10.46-1~deb13u3_arm64.deb \
        > SHA256SUMS ;; \
      *) echo "unsupported target architecture: $arch" >&2; exit 1 ;; \
    esac; \
    while read -r digest file; do \
      case "$file" in \
        libpcre2-8-0_*) pool=pool/updates/main/p/pcre2 ;; \
        *) echo "unexpected package: $file" >&2; exit 1 ;; \
      esac; \
      curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --retry-connrefused \
        "https://deb.debian.org/debian-security/$pool/$file" --output "$file"; \
    done < SHA256SUMS; \
    sha256sum --check --strict SHA256SUMS; \
    rm SHA256SUMS

# Slim Debian runtime rather than distroless: the image is meant to be run
# directly (`docker run ... gitforgeops plan`) and in contexts that expect a
# usable /bin/sh, and several of its code paths shell out — `validate` execs
# `ferrum-edge`, overrides inspect Git, delivery execs `age`. Trixie matches
# the glibc of the upstream ferrum-edge image so the copied binary links cleanly.
# Issue #431: the `debian:trixie-slim` digest still carries
# libpcre2-8-0 10.46-1~deb13u2, which has CVE-2026-103111. Reintroduce the
# `runtime-security-updates` stage for this fixed HIGH until a rebuilt
# `trixie-slim` digest carries libpcre2-8-0 >= 10.46-1~deb13u3; then drop this
# stage. The .deb is pinned by version and SHA-256 from its immutable pool path.
# Install it before the purge below. Never `apt-get`.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# Install only bytes the builder already verified against the reviewed digests.
COPY --from=builder /opt/runtime-security-updates /tmp/runtime-security-updates
RUN dpkg --install /tmp/runtime-security-updates/*.deb \
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

# Run unprivileged by default (issue #347). The fixed UID/GID 65532 matches the
# upstream ferrum-edge image's non-root identity. The passwd/group entries are
# appended directly so no account tooling runs; they only give the default
# identity a name. `--user "$(id -u):$(id -g)"` overrides still work without a
# passwd entry: HOME is the world-writable, sticky /tmp (a `--tmpfs /tmp` under
# `--read-only`), and nothing the CLI runs needs a named account.
#
# No `safe.directory` entry is set: Git inspects a bind-mounted checkout only
# when the container runs as the checkout owner's UID, so a foreign-owned
# checkout leaves revision-bound overrides inactive (fail closed). `/repo`
# itself is owned by the default identity so a named volume mounted there
# starts out writable.
RUN printf '%s\n' 'gitforgeops:x:65532:65532:gitforgeops:/tmp:/usr/sbin/nologin' \
        >> /etc/passwd \
    && printf '%s\n' 'gitforgeops:x:65532:' >> /etc/group \
    && install -d -o 65532 -g 65532 -m 0755 /repo

COPY --from=ferrum-edge --chmod=0755 /app/ferrum-edge /app/ferrum-edge
COPY --from=builder --chmod=0755 /build/target/release/gitforgeops /app/gitforgeops

ENV PATH="/app:${PATH}" \
    HOME=/tmp
WORKDIR /repo
USER 65532:65532

LABEL org.opencontainers.image.title="gitforgeops" \
      org.opencontainers.image.description="GitOps CLI for Ferrum Edge gateway configuration" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge-git-forge-ops"

ENTRYPOINT ["/app/gitforgeops"]
