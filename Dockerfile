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
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked

# Slim Debian runtime rather than distroless: the image is meant to be run
# directly (`docker run ... gitforgeops plan`) and in contexts that expect a
# usable /bin/sh, and several of its code paths shell out — `validate` execs
# `ferrum-edge`, overrides inspect Git, delivery execs `age`. Trixie matches
# the glibc of the upstream ferrum-edge image so the copied binary links cleanly.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
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
