FROM ferrumedge/ferrum-edge:latest@sha256:fb0f05b0392a272ba36a493584bced171655ce8ebd36b2ae0818bb5c3c25ef2d AS ferrum-edge

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked

# Slim Debian runtime. Not fully distroless because this image is also
# used as a GitHub Actions job container (see validate-pr.yml), which
# requires /bin/sh for action bootstrap. Trixie matches the glibc of
# the upstream ferrum-edge image so the copied binary links cleanly.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
# Keep the release build a function of reviewed digests. `apt-get update` or
# `upgrade` here would execute mutable repository state and make the same
# source commit produce different runtime bytes over time. The digest-pinned
# Rust builder already carries a CA bundle, so copy those reviewed bytes.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=ferrum-edge /app/ferrum-edge /app/ferrum-edge
COPY --from=builder /build/target/release/gitforgeops /app/gitforgeops

ENV PATH="/app:${PATH}"
WORKDIR /repo

LABEL org.opencontainers.image.title="gitforgeops" \
      org.opencontainers.image.description="GitOps CLI for Ferrum Edge gateway configuration" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge-git-forge-ops"

ENTRYPOINT ["/app/gitforgeops"]
