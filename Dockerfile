ARG FERRUM_EDGE_VERSION=latest

FROM ferrumedge/ferrum-edge:${FERRUM_EDGE_VERSION} AS ferrum-edge

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# Slim Debian runtime. Not fully distroless because this image is also
# used as a GitHub Actions job container (see validate-pr.yml), which
# requires /bin/sh for action bootstrap. Trixie matches the glibc of
# the upstream ferrum-edge image so the copied binary links cleanly.
FROM debian:trixie-slim
# `upgrade` picks up security fixes published after the base image tag was
# last rebuilt (e.g. util-linux CVE-2026-53612/53613/53614). Without it the
# image ships known-fixed CVEs and the Trivy scan fails.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ferrum-edge /app/ferrum-edge /app/ferrum-edge
COPY --from=builder /build/target/release/gitforgeops /app/gitforgeops

ENV PATH="/app:${PATH}"
WORKDIR /repo

LABEL org.opencontainers.image.title="gitforgeops" \
      org.opencontainers.image.description="GitOps CLI for Ferrum Edge gateway configuration" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge-git-forge-ops"

ENTRYPOINT ["/app/gitforgeops"]
