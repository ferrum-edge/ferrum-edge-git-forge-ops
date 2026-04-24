ARG FERRUM_EDGE_VERSION=latest

FROM ferrumedge/ferrum-edge:${FERRUM_EDGE_VERSION} AS ferrum-edge

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# Minimal distroless runtime image.
# `-cc` variant provides glibc + libgcc for dynamically-linked Rust binaries,
# plus ca-certificates for HTTPS (rustls reads /etc/ssl/certs). Debian 13
# (trixie) distroless has glibc 2.40, forward-compatible with binaries built
# on Debian 12 (bookworm, glibc 2.36).
FROM gcr.io/distroless/cc-debian13

COPY --from=ferrum-edge /app/ferrum-edge /app/ferrum-edge
COPY --from=builder /build/target/release/gitforgeops /app/gitforgeops

ENV PATH="/app:${PATH}"
WORKDIR /repo

LABEL org.opencontainers.image.title="gitforgeops" \
      org.opencontainers.image.description="GitOps CLI for Ferrum Edge gateway configuration" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge-git-forge-ops"

ENTRYPOINT ["/app/gitforgeops"]
