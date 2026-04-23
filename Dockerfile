ARG FERRUM_EDGE_VERSION=latest

FROM ferrumedge/ferrum-edge:${FERRUM_EDGE_VERSION} AS ferrum-edge

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ferrum-edge /usr/local/bin/ferrum-edge /usr/local/bin/ferrum-edge
COPY --from=builder /build/target/release/gitforgeops /usr/local/bin/gitforgeops
WORKDIR /repo
ENTRYPOINT ["gitforgeops"]
