# syntax=docker/dockerfile:1
#
# SecGit server image. Designed to run INSIDE a confidential VM (AMD SEV-SNP / Intel
# TDX). Built for reproducibility: pinned toolchain, SOURCE_DATE_EPOCH, locked deps.
# The resulting image's launch measurement is what attestation proves == this OSS build.

ARG RUST_VERSION=1.89.0
ARG SOURCE_DATE_EPOCH=1700000000

FROM rust:${RUST_VERSION}-bookworm AS build
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# aws-lc-rs builds AWS-LC from source: needs cmake + a C toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# --locked enforces Cargo.lock for reproducibility.
RUN cargo build --release --locked -p secgit-server -p secgit-verify
# Image-transparency artifacts, derived deterministically from the locked graph and the
# built binaries. These let anyone correlate the running image with this OSS build.
RUN mkdir -p /out \
    && cargo run --release --locked -p xtask -- sbom Cargo.lock /out/sbom.json \
    && cargo run --release --locked -p xtask -- measure \
        target/release/secgit-server target/release/secgit-verify \
    && cp image-manifest.json /out/image-manifest.json

FROM debian:bookworm-slim AS runtime
# The forge uses canonical git as its pack engine (gitoxide can't serve receive-pack).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Non-root runtime user.
RUN useradd --system --create-home --uid 10001 secgit
COPY --from=build /src/target/release/secgit-server /usr/local/bin/secgit-server
COPY --from=build /src/target/release/secgit-verify /usr/local/bin/secgit-verify
COPY --from=build /out/sbom.json /usr/local/share/secgit/sbom.json
COPY --from=build /out/image-manifest.json /usr/local/share/secgit/image-manifest.json
USER secgit
ENV SECGIT_DATA=/data \
    SECGIT_ADDR=0.0.0.0:8080 \
    SECGIT_SBOM=/usr/local/share/secgit/sbom.json \
    SECGIT_IMAGE_MANIFEST=/usr/local/share/secgit/image-manifest.json
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/secgit-verify", "selftest"]
ENTRYPOINT ["/usr/local/bin/secgit-server"]
