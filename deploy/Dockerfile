# syntax=docker/dockerfile:1
#
# SecGit server image. Designed to run INSIDE a confidential VM (AMD SEV-SNP / Intel
# TDX). Built for BIT-FOR-BIT reproducibility so the launch measurement of a guest built
# from this rootfs equals a value derivable from source (see docs/packaging.md and
# docs/adr/0005-reproducible-builds.md). Verified by `deploy/repro-build.sh` (build twice,
# compare digests).
#
# Reproducibility levers, all load-bearing:
#   - base images pinned by DIGEST (RUST_DIGEST / RUNTIME_DIGEST; the tag alone can move);
#   - apt pinned to a Debian SNAPSHOT so package versions are frozen in time;
#   - SOURCE_DATE_EPOCH threaded in, and layer file mtimes rewritten at export via
#     BuildKit `--output ...,rewrite-timestamp=true` (see repro-build.sh);
#   - cargo build with `--locked`, `CARGO_INCREMENTAL=0`, and `--remap-path-prefix` so no
#     absolute build paths are embedded in the binaries.

ARG RUST_VERSION=1.89.0
# Pin the base images by digest. Default is empty (tag-only) so a plain `docker build`
# still works for local iteration; RELEASE / CI builds MUST pass the resolved digests
# (repro-build.sh enforces this). Resolve with:
#   docker buildx imagetools inspect rust:1.89.0-bookworm --format '{{.Manifest.Digest}}'
#   docker buildx imagetools inspect debian:bookworm-slim  --format '{{.Manifest.Digest}}'
ARG RUST_DIGEST=
ARG RUNTIME_DIGEST=
# Debian snapshot timestamp: freezes apt package versions to a point in time so two
# independent rebuilds resolve identical dependencies. Bump deliberately, never floatingly.
ARG DEBIAN_SNAPSHOT=20240701T000000Z
ARG SOURCE_DATE_EPOCH=1700000000

FROM rust:${RUST_VERSION}-bookworm${RUST_DIGEST} AS build
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    # Strip absolute build paths from the binaries: /src (workspace) and the cargo
    # registry cache. Without this the embedded paths make the binary non-reproducible.
    RUSTFLAGS="--remap-path-prefix=/src=/secgit --remap-path-prefix=/usr/local/cargo=/cargo"
# Freeze apt to the Debian snapshot, then install the C toolchain aws-lc-rs needs.
# `Check-Valid-Until false` is required because snapshot repos have stale Release dates.
RUN set -eux; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian-security.sources; \
    rm -f /etc/apt/sources.list; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until; \
    apt-get update; \
    apt-get install -y --no-install-recommends cmake clang; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# --locked enforces Cargo.lock for reproducibility.
RUN cargo build --release --locked -p secgit-server -p secgit-verify
# Image-transparency artifacts, derived deterministically from the locked graph and the
# built binaries. These let anyone correlate the running image with this OSS build. The
# artifact digests here are also the values `xtask snp-measure` cross-checks the launch
# inputs against (see deploy/snp-inputs.example.json).
RUN set -eux; \
    mkdir -p /out; \
    cargo run --release --locked -p xtask -- sbom Cargo.lock /out/sbom.json; \
    cargo run --release --locked -p xtask -- measure \
        target/release/secgit-server target/release/secgit-verify; \
    cp image-manifest.json /out/image-manifest.json; \
    # Belt-and-suspenders determinism: clamp generated artifact mtimes (BuildKit's
    # rewrite-timestamp handles layer export, this covers in-stage reads).
    find /out target/release/secgit-server target/release/secgit-verify \
        -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

FROM debian:bookworm-slim${RUNTIME_DIGEST} AS runtime
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT
# The forge uses canonical git as its pack engine (gitoxide can't serve receive-pack).
RUN set -eux; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian-security.sources; \
    rm -f /etc/apt/sources.list; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    rm -rf /var/lib/apt/lists/*
# Non-root runtime user with a fixed uid/gid (deterministic passwd/group entries).
RUN groupadd --system --gid 10001 secgit \
    && useradd --system --create-home --uid 10001 --gid 10001 secgit
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
