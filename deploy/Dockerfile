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
# Pin the base images by digest (the `@sha256:...` prefix is baked into the FROM lines
# below). Pinning is REQUIRED, not optional: a bare tag floats to the latest point release,
# and when the base image drifts ahead of the frozen apt snapshot its pre-installed packages
# (e.g. perl-base) become NEWER than anything the snapshot offers, so `apt-get install` can no
# longer satisfy an exact-version dependency and dies with "held broken packages". The two
# levers must therefore move together: whenever you re-pin a digest below, bump DEBIAN_SNAPSHOT
# to the newest snapshot.debian.org capture at/near that image's build date (see the note on the
# snapshot ARG), so apt only upgrades the image's packages, never downgrades. Re-resolve with:
#   docker buildx imagetools inspect rust:1.89.0-bookworm --format '{{.Manifest.Digest}}'
#   docker buildx imagetools inspect debian:bookworm-slim  --format '{{.Manifest.Digest}}'
ARG RUST_DIGEST=@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff
ARG RUNTIME_DIGEST=@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
# Debian snapshot timestamp: freezes apt package versions to a point in time so two
# independent rebuilds resolve identical dependencies. Bump deliberately, never floatingly, and
# keep it close to (and never far behind) the RUNTIME_DIGEST base image's build date: the
# snapshot must be able to UPGRADE the base image's pre-installed packages, never be asked to
# downgrade them. debian:bookworm-slim @60eac75 was built 2026-06-24; this points at the newest
# snapshot.debian.org capture at pinning time, which carries the same perl-base (5.36.0-7+deb12u3).
ARG DEBIAN_SNAPSHOT=20260615T000000Z
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
# NOTE: the snapshot is fetched over plain HTTP on purpose. apt authenticity comes from the
# GPG-signed InRelease verified against the `Signed-By` debian-archive-keyring — NOT from TLS —
# so HTTP is safe and byte-identical for reproducibility, and it avoids a ca-certificates
# bootstrap in the minimal runtime stage (debian:bookworm-slim ships no CA bundle).
RUN set -eux; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian-security.sources; \
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
# HTTP (not HTTPS) on purpose: this minimal image has no ca-certificates yet, and apt trust is
# GPG-based (Signed-By), so HTTP both works and stays reproducible. The ca-certificates package
# installed just below is what the server later uses for its own OUTBOUND HTTPS (AMD KDS / KBS).
RUN set -eux; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian-security.sources; \
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
