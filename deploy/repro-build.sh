#!/usr/bin/env bash
#
# Build the SecGit OCI image TWICE, independently, and fail unless both builds produce a
# bit-for-bit identical image (same manifest digest). This is the CI gate behind claim 12
# in docs/STATUS.md: "the reproducible build is actually reproducible." Without this gate,
# "reproducible build" is an aspiration; with it, an independent verifier who rebuilds from
# the same source + pinned inputs is guaranteed the same artifact — the necessary
# precondition for binding the SEV-SNP launch measurement to the OSS build (claim 5).
#
# Requires: Docker BuildKit >= 0.13 (for `--output ...,rewrite-timestamp=true`).
#
# Usage:
#   deploy/repro-build.sh
# Environment (all optional; release/CI SHOULD pin the base digests):
#   SOURCE_DATE_EPOCH  fixed build timestamp (default 1700000000)
#   DEBIAN_SNAPSHOT    Debian snapshot.debian.org timestamp (default 20260615T000000Z)
#   RUST_VERSION       rust base tag (default 1.89.0)
#   RUST_DIGEST        "@sha256:..." pin for rust:${RUST_VERSION}-bookworm
#   RUNTIME_DIGEST     "@sha256:..." pin for debian:bookworm-slim
#   KEEP_ARTIFACTS=1   copy the two OCI tarballs out for inspection on mismatch
#
# The default digests below are pinned and MUST stay in lockstep with DEBIAN_SNAPSHOT and with
# deploy/Dockerfile's ARG defaults: the snapshot date must be >= the pinned base images' build
# dates so apt only ever upgrades their pre-installed packages, never downgrades them (a stale
# snapshot vs a fresher base image is what triggers "held broken packages").
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

: "${SOURCE_DATE_EPOCH:=1700000000}"
: "${DEBIAN_SNAPSHOT:=20260615T000000Z}"
RUST_VERSION="${RUST_VERSION:-1.89.0}"
RUST_DIGEST="${RUST_DIGEST:-@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff}"
RUNTIME_DIGEST="${RUNTIME_DIGEST:-@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df}"
export SOURCE_DATE_EPOCH

if ! docker buildx version >/dev/null 2>&1; then
  echo "ERROR: 'docker buildx' is required (BuildKit >= 0.13 for rewrite-timestamp)." >&2
  exit 2
fi

# Local iteration is allowed with unpinned bases, but a reproducibility CLAIM across time
# requires pinned base-image digests (a moving tag silently breaks determinism).
if [ -z "$RUST_DIGEST" ] || [ -z "$RUNTIME_DIGEST" ]; then
  echo "WARNING: base image digests not pinned (RUST_DIGEST / RUNTIME_DIGEST empty)." >&2
  echo "         Same-run reproducibility still holds; cross-time reproducibility does not." >&2
  echo "         Resolve + pin with:" >&2
  echo "           docker buildx imagetools inspect rust:${RUST_VERSION}-bookworm --format '{{.Manifest.Digest}}'" >&2
  echo "           docker buildx imagetools inspect debian:bookworm-slim --format '{{.Manifest.Digest}}'" >&2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

build_once() {
  local n="$1"
  echo ">>> reproducibility build #$n (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
  docker buildx build \
    --no-cache \
    --file deploy/Dockerfile \
    --build-arg "RUST_VERSION=$RUST_VERSION" \
    --build-arg "RUST_DIGEST=$RUST_DIGEST" \
    --build-arg "RUNTIME_DIGEST=$RUNTIME_DIGEST" \
    --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --output "type=oci,dest=$workdir/image-$n.tar,rewrite-timestamp=true" \
    --metadata-file "$workdir/meta-$n.json" \
    .
}

# Pull "containerimage.digest":"sha256:..." out of the buildx metadata file (no jq dep).
digest_of() {
  grep -o '"containerimage.digest"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" \
    | head -n1 | sed 's/.*"\(sha256:[0-9a-f]*\)".*/\1/'
}

build_once 1
build_once 2

d1="$(digest_of "$workdir/meta-1.json")"
d2="$(digest_of "$workdir/meta-2.json")"

echo
echo "build #1 image digest: ${d1:-<none>}"
echo "build #2 image digest: ${d2:-<none>}"

if [ -n "$d1" ] && [ "$d1" = "$d2" ]; then
  echo "[PASS] OCI image is bit-for-bit reproducible: $d1"
  exit 0
fi

echo "[FAIL] image digests differ between two independent builds — NOT reproducible." >&2
echo "       Localize the drift:" >&2
echo "         mkdir a b && tar -xf image-1.tar -C a && tar -xf image-2.tar -C b && diff -r a b" >&2
if [ "${KEEP_ARTIFACTS:-0}" = "1" ]; then
  cp "$workdir"/image-*.tar "$workdir"/meta-*.json "$repo_root/" || true
  echo "       (artifacts copied to $repo_root)" >&2
  trap - EXIT
fi
exit 1
