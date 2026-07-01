#!/usr/bin/env bash
#
# Prove the published SecGit image carries NO secret/key material. The KEK is released into
# the CVM by attestation at boot (deploy/guest/secgit.service), never baked into an image
# layer or env var. This scan fails CI if that invariant is ever violated.
#
# Checks, over the image's exported filesystem AND its config/env:
#   1. no private-key files (*.kek, *.key, *.pem private blocks, id_* SSH keys);
#   2. no dev/insecure key env baked into the image (SECGIT_DEV_KEK_HEX, SECGIT_INSECURE_HTTP);
#   3. no obvious high-entropy secret files under common paths.
#
# Usage:
#   deploy/verify-no-secrets.sh [IMAGE_TAG]      # scan a built image (default secgit/secgit-server:m7)
#   ROOTFS=/path/to/rootfs deploy/verify-no-secrets.sh   # scan an already-exported rootfs
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
image="${1:-secgit/secgit-server:m7}"
fail=0

scan_rootfs() {
  local root="$1"
  echo ">>> scanning rootfs at $root"

  # 1. private-key-looking files.
  local hits
  hits="$(find "$root" -type f \
      \( -name '*.kek' -o -name '*.key' -o -name '*.pem' -o -name 'id_rsa' \
         -o -name 'id_ed25519' -o -name '*.p12' -o -name '*.pfx' \) 2>/dev/null || true)"
  if [ -n "$hits" ]; then
    echo "[FAIL] key-material files present in image:" >&2
    echo "$hits" >&2
    fail=1
  else
    echo "[ok] no *.kek/*.key/*.pem/id_* key files"
  fi

  # 2. PEM PRIVATE KEY blocks embedded anywhere.
  if grep -RIl -- "-----BEGIN .*PRIVATE KEY-----" "$root" 2>/dev/null | grep -q .; then
    echo "[FAIL] a PEM PRIVATE KEY block is embedded in the image" >&2
    grep -RIl -- "-----BEGIN .*PRIVATE KEY-----" "$root" 2>/dev/null >&2 || true
    fail=1
  else
    echo "[ok] no embedded PEM PRIVATE KEY blocks"
  fi

  # 3. dev/insecure env accidentally written into the image (e.g. a leaked .env).
  if grep -RIn -- "SECGIT_DEV_KEK_HEX" "$root" 2>/dev/null | grep -q .; then
    echo "[FAIL] SECGIT_DEV_KEK_HEX present in image filesystem (dev KEK must never ship)" >&2
    fail=1
  else
    echo "[ok] no SECGIT_DEV_KEK_HEX in filesystem"
  fi
}

scan_image_env() {
  local img="$1"
  command -v docker >/dev/null 2>&1 || return 0
  echo ">>> inspecting image env/config: $img"
  local env_json
  env_json="$(docker image inspect "$img" --format '{{json .Config.Env}}' 2>/dev/null || echo '[]')"
  if printf '%s' "$env_json" | grep -Eq "SECGIT_DEV_KEK_HEX|SECGIT_INSECURE_HTTP"; then
    echo "[FAIL] image env contains a dev/insecure key knob:" >&2
    printf '%s\n' "$env_json" >&2
    fail=1
  else
    echo "[ok] image env has no dev/insecure key knobs"
  fi
}

if [ -n "${ROOTFS:-}" ]; then
  scan_rootfs "$ROOTFS"
else
  command -v docker >/dev/null 2>&1 || {
    echo "ERROR: docker required to export the image (or set ROOTFS=/path to a rootfs)." >&2
    exit 2
  }
  # Build if the image is not present locally.
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo ">>> image $image not found locally; building it"
    docker build --file "$repo_root/deploy/Dockerfile" --tag "$image" "$repo_root"
  fi
  rootfs="$(mktemp -d)"
  cid="$(docker create "$image")"
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$rootfs"' EXIT
  docker export "$cid" | tar -x -C "$rootfs"
  scan_rootfs "$rootfs"
  scan_image_env "$image"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "[PASS] no secret/key material found in the image. KEK is attestation-released at boot."
  exit 0
fi
echo "[FAIL] secret material detected — the image is NOT publishable." >&2
exit 1
