#!/usr/bin/env bash
#
# One-command SecGit bring-up. Two paths:
#
#   deploy/up.sh --mock    Dev/CI path (no silicon). Builds + runs the hardened OCI image via
#                          docker compose against the MOCK/dev key path. Confidentiality is
#                          NOT enforced here (no real TEE) — this is for exploring the forge.
#
#   deploy/up.sh --snp     Real confidential path. Builds the reproducible OVMF + guest UKI,
#                          binds + predicts the launch measurement, then boots the SEV-SNP CVM
#                          (measured, kernel-hashes=on). Requires an AMD SEV-SNP Linux host.
#
# After --snp, a verifier proves the claim in one command from docs/acceptance-snp.md:
#   secgit-verify probe-snp && \
#   secgit-verify acceptance-snp --url https://<host>:8443 --data-dir /var/lib/secgit \
#     --product Milan --reference snp-reference.json --out acceptance-transcript.json && \
#   secgit-verify verify-transcript acceptance-transcript.json acceptance-transcript.json.vk.json
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

mode="${1:-}"
case "$mode" in
  --mock)
    echo ">>> SecGit dev bring-up (mock/dev key path; confidentiality NOT enforced)"
    : "${SECGIT_DEV_KEK_HEX:=$(openssl rand -hex 32 2>/dev/null || echo "$(head -c32 /dev/urandom | xxd -p | tr -d '\n')")}"
    export SECGIT_DEV_KEK_HEX
    echo "    using an ephemeral dev KEK (persisted for this run only)"
    if docker compose version >/dev/null 2>&1; then
      exec docker compose -f deploy/docker-compose.yml up --build
    else
      exec docker-compose -f deploy/docker-compose.yml up --build
    fi
    ;;

  --snp)
    echo ">>> SecGit confidential bring-up (AMD SEV-SNP)"
    data_img="${SECGIT_DATA_IMG:-/var/lib/secgit/data.img}"

    # 1. firmware (built once; pinned in ovmf.pin.json).
    if [ ! -f deploy/guest/out/OVMF.fd ]; then
      : "${EDK2_COMMIT:?set EDK2_COMMIT=<reviewed edk2 sha> so build-ovmf.sh can build OVMF}"
      deploy/guest/build-ovmf.sh
    fi

    # 2. guest UKI + commit-bound predicted measurement (fail-closed digest bind).
    deploy/guest/build-guest.sh ${SECGIT_TRANSPARENCY_LOG:+--log "$SECGIT_TRANSPARENCY_LOG"}

    # 3. (optional) PQC-native provenance over the artifact set. A release exports
    #    SECGIT_PROVENANCE_KEY=<offline bundle> so the signature matches the published
    #    deploy/provenance.vk.json; we then re-verify against that published key to catch a
    #    key mismatch before the artifact ships. (Unset key => an ephemeral dev signature.)
    if [ "${SECGIT_SIGN_PROVENANCE:-0}" = "1" ]; then
      cargo run -q -p xtask --release --locked -- provenance \
        --reference snp-reference.json \
        --image-manifest image-manifest.json \
        ${SECGIT_TRANSPARENCY_LOG:+--log "$SECGIT_TRANSPARENCY_LOG"}
      if [ -n "${SECGIT_PROVENANCE_KEY:-}" ] && [ -f deploy/provenance.vk.json ]; then
        echo ">>> verifying the release signature against the published provenance key"
        cargo run -q -p secgit-verify --release --locked -- \
          verify-provenance provenance.json provenance.json.sig deploy/provenance.vk.json
      fi
    fi

    # 4. boot the measured CVM. snp-reference.json pins the measurement the guest must attest.
    echo ">>> launching the SEV-SNP guest; verify it with secgit-verify acceptance-snp"
    exec deploy/guest/launch-snp.sh --data "$data_img" --reference snp-reference.json
    ;;

  *)
    echo "usage: deploy/up.sh --mock | --snp" >&2
    echo "  --mock   dev/CI docker-compose path (no silicon; confidentiality not enforced)" >&2
    echo "  --snp    build + boot the measured SEV-SNP CVM (needs an AMD SEV-SNP host)" >&2
    exit 2
    ;;
esac
