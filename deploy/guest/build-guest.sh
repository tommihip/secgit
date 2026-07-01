#!/usr/bin/env bash
#
# Assemble the SecGit confidential-guest artifact and BIND its launch measurement to the
# reproducible OSS build. This is the M7 crux: it turns the reproducible OCI image into a
# bootable, measurable SEV-SNP guest whose predicted measurement (xtask snp-measure) equals
# what the CVM actually boots to.
#
# Pipeline:
#   1. build the reproducible OCI image (deploy/Dockerfile) and export its rootfs;
#   2. drive mkosi (deploy/guest/mkosi.conf) to fuse kernel+initrd+cmdline into ONE UKI,
#      importing the byte-identical secgit binaries from that rootfs (mkosi.finalize);
#   3. recompute SHA-384 of OVMF.fd + the UKI, fill snp-inputs.json + ovmf.pin.json;
#   4. run `xtask snp-measure` (fail-closed on any digest drift) to emit a commit-bound
#      snp-reference.json — the value a verifier pins into Policy.allowed_measurements.
#
# BUILD HOST: Linux/x86_64 with docker + mkosi (>= 20) + systemd-ukify. Not runnable on macOS.
# Prerequisite: deploy/guest/build-ovmf.sh has produced deploy/guest/out/OVMF.fd (this script
# builds it if EDK2_COMMIT is set and OVMF.fd is missing).
#
# SecureBoot + dm-verity: mkosi.conf enables `SecureBoot=yes` + `Verity=hash`, producing a
# dm-verity-protected root disk and a signed UKI whose `.roothash` section (and thus the
# roothash) is folded into the launch measurement. Supply signing keys at build time via
# SECGIT_SB_KEY / SECGIT_SB_CERT (PEM key + X.509 cert); they are NEVER committed. If unset,
# the build still runs but the UKI is unsigned (dev only) — a release MUST set them.
#
# [VERIFY] mkosi option names track a fast-moving tool; validate against your mkosi version.
#
# Usage:
#   deploy/guest/build-guest.sh [--log transparency.log]
# Environment (optional):
#   SOURCE_DATE_EPOCH  fixed build epoch (default 1700000000)
#   DEBIAN_SNAPSHOT    Debian snapshot (default 20260615T000000Z)
#   IMAGE_TAG          local OCI tag for the rootfs export (default secgit/secgit-server:m7)
#   SECGIT_SB_KEY      PEM private key to sign the UKI (SecureBoot); unset => unsigned dev UKI
#   SECGIT_SB_CERT     X.509 cert matching SECGIT_SB_KEY
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
guest_dir="$repo_root/deploy/guest"
out_dir="$guest_dir/out"
inputs_example="$repo_root/deploy/snp-inputs.example.json"
inputs="$repo_root/snp-inputs.json"
manifest="$repo_root/image-manifest.json"
reference="$repo_root/snp-reference.json"

: "${SOURCE_DATE_EPOCH:=1700000000}"
: "${DEBIAN_SNAPSHOT:=20260615T000000Z}"
: "${IMAGE_TAG:=secgit/secgit-server:m7}"
export SOURCE_DATE_EPOCH DEBIAN_SNAPSHOT

log_path=""
while [ $# -gt 0 ]; do
  case "$1" in
    --log) log_path="${2:?--log needs a path}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

cd "$repo_root"
mkdir -p "$out_dir"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker required" >&2; exit 2; }
command -v mkosi  >/dev/null 2>&1 || { echo "ERROR: mkosi required (>= 20)" >&2; exit 2; }

sha384_of() {
  if command -v sha384sum >/dev/null 2>&1; then sha384sum "$1" | awk '{print $1}';
  else openssl dgst -sha384 "$1" | awk '{print $NF}'; fi
}

# --- 0. OVMF firmware -------------------------------------------------------------------
if [ ! -f "$out_dir/OVMF.fd" ]; then
  if [ -n "${EDK2_COMMIT:-}" ]; then
    echo ">>> OVMF.fd missing; building it via build-ovmf.sh"
    "$guest_dir/build-ovmf.sh"
  else
    echo "ERROR: $out_dir/OVMF.fd missing. Run deploy/guest/build-ovmf.sh first" >&2
    echo "       (or set EDK2_COMMIT=<sha> to have this script build it)." >&2
    exit 2
  fi
fi

# --- 1. reproducible OCI image + rootfs export ------------------------------------------
echo ">>> building reproducible OCI image ($IMAGE_TAG)"
docker build \
  --file deploy/Dockerfile \
  --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --tag "$IMAGE_TAG" \
  .

rootfs="$(mktemp -d)"
cid="$(docker create "$IMAGE_TAG")"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$rootfs"' EXIT
echo ">>> exporting OCI rootfs for the guest import"
docker export "$cid" | tar -x -C "$rootfs"

# Lift the image-transparency manifest out of the rootfs so snp-measure can cross-check the
# launch inputs against the exact binaries the OCI reproducibility gate verified.
if [ -f "$rootfs/usr/local/share/secgit/image-manifest.json" ]; then
  cp "$rootfs/usr/local/share/secgit/image-manifest.json" "$manifest"
fi

# --- 2. mkosi -> reproducible dm-verity root disk + signed UKI --------------------------
echo ">>> assembling the guest (dm-verity root + UKI) with mkosi"
export SECGIT_OCI_ROOTFS="$rootfs"
mkosi_args=(--directory "$guest_dir" --output-dir "$out_dir" --force)
if [ -n "${SECGIT_SB_KEY:-}" ] && [ -n "${SECGIT_SB_CERT:-}" ]; then
  echo ">>> signing the UKI with the supplied SecureBoot key"
  mkosi_args+=(--secure-boot-key "$SECGIT_SB_KEY" --secure-boot-certificate "$SECGIT_SB_CERT")
else
  echo "WARNING: SECGIT_SB_KEY/SECGIT_SB_CERT unset — building an UNSIGNED UKI (dev only)." >&2
fi
mkosi "${mkosi_args[@]}" build

uki="$out_dir/secgit-guest.efi"
if [ ! -f "$uki" ]; then
  # mkosi may name the UKI after Output=; accept the first *.efi it produced.
  uki="$(find "$out_dir" -maxdepth 1 -name '*.efi' | head -n1 || true)"
fi
[ -n "$uki" ] && [ -f "$uki" ] || { echo "ERROR: mkosi produced no UKI (.efi) in $out_dir" >&2; exit 1; }

# The dm-verity root disk (root + hash partitions) the launcher attaches as /dev/vda.
root_disk="$out_dir/secgit-guest.raw"
if [ ! -f "$root_disk" ]; then
  root_disk="$(find "$out_dir" -maxdepth 1 -name '*.raw' ! -name '*.verity' | head -n1 || true)"
fi
[ -n "$root_disk" ] && [ -f "$root_disk" ] || { echo "ERROR: mkosi produced no root disk (.raw) in $out_dir" >&2; exit 1; }

# --- 3. recompute digests + pin ---------------------------------------------------------
ovmf_sha="$(sha384_of "$out_dir/OVMF.fd")"
uki_sha="$(sha384_of "$uki")"
echo ">>> OVMF.fd sha384 = $ovmf_sha"
echo ">>> UKI      sha384 = $uki_sha  ($uki)"

python3 - "$inputs_example" "$inputs" "$out_dir/OVMF.fd" "$uki" "$ovmf_sha" "$uki_sha" <<'PY'
import json, sys
ex, out, ovmf_path, uki_path, ovmf_sha, uki_sha = sys.argv[1:7]
with open(ex) as f:
    d = json.load(f)
d.pop("_comment", None)
d["ovmf"] = ovmf_path
d["kernel"] = uki_path
for a in d.get("expected_artifacts", []):
    if a.get("role") == "ovmf":
        a["path"], a["sha384_hex"] = ovmf_path, ovmf_sha
    elif a.get("role") == "uki":
        a["path"], a["sha384_hex"] = uki_path, uki_sha
with open(out, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
print(f"wrote {out}")
PY

# --- 4. commit-bound predicted measurement ----------------------------------------------
echo ">>> predicting the launch measurement (fail-closed digest bind)"
xtask_args=(run -p xtask --release --locked -- snp-measure --inputs "$inputs" --out "$reference")
[ -f "$manifest" ] && xtask_args+=(--image-manifest "$manifest")
[ -n "$log_path" ] && xtask_args+=(--log "$log_path")
cargo "${xtask_args[@]}"

echo
echo "[OK] guest assembled and measurement bound."
echo "     UKI:        $uki   (SecureBoot-signed; embeds the dm-verity roothash)"
echo "     root disk:  $root_disk   (dm-verity root+hash; attach as /dev/vda)"
echo "     OVMF:       $out_dir/OVMF.fd"
echo "     inputs:     $inputs"
echo "     reference:  $reference   (pin into SECGIT_SNP_REFERENCE / Policy.allowed_measurements)"
echo
echo "Next: deploy/guest/launch-snp.sh boots this under QEMU with kernel-hashes=on;"
echo "      xtask provenance signs the artifact set; secgit-verify acceptance-snp proves"
echo "      predicted == live on real silicon."
