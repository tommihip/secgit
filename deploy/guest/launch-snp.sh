#!/usr/bin/env bash
#
# Launch the SecGit confidential guest under QEMU as an AMD SEV-SNP CVM, MEASURED so the
# running instance's launch measurement equals the value predicted by xtask snp-measure
# (deploy/guest/build-guest.sh -> snp-reference.json). This is the operator-side boot in
# docs/acceptance-snp.md §3; a skeptical verifier then runs `secgit-verify acceptance-snp`.
#
# The measured-direct-boot path folds OVMF + kernel + initrd + cmdline into the SHA-384
# launch digest. That requires:
#   - OVMF.fd built from OvmfPkg/AmdSev/AmdSevX64.dsc with SNP_KERNEL_HASHES (build-ovmf.sh),
#   - kernel-hashes=on on the sev-snp-guest object (set below),
#   - the UKI passed as -kernel and a cmdline byte-identical to snp-inputs.json `append`
#     and to deploy/guest/mkosi.conf KernelCommandLine.
#
# HOST: an AMD EPYC (Milan/Genoa) machine with SEV-SNP enabled, a recent QEMU (>= 9.x with
# sev-snp-guest support), and the guest artifacts from build-guest.sh. Not runnable on macOS.
#
# [VERIFY] QEMU's SEV-SNP object/option names are still stabilising across versions (and some
# stacks launch via IGVM instead — then the measurement is computed with igvmmeasure over the
# IGVM file, and vmm_launch_method in snp-inputs.json must say so). Confirm against your QEMU.
#
# Usage:
#   deploy/guest/launch-snp.sh [--data /var/lib/secgit/data.img] [--reference snp-reference.json]
# Environment (optional; MUST match the values folded into snp-reference.json):
#   VCPUS       vCPU count       (default 4)
#   VCPU_TYPE   QEMU cpu model   (default EPYC-v4)
#   MEM         guest RAM        (default 4096)
#   CMDLINE     kernel cmdline   (default: console=ttyS0 systemd.verity=yes ro)
#   HOST_PORT   forwarded ingress port on the host (default 8443)
#   OVMF        firmware path    (default deploy/guest/out/OVMF.fd)
#   UKI         UKI path         (default deploy/guest/out/secgit-guest.efi)
#   ROOT_DISK   dm-verity root+hash disk image (default deploy/guest/out/secgit-guest.raw)
#   QEMU        qemu binary      (default qemu-system-x86_64)
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
out_dir="$repo_root/deploy/guest/out"

VCPUS="${VCPUS:-4}"
VCPU_TYPE="${VCPU_TYPE:-EPYC-v4}"
MEM="${MEM:-4096}"
CMDLINE="${CMDLINE:-console=ttyS0 systemd.verity=yes ro}"
HOST_PORT="${HOST_PORT:-8443}"
OVMF="${OVMF:-$out_dir/OVMF.fd}"
UKI="${UKI:-$out_dir/secgit-guest.efi}"
ROOT_DISK="${ROOT_DISK:-$out_dir/secgit-guest.raw}"
QEMU="${QEMU:-qemu-system-x86_64}"

data_img=""
reference="$repo_root/snp-reference.json"
while [ $# -gt 0 ]; do
  case "$1" in
    --data) data_img="${2:?--data needs a path}"; shift 2 ;;
    --reference) reference="${2:?--reference needs a path}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v "$QEMU" >/dev/null 2>&1 || { echo "ERROR: $QEMU not found" >&2; exit 2; }
[ -f "$OVMF" ] || { echo "ERROR: OVMF firmware missing: $OVMF (run build-ovmf.sh)" >&2; exit 2; }
[ -f "$UKI" ]  || { echo "ERROR: guest UKI missing: $UKI (run build-guest.sh)" >&2; exit 2; }
[ -f "$ROOT_DISK" ] || { echo "ERROR: dm-verity root disk missing: $ROOT_DISK (run build-guest.sh)" >&2; exit 2; }

# The kernel cmdline is measurement-critical: warn loudly if it diverges from the reference.
if [ -f "$reference" ] && command -v python3 >/dev/null 2>&1; then
  ref_append="$(python3 - "$reference" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("params", {}).get("append", ""))
except Exception:
    print("")
PY
)"
  if [ -n "$ref_append" ] && [ "$ref_append" != "$CMDLINE" ]; then
    echo "WARNING: CMDLINE differs from snp-reference.json append — the live measurement" >&2
    echo "         WILL NOT match the prediction. Reference: [$ref_append]  Launch: [$CMDLINE]" >&2
  fi
fi

# The dm-verity root disk (root + hash partitions). Its integrity is anchored by the roothash
# embedded in the MEASURED UKI, so the untrusted host cannot tamper with it undetected. It is
# the first virtio disk (/dev/vda); systemd auto-discovers the root + verity partitions.
disk_args=(-drive "file=$ROOT_DISK,if=virtio,format=raw")

# Persistent encrypted data disk (ciphertext-only from the host's view; the guest decrypts in
# CVM memory after the attestation-gated KEK release). Created sparse on first launch.
if [ -n "$data_img" ]; then
  if [ ! -f "$data_img" ]; then
    echo ">>> creating 20G data image at $data_img"
    mkdir -p "$(dirname "$data_img")"
    truncate -s 20G "$data_img"
  fi
  disk_args+=(-drive "file=$data_img,if=virtio,format=raw")
fi

echo ">>> launching SecGit SEV-SNP guest (measured direct boot, kernel-hashes=on)"
echo "    vcpus=$VCPUS type=$VCPU_TYPE mem=${MEM}M ingress=host:${HOST_PORT}->guest:8443"

# The launch context below MUST correspond 1:1 with snp-inputs.json (OVMF, UKI, cmdline,
# vcpus, vcpu type). sev-snp-guest with kernel-hashes=on is what includes the kernel/initrd/
# cmdline hashes in the SHA-384 measurement; id-block/auth are optional pinning left to the
# operator's key policy.
exec "$QEMU" \
  -enable-kvm \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off \
  -object memory-backend-memfd,id=ram1,size="${MEM}M",share=true,prealloc=false \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
  -cpu "$VCPU_TYPE" \
  -smp "$VCPUS" \
  -m "${MEM}M" \
  -no-reboot \
  -bios "$OVMF" \
  -kernel "$UKI" \
  -append "$CMDLINE" \
  "${disk_args[@]}" \
  -netdev user,id=net0,hostfwd=tcp::"${HOST_PORT}"-:8443 \
  -device virtio-net-pci,netdev=net0 \
  -nographic
