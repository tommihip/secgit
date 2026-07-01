#!/usr/bin/env bash
#
# Build the OVMF firmware that measured-direct-boots the SecGit guest UKI, REPRODUCIBLY,
# from a pinned edk2 commit. The firmware is folded into the SEV-SNP launch measurement, so
# it must be built from a pinned source with a fixed toolchain and its digest pinned in
# deploy/guest/ovmf.pin.json.
#
# WHY AmdSev (not stock OVMF): measured direct boot requires OvmfPkg/AmdSev/AmdSevX64.dsc,
# which emits a single OVMF.fd carrying the SNP_KERNEL_HASHES metadata section. The launcher
# then sets kernel-hashes=on (see deploy/guest/launch-snp.sh) so the kernel/initrd/cmdline
# hashes are included in the measurement. A stock OvmfPkgX64.dsc build does NOT do this.
#
# BUILD HOST: this runs on Linux/x86_64 (or in a Linux container). It cannot run on macOS.
# The build is executed inside a pinned Debian-snapshot container for a deterministic
# toolchain; pass BUILD_LOCAL=1 to build directly on the host instead (less reproducible).
#
# [VERIFY] edk2 reproducibility is good but not perfect across toolchain versions. Always
# confirm two independent runs produce the same sha384 before pinning; the pinned toolchain
# container is what makes this hold across time.
#
# Usage:
#   EDK2_COMMIT=<sha> deploy/guest/build-ovmf.sh          # build in pinned container
#   BUILD_LOCAL=1 deploy/guest/build-ovmf.sh              # build on this host directly
#
# Environment (optional unless noted):
#   EDK2_COMMIT        edk2 commit to build (falls back to ovmf.pin.json edk2_commit)
#   EDK2_REPO          edk2 git remote (default: from ovmf.pin.json)
#   SOURCE_DATE_EPOCH  fixed build epoch (default 1700000000; matches everything else)
#   DEBIAN_SNAPSHOT    builder base snapshot (default 20240701T000000Z; matches Dockerfile)
#   BUILD_LOCAL=1      skip the container and build on the host toolchain
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
guest_dir="$repo_root/deploy/guest"
out_dir="$guest_dir/out"
pin_file="$guest_dir/ovmf.pin.json"

: "${SOURCE_DATE_EPOCH:=1700000000}"
: "${DEBIAN_SNAPSHOT:=20240701T000000Z}"
export SOURCE_DATE_EPOCH

# Pull pinned values out of ovmf.pin.json (python3 for robust JSON parsing; no jq dep).
read_pin() {
  python3 - "$pin_file" "$1" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print(d.get(sys.argv[2], ""))
PY
}

EDK2_REPO="${EDK2_REPO:-$(read_pin edk2_repo)}"
EDK2_REPO="${EDK2_REPO:-https://github.com/tianocore/edk2}"
EDK2_COMMIT="${EDK2_COMMIT:-$(read_pin edk2_commit)}"

case "$EDK2_COMMIT" in
  ""|REPLACE_WITH_PINNED_EDK2_COMMIT_SHA)
    echo "ERROR: no pinned edk2 commit. Set EDK2_COMMIT=<sha> (a reviewed, reproducible" >&2
    echo "       tianocore/edk2 revision that builds OvmfPkg/AmdSev/AmdSevX64.dsc), then" >&2
    echo "       this script pins its resolved sha into deploy/guest/ovmf.pin.json." >&2
    exit 2
    ;;
esac

mkdir -p "$out_dir"

# The actual build steps, run either in a pinned container or directly on the host.
build_script='
set -euxo pipefail
export SOURCE_DATE_EPOCH="'"$SOURCE_DATE_EPOCH"'"
export DEBIAN_FRONTEND=noninteractive
work="$(mktemp -d)"
cd "$work"
git clone --no-checkout "'"$EDK2_REPO"'" edk2
cd edk2
git checkout "'"$EDK2_COMMIT"'"
git submodule update --init --recursive
# Deterministic toolchain flags; strip build paths and timestamps where edk2 allows.
export PYTHON_COMMAND=python3
make -C BaseTools -j"$(nproc)"
. edksetup.sh
# AmdSev target + SNP_KERNEL_HASHES => single OVMF.fd usable with kernel-hashes=on.
build -a X64 -t GCC5 -b RELEASE \
  -p OvmfPkg/AmdSev/AmdSevX64.dsc \
  -D SNP_KERNEL_HASHES=TRUE \
  -D DEBUG_ON_SERIAL_PORT=TRUE
cp Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd "'"$out_dir"'/OVMF.fd"
'

if [ "${BUILD_LOCAL:-0}" = "1" ]; then
  echo ">>> building OVMF on the host (BUILD_LOCAL=1; less reproducible across machines)"
  bash -c "$build_script"
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found. Install docker, or set BUILD_LOCAL=1 to build on the host." >&2
    exit 2
  fi
  echo ">>> building OVMF in a pinned Debian-snapshot container (deterministic toolchain)"
  # Pin the builder toolchain to the same Debian snapshot the rest of the build uses so the
  # firmware bytes do not float with the host's package versions.
  builder_setup='
set -eux
printf "Types: deb\nURIs: https://snapshot.debian.org/archive/debian/'"$DEBIAN_SNAPSHOT"'/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n" > /etc/apt/sources.list.d/debian.sources
rm -f /etc/apt/sources.list
echo "Acquire::Check-Valid-Until \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until
apt-get update
apt-get install -y --no-install-recommends \
  build-essential uuid-dev iasl nasm python3 python3-distutils git ca-certificates
'
  docker run --rm \
    -e SOURCE_DATE_EPOCH \
    -v "$out_dir":"$out_dir" \
    debian:bookworm-slim \
    bash -c "$builder_setup"$'\n'"$build_script"
fi

if [ ! -f "$out_dir/OVMF.fd" ]; then
  echo "ERROR: build did not produce $out_dir/OVMF.fd" >&2
  exit 1
fi

# Compute the SHA-384 of the firmware (portable: sha384sum or openssl).
sha384_of() {
  if command -v sha384sum >/dev/null 2>&1; then
    sha384sum "$1" | awk '{print $1}'
  else
    openssl dgst -sha384 "$1" | awk '{print $NF}'
  fi
}
digest="$(sha384_of "$out_dir/OVMF.fd")"

# Pin the resolved commit + digest back into ovmf.pin.json so the launch descriptor and
# xtask snp-measure bind to the exact bytes.
python3 - "$pin_file" "$EDK2_COMMIT" "$digest" <<'PY'
import json, sys
path, commit, digest = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    d = json.load(f)
d["edk2_commit"] = commit
d["sha384_hex"] = digest
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY

echo
echo "[OK] built OVMF.fd"
echo "     path:   $out_dir/OVMF.fd"
echo "     edk2:   $EDK2_COMMIT"
echo "     sha384: $digest"
echo "     pinned into $pin_file"
echo
echo "Next: deploy/guest/build-guest.sh assembles the UKI and binds the measurement."
