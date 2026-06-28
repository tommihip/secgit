# ADR 0005: Reproducible builds and image transparency

Status: accepted

## Decision
The verifiability claim ("running image == audited OSS build") requires:

1. **Reproducible builds**: pinned Rust toolchain (`rust-toolchain`/Dockerfile ARG),
   `Cargo.lock` enforced with `--locked`, `SOURCE_DATE_EPOCH` set, `panic=abort` +
   `strip` + `codegen-units=1` in the release profile, no embedded build paths/time.
2. **Deterministic measurement**: the SEV-SNP `MEASUREMENT` (SHA-384 over the guest
   launch context: firmware/OVMF + kernel + initrd + cmdline) must be derivable from
   the reproducible build outputs.
3. **Image transparency**: publish the measurement (and artifact digests) to the
   PQC-signed transparency log (`crates/secgit-audit`) via `xtask emit-transparency`,
   so a verifier compares the attested measurement to the published OSS-build value.

## Tooling (`xtask`)
- `xtask measure <artifacts...>` -> deterministic SHA-384 digests + `image-manifest.json`.
- `xtask emit-transparency <manifest> <log>` -> append to a PQC-signed transparency log.
- `xtask verify-image <manifest> <sha384>` -> check a digest is published.

## `[VERIFY]`
The exact launch-context measurement is produced by `sev-snp-measure` over the VM
launch context; wiring it (and TDX MRTD) to the reproducible artifacts is an M5 task on
real silicon. `xtask` manages the manifest/transparency plumbing around it today.

## Residual sub-decision
Reproducible-build toolchain specifics (plain cargo + pinned toolchain vs Nix) — see
ADR 0010.
