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
- `xtask snp-measure --inputs <descriptor> --image-manifest <manifest> --log <log>` ->
  recompute launch-input digests (fail-closed on mismatch), bind the source `git_commit`,
  and emit a commit-bound `snp-reference.json` published to the transparency log.

## Update (M5): resolved sub-decisions and the commit-bound chain
- **OCI reproducibility is CI-gated.** `deploy/Dockerfile` pins base images by digest, apt
  by Debian snapshot, threads `SOURCE_DATE_EPOCH` (with BuildKit `rewrite-timestamp`), and
  uses `--locked` + `--remap-path-prefix`. `deploy/repro-build.sh` builds twice and fails on
  any digest drift (CI `reproducibility` job). This is the precondition for claim 5.
- **Guest toolchain sub-decision resolved: mkosi -> UKI** (closes the ADR 0010 "plain cargo
  vs Nix" residual for the guest image). `deploy/guest/` scaffolds a reproducible UKI build
  and pins the OVMF firmware provenance (`ovmf.pin.json`); actual assembly is M7.
- **Chain published:** git commit -> reproducible image -> predicted launch measurement,
  emitted as a signed transparency artifact and diffed predicted-vs-live by the acceptance
  harness.

## `[VERIFY]`
The exact launch-context measurement is produced by `sev-snp-measure` over the VM launch
context (OVMF measured-direct-boot of the UKI, `kernel-hashes=on`, OVMF built from
`AmdSev/AmdSevX64.dsc`); the descriptor records `vmm_launch_method` so an **IGVM** launch
path (measured with `igvmmeasure`) can be swapped in. The live predicted-vs-live match (and
TDX MRTD) remains an on-silicon task (M7 + acceptance). `xtask` manages the manifest /
transparency / prediction plumbing around it today.
