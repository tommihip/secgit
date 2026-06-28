# ADR 0002: CVM target and provider-neutral attestation

Status: accepted

## Decision
CVM-based confidential computing (AMD SEV-SNP / Intel TDX), whole-VM TCB, over
enclave-only models. Attestation is **provider-neutral** and **vendor-root-anchored**:

- Guest evidence via the cross-vendor Linux `configfs-tsm` interface
  (`/sys/kernel/config/tsm/report`, kernel 6.7+) — NOT cloud IMDS, NOT a vTPM.
- Verification against CPU-vendor roots: AMD `ARK -> ASK -> VCEK -> report` (VCEK from
  AMD KDS, offline cache for air-gap); Intel DCAP for TDX.
- **No cloud-specific attestation dependency** anywhere in the tree (no `az-*-vtpm`,
  MAA, IMDS, SaaS attestation). Enforced by `deny.toml` and a runtime guard in the
  Trustee adapter.

## Abstraction (`crates/secgit-attest`)
`Attester` (guest) and `Verifier` (relying party) traits with backends `snp`, `tdx`,
`mock`. SEV-SNP first; TDX behind the same traits. The `mock` backend is dev/CI only;
the vertical slice is proven on real AMD SEV-SNP silicon.

## Build on Trustee, on our terms
We self-host Confidential Containers Trustee (KBS + Attestation Service) using only the
provider-neutral `snp`/`tdx` verifier drivers, verifying against vendor roots, with no
external attestation SaaS. We keep a clean swap boundary (`KeyRelease`) and own the
BYOK/KEK envelope and resource-release policy on top. Trustee is Apache-2.0 and
spin-out-safe; no clean-room rewrite is planned.

## Reproducible build == running image
The attestation `MEASUREMENT` must equal a value derived from the reproducible OSS
build (ADR 0005), published to the transparency log, so users verify "running image ==
OSS build."

## `[VERIFY]` / status
- `az-snp-vtpm`/`az-tdx-vtpm` exist but are FORBIDDEN (cloud-coupled). We use
  `virtee/sev` + `snpguest` primitives and our own verifier instead.
- Trustee bare-metal SNP launch-measurement validation has known gaps; we own the
  reference-value (RVPS) pipeline for firmware + kernel + initrd + cmdline.

## Residual sub-decision
Which CVM/sovereign substrate to prove on first — see ADR 0010.
