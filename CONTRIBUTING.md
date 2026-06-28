# Contributing to SecGit

Thank you for helping build provider-blind, verifiable code hosting.

## Developer Certificate of Origin (DCO)

Every commit MUST be signed off, certifying the [DCO](https://developercertificate.org/):

```
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. CI rejects
commits without it.

## Contributor License Agreement (CLA)

To keep clean IP ownership for a possible future spin-out, first-time contributors
must accept the CLA (see `CLA.md`). The CLA bot will prompt you on your first PR.

## Ground rules that protect the wedge

These are enforced in review and (where possible) in CI via `cargo deny`:

1. **No cloud-specific attestation dependencies.** Attestation is provider-neutral
   and anchored to CPU-vendor roots (AMD KDS / Intel DCAP) via `configfs-tsm`.
   Do not add `az-*-vtpm`, MAA/IMDS clients, or any SaaS attestation client.
2. **No plaintext leaves the TEE boundary.** Repo plaintext exists only inside the
   confidential VM. Anything crossing the boundary is ciphertext or attestation
   evidence.
3. **Crypto-agility is mandatory.** Every ciphertext and signature carries an
   algorithm id and version. Never hard-code a scheme at a call site; go through
   `secgit-crypto`.
4. **Audited crypto for PQC.** Production PQC uses the `aws-lc-rs` path. New
   pure-Rust crypto crates need explicit justification in an ADR.

## Building and testing

```
cargo build --workspace
cargo test --workspace
cargo deny check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
