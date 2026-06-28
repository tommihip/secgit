# ADR 0004: Hybrid post-quantum crypto stack and crypto-agility

Status: accepted

## Decision
Hybrid post-quantum cryptography with crypto-agility: every ciphertext and signature
carries a `(kind, scheme, version)` header (`crates/secgit-crypto`), so schemes are
swappable without format breaks.

| Use | Primitive | Where |
| --- | --- | --- |
| Bulk data at rest | AES-256-GCM / ChaCha20-Poly1305 | `aead` |
| Key wrap (DEK under KEK) | AEAD key-wrap | `aead::wrap_key` |
| Key release / BYOK channel | hybrid X25519 + ML-KEM-768 | `kem` |
| Transport | rustls `prefer-post-quantum` (X25519MLKEM768) | reverse proxy / future |
| Signatures (audit, commit, build) | hybrid Ed25519 + ML-DSA-65 | `sig` |
| Long-lived transparency log | hybrid Ed25519 + ML-DSA-87 (SLH-DSA target) | `sig` |

Library: aws-lc-rs / rustls PQC path (audited, C-backed) — the one conscious exception
to all-Rust. Track audit status of every crypto dependency.

## Honest caveat (must appear in user-facing claims)
Hardware TEE attestation (SEV-SNP/TDX) signs with **classical vendor ECDSA** and cannot
be made post-quantum unilaterally. We claim "**post-quantum confidential storage and
transport**", NOT "fully post-quantum attestation," and layer our own hybrid-PQC
signatures on top everywhere we control the keys.

## `[VERIFY]` status (June 2026)
- rustls `X25519MLKEM768` KEM: stable, default — good.
- aws-lc-rs ML-DSA: only via `unstable::signature` (stabilization slipping; last ETA
  ~Mar 2026). Pinned and isolated in `crates/secgit-crypto/src/mldsa.rs`.
- aws-lc-rs has **no SLH-DSA** — see ADR 0010 for the long-lived-log sub-decision.
- aws-lc / aws-lc-sys relicensed to Apache-2.0 (~Mar 2026): the old OpenSSL
  advertising-clause / AGPL-incompatibility is resolved. Clean for an AGPL core.
