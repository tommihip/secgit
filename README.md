# SecGit

> Provider-blind, attestation-backed, post-quantum code hosting for regulated and
> sensitive **private** code.

The operator can't read your code, can't train on it, can't be subpoenaed into
surrendering it, and your data is safe from harvest-now-decrypt-later — **and all of
this is verifiable.**

## The wedge

- **Provider-blind hosting** — plaintext exists only inside an attestable TEE (CVM).
- **User-verifiable remote attestation** — anyone can confirm the running service
  matches the open-source, reproducibly-built image and that confidentiality holds.
- **BYOK / customer-held keys** with attestation-gated key release.
- **Independent tamper-evident audit log** (hash-chained / Merkle transparency log).
- **"No AI training"** as a *consequence* of provider-blindness, not a policy promise.
- **Hybrid post-quantum cryptography** for storage keys, key release, transport, and
  the signatures we control.

## Architecture at a glance

```
crates/
  secgit-crypto     crypto-agility core (versioned envelopes; AES/ChaCha, hybrid
                    X25519+ML-KEM-768, hybrid Ed25519+ML-DSA, swappable schemes)
  secgit-attest     provider-neutral attestation (configfs-tsm reports; AMD/Intel
                    vendor-root verification; snp / tdx / mock backends)
  secgit-keybroker  attestation-gated KEK release (Trustee KBS+AS adapter + local
                    RCAR broker); BYOK + resource-release policy
  secgit-store      encrypted-at-rest object store (per-repo DEK wrapped by KEK)
  secgit-audit      independent hash-chain + Merkle transparency log, PQC-signed
  secgit-identity   User -> Org(Team) -> Repo model; pluggable auth (OIDC + local)
  secgit-forge      minimal forge: gix for reads, git CLI as pack engine
  secgit-git        smart-HTTP wire handler (shells to git-upload-pack/receive-pack)
  secgit-api        framework-agnostic handlers + sandbox-tier policy
  secgit-verify     standalone user-facing attestation verifier (CLI)
bins/
  secgit-server     the binary that runs inside the confidential VM
xtask/              reproducible-build + image-transparency tooling
```

## Honest caveat

Hardware TEE attestation (SEV-SNP / TDX) currently signs with classical ECDSA
controlled by the CPU vendor and cannot be made post-quantum unilaterally. We claim
**post-quantum confidential storage and transport**, *not* fully post-quantum
attestation, and we layer our own hybrid-PQC signatures on top everywhere we control
them. See `docs/adr/0004-crypto-stack.md`.

## Build order

The **attestation vertical slice comes first** (M1). See
`docs/adr/0009-milestones.md`.

## Status

Foundation / pre-alpha. `[VERIFY]` markers in code and ADRs flag fast-moving upstream
tooling (rustls/aws-lc-rs PQC, gitoxide server-side, CVM attestation libs) whose
versions should be re-checked at implementation time.

## License

AGPL-3.0-or-later. Contributions require DCO sign-off and the CLA — see
`CONTRIBUTING.md`.
