# ADR 0009: Master milestone map (attestation vertical slice FIRST)

Status: accepted

Hard principle: DEPTH on the verifiable confidential claim; FLOOR on commodity forge
features. The failure mode is "the confidentiality claim isn't verifiable
end-to-end," not "fewer features than GitHub."

## Milestones (each maps to crates)
- **M0 Foundation** — workspace, AGPL+DCO/CLA, CI, `cargo-deny` ban-list,
  `secgit-crypto` agility core + `mock` TEE.
- **M1 Attestation vertical slice (headline)** — `secgit-attest` (provider-neutral
  SNP via `configfs-tsm` + vendor-root verifier; mock for CI), `secgit-keybroker`
  (attestation-gated KEK release; Trustee swap boundary), `secgit-verify` (user-facing
  flow). Proven on real AMD SEV-SNP silicon. Done = an outsider verifies the running
  TEE and a KEK releases only after attestation. (`secgit-verify selftest` runs it.)
- **M2 Confidential storage + minimal forge** — `secgit-store` (envelope encryption),
  `secgit-forge` (gix reads + git-CLI pack engine), `secgit-git` (smart-HTTP),
  `secgit-server` serves a private repo end-to-end with the M1 KEK.
- **M3 Transparency-log audit** — `secgit-audit` (hash-chain + Merkle, PQC-signed
  checkpoints; inclusion/consistency proofs); commit/build attestation signing.
- **M4 Identity + access control** — `secgit-identity` (User/Org/Repo, OIDC+local).
- **M5 Reproducible builds + image transparency** — `xtask`; bind launch measurement
  to the OSS build so "running image == OSS build" is user-verifiable.
- **M6 Demo-as-sandbox tiers** — `secgit-api` (anonymous ephemeral repo, light
  account) + public instance with abuse/DoS controls. **Delivered (MOCK-VERIFIED):**
  transport hardening (connection cap, socket timeouts/slowloris, header/body caps,
  chunked rejection), memory-bounded per-IP/-account/-repo token-bucket rate limits keyed
  on the TCP peer IP, git-pack + subprocess wall-clock/size bounds (`fsckObjects`), bounded
  `seal_to_store` (push-rate + seal-concurrency + bundle wall-clock), ephemeral GC +
  startup reconciliation, an optional hashcash PoW gate (default off), an encrypted
  abuse-report queue with audit-logged operator takedown, content-free token-gated
  metrics, and per-tier confidentiality leak-tests. See ADR 0007 for the control detail.
- **M7 Packaging** — OCI + Compose for a confidential VM (`deploy/`); hardening.

## Out of v1
Confidential CI (v2 headline); v1 uses customer-controlled external runners.
