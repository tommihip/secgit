# Metadata confidentiality boundary

This document states, honestly and precisely, what SecGit protects from the operator and
what it does not. The wedge is "the operator can't read your code" — but a credible
confidentiality claim must also be explicit about *metadata*, because metadata leaks
(repo names, who pushed what when) can be as sensitive as contents.

This boundary is enforced in code and accompanied by leak-tests (see A.4). It is not a
policy promise.

## Protected (ciphertext at rest; never plaintext to the operator)

- **Repository contents** — every git object. Stored only as an encrypted `git bundle`
  under the repo DEK (`secgit-store` + `secgit-forge`). Plaintext exists only inside the
  CVM on the working path (ideally tmpfs), unlocked by the attestation-released KEK.
- **Repository/DEK identifiers on disk** — store paths are `sha256(repo_id)`, not names.
- **Audit-log event metadata** — repo ids, owners, ref names, actors, and event types.
  When the server runs with an instance audit key (the default in `secgit-server`, see
  `derive_audit_key`), each transparency-log record is AEAD-sealed
  (`TransparencyLog::open_encrypted`). The operator sees only ciphertext lines.
- **Released keys (KEK/DEK)** — never written to disk; KEK lives only in CVM memory after
  attestation; DEKs are stored wrapped under the KEK.
- **Transport payloads** — once in-CVM PQC-TLS is enabled (A.3), git/HTTP bytes are
  ciphertext on the wire up to the CVM boundary (no external-proxy plaintext hop).

## Publicly verifiable WITHOUT revealing protected metadata

The independent-verifiability guarantees do not require exposing any of the above:

- **Signed checkpoints** (`Checkpoint`) commit only to the Merkle **root hash** + tree
  size + timestamp, signed with the long-lived hybrid-PQC key. They reveal nothing about
  individual events.
- **Inclusion / consistency proofs** are sequences of **hashes** only. A relying party
  who already knows *their own* event can prove it is in the log without the operator (or
  anyone else) learning other events.

So a third party can confirm "the log is append-only and my push is in it" while the
event corpus stays confidential.

## Observable to the operator (honest limits)

A whole-VM CVM with encrypted memory + encrypted storage still leaves some signals. We do
NOT claim to hide these in v1, and we say so plainly:

- **Aggregate ciphertext volume / growth** — total bytes stored and that they increased
  after a push (per-repo sizes are obscured by per-object encryption + hashed paths, but
  gross volume is visible).
- **Coarse timing / traffic patterns** — that the service received requests and when, and
  approximate request sizes (mitigated, not eliminated, by TLS record padding). Network
  metadata to/from the CVM is visible to the host.
- **Existence and liveness** of the service and the number of on-disk objects/log records
  (counts, not contents).
- **The reproducible-build measurement** — deliberately public; it is the anchor that
  proves "running image == OSS build."

Defeating traffic-analysis and volume side channels (constant-rate padding, ORAM-style
access) is explicitly out of scope for v1 and noted in the threat model
(`docs/threat-model.md`).

## Hardware caveat (unchanged)

The SEV-SNP/TDX attestation report itself is signed by the CPU vendor with **classical
ECDSA**. We layer hybrid-PQC signatures everywhere we control keys (audit log, commit and
build attestations) but cannot make the hardware attestation post-quantum unilaterally.
Claim: "post-quantum confidential storage and transport," not "fully post-quantum
attestation."
