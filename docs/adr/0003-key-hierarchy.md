# ADR 0003: Envelope key hierarchy and attestation-gated KEK release

Status: accepted

## Decision
Envelope encryption:

```
KEK (customer-controlled; org-level, or user-level for personal repos)
  └─ wraps ─> per-repo DEK (stored wrapped on disk)
                └─ encrypts ─> repo bytes (AEAD)
```

- The **KEK is released into the TEE only after successful attestation** and lives in
  TEE memory only; it never touches disk.
- The **DEK** appears on disk only wrapped by the KEK (`crates/secgit-store`).
- Demo/personal = platform/user-managed keys; enterprise = org BYOK to a customer
  KMS/HSM, released through the same attestation gate.

## Release protocol (RCAR) — `crates/secgit-keybroker`
1. The TEE generates an ephemeral hybrid (X25519+ML-KEM-768) keypair and a nonce, and
   binds `SHA-512(nonce || tee_pubkey)` into the attestation `report_data`.
2. It sends `{resource_id, evidence, runtime_pubkey, nonce}` to the broker.
3. The broker verifies evidence (provider-neutral verifier + measurement policy),
   re-derives and checks the binding, then **encapsulates the KEK to the TEE pubkey**.
4. Only the attested TEE can open the wrapped KEK.

`KeyRelease` is the swap boundary: `LocalKeyBroker` (in-tree, complete) today; the
self-hosted Trustee KBS adapter swaps in with no caller changes.

## Rotation / revocation
KEKs and DEKs are versioned (crypto-agility, ADR 0004). KEK rotation rewraps DEKs;
revocation = refuse release + re-encrypt. Per-resource policy lives in the broker.

## Residual sub-decision
Key recovery / escrow policy and its honesty/UX tradeoff — see ADR 0010.
