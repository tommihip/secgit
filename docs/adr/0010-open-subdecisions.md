# ADR 0010: Open sub-decisions to settle

Status: open — these are surfaced for an explicit decision; they do not reopen settled
decisions. Each lists options, a recommendation, and the tradeoff.

## 1. Key recovery / escrow policy (from ADR 0003)
The honesty/UX crux of the whole wedge.

- **(A) True zero-knowledge** — no escrow; lose the KEK, lose the data. Maximally
  honest ("the operator literally cannot recover or surrender your code"). Worst UX;
  one lost key = permanent loss.
- **(B) Customer-held recovery** — Shamir split / social recovery with shares held by
  the customer (and/or hardware tokens). Operator still can't recover unilaterally.
  Good honesty, better UX, more moving parts.
- **(C) Org-KMS escrow** — recovery via the customer's own KMS/HSM. Recoverable by the
  customer's KMS admins, not the operator. Best enterprise UX; weakest "even you can't
  be coerced" story.

Recommendation: default **(A)** for the anonymous/personal tiers (it is the cleanest
proof of the claim) and offer **(B)/(C)** as opt-in for orgs. Critically: the public
claim wording must match the tier (see item 4).

## 2. SLH-DSA source for the long-lived transparency log (from ADR 0004)
aws-lc-rs has no SLH-DSA today.

- **(A) Ship ML-DSA-87 now**, swap SLH-DSA later via crypto-agility (no format break).
  Recommended — keeps the audited-C preference and unblocks M3/M5.
- **(B) `fips205` pure-Rust crate** — gets SLH-DSA now but violates the audited-C
  preference (track audit status).
- **(C) OpenSSL 3.5 binding** — SLH-DSA available, adds a second C crypto stack.

Recommendation: **(A)** now; revisit when aws-lc-rs adds SLH-DSA or an audited Rust
implementation lands.

## 3. First CVM / sovereign substrate to prove on (from ADR 0002)
Decision taken: provider-neutral, vendor-root-anchored, **lean SEV-SNP first**, with a
hardware-agnostic abstraction and a mock for CI. Remaining choice is *where* to run the
first real-silicon proof:

- Bare-metal AMD SEV-SNP on an EU-owned provider (OVHcloud/Scaleway) — maximum
  sovereignty purity; we own more host/launch tooling.
- A managed SEV-SNP CVM for the first proof, then port to bare-metal EU.

Recommendation: prove the slice on whatever genuine SEV-SNP silicon is fastest to
access, but keep the verifier cloud-agnostic so the sovereign-bare-metal target is a
deployment choice, not a code change. (No cloud attestation dependency either way.)

## 5. Attestation freshness: replay-detection vs broker-issued challenge (from the trust path)
The KEK-release flow binds a **guest-chosen** nonce + timestamp into the attested
`report_data` (`SHA-512(nonce ‖ timestamp ‖ ephemeral KEM pubkey)`), and the broker enforces
a durable, TTL-bounded **replay guard** (`secgit-keybroker::replay`): reused nonces and
out-of-window timestamps are refused. This is **replay-detection + bounded staleness**, not
verifier-guaranteed freshness — because the guest still picks the nonce/timestamp.

- **(A) Guest nonce + broker-side replay guard (current).** No extra round-trip; durable,
  restart-surviving, fail-safe. Cannot, by itself, prove liveness against a guest that
  colludes to pre-mint evidence within the TTL.
- **(B) Broker-issued challenge.** The *broker* picks the nonce (RCAR challenge) so freshness
  is verifier-guaranteed. Costs a round-trip and broker-side challenge state; strongest
  guarantee.

Recommendation: keep **(A)** as shipped (documented honestly in `docs/threat-model.md` T7),
and revisit **(B)** with the security auditor — it is the natural upgrade if a stronger
liveness guarantee is required. Tracked here so the limitation is explicit, not implicit.

## 4. Claim wording vs escrow/attestation reality
- Storage/transport: "post-quantum" — OK.
- Attestation: "hybrid-PQC signatures layered on classical vendor-ECDSA hardware
  attestation" — never "fully post-quantum attestation" (ADR 0004 caveat).
- Recoverability: the "operator can't surrender your code" claim is only literally true
  under option 1(A); for 1(B)/1(C) the wording must shift to "the operator can't
  unilaterally recover/surrender your code." Marketing copy must be tier-accurate.
