# SecGit verification ledger

This is a **launch-transparency document**: for every load-bearing claim, it states not just
whether code exists, but **how far that claim has actually been verified**. It deliberately
replaces the older DONE/PARTIAL/STUB vocabulary (which conflated "code written" with "claim
proven") — the distinction that matters to a skeptical reader is *what evidence backs this*.

## Verification tags

| Tag | Meaning | Evidence |
|---|---|---|
| **MOCK-VERIFIED** | Proven in CI against the software mock TEE / synthetic fixtures. The logic is exercised and refuses bad input, but **no real silicon was involved**. | `cargo test --workspace --locked`, `secgit-verify selftest`, `--mock` harness |
| **SILICON-VERIFIED** | Proven on a genuine AMD SEV-SNP CVM, captured in a **PQC-signed acceptance transcript** (`secgit-verify acceptance-snp` → `verify-transcript`). | a signed `acceptance-transcript.json` from real hardware |
| **UNVERIFIED** | Requires hardware we have not yet run on, or otherwise not yet proven. Code may exist and be MOCK-VERIFIED, but the end-to-end claim is not established. | — |

> **Current silicon status:** nothing below is `SILICON-VERIFIED` yet — **no signed
> acceptance transcript from real SEV-SNP silicon exists at the time of writing.** Every
> claim that fundamentally depends on the hardware root is therefore `UNVERIFIED` until the
> one-command harness (`docs/acceptance-snp.md` §Quickstart) is run on a provisioned CVM and
> emits a transcript. This honesty is the point of the ledger.

---

## One-line summary

The confidential **core composes end-to-end against the mock TEE** and is MOCK-VERIFIED:
attestation-gated KEK release (with VMPL pinning, a durable replay/freshness guard, and
fail-closed VCEK revocation) → envelope-encrypted store → PQC-signed transparency log, all
provable with `secgit-verify selftest` and `secgit-verify acceptance-snp --mock`. The SNP
trust root (VCEK/KDS chain + CRL + launch-measurement match), in-CVM PQC-TLS channel binding,
and provider-blindness on a real host are **implemented and MOCK-VERIFIED**, but remain
**UNVERIFIED on silicon** pending the signed acceptance transcript.

---

## Resolution of the prior `secgit-attest` contradiction

The previous status said both "`secgit-attest — PARTIAL`" (per-crate) and "User-verifiable
attestation: DONE" (intent). Both were half-true on the wrong axis. Under this ledger:

- **`secgit-attest` code is MOCK-VERIFIED:** report parsing, ECDSA-P384 signature
  verification, the `ARK→ASK→VCEK` X.509 chain (synthetic-chain + pinned-ARK tests), VMPL
  enforcement, and CRL revocation logic all have passing tests.
- **The live attestation claim is UNVERIFIED:** `vendor_verified` against a *genuine* AMD
  report fetched from real KDS, with a real CRL and a measurement match, has not yet run on
  silicon. That flips to SILICON-VERIFIED with the transcript.

No contradiction remains: the code is done and mock-proven; the silicon proof is pending.

---

## Claim ledger (Tier-0 intent)

| # | Claim | Status | Proof / how to reproduce |
|---|---|---|---|
| 1 | Provider-blind **at rest** (store ciphertext-only) | **MOCK-VERIFIED**; UNVERIFIED on a real host disk | `secgit-store::data_on_disk_is_ciphertext`; harness step (f) `--mock`. Silicon: harness step (f) greps `--data-dir` |
| 2 | Provider-blind **in transit** (in-CVM PQC-TLS, no plaintext hop) | **MOCK-VERIFIED** | `tls::handshake_uses_pq_kx_and_wire_is_ciphertext`, `tls::loopback_observer_sees_only_ciphertext` |
| 3 | User-verifiable attestation to **AMD roots** (ARK→ASK→VCEK + KDS) | **MOCK-VERIFIED** (synthetic chain, pinned ARK); UNVERIFIED on silicon | `vcek::{real_ask_chains_to_pinned_ark, wrong_ark_rejects_ask}`; harness step (b) live |
| 4 | VCEK **revocation** (CRL, ASK-signed, fail-closed) | **MOCK-VERIFIED**; UNVERIFIED on silicon | `vcek::{revoked_serial_is_detected, cached_crl_window_is_bounded}`; harness step (b) live |
| 5 | Launch **measurement == reproducible build** | **MOCK-VERIFIED** (tool); UNVERIFIED on silicon (live match) | `xtask` `snp-measure --inputs`; harness step (c) predicted-vs-live diff |
| 6 | Channel binding (report ⇔ live TLS peer) defeats MITM relay | **MOCK-VERIFIED**; UNVERIFIED on silicon | `keybroker::tampered_runtime_pubkey_breaks_binding`; harness step (a) live |
| 7 | Attestation-gated **KEK release** (vendor root + measurement + **VMPL0** + replay/freshness) | **MOCK-VERIFIED**; UNVERIFIED on silicon | `snp::wrong_vmpl_is_refused`, `keybroker::{replayed,stale}_release_is_refused`, `acceptance-snp --expect-refuse …`; harness step (d) live |
| 8 | BYOK / self-hosted KBS (`KeyRelease`) | **MOCK-VERIFIED** (`LocalKeyBroker`); KBS HTTP client UNVERIFIED against a live Trustee | `keybroker` tests; `bins/secgit-server/src/kbs.rs` |
| 9 | Independent **tamper-evident audit log** (+ metadata boundary) | **MOCK-VERIFIED** | `audit::{metadata_boundary_via_leaktest_harness, …}`, `merkle::*`, `secgit-verify verify-checkpoint` |
| 10 | **"No AI training"** as a technical consequence | **MOCK-VERIFIED** | `xtask` `no_ml_or_telemetry_deps_in_graph`, `egress_check…`; `cargo deny check`; T1/T2 leak-tests |
| 11 | Hybrid **PQC** (storage, key release, signatures, transport) | **MOCK-VERIFIED** | `secgit-crypto` tests; `tls::pq_kx_is_preferred` |
| 12 | Reproducible build == running image (transparency artifacts) | **MOCK-VERIFIED** (artifacts); UNVERIFIED that artifact == silicon image | `xtask` manifest/SBOM tests; `/sbom`, `/image-manifest`; claim 5 closes the loop on silicon |

Everything tagged "UNVERIFIED on silicon" becomes SILICON-VERIFIED the moment a signed
`acceptance-transcript.json` covering it is produced by `secgit-verify acceptance-snp --url …`
on a genuine SEV-SNP CVM and re-checked with `verify-transcript`.

---

## Per-crate map (code maturity, independent of silicon proof)

All crates below are MOCK-VERIFIED (tests pass in CI). "Silicon" column flags the part whose
*claim* still needs hardware.

| Crate | Code | Needs silicon for |
|---|---|---|
| `secgit-crypto` | hybrid KEM/sig, AEAD, key-wrap, agility envelope | — |
| `secgit-net` | single audited outbound HTTPS client (rustls + Mozilla roots), shared by server + verify | — |
| `secgit-attest` | trait seam, mock, SNP parse + ECDSA-P384, VCEK chain, **VMPL**, **CRL revocation** | live `vendor_verified` (claims 3–4, 7) |
| `secgit-keybroker` | `LocalKeyBroker` RCAR + KEM-seal, **durable replay/freshness guard**; `trustee` KBS adapter | live KBS + on-silicon release (claims 7–8) |
| `secgit-store` | per-repo DEK envelope, AAD-bound, ciphertext-on-disk | host-disk grep (claim 1) |
| `secgit-audit` | hash chain + RFC 6962 Merkle, PQC checkpoints, encrypted-at-rest metadata boundary | — |
| `secgit-identity` | model + RBAC + local auth; OIDC seam; in-memory directory (persistence is later work) | — |
| `secgit-forge` / `secgit-git` | bare-repo create/seal/restore; smart-HTTP | — |
| `secgit-api` | ephemeral + Light/Managed tiers, quotas | — |
| `secgit-leaktest` | shared canary/at-rest/on-wire leak harness | — |
| `secgit-verify` | `selftest`, `verify-checkpoint`, **`probe-snp`**, **`acceptance-snp` (+`--mock`, `--expect-refuse`)**, **`verify-transcript`** | the live `acceptance-snp` run (produces the transcript) |
| `bins/secgit-server` | in-CVM PQC-TLS, attestation-gated boot, forge/API/web/SSH | on-silicon boot (claims 1–7) |
| `xtask` | image-transparency manifest, SBOM, `snp-measure` (`--inputs`) | live measurement match (claim 5) |

---

## Gate status (CI, no hardware)

`cargo test --workspace --locked` green · `secgit-verify selftest` green ·
`secgit-verify acceptance-snp --mock` green · `cargo fmt --check` green ·
`cargo clippy --all-targets -D warnings` green · `cargo deny check bans licenses sources` green.

`[VERIFY]` `cargo deny check advisories` may abort if the local advisory-db contains a
CVSS v4.0 RUSTSEC entry that the installed cargo-deny cannot parse (a tooling-version issue,
not an advisory hit). Re-check when cargo-deny gains CVSS 4.0 support.

## The single remaining gate to "SILICON-VERIFIED"

Run, on a genuine AMD SEV-SNP CVM running the published reproducible image:

```bash
secgit-verify probe-snp          # raw guest report available (not a cloud vTPM)
secgit-verify acceptance-snp --url https://<host>:<port> --data-dir /var/lib/secgit \
  --product Milan --reference snp-reference.json --out acceptance-transcript.json
secgit-verify verify-transcript acceptance-transcript.json acceptance-transcript.json.vk.json
```

Publishing that signed transcript is what promotes claims 1, 3–7, 12 to **SILICON-VERIFIED**.
Until then this document states, plainly, that they are not.
