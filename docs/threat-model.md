# SecGit Threat Model (as-built)

This document models threats against the **actual code in this repository**, not an
aspirational design. Where the implementation does not yet resist a threat, it says so. It
is paired with the reusable leak-test harness (`secgit-leaktest`) that every
plaintext-touching feature must pass (see §7).

The wedge it defends: *the operator can't read your code, can't train on it, can't be
subpoenaed into surrendering plaintext, and your data resists harvest-now-decrypt-later —
and all of this is verifiable.*

---

## 1. Assets

| Asset | Sensitivity |
|---|---|
| Repository contents (blobs, trees, commits) | highest — the product's reason to exist |
| Repository metadata (names, refs, push graph, actor ids, timestamps) | high — often as revealing as contents |
| Audit/transparency log entries | high (metadata) + integrity-critical |
| KEK (key-encrypting key) and per-repo DEKs | catastrophic if leaked |
| TLS private key (in-CVM) | high (channel integrity) |
| Long-lived log signing key | integrity of the public verifiability story |

---

## 2. Adversaries and trust boundaries

| Adversary | Capability assumed | In TCB? |
|---|---|---|
| **Malicious operator** | full root on the host, reads disk + RAM pages of the *host*, controls networking, can restart/replace processes outside the CVM | **no** — primary adversary |
| **Compromised host OS / hypervisor** | same as above, plus VMM control | **no** — SEV-SNP isolates guest memory |
| **Network attacker / MITM** | observes + modifies all traffic to the CVM | **no** |
| **Subpoena / legal compulsion of operator** | operator compelled to hand over what it *has* | **no** (operator has only ciphertext) |
| **Future quantum adversary** | records ciphertext now, decrypts later | **no** (hybrid PQC) |
| AMD CPU + firmware/microcode | correct SEV-SNP isolation + attestation | **yes** (root of hardware trust) |
| Guest kernel + `configfs-tsm` + OVMF | correct report generation, measured at launch | **yes** (measured TCB) |
| SecGit in-CVM code | correct handling of plaintext | **yes** (measured TCB; minimized + reviewed) |

The trust boundary is the SEV-SNP CVM. Everything inside is measured and attested;
everything outside is assumed hostile.

---

## 3. Threats, mitigations, residual risk

### T1 — Operator reads repository contents at rest
- **Mitigation:** `EncryptedStore` encrypts every object under a per-repo DEK wrapped by
  the KEK; the KEK exists only in CVM memory after attestation-gated release. `repo_id` is
  hashed (`sha256`) for on-disk paths.
- **Leak-test:** `secgit-store::data_on_disk_is_ciphertext` (now via `secgit-leaktest`).
- **Residual:** none at rest beyond ciphertext volume; see T4 for metadata, T9 for RAM.

### T2 — Operator reads contents/metadata in transit
- **Mitigation:** PQC-TLS (`rustls` + `aws-lc-rs`, `prefer-post-quantum`,
  `X25519MLKEM768`) terminates **inside** the CVM (ADR 0007 corrected). No plaintext hop
  exists between an external proxy and the CVM because there is no such proxy in the trust
  path.
- **Leak-test:** `secgit-server::tls::handshake_uses_pq_kx_and_wire_is_ciphertext` and
  `secgit-server::tls::loopback_observer_sees_only_ciphertext` (a real loopback socket with
  an on-path observer; the ADR-0007 "no operator plaintext hop" regression guard).
- **Residual:** the dev-only `SECGIT_INSECURE_HTTP` escape hatch serves plaintext; it logs
  a loud warning and must be absent in production (checked by the acceptance runbook).

### T3 — Operator harvests ciphertext now to decrypt with a quantum computer later
- **Mitigation:** hybrid KEM (X25519 + ML-KEM-768) for key release and hybrid signatures
  (Ed25519 + ML-DSA) throughout; PQ key exchange on the wire. Classical break alone does
  not yield plaintext.
- **Residual:** trust in ML-KEM/ML-DSA as standardized; mitigated by the *hybrid*
  construction (classical security retained even if PQC is later weakened) and
  crypto-agility headers `(kind, scheme, version)` for rotation.

### T4 — Operator infers metadata from the audit log
- **Mitigation:** `TransparencyLog::open_encrypted` AEAD-seals each record at rest under an
  instance key derived from the KEK; public verifiability is preserved because relying
  parties verify the PQC-signed checkpoint (commits only to the Merkle root) plus inclusion
  proofs (sibling hashes only) — neither reveals event contents. See
  `docs/metadata-boundary.md`.
- **Leak-test:** `secgit-audit::{encrypted_log_hides_metadata_but_stays_verifiable,
  metadata_boundary_via_leaktest_harness}` (the latter drives the shared `secgit-leaktest`
  harness with canaries planted in repo_id/owner/ref metadata).
- **Residual (unavoidably observable):** aggregate request timing, total ciphertext
  volume, and connection counts. Documented, not hidden.

### T5 — Attestation spoofing (operator pretends a non-TEE is a TEE)
- **Mitigation:** the SNP report signature is verified to the **VCEK**, which chains
  `VCEK → ASK → ARK` with the ARK **pinned** in the binary (`secgit-attest::vcek`); ASK and
  VCEK are fetched from AMD KDS with an offline cache. A forged report cannot produce a
  valid VCEK signature without AMD's keys. **Revocation:** the VCEK serial is checked
  against the AMD KDS CRL (whose ASK RSASSA-PSS signature is itself verified); revocation
  **fails closed** — an unobtainable/expired CRL refuses release — with a bounded,
  configurable offline-cache window (`secgit-attest::vcek::check_revocation`).
- **Leak-test / check:** `secgit-attest::vcek::{wrong_ark_rejects_ask, revoked_serial_is_detected,
  cached_crl_window_is_bounded}` (CI/mock); live ASK-signed-CRL fetch is gated-on-silicon.
- **Residual:** compromise of AMD's signing infrastructure (out of scope; the entire
  ecosystem shares this root). TCB-rollback is bounded by the TCB floor in policy.

### T6 — MITM relays a genuine report from a *different* real TEE
- **Mitigation:** channel binding — for KEK release `report_data =
  SHA-512(nonce ‖ timestamp ‖ ephemeral KEM public key)` (the timestamp also drives the
  replay guard, T7); for the `/attestation` endpoint the binding is the live TLS cert SPKI.
  A relayed report won't match the verifier's actual channel.
- **Leak-test / check:** `secgit-keybroker::tampered_runtime_pubkey_breaks_binding` (CI/mock),
  `secgit-verify acceptance-snp --expect-refuse tampered-report` (CI/mock), and acceptance
  runbook §4a / harness step (a) on silicon.
- **Residual:** none beyond the binding being correctly checked by the relying party (the
  `secgit-verify` tool does this).

### T7 — Key-release bypass (get the KEK without a valid attestation)
- **Mitigation:** `LocalKeyBroker`/`HttpKbsClient` release the KEK only after
  `Verifier::verify` passes against `Policy { require_vendor_root, allowed_measurements,
  expected_vmpl }`, and the KEK is KEM-sealed to the attested ephemeral key (only the
  genuine TEE can open it). The policy also **pins the VMPL** (VMPL0) so a less-privileged
  context cannot supply attestation for the release, and a **durable, TTL-bounded replay
  guard** refuses replayed nonces and stale (out-of-window) evidence. On non-SNP hosts the
  server uses `MockVerifier` and logs a loud DEV/CI-only warning; production requires
  `configfs-tsm` (acceptance §3).
- **Leak-test / check:** `secgit-attest::snp::{wrong_vmpl_is_refused,
  nonzero_vmpl_report_refused_when_vmpl0_required}`,
  `secgit-keybroker::{replayed_release_is_refused, stale_release_is_refused}`, and
  `secgit-verify acceptance-snp --expect-refuse {wrong-measurement,replay,stale,unknown-resource}`
  (all CI/mock).
- **Replay caveat (design item B):** the guest still chooses the nonce/timestamp, so this is
  replay-*detection* + bounded staleness, NOT verifier-guaranteed freshness; a broker-issued
  challenge is tracked in `docs/adr/0010-open-subdecisions.md` to revisit with the auditor.
- **Residual:** if an operator runs a *modified* build, its launch measurement won't match
  the published reference (T8), so a strict-policy KBS refuses release.

### T8 — Operator boots a backdoored image
- **Mitigation:** the SNP launch measurement (SHA-384 over OVMF+kernel+initrd+cmdline) is
  pinned via `SECGIT_SNP_REFERENCE` to a value independently reproducible with
  `xtask snp-measure` and published to the transparency log. A different image → different
  measurement → policy rejects it.
- **Residual:** depends on reproducible builds being real (source ↔ artifact); that is the
  reproducible-build gate, tracked separately (M5/M7).

### T9 — Memory-/side-channel extraction of plaintext or keys
- **Mitigation:** SEV-SNP encrypts and integrity-protects guest memory against the host;
  `zeroize` clears key material; the KEK is never written to disk.
- **Residual (does NOT fully resist):** microarchitectural side channels, CIPHERTEXT-side
  channels against SEV-SNP, and physical attacks beyond the SEV-SNP threat model are out of
  scope and not claimed. This is the honest limit of the hardware root.

### T10 — Subpoena / legal compulsion
- **Mitigation:** the operator possesses only ciphertext and cannot derive the KEK (it is
  released only to attested TEE memory and KEM-sealed). Compelling the operator yields
  nothing readable.
- **Residual:** compelling the *customer* (who can authenticate into a TEE session) is
  outside SecGit's control; key-recovery/escrow choices (ADR 0010-1) are tier-accurate and
  default to zero-knowledge for anon/personal.

### T11 — "No AI training" violation (plaintext exfiltrated for model training)
- **Mitigation:** enforced *consequence*, not a promise — plaintext exists only in TEE
  memory, there is no plaintext egress path, and `deny.toml` bans ML/AI/telemetry crates,
  verified by `xtask egress-check`. See `docs/no-ai-training.md`.
- **Residual:** the ban is a denylist, not a proof that no networking exists; combined with
  the at-rest/on-wire leak-tests and the minimal reviewed trust path it is what makes the
  claim credible.

### T12 — Tampering with / forking the audit log
- **Mitigation:** hash-chained, Merkle-committed records with PQC-signed checkpoints;
  `secgit-verify verify-checkpoint` lets any party confirm the signed root. Consistency
  proofs detect a forked history.
- **Residual:** an operator can withhold/stop the log, but cannot rewrite it undetectably;
  monitoring checkpoint continuity catches a stall.

---

## 4. Residual costs and explicit non-goals

- **Incremental seal cost:** confidentiality is at the object/pack layer; pushes append
  O(delta) bundle segments rather than re-bundling the whole repo, with a periodic full
  compaction folding segments into a base — an accepted, bounded amortized cost of the design.
- **`configfs-tsm` trust:** the guest kernel's TSM interface is inside the measured TCB; a
  bug there is a TCB bug, caught (if it changes the image) by the measurement gate.
- **Confidential CI is v2:** running untrusted build steps against plaintext materially
  expands the enclave trust surface and is deliberately deferred; v1 ships only the
  external/self-hosted-runner escape hatch.

---

## 5. What is verifiable by a third party (no trust in SecGit/operator)

1. SNP report verifies to AMD KDS roots (T5) — `secgit-verify` + KDS.
2. Launch measurement equals the published OSS build (T8) — `xtask snp-measure`.
3. Channel is the attested TEE (T6) — `report_data` binding.
4. Host disk is ciphertext-only (T1/T4) — `grep` for a canary.
5. Audit checkpoint signature valid (T12) — `verify-checkpoint`.

The full procedure is `docs/acceptance-snp.md`.

---

## 6. Trust-surface discipline

The trust-critical path (attestation → key release → store unlock → plaintext handling)
stays minimal and reviewed. Feature breadth in the forge (web UX, PR review, search, APIs)
must render *through* the confidential layer and never weaken the confidentiality claim —
enforced by §7.

---

## 7. The leak-test rule (CI gate)

Every feature that ever holds plaintext ships a test using `secgit-leaktest`:

1. create a unique `Canary`,
2. drive the feature with the canary as content/metadata,
3. assert the canary is absent from every operator-visible surface:
   - at rest: `assert_dir_ciphertext_nonempty(data_dir, &[canary, ...])`,
   - on the wire: `assert_bytes_absent(wire_buffer, canary, "tls wire")`.

A green run is not a proof of confidentiality, but a leak is a definitive disproof. Current
adopters: `secgit-store`, `secgit-audit`, `secgit-server` (TLS), **per-tier repo storage**
(`bins/secgit-server/tests/tier_leaktest.rs` — anonymous/Light/Managed), the **encrypted
abuse queue** (`abuse::reports_persist_and_are_ciphertext_at_rest`), and the **content-free
metrics** surface (`metrics::metrics_are_content_free`). New plaintext-touching or
operator-visible features MUST add a leak-test before merge.

---

## 8. Verification mapping (T1–T14)

Every threat maps to a concrete, runnable proof. **Gate** says where it runs: `CI(mock)`
runs in `cargo test` with no hardware; `gated-on-silicon` requires a real SEV-SNP CVM and is
proven by the one-command harness `secgit-verify acceptance-snp` (which emits a PQC-signed
transcript — the launch transparency proof). No claim is `SILICON-VERIFIED` until that signed
transcript exists on real silicon (see `docs/STATUS.md`).

| Threat | Proof | Gate |
|---|---|---|
| **T1** contents at rest | `secgit-store::data_on_disk_is_ciphertext`; harness step (f) | CI(mock) + gated-on-silicon |
| **T2** in transit | `tls::handshake_uses_pq_kx_and_wire_is_ciphertext`, `tls::loopback_observer_sees_only_ciphertext` | CI(mock) |
| **T3** harvest-now-decrypt-later | hybrid KEM/sig unit tests in `secgit-crypto`; `tls::pq_kx_is_preferred` | CI(mock) |
| **T4** audit metadata | `secgit-audit::{encrypted_log_hides_metadata_but_stays_verifiable, metadata_boundary_via_leaktest_harness}` | CI(mock) |
| **T5** attestation spoofing | `vcek::{wrong_ark_rejects_ask, revoked_serial_is_detected, cached_crl_window_is_bounded}`; harness step (b) | CI(mock) + gated-on-silicon |
| **T6** relayed report (MITM) | `keybroker::tampered_runtime_pubkey_breaks_binding`; `acceptance-snp --expect-refuse tampered-report`; harness step (a) | CI(mock) + gated-on-silicon |
| **T7** key-release bypass | `snp::{wrong_vmpl_is_refused, nonzero_vmpl_report_refused_when_vmpl0_required}`, `keybroker::{replayed_release_is_refused, stale_release_is_refused}`, `acceptance-snp --expect-refuse {wrong-measurement,replay,stale,unknown-resource}`; harness step (d) | CI(mock) + gated-on-silicon |
| **T8** backdoored image | `xtask snp-measure` predicted measurement; harness step (c) predicted-vs-live diff | CI(mock) for the tool; gated-on-silicon for the live match |
| **T9** memory/side-channel | hardware property of SEV-SNP; **not** software-testable — verified only by the on-silicon acceptance (step 2) and explicitly bounded as a non-goal above | gated-on-silicon (documented limit) |
| **T10** subpoena | follows from T1/T4/T7 (operator holds only ciphertext, cannot derive the KEK) — no separate test; verified by the on-silicon acceptance | gated-on-silicon (documented) |
| **T11** no-AI-training | `xtask` `no_ml_or_telemetry_deps_in_graph`, `egress_check_detects_a_planted_dependency`; `cargo deny check` ban-list; T1/T2 leak-tests | CI(mock) |
| **T12** audit tamper/fork | `merkle::{inclusion_named_non_pow2_sizes, inclusion_wrong_tree_size_is_rejected, consistency_named_non_pow2_sizes, tampered_inclusion_fails, consistency_rejects_forked_history}`, `audit::corrupted_file_is_rejected_on_load`; `secgit-verify verify-checkpoint` | CI(mock) |
| **T13** public-sandbox abuse/DoS | `http::tests::*` (conn/body/header/chunked caps), `ratelimit::tests::*` (token-bucket + concurrency semaphore), `secgit-git` `GitLimits` + subprocess watchdog, bounded seal concurrency; encrypted abuse queue + audit-logged takedown (`abuse::*`) | CI(mock) |
| **T14** per-tier confidentiality + content-free observability | `bins/secgit-server/tests/tier_leaktest.rs` (anonymous/Light/Managed ciphertext at rest), `tls::loopback_observer_sees_only_ciphertext` (on-wire), `metrics::metrics_are_content_free` (metrics leak nothing; no telemetry egress) | CI(mock) |
