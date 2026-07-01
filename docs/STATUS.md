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

## As-built vs intent for M5 (reproducible builds + measurement binding)

M5's promise is *"the running image == the audited OSS build, and a third party can prove it."*
This is an honest map of that promise as of this iteration.

**Real (present and CI-exercised):**
- `xtask sbom` emits a CycloneDX 1.5 SBOM from `Cargo.lock`; `xtask measure` emits an
  `image-manifest.json` of SHA-384 binary digests; both are served at `/sbom` and
  `/image-manifest` and can be appended to the PQC-signed transparency log.
- `xtask snp-measure` wraps `sev-snp-measure` and writes a `snp-reference.json` whose
  `measurement_hex` pins `Policy.allowed_measurements` (`SECGIT_SNP_REFERENCE`).
- The reproducible-build **chain is now CI-gated**: `deploy/repro-build.sh` builds the OCI
  image twice and fails on any digest/rootfs drift (see claim 12).
- The launch reference is now **commit-bound**: `xtask snp-measure` records the source
  `git commit` and cross-checks the launch-input artifact digests against
  `image-manifest.json` before emitting the signed reference (see claim 5).

**Mock-only / not yet load-bearing:**
- No signed SEV-SNP transcript exists, so the *live* measurement match is UNVERIFIED on
  silicon. `snp-measure` predicts a measurement; nothing has yet confirmed a genuine CVM
  boots to it.
- The guest-image assembly (`deploy/guest/` mkosi -> UKI) is **scaffolded and pinned but
  not built/booted here** — actual bootable-guest assembly is M7. Until M7 runs, the
  predicted measurement is computed against declared/pinned firmware refs, not an image a
  CVM has actually launched.

**Missing (deferred, tracked):**
- On-silicon production of a real launch measurement and its diff against the prediction
  (M7 + silicon acceptance).
- OVMF built from `OvmfPkg/AmdSev/AmdSevX64.dsc` with the `SNP_KERNEL_HASHES` metadata
  section and `kernel-hashes=on` at launch — required for measured direct boot of the UKI;
  declared in the launch descriptor, produced in M7.

---

## As-built vs intent for M6 (public-sandbox hardening)

M6's promise is *"the public instance survives a hostile internet across all three tiers,
with zero new plaintext/metadata egress and the confidentiality invariant proven per tier."*
This is an honest map of that promise as of this iteration. Everything below is
**MOCK-VERIFIED** (CI, no silicon) — it is attack-surface / abuse-control work whose proofs
are unit/integration tests and leak-tests, not hardware.

**Real (present and CI-exercised):**
- **Transport DoS hardening** (`bins/secgit-server/src/http.rs`, `main.rs`): bounded
  connection semaphore, socket read/write timeouts (slowloris defense on handshake +
  header/body reads), header byte + count caps (`431`), body-size cap enforced on
  `Content-Length` before allocation (`413`), and explicit rejection of chunked
  transfer-encoding. Unit tests in `http.rs` cover each limit.
- **Rate limiting** (`ratelimit.rs`): dependency-free, memory-bounded token buckets keyed on
  the **TCP peer IP** (XFF is treated as untrusted per ADR 0007) — per-IP request, per-IP
  git-op, per-account, and per-repo push buckets. The anonymous ephemeral limiter now keys on
  peer IP, not spoofable `x-forwarded-for`.
- **Git subprocess bounds** (`secgit-git`, `secgit-forge`): wall-clock watchdog that kills a
  hung `git` child; fetch output cap; push input cap via `receive.maxInputSize` +
  `transfer.fsckObjects` (decompression-bomb / malformed-object defense). Every forge `git`
  invocation (including the `git bundle` seal) runs under a wall-clock cap.
- **`seal_to_store` amplification bound**: per-repo push rate limit + a global bounded seal
  concurrency semaphore + the bundle wall-clock cap. (Incremental/O(delta) sealing is a
  deliberately-deferred v2, see ADR 0007.)
- **Ephemeral GC + reconciliation** (`main.rs`, `secgit-api::EphemeralRepos::gc`,
  `EncryptedStore::delete_repo`, `Forge::delete`): a background sweep wipes expired ephemeral
  working sets + encrypted storage; startup reconciles orphaned `ephemeral/*` state left by a
  crash/restart.
- **Anonymous hardening**: aggressive per-IP defaults + an optional CLI-friendly hashcash
  **PoW** gate (`pow.rs`, default OFF, configurable difficulty) with a challenge endpoint.
- **Abuse / takedown** (`abuse.rs`): public `POST /abuse/report` into an **encrypted** queue
  (operator stays content-blind), operator force-delete-by-id (`POST /admin/repos/delete`,
  token-gated), and audit-logged takedowns.
- **Content-free observability** (`metrics.rs`): a fixed-label atomic registry rendered as
  Prometheus text, token-gated and served on a **separately bindable** (localhost-default)
  listener; a leak-test proves the output carries no repo id / content.
- **Sandbox UX + config** (`config.rs`): all limits + tier knobs are env-overridable; the
  landing page carries a "public sandbox — no production secrets" warning, a managed-tier
  waitlist (email → encrypted queue), and an abuse-report pointer.
- **Process-group kill of git subprocesses** (`secgit-git`/`secgit-forge`): every `git` child
  is spawned as its own process-group leader and the wall-clock/output-cap watchdog kills the
  **whole group**, so grandchildren (`pack-objects`) cannot linger. Covered by Linux
  grandchild-kill unit tests.
- **Incremental / O(delta) append-only sealing** (`secgit-store` + `secgit-forge`): pushes
  append encrypted delta bundle segments tracked in a `seal.manifest` (multi-segment restore,
  bounded compaction, legacy `repo.bundle` migration) instead of re-bundling the whole repo;
  per-push seal cost scales with the push, not the repo. Covered by delta/restore/compaction/
  migration unit tests; ciphertext-at-rest re-checked by the tier leak-tests.

**Mock-only / not yet load-bearing:**
- Rate-limit identity is the direct TCP peer IP; PROXY-protocol / a trusted L4 front is noted
  as future config (ADR 0007), so behind a NAT all clients share a bucket.

**Missing (deferred, tracked):**
- A distributed / shared-state rate limiter for multi-instance sandboxes (single-instance
  today).

---

## As-built vs intent for M7 (packaging → attestable CVM guest)

M7's promise is *"a deployable, attestable artifact: the SecGit service running inside a
SEV-SNP guest, packaged, signed, and hardened — where the measurement a third party predicts
from source (M5) equals the measurement the CVM actually boots to."* This is an honest map of
that promise. The distinction that matters here: an OCI container is **not** an attestable
CVM. The build-host reality is also honest — this repo is developed on macOS/arm64 and CI runs
on cloud x86 **without SEV-SNP silicon**, so M7 delivers *tooling + config + scripts* whose
logic is MOCK-VERIFIED (unit tests, script lint, mock/dev bring-up) and whose guest artifacts
are **built on a Linux/AMD host and only SILICON-VERIFIED once the acceptance transcript
exists** (`docs/acceptance-snp.md`).

**Real (present and CI-exercised / mock-verified):**
- **Reproducible OCI image** (`deploy/Dockerfile`) with SBOM + image-manifest baked in and a
  `secgit-verify selftest` HEALTHCHECK; the build-twice bit-identical gate
  (`deploy/repro-build.sh`) runs in CI (claim 12).
- **Guest-image assembly tooling** now exists end-to-end (built on Linux, not here):
  `deploy/guest/build-ovmf.sh` (reproducible `OvmfPkg/AmdSev/AmdSevX64.dsc` + `SNP_KERNEL_HASHES`,
  pinned edk2 commit), `deploy/guest/build-guest.sh` (exports the reproducible OCI rootfs, drives
  mkosi to a reproducible UKI, recomputes SHA-384s, and fills `snp-inputs.json` +
  `ovmf.pin.json`), and `deploy/guest/launch-snp.sh` (QEMU `sev-snp-guest,kernel-hashes=on`,
  measured direct boot of OVMF + UKI + the byte-exact cmdline).
- **Predicted == deployed binding:** `deploy/guest/build-guest.sh` runs `xtask snp-measure
  --inputs snp-inputs.json --image-manifest image-manifest.json`, which fail-closes on any
  launch-artifact digest drift and emits a commit-bound `snp-reference.json` (claim 5).
- **PQC-native provenance signing:** `xtask provenance` emits an in-toto/SLSA-style predicate
  over the OCI image digest + OVMF/UKI/SBOM digests + measurement + git commit, signs it with
  the long-lived hybrid PQC key (Ed25519+ML-DSA-87), and appends it to the transparency log;
  `secgit-verify verify-provenance` re-checks the signature and cross-checks every digest.
  No sigstore/Fulcio/Rekor — provider-neutral, self-hosted (ADR 0004/0008).
- **Runtime hardening beyond Compose:** a default-deny **seccomp profile**
  (`deploy/seccomp-secgit.json`) wired into `deploy/docker-compose.yml` alongside the existing
  `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, non-root uid, plus
  memory/CPU limits and a restart policy. The **no-plaintext-egress** invariant is enforced
  in-guest by an nftables allowlist (`deploy/guest/nftables.conf`) baked into the measured UKI —
  default-drop egress, allow only AMD KDS (+ optional self-hosted KBS) and the service ingress.
- **configfs-tsm-capable kernel:** the guest installs `linux-image-cloud-amd64` from
  bookworm-backports (>= 6.7, with `CONFIG_TSM`/`CONFIG_SEV_GUEST`) via a reproducible apt pin
  from the same pinned snapshot (`deploy/guest/mkosi.pkgmngr/`), so `/sys/kernel/config/tsm/report`
  is present for boot-time attestation. `[VERIFY]` on the target silicon.
- **SecureBoot-signed UKI + dm-verity root:** `deploy/guest/mkosi.conf` `[Validation]` sets
  `SecureBoot=yes` + `Verity=hash`, producing a dm-verity-protected root disk and a signed UKI
  whose `.roothash` section is folded into the launch measurement — a tamper on the root disk
  fails verification and any change to the root is caught by the measurement. The cmdline names
  no `root=` device (systemd auto-discovers the root + verity partitions); `build-guest.sh` takes
  the signing key via `SECGIT_SB_KEY`/`SECGIT_SB_CERT` (never committed) and `launch-snp.sh`
  attaches the verity root disk as `/dev/vda`. `[VERIFY]` the roothash-in-UKI vs cmdline behavior
  on your mkosi version.
- **No-secrets-in-image + boot-time KEK release:** `deploy/verify-no-secrets.sh` scans the
  built image layers/env for key material (CI-wired); the guest boots a systemd unit that runs
  `secgit-server` with `SECGIT_SNP_REFERENCE` (+ optional `SECGIT_KBS_URL`) and **no KEK**, so
  the KEK is released via attestation at boot, never baked into the image.
- **Upgrade + backup + one-command bring-up:** `docs/operations.md` documents the upgrade
  (new image → new measurement → re-attestation; encrypted `/data` + wrapped DEKs persist) and
  backup (ciphertext-only store is safe to copy anywhere; KEK recovery per ADR 0010 #1) stories;
  `deploy/up.sh --mock` brings up the dev/Compose path in one command and `deploy/up.sh --snp`
  builds + launches the CVM in one command.

**Mock-only / not yet load-bearing:**
- The guest build scripts are **lint- and dry-run-checked in CI** and exercised on a Linux
  builder, but no genuine SEV-SNP CVM has booted the artifact here, so the **live** measurement
  match remains UNVERIFIED on silicon (promotes with the acceptance transcript, claim 5).
- The nftables egress allowlist is baked into the UKI and unit-reasoned, but its enforcement is
  only proven on a booted guest; on the dev/Compose path the host firewall is explicitly **not**
  a trust boundary (the host is untrusted), so it is defense-in-depth documentation there.
- Provenance signing supports a **persistent release key**: `xtask provenance-keygen` produces
  an offline signing bundle + a published verifying key (committed at `deploy/provenance.vk.json`,
  which `secgit-verify verify-provenance` now defaults to), and a tag-gated `release-provenance`
  CI job signs with the offline key and re-verifies against the published one (PR CI keeps the
  ephemeral roundtrip). The remaining operator step — custody of the private bundle in an HSM /
  air-gapped vault — is a documented procedure (`docs/operations.md` §3b), not code.

**Missing (deferred, tracked):**
- **Signed** dm-verity (`Verity=signed`) with the roothash signature validated by a key in the
  measured initrd is a further hardening on top of today's `Verity=hash` (whose roothash is
  already measured via the signed UKI); deferred.
- On-silicon production of the real launch measurement and its diff against the prediction
  (the single remaining gate, below).

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
| 5 | Launch **measurement == reproducible build** | **MOCK-VERIFIED** (tool + commit-bound reference + guest-assembly tooling); UNVERIFIED on silicon (live match) | `deploy/guest/build-ovmf.sh` (reproducible OVMF + `SNP_KERNEL_HASHES`) + `deploy/guest/build-guest.sh` (reproducible UKI, fills `snp-inputs.json`) → `xtask snp-measure --inputs <descriptor> --image-manifest` recomputes launch-input digests (fail-closed), binds `git_commit`, pins the actual OVMF+UKI; `deploy/guest/launch-snp.sh` boots it `kernel-hashes=on`; harness step (c) predicted-vs-live diff |
| 6 | Channel binding (report ⇔ live TLS peer) defeats MITM relay | **MOCK-VERIFIED**; UNVERIFIED on silicon | `keybroker::tampered_runtime_pubkey_breaks_binding`; harness step (a) live |
| 7 | Attestation-gated **KEK release** (vendor root + measurement + **VMPL0** + replay/freshness) | **MOCK-VERIFIED**; UNVERIFIED on silicon | `snp::wrong_vmpl_is_refused`, `keybroker::{replayed,stale}_release_is_refused`, `acceptance-snp --expect-refuse …`; harness step (d) live |
| 8 | BYOK / self-hosted KBS (`KeyRelease`) | **MOCK-VERIFIED** (`LocalKeyBroker`); KBS HTTP client UNVERIFIED against a live Trustee | `keybroker` tests; `bins/secgit-server/src/kbs.rs` |
| 9 | Independent **tamper-evident audit log** (+ metadata boundary) | **MOCK-VERIFIED** | `audit::{metadata_boundary_via_leaktest_harness, …}`, `merkle::*`, `secgit-verify verify-checkpoint` |
| 10 | **"No AI training"** as a technical consequence | **MOCK-VERIFIED** | `xtask` `no_ml_or_telemetry_deps_in_graph`, `egress_check…`; `cargo deny check`; T1/T2 leak-tests |
| 11 | Hybrid **PQC** (storage, key release, signatures, transport) | **MOCK-VERIFIED** | `secgit-crypto` tests; `tls::pq_kx_is_preferred` |
| 12 | Reproducible build == running image (transparency artifacts) | **MOCK-VERIFIED** (artifacts) + **reproducibility CI-gated** (build-twice bit-identical); UNVERIFIED that artifact == silicon image | `deploy/repro-build.sh` + CI `reproducibility` job (two builds -> identical digest); `xtask` manifest/SBOM tests; `/sbom`, `/image-manifest`; claim 5 closes the loop on silicon |
| 13 | Public sandbox survives hostile **abuse/DoS** (conn/timeout/size caps, per-IP/-account/-repo rate limits, git-pack + seal bounds) | **MOCK-VERIFIED** | `http::tests::*` (body/header/chunked caps), `ratelimit::tests::*` (token bucket + semaphore), `secgit-git` `GitLimits` + watchdog, bounded seal concurrency |
| 14 | Per-tier confidentiality (**anonymous / Light / Managed** ciphertext at rest) | **MOCK-VERIFIED**; UNVERIFIED on a real host disk | `bins/secgit-server/tests/tier_leaktest.rs` (canary at-rest per tier); on-wire via `tls::loopback_observer_sees_only_ciphertext` |
| 15 | **Content-free observability** (metrics leak no repo content/metadata, no egress) | **MOCK-VERIFIED** | `metrics::tests::metrics_are_content_free`; pull-only, token-gated, localhost-default listener; telemetry crates banned (`deny.toml`) |
| 16 | Abuse **takedown** by id (encrypted report queue, operator content-blind, audit-logged) | **MOCK-VERIFIED** | `abuse::tests::reports_persist_and_are_ciphertext_at_rest`; `POST /abuse/report` → encrypted queue; token-gated `POST /admin/repos/delete` → `AuditEvent::Admin` |
| 17 | Published-artifact **provenance** (PQC-signed in-toto/SLSA over OCI image + OVMF + UKI + SBOM + measurement, anchored in our transparency log) | **MOCK-VERIFIED** | `xtask::tests::provenance_statement_signs_and_verifies_over_canonical_bytes`; `xtask provenance` → `secgit-verify verify-provenance` roundtrip in CI; no sigstore/Fulcio/Rekor |
| 18 | **No secrets in the image**; KEK attestation-released at boot | **MOCK-VERIFIED** | `deploy/verify-no-secrets.sh` (image layer + env scan, CI-gated); `deploy/guest/secgit.service` boots with no KEK; harness step (d) proves the live release |
| 19 | **No-plaintext-egress** enforced in the measured guest | **MOCK-VERIFIED**; UNVERIFIED on silicon | `deploy/guest/nftables.conf` (default-drop egress, allow only 443/DNS + ingress) baked into the UKI via `mkosi.finalize`; `xtask::tests::guest_egress_allowlist_is_default_drop`; layered over `deny.toml`/`egress-check` (claim 10) |

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
| `secgit-forge` / `secgit-git` | bare-repo create/seal/restore; smart-HTTP; **git subprocess wall-clock/output/input bounds + `fsckObjects`**; `delete`/`delete_repo` for GC/takedown | — |
| `secgit-api` | ephemeral + Light/Managed tiers, quotas | — |
| `secgit-leaktest` | shared canary/at-rest/on-wire leak harness | — |
| `secgit-verify` | `selftest`, `verify-checkpoint`, **`probe-snp`**, **`acceptance-snp` (+`--mock`, `--expect-refuse`)**, **`verify-transcript`**, **`verify-provenance`** | the live `acceptance-snp` run (produces the transcript) |
| `bins/secgit-server` | in-CVM PQC-TLS, attestation-gated boot, forge/API/web/SSH; **M6 public-sandbox hardening** (transport caps, token-bucket rate limits, PoW gate, ephemeral GC, encrypted abuse queue + takedown, content-free metrics) | on-silicon boot (claims 1–7) |
| `xtask` | image-transparency manifest, SBOM, commit-bound `snp-measure` (`--inputs`/`--image-manifest`, fail-closed digest bind), **PQC-native `provenance`**; `deploy/repro-build.sh` build-twice gate; **`deploy/guest/` OVMF+UKI build + QEMU launch scripts**, `deploy/verify-no-secrets.sh`, `deploy/up.sh` | live measurement match (claim 5); on-silicon guest boot |

---

## Gate status (CI, no hardware)

`cargo test --workspace --locked` green · `secgit-verify selftest` green ·
`secgit-verify acceptance-snp --mock` green · `cargo fmt --check` green ·
`cargo clippy --all-targets -D warnings` green · `cargo deny check bans licenses sources` green ·
`deploy/repro-build.sh` (CI `reproducibility` job) builds the image twice to an identical digest ·
CI `packaging` job: seccomp profile parses, `xtask provenance` → `verify-provenance` roundtrip,
the published `deploy/provenance.vk.json` is well-formed, `snp-measure --inputs` on a fixture,
`verify-no-secrets.sh` rootfs scan, and `bash -n` lint of the `deploy/guest/*.sh` assembly/launch
scripts · CI `release-provenance` job (tag builds): signs with the offline release key and
re-verifies against the published verifying key.

`[VERIFY]` `cargo deny check advisories` may abort if the local advisory-db contains a
CVSS v4.0 RUSTSEC entry that the installed cargo-deny cannot parse (a tooling-version issue,
not an advisory hit). Re-check when cargo-deny gains CVSS 4.0 support.

## The single remaining gate to "SILICON-VERIFIED"

The M7 guest-assembly tooling now makes the operator side one command; the verifier side is
unchanged. On a genuine AMD SEV-SNP host:

```bash
# Operator: build the measured guest and boot it (predicts snp-reference.json en route).
EDK2_COMMIT=<reviewed edk2 sha> deploy/up.sh --snp

# Verifier: prove the running instance and emit the signed transcript.
secgit-verify probe-snp          # raw guest report available (not a cloud vTPM)
secgit-verify acceptance-snp --url https://<host>:8443 --data-dir /var/lib/secgit \
  --product Milan --reference snp-reference.json --out acceptance-transcript.json
secgit-verify verify-transcript acceptance-transcript.json acceptance-transcript.json.vk.json
```

Publishing that signed transcript is what promotes claims 1, 3–7, 12 to **SILICON-VERIFIED**.
Until then this document states, plainly, that they are not.
