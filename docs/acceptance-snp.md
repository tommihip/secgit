# On-Silicon Acceptance Test — SEV-SNP (external party)

This is the runbook a **skeptical external party** follows to confirm SecGit's central
claim on real AMD SEV-SNP hardware:

> The operator cannot read your code. The TEE that holds the plaintext is genuine AMD
> silicon running the exact published open-source build, and you can verify all of this
> yourself — the trust does not rest on the operator's word.

It is written so the verifier trusts **only** AMD's CPU-vendor roots and the published
OSS build artifacts — never SecGit the company or the host operator.

The cryptographic machinery, the SNP report parser/verifier, the AMD KDS `ARK→ASK→VCEK`
chain validation, the in-CVM PQC-TLS terminator, and the encrypted-at-rest store are all
implemented and unit-tested in this repo today (`cargo test --workspace`). What this
document gates is the **actual run on provisioned silicon**; nothing here mocks the TEE.

---

## Quickstart: the one-command harness

The whole runbook below is automated by `secgit-verify`. Sections §2–§5 explain what each
step proves; in practice you run three commands:

```bash
# 0. Validate the orchestration locally first (no hardware, runs in CI too):
secgit-verify acceptance-snp --mock

# 1. On the candidate host, confirm a RAW SEV-SNP guest report is available
#    (a cloud vTPM-only path FAILS — it violates provider-neutrality):
secgit-verify probe-snp

# 2. Run the full end-to-end acceptance against the live instance and emit a
#    PQC-signed transcript (the launch transparency proof):
secgit-verify acceptance-snp \
  --url https://<host>:<port> \
  --data-dir /var/lib/secgit \
  --product Milan \
  --reference snp-reference.json \
  --out acceptance-transcript.json

# 3. Anyone can re-check the signed transcript later:
secgit-verify verify-transcript acceptance-transcript.json acceptance-transcript.json.vk.json
```

The harness executes steps (a)–(g): fetch report over PQC-TLS + channel-binding check →
`ARK→ASK→VCEK` + KDS fetch + **CRL revocation** → launch-measurement-vs-predicted diff →
the real attestation-gated KEK-release decision under strict policy (vendor root, pinned
measurement, **VMPL0**) → ephemeral repo + push over PQC-TLS → grep `--data-dir` for a
unique canary (provider-blindness) → emit the PQC-signed transcript. It is **idempotent**
(safe to re-run) and prints `PASS`/`FAIL` with detail at every step.

> Nothing is `SILICON-VERIFIED` (see `docs/STATUS.md`) until a signed transcript from
> step 2 exists, produced on real SEV-SNP silicon.

---

## 0. Roles and trust assumptions

| Party | Trusted for | NOT trusted for |
|---|---|---|
| AMD | CPU-vendor roots (ARK/ASK/VCEK), genuineness of the SNP report signature | anything about SecGit |
| OSS build (reproducible) | the measured firmware+kernel+initrd+cmdline = published source | — |
| Verifier (you) | running the checks below | — |
| **Operator / host** | **nothing** — assumed actively malicious | reading plaintext, swapping the image, MITM |

The acceptance passes only if every check below is satisfied **using artifacts the
verifier fetched independently** (AMD KDS over the public internet, the OSS release page),
not artifacts handed over by the operator.

---

## 1. Prerequisites

On the verifier's own machine (not the server):

- A recent `git` and the `secgit-verify` binary from the **published** release (or built
  from the reproducible build — see `docs/` reproducible-build notes).
- `sev-snp-measure` (`pip install sev-snp-measure`) to independently recompute the
  expected launch measurement.
- Network egress to `https://kdsintf.amd.com` (AMD KDS) for VCEK/chain fetch.

On the host: an AMD EPYC (Milan or Genoa) machine with SEV-SNP enabled and `configfs-tsm`
available to guests (`/sys/kernel/config/tsm/report`).

---

## 2. Independently reproduce the expected launch measurement

Before trusting any running instance, compute what a genuine launch of the published image
*must* measure to. From the published build artifacts (OVMF firmware, kernel, initrd, and
the exact kernel cmdline):

```bash
# One command: the pinned launch descriptor names the EXACT OVMF + UKI, the cmdline, and the
# vCPU topology (see deploy/snp-inputs.example.json). Cross-checking against the image
# manifest binds the prediction to the reproducible build; explicit flags still override.
cargo run -p xtask -- snp-measure \
  --inputs snp-inputs.json \
  --image-manifest image-manifest.json \
  --out snp-reference.json

# Equivalent fully-explicit form (UKI as the measured -kernel payload):
cargo run -p xtask -- snp-measure \
  --ovmf  deploy/guest/out/OVMF.fd \
  --kernel deploy/guest/out/secgit-guest.efi \
  --append "<published kernel cmdline>" \
  --vcpus 4 --vcpu-type EPYC-v4 \
  --out snp-reference.json
```

This wraps `sev-snp-measure` and writes a **commit-bound** `snp-reference.json` containing
`measurement_hex` (the SHA-384 launch digest), the source `git_commit`, and the recomputed
`launch_artifacts` digests. `xtask` refuses to emit the reference if any launch artifact's
digest disagrees with its pin or with `image-manifest.json`. Record `measurement_hex` as
`M_expected`. The same file is consumed by the harness
(`acceptance-snp --reference snp-reference.json`) for the predicted-vs-live diff in §4c.

The same reference is published to the transparency log so a third party can confirm it
matches the OSS release:

```bash
cargo run -p xtask -- snp-measure ... --log transparency.log
cargo run -p secgit-verify -- verify-checkpoint checkpoint.json verifying_key.json
```

> If you cannot rebuild the artifacts bit-for-bit, the chain of trust to "the published
> source" is broken — stop here. That is the reproducible-build gate, not an SNP gate.

---

## 3. Boot SecGit on the silicon (operator-side, observed)

The operator launches the CVM with the published image. Relevant server configuration:

| Env var | Meaning for the acceptance run |
|---|---|
| `SECGIT_SNP_PRODUCT` | `Milan` or `Genoa` — selects the pinned AMD ARK root |
| `SECGIT_SNP_REFERENCE` | path to `snp-reference.json` → pins `allowed_measurements` to `M_expected` |
| `SECGIT_KBS_URL` | (optional) self-hosted key broker that holds the KEK |
| `SECGIT_VCEK_CACHE` | offline VCEK + CRL cache dir (air-gap support) |
| `SECGIT_CRL_MAX_AGE_SECS` | bounded offline window for a cached CRL (default 86400); revocation **fails closed** outside it |
| `SECGIT_SNP_EXPECTED_VMPL` | VMPL the report must carry (default `0`) |
| `SECGIT_REPLAY_TTL_SECS` | replay-guard freshness/retention window (default 300) |
| `SECGIT_ADDR` | listen address (PQC-TLS terminates **in-process**, inside the CVM) |

`SECGIT_INSECURE_HTTP` and the mock verifier (`MockVerifier`) MUST be **absent** — the
server logs `using real SEV-SNP verifier` on boot when `configfs-tsm` is present, and
`WARNING ... MOCK verifier` otherwise. If you see the mock warning, the run is invalid.

On boot the server performs the attestation-gated KEK release **before** opening the
encrypted store. `report_data` is `SHA-512(nonce ‖ binding)` (see
`secgit_attest::ReportData::bind`):
1. for **KEK release** the bound material is `timestamp ‖ ephemeral X25519+ML-KEM-768
   public key`, so the broker can KEM-seal the KEK to exactly the key the attested TEE
   holds AND its durable, TTL-bounded replay guard can refuse replayed/stale evidence on a
   time basis (`SECGIT_REPLAY_TTL_SECS`, default 300). This is replay-*detection*, not
   verifier-guaranteed freshness — see design item B in `docs/adr/0010-open-subdecisions.md`;
2. for the **`/attestation` control-plane endpoint** the `binding` is the live TLS cert
   SPKI (`secgit-tls-spki-sha256:<hex>`), giving the verifier channel binding (§4a);
3. the SNP report is obtained via `configfs-tsm`;
4. the broker verifies the report against the AMD `ARK→ASK→VCEK` chain, the **CRL**
   (revocation fails closed; `SECGIT_CRL_MAX_AGE_SECS` bounds the offline window), the
   pinned measurement, and the expected **VMPL** (VMPL0 by default;
   `SECGIT_SNP_EXPECTED_VMPL`), then releases the KEK KEM-sealed to the ephemeral key.

---

## 4. Verifier checks (the actual acceptance)

### 4a. The channel is genuinely the attested TEE (defeats MITM relay)

Fetch the attestation evidence over the **PQC-TLS** connection you will also push over:

```bash
curl --tlsv1.3 https://<host>:<port>/attestation > evidence.json
```

Confirm `report_data` commits to the SHA-256 of the SPKI of the very TLS certificate that
terminated *this* connection (`tls_spki_sha256_hex` in the response). This binds the
attestation to the live channel — an operator cannot relay a report from some *other* real
TEE while terminating your TLS itself.

### 4b. The report verifies to AMD roots (not to SecGit)

Validate the SNP report in `evidence.json`:
- the report signature verifies under the **VCEK** (ECDSA-P384),
- the VCEK chains `VCEK → ASK → ARK`, and the ARK matches the **pinned** AMD root for the
  product (the verifier fetches ASK/VCEK from `https://kdsintf.amd.com` itself; only the
  ARK is pinned in the binary),
- TCB in the report is at or above policy floor.

This is exactly the path `secgit-attest::vcek::verify_vcek` + `snp::SnpVerifier` execute;
the verifier re-runs it independently with its own KDS fetch.

### 4c. The measurement equals the published OSS build

Confirm the report's launch `measurement` equals `M_expected` from §2. Any mismatch means
the operator booted a different image (a backdoored build, a debug build, or a different
cmdline) — fail.

### 4d. Operator cannot read the repo (ciphertext-only on host)

Create an **ephemeral** repo and push real content over in-CVM PQC-TLS:

```bash
git init demo && cd demo && echo "canary-$(uuidgen)" > secret.txt
git add -A && git commit -m "acceptance canary"
git remote add origin https://<host>:<port>/<repo>.git
git push origin main
```

Then, on the **host** (operator's view of the disk — outside the CVM), grep the entire
SecGit data directory for the canary string and any plaintext metadata (repo name, branch
names, your identity, commit message):

```bash
grep -R "canary-" /var/lib/secgit/         # MUST find nothing
strings /var/lib/secgit/**/* | grep -i demo # MUST NOT reveal repo/ref names
```

Both must come up empty: object contents are encrypted in `EncryptedStore`, and the audit
log is AEAD-encrypted at rest (see `docs/metadata-boundary.md`). The only thing the host
sees is ciphertext volume and aggregate timing.

### 4e. Independent audit-log verification

The transparency log's PQC-signed checkpoint must verify under the published verifying key,
proving the audit trail wasn't forked or rewritten:

```bash
secgit-verify verify-checkpoint checkpoint.json verifying_key.json
```

---

## 5. Pass / fail criteria

The instance **passes** acceptance iff **all** hold:

1. Server used the real SNP verifier (no mock warning), TLS terminated in-CVM.
2. `report_data` binds the live TLS SPKI (§4a).
3. SNP report verifies to the pinned AMD ARK via KDS-fetched ASK/VCEK (§4b).
4. Launch measurement == independently reproduced `M_expected` (§4c).
5. Host disk is ciphertext-only; canary and metadata absent (§4d).
6. Transparency checkpoint verifies (§4e).

Any single failure invalidates the confidentiality claim for that instance.

---

## 6. What this does and does not prove

**Proves:** the plaintext lived only inside genuine AMD silicon running the exact published
build; the operator saw only ciphertext; the channel you used is that same TEE; the audit
trail is tamper-evident.

**Does not prove:** absence of AMD-firmware/microcode side channels, physical attacks
beyond the SEV-SNP threat model, or correctness of the published source itself (that is the
job of source review + reproducible builds). `configfs-tsm` and the guest kernel are inside
the TCB — see `docs/threat-model.md`.

---

## 7. Measurement reproducibility / remediation

The launch-measurement match (§4c) is the **most likely place a first run fails**, because
the SHA-384 launch digest is sensitive to every byte of the launch context. When the harness
prints a `MISMATCH predicted=… live=…` at step (c), work through these — they are ordered by
how often they bite:

1. **Kernel command line (`--append`).** Must be **byte-identical** to what the CVM actually
   boots with, including ordering, whitespace, and any `root=`, `console=`, `ro/rw`, and
   initrd hand-off args. A single differing space changes the digest. Capture the live
   cmdline the operator configured and diff it against `snp-inputs.json`.
2. **Firmware / OVMF build.** The `--ovmf` blob must be the exact published firmware, pinned
   in `deploy/guest/ovmf.pin.json`. For **measured direct boot** it MUST be built from
   `OvmfPkg/AmdSev/AmdSevX64.dsc` (a single `OVMF.fd` carrying the `SNP_KERNEL_HASHES`
   section) and launched with `kernel-hashes=on`; a stock `OvmfPkgX64.dsc` build omits the
   kernel/initrd/cmdline from the measurement. A distro-patched OVMF or different build date
   also differs.
3. **Kernel + initrd artifacts (the UKI).** SecGit fuses kernel+initrd+cmdline into a single
   reproducible UKI (`deploy/guest/mkosi.conf`); pass that UKI as the measured `--kernel`.
   A locally regenerated UKI (different compression, mtimes, or module set) will not match —
   build it reproducibly (pinned `SOURCE_DATE_EPOCH`, Debian snapshot, sorted inputs).
   `[VERIFY] / decision:` SecGit targets the `sev-snp-measure` OVMF measured-direct-boot path
   (recorded as `vmm_launch_method` in the descriptor). If your host instead launches via
   **IGVM** (some newer QEMU/cloud-hypervisor stacks), the measurement is computed over the
   IGVM file with `igvmmeasure`, not OVMF+kernel+initrd — set `vmm_launch_method` accordingly
   and use the matching tool. Confirm which path the target host uses before the run.
4. **vCPU count and type (`--vcpus`, `--vcpu-type`).** The measurement includes the VMSA for
   each vCPU; `4`/`EPYC-v4` here must equal the launch topology exactly. Genoa vs Milan vCPU
   types differ.
5. **Build determinism.** Rebuild the image with `--locked` and a fixed `SOURCE_DATE_EPOCH`;
   confirm two independent rebuilds produce the same artifacts before blaming the measurer.

The diff-driven loop:

```bash
# Re-emit the prediction from the (corrected) single inputs file:
cargo run -p xtask -- snp-measure --inputs snp-inputs.json --out snp-reference.json
# Re-run just the live comparison; the harness prints the precise predicted/live pair:
secgit-verify acceptance-snp --url https://<host>:<port> --reference snp-reference.json --data-dir /var/lib/secgit
```

Iterate on `snp-inputs.json` until `predicted == live`. If you cannot make independent
rebuilds converge bit-for-bit, the trust chain to "the published source" is broken — that is
a reproducible-build defect, not an SNP defect, and must be fixed there.

---

## 8. Adversarial runnables — confirm the box *refuses* (negative acceptance)

A genuine acceptance also proves the trust path **rejects** bad inputs. Each scenario PASSES
iff it is REFUSED. The mock-constructible refusals run anywhere (and in CI):

```bash
secgit-verify acceptance-snp --expect-refuse wrong-measurement
secgit-verify acceptance-snp --expect-refuse replay
secgit-verify acceptance-snp --expect-refuse stale
secgit-verify acceptance-snp --expect-refuse tampered-report
secgit-verify acceptance-snp --expect-refuse unknown-resource
```

On the silicon box, additionally confirm the strict policy refuses a *wrong* reference and a
mismatched VMPL by feeding deliberately-wrong inputs to the live run — these MUST fail at
step (c)/(d):

```bash
# Wrong measurement reference: step (c) must report MISMATCH (and overall FAIL).
secgit-verify acceptance-snp --url https://<host>:<port> --reference wrong-reference.json --data-dir /var/lib/secgit

# Wrong expected VMPL on the server (operator misconfig / less-privileged context):
#   boot with SECGIT_SNP_EXPECTED_VMPL=2 against a real VMPL0 report -> KEK release refused.
```

The `wrong-vmpl`, `revoked-vcek`, `broken-chain`, and `invalid-vcek-sig` refusals are proven
at unit level by `cargo test -p secgit-attest` (mock-runnable) and by the live chain/CRL/VMPL
checks during the on-silicon run; they are not constructible from the mock TEE alone.
