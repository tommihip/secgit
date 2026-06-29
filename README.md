<div align="center">

<img src="docs/assets/social-preview.jpg" alt="SecGit" width="640" />

# SecGit

### Git hosting where the operator literally *cannot* read your code — and you can prove it.

**Provider-blind, attestation-backed, post-quantum code hosting for regulated and sensitive private code.**

The operator can't read your code, can't train on it, can't be subpoenaed into surrendering it, and your data is safe from harvest-now-decrypt-later — **and all of this is cryptographically verifiable by anyone.**

[![CI](https://img.shields.io/github/actions/workflow/status/tommihip/secgit/ci.yml?branch=main&label=CI)](https://github.com/tommihip/secgit/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](rust-toolchain.toml)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-yellow.svg)](docs/STATUS.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome%20(DCO)-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

> [!IMPORTANT]
> **Honest status: pre-alpha.** The confidential core (attestation-gated key release → encrypted-at-rest store → PQC-signed transparency log) **composes end-to-end and is MOCK-VERIFIED in CI** against a software mock TEE. **No signed SEV-SNP silicon transcript exists yet**, so every claim that ultimately depends on the hardware root is `UNVERIFIED on silicon` until we publish that transcript. We track this honestly in a public ledger — see [`docs/STATUS.md`](docs/STATUS.md). The radical transparency *is* the product.

## Why SecGit?

Every other "secure" code host eventually asks you to **trust the operator**. SecGit replaces that trust with **math and hardware you can check yourself**.

- 🔒 **Provider-blind hosting** — your plaintext exists only inside an attestable confidential VM (TEE). On disk and on the wire, the operator sees nothing but ciphertext.
- 🔎 **User-verifiable remote attestation** — anyone can confirm that the running service matches the open-source, reproducibly-built image, and that the confidentiality guarantee actually holds. No "trust us" required.
- 🔑 **BYOK / customer-held keys** — keys are released *only* to a genuine, attested TEE. A forged or modified environment gets nothing.
- 📜 **Independent tamper-evident audit log** — a hash-chained / Merkle transparency log with PQC-signed checkpoints. History can't be quietly rewritten.
- 🚫 **"No AI training" as a consequence, not a policy** — there's no place in the system where your plaintext is reachable by a training pipeline, and the build *bans* ML/telemetry dependencies. It's enforced and tested, not promised in a contract.
- 🛡️ **Hybrid post-quantum cryptography** — storage keys, key release, transport, and the signatures we control all use hybrid PQC (X25519 + ML-KEM-768, Ed25519 + ML-DSA). Harvest-now-decrypt-later doesn't work on your repos.

## How is this different from GitHub, GitLab, or self-hosting?

- **vs. GitHub / GitLab SaaS:** they can read every byte you push (and so can anyone who subpoenas or breaches them). SecGit operators physically hold only ciphertext.
- **vs. "encrypted" SaaS that holds your keys:** if the provider can decrypt to serve you, the provider can decrypt for anyone else. SecGit releases keys *only* into attested TEE memory, never to the operator.
- **vs. self-hosting it yourself:** self-hosting moves the trust to *your* ops team and infra. SecGit's guarantee is verifiable even when someone *else* runs the server — because the hardware attests to the exact code that's running.

The wedge in one sentence: **encrypted at rest and in transit under keys the operator never possesses, running inside hardware that proves what it's executing — verifiable by you, not asserted by us.**

## See for yourself in ~60 seconds

The entire workspace builds and runs natively on macOS (Apple Silicon) and Linux against the **mock TEE** — no Docker, no Linux VM needed to explore. (Confidentiality is *not* enforced on the mock path; that requires real AMD SEV-SNP silicon. See [`docs/dev-macos.md`](docs/dev-macos.md).)

```bash
git clone https://github.com/tommihip/secgit
cd secgit

# Build + run the in-process vertical slice:
# attestation-gated KEK release -> encrypted store -> PQC-signed transparency log.
cargo run -p secgit-verify -- selftest

# Dry-run the full acceptance harness against the mock TEE (no silicon required).
cargo run -p secgit-verify -- acceptance-snp --mock
```

Run the server and push a real repo to it:

```bash
# Pick a stable dev KEK so encrypted data survives restarts.
export SECGIT_DEV_KEK_HEX=$(openssl rand -hex 32)

# Serve on 127.0.0.1:8080 with a seeded local account (dev tier; plaintext HTTP for local only).
SECGIT_INSECURE_HTTP=1 \
SECGIT_BOOTSTRAP_USER=dev SECGIT_BOOTSTRAP_PASS=devpass \
  cargo run -p secgit-server
```

Then, in another shell:

```bash
open http://127.0.0.1:8080/        # landing page: the wedge + how to verify
open http://127.0.0.1:8080/ui      # browse repos (log in: dev / devpass)

# Push-to-create your first encrypted repo:
mkdir /tmp/demo && cd /tmp/demo && git init -q && echo hi > a.txt
git add -A && git -c user.email=a@b.c -c user.name=dev commit -qm init
git push http://dev:devpass@127.0.0.1:8080/dev/demo HEAD:refs/heads/main
```

Refresh `/ui` and your repo is there — files, history, and blame all served from inside the (mock) TEE, while on disk it's only ciphertext.

## Architecture at a glance

```
crates/
  secgit-crypto     crypto-agility core (versioned envelopes; AES/ChaCha, hybrid
                    X25519+ML-KEM-768, hybrid Ed25519+ML-DSA, swappable schemes)
  secgit-net        single audited outbound HTTPS client (rustls + Mozilla roots)
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
  secgit-leaktest   shared canary / at-rest / on-wire leak-test harness
  secgit-verify     standalone user-facing attestation verifier (CLI)
bins/
  secgit-server     the binary that runs inside the confidential VM
xtask/              reproducible-build + image-transparency tooling
```

Deeper reading: the [threat model (as-built)](docs/threat-model.md) and the [architecture decision records](docs/adr/).

## Don't trust us — verify

SecGit is built so a skeptical third party can check the load-bearing claims without trusting the operator *or* the SecGit project:

1. **The running service is the open-source code** — the SNP launch measurement equals the reproducible build ([`xtask snp-measure`](xtask/)).
2. **The attestation is genuine** — the SNP report verifies to AMD KDS roots (`VCEK → ASK → ARK`, with revocation checked and fail-closed).
3. **The channel is the attested TEE** — channel binding defeats a relayed report from a different machine.
4. **The disk holds only ciphertext** — `grep` for a planted canary finds nothing.
5. **The audit log is intact** — `secgit-verify verify-checkpoint` confirms the PQC-signed Merkle root.

Each maps to a concrete, runnable proof. The full per-claim ledger (and exactly what is MOCK-VERIFIED vs UNVERIFIED-on-silicon today) lives in [`docs/STATUS.md`](docs/STATUS.md); the acceptance procedure is in [`docs/acceptance-snp.md`](docs/acceptance-snp.md).

## Honest caveat on post-quantum attestation

Hardware TEE attestation (SEV-SNP / TDX) currently signs with classical ECDSA controlled by the CPU vendor, and that can't be made post-quantum unilaterally. So we claim **post-quantum confidential storage and transport**, *not* fully post-quantum attestation — and we layer our own hybrid-PQC signatures on top everywhere we control them. See [`docs/adr/0004-crypto-stack.md`](docs/adr/0004-crypto-stack.md).

## Roadmap

Depth on the verifiable confidential claim first; floor on commodity forge features. (See [`docs/adr/0009-milestones.md`](docs/adr/0009-milestones.md).)

- [x] **M0 — Foundation:** workspace, AGPL + DCO/CLA, CI, `cargo-deny` ban-list, crypto-agility core + mock TEE.
- [x] **M1 — Attestation vertical slice:** provider-neutral SNP verifier, attestation-gated KEK release, user-facing verifier *(MOCK-VERIFIED; silicon transcript pending).*
- [x] **M2 — Confidential storage + minimal forge:** envelope-encrypted store, gix reads + git-CLI pack engine, smart-HTTP server.
- [x] **M3 — Transparency-log audit:** hash-chain + Merkle, PQC-signed checkpoints, inclusion/consistency proofs.
- [x] **M4 — Identity + access control:** User/Org/Repo model, OIDC + local auth.
- [ ] **M5 — Reproducible builds + image transparency:** bind launch measurement to the OSS build.
- [ ] **M6 — Demo-as-sandbox tiers:** public instance with abuse/DoS controls.
- [ ] **M7 — Packaging:** OCI + Compose for a confidential VM, hardening.
- [ ] **Silicon acceptance:** publish the signed SEV-SNP transcript that promotes the core claims to `SILICON-VERIFIED`.

## Contributing

Contributions are very welcome. Building requires Rust 1.85+ and a C toolchain + CMake (for the audited `aws-lc-rs` PQC provider) — see [`docs/dev-macos.md`](docs/dev-macos.md). Commits require [DCO](https://developercertificate.org/) sign-off (`git commit -s`), and first-time contributors accept a CLA. Details in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[AGPL-3.0-or-later](LICENSE).

---

<div align="center">

**If a code host that genuinely can't read your code sounds like it should exist — star the repo and follow along.** ⭐

</div>
