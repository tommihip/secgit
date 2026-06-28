# "No AI training" — a technical consequence, not a policy promise

Most vendors answer "will you train on my code?" with a clause in a contract. SecGit
answers it with **architecture**: there is no place in the system where your plaintext is
available to a training pipeline, and that is enforced and tested in the build — not
promised.

This document states the technical argument and points at the enforcement.

## The argument

1. **Plaintext exists only inside the TEE, only in memory.**
   - Repository contents are decrypted only inside the confidential VM, after the KEK is
     released through attestation (`secgit-keybroker`, `secgit-store`). On disk everything
     is ciphertext (`store` + `secgit-forge` encrypted bundles), including audit-log
     event metadata (`TransparencyLog::open_encrypted`). Leak-tests:
     `secgit-store::tests::data_on_disk_is_ciphertext`,
     `secgit-audit::tests::encrypted_log_hides_metadata_but_stays_verifiable`.
   - The KEK itself is never written to disk; it lives only in CVM memory.

2. **No plaintext leaves the CVM.**
   - Transport is PQC-TLS terminated *inside* the CVM (`bins/secgit-server/src/tls.rs`),
     so there is no operator-visible plaintext hop. Leak-test:
     `secgit-server::tls::tests::handshake_uses_pq_kx_and_wire_is_ciphertext`.
   - The only outbound network calls the server makes by design carry **non-secret**
     data: fetching public AMD KDS/VCEK certificates and sending **attestation evidence**
     to a key broker (A.2). None of these carry repository plaintext.

3. **There is no ML/training machinery in the trust path.**
   - The server that handles plaintext has **no** ML/inference/training framework, no
     embedding/vector-store client, and no outbound LLM API client in its dependency
     graph. So even a malicious build change that tried to "just call a model" would have
     to first add a dependency — which the build gate rejects.

4. **Operator can't subpoena what it can't read.**
   - Because the operator only ever holds ciphertext + attestation evidence, there is no
     plaintext corpus to hand to a training process, a third party, or a court. (Key
     recovery/escrow posture is tier-specific; see ADR 0010.)

## Enforcement (checked in CI, runnable locally)

- **Dependency ban (`deny.toml`).** The `[bans].deny` list forbids ML/inference/training
  frameworks (`tch`, `torch-sys`, `tensorflow*`, `onnxruntime*`, `ort`, `candle-*`,
  `burn`, `dfdx`, `linfa`, `smartcore`, `rust-bert`, `llm`, `llama*`), tokenizers/LLM
  clients (`tokenizers`, `tiktoken-rs`, `openai-api-rs`, `async-openai`), vector stores
  (`qdrant-client`, `pinecone-sdk`), and exfiltration-prone telemetry SDKs (`sentry`,
  `opentelemetry-otlp`, `segment`). Run: `cargo deny check bans`.
- **Standalone egress check (`xtask egress-check`).** Scans `Cargo.lock` for the same ban
  list, so the invariant holds even when cargo-deny can't run (e.g. an advisory-DB parse
  issue). Run: `cargo run -p xtask -- egress-check`. Tested by
  `xtask::tests::no_ml_or_telemetry_deps_in_graph` (plus a planted-dependency negative
  test).
- **At-rest + on-wire leak-tests** (listed above) prove the plaintext channels the ban
  protects are themselves closed.

## Honest limits

- This says nothing about what a *user* chooses to run against their own plaintext inside
  their own tenant — it constrains **SecGit the operator/service**, which is the trust
  question that matters here.
- The ban list is a denylist of known crates; it is a strong guard but not a proof that
  no networking code exists. The combination with the at-rest/on-wire leak-tests and the
  minimal, reviewed trust path (A.4 threat model) is what makes the claim credible.
- Confidential CI (running untrusted build steps against plaintext) is deliberately **v2**
  and out of the v1 trust surface (ADR 0007); v1 uses external/self-hosted runners.
