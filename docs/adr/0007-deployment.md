# ADR 0007: Demo-as-sandbox deployment model

Status: accepted

## Decision
The public instance is the **real OSS build deployed in sandbox mode** — a config
(`DeploymentConfig.sandbox_mode`), not a separate codebase. Three interaction tiers
(`crates/secgit-api`):

- **Tier a — Anonymous (no account):** run the attestation-verification flow against a
  live repo, AND create an anonymous **ephemeral repo** (throwaway push token,
  auto-expiring TTL, size-capped) to push your own code and confirm "they can't read MY
  repo." The frictionless viral path. Abuse controls: per-client create rate limit,
  TTL GC, byte-cap accounting (`EphemeralRepos`).
- **Tier b — Light (OIDC/local):** persistent capped sandbox repos; managed-product
  waitlist.
- **Tier c — Managed/enterprise (later):** org + BYOK-to-customer-KMS + IdP.

## Packaging
OCI container + Compose (`deploy/`), designed to run **inside a confidential VM**. The
container reads attestation evidence from the guest via `configfs-tsm`; there is no
cloud-attestation sidecar.

## TLS terminates INSIDE the CVM (corrected)
**Superseded decision:** an earlier draft expected TLS termination at an upstream reverse
proxy. That is **rejected**: a proxy outside the CVM would see plaintext git/HTTP between
itself and the TEE, which is exactly the operator-visible plaintext the wedge forbids.

PQC-TLS is therefore terminated **in-process inside the CVM** by `secgit-server`
(`bins/secgit-server/src/tls.rs`), using rustls' aws-lc-rs provider with
`prefer-post-quantum`, so the hybrid `X25519MLKEM768` group is highest-priority
(harvest-now-decrypt-later resistant). No reverse proxy may sit between the network and
the CVM on the plaintext side; any L4 load balancer must pass through encrypted bytes
only.

- **Cert trust = attestation, not web PKI.** The server uses a self-signed (or
  operator-supplied) leaf; the SHA-256 of its SubjectPublicKeyInfo is bound into the
  attestation `report_data` and surfaced at `GET /attestation` (`channel_binding`,
  `tls_spki_sha256_hex`). A client running `secgit-verify` confirms the attested TEE is
  its actual TLS peer, defeating a man-in-the-middle that relays attestation from a
  genuine TEE.
- **Dev escape hatch.** `SECGIT_INSECURE_HTTP=1` serves plaintext for local testing only
  and logs a loud warning; it is never provider-blind on the wire.
- Request decompression (e.g. gzipped git fetch bodies) is handled per-route inside the
  CVM, not by an external proxy.

A leak-test (`tls::tests::handshake_uses_pq_kx_and_wire_is_ciphertext`) asserts the PQ
group is negotiated and that application plaintext never appears on the wire.

## Abuse / DoS hardening (M6)
The public instance must survive a hostile internet without weakening the wedge. The
controls live on the serve path in `bins/secgit-server` and are all **config-driven**
(`config.rs`, `SECGIT_*` env), so the same OSS build runs locked-down or permissive.

- **Transport (custom HTTP/1.1 stack, hardened in place).** We deliberately keep the
  dependency-free HTTP stack rather than adopt hyper/axum — a heavyweight framework would
  expand the in-CVM trust surface and contradict the all-Rust/minimal-TCB principle. It is
  hardened with: a bounded connection semaphore, socket read/write timeouts (slowloris
  defense across the TLS handshake and header/body reads), header byte + count caps
  (`431`), a body-size cap enforced on `Content-Length` before allocation (`413`), and
  explicit rejection of chunked transfer-encoding.
- **Rate-limit identity = TCP peer IP.** `stream.peer_addr()` is the trusted client id;
  `X-Forwarded-For` is treated as **untrusted** because this ADR forbids a trusted plaintext
  proxy in front of the CVM (a proxy would see plaintext). Consequence: behind a NAT, clients
  share a bucket. PROXY-protocol / a trusted L4 front that forwards the real peer is a noted
  future config, not built now. Buckets are memory-bounded token buckets (`ratelimit.rs`):
  per-IP request, per-IP git-op, per-account, and per-repo push.
- **Git subprocess bounds.** `secgit-git`/`secgit-forge` run every `git` child under a
  wall-clock watchdog (killed on timeout), a fetch output cap, and — for pushes —
  `receive.maxInputSize` + `transfer.fsckObjects` (decompression-bomb / malformed-object
  defense). The watchdog spawns each `git` child as its own process-group leader
  (`process_group(0)`) and kills the **whole group** on timeout/output-cap, so grandchildren
  (`pack-objects`) cannot linger.
- **`seal_to_store` amplification.** Sealing is **incremental / append-only**: each push
  appends an O(delta) `git bundle --all --not <sealed tips>` segment (tracked in an encrypted
  `seal.manifest`) instead of re-bundling the whole repo, so per-push cost scales with the
  push, not the repo. A periodic compaction (every `SECGIT_SEAL_MAX_SEGMENTS` segments, default
  32) folds segments back into a fresh base, keeping restore cost and object count bounded.
  Residual amplification (compaction × push-frequency) is bounded by the per-repo push rate
  limit, a global **seal-concurrency semaphore**, and the bundle wall-clock cap.
- **Ephemeral GC + reconciliation.** A background sweep wipes expired ephemeral working sets
  and their encrypted storage; on startup, orphaned `ephemeral/*` state (ephemeral lifecycle
  is in-memory only) is reconciled and wiped.
- **PoW escalation lever.** An optional CLI-friendly hashcash gate on anonymous create
  (`pow.rs`), **default OFF** — rate limits are primary; PoW is the escalation lever. The
  challenge is stateless + server-authenticated (HMAC) with a bounded replay set.
- **Abuse / takedown.** Since the operator is content-blind, takedown is by repo **id**, never
  content review: `POST /abuse/report` writes to an **encrypted** queue (`abuse.rs`); a
  token-gated `POST /admin/repos/delete` force-deletes by id; every takedown is recorded in
  the PQC-signed transparency log (`AuditEvent::Admin`).
- **Content-free observability (metrics tension resolved).** Metrics are needed but the
  operator is untrusted, so the registry (`metrics.rs`) is **content-free by construction**
  (fixed label set, no repo ids/paths/usernames/IPs/sizes) — nothing to leak. It is
  additionally defense-in-depth: token-gated and served on a **separately bindable**
  (localhost-default, never public unless configured) pull-only listener; no outbound push,
  preserving no-telemetry / no-egress. A leak-test scans the rendered output for a canary.

Per-tier leak-tests (`bins/secgit-server/tests/tier_leaktest.rs`) prove ciphertext-at-rest
for the anonymous/Light/Managed repo-id shapes; on-wire is covered generically by the TLS
loopback leak-test.

## Out of scope for v1
Confidential CI (the v2 headline). v1 supports customer-controlled external/self-hosted
runners as the escape hatch.
