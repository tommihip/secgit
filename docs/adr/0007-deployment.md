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

## Out of scope for v1
Confidential CI (the v2 headline). v1 supports customer-controlled external/self-hosted
runners as the escape hatch.
