# SecGit operations: bring-up, upgrade, backup

This is the operator runbook for a self-hosted SecGit instance. It covers one-command
bring-up (mock/dev and real SEV-SNP), the upgrade procedure (why an upgrade re-triggers
attestation and how state survives it), and backup/restore of the encrypted store. The trust
model is unchanged throughout: the operator/host is untrusted and sees only ciphertext; the
KEK is released into the CVM by attestation at boot, never held on the host.

## 1. One-command bring-up

```bash
# Dev / exploration (no silicon; confidentiality NOT enforced — a mock/dev KEK is used):
deploy/up.sh --mock

# Real confidential path (AMD SEV-SNP Linux host): builds OVMF + guest UKI, predicts the
# launch measurement, and boots the measured CVM:
EDK2_COMMIT=<reviewed edk2 sha> deploy/up.sh --snp
```

`--snp` runs the full pipeline: `deploy/guest/build-ovmf.sh` (reproducible firmware) →
`deploy/guest/build-guest.sh` (reproducible UKI + commit-bound `snp-reference.json`) →
optional `xtask provenance` (PQC-signed provenance) → `deploy/guest/launch-snp.sh` (measured
`kernel-hashes=on` boot). See [packaging.md](packaging.md) for the artifact chain and
[acceptance-snp.md](acceptance-snp.md) for the verifier's side.

### Verify the running instance (verifier, not operator)

```bash
secgit-verify probe-snp
secgit-verify acceptance-snp --url https://<host>:8443 --data-dir /var/lib/secgit \
  --product Milan --reference snp-reference.json --out acceptance-transcript.json
secgit-verify verify-transcript acceptance-transcript.json acceptance-transcript.json.vk.json
```

## 2. Upgrade

An image upgrade is a **new measured guest**, so it is intentionally an attestation event:

1. Build and publish the new image (reproducibly) and re-run `deploy/guest/build-guest.sh` to
   emit the new `snp-reference.json` (a new `measurement_hex`, bound to the new git commit)
   and, if you sign provenance, a new `provenance.json` appended to the transparency log.
2. The new measurement **must be allow-listed before it can boot to a released KEK**:
   - self-hosted KBS: add the new `measurement_hex` to the broker's allowed set (keep the old
     one during the rollover window so a rollback still attests);
   - local broker: set `SECGIT_SNP_REFERENCE` to the new reference.
3. Boot the new guest. On boot it performs the attestation-gated KEK release under the new
   measurement, then opens the **existing** encrypted `/data`.

Why state survives: the KEK is unchanged across the upgrade; only the guest measurement
changes. The encrypted store holds per-repo DEKs wrapped by that same KEK, so a freshly
attested new guest that receives the KEK can unwrap exactly the data the old guest could.
Nothing in `/data` is tied to a specific measurement.

Rollback is symmetric: keep the previous measurement allow-listed and re-launch the previous
UKI. Because the measurement is published + commit-bound, a verifier can always tell which
image is actually running.

> Do NOT rotate the KEK as part of a routine image upgrade — that is a separate, deliberate
> key-rotation operation (`AuditEvent::KeyRotated`) with its own re-encryption cost.

## 3. Backup and restore

The entire on-disk store is **ciphertext-only** (per-repo objects sealed with per-repo DEKs;
the DEKs stored wrapped by the KEK; the audit log AEAD-encrypted at rest — see
[metadata-boundary.md](metadata-boundary.md)). Therefore:

- **Backup** = copy the `/data` volume (or the CVM's data disk image) anywhere, including
  untrusted storage. There is no plaintext to protect; the host already only ever saw
  ciphertext. Snapshot `/data` while the service is briefly quiesced (or use a filesystem/
  block snapshot) to get a consistent copy.
- **Restore** = place the backed-up `/data` under the new guest and boot. The newly attested
  guest receives the KEK, unwraps the DEKs, and serves the repos. No plaintext ever leaves
  the TEE during backup or restore.

### The KEK is the recovery root

Backups are useless without the KEK, by design. KEK recovery follows the tier policy in
[adr/0010-open-subdecisions.md](adr/0010-open-subdecisions.md) #1:

- **Anonymous / personal (default, zero-knowledge):** no escrow. Lose the KEK, lose the data —
  this is the literal proof of "the operator cannot recover or surrender your code."
- **Org (opt-in):** customer-held recovery (Shamir/social) or the customer's own KMS/HSM. The
  operator still cannot recover unilaterally; wording shifts to "the operator can't
  *unilaterally* recover/surrender your code."

Protect the KEK / customer KMS credentials with the same rigor as the data they unlock;
publish the provenance verifying key so downstreams can check `provenance.json` after restore.

## 3b. Provenance release-key ceremony

Release provenance (`provenance.json`) is signed with a **long-lived hybrid PQC key** (Ed25519
+ ML-DSA-87). Verifiers check a release against the **published verifying key** committed at
[`deploy/provenance.vk.json`](../deploy/provenance.vk.json); `secgit-verify verify-provenance`
defaults to it, so a user needs nothing out-of-band.

The private half is generated **once, offline**, and never touches the repo or CI logs:

1. **Generate (air-gapped host):**

```bash
cargo run -p xtask -- provenance-keygen \
  --bundle-out provenance-signing-key.json \
  --vk-out deploy/provenance.vk.json
```

   This writes the PRIVATE `SigningKeyBundle` (mode `0600`) and the PUBLIC `VerifyingKey`.

2. **Publish the public key:** commit `deploy/provenance.vk.json`. It is safe to distribute and
   is what every verifier trusts.

3. **Store the private bundle offline:** move `provenance-signing-key.json` into an HSM / KMS or
   an air-gapped, access-controlled vault. It is `.gitignore`d so it cannot be committed by
   accident. Anyone holding it can forge SecGit release provenance — treat it like a code-signing
   root.

4. **Sign a release:** on the release host, provide the bundle to the signer via the environment
   only (never a file in the tree):

```bash
export SECGIT_PROVENANCE_KEY=/secure/provenance-signing-key.json
deploy/up.sh --snp                 # with SECGIT_SIGN_PROVENANCE=1, or run `xtask provenance`
```

   `deploy/up.sh` re-verifies the fresh signature against the committed public key before the
   artifact ships. In CI the `release-provenance` job (tag builds only) does the same, sourcing
   the bundle from the `PROVENANCE_SIGNING_KEY` repository secret; PR CI keeps an ephemeral-key
   roundtrip and never needs the secret.

5. **Rotation:** re-run step 1 (`--force`), commit the new `deploy/provenance.vk.json`, and
   re-store the new bundle offline. Consumers pick up the new key with the next checkout; keep an
   overlap window if you re-sign in-flight artifacts.

## 4. What the operator never has

- The KEK in plaintext on the host (released only into CVM memory after attestation).
- Any plaintext repo content, ref names, identities, or audit entries (all ciphertext at rest).
- The ability to loosen the guest's egress policy without changing the measurement
  (`deploy/guest/nftables.conf` is baked into the measured UKI).
