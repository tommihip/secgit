# Enterprise SSO (SAML 2.0) and Provisioning (SCIM 2.0)

SecGit's enterprise identity surfaces run **inside the CVM**, like everything else. They
authenticate and provision *users*; they do **not** touch the confidentiality-critical KEK
path. A bug in SAML/SCIM could let an attacker impersonate a user to the forge, but the
provider-blindness guarantee ("the operator can't read your code") continues to rest on
attestation-gated key release, not on these protocols.

Implemented in the `secgit-sso` crate (`saml`, `scim`, and a scoped `xml` parser +
canonicalizer), wired into `secgit-server` via `src/sso.rs`.

## SAML 2.0 Web SSO (Service Provider)

### Flow

1. Admin registers SecGit with their IdP using SP metadata from `GET /sso/saml/metadata`.
2. User authenticates at the IdP; the IdP POSTs a signed `<Response>` to the ACS endpoint
   `POST /sso/saml/acs` (HTTP-POST binding, form field `SAMLResponse`, base64).
3. SecGit verifies the assertion **inside the CVM** and, on success, just-in-time
   provisions the user and mints a session bearer token (also usable as the HTTP Basic
   password for git over HTTPS).

### What is verified

- **XML-DSig signature** over the assertion (preferred) or the response:
  - Enveloped-signature transform + **Exclusive XML Canonicalization** (`xml-exc-c14n#`).
  - `rsa-sha256` signature, `sha256` digest.
  - The signature is verified against a **pinned IdP certificate** (configured
    out-of-band), *not* the certificate embedded in the document's `KeyInfo`. A forged
    embedded cert is therefore irrelevant.
  - Both the reference digest (over the canonicalized, signature-stripped element) and the
    RSA signature (over the canonicalized `SignedInfo`) are checked.
- **SAML profile checks**: top-level `Status` = Success; `Issuer` = configured IdP
  entityID; `Conditions` `NotBefore`/`NotOnOrAfter` (with clock skew); `AudienceRestriction`
  = configured SP entityID; `SubjectConfirmationData` `Recipient` = ACS URL and its
  `NotOnOrAfter`.

### Supported profile / limitations (be honest)

- Signature algorithm: RSA-SHA256 only (crypto-agility can add ML-DSA/ECDSA later).
- Canonicalization: exclusive c14n (`xml-exc-c14n#`), with optional `InclusiveNamespaces`
  PrefixList. Inclusive c14n (`xml-c14n#`) is not implemented.
- `EncryptedAssertion` is **rejected** (not yet supported); SAML 1.x and DTDs are rejected.
- The XML parser intentionally supports only the element/attribute/namespace/text profile
  IdPs emit for assertions. It rejects DOCTYPE/DTD (XXE-safe).

The canonicalizer is implemented to the W3C exc-c14n recommendation and is round-trip
tested against signatures generated with a real RSA key + X.509 cert (see
`crates/secgit-sso/tests/fixtures` and the `end_to_end_signed_assertion` test).
**Operational note:** because c14n edge cases vary across IdPs, validate interop against the
specific target IdP during onboarding before relying on it in production.

### Configuration (environment)

| Variable | Meaning |
| --- | --- |
| `SECGIT_SAML_SP_ENTITY_ID` | Our SP entityID (must equal assertion `<Audience>`) |
| `SECGIT_SAML_ACS_URL` | Assertion Consumer Service URL (must equal `Recipient`) |
| `SECGIT_SAML_IDP_ENTITY_ID` | Expected IdP entityID (must equal assertion `<Issuer>`) |
| `SECGIT_SAML_IDP_CERT` | Path to the pinned IdP signing cert (PEM or DER) |
| `SECGIT_EXTERNAL_URL` | Public base URL (SP metadata, SCIM `meta.location`) |

All four SAML variables must be set to enable SAML; otherwise `/sso/saml/*` returns 503.

## SCIM 2.0 Provisioning

`/scim/v2/...` implements RFC 7643/7644 Users and Groups:

- `Users`: create / get / list (with `userName eq "..."` / `externalId eq "..."` filters) /
  replace (PUT) / **PATCH** (the near-universal `active` toggle for deprovisioning) / delete.
- `Groups`: create / get / list / replace / delete.
- `ServiceProviderConfig` advertises the supported feature set.

Provisioned users land in the **encrypted identity directory**; SCIM-specific fields
(`active`, `externalId`, `displayName`) and groups live in an encrypted side-store. So all
provisioned metadata is ciphertext on the operator's disk like every other record.

**Deprovisioning is immediate**: deactivating (`active=false`) or deleting a user revokes
that user's live sessions.

### Authentication

SCIM is gated by a dedicated **provisioning bearer token** (`SECGIT_SCIM_TOKEN`), compared
in constant time, separate from user sessions. If unset, `/scim/v2/*` returns 503.

| Variable | Meaning |
| --- | --- |
| `SECGIT_SCIM_TOKEN` | Bearer token IdPs present to provision (keep secret) |
