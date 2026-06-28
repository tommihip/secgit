# ADR 0006: Identity model and auth abstraction

Status: accepted

## Decision
Identity model: **Users -> Organizations (with Teams) -> Repos**. A repo is owned by a
user (personal) or an org. v1 is **private repos only** — everything encrypted, no
public repos. KEK ownership maps to org (or user for personal repos), consistent with
ADR 0003. (`crates/secgit-identity::model`.)

## Authorization
Effective role on a repo = max of: personal ownership (Admin), org ownership (Admin),
direct collaborator grant, and team grants (for team members). Roles ordered
`Read < Write < Admin`. Resolver: `Directory::effective_role` / `can`.

## Authentication
Pluggable `Authenticator` trait. v1 ships:
- **Local accounts**: username/password with PBKDF2-HMAC-SHA256 (aws-lc-rs),
  600k iterations, per-user salt.
- **OIDC-first**: `OidcVerifier` seam (validate ID token vs provider JWKS, map subject
  to user). `[VERIFY]` JWKS/JWT validation wired when the provider is selected.

SAML/SCIM are deferred to the enterprise tier.
