//! # secgit-sso
//!
//! Enterprise single-sign-on and provisioning for SecGit, executed **inside the CVM**:
//!
//! - [`saml`] — SAML 2.0 Web-SSO Service Provider: verifies IdP-signed assertions
//!   (enveloped XML-DSig, exclusive-c14n, RSA-SHA256) against a pinned IdP certificate and
//!   enforces the SAML profile checks. Includes a minimal, scoped XML parser + canonicalizer
//!   ([`xml`]) so no general XML/crypto stack is pulled into the TCB.
//! - [`scim`] — SCIM 2.0 provisioning of Users and Groups over a storage-agnostic backend
//!   the server implements on top of the encrypted identity directory.
//!
//! Neither surface touches the confidentiality-critical KEK path: they authenticate and
//! provision *users*, while "the operator can't read your code" continues to rest on
//! attestation-gated key release. The supported SAML profile and its security boundary are
//! documented in `docs/sso-saml.md`.

pub mod saml;
pub mod scim;
pub mod xml;

pub use saml::{SamlError, SamlSp, VerifiedAssertion};
pub use scim::{Scim, ScimBackend, ScimError, ScimGroup, ScimResponse, ScimUser};
