//! # secgit-crypto
//!
//! The crypto-agility core for SecGit. Every confidential artifact in the system —
//! bulk data at rest, wrapped keys, and signatures — is produced and consumed through
//! this crate, and every artifact is self-describing: it carries a `(kind, scheme,
//! version)` header so schemes can be added or retired without breaking formats.
//!
//! ## What lives where
//! - [`aead`]: AES-256-GCM / ChaCha20-Poly1305 for bulk data and symmetric key-wrap.
//! - [`kem`]: hybrid X25519 + ML-KEM-768 for the attestation-gated release channel.
//! - [`sig`]: hybrid Ed25519 + ML-DSA for audit/commit/build signatures.
//! - [`primitives`]: rng, digests, HKDF.
//! - [`ids`] / [`envelope`]: the agility machinery (scheme ids + binary framing).
//!
//! ## Honest caveat
//! Hardware TEE attestation (SEV-SNP / TDX) signs with classical vendor ECDSA and
//! cannot be made post-quantum unilaterally. This crate provides PQ confidentiality
//! (storage + key release) and PQ signatures everywhere SecGit controls the keys; it
//! does NOT make the hardware attestation itself post-quantum.

pub mod aead;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod kem;
mod mldsa;
pub mod primitives;
pub mod sig;

pub use error::{CryptoError, Result};
pub use ids::{
    AeadScheme, KemScheme, Kind, SigScheme, DEFAULT_AEAD, DEFAULT_KEM, DEFAULT_SIG, LONG_LIVED_SIG,
};

/// Inspect any SecGit crypto artifact's agility header without decrypting it.
///
/// Useful for migration tooling and audits ("what scheme is this object under?").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactInfo {
    pub kind: Kind,
    pub scheme: u16,
    pub version: u8,
}

pub fn inspect(artifact: &[u8]) -> Result<ArtifactInfo> {
    let env = envelope::Envelope::decode(artifact)?;
    Ok(ArtifactInfo {
        kind: env.kind,
        scheme: env.scheme,
        version: env.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_reports_header() {
        let key = aead::SymKey::generate().unwrap();
        let ct = aead::seal(DEFAULT_AEAD, &key, b"", b"x").unwrap();
        let info = inspect(&ct).unwrap();
        assert_eq!(info.kind, Kind::Aead);
        assert_eq!(info.scheme, DEFAULT_AEAD.as_u16());
        assert_eq!(info.version, 1);
    }
}
