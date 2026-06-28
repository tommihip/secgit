//! ML-DSA (FIPS 204) post-quantum signatures via aws-lc-rs.
//!
//! `[VERIFY]` aws-lc-rs exposes ML-DSA only through `unstable::signature` as of
//! v1.17 (stabilization slipping; last upstream ETA ~Mar 2026). This module is the
//! single isolation point for that unstable surface so a stabilization (or a backend
//! swap to SLH-DSA for the long-lived log) is a one-file change.
//!
//! Parameter sets: ML-DSA-65 for general use, ML-DSA-87 for the long-lived log.

use crate::error::{CryptoError, Result};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    MlDsa65,
    MlDsa87,
}

impl Param {
    fn signing(self) -> &'static aws_lc_rs::unstable::signature::PqdsaSigningAlgorithm {
        match self {
            Param::MlDsa65 => &ML_DSA_65_SIGNING,
            Param::MlDsa87 => &ML_DSA_87_SIGNING,
        }
    }
    fn verifying(self) -> &'static aws_lc_rs::unstable::signature::PqdsaVerificationAlgorithm {
        match self {
            Param::MlDsa65 => &ML_DSA_65,
            Param::MlDsa87 => &ML_DSA_87,
        }
    }
}

/// An ML-DSA keypair plus the raw bytes needed to persist and re-load it.
pub struct MlDsaKey {
    kp: PqdsaKeyPair,
    seed: Vec<u8>,
    public: Vec<u8>,
}

// ===========================================================================
// aws-lc-rs 1.17 unstable ML-DSA API (verified against
// aws-lc-rs-1.17.0/src/pqdsa/key_pair.rs; this is the ONE file that touches the
// unstable surface):
//   * `PqdsaKeyPair::from_seed(&'static PqdsaSigningAlgorithm, &[u8]) -> Result<_,
//     KeyRejected>` — deterministic 32-byte-seed keygen (FIPS 204).
//   * `KeyPair::public_key(&kp).as_ref() -> &[u8]` for raw public bytes.
//   * `kp.sign(msg, &mut sig) -> Result<usize, Unspecified>` writes into a caller
//     buffer sized by `kp.algorithm().signature_len()` and returns the byte length.
// If a future version stabilizes or renames these, only this file changes.
// ===========================================================================

impl MlDsaKey {
    pub fn generate(param: Param) -> Result<Self> {
        // Generate our own 32-byte seed so the key is persistable by seed and we never
        // depend on extracting a seed back out of a randomly-generated key.
        let seed = crate::primitives::random_vec(32)?;
        Self::from_seed(param, &seed)
    }

    pub fn from_seed(param: Param, seed: &[u8]) -> Result<Self> {
        let kp =
            PqdsaKeyPair::from_seed(param.signing(), seed).map_err(|_| CryptoError::Backend)?;
        let public = kp.public_key().as_ref().to_vec();
        Ok(Self {
            kp,
            seed: seed.to_vec(),
            public,
        })
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; self.kp.algorithm().signature_len()];
        let n = self
            .kp
            .sign(msg, &mut sig)
            .map_err(|_| CryptoError::Backend)?;
        sig.truncate(n);
        Ok(sig)
    }
}

/// Stateless verification of an ML-DSA signature against raw public-key bytes.
pub fn verify(param: Param, public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(param.verifying(), public)
        .verify(msg, sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_sign_verify_and_persist() {
        let key = MlDsaKey::generate(Param::MlDsa65).unwrap();
        let sig = key.sign(b"audit checkpoint").unwrap();
        assert!(verify(
            Param::MlDsa65,
            key.public(),
            b"audit checkpoint",
            &sig
        ));
        assert!(!verify(Param::MlDsa65, key.public(), b"tampered", &sig));

        // Reload from seed and confirm the public key is identical (pinned identity).
        let reloaded = MlDsaKey::from_seed(Param::MlDsa65, key.seed()).unwrap();
        assert_eq!(reloaded.public(), key.public());
        let sig2 = reloaded.sign(b"audit checkpoint").unwrap();
        assert!(verify(
            Param::MlDsa65,
            key.public(),
            b"audit checkpoint",
            &sig2
        ));
    }
}
