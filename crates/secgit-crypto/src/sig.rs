//! Hybrid digital signatures: Ed25519 + ML-DSA.
//!
//! Used for audit-log checkpoints, commit signing, and build attestations — every
//! signature SecGit controls. A signature is valid only if BOTH the classical and
//! the post-quantum half verify, so forgery requires breaking both. The verifying
//! identity is the pinned `(ed25519_pub, mldsa_pub)` pair; signatures carry only the
//! two signature blobs (not the public keys), so a forger can't substitute keys.
//!
//! `Ed25519MlDsa87` is the stronger parameter set reserved for the long-lived
//! transparency log; see `docs/adr/0010-open-subdecisions.md` for the SLH-DSA path.

use crate::envelope::{Envelope, Reader, Writer};
use crate::error::{CryptoError, Result};
use crate::ids::{Kind, SigScheme};
use crate::mldsa::{self, MlDsaKey, Param};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

const VERSION: u8 = 1;

fn param_for(scheme: SigScheme) -> Param {
    match scheme {
        SigScheme::Ed25519MlDsa65 => Param::MlDsa65,
        SigScheme::Ed25519MlDsa87 => Param::MlDsa87,
    }
}

/// A hybrid signing key. Holds both private keys in memory.
pub struct SigningKey {
    scheme: SigScheme,
    ed: Ed25519KeyPair,
    ed_pub: Vec<u8>,
    mldsa: MlDsaKey,
}

/// Persistable form of a [`SigningKey`] (store securely; contains private material).
#[derive(Serialize, Deserialize)]
pub struct SigningKeyBundle {
    pub scheme: u16,
    pub ed25519_pkcs8_hex: String,
    pub mldsa_seed_hex: String,
}

/// The public identity used to verify signatures from a [`SigningKey`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyingKey {
    pub scheme: u16,
    pub ed25519_pub: Vec<u8>,
    pub mldsa_pub: Vec<u8>,
}

impl SigningKey {
    pub fn generate(scheme: SigScheme) -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::Backend)?;
        let ed = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| CryptoError::Backend)?;
        let ed_pub = ed.public_key().as_ref().to_vec();
        let mldsa = MlDsaKey::generate(param_for(scheme))?;
        Ok(Self {
            scheme,
            ed,
            ed_pub,
            mldsa,
        })
    }

    /// Generate a key together with its persistable bundle in one step.
    pub fn generate_with_bundle(scheme: SigScheme) -> Result<(Self, SigningKeyBundle)> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::Backend)?;
        let ed = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| CryptoError::Backend)?;
        let ed_pub = ed.public_key().as_ref().to_vec();
        let mldsa = MlDsaKey::generate(param_for(scheme))?;
        let bundle = SigningKeyBundle {
            scheme: scheme.as_u16(),
            ed25519_pkcs8_hex: hex::encode(pkcs8.as_ref()),
            mldsa_seed_hex: hex::encode(mldsa.seed()),
        };
        Ok((
            Self {
                scheme,
                ed,
                ed_pub,
                mldsa,
            },
            bundle,
        ))
    }

    pub fn from_bundle(bundle: &SigningKeyBundle) -> Result<Self> {
        let scheme = SigScheme::from_u16(bundle.scheme)?;
        let pkcs8 = hex::decode(&bundle.ed25519_pkcs8_hex)
            .map_err(|_| CryptoError::Key("bad pkcs8 hex"))?;
        let ed = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| CryptoError::Backend)?;
        let ed_pub = ed.public_key().as_ref().to_vec();
        let seed = hex::decode(&bundle.mldsa_seed_hex)
            .map_err(|_| CryptoError::Key("bad mldsa seed hex"))?;
        let mldsa = MlDsaKey::from_seed(param_for(scheme), &seed)?;
        Ok(Self {
            scheme,
            ed,
            ed_pub,
            mldsa,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            scheme: self.scheme.as_u16(),
            ed25519_pub: self.ed_pub.clone(),
            mldsa_pub: self.mldsa.public().to_vec(),
        }
    }

    /// Produce a hybrid signature envelope over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let ed_sig = self.ed.sign(msg);
        let mldsa_sig = self.mldsa.sign(msg)?;
        let mut w = Writer::new();
        w.lp32(ed_sig.as_ref());
        w.lp32(&mldsa_sig);
        Ok(Envelope::new(Kind::Signature, self.scheme.as_u16(), VERSION, w.into_vec()).encode())
    }
}

/// Verify a hybrid signature envelope. Returns `Ok(())` only if BOTH halves verify
/// against the pinned [`VerifyingKey`].
pub fn verify(vk: &VerifyingKey, msg: &[u8], envelope_bytes: &[u8]) -> Result<()> {
    let env = Envelope::decode(envelope_bytes)?;
    if env.kind != Kind::Signature {
        return Err(CryptoError::Malformed("not a signature envelope"));
    }
    if env.version != VERSION {
        return Err(CryptoError::UnknownVersion(env.version));
    }
    if env.scheme != vk.scheme {
        return Err(CryptoError::Malformed("scheme mismatch with verifying key"));
    }
    let scheme = SigScheme::from_u16(env.scheme)?;

    let mut r = Reader::new(&env.body);
    let ed_sig = r.lp32()?;
    let mldsa_sig = r.lp32()?;

    // Classical half.
    UnparsedPublicKey::new(&ED25519, &vk.ed25519_pub)
        .verify(msg, ed_sig)
        .map_err(|_| CryptoError::BadSignature)?;
    // Post-quantum half.
    if !mldsa::verify(param_for(scheme), &vk.mldsa_pub, msg, mldsa_sig) {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_sign_verify() {
        let (sk, _bundle) = SigningKey::generate_with_bundle(SigScheme::Ed25519MlDsa65).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"hello world").unwrap();
        assert!(verify(&vk, b"hello world", &sig).is_ok());
        assert!(verify(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn persistence_roundtrip() {
        let (sk, bundle) = SigningKey::generate_with_bundle(SigScheme::Ed25519MlDsa65).unwrap();
        let vk = sk.verifying_key();
        let sk2 = SigningKey::from_bundle(&bundle).unwrap();
        assert_eq!(sk2.verifying_key(), vk);
        let sig = sk2.sign(b"persisted").unwrap();
        assert!(verify(&vk, b"persisted", &sig).is_ok());
    }

    #[test]
    fn long_lived_param_set() {
        let (sk, _b) = SigningKey::generate_with_bundle(SigScheme::Ed25519MlDsa87).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"log checkpoint").unwrap();
        assert!(verify(&vk, b"log checkpoint", &sig).is_ok());
    }
}
