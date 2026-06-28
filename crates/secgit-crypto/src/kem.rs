//! Hybrid key encapsulation: X25519 + ML-KEM-768.
//!
//! This is the attestation-gated key-release channel (and BYOK transport). In the
//! RCAR flow the recipient is the TEE, which generates an *ephemeral* hybrid keypair
//! per attestation and binds its public key into the attestation report. The sender
//! (key broker) encapsulates the KEK to that public key; only the attested TEE can
//! open it.
//!
//! Security rationale: confidentiality holds as long as *either* X25519 *or*
//! ML-KEM-768 remains unbroken (defends against harvest-now-decrypt-later while the
//! PQ primitive matures).

use crate::envelope::{Envelope, Reader, Writer};
use crate::error::{CryptoError, Result};
use crate::ids::{KemScheme, Kind};
use crate::primitives::{hkdf_sha384, random_bytes};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::kem;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroize;

const VERSION: u8 = 1;
const HKDF_INFO: &[u8] = b"secgit/hybrid-kem/x25519+mlkem768/v1";

/// A recipient's hybrid public key (safe to publish / put in an attestation report).
#[derive(Clone, Debug)]
pub struct RecipientPublic {
    pub x25519: [u8; 32],
    pub mlkem_ek: Vec<u8>,
}

impl RecipientPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.x25519);
        w.lp32(&self.mlkem_ek);
        w.into_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let mut x = [0u8; 32];
        x.copy_from_slice(r.take(32)?);
        let ek = r.lp32()?.to_vec();
        Ok(Self {
            x25519: x,
            mlkem_ek: ek,
        })
    }
}

/// A recipient's hybrid keypair. Holds private material in memory only.
///
/// `[VERIFY]` `mlkem_dk`'s type is the concrete aws-lc-rs ML-KEM decapsulation key.
/// In aws-lc-rs 1.17 this is `kem::DecapsulationKey<kem::AlgorithmId>`; if a future
/// version drops the type parameter, this single field annotation is the only change.
pub struct RecipientKeypair {
    x_secret: XSecret,
    x_public: [u8; 32],
    mlkem_dk: kem::DecapsulationKey<kem::AlgorithmId>,
    mlkem_ek: Vec<u8>,
}

impl RecipientKeypair {
    /// Generate a fresh ephemeral hybrid keypair (per-attestation in the RCAR flow).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        random_bytes(&mut seed)?;
        let x_secret = XSecret::from(seed);
        seed.zeroize();
        let x_public = XPublic::from(&x_secret).to_bytes();

        let mlkem_dk =
            kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| CryptoError::Backend)?;
        let ek = mlkem_dk
            .encapsulation_key()
            .map_err(|_| CryptoError::Backend)?;
        let mlkem_ek = ek
            .key_bytes()
            .map_err(|_| CryptoError::Backend)?
            .as_ref()
            .to_vec();

        Ok(Self {
            x_secret,
            x_public,
            mlkem_dk,
            mlkem_ek,
        })
    }

    pub fn public(&self) -> RecipientPublic {
        RecipientPublic {
            x25519: self.x_public,
            mlkem_ek: self.mlkem_ek.clone(),
        }
    }

    /// Open a wrapped secret encapsulated to this keypair.
    pub fn open(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>> {
        let env = Envelope::decode(envelope_bytes)?;
        if env.kind != Kind::WrappedKey {
            return Err(CryptoError::Malformed("not a wrapped-key envelope"));
        }
        if env.version != VERSION {
            return Err(CryptoError::UnknownVersion(env.version));
        }
        let _scheme = KemScheme::from_u16(env.scheme)?;

        let mut r = Reader::new(&env.body);
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(r.take(32)?);
        let mlkem_ct = r.lp32()?;
        let nonce_bytes = r.take(NONCE_LEN)?;
        let mut in_out = r.rest().to_vec();

        // Classical half.
        let x_ss = self.x_secret.diffie_hellman(&XPublic::from(eph_pub));
        // PQ half.
        let mlkem_ss = self
            .mlkem_dk
            .decapsulate(mlkem_ct.into())
            .map_err(|_| CryptoError::Backend)?;

        let aead_key = combine(x_ss.as_bytes(), mlkem_ss.as_ref())?;
        let k = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &aead_key).map_err(|_| CryptoError::Key("aead"))?,
        );
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_bytes);
        let pt = k
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(pt.to_vec())
    }
}

/// Encapsulate `secret` to `recipient`. Returns an encoded wrapped-key envelope.
pub fn seal_to(recipient: &RecipientPublic, secret: &[u8]) -> Result<Vec<u8>> {
    // Ephemeral classical key.
    let mut seed = [0u8; 32];
    random_bytes(&mut seed)?;
    let eph_secret = XSecret::from(seed);
    seed.zeroize();
    let eph_public = XPublic::from(&eph_secret).to_bytes();
    let x_ss = eph_secret.diffie_hellman(&XPublic::from(recipient.x25519));

    // PQ encapsulation.
    let ek = kem::EncapsulationKey::new(&kem::ML_KEM_768, &recipient.mlkem_ek)
        .map_err(|_| CryptoError::Key("bad ml-kem ek"))?;
    let (mlkem_ct, mlkem_ss) = ek.encapsulate().map_err(|_| CryptoError::Backend)?;

    let aead_key = combine(x_ss.as_bytes(), mlkem_ss.as_ref())?;
    let k = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &aead_key).map_err(|_| CryptoError::Key("aead"))?,
    );
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_bytes)?;
    let mut in_out = secret.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::empty(),
        &mut in_out,
    )
    .map_err(|_| CryptoError::Backend)?;

    let mut w = Writer::new();
    w.bytes(&eph_public);
    w.lp32(mlkem_ct.as_ref());
    w.bytes(&nonce_bytes);
    w.bytes(&in_out);
    Ok(Envelope::new(
        Kind::WrappedKey,
        KemScheme::X25519MlKem768.as_u16(),
        VERSION,
        w.into_vec(),
    )
    .encode())
}

fn combine(x_ss: &[u8], mlkem_ss: &[u8]) -> Result<Vec<u8>> {
    let mut ikm = Vec::with_capacity(x_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(mlkem_ss);
    let key = hkdf_sha384(&ikm, b"secgit-hybrid-kem-salt", HKDF_INFO, 32);
    ikm.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let recipient = RecipientKeypair::generate().unwrap();
        let pubkey = recipient.public();
        let secret = b"this is a 32-byte KEK..........!";
        let wrapped = seal_to(&pubkey, secret).unwrap();
        let opened = recipient.open(&wrapped).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let r1 = RecipientKeypair::generate().unwrap();
        let r2 = RecipientKeypair::generate().unwrap();
        let wrapped = seal_to(&r1.public(), b"secret").unwrap();
        assert!(r2.open(&wrapped).is_err());
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        let r = RecipientKeypair::generate().unwrap();
        let pb = r.public().to_bytes();
        let p2 = RecipientPublic::from_bytes(&pb).unwrap();
        let wrapped = seal_to(&p2, b"secret").unwrap();
        assert_eq!(r.open(&wrapped).unwrap(), b"secret");
    }
}
