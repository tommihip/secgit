//! Authenticated encryption for bulk data at rest and symmetric key-wrapping.
//!
//! AES-256-GCM and ChaCha20-Poly1305 (both quantum-resistant for confidentiality).
//! All outputs are self-describing envelopes carrying the scheme id, so the open path
//! never has to be told which algorithm was used.

use crate::envelope::{Envelope, Reader, Writer};
use crate::error::{CryptoError, Result};
use crate::ids::{AeadScheme, Kind};
use crate::primitives::random_bytes;
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const VERSION: u8 = 1;

/// A 256-bit symmetric key (a KEK or DEK). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; 32]);

impl SymKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn generate() -> Result<Self> {
        let mut b = [0u8; 32];
        random_bytes(&mut b)?;
        Ok(Self(b))
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymKey(***)")
    }
}

fn unbound(scheme: AeadScheme, key: &[u8; 32]) -> Result<UnboundKey> {
    let alg = match scheme {
        AeadScheme::Aes256Gcm => &AES_256_GCM,
        AeadScheme::ChaCha20Poly1305 => &CHACHA20_POLY1305,
    };
    UnboundKey::new(alg, key).map_err(|_| CryptoError::Key("bad aead key length"))
}

/// Encrypt `plaintext` with `aad` bound in. Returns an encoded envelope.
pub fn seal(scheme: AeadScheme, key: &SymKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let k = LessSafeKey::new(unbound(scheme, key.expose())?);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    k.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::Backend)?;

    let mut w = Writer::new();
    w.bytes(&nonce_bytes);
    w.bytes(&in_out);
    Ok(Envelope::new(Kind::Aead, scheme.as_u16(), VERSION, w.into_vec()).encode())
}

/// Decrypt an envelope produced by [`seal`]. `aad` must match what was sealed.
pub fn open(key: &SymKey, aad: &[u8], envelope_bytes: &[u8]) -> Result<Vec<u8>> {
    let env = Envelope::decode(envelope_bytes)?;
    if env.kind != Kind::Aead {
        return Err(CryptoError::Malformed("not an aead envelope"));
    }
    if env.version != VERSION {
        return Err(CryptoError::UnknownVersion(env.version));
    }
    let scheme = AeadScheme::from_u16(env.scheme)?;
    let k = LessSafeKey::new(unbound(scheme, key.expose())?);

    let mut r = Reader::new(&env.body);
    let nonce_bytes = r.take(NONCE_LEN)?;
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let mut in_out = r.rest().to_vec();

    let plain = k
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(plain.to_vec())
}

/// Wrap a DEK under a KEK (envelope encryption). Convenience over [`seal`] with a
/// domain-separating AAD so wrapped keys can't be confused with bulk data.
pub fn wrap_key(scheme: AeadScheme, kek: &SymKey, dek: &SymKey) -> Result<Vec<u8>> {
    seal(scheme, kek, b"secgit/dek-wrap/v1", dek.expose())
}

/// Unwrap a DEK produced by [`wrap_key`].
pub fn unwrap_key(kek: &SymKey, wrapped: &[u8]) -> Result<SymKey> {
    let pt = open(kek, b"secgit/dek-wrap/v1", wrapped)?;
    if pt.len() != 32 {
        return Err(CryptoError::Key("unwrapped key wrong length"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&pt);
    Ok(SymKey::from_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_both_schemes() {
        for scheme in [AeadScheme::Aes256Gcm, AeadScheme::ChaCha20Poly1305] {
            let key = SymKey::generate().unwrap();
            let ct = seal(scheme, &key, b"aad", b"top secret repo bytes").unwrap();
            let pt = open(&key, b"aad", &ct).unwrap();
            assert_eq!(pt, b"top secret repo bytes");
        }
    }

    #[test]
    fn tamper_is_detected() {
        let key = SymKey::generate().unwrap();
        let mut ct = seal(AeadScheme::Aes256Gcm, &key, b"aad", b"data").unwrap();
        let n = ct.len();
        ct[n - 1] ^= 0x01;
        assert!(matches!(
            open(&key, b"aad", &ct),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = SymKey::generate().unwrap();
        let ct = seal(AeadScheme::Aes256Gcm, &key, b"aad1", b"data").unwrap();
        assert!(open(&key, b"aad2", &ct).is_err());
    }

    #[test]
    fn key_wrap_roundtrip() {
        let kek = SymKey::generate().unwrap();
        let dek = SymKey::generate().unwrap();
        let wrapped = wrap_key(AeadScheme::Aes256Gcm, &kek, &dek).unwrap();
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped.expose(), dek.expose());

        let wrong = SymKey::generate().unwrap();
        assert!(unwrap_key(&wrong, &wrapped).is_err());
    }
}
