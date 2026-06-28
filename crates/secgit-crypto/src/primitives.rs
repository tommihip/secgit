//! Thin, dependable wrappers over aws-lc-rs for rng, digest, HKDF.
//!
//! These are the only places that touch the raw backend for hashing/KDF/rng so the
//! rest of the crate stays backend-agnostic.

use crate::error::{CryptoError, Result};
use aws_lc_rs::{digest, hmac, rand::SecureRandom, rand::SystemRandom};

/// Fill `buf` with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    let rng = SystemRandom::new();
    rng.fill(buf).map_err(|_| CryptoError::Backend)
}

pub fn random_vec(len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    random_bytes(&mut v)?;
    Ok(v)
}

/// SHA-256 (used for the audit hash-chain / Merkle tree).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-384 (used inside the hybrid KEM KDF).
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let d = digest::digest(&digest::SHA384, data);
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_ref());
    out
}

/// HKDF-SHA384 (extract-then-expand) implemented over HMAC for API stability.
///
/// Returns `out_len` bytes of derived key material. Used to combine the classical
/// and post-quantum shared secrets of the hybrid KEM into a single AEAD key.
pub fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    // Extract
    let salt_key = hmac::Key::new(hmac::HMAC_SHA384, salt);
    let prk = hmac::sign(&salt_key, ikm);

    // Expand
    let prk_key = hmac::Key::new(hmac::HMAC_SHA384, prk.as_ref());
    let mut out = Vec::with_capacity(out_len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut ctx = Vec::with_capacity(prev.len() + info.len() + 1);
        ctx.extend_from_slice(&prev);
        ctx.extend_from_slice(info);
        ctx.push(counter);
        let t = hmac::sign(&prk_key, &ctx);
        prev = t.as_ref().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.checked_add(1).ok_or(CryptoError::Backend)?;
    }
    out.truncate(out_len);
    Ok(out)
}

/// HMAC-SHA256 (used to sign outbound webhook payloads so receivers can verify
/// authenticity and integrity of delivered events).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Constant-time equality for comparing MACs / hashes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_and_hash() {
        let a = random_vec(32).unwrap();
        let b = random_vec(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(sha256(b"abc").len(), 32);
        assert_eq!(sha384(b"abc").len(), 48);
    }

    #[test]
    fn hkdf_is_deterministic_and_sized() {
        let k1 = hkdf_sha384(b"ikm", b"salt", b"info", 32).unwrap();
        let k2 = hkdf_sha384(b"ikm", b"salt", b"info", 32).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        let k3 = hkdf_sha384(b"ikm", b"salt", b"other", 32).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn hmac_sha256_is_stable_and_keyed() {
        let a = hmac_sha256(b"key", b"payload");
        let b = hmac_sha256(b"key", b"payload");
        assert_eq!(a, b);
        let c = hmac_sha256(b"other", b"payload");
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
