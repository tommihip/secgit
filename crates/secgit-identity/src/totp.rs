//! TOTP (RFC 6238) for second-factor authentication.
//!
//! HMAC-SHA1, 6 digits, 30-second steps — the de-facto standard understood by every
//! authenticator app. Secrets are generated in the TEE and stored (like all identity
//! material) encrypted at rest via the [`crate::store`] layer; only the shared secret and
//! a small clock-skew window are needed to verify.

use crate::IdentityError;
use aws_lc_rs::hmac;

const DIGITS: u32 = 6;
const STEP_SECS: u64 = 30;
const SECRET_LEN: usize = 20;

/// A TOTP shared secret (raw bytes; base32 for provisioning).
#[derive(Debug, Clone)]
pub struct TotpSecret {
    bytes: Vec<u8>,
}

impl TotpSecret {
    /// Generate a fresh random secret.
    pub fn generate() -> Result<Self, IdentityError> {
        let bytes =
            secgit_crypto::primitives::random_vec(SECRET_LEN).map_err(|_| IdentityError::Crypto)?;
        Ok(Self { bytes })
    }

    /// Reconstruct a secret from raw bytes (e.g. loaded from the encrypted store).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// RFC 4648 base32 (no padding) for `otpauth://` provisioning URIs.
    pub fn base32(&self) -> String {
        base32_encode(&self.bytes)
    }

    /// Build an `otpauth://totp/...` URI for QR provisioning.
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
            self.base32()
        )
    }

    /// Compute the TOTP code at a given unix time.
    pub fn code_at(&self, unix_secs: u64) -> String {
        let counter = unix_secs / STEP_SECS;
        hotp(&self.bytes, counter)
    }

    /// Verify `code` against the current time, allowing +/- `window` steps of clock skew.
    pub fn verify_at(&self, code: &str, unix_secs: u64, window: u64) -> bool {
        let counter = unix_secs / STEP_SECS;
        let lo = counter.saturating_sub(window);
        let hi = counter.saturating_add(window);
        let code_bytes = code.as_bytes();
        for c in lo..=hi {
            let expected = hotp(&self.bytes, c);
            // constant-time compare to avoid leaking digit-by-digit matches.
            if secgit_crypto::primitives::ct_eq(expected.as_bytes(), code_bytes) {
                return true;
            }
        }
        false
    }
}

fn hotp(secret: &[u8], counter: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let digest = tag.as_ref();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let modulo = 10u32.pow(DIGITS);
    format!("{:0width$}", bin % modulo, width = DIGITS as usize)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_test_vector() {
        // RFC 6238 Appendix B uses ASCII secret "12345678901234567890".
        let secret = TotpSecret::from_bytes(b"12345678901234567890".to_vec());
        // T = 59s -> counter 1 -> known 8-digit TOTP 94287082; lower 6 digits = 287082.
        assert_eq!(secret.code_at(59), "287082");
        // T = 1111111109 -> 8-digit 07081804 -> 6 digits 081804.
        assert_eq!(secret.code_at(1_111_111_109), "081804");
    }

    #[test]
    fn verify_accepts_within_window_and_rejects_outside() {
        let secret = TotpSecret::generate().unwrap();
        let now = 1_700_000_000u64;
        let code = secret.code_at(now);
        assert!(secret.verify_at(&code, now, 1));
        // one step earlier still accepted with window 1
        assert!(secret.verify_at(&code, now + STEP_SECS, 1));
        // far away rejected
        assert!(!secret.verify_at(&code, now + 10 * STEP_SECS, 1));
        assert!(!secret.verify_at("000000", now, 1) || secret.code_at(now) == "000000");
    }

    #[test]
    fn provisioning_uri_contains_base32_secret() {
        let secret = TotpSecret::from_bytes(b"12345678901234567890".to_vec());
        let uri = secret.provisioning_uri("SecGit", "alice");
        assert!(uri.starts_with("otpauth://totp/SecGit:alice?secret="));
        assert!(uri.contains(&secret.base32()));
    }
}
