//! Pluggable authentication: OIDC-first + local accounts in v1.
//!
//! The [`Authenticator`] trait is the abstraction; [`LocalAuthenticator`] implements
//! username/password with PBKDF2-HMAC-SHA256 (via aws-lc-rs). [`OidcVerifier`] is the
//! seam for OIDC providers; SAML/SCIM are deliberately deferred to the enterprise tier.

use crate::IdentityError;
use aws_lc_rs::pbkdf2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU32;

const PBKDF2_ITERATIONS: u32 = 600_000;
const PBKDF2_OUTPUT_LEN: usize = 32;
const SALT_LEN: usize = 16;

/// A stored password verifier (never the password itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHash {
    pub salt_hex: String,
    pub hash_hex: String,
    pub iterations: u32,
}

impl PasswordHash {
    pub fn from_password(password: &str) -> Result<Self, IdentityError> {
        let salt =
            secgit_crypto::primitives::random_vec(SALT_LEN).map_err(|_| IdentityError::Crypto)?;
        let mut out = [0u8; PBKDF2_OUTPUT_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut out,
        );
        Ok(Self {
            salt_hex: hex::encode(salt),
            hash_hex: hex::encode(out),
            iterations: PBKDF2_ITERATIONS,
        })
    }

    pub fn verify(&self, password: &str) -> bool {
        let (Ok(salt), Ok(expected)) = (hex::decode(&self.salt_hex), hex::decode(&self.hash_hex))
        else {
            return false;
        };
        let Some(iters) = NonZeroU32::new(self.iterations) else {
            return false;
        };
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iters,
            &salt,
            password.as_bytes(),
            &expected,
        )
        .is_ok()
    }
}

/// The authentication abstraction. Returns a user id on success.
pub trait Authenticator {
    fn authenticate(&self, username: &str, secret: &str) -> Result<String, IdentityError>;
}

/// Local username/password authenticator backed by stored PBKDF2 verifiers.
#[derive(Default)]
pub struct LocalAuthenticator {
    /// username -> (user_id, password hash)
    creds: HashMap<String, (String, PasswordHash)>,
}

impl LocalAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(
        &mut self,
        username: &str,
        user_id: &str,
        password: &str,
    ) -> Result<(), IdentityError> {
        let ph = PasswordHash::from_password(password)?;
        self.creds
            .insert(username.to_string(), (user_id.to_string(), ph));
        Ok(())
    }
}

impl Authenticator for LocalAuthenticator {
    fn authenticate(&self, username: &str, secret: &str) -> Result<String, IdentityError> {
        let (user_id, ph) = self.creds.get(username).ok_or(IdentityError::AuthFailed)?;
        if ph.verify(secret) {
            Ok(user_id.clone())
        } else {
            Err(IdentityError::AuthFailed)
        }
    }
}

/// Claims extracted from a verified OIDC ID token.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub subject: String,
    pub email: Option<String>,
    pub issuer: String,
}

/// OIDC seam. A production verifier validates the ID token signature against the
/// provider JWKS and checks issuer/audience/expiry, then maps `subject` to a user.
pub trait OidcVerifier {
    fn verify_id_token(&self, id_token: &str) -> Result<OidcClaims, IdentityError>;
}

/// Decode unpadded (or padded) base64url into bytes.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    const INVALID: u8 = 0xFF;
    let mut table = [INVALID; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = table[c as usize];
        if v == INVALID {
            return Err(IdentityError::Serde("invalid base64url".into()));
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// A single RSA JSON Web Key (the fields SecGit uses from a provider JWKS).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: String,
    /// base64url big-endian modulus.
    pub n: String,
    /// base64url big-endian exponent.
    pub e: String,
    #[serde(default)]
    pub alg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksDoc {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: serde_json::Value,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    email: Option<String>,
}

/// A JWKS-backed OIDC ID-token verifier (RS256).
///
/// Following the same transport-agnostic discipline as the SNP VCEK resolver, the JWKS is
/// fetched out-of-band (by the server's minimal HTTPS client) and injected here; this type
/// performs only validation: RS256 signature against the provider's keys, plus
/// issuer/audience/expiry checks. The signature is verified with `aws-lc-rs` (no new crypto
/// stack).
pub struct JwksOidcVerifier {
    issuer: String,
    audience: String,
    keys: HashMap<String, (Vec<u8>, Vec<u8>)>,
    leeway_secs: u64,
}

impl JwksOidcVerifier {
    /// Build a verifier from a provider JWKS JSON document.
    pub fn from_jwks(
        issuer: &str,
        audience: &str,
        jwks_json: &[u8],
    ) -> Result<Self, IdentityError> {
        let doc: JwksDoc =
            serde_json::from_slice(jwks_json).map_err(|e| IdentityError::Serde(e.to_string()))?;
        let mut keys = HashMap::new();
        for k in doc.keys {
            let mut n = b64url_decode(&k.n)?;
            let e = b64url_decode(&k.e)?;
            // RsaPublicKeyComponents require no leading zero byte.
            while n.first() == Some(&0) {
                n.remove(0);
            }
            keys.insert(k.kid, (n, e));
        }
        if keys.is_empty() {
            return Err(IdentityError::Serde("JWKS has no usable keys".into()));
        }
        Ok(Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            keys,
            leeway_secs: 60,
        })
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Verify a token as of `now` (seconds since epoch). Exposed for deterministic tests.
    pub fn verify_at(&self, id_token: &str, now: u64) -> Result<OidcClaims, IdentityError> {
        let mut parts = id_token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(IdentityError::AuthFailed),
        };
        let header: JwtHeader =
            serde_json::from_slice(&b64url_decode(h)?).map_err(|_| IdentityError::AuthFailed)?;
        if header.alg != "RS256" {
            return Err(IdentityError::AuthFailed);
        }
        let kid = header.kid.ok_or(IdentityError::AuthFailed)?;
        let (n, e) = self.keys.get(&kid).ok_or(IdentityError::AuthFailed)?;

        let signing_input = format!("{h}.{p}");
        let sig = b64url_decode(s)?;
        let components = aws_lc_rs::signature::RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        };
        components
            .verify(
                &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &sig,
            )
            .map_err(|_| IdentityError::AuthFailed)?;

        let claims: JwtClaims =
            serde_json::from_slice(&b64url_decode(p)?).map_err(|_| IdentityError::AuthFailed)?;
        if claims.iss != self.issuer {
            return Err(IdentityError::AuthFailed);
        }
        if !aud_matches(&claims.aud, &self.audience) {
            return Err(IdentityError::AuthFailed);
        }
        if let Some(exp) = claims.exp {
            if now > exp.saturating_add(self.leeway_secs) {
                return Err(IdentityError::AuthFailed);
            }
        }
        if let Some(nbf) = claims.nbf {
            if nbf > now.saturating_add(self.leeway_secs) {
                return Err(IdentityError::AuthFailed);
            }
        }
        Ok(OidcClaims {
            subject: claims.sub,
            email: claims.email,
            issuer: claims.iss,
        })
    }
}

fn aud_matches(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

impl OidcVerifier for JwksOidcVerifier {
    fn verify_id_token(&self, id_token: &str) -> Result<OidcClaims, IdentityError> {
        self.verify_at(id_token, Self::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies() {
        let ph = PasswordHash::from_password("correct horse battery staple").unwrap();
        assert!(ph.verify("correct horse battery staple"));
        assert!(!ph.verify("wrong"));
    }

    #[test]
    fn local_auth_flow() {
        let mut auth = LocalAuthenticator::new();
        auth.register("alice", "user-1", "s3cret").unwrap();
        assert_eq!(auth.authenticate("alice", "s3cret").unwrap(), "user-1");
        assert!(auth.authenticate("alice", "nope").is_err());
        assert!(auth.authenticate("bob", "s3cret").is_err());
    }

    fn b64url_encode(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let mut n = (chunk[0] as u32) << 16;
            if chunk.len() > 1 {
                n |= (chunk[1] as u32) << 8;
            }
            if chunk.len() > 2 {
                n |= chunk[2] as u32;
            }
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(A[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(A[(n & 63) as usize] as char);
            }
        }
        out
    }

    /// Parse RFC8017 RSAPublicKey DER (SEQUENCE { INTEGER n, INTEGER e }) into (n, e).
    fn parse_rsa_pub_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut p = 0usize;
        assert_eq!(der[p], 0x30);
        p += 1;
        let _seq_len = read_len(der, &mut p);
        assert_eq!(der[p], 0x02);
        p += 1;
        let n_len = read_len(der, &mut p);
        let mut n = der[p..p + n_len].to_vec();
        p += n_len;
        while n.first() == Some(&0) {
            n.remove(0);
        }
        assert_eq!(der[p], 0x02);
        p += 1;
        let e_len = read_len(der, &mut p);
        let e = der[p..p + e_len].to_vec();
        (n, e)
    }
    fn read_len(d: &[u8], p: &mut usize) -> usize {
        let first = d[*p];
        *p += 1;
        if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            let mut len = 0usize;
            for _ in 0..n {
                len = (len << 8) | d[*p] as usize;
                *p += 1;
            }
            len
        }
    }

    #[test]
    fn jwks_oidc_verifier_accepts_valid_and_rejects_tampered() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;

        let kp = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pub_der = kp.public_key().as_ref().to_vec();
        let (n, e) = parse_rsa_pub_der(&pub_der);

        let jwks = format!(
            r#"{{"keys":[{{"kid":"k1","kty":"RSA","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            b64url_encode(&n),
            b64url_encode(&e)
        );
        let verifier =
            JwksOidcVerifier::from_jwks("https://idp.example", "secgit", jwks.as_bytes()).unwrap();

        let header = b64url_encode(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
        let payload = b64url_encode(
            br#"{"iss":"https://idp.example","sub":"user-42","aud":"secgit","exp":4102444800,"email":"u@example"}"#,
        );
        let signing_input = format!("{header}.{payload}");
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        let token = format!("{signing_input}.{}", b64url_encode(&sig));

        let claims = verifier.verify_at(&token, 1_700_000_000).unwrap();
        assert_eq!(claims.subject, "user-42");
        assert_eq!(claims.email.as_deref(), Some("u@example"));

        // Tampered payload -> signature fails.
        let bad = format!(
            "{header}.{}.{}",
            b64url_encode(br#"{"sub":"evil"}"#),
            b64url_encode(&sig)
        );
        assert!(verifier.verify_at(&bad, 1_700_000_000).is_err());

        // Wrong audience.
        let wrong_aud =
            JwksOidcVerifier::from_jwks("https://idp.example", "other", jwks.as_bytes()).unwrap();
        assert!(wrong_aud.verify_at(&token, 1_700_000_000).is_err());

        // Expired (exp far in the past).
        let expired_payload =
            b64url_encode(br#"{"iss":"https://idp.example","sub":"u","aud":"secgit","exp":100}"#);
        let si2 = format!("{header}.{expired_payload}");
        let mut sig2 = vec![0u8; kp.public_modulus_len()];
        kp.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            si2.as_bytes(),
            &mut sig2,
        )
        .unwrap();
        let expired = format!("{si2}.{}", b64url_encode(&sig2));
        assert!(verifier.verify_at(&expired, 1_700_000_000).is_err());
    }
}
