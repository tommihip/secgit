use thiserror::Error;

/// Errors from the crypto-agility layer.
///
/// Intentionally coarse: callers should treat any failure as "do not trust this
/// artifact" rather than branching on cryptographic specifics.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("unsupported or unknown scheme id: {0}")]
    UnknownScheme(u16),
    #[error("unsupported envelope version: {0}")]
    UnknownVersion(u8),
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("authentication failed (tampered ciphertext or wrong key)")]
    AuthFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("key material error: {0}")]
    Key(&'static str),
    #[error("backend crypto error")]
    Backend,
}

pub type Result<T> = core::result::Result<T, CryptoError>;
