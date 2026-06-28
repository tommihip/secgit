//! Algorithm identifiers for crypto-agility.
//!
//! Every ciphertext, wrapped key, and signature SecGit produces is tagged with a
//! `(kind, scheme, version)` triple so that schemes can be added or retired without
//! breaking on-disk or on-wire formats. Never branch on a concrete algorithm at a
//! call site — go through these ids and the registry.

use crate::error::{CryptoError, Result};

/// What kind of artifact an envelope holds. Lets one decoder route bytes safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Aead = 1,
    WrappedKey = 2,
    Signature = 3,
}

impl Kind {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Kind::Aead,
            2 => Kind::WrappedKey,
            3 => Kind::Signature,
            _ => return Err(CryptoError::Malformed("unknown artifact kind")),
        })
    }
}

/// Authenticated-encryption schemes for bulk data at rest.
///
/// Both are already considered quantum-resistant for confidentiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadScheme {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

/// Key-encapsulation / wrapping schemes for the attestation-gated key-release
/// channel and BYOK transport. Hybrid = classical X25519 + PQ ML-KEM-768.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemScheme {
    /// X25519 + ML-KEM-768, shared secrets combined via HKDF-SHA384.
    X25519MlKem768 = 1,
}

/// Signature schemes. Hybrid = classical Ed25519 + PQ ML-DSA.
///
/// `Ed25519MlDsa65` is the general-purpose scheme (audit entries, commit/build
/// attestations). `LongLived` is reserved for the long-lived transparency log,
/// where SLH-DSA is the eventual target; see `docs/adr/0010-open-subdecisions.md`.
/// It is pluggable precisely so the log scheme can be swapped without a format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SigScheme {
    Ed25519MlDsa65 = 1,
    /// Stronger PQ parameter set used as the placeholder for the long-lived log
    /// until an audited SLH-DSA backend is wired in.
    Ed25519MlDsa87 = 2,
}

macro_rules! u16_enum_conv {
    ($t:ty, $($val:expr => $variant:expr),+ $(,)?) => {
        impl $t {
            pub fn from_u16(v: u16) -> Result<Self> {
                Ok(match v {
                    $(x if x == ($val as u16) => $variant,)+
                    _ => return Err(CryptoError::UnknownScheme(v)),
                })
            }
            pub fn as_u16(self) -> u16 { self as u16 }
        }
    };
}

u16_enum_conv!(AeadScheme,
    AeadScheme::Aes256Gcm => AeadScheme::Aes256Gcm,
    AeadScheme::ChaCha20Poly1305 => AeadScheme::ChaCha20Poly1305,
);
u16_enum_conv!(KemScheme,
    KemScheme::X25519MlKem768 => KemScheme::X25519MlKem768,
);
u16_enum_conv!(SigScheme,
    SigScheme::Ed25519MlDsa65 => SigScheme::Ed25519MlDsa65,
    SigScheme::Ed25519MlDsa87 => SigScheme::Ed25519MlDsa87,
);

/// Current default schemes. Centralised so a policy change is one edit.
pub const DEFAULT_AEAD: AeadScheme = AeadScheme::Aes256Gcm;
pub const DEFAULT_KEM: KemScheme = KemScheme::X25519MlKem768;
pub const DEFAULT_SIG: SigScheme = SigScheme::Ed25519MlDsa65;
pub const LONG_LIVED_SIG: SigScheme = SigScheme::Ed25519MlDsa87;
