//! # secgit-attest
//!
//! Provider-neutral remote attestation. This crate deliberately contains **no
//! cloud-specific** code paths: no Azure vTPM, no MAA/IMDS, no SaaS attestation
//! client (the `deny.toml` ban-list enforces this at the dependency level). Evidence
//! is obtained from the guest via the cross-vendor Linux `configfs-tsm` interface and
//! verified against CPU-vendor roots (AMD KDS / Intel DCAP).
//!
//! ## Abstraction
//! - [`Attester`] — guest side: produce [`Evidence`] binding a [`ReportData`] value.
//! - [`Verifier`] — relying-party side: verify [`Evidence`] and return [`Claims`].
//!
//! Backends implement the same traits so the rest of SecGit is hardware-agnostic:
//! - [`mock`] — deterministic software TEE for dev/CI (NOT secure).
//! - [`snp`] — AMD SEV-SNP via `configfs-tsm`, verified against AMD roots.
//! - [`tdx`] — Intel TDX placeholder behind the same trait (`[VERIFY]`).
//!
//! The vertical slice is proven on real AMD SEV-SNP silicon; `mock` exists only so
//! the rest of the system is testable off-silicon.

pub mod mock;
pub mod snp;
pub mod tdx;
pub mod vcek;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestError {
    #[error("attestation backend unavailable on this host: {0}")]
    Unavailable(String),
    #[error("evidence is malformed: {0}")]
    Malformed(&'static str),
    #[error("evidence failed verification: {0}")]
    Rejected(&'static str),
    #[error("report_data does not match the expected challenge binding")]
    ReportDataMismatch,
    #[error("measurement not in the set of allowed (reproducible-build) values")]
    MeasurementNotAllowed,
    #[error("report VMPL does not match the policy's expected privilege level")]
    VmplNotAllowed,
    #[error("backend not supported yet: {0}")]
    Unsupported(&'static str),
    #[error("io error: {0}")]
    Io(String),
}

pub type Result<T> = core::result::Result<T, AttestError>;

/// Which TEE technology produced the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backend {
    /// Software mock — dev/CI only, provides NO security.
    Mock,
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
}

/// The 64-byte `REPORT_DATA` field carried in a TEE report.
///
/// SecGit binds it to `SHA-512(nonce || tee_pubkey)` so a verifier knows the report
/// is fresh (nonce) and channel-bound (the ephemeral hybrid-KEM public key the broker
/// will encapsulate the KEK to). This is the cryptographic glue of the RCAR flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportData(#[serde(with = "hex_array64")] pub [u8; 64]);

impl ReportData {
    /// Bind a freshness nonce and the TEE's runtime public key into report data.
    pub fn bind(nonce: &[u8], tee_pubkey: &[u8]) -> Self {
        let mut input = Vec::with_capacity(nonce.len() + tee_pubkey.len());
        input.extend_from_slice(nonce);
        input.extend_from_slice(tee_pubkey);
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, &input);
        let mut out = [0u8; 64];
        out.copy_from_slice(d.as_ref());
        Self(out)
    }
    pub fn zeroed() -> Self {
        Self([0u8; 64])
    }
}

/// Opaque, serializable attestation evidence passed from guest to verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub backend: Backend,
    /// The raw TEE report (SNP report bytes, TDX quote, or mock blob).
    #[serde(with = "hex_vec")]
    pub report: Vec<u8>,
    /// The runtime/TEE public key the report_data commits to (for the caller's
    /// convenience; the verifier re-derives and checks the binding).
    #[serde(with = "hex_vec", default)]
    pub runtime_pubkey: Vec<u8>,
}

/// Verified facts extracted from accepted evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub backend: Backend,
    /// The launch measurement (e.g. SNP MEASUREMENT). Compared to reference values.
    #[serde(with = "hex_vec")]
    pub measurement: Vec<u8>,
    pub report_data: ReportData,
    /// True only if the evidence chained to a genuine CPU-vendor root.
    pub vendor_verified: bool,
    /// Free-form, backend-specific TCB/identity facts for policy/audit.
    pub extra: serde_json::Value,
}

/// Reference values + policy a verifier evaluates evidence against.
///
/// `allowed_measurements` are the launch measurements of reproducibly-built images
/// SecGit trusts (this is the "running image == OSS build" anchor, fed by `xtask`/the
/// transparency log). Empty means "accept any" — only valid in dev with `Mock`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allowed_measurements: Vec<Vec<u8>>,
    /// Require the evidence to chain to a genuine vendor root (always true in prod).
    pub require_vendor_root: bool,
    /// The VMPL the report MUST have been generated at (`None` = don't check).
    ///
    /// SecGit runs as the guest at VMPL0 (most privileged), so a genuine in-CVM report
    /// must be VMPL0. A report bearing a different VMPL was produced by a less-privileged
    /// context (e.g. a nested or co-tenant guest level) and must be refused — otherwise a
    /// process that is NOT the measured TEE could supply attestation for the KEK release.
    pub expected_vmpl: Option<u32>,
}

impl Policy {
    pub fn dev_permissive() -> Self {
        Self {
            allowed_measurements: vec![],
            require_vendor_root: false,
            expected_vmpl: None,
        }
    }
    pub fn measurement_allowed(&self, m: &[u8]) -> bool {
        self.allowed_measurements.is_empty()
            || self.allowed_measurements.iter().any(|a| a.as_slice() == m)
    }
    /// True if `vmpl` satisfies the policy (no constraint, or an exact match).
    pub fn vmpl_allowed(&self, vmpl: u32) -> bool {
        self.expected_vmpl.is_none_or(|e| e == vmpl)
    }
}

/// Guest-side: produce evidence binding a challenge.
pub trait Attester {
    fn backend(&self) -> Backend;
    fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence>;
}

/// Relying-party-side: verify evidence and return the facts it proves.
pub trait Verifier {
    fn backend(&self) -> Backend;
    fn verify(&self, evidence: &Evidence, expected: &ReportData, policy: &Policy)
        -> Result<Claims>;
}

/// Auto-detect a usable guest attester (SNP if `configfs-tsm` is present, else Mock).
pub fn detect_attester() -> Box<dyn Attester> {
    if snp::SnpAttester::available() {
        Box::new(snp::SnpAttester::new())
    } else {
        Box::new(mock::MockAttester::new())
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

mod hex_array64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("report_data must be 64 bytes"));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_binding_is_stable_and_sensitive() {
        let a = ReportData::bind(b"nonce", b"pubkey");
        let b = ReportData::bind(b"nonce", b"pubkey");
        let c = ReportData::bind(b"nonce2", b"pubkey");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn evidence_json_roundtrips() {
        let ev = Evidence {
            backend: Backend::Mock,
            report: vec![1, 2, 3],
            runtime_pubkey: vec![4, 5],
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back.report, ev.report);
    }
}
