//! Intel TDX backend — placeholder behind the same provider-neutral abstraction.
//!
//! `[VERIFY]` TDX support is intentionally a trait-conforming stub for now: the
//! design commits to "TDX behind the same `Attester`/`Verifier` traits as SEV-SNP",
//! and the cross-vendor `configfs-tsm` interface already yields TDX quotes
//! (`tdx_guest` provider). Full verification requires parsing the TD quote and
//! validating the Intel DCAP cert chain (PCK -> Intel SGX Root CA) against pinned
//! Intel roots — the analogue of the SNP VCEK path — which is tracked as follow-on
//! work. Keeping the stub here proves the abstraction is real and lock-in-free.

use crate::{
    AttestError, Attester, Backend, Claims, Evidence, Policy, ReportData, Result, Verifier,
};

/// Linux `configfs-tsm` report interface (TDX uses the `tdx_guest` provider). Guest-side
/// quote retrieval is Linux-only; non-Linux targets compile a stub instead.
#[cfg(target_os = "linux")]
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

pub struct TdxAttester;

impl TdxAttester {
    pub fn new() -> Self {
        Self
    }
    /// True if this host exposes the `configfs-tsm` report interface (Linux only).
    #[cfg(target_os = "linux")]
    pub fn available() -> bool {
        // Same cross-vendor interface as SNP; provider would read "tdx_guest".
        std::path::Path::new(TSM_REPORT_DIR).exists()
    }

    /// Non-Linux stub: TDX guest attestation requires the Linux `configfs-tsm` interface.
    #[cfg(not(target_os = "linux"))]
    pub fn available() -> bool {
        false
    }
}

impl Default for TdxAttester {
    fn default() -> Self {
        Self::new()
    }
}

impl Attester for TdxAttester {
    fn backend(&self) -> Backend {
        Backend::Tdx
    }
    fn get_evidence(&self, _report_data: &ReportData) -> Result<Evidence> {
        Err(AttestError::Unsupported(
            "TDX quote retrieval not implemented yet (configfs-tsm tdx_guest)",
        ))
    }
}

#[derive(Default)]
pub struct TdxVerifier;

impl TdxVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Verifier for TdxVerifier {
    fn backend(&self) -> Backend {
        Backend::Tdx
    }
    fn verify(&self, _e: &Evidence, _expected: &ReportData, _policy: &Policy) -> Result<Claims> {
        Err(AttestError::Unsupported(
            "TDX quote verification (DCAP cert chain) not implemented yet",
        ))
    }
}
