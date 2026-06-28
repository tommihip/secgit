//! Adapter for a self-hosted Confidential Containers **Trustee** (KBS + Attestation
//! Service).
//!
//! Architecture decision (see `docs/adr/0003-key-hierarchy.md`): we build on Trustee
//! but on our terms —
//!   1. only the **provider-neutral** `snp` / `tdx` verifier drivers are enabled,
//!      never the Azure-vTPM driver;
//!   2. the Attestation Service is **self-hosted**, verifying against CPU-vendor roots
//!      (AMD KDS / Intel DCAP), with no external attestation SaaS;
//!   3. we keep this clean swap boundary ([`KeyRelease`]) and own the BYOK/KEK
//!      envelope and resource-release policy on top.
//!
//! This module owns the **configuration + provider-neutrality guard** ([`TrusteeConfig`])
//! and the [`KeyRelease`] swap boundary. To keep this crate dependency-light (no HTTP/TLS
//! stack, so the provider-neutrality ban-list stays trivially satisfiable), the live
//! HTTPS client that performs the release exchange lives in the server
//! (`secgit-server::kbs::HttpKbsClient`), which reuses [`TrusteeConfig::assert_provider_neutral`]
//! and the shared [`ReleaseRequest`]/[`ReleaseResponse`] JSON. [`TrusteeKbs`] below is the
//! in-crate placeholder for an embedded client and returns `NotConfigured`.

use crate::{KeyRelease, ReleaseRequest, ReleaseResponse, Result};

/// Configuration for talking to a self-hosted Trustee KBS.
#[derive(Debug, Clone)]
pub struct TrusteeConfig {
    /// Base URL of the self-hosted KBS (e.g. `https://kbs.internal:8080`).
    pub kbs_url: String,
    /// Enabled verifier drivers. MUST be provider-neutral (`snp`/`tdx`).
    pub drivers: Vec<String>,
}

impl TrusteeConfig {
    pub fn new(kbs_url: impl Into<String>) -> Self {
        Self {
            kbs_url: kbs_url.into(),
            drivers: vec!["snp".into(), "tdx".into()],
        }
    }
    /// Guard the provider-neutrality invariant at runtime as well as in `deny.toml`.
    pub fn assert_provider_neutral(&self) -> core::result::Result<(), &'static str> {
        for d in &self.drivers {
            if d.contains("az-") || d.contains("vtpm") || d.contains("maa") {
                return Err("cloud-specific attestation driver is forbidden");
            }
        }
        Ok(())
    }
}

/// Trustee KBS-backed key release. The clean swap-in for [`LocalKeyBroker`].
pub struct TrusteeKbs {
    #[allow(dead_code)]
    config: TrusteeConfig,
}

impl TrusteeKbs {
    pub fn new(config: TrusteeConfig) -> core::result::Result<Self, &'static str> {
        config.assert_provider_neutral()?;
        Ok(Self { config })
    }
}

impl KeyRelease for TrusteeKbs {
    fn release(&self, _req: &ReleaseRequest) -> Result<ReleaseResponse> {
        // The live RCAR HTTP exchange against the self-hosted KBS is wired in M1.
        Err(crate::BrokerError::NotConfigured(
            "Trustee KBS HTTP client not wired yet; use LocalKeyBroker for the slice",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cloud_drivers() {
        let mut cfg = TrusteeConfig::new("https://kbs.internal");
        cfg.drivers = vec!["az-snp-vtpm".into()];
        assert!(TrusteeKbs::new(cfg).is_err());
    }

    #[test]
    fn accepts_provider_neutral_drivers() {
        let cfg = TrusteeConfig::new("https://kbs.internal");
        assert!(TrusteeKbs::new(cfg).is_ok());
    }
}
