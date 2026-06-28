//! Self-hosted key-broker (Trustee-style) client, behind the [`KeyRelease`] trait.
//!
//! In production the KEK does not live in this process: the server sends its attestation
//! evidence to a **self-hosted** key broker (a Confidential Containers Trustee with only
//! the provider-neutral `snp`/`tdx` verifier drivers, never a cloud/vTPM driver), which
//! verifies the evidence against CPU-vendor roots and returns the KEK **KEM-sealed to the
//! TEE's ephemeral public key**. Only the attested TEE can open it.
//!
//! This client speaks SecGit's [`ReleaseRequest`]/[`ReleaseResponse`] JSON over HTTPS.
//! Bridging to an existing Trustee deployment's exact RCAR endpoints is a thin adapter on
//! top of this boundary; the trust properties (remote verify + KEM-sealed release) are
//! the same.

use secgit_keybroker::trustee::TrusteeConfig;
use secgit_keybroker::{BrokerError, KeyRelease, ReleaseRequest, ReleaseResponse};

/// HTTPS client for a self-hosted key broker.
pub struct HttpKbsClient {
    release_url: String,
}

impl HttpKbsClient {
    /// Build a client for `base_url`, enforcing the provider-neutrality invariant on the
    /// requested verifier drivers (no Azure vTPM / MAA).
    pub fn new(base_url: &str, drivers: &[String]) -> core::result::Result<Self, &'static str> {
        let cfg = TrusteeConfig {
            kbs_url: base_url.to_string(),
            drivers: drivers.to_vec(),
        };
        cfg.assert_provider_neutral()?;
        Ok(Self {
            release_url: format!("{}/release", base_url.trim_end_matches('/')),
        })
    }
}

impl KeyRelease for HttpKbsClient {
    fn release(&self, req: &ReleaseRequest) -> secgit_keybroker::Result<ReleaseResponse> {
        let body = serde_json::to_vec(req).map_err(|_| BrokerError::Malformed("encode request"))?;
        let resp = secgit_net::https_post_json(&self.release_url, &body).map_err(|e| {
            eprintln!("secgit-server: KBS release call failed: {e}");
            BrokerError::NotConfigured("KBS release request failed")
        })?;
        serde_json::from_slice(&resp).map_err(|_| BrokerError::Malformed("decode KBS response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cloud_drivers() {
        assert!(HttpKbsClient::new("https://kbs.internal", &["az-snp-vtpm".into()]).is_err());
    }

    #[test]
    fn builds_release_url() {
        let c = HttpKbsClient::new("https://kbs.internal:8443/", &["snp".into()]).unwrap();
        assert_eq!(c.release_url, "https://kbs.internal:8443/release");
    }
}
