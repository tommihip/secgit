//! Software "mock" TEE backend for development and CI.
//!
//! SECURITY: this provides NO confidentiality or integrity guarantees against a real
//! adversary. It exists so the rest of SecGit (key broker, store, forge, verifier) is
//! testable without confidential hardware. A mock report is just a measurement plus a
//! report_data, authenticated with a well-known development key. The vertical slice is
//! always proven on real AMD SEV-SNP silicon; mock is never acceptable in production.

use crate::{
    AttestError, Attester, Backend, Claims, Evidence, Policy, ReportData, Result, Verifier,
};
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};

/// A well-known, intentionally public development key. Its publicness is the point:
/// nobody should ever mistake mock evidence for a real attestation.
const DEV_HMAC_KEY: &[u8] = b"secgit-mock-tee-development-key-DO-NOT-USE-IN-PROD";

/// The fixed launch measurement reported by the mock TEE.
pub const MOCK_MEASUREMENT: [u8; 32] = [0x5e; 32];

#[derive(Serialize, Deserialize)]
struct MockReport {
    measurement: String,
    report_data: String,
    mac: String,
}

fn mac_over(measurement: &[u8], report_data: &[u8; 64]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, DEV_HMAC_KEY);
    let mut msg = Vec::with_capacity(measurement.len() + 64);
    msg.extend_from_slice(measurement);
    msg.extend_from_slice(report_data);
    hmac::sign(&key, &msg).as_ref().to_vec()
}

#[derive(Default)]
pub struct MockAttester {
    measurement: [u8; 32],
}

impl MockAttester {
    pub fn new() -> Self {
        Self {
            measurement: MOCK_MEASUREMENT,
        }
    }
    /// Override the measurement (used in tests to simulate a different image).
    pub fn with_measurement(measurement: [u8; 32]) -> Self {
        Self { measurement }
    }
}

impl Attester for MockAttester {
    fn backend(&self) -> Backend {
        Backend::Mock
    }
    fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence> {
        let report = MockReport {
            measurement: hex::encode(self.measurement),
            report_data: hex::encode(report_data.0),
            mac: hex::encode(mac_over(&self.measurement, &report_data.0)),
        };
        let bytes =
            serde_json::to_vec(&report).map_err(|_| AttestError::Malformed("mock encode"))?;
        Ok(Evidence {
            backend: Backend::Mock,
            report: bytes,
            runtime_pubkey: vec![],
        })
    }
}

#[derive(Default)]
pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Verifier for MockVerifier {
    fn backend(&self) -> Backend {
        Backend::Mock
    }
    fn verify(
        &self,
        evidence: &Evidence,
        expected: &ReportData,
        policy: &Policy,
    ) -> Result<Claims> {
        if evidence.backend != Backend::Mock {
            return Err(AttestError::Malformed("not mock evidence"));
        }
        let report: MockReport = serde_json::from_slice(&evidence.report)
            .map_err(|_| AttestError::Malformed("mock decode"))?;
        let measurement = hex::decode(&report.measurement)
            .map_err(|_| AttestError::Malformed("mock measurement"))?;
        let rd_bytes = hex::decode(&report.report_data)
            .map_err(|_| AttestError::Malformed("mock report_data"))?;
        if rd_bytes.len() != 64 {
            return Err(AttestError::Malformed("mock report_data len"));
        }
        let mut rd = [0u8; 64];
        rd.copy_from_slice(&rd_bytes);
        let mac = hex::decode(&report.mac).map_err(|_| AttestError::Malformed("mock mac"))?;

        // "Signature" check: constant-time HMAC verify.
        let expected_mac = mac_over(&measurement, &rd);
        if !secgit_crypto::primitives::ct_eq(&mac, &expected_mac) {
            return Err(AttestError::Rejected("mock mac mismatch"));
        }
        // Freshness + channel binding.
        if rd != expected.0 {
            return Err(AttestError::ReportDataMismatch);
        }
        // Reproducible-build anchor.
        if policy.require_vendor_root {
            return Err(AttestError::Rejected(
                "mock cannot satisfy vendor-root policy",
            ));
        }
        if !policy.measurement_allowed(&measurement) {
            return Err(AttestError::MeasurementNotAllowed);
        }

        Ok(Claims {
            backend: Backend::Mock,
            measurement,
            report_data: ReportData(rd),
            vendor_verified: false,
            extra: serde_json::json!({ "mock": true }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_attest_verify_roundtrip() {
        let att = MockAttester::new();
        let rd = ReportData::bind(b"nonce", b"tee-pubkey");
        let ev = att.get_evidence(&rd).unwrap();

        let v = MockVerifier::new();
        let claims = v.verify(&ev, &rd, &Policy::dev_permissive()).unwrap();
        assert_eq!(claims.measurement, MOCK_MEASUREMENT.to_vec());
        assert!(!claims.vendor_verified);
    }

    #[test]
    fn freshness_mismatch_rejected() {
        let att = MockAttester::new();
        let ev = att.get_evidence(&ReportData::bind(b"n1", b"pk")).unwrap();
        let v = MockVerifier::new();
        let err = v.verify(
            &ev,
            &ReportData::bind(b"n2", b"pk"),
            &Policy::dev_permissive(),
        );
        assert!(matches!(err, Err(AttestError::ReportDataMismatch)));
    }

    #[test]
    fn vendor_root_policy_rejects_mock() {
        let att = MockAttester::new();
        let rd = ReportData::bind(b"n", b"pk");
        let ev = att.get_evidence(&rd).unwrap();
        let v = MockVerifier::new();
        let policy = Policy {
            allowed_measurements: vec![],
            require_vendor_root: true,
            expected_vmpl: None,
        };
        assert!(v.verify(&ev, &rd, &policy).is_err());
    }

    #[test]
    fn disallowed_measurement_rejected() {
        let att = MockAttester::with_measurement([0xAB; 32]);
        let rd = ReportData::bind(b"n", b"pk");
        let ev = att.get_evidence(&rd).unwrap();
        let v = MockVerifier::new();
        let policy = Policy {
            allowed_measurements: vec![MOCK_MEASUREMENT.to_vec()],
            require_vendor_root: false,
            expected_vmpl: None,
        };
        assert!(matches!(
            v.verify(&ev, &rd, &policy),
            Err(AttestError::MeasurementNotAllowed)
        ));
    }
}
