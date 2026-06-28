//! # secgit-keybroker
//!
//! Attestation-gated key release: the KEK (key-encryption key) is handed to the TEE
//! **only after** its attestation evidence verifies and a resource-release policy
//! passes. This is the heart of the M1 vertical slice.
//!
//! ## Flow (RCAR: Request - Challenge - Attestation - Response)
//! 1. The TEE generates an *ephemeral hybrid (X25519+ML-KEM-768) keypair* and a fresh
//!    nonce, binds `SHA-512(nonce || tee_pubkey)` into the attestation report_data,
//!    and produces [`secgit_attest::Evidence`].
//! 2. It sends `{resource_id, evidence, runtime_pubkey, nonce}` to the broker.
//! 3. The broker verifies the evidence (provider-neutral verifier + measurement
//!    policy), re-derives and checks the report_data binding, looks up the KEK for the
//!    resource, and **encapsulates the KEK to the TEE's ephemeral public key**.
//! 4. Only the attested TEE can open the wrapped KEK.
//!
//! ## Swap boundary
//! [`KeyRelease`] is the trait we build against. [`LocalKeyBroker`] is a complete
//! in-tree implementation (used for the slice and tests). [`trustee::TrusteeKbs`] is
//! the adapter for a self-hosted Confidential Containers Trustee (KBS + Attestation
//! Service, `snp`/`tdx` drivers only — no cloud/vTPM drivers). We own the BYOK/KEK
//! envelope and resource-release policy on top of either.

pub mod replay;
pub mod trustee;

use replay::{ReplayError, ReplayGuard};
use secgit_attest::{Attester, Evidence, Policy, ReportData, Verifier};
use secgit_crypto::aead::SymKey;
use secgit_crypto::kem::{RecipientKeypair, RecipientPublic};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("attestation rejected: {0}")]
    Attestation(#[from] secgit_attest::AttestError),
    #[error("crypto error: {0}")]
    Crypto(#[from] secgit_crypto::CryptoError),
    #[error("unknown resource: {0}")]
    UnknownResource(String),
    #[error("resource-release policy denied access to {0}")]
    PolicyDenied(String),
    #[error("broker backend not configured: {0}")]
    NotConfigured(&'static str),
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("replayed attestation evidence (nonce already used)")]
    Replay,
    #[error("stale attestation evidence (timestamp outside freshness window)")]
    StaleEvidence,
}

pub type Result<T> = core::result::Result<T, BrokerError>;

/// A guest's request for a resource (KEK), carrying its attestation evidence and the
/// ephemeral public key the response must be encapsulated to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub resource_id: String,
    pub evidence: Evidence,
    /// Serialized [`RecipientPublic`] (hybrid KEM public key) — bound into report_data.
    #[serde(with = "hex_vec")]
    pub runtime_pubkey: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub nonce: Vec<u8>,
    /// Guest-chosen unix-second timestamp, bound into the attested `report_data` so the
    /// broker's replay guard can reject stale evidence on a time basis. Defaults to 0 for
    /// requests produced before this field existed (older clients / fixtures).
    #[serde(default)]
    pub timestamp: u64,
}

/// The release-flow `report_data` binding: `SHA-512(nonce ‖ timestamp_le ‖ runtime_pubkey)`.
///
/// Folding the timestamp into the attested binding (rather than sending it alongside) is
/// what lets the replay guard trust it: the operator cannot change the timestamp without
/// the genuine TEE re-attesting. Both guest and broker derive it identically.
pub fn release_report_data(nonce: &[u8], timestamp: u64, runtime_pubkey: &[u8]) -> ReportData {
    let mut bound_nonce = Vec::with_capacity(nonce.len() + 8);
    bound_nonce.extend_from_slice(nonce);
    bound_nonce.extend_from_slice(&timestamp.to_le_bytes());
    ReportData::bind(&bound_nonce, runtime_pubkey)
}

/// The broker's response: the requested secret, encapsulated to the TEE pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResponse {
    #[serde(with = "hex_vec")]
    pub wrapped: Vec<u8>,
}

/// The swap boundary: anything that can release a resource gated on attestation.
pub trait KeyRelease {
    fn release(&self, req: &ReleaseRequest) -> Result<ReleaseResponse>;
}

/// Supplies KEKs by resource id. For BYOK this is backed by a customer KMS/HSM; for
/// demo/personal it's platform/user-managed (e.g. [`InMemoryKekProvider`]).
pub trait KekProvider: Send + Sync {
    fn get_kek(&self, resource_id: &str) -> Option<SymKey>;
}

/// In-memory KEK provider for dev and the personal/demo tier.
#[derive(Default)]
pub struct InMemoryKekProvider {
    keks: std::collections::HashMap<String, SymKey>,
}

impl InMemoryKekProvider {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, resource_id: impl Into<String>, kek: SymKey) {
        self.keks.insert(resource_id.into(), kek);
    }
}

impl KekProvider for InMemoryKekProvider {
    fn get_kek(&self, resource_id: &str) -> Option<SymKey> {
        self.keks.get(resource_id).cloned()
    }
}

/// A complete, in-tree attestation-gated broker.
pub struct LocalKeyBroker {
    verifier: Box<dyn Verifier>,
    policy: Policy,
    keks: Box<dyn KekProvider>,
    /// Optional durable replay/freshness guard. When set, the broker refuses replayed or
    /// stale evidence before releasing the KEK. `None` keeps the in-process/dev path simple.
    replay_guard: Option<ReplayGuard>,
}

impl LocalKeyBroker {
    pub fn new(verifier: Box<dyn Verifier>, policy: Policy, keks: Box<dyn KekProvider>) -> Self {
        Self {
            verifier,
            policy,
            keks,
            replay_guard: None,
        }
    }

    /// Attach a durable replay/freshness guard (recommended for any network-facing release
    /// path and for the adversarial acceptance scenarios).
    pub fn with_replay_guard(mut self, guard: ReplayGuard) -> Self {
        self.replay_guard = Some(guard);
        self
    }
}

impl KeyRelease for LocalKeyBroker {
    fn release(&self, req: &ReleaseRequest) -> Result<ReleaseResponse> {
        // 1. Re-derive the expected channel binding (nonce ‖ timestamp ‖ pubkey) and verify
        //    the evidence. The verifier checks report_data == expected, vendor root, VMPL,
        //    and the measurement against the reproducible-build policy.
        let expected = release_report_data(&req.nonce, req.timestamp, &req.runtime_pubkey);
        let _claims = self
            .verifier
            .verify(&req.evidence, &expected, &self.policy)?;

        // 1b. Replay/freshness: refuse reused nonces and stale (out-of-window) evidence.
        if let Some(guard) = &self.replay_guard {
            match guard.check_and_record(&req.nonce, req.timestamp) {
                Ok(()) => {}
                Err(ReplayError::Replayed) => return Err(BrokerError::Replay),
                Err(ReplayError::Stale) => return Err(BrokerError::StaleEvidence),
            }
        }

        // 2. Resource-release policy: does this KEK exist / is it releasable?
        let kek = self
            .keks
            .get_kek(&req.resource_id)
            .ok_or_else(|| BrokerError::UnknownResource(req.resource_id.clone()))?;

        // 3. Encapsulate the KEK to the attested TEE's ephemeral hybrid public key.
        let recipient = RecipientPublic::from_bytes(&req.runtime_pubkey)
            .map_err(|_| BrokerError::Malformed("bad runtime_pubkey"))?;
        let wrapped = secgit_crypto::kem::seal_to(&recipient, kek.expose())?;
        Ok(ReleaseResponse { wrapped })
    }
}

/// Guest-side helper: run the full attest-and-unwrap flow in one call.
///
/// Generates the ephemeral hybrid keypair, binds the channel, attests, asks the broker
/// to release the resource, and unwraps the KEK — which then lives only in TEE memory.
pub fn attest_and_unwrap(
    resource_id: &str,
    attester: &dyn Attester,
    broker: &dyn KeyRelease,
) -> Result<SymKey> {
    let kp = RecipientKeypair::generate()?;
    let runtime_pubkey = kp.public().to_bytes();
    let nonce = secgit_crypto::primitives::random_vec(32)?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Bind nonce + timestamp + pubkey into the attested report_data so the broker can
    // both channel-bind the KEM seal AND enforce replay/freshness on the timestamp.
    let report_data = release_report_data(&nonce, timestamp, &runtime_pubkey);
    let evidence = attester.get_evidence(&report_data)?;

    let req = ReleaseRequest {
        resource_id: resource_id.to_string(),
        evidence,
        runtime_pubkey,
        nonce,
        timestamp,
    };
    let resp = broker.release(&req)?;

    let kek_bytes = kp.open(&resp.wrapped)?;
    if kek_bytes.len() != 32 {
        return Err(BrokerError::Malformed("released KEK wrong length"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&kek_bytes);
    Ok(SymKey::from_bytes(b))
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

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_attest::mock::{MockAttester, MockVerifier};

    fn broker_with_kek(resource: &str, kek: SymKey) -> LocalKeyBroker {
        let mut provider = InMemoryKekProvider::new();
        provider.insert(resource, kek);
        LocalKeyBroker::new(
            Box::new(MockVerifier::new()),
            Policy::dev_permissive(),
            Box::new(provider),
        )
    }

    #[test]
    fn end_to_end_attested_kek_release() {
        let kek = SymKey::generate().unwrap();
        let expected = kek.expose().to_vec();
        let broker = broker_with_kek("org/acme/kek", kek);

        let attester = MockAttester::new();
        let released = attest_and_unwrap("org/acme/kek", &attester, &broker).unwrap();
        assert_eq!(released.expose().to_vec(), expected);
    }

    #[test]
    fn unknown_resource_is_denied() {
        let broker = broker_with_kek("org/acme/kek", SymKey::generate().unwrap());
        let attester = MockAttester::new();
        let err = attest_and_unwrap("org/other/kek", &attester, &broker);
        assert!(matches!(err, Err(BrokerError::UnknownResource(_))));
    }

    #[test]
    fn tampered_runtime_pubkey_breaks_binding() {
        // A man-in-the-middle who swaps the runtime pubkey can't get a usable KEK:
        // the report_data binding (and thus the verifier) will reject it.
        let kek = SymKey::generate().unwrap();
        let broker = broker_with_kek("r", kek);

        let kp = RecipientKeypair::generate().unwrap();
        let nonce = secgit_crypto::primitives::random_vec(32).unwrap();
        let ts = 1_700_000_000u64;
        let rd = release_report_data(&nonce, ts, &kp.public().to_bytes());
        let evidence = MockAttester::new().get_evidence(&rd).unwrap();

        // Attacker substitutes their own pubkey in the request.
        let attacker = RecipientKeypair::generate().unwrap();
        let req = ReleaseRequest {
            resource_id: "r".into(),
            evidence,
            runtime_pubkey: attacker.public().to_bytes(),
            nonce,
            timestamp: ts,
        };
        assert!(broker.release(&req).is_err());
    }

    fn guarded_broker(resource: &str, kek: SymKey, guard_path: &std::path::Path) -> LocalKeyBroker {
        let mut provider = InMemoryKekProvider::new();
        provider.insert(resource, kek);
        LocalKeyBroker::new(
            Box::new(MockVerifier::new()),
            Policy::dev_permissive(),
            Box::new(provider),
        )
        .with_replay_guard(ReplayGuard::open(guard_path, 300).unwrap())
    }

    /// A replayed release request (same nonce) is refused by a guarded broker.
    /// CI(mock).
    #[test]
    fn replayed_release_is_refused() {
        let dir = std::env::temp_dir().join(format!("secgit-kb-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let guard_path = dir.join("replay.json");

        let kek = SymKey::generate().unwrap();
        let broker = guarded_broker("r", kek, &guard_path);

        let kp = RecipientKeypair::generate().unwrap();
        let runtime_pubkey = kp.public().to_bytes();
        let nonce = secgit_crypto::primitives::random_vec(32).unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let rd = release_report_data(&nonce, ts, &runtime_pubkey);
        let evidence = MockAttester::new().get_evidence(&rd).unwrap();
        let req = ReleaseRequest {
            resource_id: "r".into(),
            evidence,
            runtime_pubkey,
            nonce,
            timestamp: ts,
        };

        // First use succeeds, exact replay is refused.
        assert!(broker.release(&req).is_ok());
        assert!(matches!(broker.release(&req), Err(BrokerError::Replay)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stale evidence (old attested timestamp) is refused by a guarded broker.
    /// CI(mock).
    #[test]
    fn stale_release_is_refused() {
        let dir = std::env::temp_dir().join(format!("secgit-kb-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let guard_path = dir.join("replay.json");

        let kek = SymKey::generate().unwrap();
        let broker = guarded_broker("r", kek, &guard_path);

        let kp = RecipientKeypair::generate().unwrap();
        let runtime_pubkey = kp.public().to_bytes();
        let nonce = secgit_crypto::primitives::random_vec(32).unwrap();
        // Timestamp 10 minutes in the past (> 300s ttl) -> stale.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = now - 600;
        let rd = release_report_data(&nonce, ts, &runtime_pubkey);
        let evidence = MockAttester::new().get_evidence(&rd).unwrap();
        let req = ReleaseRequest {
            resource_id: "r".into(),
            evidence,
            runtime_pubkey,
            nonce,
            timestamp: ts,
        };
        assert!(matches!(
            broker.release(&req),
            Err(BrokerError::StaleEvidence)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
