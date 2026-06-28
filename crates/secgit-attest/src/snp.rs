//! AMD SEV-SNP backend — provider-neutral.
//!
//! Guest evidence is obtained through the cross-vendor Linux `configfs-tsm` interface
//! (`/sys/kernel/config/tsm/report`, kernel 6.7+), NOT through any cloud metadata
//! service or vTPM. The verifier parses the SNP attestation report and verifies its
//! ECDSA-P384 signature against the chip's VCEK.
//!
//! ## Trust chain
//! `AMD Root Key (ARK) -> AMD SEV Key (ASK) -> VCEK -> report`. The ARK is pinned
//! (embedded) and the VCEK is fetched from the AMD Key Distribution Service (KDS) for
//! the chip id + reported TCB in the report (offline cache for air-gapped installs).
//!
//! This module implements report parsing and the report-signature verification (the
//! cryptographic heart). The `ARK->ASK->VCEK` X.509 chain validation that produces a
//! trusted [`VcekKey`] lives in [`crate::vcek`] (pinned ARK + KDS fetch with offline
//! cache). Construct an [`SnpVerifier`] with a chain-validated VCEK so `vendor_verified`
//! is meaningful.

use crate::{
    AttestError, Attester, Backend, Claims, Evidence, Policy, ReportData, Result, Verifier,
};
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED};

/// Linux `configfs-tsm` report interface. The guest-side report fetch is a Linux/AMD-only
/// path (see [`SnpAttester`]); non-Linux targets compile a stub instead.
#[cfg(target_os = "linux")]
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

// Field offsets into the SNP attestation report (ABI spec, Table 23).
const OFF_VERSION: usize = 0x000;
/// VMPL the report was generated at (u32, little-endian). SecGit expects VMPL0.
const OFF_VMPL: usize = 0x030;
const OFF_REPORT_DATA: usize = 0x050;
const OFF_MEASUREMENT: usize = 0x090;
const OFF_HOST_DATA: usize = 0x0C0;
const OFF_REPORTED_TCB: usize = 0x180;
const OFF_CHIP_ID: usize = 0x1A0;
const OFF_SIGNATURE: usize = 0x2A0;
const SIG_FIELD_LEN: usize = 512;
const REPORT_MIN_LEN: usize = OFF_SIGNATURE + SIG_FIELD_LEN;
/// Size of one ECDSA component field in the SNP signature (little-endian, padded).
const SNP_SIG_COMPONENT: usize = 72;
/// Bytes actually significant for a P-384 component.
const P384_COMPONENT: usize = 48;

/// Parsed view over the security-relevant fields of an SNP report.
#[derive(Debug, Clone)]
pub struct SnpReport {
    pub version: u32,
    /// The VMPL the report was generated at. A genuine in-CVM report is VMPL0.
    pub vmpl: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub reported_tcb: u64,
    pub chip_id: [u8; 64],
    /// The bytes covered by the signature (`[0, OFF_SIGNATURE)`).
    pub signed_data: Vec<u8>,
    /// ECDSA r||s in big-endian, 96 bytes (converted from SNP little-endian layout).
    pub signature_be: [u8; 96],
}

pub fn parse_report(bytes: &[u8]) -> Result<SnpReport> {
    if bytes.len() < REPORT_MIN_LEN {
        return Err(AttestError::Malformed("snp report too short"));
    }
    let rd32 = |off: usize| -> u32 {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let rd64 = |off: usize| -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[off..off + 8]);
        u64::from_le_bytes(a)
    };

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&bytes[OFF_REPORT_DATA..OFF_REPORT_DATA + 64]);
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&bytes[OFF_MEASUREMENT..OFF_MEASUREMENT + 48]);
    let mut host_data = [0u8; 32];
    host_data.copy_from_slice(&bytes[OFF_HOST_DATA..OFF_HOST_DATA + 32]);
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(&bytes[OFF_CHIP_ID..OFF_CHIP_ID + 64]);

    // Convert the SNP little-endian r/s fields to big-endian for aws-lc-rs.
    let sig = &bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIG_FIELD_LEN];
    let r_be = le_field_to_be(&sig[0..SNP_SIG_COMPONENT]);
    let s_be = le_field_to_be(&sig[SNP_SIG_COMPONENT..2 * SNP_SIG_COMPONENT]);
    let mut signature_be = [0u8; 96];
    signature_be[..P384_COMPONENT].copy_from_slice(&r_be);
    signature_be[P384_COMPONENT..].copy_from_slice(&s_be);

    Ok(SnpReport {
        version: rd32(OFF_VERSION),
        vmpl: rd32(OFF_VMPL),
        report_data,
        measurement,
        host_data,
        reported_tcb: rd64(OFF_REPORTED_TCB),
        chip_id,
        signed_data: bytes[0..OFF_SIGNATURE].to_vec(),
        signature_be,
    })
}

/// Take the first `P384_COMPONENT` bytes of a little-endian SNP signature field and
/// return them big-endian.
fn le_field_to_be(field: &[u8]) -> [u8; P384_COMPONENT] {
    let mut out = [0u8; P384_COMPONENT];
    for i in 0..P384_COMPONENT {
        out[i] = field[P384_COMPONENT - 1 - i];
    }
    out
}

/// Inverse of [`le_field_to_be`] (used to assemble test reports).
#[cfg(test)]
fn be_to_le_field(be: &[u8; P384_COMPONENT]) -> [u8; SNP_SIG_COMPONENT] {
    let mut out = [0u8; SNP_SIG_COMPONENT];
    for i in 0..P384_COMPONENT {
        out[i] = be[P384_COMPONENT - 1 - i];
    }
    out
}

/// A VCEK public key that has been validated to chain to the pinned AMD roots.
///
/// Construct this only after verifying the ARK->ASK->VCEK X.509 chain (the KDS fetch /
/// offline-cache step). Holding one is the verifier's assertion of "genuine AMD chip".
#[derive(Clone)]
pub struct VcekKey {
    /// Uncompressed SEC1 point: `0x04 || X(48) || Y(48)` (97 bytes).
    pub sec1_uncompressed: Vec<u8>,
}

/// Verify an SNP report's signature against a VCEK public key.
pub fn verify_report_signature(report: &SnpReport, vcek: &VcekKey) -> bool {
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &vcek.sec1_uncompressed)
        .verify(&report.signed_data, &report.signature_be)
        .is_ok()
}

/// Guest-side SNP attester using `configfs-tsm`.
pub struct SnpAttester {
    /// Echoed into produced [`Evidence`]; only read on the Linux fetch path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    runtime_pubkey: Vec<u8>,
}

impl Default for SnpAttester {
    fn default() -> Self {
        Self::new()
    }
}

impl SnpAttester {
    pub fn new() -> Self {
        Self {
            runtime_pubkey: vec![],
        }
    }
    pub fn with_runtime_pubkey(pubkey: Vec<u8>) -> Self {
        Self {
            runtime_pubkey: pubkey,
        }
    }
    /// True if this host exposes the `configfs-tsm` report interface.
    ///
    /// The genuine guest-side report fetch is a Linux/AMD path; on non-Linux targets this
    /// is always `false`, so [`crate::detect_attester`] falls back to the mock backend.
    #[cfg(target_os = "linux")]
    pub fn available() -> bool {
        std::path::Path::new(TSM_REPORT_DIR).exists()
    }

    /// Non-Linux stub: SEV-SNP guest attestation requires the Linux `configfs-tsm`
    /// interface, so no real attester is available here.
    #[cfg(not(target_os = "linux"))]
    pub fn available() -> bool {
        false
    }
}

impl Attester for SnpAttester {
    fn backend(&self) -> Backend {
        Backend::SevSnp
    }

    /// Linux/AMD path: fetch a genuine SNP report via `configfs-tsm`. This code is the
    /// real trust-critical guest-side fetch and is unchanged across this platform split.
    #[cfg(target_os = "linux")]
    fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence> {
        if !Self::available() {
            return Err(AttestError::Unavailable(
                "configfs-tsm not present (need SEV-SNP guest, kernel 6.7+)".into(),
            ));
        }
        // Create a unique report entry, write the challenge, read back the report.
        let unique = format!(
            "secgit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = format!("{TSM_REPORT_DIR}/{unique}");
        std::fs::create_dir(&dir).map_err(|e| AttestError::Io(e.to_string()))?;
        let cleanup = || {
            let _ = std::fs::remove_dir(&dir);
        };
        if let Err(e) = std::fs::write(format!("{dir}/inblob"), report_data.0) {
            cleanup();
            return Err(AttestError::Io(e.to_string()));
        }
        let outblob = match std::fs::read(format!("{dir}/outblob")) {
            Ok(b) => b,
            Err(e) => {
                cleanup();
                return Err(AttestError::Io(e.to_string()));
            }
        };
        cleanup();
        Ok(Evidence {
            backend: Backend::SevSnp,
            report: outblob,
            runtime_pubkey: self.runtime_pubkey.clone(),
        })
    }

    /// Non-Linux stub: there is no `configfs-tsm` here, so no genuine evidence can be
    /// produced. Callers fall back to the mock backend via [`crate::detect_attester`].
    #[cfg(not(target_os = "linux"))]
    fn get_evidence(&self, _report_data: &ReportData) -> Result<Evidence> {
        Err(AttestError::Unavailable(format!(
            "SEV-SNP attestation requires Linux/AMD x86 (configfs-tsm); this is {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
        )))
    }
}

/// Resolves a chain-validated VCEK for a report's `(chip_id, reported_tcb)`.
///
/// Implemented by the caller (e.g. the server, which fetches from AMD KDS and validates
/// via [`crate::vcek`]) so this crate needs no HTTP stack. Returns a [`VcekKey`] only if
/// the chip's cert chained to the pinned AMD root.
pub type VcekResolver = dyn Fn(&[u8], u64) -> Result<VcekKey> + Send + Sync;

/// Relying-party SNP verifier.
///
/// In production, construct with either a pre-resolved VCEK ([`Self::with_vcek`]) or a
/// resolver ([`Self::with_resolver`]) that fetches+validates the chip's VCEK from the
/// report at verify time. Without either, the verifier can parse and check
/// report_data/measurement but cannot assert genuineness (and is rejected under a
/// `require_vendor_root` policy).
#[derive(Default)]
pub struct SnpVerifier {
    vcek: Option<VcekKey>,
    resolver: Option<Box<VcekResolver>>,
}

impl SnpVerifier {
    pub fn new() -> Self {
        Self {
            vcek: None,
            resolver: None,
        }
    }
    pub fn with_vcek(vcek: VcekKey) -> Self {
        Self {
            vcek: Some(vcek),
            resolver: None,
        }
    }
    /// Build a verifier that resolves+validates the VCEK from each report's chip id and
    /// reported TCB (the standard flow: the verifier learns the chip from the evidence).
    pub fn with_resolver(
        resolver: impl Fn(&[u8], u64) -> Result<VcekKey> + Send + Sync + 'static,
    ) -> Self {
        Self {
            vcek: None,
            resolver: Some(Box::new(resolver)),
        }
    }
}

impl Verifier for SnpVerifier {
    fn backend(&self) -> Backend {
        Backend::SevSnp
    }
    fn verify(
        &self,
        evidence: &Evidence,
        expected: &ReportData,
        policy: &Policy,
    ) -> Result<Claims> {
        if evidence.backend != Backend::SevSnp {
            return Err(AttestError::Malformed("not snp evidence"));
        }
        let report = parse_report(&evidence.report)?;

        // Channel binding + freshness.
        if report.report_data != expected.0 {
            return Err(AttestError::ReportDataMismatch);
        }

        // Genuineness: VCEK signature over the report. The VCEK is either pre-supplied
        // or resolved (fetched + chain-validated to the pinned AMD root) from the
        // report's chip id and reported TCB.
        let resolved;
        let vcek = match &self.vcek {
            Some(v) => Some(v),
            None => match &self.resolver {
                Some(r) => {
                    resolved = r(&report.chip_id, report.reported_tcb)?;
                    Some(&resolved)
                }
                None => None,
            },
        };
        let vendor_verified = match vcek {
            Some(vcek) => verify_report_signature(&report, vcek),
            None => false,
        };
        if policy.require_vendor_root && !vendor_verified {
            return Err(AttestError::Rejected(
                "report did not verify against a genuine AMD VCEK",
            ));
        }

        // Privilege level: the report must come from the VMPL the policy expects (VMPL0
        // for the in-CVM TEE). A wrong VMPL means a less-privileged context produced it.
        if !policy.vmpl_allowed(report.vmpl) {
            return Err(AttestError::VmplNotAllowed);
        }

        // Reproducible-build anchor.
        if !policy.measurement_allowed(&report.measurement) {
            return Err(AttestError::MeasurementNotAllowed);
        }

        Ok(Claims {
            backend: Backend::SevSnp,
            measurement: report.measurement.to_vec(),
            report_data: ReportData(report.report_data),
            vendor_verified,
            extra: serde_json::json!({
                "snp_version": report.version,
                "vmpl": report.vmpl,
                "reported_tcb": report.reported_tcb,
                "chip_id": hex::encode(report.chip_id),
                "host_data": hex::encode(report.host_data),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

    /// Build a minimally-valid SNP-format report with the given fields and sign it
    /// with a fresh P-384 key, mimicking a genuine VCEK. VMPL defaults to 0.
    fn make_signed_report(report_data: &[u8; 64], measurement: &[u8; 48]) -> (Vec<u8>, VcekKey) {
        make_signed_report_vmpl(report_data, measurement, 0)
    }

    /// Like [`make_signed_report`] but stamps an explicit VMPL (signed-over field).
    fn make_signed_report_vmpl(
        report_data: &[u8; 64],
        measurement: &[u8; 48],
        vmpl: u32,
    ) -> (Vec<u8>, VcekKey) {
        let mut buf = vec![0u8; REPORT_MIN_LEN];
        buf[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&2u32.to_le_bytes());
        buf[OFF_VMPL..OFF_VMPL + 4].copy_from_slice(&vmpl.to_le_bytes());
        buf[OFF_REPORT_DATA..OFF_REPORT_DATA + 64].copy_from_slice(report_data);
        buf[OFF_MEASUREMENT..OFF_MEASUREMENT + 48].copy_from_slice(measurement);

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let vcek = VcekKey {
            sec1_uncompressed: kp.public_key().as_ref().to_vec(),
        };

        let signed = buf[0..OFF_SIGNATURE].to_vec();
        let sig = kp.sign(&rng, &signed).unwrap();
        let sig_be = sig.as_ref(); // r||s big-endian, 96 bytes
        let mut r_be = [0u8; P384_COMPONENT];
        let mut s_be = [0u8; P384_COMPONENT];
        r_be.copy_from_slice(&sig_be[..P384_COMPONENT]);
        s_be.copy_from_slice(&sig_be[P384_COMPONENT..]);
        let r_le = be_to_le_field(&r_be);
        let s_le = be_to_le_field(&s_be);
        buf[OFF_SIGNATURE..OFF_SIGNATURE + SNP_SIG_COMPONENT].copy_from_slice(&r_le);
        buf[OFF_SIGNATURE + SNP_SIG_COMPONENT..OFF_SIGNATURE + 2 * SNP_SIG_COMPONENT]
            .copy_from_slice(&s_le);

        (buf, vcek)
    }

    #[test]
    fn parse_and_verify_signature() {
        let rd = ReportData::bind(b"nonce", b"tee-pubkey");
        let measurement = [0x11u8; 48];
        let (report_bytes, vcek) = make_signed_report(&rd.0, &measurement);

        let parsed = parse_report(&report_bytes).unwrap();
        assert_eq!(parsed.report_data, rd.0);
        assert_eq!(parsed.measurement, measurement);
        assert!(verify_report_signature(&parsed, &vcek));
    }

    #[test]
    fn full_verifier_accepts_genuine_report() {
        let rd = ReportData::bind(b"n", b"pk");
        let measurement = [0x22u8; 48];
        let (report_bytes, vcek) = make_signed_report(&rd.0, &measurement);
        let ev = Evidence {
            backend: Backend::SevSnp,
            report: report_bytes,
            runtime_pubkey: vec![],
        };

        let verifier = SnpVerifier::with_vcek(vcek);
        let policy = Policy {
            allowed_measurements: vec![measurement.to_vec()],
            require_vendor_root: true,
            expected_vmpl: Some(0),
        };
        let claims = verifier.verify(&ev, &rd, &policy).unwrap();
        assert!(claims.vendor_verified);
        assert_eq!(claims.measurement, measurement.to_vec());
    }

    #[test]
    fn verifier_with_resolver_accepts_genuine_report() {
        let rd = ReportData::bind(b"n", b"pk");
        let measurement = [0x55u8; 48];
        let (report_bytes, vcek) = make_signed_report(&rd.0, &measurement);
        let ev = Evidence {
            backend: Backend::SevSnp,
            report: report_bytes,
            runtime_pubkey: vec![],
        };
        // The resolver stands in for KDS fetch + chain validation.
        let verifier = SnpVerifier::with_resolver(move |_chip_id, _tcb| Ok(vcek.clone()));
        let policy = Policy {
            allowed_measurements: vec![measurement.to_vec()],
            require_vendor_root: true,
            expected_vmpl: Some(0),
        };
        let claims = verifier.verify(&ev, &rd, &policy).unwrap();
        assert!(claims.vendor_verified);
    }

    #[test]
    fn tampered_measurement_fails_signature() {
        let rd = ReportData::bind(b"n", b"pk");
        let (mut report_bytes, vcek) = make_signed_report(&rd.0, &[0x33u8; 48]);
        report_bytes[OFF_MEASUREMENT] ^= 0xFF; // tamper after signing
        let parsed = parse_report(&report_bytes).unwrap();
        assert!(!verify_report_signature(&parsed, &vcek));
    }

    #[test]
    fn require_vendor_root_without_vcek_is_rejected() {
        let rd = ReportData::bind(b"n", b"pk");
        let (report_bytes, _vcek) = make_signed_report(&rd.0, &[0x44u8; 48]);
        let ev = Evidence {
            backend: Backend::SevSnp,
            report: report_bytes,
            runtime_pubkey: vec![],
        };
        let verifier = SnpVerifier::new();
        let policy = Policy {
            allowed_measurements: vec![],
            require_vendor_root: true,
            expected_vmpl: None,
        };
        assert!(verifier.verify(&ev, &rd, &policy).is_err());
    }

    /// A report at the expected VMPL passes the VMPL gate; a wrong VMPL is refused.
    /// CI(mock): constructed without real silicon.
    #[test]
    fn wrong_vmpl_is_refused() {
        let rd = ReportData::bind(b"n", b"pk");
        let measurement = [0x66u8; 48];
        // Default make_signed_report writes VMPL0.
        let (report_bytes, vcek) = make_signed_report(&rd.0, &measurement);
        let parsed = parse_report(&report_bytes).unwrap();
        assert_eq!(parsed.vmpl, 0);

        let ev = Evidence {
            backend: Backend::SevSnp,
            report: report_bytes,
            runtime_pubkey: vec![],
        };
        let verifier = SnpVerifier::with_vcek(vcek);

        // VMPL0 expected -> accepted.
        let ok_policy = Policy {
            allowed_measurements: vec![measurement.to_vec()],
            require_vendor_root: true,
            expected_vmpl: Some(0),
        };
        assert!(verifier.verify(&ev, &rd, &ok_policy).is_ok());

        // Expect VMPL2 but the report is VMPL0 -> refused.
        let bad_policy = Policy {
            allowed_measurements: vec![measurement.to_vec()],
            require_vendor_root: true,
            expected_vmpl: Some(2),
        };
        assert!(matches!(
            verifier.verify(&ev, &rd, &bad_policy),
            Err(AttestError::VmplNotAllowed)
        ));
    }

    /// A report whose VMPL field is non-zero is refused when VMPL0 is required.
    /// CI(mock).
    #[test]
    fn nonzero_vmpl_report_refused_when_vmpl0_required() {
        let rd = ReportData::bind(b"n", b"pk");
        let measurement = [0x77u8; 48];
        let (report_bytes, vcek) = make_signed_report_vmpl(&rd.0, &measurement, 2);
        let parsed = parse_report(&report_bytes).unwrap();
        assert_eq!(parsed.vmpl, 2);

        let ev = Evidence {
            backend: Backend::SevSnp,
            report: report_bytes,
            runtime_pubkey: vec![],
        };
        let verifier = SnpVerifier::with_vcek(vcek);
        let policy = Policy {
            allowed_measurements: vec![measurement.to_vec()],
            require_vendor_root: true,
            expected_vmpl: Some(0),
        };
        assert!(matches!(
            verifier.verify(&ev, &rd, &policy),
            Err(AttestError::VmplNotAllowed)
        ));
    }
}
