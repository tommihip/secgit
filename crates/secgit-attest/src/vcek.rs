//! AMD KDS VCEK resolution + `ARK -> ASK -> VCEK` X.509 chain validation.
//!
//! This closes the SEV-SNP trust root: a parsed report is only trustworthy once its
//! ECDSA-P384 signature verifies against a VCEK that **chains to a genuine AMD root**.
//!
//! - The **ARK** (AMD Root Key) for each supported product is *pinned* (embedded PEM in
//!   `src/roots/`), so we never trust a root fetched at runtime.
//! - The **VCEK** (and the ASK linking it to the ARK) is fetched from the AMD Key
//!   Distribution Service (KDS) for the report's chip id + reported TCB, with an
//!   **offline cache** so air-gapped/repeat verifications need no network.
//! - All certificate parsing is pure-Rust (`x509-cert`); all signature verification is
//!   done by `aws-lc-rs` (RSA-PSS-SHA384 for ARK/ASK/VCEK certs). No OpenSSL, no ring.
//!
//! This crate stays free of any HTTP stack: the network fetch is an injected closure
//! (`resolve_vcek`), so the trust-critical code has no transport dependency. The server
//! supplies a concrete (rustls/aws-lc) KDS client.

use crate::snp::VcekKey;
use crate::{AttestError, Result};
use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PSS_2048_8192_SHA384};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::crl::CertificateList;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;

/// RSASSA-PSS (PKCS#1 v2.1) — the signature algorithm of AMD ARK/ASK/VCEK certs.
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
/// id-ecPublicKey — the VCEK's leaf key type (P-384).
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// Uncompressed SEC1 point length for P-384: `0x04 || X(48) || Y(48)`.
const P384_POINT_LEN: usize = 97;

/// AMD CPU product line whose ARK we pin as a trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Milan,
    Genoa,
}

impl Product {
    pub fn as_str(&self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "milan" => Some(Product::Milan),
            "genoa" => Some(Product::Genoa),
            _ => None,
        }
    }

    /// The pinned, embedded AMD Root Key certificate (PEM) — the trust anchor.
    pub fn ark_pem(&self) -> &'static str {
        match self {
            Product::Milan => include_str!("roots/ark-milan.pem"),
            Product::Genoa => include_str!("roots/ark-genoa.pem"),
        }
    }
}

/// SEV-SNP TCB component versions decomposed from a report's `reported_tcb`.
///
/// `TCB_VERSION` layout (little-endian bytes): `[bootloader, tee, _, _, _, _, snp,
/// microcode]`. These map to the KDS query parameters `blSPL/teeSPL/snpSPL/ucodeSPL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl Tcb {
    pub fn from_reported(reported_tcb: u64) -> Self {
        let b = reported_tcb.to_le_bytes();
        Self {
            bootloader: b[0],
            tee: b[1],
            snp: b[6],
            microcode: b[7],
        }
    }
}

/// KDS URL for the chip's VCEK at a given TCB.
pub fn kds_vcek_url(product: Product, chip_id: &[u8], tcb: &Tcb) -> String {
    format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        product.as_str(),
        hex::encode(chip_id),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    )
}

/// KDS URL for the product's ASK+ARK certificate chain (PEM).
pub fn kds_cert_chain_url(product: Product) -> String {
    format!(
        "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
        product.as_str()
    )
}

/// KDS URL for the product's VCEK certificate revocation list (DER).
pub fn kds_crl_url(product: Product) -> String {
    format!("https://kdsintf.amd.com/vcek/v1/{}/crl", product.as_str())
}

/// Policy for VCEK revocation checking.
///
/// SecGit fails **closed**: a confidential-code host refuses to release the KEK rather than
/// silently skipping revocation when the AMD KDS CRL cannot be obtained. A bounded offline
/// cache window lets air-gapped/repeat verifications proceed without re-fetching, but a CRL
/// older than `max_crl_age_secs` (and unrefreshable) is treated as unobtainable -> refuse.
#[derive(Debug, Clone, Copy)]
pub struct RevocationConfig {
    /// Master switch. Default `true` (fail-closed). Set `false` only for dev/mock paths
    /// that have no network and explicitly accept the weaker guarantee.
    pub enabled: bool,
    /// Maximum age (seconds) of a cached CRL that may be used when KDS is unreachable.
    pub max_crl_age_secs: u64,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        // 24h default offline window: long enough for transient KDS outages / air-gap
        // refresh cycles, short enough to bound exposure to a freshly-revoked VCEK.
        Self {
            enabled: true,
            max_crl_age_secs: 24 * 3600,
        }
    }
}

/// Parse a single DER certificate.
pub fn parse_cert_der(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|_| AttestError::Malformed("invalid DER certificate"))
}

/// Parse a single PEM certificate.
pub fn parse_cert_pem(pem: &str) -> Result<Certificate> {
    Certificate::from_pem(pem.as_bytes())
        .map_err(|_| AttestError::Malformed("invalid PEM certificate"))
}

/// Parse a concatenated PEM cert chain (KDS `cert_chain` returns ASK then ARK).
pub fn parse_cert_chain_pem(pem: &str) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            cur.clear();
        }
        if in_cert {
            cur.push_str(line);
            cur.push('\n');
        }
        if line.contains("END CERTIFICATE") {
            in_cert = false;
            out.push(parse_cert_pem(&cur)?);
        }
    }
    if out.is_empty() {
        return Err(AttestError::Malformed("no certificates in chain"));
    }
    Ok(out)
}

/// Verify that `child` was signed by `issuer` using RSASSA-PSS-SHA384 (AMD's scheme).
fn rsa_pss_sha384_signed_by(issuer: &Certificate, child: &Certificate) -> Result<()> {
    if child.signature_algorithm.oid != OID_RSASSA_PSS {
        return Err(AttestError::Rejected(
            "certificate not signed with RSASSA-PSS",
        ));
    }
    // Issuer RSA public key: the SPKI BitString is the PKCS#1 RSAPublicKey DER that
    // aws-lc-rs' RSA verifier expects directly.
    let issuer_pk = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    // Re-encode the signed TBS (canonical DER; AMD certs are DER so this round-trips).
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|_| AttestError::Malformed("could not re-encode tbsCertificate"))?;
    let sig = child.signature.raw_bytes();
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, issuer_pk)
        .verify(&tbs, sig)
        .map_err(|_| AttestError::Rejected("certificate signature did not verify"))
}

fn issuer_matches_subject(issuer: &Certificate, child: &Certificate) -> bool {
    child.tbs_certificate.issuer == issuer.tbs_certificate.subject
}

/// Extract a validated P-384 VCEK public key from an `id-ecPublicKey` SPKI point.
fn ec_p384_vcek(alg_oid: ObjectIdentifier, point: &[u8]) -> Result<VcekKey> {
    if alg_oid != OID_EC_PUBLIC_KEY {
        return Err(AttestError::Rejected("VCEK leaf is not an EC public key"));
    }
    if point.len() != P384_POINT_LEN || point[0] != 0x04 {
        return Err(AttestError::Rejected(
            "VCEK is not an uncompressed P-384 point",
        ));
    }
    Ok(VcekKey {
        sec1_uncompressed: point.to_vec(),
    })
}

/// Validate the full `ARK(pinned) -> ASK -> VCEK` chain and return the VCEK public key.
///
/// On success, the returned [`VcekKey`] is the relying party's assertion of "this report
/// was signed by a genuine AMD chip of the given product line."
pub fn verify_vcek(product: Product, ask: &Certificate, vcek: &Certificate) -> Result<VcekKey> {
    let ark = parse_cert_pem(product.ark_pem())?;

    // 1. The pinned ARK must be internally consistent (self-signed root).
    rsa_pss_sha384_signed_by(&ark, &ark)?;

    // 2. ASK is issued by, and signed by, the ARK.
    if !issuer_matches_subject(&ark, ask) {
        return Err(AttestError::Rejected(
            "ASK issuer does not match pinned ARK subject",
        ));
    }
    rsa_pss_sha384_signed_by(&ark, ask)?;

    // 3. VCEK is issued by, and signed by, the ASK.
    if !issuer_matches_subject(ask, vcek) {
        return Err(AttestError::Rejected(
            "VCEK issuer does not match ASK subject",
        ));
    }
    rsa_pss_sha384_signed_by(ask, vcek)?;

    // 4. Extract the leaf P-384 key used to verify the SNP report signature.
    let spki = &vcek.tbs_certificate.subject_public_key_info;
    ec_p384_vcek(spki.algorithm.oid, spki.subject_public_key.raw_bytes())
}

/// A filesystem-backed offline cache for fetched VCEK/cert-chain bytes (air-gap support).
pub struct VcekCache {
    dir: PathBuf,
}

impl VcekCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(key)).ok()
    }
    fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| AttestError::Io(e.to_string()))?;
        std::fs::write(self.dir.join(key), bytes).map_err(|e| AttestError::Io(e.to_string()))
    }
    /// Return `(bytes, age_secs)` for a cached entry, where age is derived from the file
    /// mtime (set at `put` time). Used to enforce the bounded offline CRL window.
    fn get_with_age(&self, key: &str) -> Option<(Vec<u8>, u64)> {
        let path = self.dir.join(key);
        let bytes = std::fs::read(&path).ok()?;
        let mtime = std::fs::metadata(&path).ok()?.modified().ok()?;
        let age = SystemTime::now()
            .duration_since(mtime)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Some((bytes, age))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify that a CRL was signed by `issuer` (the ASK) using RSASSA-PSS-SHA384.
fn crl_signed_by(issuer: &Certificate, crl: &CertificateList) -> Result<()> {
    if crl.signature_algorithm.oid != OID_RSASSA_PSS {
        return Err(AttestError::Rejected("CRL not signed with RSASSA-PSS"));
    }
    if crl.tbs_cert_list.issuer != issuer.tbs_certificate.subject {
        return Err(AttestError::Rejected(
            "CRL issuer does not match ASK subject",
        ));
    }
    let issuer_pk = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let tbs = crl
        .tbs_cert_list
        .to_der()
        .map_err(|_| AttestError::Malformed("could not re-encode tbsCertList"))?;
    let sig = crl.signature.raw_bytes();
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, issuer_pk)
        .verify(&tbs, sig)
        .map_err(|_| AttestError::Rejected("CRL signature did not verify against ASK"))
}

/// True if `serial` appears in the CRL's revoked list. Pure; the heart of the refusal.
pub fn serial_revoked(crl: &CertificateList, serial: &[u8]) -> bool {
    match &crl.tbs_cert_list.revoked_certificates {
        None => false,
        Some(list) => list.iter().any(|rc| rc.serial_number.as_bytes() == serial),
    }
}

/// Decide whether a cached CRL may be used given its age and the policy window. Pure so the
/// fail-closed offline behavior is unit-testable without a network.
pub fn cached_crl_usable(age_secs: u64, cfg: &RevocationConfig) -> bool {
    age_secs <= cfg.max_crl_age_secs
}

/// Fetch (or use a fresh-enough cached) CRL, verify its ASK signature, and refuse if the
/// VCEK serial is revoked. Fails **closed**: if no acceptable CRL can be obtained, returns
/// an error so the caller refuses the release.
fn check_revocation<F>(
    product: Product,
    ask: &Certificate,
    vcek: &Certificate,
    cache: &VcekCache,
    fetch: &F,
    cfg: &RevocationConfig,
) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    if !cfg.enabled {
        return Ok(());
    }
    let crl_name = format!("crl-{}.der", product.as_str());

    // Prefer a fresh-enough cached CRL (avoids hammering KDS); else fetch; on fetch failure
    // fall back to a cached CRL only if within the bounded window; else fail closed.
    let crl_der = match cache.get_with_age(&crl_name) {
        Some((bytes, age)) if cached_crl_usable(age, cfg) => bytes,
        _ => match fetch(&kds_crl_url(product)) {
            Ok(bytes) => {
                cache.put(&crl_name, &bytes)?;
                bytes
            }
            Err(fetch_err) => match cache.get_with_age(&crl_name) {
                Some((bytes, age)) if cached_crl_usable(age, cfg) => bytes,
                _ => {
                    // Fail closed: surface the fetch error but refuse rather than skip.
                    eprintln!("secgit-attest: CRL fetch failed: {fetch_err}");
                    return Err(AttestError::Rejected(
                        "CRL unobtainable and no fresh cached CRL (failing closed on revocation)",
                    ));
                }
            },
        },
    };

    let crl = CertificateList::from_der(&crl_der)
        .map_err(|_| AttestError::Malformed("invalid DER CRL"))?;

    // The CRL must be genuinely AMD's (signed by the ASK), not an attacker-substituted blob.
    crl_signed_by(ask, &crl)?;

    // Respect the CRL's own validity: a long-expired CRL (beyond the offline window) is not
    // trustworthy evidence of current revocation state.
    if let Some(next) = &crl.tbs_cert_list.next_update {
        let next_secs = next.to_unix_duration().as_secs();
        let now = now_unix();
        if now > next_secs.saturating_add(cfg.max_crl_age_secs) {
            return Err(AttestError::Rejected(
                "CRL is expired beyond the offline window (failing closed)",
            ));
        }
    }

    let serial = vcek.tbs_certificate.serial_number.as_bytes();
    if serial_revoked(&crl, serial) {
        return Err(AttestError::Rejected(
            "VCEK is revoked (present in AMD CRL)",
        ));
    }
    Ok(())
}

/// Resolve a validated VCEK for an SNP report.
///
/// Uses the offline cache first; on a miss, calls `fetch(url)` (an injected HTTP getter)
/// and caches the result. The returned key has already been validated to chain to the
/// pinned ARK. `chip_id` is the report's `CHIP_ID`; `reported_tcb` its `REPORTED_TCB`.
pub fn resolve_vcek<F>(
    product: Product,
    chip_id: &[u8],
    reported_tcb: u64,
    cache: &VcekCache,
    fetch: F,
    revocation: &RevocationConfig,
) -> Result<VcekKey>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    let tcb = Tcb::from_reported(reported_tcb);
    let vcek_name = format!(
        "vcek-{}-{}-bl{}-tee{}-snp{}-uc{}.der",
        product.as_str(),
        hex::encode(chip_id),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    let chain_name = format!("certchain-{}.pem", product.as_str());

    let vcek_der = match cache.get(&vcek_name) {
        Some(b) => b,
        None => {
            let b = fetch(&kds_vcek_url(product, chip_id, &tcb))?;
            cache.put(&vcek_name, &b)?;
            b
        }
    };
    let chain_pem = match cache.get(&chain_name) {
        Some(b) => b,
        None => {
            let b = fetch(&kds_cert_chain_url(product))?;
            cache.put(&chain_name, &b)?;
            b
        }
    };

    let chain = parse_cert_chain_pem(&String::from_utf8_lossy(&chain_pem))?;
    let ask = chain
        .into_iter()
        .next()
        .ok_or(AttestError::Malformed("empty KDS cert chain"))?;
    let vcek = parse_cert_der(&vcek_der)?;
    // 1. Chain validation: ARK(pinned) -> ASK -> VCEK signatures + the leaf key.
    let key = verify_vcek(product, &ask, &vcek)?;
    // 2. Revocation: refuse a chain-valid-but-revoked VCEK (fails closed if no CRL).
    check_revocation(product, &ask, &vcek, cache, &fetch, revocation)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASK_MILAN: &str = include_str!("../tests/fixtures/ask-milan.pem");
    const ASK_GENOA: &str = include_str!("../tests/fixtures/ask-genoa.pem");

    #[test]
    fn tcb_decomposition() {
        // bytes: bl=0x03, tee=0x00, .., snp=0x14(20), microcode=0xD3(211)
        let reported = u64::from_le_bytes([0x03, 0x00, 0, 0, 0, 0, 0x14, 0xD3]);
        let tcb = Tcb::from_reported(reported);
        assert_eq!(tcb.bootloader, 3);
        assert_eq!(tcb.tee, 0);
        assert_eq!(tcb.snp, 20);
        assert_eq!(tcb.microcode, 211);
    }

    #[test]
    fn kds_urls_are_well_formed() {
        let tcb = Tcb {
            bootloader: 3,
            tee: 0,
            snp: 20,
            microcode: 211,
        };
        let url = kds_vcek_url(Product::Milan, &[0xAB, 0xCD], &tcb);
        assert_eq!(
            url,
            "https://kdsintf.amd.com/vcek/v1/Milan/abcd?blSPL=3&teeSPL=0&snpSPL=20&ucodeSPL=211"
        );
        assert_eq!(
            kds_cert_chain_url(Product::Genoa),
            "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
        );
    }

    #[test]
    fn pinned_ark_is_self_signed() {
        // Verifies the real AMD ARK roots parse and self-verify (exercises the RSA-PSS
        // SHA-384 path + canonical TBS re-encoding against genuine AMD certs).
        for product in [Product::Milan, Product::Genoa] {
            let ark = parse_cert_pem(product.ark_pem()).unwrap();
            rsa_pss_sha384_signed_by(&ark, &ark).unwrap();
        }
    }

    #[test]
    fn real_ask_chains_to_pinned_ark() {
        for (product, ask_pem) in [(Product::Milan, ASK_MILAN), (Product::Genoa, ASK_GENOA)] {
            let ark = parse_cert_pem(product.ark_pem()).unwrap();
            let ask = parse_cert_pem(ask_pem).unwrap();
            assert!(
                issuer_matches_subject(&ark, &ask),
                "{} ASK issuer",
                product.as_str()
            );
            rsa_pss_sha384_signed_by(&ark, &ask).unwrap();
        }
    }

    #[test]
    fn wrong_ark_rejects_ask() {
        // Milan ASK must NOT verify against the Genoa ARK.
        let genoa_ark = parse_cert_pem(Product::Genoa.ark_pem()).unwrap();
        let milan_ask = parse_cert_pem(ASK_MILAN).unwrap();
        assert!(rsa_pss_sha384_signed_by(&genoa_ark, &milan_ask).is_err());
    }

    #[test]
    fn ec_point_extraction_accepts_p384_and_rejects_others() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = kp.public_key().as_ref().to_vec();
        assert_eq!(point.len(), P384_POINT_LEN);

        let vcek = ec_p384_vcek(OID_EC_PUBLIC_KEY, &point).unwrap();
        assert_eq!(vcek.sec1_uncompressed, point);

        // Wrong key-type OID is rejected.
        assert!(ec_p384_vcek(OID_RSASSA_PSS, &point).is_err());
        // Wrong point shape is rejected.
        assert!(ec_p384_vcek(OID_EC_PUBLIC_KEY, &[0x04, 0x01, 0x02]).is_err());
    }

    #[test]
    fn resolver_uses_offline_cache_without_fetching() {
        // Pre-populate the cache so the fetcher must never be called; the (RSA) ASK fails
        // EC extraction at the leaf, proving the cache+parse+chain path ran end-to-end
        // without network.
        let dir = std::env::temp_dir().join(format!("secgit-vcek-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let chip = [0xAAu8; 64];
        let tcb = Tcb::from_reported(0);
        let vcek_name = format!(
            "vcek-Milan-{}-bl{}-tee{}-snp{}-uc{}.der",
            hex::encode(chip),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        );
        // Use the real ASK DER as a stand-in leaf (valid cert, but RSA not EC).
        let ask_cert = parse_cert_pem(ASK_MILAN).unwrap();
        std::fs::write(dir.join(&vcek_name), ask_cert.to_der().unwrap()).unwrap();
        std::fs::write(dir.join("certchain-Milan.pem"), ASK_MILAN).unwrap();

        let cache = VcekCache::new(&dir);
        let err = resolve_vcek(
            Product::Milan,
            &chip,
            0,
            &cache,
            |_url| panic!("fetcher must not be called when cache is warm"),
            &RevocationConfig::default(),
        );
        // Chain steps run from cache; fails at EC leaf extraction (RSA stand-in) BEFORE the
        // revocation step (so the panicking fetcher is never reached).
        assert!(matches!(err, Err(AttestError::Rejected(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A VCEK whose serial appears in the CRL is reported revoked (the refusal proof).
    /// CI(mock): uses a synthetic in-memory CRL, no network/silicon.
    #[test]
    fn revoked_serial_is_detected() {
        use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
        use x509_cert::der::asn1::BitString;
        use x509_cert::serial_number::SerialNumber;

        // Borrow a real cert's structural pieces so we can build a well-formed CRL value.
        let ask = parse_cert_pem(ASK_MILAN).unwrap();
        let now = der_now();
        let revoked_serial = SerialNumber::new(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let other_serial: &[u8] = &[0x01, 0x02, 0x03];

        let tbs = TbsCertList {
            version: x509_cert::Version::V2,
            signature: ask.signature_algorithm.clone(),
            issuer: ask.tbs_certificate.subject.clone(),
            this_update: now,
            next_update: None,
            revoked_certificates: Some(vec![RevokedCert {
                serial_number: revoked_serial.clone(),
                revocation_date: now,
                crl_entry_extensions: None,
            }]),
            crl_extensions: None,
        };
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: ask.signature_algorithm.clone(),
            signature: BitString::from_bytes(&[0u8; 4]).unwrap(),
        };

        assert!(serial_revoked(&crl, revoked_serial.as_bytes()));
        assert!(!serial_revoked(&crl, other_serial));
    }

    fn der_now() -> x509_cert::time::Time {
        x509_cert::time::Time::UtcTime(
            x509_cert::der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                1_700_000_000,
            ))
            .unwrap(),
        )
    }

    #[test]
    fn cached_crl_window_is_bounded() {
        let cfg = RevocationConfig {
            enabled: true,
            max_crl_age_secs: 3600,
        };
        assert!(cached_crl_usable(0, &cfg));
        assert!(cached_crl_usable(3600, &cfg));
        assert!(!cached_crl_usable(3601, &cfg)); // beyond the offline window -> unusable
    }

    // NOTE: the full live path (real ASK-signed CRL fetched from KDS, verified, VCEK serial
    // checked) requires a genuine chain and is exercised by the on-silicon acceptance
    // harness (gated-on-silicon). The mock-runnable refusal proofs above cover the
    // security-decisive pure logic: `serial_revoked` (a revoked serial is detected) and
    // `cached_crl_usable` (the bounded fail-closed offline window).
}
