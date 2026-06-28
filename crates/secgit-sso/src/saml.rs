//! SAML 2.0 Web-SSO **Service Provider** assertion verification.
//!
//! This validates an IdP-issued SAML Response (HTTP-POST binding) entirely inside the CVM:
//! XML-DSig signature verification (enveloped, exclusive-c14n, RSA-PKCS1-SHA256, SHA-256
//! digest) against a **pinned IdP certificate**, plus the SAML profile checks (status,
//! issuer, audience, conditions, subject-confirmation recipient/expiry).
//!
//! Supported profile (documented in `docs/sso-saml.md`):
//!
//! - Signature: enveloped, `xml-exc-c14n#`, `rsa-sha256`, digest `sha256`.
//! - Signature placement: on the `<Assertion>` (preferred) or the `<Response>`.
//! - No EncryptedAssertion (rejected), no SAML 1.x, no DTD.
//!
//! The IdP public key is taken from the pinned cert, **not** from the document's KeyInfo,
//! so a forged embedded certificate cannot be trusted.

use crate::xml::{self, Element};
use thiserror::Error;

const C14N_EXCL: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SamlError {
    #[error("xml parse error: {0}")]
    Xml(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("signature invalid: {0}")]
    Signature(String),
    #[error("assertion rejected: {0}")]
    Rejected(String),
    #[error("bad config: {0}")]
    Config(String),
}

pub type Result<T> = core::result::Result<T, SamlError>;

/// Service-provider configuration, including the pinned IdP signing key.
pub struct SamlSp {
    /// Our SP entityID — must equal the assertion's `<Audience>`.
    pub sp_entity_id: String,
    /// Our Assertion Consumer Service URL — must equal SubjectConfirmationData `Recipient`.
    pub acs_url: String,
    /// Expected IdP entityID — must equal the assertion's `<Issuer>`.
    pub idp_entity_id: String,
    /// Pinned IdP RSA public key (modulus, exponent), big-endian, no leading zero.
    idp_rsa: (Vec<u8>, Vec<u8>),
    /// Allowed clock skew in seconds for time-bound conditions.
    pub leeway_secs: i64,
}

/// What a verified assertion tells us about the authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub name_id: String,
    pub issuer: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

impl VerifiedAssertion {
    /// First value of a named attribute (case-sensitive on the SAML attribute Name).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.first())
            .map(|s| s.as_str())
    }
    /// Best-effort email: explicit attributes first, else a NameID that looks like email.
    pub fn email(&self) -> Option<String> {
        for key in [
            "email",
            "mail",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ] {
            if let Some(v) = self.attr(key) {
                return Some(v.to_string());
            }
        }
        if self.name_id.contains('@') {
            return Some(self.name_id.clone());
        }
        None
    }
}

impl SamlSp {
    /// Build an SP, pinning the IdP signing certificate (PEM or DER).
    pub fn new(
        sp_entity_id: &str,
        acs_url: &str,
        idp_entity_id: &str,
        idp_cert: &[u8],
    ) -> Result<Self> {
        let idp_rsa = rsa_pubkey_from_cert(idp_cert)?;
        Ok(Self {
            sp_entity_id: sp_entity_id.to_string(),
            acs_url: acs_url.to_string(),
            idp_entity_id: idp_entity_id.to_string(),
            idp_rsa,
            leeway_secs: 120,
        })
    }

    /// Verify a base64-encoded `SAMLResponse` form field as of `now` (unix seconds).
    pub fn verify_b64_response(&self, b64: &str, now: i64) -> Result<VerifiedAssertion> {
        let xml_bytes = b64decode(b64).ok_or(SamlError::Xml("invalid base64".into()))?;
        let xml_str = String::from_utf8(xml_bytes).map_err(|e| SamlError::Xml(e.to_string()))?;
        self.verify_response_xml(&xml_str, now)
    }

    /// Verify a decoded SAML Response XML document as of `now` (unix seconds).
    pub fn verify_response_xml(&self, xml_str: &str, now: i64) -> Result<VerifiedAssertion> {
        let root = xml::parse(xml_str).map_err(|e| SamlError::Xml(e.0))?;

        if root.find_descendant("EncryptedAssertion").is_some() {
            return Err(SamlError::Unsupported("EncryptedAssertion".into()));
        }

        // Top-level status must be Success.
        if let Some(status) = root.find_descendant("Status") {
            if let Some(code) = status.find_descendant("StatusCode") {
                let v = code.attr("Value").unwrap_or("");
                if !v.ends_with(":status:Success") {
                    return Err(SamlError::Rejected(format!("status not Success: {v}")));
                }
            }
        }

        let assertion = root
            .find_descendant("Assertion")
            .ok_or(SamlError::Rejected("no Assertion".into()))?;

        // Signature must be present and valid, covering either the Assertion or Response.
        self.verify_signature(&root, assertion)?;

        // Issuer.
        let issuer = assertion
            .child("Issuer")
            .map(|e| e.text())
            .unwrap_or_default();
        if issuer != self.idp_entity_id {
            return Err(SamlError::Rejected(format!("issuer mismatch: {issuer}")));
        }

        // Conditions: time window + audience.
        if let Some(cond) = assertion.child("Conditions") {
            if let Some(nb) = cond.attr("NotBefore") {
                let t = parse_instant(nb)?;
                if now + self.leeway_secs < t {
                    return Err(SamlError::Rejected("assertion not yet valid".into()));
                }
            }
            if let Some(na) = cond.attr("NotOnOrAfter") {
                let t = parse_instant(na)?;
                if now - self.leeway_secs >= t {
                    return Err(SamlError::Rejected("assertion expired".into()));
                }
            }
            let mut audience_ok = true;
            if let Some(ar) = cond.find_descendant("AudienceRestriction") {
                audience_ok = ar
                    .children_named("Audience")
                    .any(|a| a.text() == self.sp_entity_id);
            }
            if !audience_ok {
                return Err(SamlError::Rejected("audience mismatch".into()));
            }
        }

        // Subject confirmation: recipient + expiry (when present).
        if let Some(subj) = assertion.child("Subject") {
            if let Some(scd) = subj.find_descendant("SubjectConfirmationData") {
                if let Some(rcpt) = scd.attr("Recipient") {
                    if rcpt != self.acs_url {
                        return Err(SamlError::Rejected("recipient mismatch".into()));
                    }
                }
                if let Some(na) = scd.attr("NotOnOrAfter") {
                    let t = parse_instant(na)?;
                    if now - self.leeway_secs >= t {
                        return Err(SamlError::Rejected("subject confirmation expired".into()));
                    }
                }
            }
        }

        let name_id = assertion
            .child("Subject")
            .and_then(|s| s.find_descendant("NameID"))
            .map(|e| e.text())
            .ok_or(SamlError::Rejected("no NameID".into()))?;

        let attributes = extract_attributes(assertion);

        Ok(VerifiedAssertion {
            name_id,
            issuer,
            attributes,
        })
    }

    /// Locate a valid enveloped signature over `assertion` (preferred) or `root`.
    fn verify_signature(&self, root: &Element, assertion: &Element) -> Result<()> {
        // Find a Signature whose Reference points at the assertion or the response.
        let candidates = [(assertion, assertion.attr("ID")), (root, root.attr("ID"))];
        let mut last_err =
            SamlError::Signature("no signature covering the assertion or response".into());
        for (signed_el, id) in candidates {
            let Some(sig) = direct_signature(signed_el) else {
                continue;
            };
            match self.check_signature(root, signed_el, id, sig) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn check_signature(
        &self,
        root: &Element,
        signed_el: &Element,
        signed_id: Option<&str>,
        sig: &Element,
    ) -> Result<()> {
        let signed_info = sig
            .child("SignedInfo")
            .ok_or(SamlError::Signature("no SignedInfo".into()))?;

        // Algorithm checks.
        let c14n_alg = signed_info
            .child("CanonicalizationMethod")
            .and_then(|e| e.attr("Algorithm"))
            .unwrap_or("");
        if c14n_alg != C14N_EXCL {
            return Err(SamlError::Unsupported(format!("c14n alg: {c14n_alg}")));
        }
        let sig_alg = signed_info
            .child("SignatureMethod")
            .and_then(|e| e.attr("Algorithm"))
            .unwrap_or("");
        if !sig_alg.ends_with("#rsa-sha256") {
            return Err(SamlError::Unsupported(format!("sig alg: {sig_alg}")));
        }

        let reference = signed_info
            .find_descendant("Reference")
            .ok_or(SamlError::Signature("no Reference".into()))?;
        let uri = reference.attr("URI").unwrap_or("");
        let ref_id = uri.strip_prefix('#').unwrap_or(uri);
        if let Some(id) = signed_id {
            if !ref_id.is_empty() && ref_id != id {
                return Err(SamlError::Signature("reference URI does not match".into()));
            }
        }

        // Confirm enveloped transform and pull any InclusiveNamespaces PrefixList.
        let mut saw_enveloped = false;
        let mut ref_incl: Vec<String> = vec![];
        if let Some(transforms) = reference.child("Transforms") {
            for t in transforms.children_named("Transform") {
                let alg = t.attr("Algorithm").unwrap_or("");
                if alg == ENVELOPED {
                    saw_enveloped = true;
                } else if alg == C14N_EXCL {
                    if let Some(inc) = t.find_descendant("InclusiveNamespaces") {
                        ref_incl = prefix_list(inc);
                    }
                }
            }
        }
        if !saw_enveloped {
            return Err(SamlError::Unsupported("missing enveloped transform".into()));
        }

        // 1) Verify the digest over the enveloped, canonicalized signed element.
        let (target, inherited) =
            xml::find_with_scope(root, &|e: &Element| std::ptr::eq(e, signed_el))
                .or_else(|| {
                    // Fall back to matching by ID if pointer identity fails after clones.
                    signed_id.and_then(|sid| {
                        xml::find_with_scope(root, &|e: &Element| e.attr("ID") == Some(sid))
                    })
                })
                .ok_or(SamlError::Signature("signed element not found".into()))?;
        let canon = xml::exc_c14n_enveloped_scoped(target, &ref_incl, &inherited);
        let digest = secgit_crypto::primitives::sha256(&canon);
        let want = reference
            .find_descendant("DigestValue")
            .map(|e| e.text())
            .ok_or(SamlError::Signature("no DigestValue".into()))?;
        let want_bytes = b64decode(&want).ok_or(SamlError::Signature("bad DigestValue".into()))?;
        if want_bytes != digest {
            return Err(SamlError::Signature("digest mismatch".into()));
        }

        // 2) Verify the RSA signature over the canonicalized SignedInfo.
        let (si_el, si_scope) = xml::find_with_scope(sig, &|e: &Element| e.local == "SignedInfo")
            .ok_or(SamlError::Signature("SignedInfo not found".into()))?;
        // The SignedInfo inherits the Signature's namespace context.
        let si_canon = xml::exc_c14n_scoped(si_el, &[], &si_scope);
        let sig_value = sig
            .find_descendant("SignatureValue")
            .map(|e| e.text())
            .ok_or(SamlError::Signature("no SignatureValue".into()))?;
        let sig_bytes =
            b64decode(&sig_value).ok_or(SamlError::Signature("bad SignatureValue".into()))?;

        let comps = aws_lc_rs::signature::RsaPublicKeyComponents {
            n: self.idp_rsa.0.as_slice(),
            e: self.idp_rsa.1.as_slice(),
        };
        comps
            .verify(
                &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                &si_canon,
                &sig_bytes,
            )
            .map_err(|_| SamlError::Signature("RSA verification failed".into()))?;
        Ok(())
    }
}

/// The direct `<Signature>` child of an element (XML-DSig requires the enveloped
/// signature to be a child of the element it signs).
fn direct_signature(el: &Element) -> Option<&Element> {
    el.children.iter().find_map(|n| match n {
        xml::Node::Element(e) if e.local == "Signature" => Some(e),
        _ => None,
    })
}

fn prefix_list(inc: &Element) -> Vec<String> {
    inc.attr("PrefixList")
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

fn extract_attributes(assertion: &Element) -> Vec<(String, Vec<String>)> {
    let mut out = vec![];
    if let Some(stmt) = assertion.find_descendant("AttributeStatement") {
        for attr in stmt.children_named("Attribute") {
            let name = attr
                .attr("Name")
                .or_else(|| attr.attr("FriendlyName"))
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let values: Vec<String> = attr
                .children_named("AttributeValue")
                .map(|v| v.text())
                .collect();
            out.push((name, values));
        }
    }
    out
}

/// Parse an RFC3339/ISO8601 instant (e.g. `2026-06-28T17:00:00Z`) to unix seconds.
/// Supports the `...Z` UTC form SAML IdPs emit; fractional seconds are ignored.
fn parse_instant(s: &str) -> Result<i64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    let bad = || SamlError::Rejected(format!("bad timestamp: {s}"));
    if s.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return Err(bad());
    }
    let num = |a: usize, b: usize| -> Result<i64> { s[a..b].parse::<i64>().map_err(|_| bad()) };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let min = num(14, 16)?;
    let sec = num(17, 19)?;
    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Extract the RSA (modulus, exponent) from an X.509 certificate (PEM or DER).
fn rsa_pubkey_from_cert(cert: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use x509_cert::der::{Decode, DecodePem};
    let cert = if cert.starts_with(b"-----BEGIN") {
        x509_cert::Certificate::from_pem(cert).map_err(|e| SamlError::Config(e.to_string()))?
    } else {
        x509_cert::Certificate::from_der(cert).map_err(|e| SamlError::Config(e.to_string()))?
    };
    let spki = cert.tbs_certificate.subject_public_key_info;
    let key_der = spki
        .subject_public_key
        .as_bytes()
        .ok_or(SamlError::Config("no SPKI bit string".into()))?;
    parse_rsa_public_key(key_der)
}

/// Parse an RFC8017 `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut p = 0usize;
    let bad = || SamlError::Config("malformed RSAPublicKey DER".into());
    if *der.first().ok_or_else(bad)? != 0x30 {
        return Err(bad());
    }
    p += 1;
    let _ = read_der_len(der, &mut p).ok_or_else(bad)?;
    if *der.get(p).ok_or_else(bad)? != 0x02 {
        return Err(bad());
    }
    p += 1;
    let n_len = read_der_len(der, &mut p).ok_or_else(bad)?;
    let mut n = der.get(p..p + n_len).ok_or_else(bad)?.to_vec();
    p += n_len;
    while n.first() == Some(&0) {
        n.remove(0);
    }
    if *der.get(p).ok_or_else(bad)? != 0x02 {
        return Err(bad());
    }
    p += 1;
    let e_len = read_der_len(der, &mut p).ok_or_else(bad)?;
    let e = der.get(p..p + e_len).ok_or_else(bad)?.to_vec();
    Ok((n, e))
}

fn read_der_len(d: &[u8], p: &mut usize) -> Option<usize> {
    let first = *d.get(*p)?;
    *p += 1;
    if first & 0x80 == 0 {
        Some(first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *d.get(*p)? as usize;
            *p += 1;
        }
        Some(len)
    }
}

/// Standard base64 decode (ignores ASCII whitespace; accepts padding).
fn b64decode(s: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    let mut table = [INVALID; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            break;
        }
        let v = table[c as usize];
        if v == INVALID {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

    fn b64encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                A[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn parse_instant_utc() {
        assert_eq!(parse_instant("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_instant("2000-01-01T00:00:00Z").unwrap(), 946684800);
        assert_eq!(parse_instant("2026-06-28T17:00:00Z").unwrap(), 1782666000);
    }

    /// Build a self-signed RSA cert + key, sign a SAML assertion exactly the way an IdP
    /// would (enveloped, exc-c14n, rsa-sha256), and verify the full path round-trips,
    /// while tamper/expiry/audience negatives are rejected.
    #[test]
    fn end_to_end_signed_assertion() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::KeyPair;

        // Pinned IdP RSA cert + its private key (generated offline with OpenSSL; see
        // tests/fixtures). The SP pins the cert; we sign exactly as a real IdP would.
        let cert_pem = include_str!("../tests/fixtures/idp_cert.pem").to_string();
        let key_pkcs8 = include_bytes!("../tests/fixtures/idp_key_pkcs8.der");
        let kp = KeyPair::from_pkcs8(key_pkcs8).unwrap();

        let assertion_id = "_a1";
        // Inner assertion (without signature) — must match what we canonicalize.
        let assertion_body = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="2026-06-28T17:00:00Z"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/acs" NotOnOrAfter="2026-06-28T18:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-06-28T16:00:00Z" NotOnOrAfter="2026-06-28T18:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#
        );

        // Digest the enveloped, canonicalized assertion (no signature present yet).
        let assertion_el = xml::parse(&assertion_body).unwrap();
        let canon = xml::exc_c14n_enveloped(&assertion_el, &[]);
        let digest = secgit_crypto::primitives::sha256(&canon);
        let digest_b64 = b64encode(&digest);

        // Build SignedInfo referencing the assertion, then canonicalize + RSA-sign it.
        let signed_info = format!(
            r##"<ds:SignedInfo xmlns:ds="{SIG_NS}"><ds:CanonicalizationMethod Algorithm="{C14N_EXCL}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{C14N_EXCL}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );
        let si_el = xml::parse(&signed_info).unwrap();
        let si_canon = xml::exc_c14n(&si_el, &[]);
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &si_canon,
            &mut sig,
        )
        .unwrap();
        let sig_b64 = b64encode(&sig);

        // Assemble the full signed assertion (Signature enveloped inside the Assertion).
        let signature = format!(
            r#"<ds:Signature xmlns:ds="{SIG_NS}">{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"#
        );
        let signed_assertion =
            assertion_body.replace("<saml:Subject>", &format!("{signature}<saml:Subject>"));
        let response = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{signed_assertion}</samlp:Response>"#
        );

        let sp = SamlSp::new(
            "https://sp.example",
            "https://sp.example/acs",
            "https://idp.example",
            cert_pem.as_bytes(),
        )
        .unwrap();

        let now = 1782666000; // 2026-06-28T17:00:00Z
        let v = sp.verify_response_xml(&response, now).unwrap();
        assert_eq!(v.name_id, "alice@example.com");
        assert_eq!(v.issuer, "https://idp.example");
        assert_eq!(v.email().as_deref(), Some("alice@example.com"));

        // Tamper: flip the NameID -> digest mismatch.
        let tampered = response.replace("alice@example.com", "evil@example.com");
        assert!(matches!(
            sp.verify_response_xml(&tampered, now),
            Err(SamlError::Signature(_))
        ));

        // Expired (well after NotOnOrAfter 2026-06-28T18:00:00Z = 1782669600).
        assert!(matches!(
            sp.verify_response_xml(&response, 1782700000),
            Err(SamlError::Rejected(_))
        ));

        // Wrong audience.
        let sp_wrong = SamlSp::new(
            "https://other.example",
            "https://sp.example/acs",
            "https://idp.example",
            cert_pem.as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            sp_wrong.verify_response_xml(&response, now),
            Err(SamlError::Rejected(_))
        ));

        // Wrong pinned key (a different RSA cert) -> RSA verification fails.
        let other_cert = include_str!("../tests/fixtures/idp_cert_other.pem");
        let sp_badkey = SamlSp::new(
            "https://sp.example",
            "https://sp.example/acs",
            "https://idp.example",
            other_cert.as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            sp_badkey.verify_response_xml(&response, now),
            Err(SamlError::Signature(_))
        ));
    }
}
