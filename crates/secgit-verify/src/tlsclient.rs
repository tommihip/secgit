//! A tiny TLS client for the acceptance harness's connection to a live SecGit instance.
//!
//! Unlike `secgit-net` (which authenticates public endpoints against Mozilla roots), this
//! client connects to the in-CVM server whose leaf cert is **self-signed**: its authenticity
//! comes from *attestation*, not web PKI. So the client deliberately accepts any presented
//! certificate, but **captures** the leaf so the harness can compute its SPKI SHA-256 and
//! confirm the attestation `report_data` channel-binds to exactly that cert (acceptance
//! §4a). The security is in that post-hoc binding check, not in the TLS trust decision.
//!
//! This path runs only against an operator-provided `--url`; it is exercised on real silicon
//! (gated-on-silicon), not in CI.

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

/// A capture-and-accept verifier: records the server leaf cert, accepts any chain. Safe
/// here only because authenticity is established afterward via the attestation binding.
#[derive(Debug)]
struct CaptureVerifier {
    captured: Mutex<Option<Vec<u8>>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The result of an HTTPS request to the live instance.
pub struct Fetched {
    pub body: Vec<u8>,
    /// SHA-256 (hex) of the captured leaf cert's SubjectPublicKeyInfo (channel binding).
    pub peer_spki_sha256_hex: String,
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Target> {
    let rest = url
        .strip_prefix("https://")
        .context("acceptance --url must be https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad port")?),
        None => (authority.to_string(), 443u16),
    };
    Ok(Target {
        host,
        port,
        path: path.to_string(),
    })
}

/// Issue one request, returning the response body and the captured peer SPKI fingerprint.
pub fn request(method: &str, url: &str, json_body: Option<&[u8]>) -> Result<Fetched> {
    let t = parse(url)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = Arc::new(CaptureVerifier {
        captured: Mutex::new(None),
        algs: provider.signature_verification_algorithms,
    });
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let server_name = ServerName::try_from(t.host.clone()).context("invalid server name")?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), server_name).context("tls client")?;
    let sock = TcpStream::connect((t.host.as_str(), t.port))
        .with_context(|| format!("connecting to {}:{}", t.host, t.port))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: secgit-verify\r\nAccept: */*\r\nConnection: close\r\n",
        t.path, t.host
    );
    if let Some(b) = json_body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).context("writing request")?;
    if let Some(b) = json_body {
        tls.write_all(b).context("writing body")?;
    }
    tls.flush().ok();

    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw);
    if raw.is_empty() {
        bail!("empty response from {url}");
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let body = raw[split + 4..].to_vec();

    let captured = verifier
        .captured
        .lock()
        .unwrap()
        .clone()
        .context("server presented no certificate")?;
    let peer_spki_sha256_hex = spki_sha256_hex(&captured);

    Ok(Fetched {
        body,
        peer_spki_sha256_hex,
    })
}

/// SHA-256 (hex) of the cert's SubjectPublicKeyInfo. Mirrors `secgit-server::tls` so the
/// harness computes the same fingerprint the server bound into `report_data`.
fn spki_sha256_hex(cert_der: &[u8]) -> String {
    let spki = extract_spki(cert_der).unwrap_or_else(|| cert_der.to_vec());
    hex::encode(secgit_crypto::primitives::sha256(&spki))
}

fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (tbs, _) = der_seq(cert_der)?;
    let (tbs_inner, _) = der_seq(tbs)?;
    let mut rest = tbs_inner;
    if rest.first() == Some(&0xA0) {
        rest = der_skip(rest)?;
    }
    for _ in 0..5 {
        rest = der_skip(rest)?;
    }
    der_element(rest)
}

fn der_seq(b: &[u8]) -> Option<(&[u8], &[u8])> {
    if b.first()? != &0x30 {
        return None;
    }
    let (len, hdr) = der_len(&b[1..])?;
    let start = 1 + hdr;
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((&b[start..end], &b[end..]))
}

fn der_element(b: &[u8]) -> Option<Vec<u8>> {
    if b.is_empty() {
        return None;
    }
    let (len, hdr) = der_len(&b[1..])?;
    let end = 1usize.checked_add(hdr)?.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some(b[..end].to_vec())
}

fn der_skip(b: &[u8]) -> Option<&[u8]> {
    if b.is_empty() {
        return None;
    }
    let (len, hdr) = der_len(&b[1..])?;
    let end = 1usize.checked_add(hdr)?.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some(&b[end..])
}

fn der_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &byte in &b[1..1 + n] {
        len = (len << 8) | byte as usize;
    }
    Some((len, 1 + n))
}
