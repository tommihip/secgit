//! In-CVM PQC-TLS termination.
//!
//! TLS is terminated **inside** the confidential VM by this process — NOT at an upstream
//! reverse proxy — so there is no operator-visible plaintext hop between a proxy and the
//! TEE (that would defeat provider-blindness; see `docs/adr/0007-deployment.md`).
//!
//! Key exchange uses rustls' default aws-lc-rs provider with `prefer-post-quantum`, which
//! makes the hybrid `X25519MLKEM768` group highest priority — post-quantum transport that
//! resists harvest-now-decrypt-later.
//!
//! ## Trust model for the certificate
//! The server's authenticity is established by **remote attestation**, not web PKI: the
//! SHA-256 of the cert's SubjectPublicKeyInfo is bound into the attestation `report_data`
//! (`secgit-attest`), so a client that runs `secgit-verify` confirms it is talking TLS to
//! the exact attested TEE. A self-signed leaf is therefore the correct default; an
//! operator-supplied cert (`SECGIT_TLS_CERT`/`SECGIT_TLS_KEY`) is also supported.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::Arc;

/// A ready-to-serve TLS config plus the SPKI fingerprint a client pins via attestation.
pub struct TlsMaterial {
    pub config: Arc<ServerConfig>,
    /// SHA-256 of the certificate's SubjectPublicKeyInfo (hex). Bound into the SNP/mock
    /// attestation `report_data` so the attested channel is the TLS channel.
    pub spki_sha256_hex: String,
}

/// Build TLS material: operator-provided PEM if `SECGIT_TLS_CERT`/`SECGIT_TLS_KEY` are
/// set, otherwise an ephemeral attestation-pinned self-signed leaf.
pub fn load_or_generate() -> Result<TlsMaterial> {
    let (certs, key) = match (
        std::env::var("SECGIT_TLS_CERT"),
        std::env::var("SECGIT_TLS_KEY"),
    ) {
        (Ok(cert_path), Ok(key_path)) => load_pem(&cert_path, &key_path)?,
        _ => {
            eprintln!(
                "secgit-server: no SECGIT_TLS_CERT/KEY; generating an ephemeral \
                 attestation-pinned self-signed cert (authenticity comes from attestation)"
            );
            generate_self_signed()?
        }
    };
    let spki_sha256_hex = spki_sha256_hex(&certs[0]);
    let config = server_config(certs, key)?;
    Ok(TlsMaterial {
        config,
        spki_sha256_hex,
    })
}

/// Construct the rustls `ServerConfig` (aws-lc-rs provider, PQ-preferred kx by default).
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls ServerConfig")?;
    Ok(Arc::new(config))
}

fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = std::fs::read(cert_path).with_context(|| format!("reading {cert_path}"))?;
    let key_bytes = std::fs::read(key_path).with_context(|| format!("reading {key_path}"))?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing cert PEM")?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {cert_path}");
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .context("parsing key PEM")?
        .with_context(|| format!("no private key in {key_path}"))?;
    Ok((certs, key))
}

fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generating self-signed cert")?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("serializing self-signed key: {e}"))?;
    Ok((vec![cert_der], key_der))
}

/// SHA-256 of the certificate's SubjectPublicKeyInfo, as hex.
///
/// We extract the SPKI from the DER cert (it is the certificate's public-key field) and
/// hash it. Pinning the SPKI (not the whole cert) survives cert re-issuance with the same
/// key, which is what attestation actually vouches for.
pub fn spki_sha256_hex(cert: &CertificateDer<'_>) -> String {
    let spki = extract_spki(cert.as_ref()).unwrap_or_else(|| cert.as_ref().to_vec());
    hex::encode(secgit_crypto::primitives::sha256(&spki))
}

/// Best-effort extraction of the SubjectPublicKeyInfo SEQUENCE from an X.509 cert DER.
/// Falls back (caller substitutes the whole cert) if the structure is unexpected.
fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }
    let (tbs, _) = der_sequence_content(cert_der)?; // outer Certificate -> content
    let (tbs_inner, _) = der_sequence_content(tbs)?; // tbsCertificate -> content
                                                     // tbsCertificate fields: [0] version (optional, context tag 0xA0), serialNumber INT,
                                                     // signature SEQ, issuer SEQ, validity SEQ, subject SEQ, subjectPublicKeyInfo SEQ.
    let mut rest = tbs_inner;
    // Skip optional version [0].
    if rest.first() == Some(&0xA0) {
        rest = der_skip(rest)?;
    }
    // Skip serialNumber, signature, issuer, validity, subject (5 elements).
    for _ in 0..5 {
        rest = der_skip(rest)?;
    }
    // The next element is SubjectPublicKeyInfo (a SEQUENCE); return it whole (tag+len+val).
    der_element(rest)
}

/// Return (content, remaining_after_element) for a DER SEQUENCE at the front of `b`.
fn der_sequence_content(b: &[u8]) -> Option<(&[u8], &[u8])> {
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

/// Return the full element (tag+len+content) at the front of `b`.
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

/// Skip the element at the front of `b`, returning the remainder.
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

/// Parse a DER length, returning (length, header_bytes_consumed).
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

/// True if rustls' default key-exchange ordering puts the PQ hybrid first.
pub fn post_quantum_preferred() -> bool {
    rustls::crypto::aws_lc_rs::DEFAULT_KX_GROUPS
        .first()
        .map(|g| g.name() == rustls::NamedGroup::X25519MLKEM768)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{ServerName, UnixTime};
    use std::io::{Read, Write};

    #[test]
    fn pq_kx_is_preferred() {
        assert!(
            post_quantum_preferred(),
            "rustls must prefer X25519MLKEM768 (check the prefer-post-quantum feature)"
        );
    }

    /// A pinning verifier: the client trusts exactly the server's self-signed leaf, the
    /// way attestation pins it in production (signature checks still run for real).
    #[derive(Debug)]
    struct PinnedCert {
        cert: CertificateDer<'static>,
        algs: rustls::crypto::WebPkiSupportedAlgorithms,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedCert {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            if end_entity.as_ref() == self.cert.as_ref() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("cert pin mismatch".into()))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.algs.supported_schemes()
        }
    }

    #[test]
    fn handshake_uses_pq_kx_and_wire_is_ciphertext() {
        let (certs, key) = generate_self_signed().unwrap();
        let leaf = certs[0].clone();
        let server_cfg = server_config(certs, key).unwrap();

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let verifier = PinnedCert {
            cert: leaf,
            algs: provider.signature_verification_algorithms,
        };
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        // Drive the in-memory handshake to completion.
        for _ in 0..16 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
        }
        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "handshake stalled"
        );

        // Post-quantum hybrid kx must have been negotiated.
        assert_eq!(
            server.negotiated_key_exchange_group().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "expected X25519MLKEM768 to be negotiated"
        );

        // LEAK TEST: application plaintext must not appear on the wire.
        let secret = b"PLAINTEXT-REPO-BYTES-MUST-NOT-LEAK";
        client.writer().write_all(secret).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        assert!(
            !wire.windows(secret.len()).any(|w| w == secret),
            "plaintext leaked onto the TLS wire"
        );

        // And the server decrypts it correctly inside the TEE.
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut got = vec![0u8; secret.len()];
        server.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, secret);
    }

    /// A stream wrapper that tees every byte written to the socket into a shared buffer —
    /// exactly what an operator sitting on the network path (between a would-be proxy and the
    /// CVM) could capture.
    struct RecordingStream {
        inner: std::net::TcpStream,
        observed: Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl Read for RecordingStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.observed.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// End-to-end over a REAL loopback TCP socket: the server terminates PQC-TLS inside the
    /// "CVM" (server thread), and an on-path observer captures the raw wire bytes. The
    /// application plaintext (a canary) must never appear on that wire — only ciphertext —
    /// while the server still decrypts it correctly. This is the ADR-0007 regression guard:
    /// there is no operator-visible plaintext hop.
    #[test]
    fn loopback_observer_sees_only_ciphertext() {
        use std::net::{TcpListener, TcpStream};

        let (certs, key) = generate_self_signed().unwrap();
        let leaf = certs[0].clone();
        let server_cfg = server_config(certs, key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let canary = b"PLAINTEXT-REPO-PUSH-CANARY-9c1f-must-not-appear-on-wire".to_vec();
        let canary_srv = canary.clone();

        // Server: accept one connection, complete the handshake, read the canary.
        let srv = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut got = vec![0u8; canary_srv.len()];
            tls.read_exact(&mut got).unwrap();
            assert_eq!(got, canary_srv, "server must decrypt the canary in-TEE");
        });

        // Client: connect through a recording wrapper (the observer), pin the cert.
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let verifier = PinnedCert {
            cert: leaf,
            algs: provider.signature_verification_algorithms,
        };
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let conn = rustls::ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let sock = TcpStream::connect(addr).unwrap();
        let recording = RecordingStream {
            inner: sock,
            observed: observed.clone(),
        };
        let mut tls = rustls::StreamOwned::new(conn, recording);
        tls.write_all(&canary).unwrap();
        tls.flush().unwrap();
        srv.join().unwrap();

        // LEAK TEST: the bytes an on-path operator captured must be ciphertext-only.
        let wire = observed.lock().unwrap();
        assert!(!wire.is_empty(), "observer captured no bytes");
        assert!(
            !wire.windows(canary.len()).any(|w| w == canary.as_slice()),
            "plaintext canary leaked onto the loopback TLS wire (operator could read it!)"
        );
    }

    /// Move all pending TLS bytes from `from` into `to`.
    fn pump<A, B>(from: &mut A, to: &mut B)
    where
        A: DerefConn,
        B: DerefConn,
    {
        let mut buf = Vec::new();
        from.conn().write_tls(&mut buf).unwrap();
        if !buf.is_empty() {
            to.conn().read_tls(&mut buf.as_slice()).unwrap();
            to.conn().process_new_packets().unwrap();
        }
    }

    /// Tiny abstraction so `pump` works over both connection types.
    trait DerefConn {
        fn conn(&mut self) -> &mut rustls::ConnectionCommon<Self::Data>;
        type Data;
    }
    impl DerefConn for rustls::ServerConnection {
        type Data = rustls::server::ServerConnectionData;
        fn conn(&mut self) -> &mut rustls::ConnectionCommon<Self::Data> {
            self
        }
    }
    impl DerefConn for rustls::ClientConnection {
        type Data = rustls::client::ClientConnectionData;
        fn conn(&mut self) -> &mut rustls::ConnectionCommon<Self::Data> {
            self
        }
    }
}
