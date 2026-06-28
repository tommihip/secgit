//! Minimal outbound HTTPS client (rustls + aws-lc-rs, Mozilla roots).
//!
//! This is the **single-sourced** audited outbound HTTPS path shared by the in-CVM server
//! (AMD KDS/VCEK + CRL fetch, self-hosted KBS, GitHub importer, webhook delivery) and the
//! user-facing `secgit-verify` tool (KDS/VCEK + CRL fetch during the acceptance harness).
//! Keeping it in one place means the trust-critical outbound path is reviewed once.
//!
//! It is used only for **non-secret** calls: any released secret (e.g. the KEK) is
//! KEM-sealed to the TEE's ephemeral key, so even a fully compromised transport here cannot
//! expose it — these CA roots authenticate the endpoints, they do not gate confidentiality.
//!
//! Intentionally tiny (one request per connection, `Connection: close`); we are not shipping
//! a general HTTP client, just enough to fetch a cert/CRL and POST a release.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_https_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("https://")
        .context("only https:// URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad port")?),
        None => (authority.to_string(), 443u16),
    };
    if host.is_empty() {
        bail!("empty host in URL");
    }
    Ok(Url {
        host,
        port,
        path: path.to_string(),
    })
}

fn request(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    request_with_headers(method, url, content_type, body, &[])
}

fn request_with_headers(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    extra_headers: &[(String, String)],
) -> Result<Vec<u8>> {
    let u = parse_https_url(url)?;
    let cfg = client_config();
    let server_name =
        rustls::pki_types::ServerName::try_from(u.host.clone()).context("invalid DNS name")?;
    let conn = rustls::ClientConnection::new(cfg, server_name).context("tls client")?;
    let sock = TcpStream::connect((u.host.as_str(), u.port))
        .with_context(|| format!("connecting to {}:{}", u.host, u.port))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: secgit-net\r\nAccept: */*\r\nConnection: close\r\n",
        u.path, u.host
    );
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).context("writing request")?;
    if let Some(b) = body {
        tls.write_all(b).context("writing body")?;
    }
    tls.flush().ok();

    let mut raw = Vec::new();
    // Read to EOF (server closes the connection). A clean-close TLS error is expected.
    let _ = tls.read_to_end(&mut raw);
    if raw.is_empty() {
        bail!("empty HTTP response from {url}");
    }

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response (no header terminator)")?;
    let header = String::from_utf8_lossy(&raw[..split]);
    let status_line = header.lines().next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("could not parse HTTP status")?;
    let body = raw[split + 4..].to_vec();
    if !(200..300).contains(&code) {
        bail!("HTTP {code} from {url}: {}", String::from_utf8_lossy(&body));
    }
    Ok(body)
}

/// HTTPS GET, returning the response body (errors on non-2xx).
pub fn https_get(url: &str) -> Result<Vec<u8>> {
    request("GET", url, None, None)
}

/// HTTPS GET with caller-supplied headers (used for the GitHub importer: the bearer token,
/// `User-Agent`, and API `Accept` ride here, in the audited in-CVM HTTPS path).
pub fn https_get_with_headers(url: &str, headers: &[(String, String)]) -> Result<Vec<u8>> {
    request_with_headers("GET", url, None, None, headers)
}

/// HTTPS POST of a JSON body, returning the response body (errors on non-2xx).
pub fn https_post_json(url: &str, json: &[u8]) -> Result<Vec<u8>> {
    request("POST", url, Some("application/json"), Some(json))
}

/// HTTPS POST of a JSON body with caller-supplied headers (used for signed webhook
/// delivery: the HMAC signature and event headers ride alongside the payload).
pub fn https_post_json_with_headers(
    url: &str,
    json: &[u8],
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    request_with_headers("POST", url, Some("application/json"), Some(json), headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_urls() {
        let u = parse_https_url("https://kdsintf.amd.com/vcek/v1/Milan/abcd?blSPL=3").unwrap();
        assert_eq!(u.host, "kdsintf.amd.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/vcek/v1/Milan/abcd?blSPL=3");

        let u2 = parse_https_url("https://kbs.internal:8443/release").unwrap();
        assert_eq!(u2.host, "kbs.internal");
        assert_eq!(u2.port, 8443);
        assert_eq!(u2.path, "/release");
    }

    #[test]
    fn rejects_non_https() {
        assert!(parse_https_url("http://insecure/x").is_err());
    }
}
