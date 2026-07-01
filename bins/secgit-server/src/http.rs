//! A tiny, dependency-free HTTP/1.1 server.
//!
//! Deliberately minimal: the wedge is the confidential layer, not a bespoke HTTP
//! stack. TLS is terminated **in-process inside the CVM** (see `tls.rs`), so these
//! parse/write helpers are generic over any `Read`/`Write` and operate on the decrypted
//! side of the rustls stream — no operator-visible plaintext hop. `[VERIFY]` git
//! smart-HTTP clients may gzip fetch request bodies; that path is handled per-route.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// The TCP peer IP (set by the connection handler). This is the *trusted* client
    /// identity for rate limiting — `X-Forwarded-For` is attacker-controlled because ADR
    /// 0007 forbids a trusted plaintext proxy in front of the CVM.
    pub peer_ip: String,
}

/// Bounds applied while parsing a request, so a hostile client cannot exhaust memory or
/// hang the parser (slowloris) with monstrous headers or a giant/absent body.
#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_body_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_header_count: 100,
            max_body_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Result of parsing a request under [`HttpLimits`].
pub enum ParseOutcome {
    /// A well-formed request within all limits.
    Request(Request),
    /// The peer closed the connection with no request (EOF).
    Closed,
    /// The request violated a limit or was malformed; send this response and close.
    Reject(Response),
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }
    pub fn bearer_token(&self) -> Option<String> {
        if let Some(v) = self.header("authorization") {
            if let Some(t) = v.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        }
        self.query.get("token").cloned()
    }

    /// Parse an `application/x-www-form-urlencoded` request body into key/value pairs.
    pub fn form(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let body = String::from_utf8_lossy(&self.body);
        for pair in body.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(url_decode(k), url_decode(v));
            } else {
                map.insert(url_decode(pair), String::new());
            }
        }
        map
    }

    /// Parse HTTP Basic auth into `(username, secret)`.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        let v = self.header("authorization")?;
        let b64 = v.strip_prefix("Basic ")?.trim();
        let decoded = base64_decode(b64)?;
        let s = String::from_utf8(decoded).ok()?;
        let (u, p) = s.split_once(':')?;
        Some((u.to_string(), p.to_string()))
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
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

pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: String,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    pub fn new(status: u16, reason: &'static str, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type: content_type.to_string(),
            body,
            extra_headers: vec![],
        }
    }
    pub fn json(value: &serde_json::Value) -> Self {
        Self::new(
            200,
            "OK",
            "application/json",
            value.to_string().into_bytes(),
        )
    }
    pub fn text(status: u16, reason: &'static str, body: &str) -> Self {
        Self::new(
            status,
            reason,
            "text/plain; charset=utf-8",
            body.as_bytes().to_vec(),
        )
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.extra_headers.push((k.to_string(), v.to_string()));
        self
    }
}

/// Outcome of reading a single (bounded) line.
enum LineOutcome {
    Line(String),
    Eof,
    TooLong,
}

/// Read one CRLF/LF-terminated line, charging each byte against `budget`. Returns
/// [`LineOutcome::TooLong`] if the shared header budget is exhausted before a newline —
/// bounding both a single monstrous line and the whole header block, and defeating a
/// slowloris that trickles bytes without ever completing the request (the socket read
/// timeout, set by the caller, bounds the trickle in time).
fn read_capped_line<R: BufRead>(
    reader: &mut R,
    budget: &mut usize,
) -> std::io::Result<LineOutcome> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(LineOutcome::Eof);
            }
            break;
        }
        if *budget == 0 {
            return Ok(LineOutcome::TooLong);
        }
        *budget -= 1;
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(LineOutcome::Line(
        String::from_utf8_lossy(&buf).into_owned(),
    ))
}

fn headers_too_large() -> Response {
    Response::text(431, "Request Header Fields Too Large", "headers too large")
}

/// Parse an HTTP/1.1 request under [`HttpLimits`]. See [`ParseOutcome`].
pub fn parse_request<S: Read>(
    stream: &mut S,
    limits: &HttpLimits,
) -> std::io::Result<ParseOutcome> {
    let mut reader = BufReader::new(stream);
    let mut budget = limits.max_header_bytes;

    let request_line = match read_capped_line(&mut reader, &mut budget)? {
        LineOutcome::Eof => return Ok(ParseOutcome::Closed),
        LineOutcome::TooLong => return Ok(ParseOutcome::Reject(headers_too_large())),
        LineOutcome::Line(l) => l,
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || raw_target.is_empty() {
        return Ok(ParseOutcome::Reject(Response::text(
            400,
            "Bad Request",
            "malformed request line",
        )));
    }

    let (path, query) = split_target(&raw_target);

    let mut headers = HashMap::new();
    let mut header_count = 0usize;
    loop {
        let line = match read_capped_line(&mut reader, &mut budget)? {
            LineOutcome::Eof => break,
            LineOutcome::TooLong => return Ok(ParseOutcome::Reject(headers_too_large())),
            LineOutcome::Line(l) => l,
        };
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > limits.max_header_count {
            return Ok(ParseOutcome::Reject(headers_too_large()));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Chunked transfer-encoding is not supported by this minimal server; reject it
    // explicitly rather than silently ignoring the body framing.
    if let Some(te) = headers.get("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return Ok(ParseOutcome::Reject(Response::text(
                400,
                "Bad Request",
                "chunked transfer-encoding is not supported",
            )));
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > limits.max_body_bytes {
        return Ok(ParseOutcome::Reject(Response::text(
            413,
            "Payload Too Large",
            "request body exceeds the configured limit",
        )));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        // A lying Content-Length (bytes promised but never sent) blocks here until the
        // caller's socket read timeout fires, at which point we drop the connection.
        if reader.read_exact(&mut body).is_err() {
            return Ok(ParseOutcome::Closed);
        }
    }

    Ok(ParseOutcome::Request(Request {
        method,
        path,
        query,
        headers,
        body,
        peer_ip: String::new(),
    }))
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let mut query = HashMap::new();
    if let Some((path, qs)) = target.split_once('?') {
        for pair in qs.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                query.insert(url_decode(k), url_decode(v));
            } else {
                query.insert(url_decode(pair), String::new());
            }
        }
        (path.to_string(), query)
    } else {
        (target.to_string(), query)
    }
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn write_response<S: Write>(stream: &mut S, resp: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        resp.reason,
        resp.content_type,
        resp.body.len()
    );
    for (k, v) in &resp.extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(bytes: &[u8], limits: HttpLimits) -> ParseOutcome {
        let mut c = Cursor::new(bytes.to_vec());
        parse_request(&mut c, &limits).unwrap()
    }

    #[test]
    fn parses_a_normal_request() {
        let req = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse(req, HttpLimits::default()) {
            ParseOutcome::Request(r) => {
                assert_eq!(r.method, "GET");
                assert_eq!(r.path, "/healthz");
            }
            _ => panic!("expected a parsed request"),
        }
    }

    #[test]
    fn parses_body_within_cap() {
        let req = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        match parse(req, HttpLimits::default()) {
            ParseOutcome::Request(r) => assert_eq!(r.body, b"hello"),
            _ => panic!("expected a parsed request"),
        }
    }

    #[test]
    fn rejects_oversized_body_without_allocating_it() {
        let limits = HttpLimits {
            max_body_bytes: 8,
            ..HttpLimits::default()
        };
        // Claims a huge body; we must reject on Content-Length before allocating.
        let req = b"POST /x HTTP/1.1\r\nContent-Length: 1000000000000\r\n\r\n";
        match parse(req, limits) {
            ParseOutcome::Reject(resp) => assert_eq!(resp.status, 413),
            _ => panic!("expected 413 rejection"),
        }
    }

    #[test]
    fn rejects_oversized_headers() {
        let limits = HttpLimits {
            max_header_bytes: 40,
            ..HttpLimits::default()
        };
        let mut req = b"GET / HTTP/1.1\r\nX-Big: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 200));
        req.extend_from_slice(b"\r\n\r\n");
        match parse(&req, limits) {
            ParseOutcome::Reject(resp) => assert_eq!(resp.status, 431),
            _ => panic!("expected 431 rejection"),
        }
    }

    #[test]
    fn rejects_too_many_headers() {
        let limits = HttpLimits {
            max_header_count: 2,
            ..HttpLimits::default()
        };
        let req = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        match parse(req, limits) {
            ParseOutcome::Reject(resp) => assert_eq!(resp.status, 431),
            _ => panic!("expected 431 rejection"),
        }
    }

    #[test]
    fn rejects_chunked_encoding() {
        let req = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        match parse(req, HttpLimits::default()) {
            ParseOutcome::Reject(resp) => assert_eq!(resp.status, 400),
            _ => panic!("expected 400 rejection"),
        }
    }

    #[test]
    fn empty_stream_is_closed() {
        assert!(matches!(
            parse(b"", HttpLimits::default()),
            ParseOutcome::Closed
        ));
    }
}
