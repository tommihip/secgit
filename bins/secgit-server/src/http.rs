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

pub fn parse_request<S: Read>(stream: &mut S) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || raw_target.is_empty() {
        return Ok(None);
    }

    let (path, query) = split_target(&raw_target);

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
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
