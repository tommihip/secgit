//! Versioned binary envelope shared by every crypto artifact.
//!
//! Layout: `MAGIC(4) | kind(1) | scheme(2 LE) | version(1) | body`.
//! The `(kind, scheme, version)` header is what makes the system crypto-agile: a
//! decoder always knows how to route bytes, and old artifacts stay readable when new
//! schemes are introduced.

use crate::error::{CryptoError, Result};
use crate::ids::Kind;

pub const MAGIC: [u8; 4] = *b"SGX1";
pub const HEADER_LEN: usize = 4 + 1 + 2 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub scheme: u16,
    pub version: u8,
    pub body: Vec<u8>,
}

impl Envelope {
    pub fn new(kind: Kind, scheme: u16, version: u8, body: Vec<u8>) -> Self {
        Self {
            kind,
            scheme,
            version,
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.scheme.to_le_bytes());
        out.push(self.version);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(CryptoError::Malformed("short envelope"));
        }
        if bytes[0..4] != MAGIC {
            return Err(CryptoError::Malformed("bad magic"));
        }
        let kind = Kind::from_u8(bytes[4])?;
        let scheme = u16::from_le_bytes([bytes[5], bytes[6]]);
        let version = bytes[7];
        let body = bytes[HEADER_LEN..].to_vec();
        Ok(Self {
            kind,
            scheme,
            version,
            body,
        })
    }
}

/// Minimal length-prefixed framing helpers for envelope bodies.
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// Single-byte field writer. Part of the crypto-agile framing surface, kept for
    /// schemes that need an inline tag even if no current scheme uses it.
    #[allow(dead_code)]
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn lp32(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(b);
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(CryptoError::Malformed("truncated body"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    #[allow(dead_code)]
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn lp32(&mut self) -> Result<&'a [u8]> {
        let lb = self.take(4)?;
        let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
        self.take(len)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        let e = Envelope::new(Kind::Aead, 1, 1, vec![9, 8, 7]);
        let bytes = e.encode();
        let d = Envelope::decode(&bytes).unwrap();
        assert_eq!(e, d);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Envelope::decode(b"xx").is_err());
        assert!(Envelope::decode(b"NOPExxxx").is_err());
    }
}
