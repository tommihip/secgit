//! Optional hashcash-style proof-of-work gate for the anonymous ephemeral-create path.
//!
//! The anonymous tier needs *no* account, so it is the most spammable surface. Aggressive
//! per-IP rate limits are the primary control; this PoW is an escalation lever (default
//! OFF, see `PowConfig`). It is CLI-friendly: a client fetches a challenge, finds a nonce,
//! and submits it in a header — solvable with `sha256sum` in a shell loop (see
//! `docs/dev-macos.md`).
//!
//! Challenges are **stateless and server-authenticated**: a challenge is `random|ts` with
//! an HMAC, so the server needn't store issued challenges. A small in-memory set of
//! recently *spent* challenges (bounded, TTL'd) prevents trivial replay within the window.

use secgit_crypto::primitives::{ct_eq, hmac_sha256, random_vec, sha256};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::PowConfig;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct PowGate {
    cfg: PowConfig,
    secret: [u8; 32],
    /// spent challenge token -> expiry (unix secs); bounds replay within the TTL window.
    spent: Mutex<HashMap<String, u64>>,
}

impl PowGate {
    pub fn new(cfg: PowConfig) -> Self {
        let mut secret = [0u8; 32];
        if let Ok(v) = random_vec(32) {
            secret.copy_from_slice(&v);
        }
        Self {
            cfg,
            secret,
            spent: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn difficulty_bits(&self) -> u32 {
        self.cfg.difficulty_bits
    }

    /// Issue a fresh challenge token bound to `client` and the current time.
    ///
    /// Token form: `<rand_hex>.<ts>.<client_hash8>.<mac_hex>` where
    /// `mac = HMAC(secret, "<rand_hex>.<ts>.<client_hash8>")`.
    pub fn issue(&self, client: &str) -> String {
        let rand_hex = hex::encode(random_vec(12).unwrap_or_default());
        let ts = now();
        let client_hash8 = hex::encode(&sha256(client.as_bytes())[..8]);
        let base = format!("{rand_hex}.{ts}.{client_hash8}");
        let mac = hex::encode(hmac_sha256(&self.secret, base.as_bytes()));
        format!("{base}.{mac}")
    }

    /// Verify a submitted `"<token>:<nonce>"` solution for `client`.
    ///
    /// Checks: MAC authenticity, non-expiry, client binding, that the token has not already
    /// been spent, and that `sha256(token || ":" || nonce)` has at least `difficulty_bits`
    /// leading zero bits.
    pub fn verify(&self, submission: &str, client: &str) -> bool {
        if !self.cfg.enabled {
            return true;
        }
        let Some((token, nonce)) = submission.split_once(':') else {
            return false;
        };
        // token = base.mac ; base = rand.ts.client_hash8
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        let expected_mac = hex::encode(hmac_sha256(&self.secret, base.as_bytes()));
        if !ct_eq(expected_mac.as_bytes(), parts[3].as_bytes()) {
            return false;
        }
        let Ok(ts) = parts[1].parse::<u64>() else {
            return false;
        };
        let t = now();
        if t.saturating_sub(ts) > self.cfg.ttl_secs {
            return false;
        }
        let client_hash8 = hex::encode(&sha256(client.as_bytes())[..8]);
        if !ct_eq(client_hash8.as_bytes(), parts[2].as_bytes()) {
            return false;
        }
        if !self.spend(token, t) {
            return false; // replay
        }
        let digest = sha256(format!("{token}:{nonce}").as_bytes());
        leading_zero_bits(&digest) >= self.cfg.difficulty_bits
    }

    /// Record a token as spent (once). Returns `false` if it was already spent. Also sweeps
    /// expired entries to keep the set bounded.
    fn spend(&self, token: &str, now_secs: u64) -> bool {
        let mut spent = self.spent.lock().unwrap();
        spent.retain(|_, exp| *exp > now_secs);
        if spent.contains_key(token) {
            return false;
        }
        spent.insert(token.to_string(), now_secs + self.cfg.ttl_secs);
        true
    }
}

/// Count leading zero bits of a big-endian byte array.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(bits: u32) -> PowConfig {
        PowConfig {
            enabled: true,
            difficulty_bits: bits,
            ttl_secs: 300,
        }
    }

    #[test]
    fn disabled_gate_always_passes() {
        let gate = PowGate::new(PowConfig::default());
        assert!(gate.verify("garbage", "1.2.3.4"));
    }

    #[test]
    fn solve_and_verify_roundtrip() {
        // Low difficulty so the test solves quickly.
        let gate = PowGate::new(cfg(8));
        let token = gate.issue("1.2.3.4");
        let mut nonce = 0u64;
        let solution = loop {
            let candidate = format!("{token}:{nonce}");
            if leading_zero_bits(&sha256(candidate.as_bytes())) >= 8 {
                break candidate;
            }
            nonce += 1;
        };
        assert!(gate.verify(&solution, "1.2.3.4"));
    }

    #[test]
    fn rejects_replay_wrong_client_and_bad_mac() {
        let gate = PowGate::new(cfg(1));
        let token = gate.issue("client-a");
        // Find a nonce meeting the (trivial) 1-bit target.
        let mut nonce = 0u64;
        let solution = loop {
            let candidate = format!("{token}:{nonce}");
            if leading_zero_bits(&sha256(candidate.as_bytes())) >= 1 {
                break candidate;
            }
            nonce += 1;
        };
        // Wrong client binding fails.
        assert!(!gate.verify(&solution, "client-b"));
        // Correct client passes once...
        assert!(gate.verify(&solution, "client-a"));
        // ...but a replay is refused.
        assert!(!gate.verify(&solution, "client-a"));
        // Tampered MAC fails.
        assert!(!gate.verify(&format!("{token}deadbeef:0"), "client-a"));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xff]), 16);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
    }
}
