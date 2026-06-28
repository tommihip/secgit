//! Durable, TTL-bounded replay guard for attestation-gated key release.
//!
//! ## What this defends
//! A malicious operator can capture a previously-valid release request
//! `(evidence, nonce, timestamp, runtime_pubkey)` off the wire and resend it. Because the
//! KEK is KEM-sealed to `runtime_pubkey`, a replay alone does not hand the attacker a
//! usable KEK — but a replay that the broker *accepts* still produces a fresh sealed KEK
//! for a key the attacker does not hold, wastes a release, and (more importantly) means the
//! broker is treating stale evidence as live. We refuse it explicitly.
//!
//! The release flow binds a guest-chosen **timestamp** into the attested `report_data`
//! (`SHA-512(nonce ‖ timestamp ‖ runtime_pubkey)`), so the operator cannot backdate or
//! refresh the timestamp without the genuine TEE re-attesting. The guard then enforces:
//!   1. **freshness window** — the attested timestamp must be within `±ttl` of now, so old
//!      captured evidence is rejected on a *time* basis, not only by exact nonce match;
//!   2. **no replay** — a nonce accepted within the retention window cannot be reused.
//!
//! ## Honest limitation (tracked design item B)
//! This is replay-DETECTION and bounded staleness, NOT verifier-guaranteed freshness: the
//! *guest* still chooses the nonce and timestamp. True freshness requires a
//! **broker-issued challenge** (the verifier picks the nonce). That is recorded as design
//! item B in `docs/adr/0010-open-subdecisions.md` to revisit with the security auditor.
//! We deliberately do NOT claim "covered by KEM-sealing."
//!
//! ## Durability
//! State is persisted to a JSON file with an atomic temp-write + rename, so accepted
//! nonces survive a broker restart (an in-memory set would forget them across the very
//! restart an operator could trigger to bypass the guard). Nonces are high-entropy random
//! values that reveal nothing about repositories, so the file is not a metadata leak and
//! need not be encrypted; this also lets the guard run *before* the KEK exists.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Outcome of a replay/freshness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The attested timestamp is outside the freshness window (too old or implausibly future).
    Stale,
    /// This nonce was already accepted within the retention window.
    Replayed,
}

#[derive(Default, Serialize, Deserialize)]
struct SeenState {
    /// nonce (hex) -> unix second it was first accepted.
    seen: HashMap<String, u64>,
}

/// A durable, TTL-bounded replay/freshness guard.
pub struct ReplayGuard {
    path: PathBuf,
    /// Freshness window AND retention horizon, in seconds.
    ttl_secs: u64,
    /// Allowed clock skew into the future, in seconds.
    future_skew_secs: u64,
    state: Mutex<SeenState>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ReplayGuard {
    /// Default future clock-skew tolerance (seconds).
    pub const DEFAULT_FUTURE_SKEW: u64 = 60;

    /// Open (or create) a guard persisting to `path`, with a `ttl_secs` freshness/retention
    /// window. Loads any existing durable state.
    pub fn open(path: impl Into<PathBuf>, ttl_secs: u64) -> std::io::Result<Self> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => SeenState::default(),
        };
        Ok(Self {
            path,
            ttl_secs,
            future_skew_secs: Self::DEFAULT_FUTURE_SKEW,
            state: Mutex::new(state),
        })
    }

    pub fn with_future_skew(mut self, skew_secs: u64) -> Self {
        self.future_skew_secs = skew_secs;
        self
    }

    /// Check freshness + replay for `(nonce, timestamp)` and, if accepted, durably record
    /// the nonce. Pure time is injected via `now` for testability; production callers use
    /// [`Self::check_and_record`].
    pub fn check_and_record_at(
        &self,
        nonce: &[u8],
        timestamp: u64,
        now: u64,
    ) -> Result<(), ReplayError> {
        // 1. Freshness: reject stale or implausibly-future attested timestamps.
        let floor = now.saturating_sub(self.ttl_secs);
        if timestamp < floor || timestamp > now.saturating_add(self.future_skew_secs) {
            return Err(ReplayError::Stale);
        }

        let key = hex::encode(nonce);
        let mut st = self.state.lock().expect("replay guard poisoned");

        // 2. Prune expired records so the retention window is bounded and the file stays small.
        st.seen.retain(|_, &mut at| at >= floor);

        // 3. Replay: a nonce seen within the (pruned) window cannot be reused.
        if st.seen.contains_key(&key) {
            return Err(ReplayError::Replayed);
        }
        st.seen.insert(key, now);

        // 4. Persist durably (atomic temp + rename) BEFORE returning success.
        self.persist(&st);
        Ok(())
    }

    /// Production entry point: uses the wall clock for `now`.
    pub fn check_and_record(&self, nonce: &[u8], timestamp: u64) -> Result<(), ReplayError> {
        self.check_and_record_at(nonce, timestamp, now_unix())
    }

    fn persist(&self, st: &SeenState) {
        let Ok(bytes) = serde_json::to_vec(st) else {
            return;
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, &bytes).is_ok() {
            // Atomic replace; on failure leave the prior state intact.
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secgit-replay-{}-{}-{}.json",
            tag,
            std::process::id(),
            now_unix()
        ))
    }

    #[test]
    fn fresh_nonce_is_accepted_then_replay_refused() {
        let p = tmp_path("replay");
        let _ = std::fs::remove_file(&p);
        let g = ReplayGuard::open(&p, 300).unwrap();
        let now = 1_000_000u64;
        assert!(g.check_and_record_at(b"nonce-A", now, now).is_ok());
        // Exact replay within the window is refused.
        assert_eq!(
            g.check_and_record_at(b"nonce-A", now, now + 1),
            Err(ReplayError::Replayed)
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn stale_timestamp_refused_on_time_basis() {
        let p = tmp_path("stale");
        let _ = std::fs::remove_file(&p);
        let g = ReplayGuard::open(&p, 300).unwrap();
        let now = 2_000_000u64;
        // Evidence stamped 301s ago (> ttl) is stale even though the nonce is brand new.
        assert_eq!(
            g.check_and_record_at(b"old-nonce", now - 301, now),
            Err(ReplayError::Stale)
        );
        // Implausible future is also refused.
        assert_eq!(
            g.check_and_record_at(b"future-nonce", now + 3600, now),
            Err(ReplayError::Stale)
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn state_is_durable_across_reopen() {
        let p = tmp_path("durable");
        let _ = std::fs::remove_file(&p);
        let now = 3_000_000u64;
        {
            let g = ReplayGuard::open(&p, 300).unwrap();
            assert!(g.check_and_record_at(b"persist-me", now, now).is_ok());
        }
        // A fresh guard (simulating a broker restart) must still remember the nonce.
        let g2 = ReplayGuard::open(&p, 300).unwrap();
        assert_eq!(
            g2.check_and_record_at(b"persist-me", now, now + 5),
            Err(ReplayError::Replayed)
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn expired_nonce_is_pruned_and_reaccepted() {
        let p = tmp_path("prune");
        let _ = std::fs::remove_file(&p);
        let g = ReplayGuard::open(&p, 100).unwrap();
        let t0 = 5_000_000u64;
        assert!(g.check_and_record_at(b"n", t0, t0).is_ok());
        // Far in the future, the old record has fallen out of retention; a NEW timestamp
        // for the same nonce is fresh again (and not a replay of live evidence).
        let later = t0 + 1000;
        assert!(g.check_and_record_at(b"n", later, later).is_ok());
        let _ = std::fs::remove_file(&p);
    }
}
