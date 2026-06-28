//! Server-side sessions.
//!
//! A successful login (local password + optional TOTP, or OIDC) mints an opaque,
//! high-entropy bearer token. Only the **hash** of the token is stored (sha256), so a dump
//! of the session table does not yield live credentials. Sessions carry the user id, an
//! expiry, and a flag for whether the second factor has been satisfied (so we can model the
//! "password OK, awaiting TOTP" intermediate state).

use crate::IdentityError;
use secgit_crypto::primitives::{random_vec, sha256};
use std::collections::HashMap;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub expires_at: u64,
    /// True once all required factors (incl. TOTP if enrolled) are satisfied.
    pub mfa_satisfied: bool,
}

/// In-memory session table keyed by the token hash.
pub struct SessionStore {
    ttl_secs: u64,
    by_hash: HashMap<String, Session>,
}

impl SessionStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            by_hash: HashMap::new(),
        }
    }

    fn hash(token: &str) -> String {
        hex::encode(sha256(token.as_bytes()))
    }

    /// Create a session for `user_id`; returns the bearer token (shown once).
    pub fn create(&mut self, user_id: &str, mfa_satisfied: bool) -> Result<String, IdentityError> {
        let token = hex::encode(random_vec(32).map_err(|_| IdentityError::Crypto)?);
        let session = Session {
            user_id: user_id.to_string(),
            expires_at: now().saturating_add(self.ttl_secs),
            mfa_satisfied,
        };
        self.by_hash.insert(Self::hash(&token), session);
        Ok(token)
    }

    /// Validate a token, returning the session if present, unexpired, and MFA-complete.
    pub fn validate(&mut self, token: &str) -> Option<Session> {
        self.gc();
        let h = Self::hash(token);
        let s = self.by_hash.get(&h)?;
        if s.expires_at <= now() || !s.mfa_satisfied {
            return None;
        }
        Some(s.clone())
    }

    /// Mark a session's second factor as satisfied (after TOTP verification).
    pub fn complete_mfa(&mut self, token: &str) -> Result<(), IdentityError> {
        let h = Self::hash(token);
        let s = self.by_hash.get_mut(&h).ok_or(IdentityError::AuthFailed)?;
        s.mfa_satisfied = true;
        Ok(())
    }

    pub fn revoke(&mut self, token: &str) {
        self.by_hash.remove(&Self::hash(token));
    }

    pub fn revoke_all_for(&mut self, user_id: &str) {
        self.by_hash.retain(|_, s| s.user_id != user_id);
    }

    fn gc(&mut self) {
        let t = now();
        self.by_hash.retain(|_, s| s.expires_at > t);
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_validate_revoke() {
        let mut s = SessionStore::new(3600);
        let token = s.create("user-1", true).unwrap();
        let session = s.validate(&token).unwrap();
        assert_eq!(session.user_id, "user-1");
        s.revoke(&token);
        assert!(s.validate(&token).is_none());
    }

    #[test]
    fn token_plaintext_not_stored() {
        let mut s = SessionStore::new(3600);
        let token = s.create("u", true).unwrap();
        // The raw token must not be a key in the table; only its hash is.
        assert!(!s.by_hash.contains_key(&token));
        assert!(s.by_hash.contains_key(&SessionStore::hash(&token)));
    }

    #[test]
    fn mfa_gate_blocks_until_completed() {
        let mut s = SessionStore::new(3600);
        let token = s.create("u", false).unwrap();
        assert!(
            s.validate(&token).is_none(),
            "must be blocked until MFA satisfied"
        );
        s.complete_mfa(&token).unwrap();
        assert!(s.validate(&token).is_some());
    }

    #[test]
    fn expired_session_rejected() {
        let mut s = SessionStore::new(0);
        let token = s.create("u", true).unwrap();
        assert!(s.validate(&token).is_none());
    }

    #[test]
    fn revoke_all_for_user() {
        let mut s = SessionStore::new(3600);
        let t1 = s.create("u", true).unwrap();
        let t2 = s.create("u", true).unwrap();
        let other = s.create("v", true).unwrap();
        s.revoke_all_for("u");
        assert!(s.validate(&t1).is_none());
        assert!(s.validate(&t2).is_none());
        assert!(s.validate(&other).is_some());
    }
}
