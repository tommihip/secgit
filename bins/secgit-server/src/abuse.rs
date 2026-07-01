//! Abuse reporting + operator takedown for a public instance hosting arbitrary content.
//!
//! A public sandbox that lets anyone push code *will* host something someone wants removed
//! — this is a legal/ops reality, not optional. But the operator is **blind to content**:
//! takedown is therefore by repo *identifier* (from the reporter or a legal process),
//! never content review. Reports are stored **encrypted at rest** (operator can't read the
//! at-rest queue); an authenticated admin inside the TEE can list them over PQC-TLS and
//! force-delete by id. Every takedown is recorded in the PQC-signed transparency log.

use secgit_crypto::primitives::sha256;
use secgit_store::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Reserved store namespace for the abuse queue (its at-rest bytes are ciphertext, and the
/// namespace itself is stored under a SHA-256, so nothing here is operator-visible).
const ABUSE_REPO: &str = "__abuse__";
const REPORTS_KEY: &str = "reports";
const MAX_REASON_LEN: usize = 2000;
const MAX_QUEUE: usize = 5000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub repo_id: String,
    pub reason: String,
    /// SHA-256 (hex, truncated) of the reporter's client key — enough to correlate abuse,
    /// without retaining a raw IP.
    pub reporter_hash: String,
    pub ts: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append an abuse report to the encrypted queue. `lock` serializes the read-modify-write.
pub fn report(
    store: &EncryptedStore,
    lock: &Mutex<()>,
    repo_id: &str,
    reason: &str,
    client: &str,
) -> Result<Report, String> {
    let _guard = lock.lock().unwrap();
    let mut reports = load(store);
    let reason = reason.chars().take(MAX_REASON_LEN).collect::<String>();
    let rep = Report {
        id: hex::encode(sha256(
            format!("{}-{}-{}", now(), repo_id, client).as_bytes(),
        ))[..16]
            .to_string(),
        repo_id: repo_id.to_string(),
        reason,
        reporter_hash: hex::encode(&sha256(client.as_bytes())[..8]),
        ts: now(),
    };
    reports.push(rep.clone());
    // Bound the queue so a report flood cannot grow storage without limit.
    if reports.len() > MAX_QUEUE {
        let overflow = reports.len() - MAX_QUEUE;
        reports.drain(0..overflow);
    }
    save(store, &reports)?;
    Ok(rep)
}

/// List all queued reports (admin, inside the TEE).
pub fn list(store: &EncryptedStore) -> Vec<Report> {
    load(store)
}

/// Add an email to the managed-tier waitlist (stored encrypted at rest, deduplicated).
pub fn waitlist_add(store: &EncryptedStore, lock: &Mutex<()>, email: &str) -> Result<(), String> {
    const WAITLIST_REPO: &str = "__waitlist__";
    const EMAILS_KEY: &str = "emails";
    const MAX_WAITLIST: usize = 100_000;
    let _guard = lock.lock().unwrap();
    let mut emails: Vec<String> = match store.get(WAITLIST_REPO, EMAILS_KEY) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => vec![],
    };
    let email = email.to_string();
    if !emails.contains(&email) && emails.len() < MAX_WAITLIST {
        emails.push(email);
    }
    store.init_repo(WAITLIST_REPO).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&emails).map_err(|e| e.to_string())?;
    store
        .put(WAITLIST_REPO, EMAILS_KEY, &bytes)
        .map_err(|e| e.to_string())
}

fn load(store: &EncryptedStore) -> Vec<Report> {
    match store.get(ABUSE_REPO, REPORTS_KEY) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => vec![],
    }
}

fn save(store: &EncryptedStore, reports: &[Report]) -> Result<(), String> {
    store.init_repo(ABUSE_REPO).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(reports).map_err(|e| e.to_string())?;
    store
        .put(ABUSE_REPO, REPORTS_KEY, &bytes)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;

    #[test]
    fn reports_persist_and_are_ciphertext_at_rest() {
        let dir = std::env::temp_dir().join(format!("secgit-abuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        let lock = Mutex::new(());

        let canary = secgit_leaktest::Canary::new("abuse-reason");
        report(&store, &lock, "ephemeral/abc", canary.as_str(), "1.2.3.4").unwrap();
        report(&store, &lock, "bob/secret", "spam", "5.6.7.8").unwrap();

        let all = list(&store);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].repo_id, "ephemeral/abc");
        // The reason text (and the reported id) must be ciphertext on the operator's disk.
        secgit_leaktest::assert_dir_ciphertext_nonempty(&dir, &[canary.as_bytes(), b"bob/secret"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
