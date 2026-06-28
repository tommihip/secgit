//! Webhooks and notifications — the eventing layer of the forge.
//!
//! Both are **metadata** and therefore live encrypted-at-rest in the same
//! [`EncryptedStore`] as everything else: webhook configs (including their signing
//! secrets and destination URLs) are ciphertext on the operator's disk, and so are
//! per-user notifications. Delivery is best-effort, outbound-only, HTTPS-only, and the
//! payload carries an HMAC-SHA256 signature so receivers can verify authenticity.
//!
//! Note the confidentiality boundary: webhook delivery is the one place repository
//! events deliberately leave the CVM, *to an endpoint the repo's admin configured*. We
//! never put plaintext file contents in a webhook payload — only event metadata (repo id,
//! refs, PR numbers, actor) the admin already controls. This keeps "the operator can't
//! read your code" intact while still enabling integrations.

use secgit_store::EncryptedStore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Namespace under which a repo's webhooks are stored (one logical bucket per repo).
fn hooks_ns(repo_id: &str) -> String {
    format!("_hooks/{repo_id}")
}
/// Namespace under which a user's notifications are stored.
fn notif_ns(user_id: &str) -> String {
    format!("_notif/{user_id}")
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub repo_id: String,
    /// HTTPS endpoint to POST events to.
    pub url: String,
    /// HMAC-SHA256 signing secret (hex). Receivers verify `X-SecGit-Signature`.
    pub secret: String,
    /// Event types this hook subscribes to (`push`, `pull_request`, `review`) or `*`.
    pub events: Vec<String>,
    pub active: bool,
    pub created_at: u64,
}

impl Webhook {
    fn subscribes(&self, event: &str) -> bool {
        self.active && (self.events.iter().any(|e| e == "*" || e == event))
    }
    /// Redacted view safe to return over the API (never leak the signing secret).
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "repo_id": self.repo_id,
            "url": self.url,
            "events": self.events,
            "active": self.active,
            "created_at": self.created_at,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub kind: String,
    pub repo_id: String,
    pub subject: String,
    pub body: String,
    pub read: bool,
    pub created_at: u64,
}

impl Notification {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "kind": self.kind,
            "repo_id": self.repo_id,
            "subject": self.subject,
            "body": self.body,
            "read": self.read,
            "created_at": self.created_at,
        })
    }
}

/// Eventing handle over a borrowed encrypted store.
pub struct Events<'a> {
    store: &'a EncryptedStore,
}

impl<'a> Events<'a> {
    pub fn new(store: &'a EncryptedStore) -> Self {
        Self { store }
    }

    // ---- Webhooks ------------------------------------------------------------

    pub fn create_hook(
        &self,
        repo_id: &str,
        url: &str,
        secret: &str,
        events: Vec<String>,
    ) -> Result<Webhook, String> {
        if !url.starts_with("https://") {
            return Err("webhook url must be https://".into());
        }
        let id = format!("wh_{:016x}", rand_u64());
        let hook = Webhook {
            id: id.clone(),
            repo_id: repo_id.to_string(),
            url: url.to_string(),
            secret: secret.to_string(),
            events,
            active: true,
            created_at: now_secs(),
        };
        self.put(&hooks_ns(repo_id), &format!("hook/{id}"), &hook)?;
        self.index_add(&hooks_ns(repo_id), "hook/index", &id)?;
        Ok(hook)
    }

    pub fn list_hooks(&self, repo_id: &str) -> Result<Vec<Webhook>, String> {
        let mut out = vec![];
        for id in self.index(&hooks_ns(repo_id), "hook/index")? {
            if let Some(h) = self.get::<Webhook>(&hooks_ns(repo_id), &format!("hook/{id}"))? {
                out.push(h);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn delete_hook(&self, repo_id: &str, id: &str) -> Result<(), String> {
        self.store
            .delete(&hooks_ns(repo_id), &format!("hook/{id}"))
            .map_err(|e| e.to_string())?;
        self.index_remove(&hooks_ns(repo_id), "hook/index", id)
    }

    /// Deliver `payload` to every active hook on `repo_id` subscribed to `event`.
    /// Best-effort and synchronous; individual failures are returned but never fatal.
    pub fn deliver(&self, repo_id: &str, event: &str, payload: &serde_json::Value) -> Vec<String> {
        let mut errors = vec![];
        let hooks = match self.list_hooks(repo_id) {
            Ok(h) => h,
            Err(e) => return vec![e],
        };
        let body = serde_json::to_vec(payload).unwrap_or_default();
        for hook in hooks.iter().filter(|h| h.subscribes(event)) {
            let sig = secgit_crypto::primitives::hmac_sha256(hook.secret.as_bytes(), &body);
            let headers = vec![
                (
                    "X-SecGit-Signature".to_string(),
                    format!("sha256={}", hex::encode(sig)),
                ),
                ("X-SecGit-Event".to_string(), event.to_string()),
                (
                    "X-SecGit-Delivery".to_string(),
                    format!("{:016x}", rand_u64()),
                ),
            ];
            if let Err(e) = secgit_net::https_post_json_with_headers(&hook.url, &body, &headers) {
                errors.push(format!("{}: {e}", hook.url));
            }
        }
        errors
    }

    // ---- Notifications -------------------------------------------------------

    pub fn notify(
        &self,
        user_id: &str,
        kind: &str,
        repo_id: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String> {
        let id = format!("nt_{:016x}", rand_u64());
        let n = Notification {
            id: id.clone(),
            user_id: user_id.to_string(),
            kind: kind.to_string(),
            repo_id: repo_id.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            read: false,
            created_at: now_secs(),
        };
        self.put(&notif_ns(user_id), &format!("notif/{id}"), &n)?;
        self.index_add(&notif_ns(user_id), "notif/index", &id)
    }

    pub fn list_notifications(&self, user_id: &str) -> Result<Vec<Notification>, String> {
        let mut out = vec![];
        for id in self.index(&notif_ns(user_id), "notif/index")? {
            if let Some(n) = self.get::<Notification>(&notif_ns(user_id), &format!("notif/{id}"))? {
                out.push(n);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn mark_read(&self, user_id: &str, id: &str) -> Result<(), String> {
        if let Some(mut n) = self.get::<Notification>(&notif_ns(user_id), &format!("notif/{id}"))? {
            n.read = true;
            self.put(&notif_ns(user_id), &format!("notif/{id}"), &n)?;
        }
        Ok(())
    }

    // ---- internals -----------------------------------------------------------

    fn put<T: Serialize>(&self, ns: &str, key: &str, v: &T) -> Result<(), String> {
        let bytes = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        self.store.put(ns, key, &bytes).map_err(|e| e.to_string())
    }
    fn get<T: DeserializeOwned>(&self, ns: &str, key: &str) -> Result<Option<T>, String> {
        match self.store.get(ns, key).map_err(|e| e.to_string())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| e.to_string())?)),
            None => Ok(None),
        }
    }
    fn index(&self, ns: &str, key: &str) -> Result<Vec<String>, String> {
        Ok(self.get(ns, key)?.unwrap_or_default())
    }
    fn index_add(&self, ns: &str, key: &str, id: &str) -> Result<(), String> {
        let mut ids = self.index(ns, key)?;
        if !ids.iter().any(|x| x == id) {
            ids.push(id.to_string());
            self.put(ns, key, &ids)?;
        }
        Ok(())
    }
    fn index_remove(&self, ns: &str, key: &str, id: &str) -> Result<(), String> {
        let mut ids = self.index(ns, key)?;
        ids.retain(|x| x != id);
        self.put(ns, key, &ids)
    }
}

fn rand_u64() -> u64 {
    let v = secgit_crypto::primitives::random_vec(8).unwrap_or_else(|_| vec![0u8; 8]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&v);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;

    fn store(tag: &str) -> (EncryptedStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("secgit-events-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (
            EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap(),
            dir,
        )
    }

    #[test]
    fn webhook_crud_and_redaction() {
        let (s, dir) = store("wh");
        let e = Events::new(&s);
        let h = e
            .create_hook(
                "repo",
                "https://example.com/hook",
                "topsecret",
                vec!["push".into()],
            )
            .unwrap();
        assert!(e
            .create_hook("repo", "http://insecure", "x", vec![])
            .is_err());
        let listed = e.list_hooks("repo").unwrap();
        assert_eq!(listed.len(), 1);
        // Redacted view must not contain the secret.
        let pj = listed[0].public_json().to_string();
        assert!(!pj.contains("topsecret"));
        e.delete_hook("repo", &h.id).unwrap();
        assert!(e.list_hooks("repo").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn notifications_lifecycle() {
        let (s, dir) = store("nt");
        let e = Events::new(&s);
        e.notify("u_a", "pull_request", "repo", "PR opened", "see PR #1")
            .unwrap();
        e.notify("u_a", "review", "repo", "review", "approved")
            .unwrap();
        let list = e.list_notifications("u_a").unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|n| !n.read));
        e.mark_read("u_a", &list[0].id).unwrap();
        let after = e.list_notifications("u_a").unwrap();
        assert_eq!(after.iter().filter(|n| n.read).count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn webhook_config_is_ciphertext_on_disk() {
        use secgit_leaktest::assert_dir_ciphertext_nonempty;
        let dir = std::env::temp_dir().join(format!("secgit-events-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let secret = "canary-webhook-secret-abc123";
        {
            let s = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
            let e = Events::new(&s);
            e.create_hook("repo", "https://example.com/h", secret, vec!["*".into()])
                .unwrap();
            e.notify("u_a", "push", "repo", "secret-subject-xyz789", "body")
                .unwrap();
        }
        assert_dir_ciphertext_nonempty(&dir, &[secret.as_bytes(), b"secret-subject-xyz789"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
