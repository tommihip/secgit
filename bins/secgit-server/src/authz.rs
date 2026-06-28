//! Identity + access control for the git smart-HTTP transport.
//!
//! Authenticated, non-ephemeral repos are gated by `secgit-identity`: a request is mapped
//! to a user (via a session bearer token or HTTP Basic against local accounts), and the
//! effective role on the target repo must meet the required level (Read for fetch, Write
//! for push). Anonymous ephemeral repos keep their separate throwaway-token path.

use crate::http::Request;
use secgit_identity::{Authenticator, LocalAuthenticator, PersistentDirectory, Role, SessionStore};

/// Server-side identity state: the persistent directory (authz + metadata, encrypted at
/// rest), local password accounts, and live sessions.
pub struct ServerIdentity {
    pub dir: PersistentDirectory,
    pub local: LocalAuthenticator,
    pub sessions: SessionStore,
}

impl ServerIdentity {
    pub fn new(
        dir: PersistentDirectory,
        local: LocalAuthenticator,
        sessions: SessionStore,
    ) -> Self {
        Self {
            dir,
            local,
            sessions,
        }
    }

    /// Resolve the requesting user id from a session bearer token or HTTP Basic auth.
    pub fn authenticate(&mut self, req: &Request) -> Option<String> {
        if let Some(token) = req.bearer_token() {
            if let Some(session) = self.sessions.validate(&token) {
                return Some(session.user_id);
            }
        }
        if let Some((user, secret)) = req.basic_auth() {
            // Basic password may itself be a session token (git credential helpers).
            if let Some(session) = self.sessions.validate(&secret) {
                return Some(session.user_id);
            }
            if let Ok(uid) = self.local.authenticate(&user, &secret) {
                return Some(uid);
            }
        }
        None
    }
}

/// The role a git operation requires.
pub fn required_role(write: bool) -> Role {
    if write {
        Role::Write
    } else {
        Role::Read
    }
}

/// Outcome of an access-control decision for a git request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Identity-backed repo; proceed (authenticated + authorized).
    Allow(String),
    /// No such repo.
    NotFound,
    /// Repo exists but the caller is unauthenticated.
    Unauthenticated,
    /// Authenticated but lacks the required role.
    Forbidden,
}

/// Decide access for an identity-backed repo (callers handle the ephemeral case first).
pub fn decide_identity(
    identity: &mut ServerIdentity,
    repo_id: &str,
    write: bool,
    req: &Request,
) -> Decision {
    if identity.dir.get_repo(repo_id).is_none() {
        return Decision::NotFound;
    }
    let Some(user) = identity.authenticate(req) else {
        return Decision::Unauthenticated;
    };
    if identity.dir.can(&user, repo_id, required_role(write)) {
        Decision::Allow(user)
    } else {
        Decision::Forbidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;
    use secgit_identity::model::{Repo, RepoOwner, User};
    use secgit_store::EncryptedStore;
    use std::collections::HashMap;

    fn req_with_basic(user: &str, pass: &str) -> Request {
        let token = {
            // base64(user:pass)
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let raw = format!("{user}:{pass}");
            let b = raw.as_bytes();
            let mut out = String::new();
            for chunk in b.chunks(3) {
                let mut n = (chunk[0] as u32) << 16;
                if chunk.len() > 1 {
                    n |= (chunk[1] as u32) << 8;
                }
                if chunk.len() > 2 {
                    n |= chunk[2] as u32;
                }
                out.push(A[((n >> 18) & 63) as usize] as char);
                out.push(A[((n >> 12) & 63) as usize] as char);
                out.push(if chunk.len() > 1 {
                    A[((n >> 6) & 63) as usize] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    A[(n & 63) as usize] as char
                } else {
                    '='
                });
            }
            out
        };
        let mut headers = HashMap::new();
        headers.insert("authorization".into(), format!("Basic {token}"));
        Request {
            method: "GET".into(),
            path: "/r".into(),
            query: HashMap::new(),
            headers,
            body: vec![],
        }
    }

    fn setup() -> ServerIdentity {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("secgit-authz-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        let mut pd = PersistentDirectory::open(store).unwrap();
        pd.create_user(User {
            id: "u_alice".into(),
            username: "alice".into(),
            email: "a@x".into(),
        })
        .unwrap();
        pd.create_repo(Repo {
            id: "alice/secret".into(),
            owner: RepoOwner::User("u_alice".into()),
            name: "secret".into(),
            private: true,
            collaborators: vec![],
        })
        .unwrap();
        let mut local = LocalAuthenticator::new();
        local.register("alice", "u_alice", "pw").unwrap();
        ServerIdentity::new(pd, local, SessionStore::new(3600))
    }

    #[test]
    fn owner_can_read_and_write() {
        let mut id = setup();
        let req = req_with_basic("alice", "pw");
        assert_eq!(
            decide_identity(&mut id, "alice/secret", false, &req),
            Decision::Allow("u_alice".into())
        );
        assert_eq!(
            decide_identity(&mut id, "alice/secret", true, &req),
            Decision::Allow("u_alice".into())
        );
    }

    #[test]
    fn wrong_password_unauthenticated() {
        let mut id = setup();
        let req = req_with_basic("alice", "nope");
        assert_eq!(
            decide_identity(&mut id, "alice/secret", false, &req),
            Decision::Unauthenticated
        );
    }

    #[test]
    fn unknown_repo_not_found() {
        let mut id = setup();
        let req = req_with_basic("alice", "pw");
        assert_eq!(
            decide_identity(&mut id, "alice/missing", false, &req),
            Decision::NotFound
        );
    }

    #[test]
    fn non_collaborator_forbidden() {
        let mut id = setup();
        id.dir
            .create_user(User {
                id: "u_bob".into(),
                username: "bob".into(),
                email: "b@x".into(),
            })
            .unwrap();
        id.local.register("bob", "u_bob", "pw2").unwrap();
        let req = req_with_basic("bob", "pw2");
        assert_eq!(
            decide_identity(&mut id, "alice/secret", false, &req),
            Decision::Forbidden
        );
    }
}
