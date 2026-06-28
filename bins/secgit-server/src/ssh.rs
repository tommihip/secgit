//! Git-over-SSH transport: authentication and access control.
//!
//! SSH is the second supported transport alongside in-CVM PQC-TLS HTTPS. This module owns
//! the security-critical core that is independent of the wire library:
//!
//! 1. map an offered SSH public key to a SecGit user ([`AuthorizedKeys`]),
//! 2. parse the requested `git-upload-pack` / `git-receive-pack` exec command into a
//!    `(Service, repo_id)` pair ([`parse_git_command`]),
//! 3. enforce the same identity access-control decision as the HTTPS transport
//!    ([`authorize_ssh`]).
//!
//! The remaining piece is the SSH wire binding (channel/exec handling), which — like the
//! git smart-HTTP path that shells out to canonical `git` — drives `git-upload-pack` /
//! `git-receive-pack` against the repo path on the decrypted side of the connection. That
//! binding is intentionally thin over the logic proven here.
//!
//! These items are exercised by the unit tests below and consumed by the SSH wire binding;
//! until that listener is compiled in, allow them to exist without a direct `main` caller.
#![allow(dead_code)]

use crate::authz::{required_role, Decision, ServerIdentity};
use secgit_crypto::primitives::sha256;
use secgit_git::Service;
use std::collections::HashMap;

/// Maps SSH public keys (by fingerprint) to SecGit user ids.
#[derive(Default)]
pub struct AuthorizedKeys {
    /// sha256(normalized key blob) -> user_id
    by_fingerprint: HashMap<String, String>,
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fingerprint of an OpenSSH public key line (e.g. `ssh-ed25519 AAAA... comment`).
    /// Normalizes by taking the `type base64` portion (ignoring the trailing comment).
    pub fn fingerprint(openssh_pubkey: &str) -> String {
        let normalized: String = openssh_pubkey
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        hex::encode(sha256(normalized.as_bytes()))
    }

    /// Authorize an SSH key for a user.
    pub fn add(&mut self, user_id: &str, openssh_pubkey: &str) {
        self.by_fingerprint
            .insert(Self::fingerprint(openssh_pubkey), user_id.to_string());
    }

    /// Resolve the user id for an offered public key, if authorized.
    pub fn user_for(&self, openssh_pubkey: &str) -> Option<&str> {
        self.by_fingerprint
            .get(&Self::fingerprint(openssh_pubkey))
            .map(String::as_str)
    }

    pub fn remove(&mut self, openssh_pubkey: &str) {
        self.by_fingerprint
            .remove(&Self::fingerprint(openssh_pubkey));
    }
}

/// Parse an SSH `exec` git command into the git service and repo id.
///
/// Accepts the canonical forms git sends, e.g.:
/// `git-upload-pack '/alice/secret.git'`, `git-receive-pack 'alice/secret'`.
pub fn parse_git_command(cmd: &str) -> Option<(Service, String)> {
    let cmd = cmd.trim();
    let (svc, rest) = if let Some(r) = cmd.strip_prefix("git-upload-pack") {
        (Service::UploadPack, r)
    } else if let Some(r) = cmd.strip_prefix("git-receive-pack") {
        (Service::ReceivePack, r)
    } else {
        return None;
    };
    let arg = rest.trim();
    // Strip optional surrounding single/double quotes.
    let arg = arg.trim_matches(|c| c == '\'' || c == '"').trim();
    if arg.is_empty() {
        return None;
    }
    let repo = arg.trim_start_matches('/').trim_end_matches('/');
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if repo.is_empty() || repo.contains("..") {
        return None;
    }
    Some((svc, repo.to_string()))
}

/// Authorize a git-over-SSH request: resolve the key to a user, then check the role the
/// requested service needs on the repo.
pub fn authorize_ssh(
    identity: &ServerIdentity,
    keys: &AuthorizedKeys,
    offered_pubkey: &str,
    cmd: &str,
) -> Decision {
    let Some((svc, repo_id)) = parse_git_command(cmd) else {
        return Decision::NotFound;
    };
    if identity.dir.get_repo(&repo_id).is_none() {
        return Decision::NotFound;
    }
    let Some(user) = keys.user_for(offered_pubkey) else {
        return Decision::Unauthenticated;
    };
    let write = matches!(svc, Service::ReceivePack);
    if identity.dir.can(user, &repo_id, required_role(write)) {
        Decision::Allow(user.to_string())
    } else {
        Decision::Forbidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;
    use secgit_identity::model::{Repo, RepoOwner, Role, User};
    use secgit_identity::{LocalAuthenticator, PersistentDirectory, SessionStore};
    use secgit_store::EncryptedStore;

    const ALICE_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlicePublicKeyBlob alice@laptop";
    const BOB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABobPublicKeyBlob bob@laptop";

    fn identity() -> ServerIdentity {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("secgit-ssh-{}-{n}", std::process::id()));
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
            collaborators: vec![("u_bob".into(), Role::Read)],
        })
        .unwrap();
        pd.create_user(User {
            id: "u_bob".into(),
            username: "bob".into(),
            email: "b@x".into(),
        })
        .unwrap();
        ServerIdentity::new(pd, LocalAuthenticator::new(), SessionStore::new(3600))
    }

    #[test]
    fn parses_git_commands() {
        assert_eq!(
            parse_git_command("git-upload-pack '/alice/secret.git'"),
            Some((Service::UploadPack, "alice/secret".into()))
        );
        assert_eq!(
            parse_git_command("git-receive-pack 'alice/secret'"),
            Some((Service::ReceivePack, "alice/secret".into()))
        );
        assert!(parse_git_command("rm -rf /").is_none());
        assert!(parse_git_command("git-upload-pack '../../etc/passwd'").is_none());
    }

    #[test]
    fn key_maps_to_user_and_authorizes() {
        let id = identity();
        let mut keys = AuthorizedKeys::new();
        keys.add("u_alice", ALICE_KEY);
        keys.add("u_bob", BOB_KEY);

        // Owner can push.
        assert_eq!(
            authorize_ssh(&id, &keys, ALICE_KEY, "git-receive-pack 'alice/secret'"),
            Decision::Allow("u_alice".into())
        );
        // Read collaborator can fetch but not push.
        assert_eq!(
            authorize_ssh(&id, &keys, BOB_KEY, "git-upload-pack 'alice/secret'"),
            Decision::Allow("u_bob".into())
        );
        assert_eq!(
            authorize_ssh(&id, &keys, BOB_KEY, "git-receive-pack 'alice/secret'"),
            Decision::Forbidden
        );
    }

    #[test]
    fn unknown_key_unauthenticated() {
        let id = identity();
        let keys = AuthorizedKeys::new();
        assert_eq!(
            authorize_ssh(&id, &keys, ALICE_KEY, "git-upload-pack 'alice/secret'"),
            Decision::Unauthenticated
        );
    }

    #[test]
    fn fingerprint_ignores_comment() {
        let a = AuthorizedKeys::fingerprint("ssh-ed25519 AAAABLOB user@host-1");
        let b = AuthorizedKeys::fingerprint("ssh-ed25519 AAAABLOB user@host-2");
        assert_eq!(a, b, "fingerprint must ignore the trailing comment");
    }
}
