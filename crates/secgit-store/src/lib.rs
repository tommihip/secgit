//! # secgit-store
//!
//! Encrypted-at-rest blob store implementing the envelope-encryption hierarchy:
//!
//! ```text
//!   KEK (released into the TEE after attestation, held in memory only)
//!     └─ wraps ─> per-repo DEK (stored wrapped on disk)
//!                   └─ encrypts ─> repo objects (AES-256-GCM / ChaCha20-Poly1305)
//! ```
//!
//! Outside the TEE, only ciphertext exists on disk. The KEK never touches disk; the
//! DEK only ever appears on disk wrapped by the KEK. Each object is bound (via AEAD
//! AAD) to its `(repo_id, key)` so ciphertexts can't be relocated or swapped.

use secgit_crypto::aead::{self, SymKey};
use secgit_crypto::ids::AeadScheme;
use secgit_crypto::primitives::sha256;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] secgit_crypto::CryptoError),
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
}

pub type Result<T> = core::result::Result<T, StoreError>;

const DEK_FILE: &str = "dek.wrapped";
const OBJECTS_DIR: &str = "objects";

/// An encrypted object store rooted at a directory, unlocked by an in-memory KEK.
pub struct EncryptedStore {
    root: PathBuf,
    kek: SymKey,
    aead: AeadScheme,
}

impl EncryptedStore {
    /// Open (or create) a store at `root`, unlocked with `kek` (released into the TEE).
    pub fn open(root: impl Into<PathBuf>, kek: SymKey) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            kek,
            aead: secgit_crypto::ids::DEFAULT_AEAD,
        })
    }

    fn repo_dir(&self, repo_id: &str) -> PathBuf {
        self.root
            .join("repos")
            .join(hex::encode(sha256(repo_id.as_bytes())))
    }

    /// Load the repo's DEK, creating and wrapping a fresh one on first use.
    fn repo_dek(&self, repo_id: &str) -> Result<SymKey> {
        let dir = self.repo_dir(repo_id);
        std::fs::create_dir_all(&dir)?;
        let dek_path = dir.join(DEK_FILE);
        if dek_path.exists() {
            let wrapped = std::fs::read(&dek_path)?;
            Ok(aead::unwrap_key(&self.kek, &wrapped)?)
        } else {
            let dek = SymKey::generate()?;
            let wrapped = aead::wrap_key(self.aead, &self.kek, &dek)?;
            atomic_write(&dek_path, &wrapped)?;
            Ok(dek)
        }
    }

    /// Returns true if a repo has been initialized in this store.
    pub fn repo_exists(&self, repo_id: &str) -> bool {
        self.repo_dir(repo_id).join(DEK_FILE).exists()
    }

    /// Initialize a repo (creates and wraps its DEK).
    pub fn init_repo(&self, repo_id: &str) -> Result<()> {
        self.repo_dek(repo_id)?;
        Ok(())
    }

    fn object_path(&self, repo_id: &str, key: &str) -> PathBuf {
        self.repo_dir(repo_id)
            .join(OBJECTS_DIR)
            .join(hex::encode(sha256(key.as_bytes())))
    }

    fn aad(repo_id: &str, key: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"secgit/object/v1\0");
        aad.extend_from_slice(repo_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(key.as_bytes());
        aad
    }

    /// Encrypt and store `plaintext` under `(repo_id, key)`.
    pub fn put(&self, repo_id: &str, key: &str, plaintext: &[u8]) -> Result<()> {
        let dek = self.repo_dek(repo_id)?;
        let aad = Self::aad(repo_id, key);
        let ct = aead::seal(self.aead, &dek, &aad, plaintext)?;
        let path = self.object_path(repo_id, key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(&path, &ct)
    }

    /// Fetch and decrypt the object at `(repo_id, key)`.
    pub fn get(&self, repo_id: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.object_path(repo_id, key);
        if !path.exists() {
            return Ok(None);
        }
        let dek = self.repo_dek(repo_id)?;
        let ct = std::fs::read(&path)?;
        let aad = Self::aad(repo_id, key);
        let pt = aead::open(&dek, &aad, &ct)?;
        Ok(Some(pt))
    }

    pub fn delete(&self, repo_id: &str, key: &str) -> Result<()> {
        let path = self.object_path(repo_id, key);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("secgit-store-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tmpdir("rt");
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        store
            .put("user/alice/repo", "refs/heads/main", b"deadbeef")
            .unwrap();
        let got = store.get("user/alice/repo", "refs/heads/main").unwrap();
        assert_eq!(got, Some(b"deadbeef".to_vec()));
        assert_eq!(store.get("user/alice/repo", "missing").unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_on_disk_is_ciphertext() {
        use secgit_leaktest::{assert_dir_ciphertext_nonempty, Canary};
        let dir = tmpdir("ct");
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        let canary = Canary::new("store-value");
        // The repo id is also sensitive metadata; both must be ciphertext at rest.
        let repo = canary.as_str();
        store.put(repo, "k", canary.as_bytes()).unwrap();
        assert_dir_ciphertext_nonempty(&dir, &[canary.as_bytes()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_kek_cannot_open_repo() {
        let dir = tmpdir("wk");
        let kek = SymKey::generate().unwrap();
        {
            let store = EncryptedStore::open(&dir, kek.clone()).unwrap();
            store.put("r", "k", b"secret").unwrap();
        }
        let store2 = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        assert!(store2.get("r", "k").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persists_across_reopen_with_same_kek() {
        let dir = tmpdir("persist");
        let kek = SymKey::generate().unwrap();
        {
            let store = EncryptedStore::open(&dir, kek.clone()).unwrap();
            store.put("r", "k", b"value").unwrap();
        }
        let store2 = EncryptedStore::open(&dir, kek).unwrap();
        assert_eq!(store2.get("r", "k").unwrap(), Some(b"value".to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
