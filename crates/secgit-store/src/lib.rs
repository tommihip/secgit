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

/// Object key of the append-only seal manifest.
///
/// The manifest is an opaque (to the store) JSON document whose schema is owned by
/// `secgit-forge`; it records the ordered list of seal segments and the git ref tips each
/// segment covers, so a repo can be sealed incrementally (O(delta)) instead of re-bundling
/// the whole repo on every push. Like every object it is encrypted under the repo DEK and
/// AAD-bound to `(repo_id, SEAL_MANIFEST_KEY)`.
pub const SEAL_MANIFEST_KEY: &str = "seal.manifest";

/// Legacy single-bundle object key used by repos sealed before incremental sealing.
///
/// A repo with this object but no [`SEAL_MANIFEST_KEY`] predates segmented sealing; the
/// forge treats it as segment 0 (the base) when it first migrates the repo to a manifest.
pub const LEGACY_BUNDLE_KEY: &str = "repo.bundle";

/// Object key for seal segment `index` (a git bundle covering a delta of refs).
///
/// Zero-padded so the lexical order of the underlying object names is irrelevant (the
/// manifest defines segment order anyway) and so the space is effectively unbounded.
pub fn segment_key(index: u32) -> String {
    format!("bundle/{index:08}")
}

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

    /// Store seal segment `index` (a git bundle covering a delta of refs).
    pub fn put_segment(&self, repo_id: &str, index: u32, bytes: &[u8]) -> Result<()> {
        self.put(repo_id, &segment_key(index), bytes)
    }

    /// Fetch seal segment `index`, if present.
    pub fn get_segment(&self, repo_id: &str, index: u32) -> Result<Option<Vec<u8>>> {
        self.get(repo_id, &segment_key(index))
    }

    /// Remove seal segment `index` (used by compaction). Idempotent.
    pub fn delete_segment(&self, repo_id: &str, index: u32) -> Result<()> {
        self.delete(repo_id, &segment_key(index))
    }

    /// Store the append-only seal manifest (opaque JSON; schema owned by `secgit-forge`).
    pub fn put_manifest(&self, repo_id: &str, bytes: &[u8]) -> Result<()> {
        self.put(repo_id, SEAL_MANIFEST_KEY, bytes)
    }

    /// Fetch the seal manifest, if the repo has been migrated to segmented sealing.
    pub fn get_manifest(&self, repo_id: &str) -> Result<Option<Vec<u8>>> {
        self.get(repo_id, SEAL_MANIFEST_KEY)
    }

    /// Remove **all** persisted state for a repo (its wrapped DEK and every object).
    ///
    /// Used by the sandbox GC / takedown path to reclaim storage for expired ephemeral
    /// repos or removed content. After this call the repo id looks un-initialized again.
    /// The directory name is a SHA-256 of the repo id, so no plaintext id is exposed even
    /// while wiping. Idempotent: a missing repo is not an error.
    pub fn delete_repo(&self, repo_id: &str) -> Result<()> {
        let dir = self.repo_dir(repo_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
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
    fn delete_repo_wipes_all_state() {
        let dir = tmpdir("delrepo");
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        store
            .put("ephemeral/abcd", "repo.bundle", b"ciphertext")
            .unwrap();
        assert!(store.repo_exists("ephemeral/abcd"));
        store.delete_repo("ephemeral/abcd").unwrap();
        assert!(!store.repo_exists("ephemeral/abcd"));
        assert_eq!(store.get("ephemeral/abcd", "repo.bundle").unwrap(), None);
        // Idempotent.
        store.delete_repo("ephemeral/abcd").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn segments_and_manifest_roundtrip_and_stay_ciphertext() {
        use secgit_leaktest::assert_dir_ciphertext_nonempty;
        let dir = tmpdir("segments");
        let store = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
        let repo = "user/alice/repo";

        store
            .put_manifest(repo, br#"{"version":1,"segments":[]}"#)
            .unwrap();
        store.put_segment(repo, 0, b"BASE-BUNDLE-BYTES").unwrap();
        store.put_segment(repo, 1, b"DELTA-BUNDLE-BYTES").unwrap();

        assert_eq!(
            store.get_manifest(repo).unwrap().as_deref(),
            Some(&b"{\"version\":1,\"segments\":[]}"[..])
        );
        assert_eq!(
            store.get_segment(repo, 0).unwrap().as_deref(),
            Some(&b"BASE-BUNDLE-BYTES"[..])
        );
        assert_eq!(
            store.get_segment(repo, 1).unwrap().as_deref(),
            Some(&b"DELTA-BUNDLE-BYTES"[..])
        );
        assert_eq!(store.get_segment(repo, 2).unwrap(), None);

        // Distinct segment keys map to distinct objects.
        assert_ne!(segment_key(0), segment_key(1));

        // Compaction can drop a delta by index; the base and manifest survive.
        store.delete_segment(repo, 1).unwrap();
        assert_eq!(store.get_segment(repo, 1).unwrap(), None);
        assert!(store.get_segment(repo, 0).unwrap().is_some());

        // The bundle payloads must be ciphertext at rest (never the plaintext bytes).
        assert_dir_ciphertext_nonempty(&dir, &[b"BASE-BUNDLE-BYTES", b"DELTA-BUNDLE-BYTES"]);
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
