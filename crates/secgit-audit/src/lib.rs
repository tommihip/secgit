//! # secgit-audit
//!
//! An **independent**, tamper-evident transparency log — built fresh on open
//! primitives, never a proprietary/external audit DB. It combines two defenses:
//!
//! - a **hash chain** (each entry commits to the previous), giving cheap append-only
//!   tamper-evidence and total ordering;
//! - an **RFC 6962 Merkle tree** (see [`merkle`]) over the chain hashes, giving anyone
//!   efficient inclusion and consistency proofs;
//!
//! and signs **checkpoints** (signed tree heads) with a hybrid post-quantum signature
//! ([`secgit_crypto::sig`]) using the long-lived parameter set. A relying party can
//! thus verify "my push really happened, in this order, and the operator hasn't
//! rewritten history" without trusting the operator.

pub mod merkle;

use merkle::Hash;
use secgit_crypto::aead::{self, SymKey};
use secgit_crypto::primitives::sha256;
use secgit_crypto::sig::{self, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] secgit_crypto::CryptoError),
    #[error("log integrity violation: {0}")]
    Integrity(&'static str),
}

pub type Result<T> = core::result::Result<T, AuditError>;

/// The kinds of events SecGit records. Kept small and explicit so the log is a
/// faithful, reviewable history of security-relevant actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum AuditEvent {
    RepoCreated {
        repo_id: String,
        owner: String,
    },
    RefUpdated {
        repo_id: String,
        reference: String,
        old: String,
        new: String,
        actor: String,
    },
    KeyReleased {
        resource_id: String,
        measurement_hex: String,
    },
    KeyRotated {
        resource_id: String,
    },
    AccessDenied {
        repo_id: String,
        actor: String,
        reason: String,
    },
    Admin {
        action: String,
        actor: String,
    },
}

/// A single committed log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub timestamp: u64,
    #[serde(with = "hex32")]
    pub prev_hash: Hash,
    pub event: AuditEvent,
    #[serde(with = "hex32")]
    pub entry_hash: Hash,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn compute_entry_hash(seq: u64, ts: u64, prev: &Hash, event_json: &[u8]) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"secgit/audit/entry/v1\0");
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(event_json);
    sha256(&buf)
}

/// A signed tree head: the operator's commitment to the log's state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub log_id: String,
    pub tree_size: u64,
    #[serde(with = "hex32")]
    pub root_hash: Hash,
    pub timestamp: u64,
    /// Hybrid PQC signature envelope over the canonical checkpoint bytes.
    pub signature_hex: String,
}

impl Checkpoint {
    fn signed_bytes(log_id: &str, tree_size: u64, root: &Hash, ts: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"secgit/audit/checkpoint/v1\0");
        b.extend_from_slice(log_id.as_bytes());
        b.push(0);
        b.extend_from_slice(&tree_size.to_le_bytes());
        b.extend_from_slice(root);
        b.extend_from_slice(&ts.to_le_bytes());
        b
    }

    /// Verify the checkpoint's PQC signature against a pinned verifying key.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<()> {
        let bytes = Self::signed_bytes(
            &self.log_id,
            self.tree_size,
            &self.root_hash,
            self.timestamp,
        );
        let sig = hex::decode(&self.signature_hex)
            .map_err(|_| AuditError::Integrity("bad checkpoint signature hex"))?;
        sig::verify(vk, &bytes, &sig)?;
        Ok(())
    }
}

/// The transparency log: an append-only file of entries plus an in-memory Merkle view.
///
/// ## Metadata confidentiality boundary
/// Event records embed security-relevant *metadata* (repo ids, owners, ref names). When
/// opened with [`TransparencyLog::open_encrypted`] the on-disk records are AEAD-sealed
/// under an instance key, so the operator sees only ciphertext at rest — closing the
/// audit-log metadata leak. The *public verifiability* path is unaffected: a relying
/// party verifies the PQC-signed [`Checkpoint`] (which commits only to the Merkle root)
/// and an inclusion proof (sibling hashes only); neither reveals event contents. See
/// `docs/metadata-boundary.md`.
pub struct TransparencyLog {
    path: PathBuf,
    log_id: String,
    entries: Vec<LogEntry>,
    leaves: Vec<Hash>,
    signer: SigningKey,
    /// When set, on-disk records are AEAD-sealed under this key (metadata boundary).
    at_rest: Option<SymKey>,
}

impl TransparencyLog {
    /// Open (or create) a log at `path` with records stored in **plaintext**, signing
    /// checkpoints with `signer`. Use [`Self::open_encrypted`] for the provider-blind
    /// at-rest guarantee; this plaintext mode is for tooling/tests that hold no key.
    pub fn open(
        path: impl Into<PathBuf>,
        log_id: impl Into<String>,
        signer: SigningKey,
    ) -> Result<Self> {
        Self::open_inner(path, log_id, signer, None)
    }

    /// Open (or create) a log whose on-disk records are AEAD-sealed under `at_rest_key`
    /// (the instance audit key). The operator sees only ciphertext, while checkpoints +
    /// inclusion proofs remain independently verifiable.
    pub fn open_encrypted(
        path: impl Into<PathBuf>,
        log_id: impl Into<String>,
        signer: SigningKey,
        at_rest_key: SymKey,
    ) -> Result<Self> {
        Self::open_inner(path, log_id, signer, Some(at_rest_key))
    }

    fn open_inner(
        path: impl Into<PathBuf>,
        log_id: impl Into<String>,
        signer: SigningKey,
        at_rest: Option<SymKey>,
    ) -> Result<Self> {
        let path = path.into();
        let mut log = Self {
            path: path.clone(),
            log_id: log_id.into(),
            entries: vec![],
            leaves: vec![],
            signer,
            at_rest,
        };
        if path.exists() {
            log.load()?;
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(log)
    }

    /// AAD binding a sealed record to its log and position (defends against on-disk
    /// record relocation/reordering, on top of the hash chain).
    fn record_aad(&self, seq: u64) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"secgit/audit-record/v1\0");
        aad.extend_from_slice(self.log_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(&seq.to_le_bytes());
        aad
    }

    /// Decode one persisted line into the JSON bytes of a `LogEntry` (decrypting in
    /// encrypted mode).
    fn decode_record(&self, seq: u64, line: &str) -> Result<Vec<u8>> {
        match &self.at_rest {
            None => Ok(line.as_bytes().to_vec()),
            Some(key) => {
                let ct = hex::decode(line.trim())
                    .map_err(|_| AuditError::Integrity("audit record not valid hex"))?;
                Ok(aead::open(key, &self.record_aad(seq), &ct)?)
            }
        }
    }

    /// Encode a `LogEntry`'s JSON bytes into a persisted line (encrypting in encrypted
    /// mode).
    fn encode_record(&self, seq: u64, json: &[u8]) -> Result<String> {
        match &self.at_rest {
            None => Ok(String::from_utf8_lossy(json).into_owned()),
            Some(key) => {
                let ct = aead::seal(
                    secgit_crypto::DEFAULT_AEAD,
                    key,
                    &self.record_aad(seq),
                    json,
                )?;
                Ok(hex::encode(ct))
            }
        }
    }

    fn load(&mut self) -> Result<()> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut prev = [0u8; 32];
        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let json = self.decode_record(i as u64, line)?;
            let entry: LogEntry = serde_json::from_slice(&json)?;
            // Re-verify the chain on load: tamper-evidence is enforced, not assumed.
            if entry.seq != i as u64 {
                return Err(AuditError::Integrity("sequence gap"));
            }
            if entry.prev_hash != prev {
                return Err(AuditError::Integrity("broken hash chain"));
            }
            let event_json = serde_json::to_vec(&entry.event)?;
            let expect =
                compute_entry_hash(entry.seq, entry.timestamp, &entry.prev_hash, &event_json);
            if expect != entry.entry_hash {
                return Err(AuditError::Integrity("entry hash mismatch"));
            }
            prev = entry.entry_hash;
            self.leaves.push(merkle::leaf_hash(&entry.entry_hash));
            self.entries.push(entry);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn root(&self) -> Hash {
        merkle::root(&self.leaves)
    }
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Append an event, persisting it durably and extending the chain + tree.
    pub fn append(&mut self, event: AuditEvent) -> Result<LogEntry> {
        let seq = self.entries.len() as u64;
        let prev = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);
        let ts = now();
        let event_json = serde_json::to_vec(&event)?;
        let entry_hash = compute_entry_hash(seq, ts, &prev, &event_json);
        let entry = LogEntry {
            seq,
            timestamp: ts,
            prev_hash: prev,
            event,
            entry_hash,
        };

        // Persist (append-only) before updating in-memory state. In encrypted mode the
        // record is AEAD-sealed so the operator never sees event metadata at rest.
        let json = serde_json::to_vec(&entry)?;
        let line = self.encode_record(seq, &json)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        f.sync_all()?;

        self.leaves.push(merkle::leaf_hash(&entry.entry_hash));
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Produce a freshly signed checkpoint for the current tree state.
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let tree_size = self.entries.len() as u64;
        let root_hash = self.root();
        let ts = now();
        let bytes = Checkpoint::signed_bytes(&self.log_id, tree_size, &root_hash, ts);
        let sig = self.signer.sign(&bytes)?;
        Ok(Checkpoint {
            log_id: self.log_id.clone(),
            tree_size,
            root_hash,
            timestamp: ts,
            signature_hex: hex::encode(sig),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Inclusion proof for entry `seq` against the current tree.
    pub fn inclusion_proof(&self, seq: usize) -> Option<(Hash, Vec<Hash>)> {
        if seq >= self.leaves.len() {
            return None;
        }
        Some((self.leaves[seq], merkle::inclusion_proof(&self.leaves, seq)))
    }

    /// Consistency proof from an earlier `tree_size` to the current tree.
    pub fn consistency_proof(&self, old_size: usize) -> Option<Vec<Hash>> {
        if old_size == 0 || old_size > self.leaves.len() {
            return None;
        }
        Some(merkle::consistency_proof(&self.leaves, old_size))
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(s).map_err(serde::de::Error::custom)?;
        if b.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hash"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::SigScheme;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("secgit-audit-{}-{}.log", tag, std::process::id()))
    }

    fn signer() -> SigningKey {
        SigningKey::generate_with_bundle(SigScheme::Ed25519MlDsa87)
            .unwrap()
            .0
    }

    #[test]
    fn append_chain_inclusion_and_signed_checkpoint() {
        let path = tmp("basic");
        let _ = std::fs::remove_file(&path);
        let mut log = TransparencyLog::open(&path, "secgit-test-log", signer()).unwrap();

        for i in 0..5 {
            log.append(AuditEvent::RepoCreated {
                repo_id: format!("r{i}"),
                owner: "alice".into(),
            })
            .unwrap();
        }
        assert_eq!(log.len(), 5);

        // Inclusion proof for entry 2 verifies against the root.
        let (leaf, proof) = log.inclusion_proof(2).unwrap();
        assert!(merkle::verify_inclusion(&leaf, 2, 5, &proof, &log.root()));

        // Signed checkpoint verifies with the log's PQC verifying key.
        let cp = log.checkpoint().unwrap();
        cp.verify(&log.verifying_key()).unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopen_reverifies_chain_and_supports_consistency() {
        let path = tmp("reopen");
        let _ = std::fs::remove_file(&path);
        let vk;
        let root_at_3;
        {
            let mut log = TransparencyLog::open(&path, "L", signer()).unwrap();
            for i in 0..3 {
                log.append(AuditEvent::Admin {
                    action: format!("a{i}"),
                    actor: "root".into(),
                })
                .unwrap();
            }
            root_at_3 = log.root();
            vk = log.verifying_key();
            let _ = vk;
        }
        // Reopen, append more, and prove the new tree is consistent with the old one.
        let mut log = TransparencyLog::open(&path, "L", signer()).unwrap();
        assert_eq!(log.len(), 3);
        for i in 0..2 {
            log.append(AuditEvent::Admin {
                action: format!("b{i}"),
                actor: "root".into(),
            })
            .unwrap();
        }
        let proof = log.consistency_proof(3).unwrap();
        assert!(merkle::verify_consistency(
            3,
            5,
            &proof,
            &root_at_3,
            &log.root()
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_log_hides_metadata_but_stays_verifiable() {
        let path = tmp("encrypted");
        let _ = std::fs::remove_file(&path);
        let key = SymKey::generate().unwrap();
        let secret_repo = "acme-private-merger-target";

        let (vk, root, leaf, proof, n);
        {
            let mut log =
                TransparencyLog::open_encrypted(&path, "L", signer(), key.clone()).unwrap();
            log.append(AuditEvent::RepoCreated {
                repo_id: secret_repo.into(),
                owner: "ceo@acme".into(),
            })
            .unwrap();
            log.append(AuditEvent::RefUpdated {
                repo_id: secret_repo.into(),
                reference: "refs/heads/main".into(),
                old: "0".repeat(40),
                new: "f".repeat(40),
                actor: "ceo@acme".into(),
            })
            .unwrap();
            n = log.len();
            root = log.root();
            vk = log.verifying_key();
            (leaf, proof) = log.inclusion_proof(0).unwrap();
            // Checkpoint signs only the Merkle root — public, metadata-free.
            log.checkpoint().unwrap().verify(&vk).unwrap();
        }

        // LEAK TEST: the on-disk log must not contain any plaintext metadata.
        let raw = std::fs::read(&path).unwrap();
        for needle in [
            secret_repo.as_bytes(),
            b"ceo@acme".as_slice(),
            b"refs/heads/main".as_slice(),
            b"RepoCreated".as_slice(),
        ] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle),
                "plaintext metadata leaked to audit log on disk: {:?}",
                String::from_utf8_lossy(needle)
            );
        }

        // Public verifiability holds with no key: inclusion proof + checkpoint sig.
        assert!(merkle::verify_inclusion(&leaf, 0, n, &proof, &root));

        // Reopening with the WRONG key must fail (records are authenticated).
        assert!(
            TransparencyLog::open_encrypted(&path, "L", signer(), SymKey::generate().unwrap())
                .is_err()
        );

        // Reopening with the right key restores + re-verifies the chain.
        let log2 = TransparencyLog::open_encrypted(&path, "L", signer(), key).unwrap();
        assert_eq!(log2.len(), n);
        assert_eq!(log2.root(), root);

        let _ = std::fs::remove_file(&path);
    }

    /// The audit-log metadata boundary, expressed through the shared `secgit-leaktest`
    /// harness: a unique canary embedded in repo_id/owner/ref metadata must be absent from
    /// every operator-visible file at rest, while the log stays publicly verifiable.
    /// CI(mock).
    #[test]
    fn metadata_boundary_via_leaktest_harness() {
        use secgit_leaktest::{assert_dir_ciphertext_nonempty, Canary};

        let dir = std::env::temp_dir().join(format!("secgit-audit-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let key = SymKey::generate().unwrap();

        // Unique canaries planted into each metadata field that must never hit the disk.
        let repo = Canary::new("repo");
        let owner = Canary::new("owner");
        let reference = Canary::new("ref");

        let (root, leaf, proof, n);
        {
            let mut log =
                TransparencyLog::open_encrypted(&path, "L", signer(), key.clone()).unwrap();
            log.append(AuditEvent::RepoCreated {
                repo_id: repo.as_str().into(),
                owner: owner.as_str().into(),
            })
            .unwrap();
            log.append(AuditEvent::RefUpdated {
                repo_id: repo.as_str().into(),
                reference: reference.as_str().into(),
                old: "0".repeat(40),
                new: "f".repeat(40),
                actor: owner.as_str().into(),
            })
            .unwrap();
            n = log.len();
            root = log.root();
            (leaf, proof) = log.inclusion_proof(0).unwrap();
            // Checkpoint signs only the Merkle root — public, metadata-free — and verifies
            // with this log's own PQC key (no at-rest key needed by a relying party).
            log.checkpoint()
                .unwrap()
                .verify(&log.verifying_key())
                .unwrap();
        }

        // Operator's disk: NONE of the canaries (or the event tag) may appear in plaintext.
        assert_dir_ciphertext_nonempty(
            &dir,
            &[
                repo.as_bytes(),
                owner.as_bytes(),
                reference.as_bytes(),
                b"RepoCreated",
                b"RefUpdated",
            ],
        );

        // Public verifiability is unaffected: inclusion proof needs no key at all.
        assert!(merkle::verify_inclusion(&leaf, 0, n, &proof, &root));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_file_is_rejected_on_load() {
        let path = tmp("corrupt");
        let _ = std::fs::remove_file(&path);
        {
            let mut log = TransparencyLog::open(&path, "L", signer()).unwrap();
            log.append(AuditEvent::Admin {
                action: "x".into(),
                actor: "r".into(),
            })
            .unwrap();
            log.append(AuditEvent::Admin {
                action: "y".into(),
                actor: "r".into(),
            })
            .unwrap();
        }
        // Flip a byte in the persisted log; reopening must fail the integrity check.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content = content.replacen("\"x\"", "\"X\"", 1);
        std::fs::write(&path, content).unwrap();
        assert!(TransparencyLog::open(&path, "L", signer()).is_err());

        let _ = std::fs::remove_file(&path);
    }
}
