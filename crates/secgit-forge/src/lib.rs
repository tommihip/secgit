//! # secgit-forge
//!
//! The minimal forge floor. The boundary with the confidential layer is explicit:
//!
//! - **Reads** (refs, HEAD, metadata) go through gitoxide (`gix`) — pure Rust.
//! - **Transfer / pack work** shells out to canonical `git` (`git-upload-pack` /
//!   `git-receive-pack`, exercised by `secgit-git`), because `[VERIFY]` gitoxide has
//!   no server-side `receive-pack` and only a nascent `upload-pack`. This keeps the
//!   forge Rust while using git as the proven pack engine.
//! - **At-rest persistence** is encrypted: a repo is serialized as a `git bundle` and
//!   stored through [`secgit_store::EncryptedStore`] under the repo's DEK, so repo data
//!   on disk outside the working set is ciphertext.
//!
//! Plaintext git objects exist only on the working path *inside the TEE* (ideally a
//! tmpfs/`ramfs` mount); the encrypted bundle is the durable artifact.

use secgit_store::{EncryptedStore, LEGACY_BUNDLE_KEY};
use serde::{Deserialize, Serialize};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default wall-clock cap for any `git` subprocess (bundle/seal, reads, pack work).
///
/// A public sandbox must not let a single request pin a git process indefinitely. The
/// cap is generous for legitimate operations on size-capped repos but bounds pathological
/// or hostile inputs. Overridable with `SECGIT_GIT_TIMEOUT_SECS`.
const DEFAULT_GIT_TIMEOUT_SECS: u64 = 120;

fn git_timeout() -> Duration {
    let secs = std::env::var("SECGIT_GIT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_GIT_TIMEOUT_SECS);
    Duration::from_secs(secs.max(1))
}

#[derive(Error, Debug)]
pub enum ForgeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("git command failed: {0}")]
    Git(String),
    #[error("gix error: {0}")]
    Gix(String),
    #[error("store error: {0}")]
    Store(#[from] secgit_store::StoreError),
    #[error("repo not found: {0}")]
    NotFound(String),
    #[error("seal manifest error: {0}")]
    Manifest(String),
}

pub type Result<T> = core::result::Result<T, ForgeError>;

/// Current on-disk seal-manifest schema version.
const SEAL_MANIFEST_VERSION: u32 = 1;

/// Default cap on the number of seal segments before a full re-seal (compaction) folds
/// them back into a single base. Bounds restore cost and per-repo object count while
/// keeping the common push O(delta). Overridable with `SECGIT_SEAL_MAX_SEGMENTS`.
const DEFAULT_MAX_SEGMENTS: u32 = 32;

fn max_segments() -> u32 {
    std::env::var("SECGIT_SEAL_MAX_SEGMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_MAX_SEGMENTS)
}

/// A git ref and the object it points at, captured at seal time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RefTip {
    name: String,
    oid: String,
}

/// One append-only seal segment: an encrypted git bundle plus the cumulative ref state the
/// repo is at *after* applying this segment (and all earlier ones). A payload-less segment
/// (`has_payload == false`) records a refs-only change (e.g. a branch deletion or a ref
/// moved to an already-sealed commit) that introduced no new git objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Segment {
    index: u32,
    has_payload: bool,
    size: u64,
    tips: Vec<RefTip>,
}

/// The append-only manifest describing how a repo is sealed incrementally.
///
/// Stored (encrypted, under the repo DEK) at [`secgit_store::SEAL_MANIFEST_KEY`]. Segment
/// 0 is a full `git bundle --all` base; each later segment is an O(delta) bundle carrying
/// only the objects reachable from the new tips but not the previously-sealed tips. Restore
/// unbundles the payload segments in order, then sets refs to the final segment's `tips`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SealManifest {
    version: u32,
    #[serde(default)]
    head: Option<String>,
    segments: Vec<Segment>,
}

impl SealManifest {
    fn last_tips(&self) -> Vec<RefTip> {
        self.segments
            .last()
            .map(|s| s.tips.clone())
            .unwrap_or_default()
    }

    /// Total sealed size in bytes across all segments (for quota accounting without
    /// decrypting anything).
    fn total_size(&self) -> u64 {
        self.segments.iter().map(|s| s.size).sum()
    }
}

fn tips_oids(tips: &[RefTip]) -> Vec<String> {
    tips.iter().map(|t| t.oid.clone()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefInfo {
    pub name: String,
    pub target: String,
}

/// A commit summary for history/log views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: String,
    pub short: String,
    pub author_name: String,
    pub author_email: String,
    pub time_unix: i64,
    pub summary: String,
}

/// One entry in a tree listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    /// `blob`, `tree`, or `commit` (submodule).
    pub kind: String,
    pub id: String,
    pub name: String,
}

/// One line of `git blame` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameLine {
    pub commit_short: String,
    pub author: String,
    pub lineno: usize,
    pub content: String,
}

/// Manages bare repositories on a working path (inside the TEE) and their encrypted
/// persistence.
pub struct Forge {
    work_root: PathBuf,
}

impl Forge {
    pub fn new(work_root: impl Into<PathBuf>) -> Result<Self> {
        // Absolutize the root FIRST. `create_bare` / `restore_from_store` run
        // `git init|clone <path>` with `cwd = work_root`; if `work_root` (and hence the
        // joined repo path) is relative — e.g. the default `SECGIT_DATA=.secgit-data` —
        // git would resolve that relative path *against* `cwd`, creating the repo at a
        // doubled path while `exists()`/`rpc()` look at the un-doubled one. Making the
        // root absolute keeps all derived paths cwd-independent. `std::path::absolute`
        // does not require the path to exist and does not resolve symlinks.
        let work_root = std::path::absolute(work_root.into())?;
        std::fs::create_dir_all(&work_root)?;
        Ok(Self { work_root })
    }

    /// Working path for a repo (sanitized so a repo id can't escape the root).
    pub fn repo_path(&self, repo_id: &str) -> PathBuf {
        let safe: String = repo_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.work_root.join(format!("{safe}.git"))
    }

    pub fn exists(&self, repo_id: &str) -> bool {
        self.repo_path(repo_id).exists()
    }

    /// Create a new bare repository on the working path.
    pub fn create_bare(&self, repo_id: &str) -> Result<()> {
        let path = self.repo_path(repo_id);
        run_git(
            &self.work_root,
            &["init", "--bare", "--quiet", path.to_str().unwrap()],
        )?;
        Ok(())
    }

    /// Mirror-clone a remote repository into the working path (used by the importer).
    ///
    /// `--mirror` brings over all refs (branches, tags). The caller is responsible for
    /// sealing the result into the encrypted store. The remote URL may embed a credential
    /// (e.g. `https://x-access-token:TOKEN@github.com/...`); it is passed to `git` and not
    /// persisted — the durable artifact is the encrypted bundle, which contains only git
    /// objects, never the token.
    pub fn clone_mirror(&self, repo_id: &str, remote_url: &str) -> Result<()> {
        let path = self.repo_path(repo_id);
        if path.exists() {
            return Err(ForgeError::Git(format!("repo already exists: {repo_id}")));
        }
        run_git(
            &self.work_root,
            &[
                "clone",
                "--mirror",
                "--quiet",
                remote_url,
                path.to_str().unwrap(),
            ],
        )?;
        Ok(())
    }

    /// List references via gitoxide (read path).
    pub fn list_refs(&self, repo_id: &str) -> Result<Vec<RefInfo>> {
        let path = self.repo_path(repo_id);
        if !path.exists() {
            return Err(ForgeError::NotFound(repo_id.into()));
        }
        let repo = gix::open(&path).map_err(|e| ForgeError::Gix(e.to_string()))?;
        let platform = repo
            .references()
            .map_err(|e| ForgeError::Gix(e.to_string()))?;
        let mut out = vec![];
        for r in platform.all().map_err(|e| ForgeError::Gix(e.to_string()))? {
            let r = r.map_err(|e| ForgeError::Gix(e.to_string()))?;
            let name = r.name().as_bstr().to_string();
            let target = r.id().to_string();
            out.push(RefInfo { name, target });
        }
        Ok(out)
    }

    /// Current HEAD commit id via gitoxide, if any.
    pub fn head(&self, repo_id: &str) -> Result<Option<String>> {
        let path = self.repo_path(repo_id);
        if !path.exists() {
            return Err(ForgeError::NotFound(repo_id.into()));
        }
        let repo = gix::open(&path).map_err(|e| ForgeError::Gix(e.to_string()))?;
        let head = repo.head().map_err(|e| ForgeError::Gix(e.to_string()))?;
        Ok(head.id().map(|id| id.to_string()))
    }

    /// Commit log for `rev` (e.g. a branch or commit id), newest first, up to `limit`.
    pub fn log(&self, repo_id: &str, rev: &str, limit: usize) -> Result<Vec<CommitInfo>> {
        let path = self.require_repo(repo_id)?;
        // Unit-separated fields, record-separated by 0x1e, to survive arbitrary text.
        let fmt = "%H%x1f%h%x1f%an%x1f%ae%x1f%at%x1f%s%x1e";
        let out = run_git(
            &path,
            &[
                "log",
                &format!("--max-count={limit}"),
                &format!("--pretty=format:{fmt}"),
                rev,
            ],
        )?;
        Ok(parse_log(&out))
    }

    /// History of a single path (follows renames), newest first.
    pub fn file_history(
        &self,
        repo_id: &str,
        rev: &str,
        file: &str,
        limit: usize,
    ) -> Result<Vec<CommitInfo>> {
        let path = self.require_repo(repo_id)?;
        let fmt = "%H%x1f%h%x1f%an%x1f%ae%x1f%at%x1f%s%x1e";
        let out = run_git(
            &path,
            &[
                "log",
                "--follow",
                &format!("--max-count={limit}"),
                &format!("--pretty=format:{fmt}"),
                rev,
                "--",
                file,
            ],
        )?;
        Ok(parse_log(&out))
    }

    /// List a tree at `rev` and `dir` (empty `dir` = repo root).
    pub fn list_tree(&self, repo_id: &str, rev: &str, dir: &str) -> Result<Vec<TreeEntry>> {
        let path = self.require_repo(repo_id)?;
        let spec = if dir.is_empty() {
            rev.to_string()
        } else {
            format!("{rev}:{}", dir.trim_matches('/'))
        };
        let out = run_git(&path, &["ls-tree", "--full-tree", &spec])?;
        let mut entries = vec![];
        for line in out.lines() {
            // "<mode> <type> <id>\t<name>"
            let (meta, name) = match line.split_once('\t') {
                Some(x) => x,
                None => continue,
            };
            let mut it = meta.split_whitespace();
            let (Some(mode), Some(kind), Some(id)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            entries.push(TreeEntry {
                mode: mode.to_string(),
                kind: kind.to_string(),
                id: id.to_string(),
                name: name.to_string(),
            });
        }
        // Directories first, then files, each alphabetical.
        entries.sort_by(|a, b| {
            (a.kind != "tree")
                .cmp(&(b.kind != "tree"))
                .then(a.name.cmp(&b.name))
        });
        Ok(entries)
    }

    /// Read a blob's raw bytes at `rev:file`.
    pub fn read_blob(&self, repo_id: &str, rev: &str, file: &str) -> Result<Vec<u8>> {
        let path = self.require_repo(repo_id)?;
        run_git_bytes(
            &path,
            &[
                "cat-file",
                "blob",
                &format!("{rev}:{}", file.trim_matches('/')),
            ],
        )
    }

    /// Unified diff for a single commit (`git show`).
    pub fn commit_diff(&self, repo_id: &str, rev: &str) -> Result<String> {
        let path = self.require_repo(repo_id)?;
        run_git(
            &path,
            &["show", "--no-color", "--patch", "--format=fuller", rev],
        )
    }

    /// `git blame` for a file at `rev`, parsed from porcelain output.
    pub fn blame(&self, repo_id: &str, rev: &str, file: &str) -> Result<Vec<BlameLine>> {
        let path = self.require_repo(repo_id)?;
        let out = run_git(
            &path,
            &["blame", "--porcelain", rev, "--", file.trim_matches('/')],
        )?;
        Ok(parse_blame(&out))
    }

    fn require_repo(&self, repo_id: &str) -> Result<PathBuf> {
        let path = self.repo_path(repo_id);
        if !path.exists() {
            return Err(ForgeError::NotFound(repo_id.into()));
        }
        Ok(path)
    }

    /// Seal the repo to encrypted storage **incrementally**.
    ///
    /// Instead of re-bundling the whole repo on every push (O(repo-size)), this appends an
    /// O(delta) segment containing only the objects reachable from the new ref tips but not
    /// from the previously-sealed tips (`git bundle --all --not <old tips>`). The first seal
    /// (or a compaction) writes a full base segment; a legacy single-`repo.bundle` repo is
    /// migrated to a manifest on its next seal. When the segment count reaches
    /// [`max_segments`] the segments are compacted back into a fresh base.
    pub fn seal_to_store(&self, repo_id: &str, store: &EncryptedStore) -> Result<()> {
        let path = self.repo_path(repo_id);
        if !path.exists() {
            return Err(ForgeError::NotFound(repo_id.into()));
        }
        store.init_repo(repo_id)?;

        let tips = self.current_tips(&path)?;
        let head = self.current_head(&path);
        let mut manifest = self.load_manifest(repo_id, store)?;

        if manifest.segments.is_empty() {
            // First seal (or freshly-migrated legacy repo with no base yet): full base.
            self.write_base_segment(repo_id, store, &path, &tips, &mut manifest)?;
        } else {
            let old_tips = manifest.last_tips();
            if old_tips == tips && manifest.head == head {
                return Ok(()); // nothing changed since the last seal
            }
            if manifest.segments.len() as u32 >= max_segments() {
                self.compact_to_base(repo_id, store, &path, &tips, &mut manifest)?;
            } else {
                self.append_delta_segment(repo_id, store, &path, &old_tips, &tips, &mut manifest)?;
            }
        }

        manifest.version = SEAL_MANIFEST_VERSION;
        manifest.head = head;
        self.store_manifest(repo_id, store, &manifest)?;
        // A migrated legacy repo no longer needs its monolithic bundle object.
        let _ = store.delete(repo_id, LEGACY_BUNDLE_KEY);
        Ok(())
    }

    /// Total sealed size (bytes) for a repo, for quota accounting without decryption.
    ///
    /// Sums the segment sizes recorded in the manifest, or falls back to the legacy
    /// single-bundle object size for a not-yet-migrated repo. Returns 0 if nothing is
    /// sealed.
    pub fn sealed_size(&self, repo_id: &str, store: &EncryptedStore) -> Result<u64> {
        if let Some(bytes) = store.get_manifest(repo_id)? {
            let manifest: SealManifest =
                serde_json::from_slice(&bytes).map_err(|e| ForgeError::Manifest(e.to_string()))?;
            return Ok(manifest.total_size());
        }
        if let Some(bytes) = store.get(repo_id, LEGACY_BUNDLE_KEY)? {
            return Ok(bytes.len() as u64);
        }
        Ok(0)
    }

    /// Restore a repo from encrypted storage. Returns false if nothing is sealed.
    ///
    /// For a segmented repo: init a bare repo, unbundle every payload segment in order
    /// (each delta's prerequisites are satisfied by the earlier segments), then set refs to
    /// the final segment's cumulative tips and restore HEAD. For a legacy repo (single
    /// `repo.bundle`, no manifest) it clones the monolithic bundle as before.
    pub fn restore_from_store(&self, repo_id: &str, store: &EncryptedStore) -> Result<bool> {
        let Some(manifest_bytes) = store.get_manifest(repo_id)? else {
            return self.restore_legacy(repo_id, store);
        };
        let manifest: SealManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| ForgeError::Manifest(e.to_string()))?;

        let path = self.repo_path(repo_id);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        run_git(
            &self.work_root,
            &["init", "--bare", "--quiet", path.to_str().unwrap()],
        )?;

        for seg in &manifest.segments {
            if !seg.has_payload {
                continue;
            }
            let Some(bytes) = store.get_segment(repo_id, seg.index)? else {
                return Err(ForgeError::Store(secgit_store::StoreError::Corrupt(
                    "seal segment referenced by manifest is missing",
                )));
            };
            let bundle_path =
                self.work_root
                    .join(format!("{}.seg{}.bundle", sanitize(repo_id), seg.index));
            std::fs::write(&bundle_path, &bytes)?;
            let res = run_git(
                &path,
                &["bundle", "unbundle", bundle_path.to_str().unwrap()],
            );
            let _ = std::fs::remove_file(&bundle_path);
            res?;
        }

        // Set refs to the final cumulative state, then HEAD.
        if let Some(final_seg) = manifest.segments.last() {
            for tip in &final_seg.tips {
                run_git(&path, &["update-ref", &tip.name, &tip.oid])?;
            }
        }
        if let Some(head) = &manifest.head {
            let _ = run_git(&path, &["symbolic-ref", "HEAD", head]);
        }
        Ok(true)
    }

    /// Legacy restore path: a single `repo.bundle` object cloned bare (pre-incremental).
    fn restore_legacy(&self, repo_id: &str, store: &EncryptedStore) -> Result<bool> {
        let Some(bytes) = store.get(repo_id, LEGACY_BUNDLE_KEY)? else {
            return Ok(false);
        };
        let path = self.repo_path(repo_id);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        let bundle_path = self
            .work_root
            .join(format!("{}.restore.bundle", sanitize(repo_id)));
        std::fs::write(&bundle_path, &bytes)?;
        run_git(
            &self.work_root,
            &[
                "clone",
                "--bare",
                "--quiet",
                bundle_path.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        )?;
        let _ = std::fs::remove_file(&bundle_path);
        Ok(true)
    }

    /// Enumerate every ref and its target oid, sorted by ref name (stable comparison).
    fn current_tips(&self, path: &Path) -> Result<Vec<RefTip>> {
        // Ref names cannot contain spaces and oids are hex, so a single space is a safe
        // field separator for `for-each-ref`.
        let out = run_git(path, &["for-each-ref", "--format=%(objectname) %(refname)"])?;
        let mut tips = Vec::new();
        for line in out.lines() {
            if let Some((oid, name)) = line.split_once(' ') {
                if !oid.is_empty() && !name.is_empty() {
                    tips.push(RefTip {
                        name: name.to_string(),
                        oid: oid.to_string(),
                    });
                }
            }
        }
        tips.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(tips)
    }

    /// The HEAD symref target (e.g. `refs/heads/main`), or None if HEAD is detached.
    fn current_head(&self, path: &Path) -> Option<String> {
        run_git(path, &["symbolic-ref", "HEAD"])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn load_manifest(&self, repo_id: &str, store: &EncryptedStore) -> Result<SealManifest> {
        match store.get_manifest(repo_id)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| ForgeError::Manifest(e.to_string()))
            }
            None => Ok(SealManifest::default()),
        }
    }

    fn store_manifest(
        &self,
        repo_id: &str,
        store: &EncryptedStore,
        manifest: &SealManifest,
    ) -> Result<()> {
        let bytes =
            serde_json::to_vec(manifest).map_err(|e| ForgeError::Manifest(e.to_string()))?;
        store.put_manifest(repo_id, &bytes)?;
        Ok(())
    }

    /// Bundle the whole repo (`--all`) into segment 0, dropping any prior segments.
    fn write_base_segment(
        &self,
        repo_id: &str,
        store: &EncryptedStore,
        path: &Path,
        tips: &[RefTip],
        manifest: &mut SealManifest,
    ) -> Result<()> {
        let bytes = self.bundle_bytes(repo_id, path, &[])?;
        for seg in &manifest.segments {
            let _ = store.delete_segment(repo_id, seg.index);
        }
        store.put_segment(repo_id, 0, &bytes)?;
        manifest.segments = vec![Segment {
            index: 0,
            has_payload: true,
            size: bytes.len() as u64,
            tips: tips.to_vec(),
        }];
        Ok(())
    }

    /// Compaction: fold all segments back into a single fresh base (O(repo-size), amortized
    /// over `max_segments` pushes). Runs under the same wall-clock cap as any git op.
    fn compact_to_base(
        &self,
        repo_id: &str,
        store: &EncryptedStore,
        path: &Path,
        tips: &[RefTip],
        manifest: &mut SealManifest,
    ) -> Result<()> {
        self.write_base_segment(repo_id, store, path, tips, manifest)
    }

    /// Append an O(delta) segment carrying only objects new since `old_tips`.
    fn append_delta_segment(
        &self,
        repo_id: &str,
        store: &EncryptedStore,
        path: &Path,
        old_tips: &[RefTip],
        tips: &[RefTip],
        manifest: &mut SealManifest,
    ) -> Result<()> {
        let next = manifest.segments.last().map(|s| s.index + 1).unwrap_or(0);
        // Only exclude prerequisites that still exist (auto-gc may have pruned an
        // unreachable old tip); a missing `--not` arg would otherwise fail the bundle.
        let old_oids = self.existing_oids(path, &tips_oids(old_tips));

        let segment = if self.has_new_objects(path, &old_oids)? {
            let bytes = self.bundle_bytes(repo_id, path, &old_oids)?;
            store.put_segment(repo_id, next, &bytes)?;
            Segment {
                index: next,
                has_payload: true,
                size: bytes.len() as u64,
                tips: tips.to_vec(),
            }
        } else {
            // Refs-only change (deletion / move to an already-sealed commit): record the
            // new tips with no bundle payload.
            Segment {
                index: next,
                has_payload: false,
                size: 0,
                tips: tips.to_vec(),
            }
        };
        manifest.segments.push(segment);
        Ok(())
    }

    /// Create a bundle of `--all` optionally excluding `--not <not_oids>`; return its bytes.
    fn bundle_bytes(&self, repo_id: &str, path: &Path, not_oids: &[String]) -> Result<Vec<u8>> {
        let bundle_path = path.with_extension(format!("{}.bundle.tmp", sanitize(repo_id)));
        let bundle_str = bundle_path.to_str().unwrap().to_string();
        let mut args: Vec<&str> = vec!["bundle", "create", &bundle_str, "--all"];
        if !not_oids.is_empty() {
            args.push("--not");
            for o in not_oids {
                args.push(o.as_str());
            }
        }
        let res = run_git(path, &args);
        let bytes = match res {
            Ok(_) => std::fs::read(&bundle_path),
            Err(e) => {
                let _ = std::fs::remove_file(&bundle_path);
                return Err(e);
            }
        };
        let _ = std::fs::remove_file(&bundle_path);
        Ok(bytes?)
    }

    /// True if any object is reachable from the current refs but not from `not_oids`.
    fn has_new_objects(&self, path: &Path, not_oids: &[String]) -> Result<bool> {
        let mut args: Vec<&str> = vec!["rev-list", "--objects", "--all"];
        if !not_oids.is_empty() {
            args.push("--not");
            for o in not_oids {
                args.push(o.as_str());
            }
        }
        let out = run_git(path, &args)?;
        Ok(out.split_whitespace().next().is_some())
    }

    /// Filter `oids` down to those that still exist as objects in the repo.
    fn existing_oids(&self, path: &Path, oids: &[String]) -> Vec<String> {
        oids.iter()
            .filter(|o| run_git(path, &["cat-file", "-e", o]).is_ok())
            .cloned()
            .collect()
    }

    /// Delete a repo's working tree from the in-TEE working path. Idempotent.
    ///
    /// This reclaims the plaintext working set (e.g. after an ephemeral repo expires or a
    /// takedown). The encrypted durable artifact is removed separately via the store.
    pub fn delete(&self, repo_id: &str) -> Result<()> {
        let path = self.repo_path(repo_id);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok(())
    }

    /// List the sanitized directory stems of every materialized repo under the working
    /// root (the `<stem>.git` directories), used by the sandbox GC to find orphaned
    /// ephemeral working sets left behind by a crash/restart.
    pub fn working_dir_stems(&self) -> Vec<String> {
        let mut stems = vec![];
        let Ok(entries) = std::fs::read_dir(&self.work_root) else {
            return stems;
        };
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(stem) = name.strip_suffix(".git") {
                        stems.push(stem.to_string());
                    }
                }
            }
        }
        stems
    }
}

fn sanitize(repo_id: &str) -> String {
    repo_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Run a git subcommand in `cwd`, returning an error with stderr on failure.
pub fn run_git(cwd: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&run_git_bytes(cwd, args)?).into_owned())
}

/// Like [`run_git`] but returns raw stdout bytes (for binary blobs).
///
/// Every git subprocess is run under a wall-clock cap ([`git_timeout`]) so no single
/// request — including the O(repo-size) `git bundle` seal — can pin a process on the
/// public sandbox indefinitely.
pub fn run_git_bytes(cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd).args(args);
    let output = exec_with_timeout(cmd, git_timeout())?;
    if !output.status.success() {
        return Err(ForgeError::Git(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

/// Run a command to completion under a wall-clock deadline, killing it on timeout.
///
/// stdout/stderr are drained in dedicated threads so a chatty child cannot deadlock on a
/// full pipe while we poll for completion. On Unix the child is spawned as its own process
/// group leader and the timeout kills the whole group, so a grandchild (e.g.
/// `git pack-objects` spawned by `git bundle`) cannot linger after the parent is killed.
fn exec_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group (pgid == child pid) so the timeout kill reaches grandchildren.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let out_handle = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_pipe.read_to_end(&mut b);
        b
    });
    let err_handle = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_pipe.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(s) => break s,
            None => {
                if Instant::now() >= deadline {
                    kill_group_and_reap(&mut child);
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return Err(ForgeError::Git(format!(
                        "git subprocess exceeded the {}s wall-clock cap and was killed",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Kill the child's entire process group, then reap the direct child.
///
/// The child leads its own group (`process_group(0)`), so `kill(-pid, SIGKILL)` reaches
/// every descendant git spawned (e.g. `pack-objects` under `git bundle`). On non-Unix we
/// fall back to a direct child kill.
fn kill_group_and_reap(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // SAFETY: a negative pid signals the process group `pid`; raw FFI, no aliasing.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn parse_log(out: &str) -> Vec<CommitInfo> {
    let mut commits = vec![];
    for record in out.split('\u{1e}') {
        let record = record.trim_matches(|c| c == '\n' || c == '\r');
        if record.is_empty() {
            continue;
        }
        let f: Vec<&str> = record.split('\u{1f}').collect();
        if f.len() < 6 {
            continue;
        }
        commits.push(CommitInfo {
            id: f[0].to_string(),
            short: f[1].to_string(),
            author_name: f[2].to_string(),
            author_email: f[3].to_string(),
            time_unix: f[4].parse().unwrap_or(0),
            summary: f[5].to_string(),
        });
    }
    commits
}

fn parse_blame(out: &str) -> Vec<BlameLine> {
    let mut lines = vec![];
    let mut cur_commit = String::new();
    let mut cur_author = String::new();
    let mut cur_lineno = 0usize;
    for line in out.lines() {
        if let Some(content) = line.strip_prefix('\t') {
            lines.push(BlameLine {
                commit_short: cur_commit.chars().take(8).collect(),
                author: cur_author.clone(),
                lineno: cur_lineno,
                content: content.to_string(),
            });
        } else if let Some(rest) = line.strip_prefix("author ") {
            cur_author = rest.to_string();
        } else if line.len() >= 40 && line.as_bytes()[0].is_ascii_hexdigit() {
            // "<sha> <orig-line> <final-line> [<num-lines>]"
            let mut it = line.split_whitespace();
            if let Some(sha) = it.next() {
                if sha.len() >= 40 {
                    cur_commit = sha.to_string();
                    if let Some(final_line) = it.nth(1) {
                        cur_lineno = final_line.parse().unwrap_or(cur_lineno);
                    }
                }
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("secgit-forge-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Create a BARE repo with one commit at `path` (test fixture). The forge stores
    /// repos bare on the working path, so we build a throwaway worktree, commit, and
    /// `clone --bare` it into place — mirroring `restore_from_store`.
    fn seed_repo(path: &Path) {
        let work = path.with_extension("seed-work");
        let _ = std::fs::remove_dir_all(&work);
        run_git(
            path.parent().unwrap(),
            &["init", "--quiet", work.to_str().unwrap()],
        )
        .unwrap();
        run_git(&work, &["config", "user.email", "t@t"]).unwrap();
        run_git(&work, &["config", "user.name", "t"]).unwrap();
        std::fs::write(work.join("README.md"), b"hello").unwrap();
        run_git(&work, &["add", "."]).unwrap();
        run_git(&work, &["commit", "--quiet", "-m", "init"]).unwrap();
        run_git(
            path.parent().unwrap(),
            &[
                "clone",
                "--bare",
                "--quiet",
                work.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&work);
    }

    /// Regression: a `Forge` built from a RELATIVE root (the default
    /// `SECGIT_DATA=.secgit-data` case) must still yield absolute repo paths, so
    /// `git init --bare <path>` run with `cwd = work_root` cannot create the repo at a
    /// doubled path that later lookups miss.
    #[test]
    fn relative_root_yields_absolute_repo_paths() {
        let rel = format!("secgit-forge-rel-{}", std::process::id());
        let forge = Forge::new(&rel).unwrap();
        let p = forge.repo_path("ephemeral/abc123");
        let is_abs = p.is_absolute();
        // `create_bare` must produce a repo at exactly `repo_path`, not a doubled path.
        let created = forge.create_bare("ephemeral/abc123").is_ok();
        let exists_where_expected = forge.exists("ephemeral/abc123");
        let _ = std::fs::remove_dir_all(&rel);
        assert!(
            is_abs,
            "repo_path must be absolute even from a relative root"
        );
        assert!(created, "create_bare must succeed");
        assert!(
            exists_where_expected,
            "repo must exist at repo_path (not a doubled path)"
        );
    }

    #[test]
    fn create_list_head_seal_restore() {
        let root = tmp("e2e");
        std::fs::create_dir_all(&root).unwrap();
        let forge = Forge::new(&root).unwrap();

        // Seed a working repo at the forge's repo path.
        let repo_id = "user-alice-dots";
        let path = forge.repo_path(repo_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        seed_repo(&path);

        // gix reads.
        let refs = forge.list_refs(repo_id).unwrap();
        assert!(refs.iter().any(|r| r.name.contains("refs/heads/")));
        let head = forge.head(repo_id).unwrap();
        assert!(head.is_some());

        // Seal encrypted, wipe, restore, verify HEAD survived the round-trip.
        let store = EncryptedStore::open(root.join("store"), SymKey::generate().unwrap()).unwrap();
        forge.seal_to_store(repo_id, &store).unwrap();
        std::fs::remove_dir_all(&path).unwrap();
        assert!(!forge.exists(repo_id));
        assert!(forge.restore_from_store(repo_id, &store).unwrap());
        assert_eq!(forge.head(repo_id).unwrap(), head);

        let _ = std::fs::remove_dir_all(&root);
    }

    fn seed_multi(path: &Path) {
        let work = path.with_extension("seed-work");
        let _ = std::fs::remove_dir_all(&work);
        run_git(
            path.parent().unwrap(),
            &["init", "--quiet", work.to_str().unwrap()],
        )
        .unwrap();
        run_git(&work, &["config", "user.email", "t@t"]).unwrap();
        run_git(&work, &["config", "user.name", "Tester"]).unwrap();
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("README.md"), b"# Title\nhello world\n").unwrap();
        std::fs::write(
            work.join("src/main.rs"),
            b"fn main() {\n    let x = 1;\n}\n",
        )
        .unwrap();
        run_git(&work, &["add", "."]).unwrap();
        run_git(&work, &["commit", "--quiet", "-m", "first commit"]).unwrap();
        std::fs::write(
            work.join("src/main.rs"),
            b"fn main() {\n    let x = 2;\n}\n",
        )
        .unwrap();
        run_git(&work, &["add", "."]).unwrap();
        run_git(&work, &["commit", "--quiet", "-m", "second commit"]).unwrap();
        run_git(
            path.parent().unwrap(),
            &[
                "clone",
                "--bare",
                "--quiet",
                work.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn browse_log_tree_blob_diff_blame() {
        let root = tmp("browse");
        std::fs::create_dir_all(&root).unwrap();
        let forge = Forge::new(&root).unwrap();
        let repo_id = "browse-repo";
        let path = forge.repo_path(repo_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        seed_multi(&path);

        let log = forge.log(repo_id, "HEAD", 10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].summary, "second commit");
        assert_eq!(log[0].author_name, "Tester");

        let root_tree = forge.list_tree(repo_id, "HEAD", "").unwrap();
        // src (tree) sorts before README.md (blob)
        assert_eq!(root_tree[0].name, "src");
        assert_eq!(root_tree[0].kind, "tree");
        assert!(root_tree
            .iter()
            .any(|e| e.name == "README.md" && e.kind == "blob"));

        let src = forge.list_tree(repo_id, "HEAD", "src").unwrap();
        assert_eq!(src.len(), 1);
        assert_eq!(src[0].name, "main.rs");

        let blob = forge.read_blob(repo_id, "HEAD", "src/main.rs").unwrap();
        assert_eq!(blob, b"fn main() {\n    let x = 2;\n}\n");

        let hist = forge
            .file_history(repo_id, "HEAD", "src/main.rs", 10)
            .unwrap();
        assert_eq!(hist.len(), 2);

        let diff = forge.commit_diff(repo_id, "HEAD").unwrap();
        assert!(diff.contains("let x = 2"));
        assert!(diff.contains("second commit"));

        let blame = forge.blame(repo_id, "HEAD", "src/main.rs").unwrap();
        assert_eq!(blame.len(), 3);
        assert_eq!(blame[1].content, "    let x = 2;");
        assert_eq!(blame[1].lineno, 2);
        assert!(!blame[1].commit_short.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Serializes tests that read/write the process-global `SECGIT_SEAL_MAX_SEGMENTS`, so a
    /// compaction test's env override can't perturb another test's segment-count assertions.
    static SEAL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn load_manifest_for_test(store: &EncryptedStore, repo_id: &str) -> SealManifest {
        let bytes = store
            .get_manifest(repo_id)
            .unwrap()
            .expect("manifest should exist after a seal");
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Mirror the mutable worktree into the forge's bare repo path and seal it.
    fn mirror_and_seal(forge: &Forge, store: &EncryptedStore, repo_id: &str, work: &Path) {
        let path = forge.repo_path(repo_id);
        let _ = std::fs::remove_dir_all(&path);
        run_git(
            path.parent().unwrap(),
            &[
                "clone",
                "--bare",
                "--quiet",
                work.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        )
        .unwrap();
        forge.seal_to_store(repo_id, store).unwrap();
    }

    #[test]
    fn incremental_seal_delta_and_multi_segment_restore() {
        let _guard = SEAL_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("incremental");
        std::fs::create_dir_all(&root).unwrap();
        let forge = Forge::new(&root).unwrap();
        let store = EncryptedStore::open(root.join("store"), SymKey::generate().unwrap()).unwrap();
        let repo_id = "inc-repo";
        std::fs::create_dir_all(forge.repo_path(repo_id).parent().unwrap()).unwrap();

        // A mutable worktree we grow commit-by-commit; each stage is mirrored bare + sealed.
        let work = root.join("work");
        run_git(&root, &["init", "--quiet", work.to_str().unwrap()]).unwrap();
        run_git(&work, &["config", "user.email", "t@t"]).unwrap();
        run_git(&work, &["config", "user.name", "t"]).unwrap();

        // Seal 1: base segment (full bundle).
        std::fs::write(work.join("a.txt"), b"one").unwrap();
        run_git(&work, &["add", "."]).unwrap();
        run_git(&work, &["commit", "--quiet", "-m", "c1"]).unwrap();
        mirror_and_seal(&forge, &store, repo_id, &work);
        let m1 = load_manifest_for_test(&store, repo_id);
        assert_eq!(m1.segments.len(), 1, "first seal is a single base segment");
        assert!(m1.segments[0].has_payload);

        // Seal 2: an O(delta) segment carrying only the new commit's objects. (Absolute
        // byte size isn't asserted: at toy scale bundle/prerequisite overhead can make a
        // one-commit delta larger than a one-commit base; the delta win is asymptotic.)
        std::fs::write(work.join("b.txt"), b"two").unwrap();
        run_git(&work, &["add", "."]).unwrap();
        run_git(&work, &["commit", "--quiet", "-m", "c2"]).unwrap();
        mirror_and_seal(&forge, &store, repo_id, &work);
        let m2 = load_manifest_for_test(&store, repo_id);
        assert_eq!(m2.segments.len(), 2, "second seal appends a delta segment");
        assert!(m2.segments[1].has_payload);

        // Seal 3: a refs-only change (new branch at an existing commit) => payload-less.
        run_git(&work, &["branch", "feature"]).unwrap();
        mirror_and_seal(&forge, &store, repo_id, &work);
        let m3 = load_manifest_for_test(&store, repo_id);
        assert_eq!(m3.segments.len(), 3);
        assert!(
            !m3.segments[2].has_payload,
            "adding a branch at a sealed commit introduces no new objects"
        );

        // The expected final state, read from the live repo before we wipe it.
        let expected_head = forge.head(repo_id).unwrap();
        let expected_refs = forge.list_refs(repo_id).unwrap();

        // Restore from scratch: unbundle base + delta, replay refs, restore HEAD.
        std::fs::remove_dir_all(forge.repo_path(repo_id)).unwrap();
        assert!(!forge.exists(repo_id));
        assert!(forge.restore_from_store(repo_id, &store).unwrap());
        assert_eq!(forge.head(repo_id).unwrap(), expected_head);
        let restored_refs = forge.list_refs(repo_id).unwrap();
        assert_eq!(
            restored_refs, expected_refs,
            "all refs survive the round-trip"
        );
        // Both commits' content is present.
        assert_eq!(forge.log(repo_id, "HEAD", 10).unwrap().len(), 2);
        assert_eq!(forge.read_blob(repo_id, "HEAD", "b.txt").unwrap(), b"two");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_repo_migrates_to_manifest_on_seal() {
        let root = tmp("legacy");
        std::fs::create_dir_all(&root).unwrap();
        let forge = Forge::new(&root).unwrap();
        let store = EncryptedStore::open(root.join("store"), SymKey::generate().unwrap()).unwrap();
        let repo_id = "legacy-repo";
        let path = forge.repo_path(repo_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        seed_repo(&path);

        // Simulate a pre-incremental seal: a single `repo.bundle` object, no manifest.
        let legacy_bundle = root.join("legacy.bundle");
        run_git(
            &path,
            &["bundle", "create", legacy_bundle.to_str().unwrap(), "--all"],
        )
        .unwrap();
        store.init_repo(repo_id).unwrap();
        store
            .put(
                repo_id,
                LEGACY_BUNDLE_KEY,
                &std::fs::read(&legacy_bundle).unwrap(),
            )
            .unwrap();
        assert!(store.get_manifest(repo_id).unwrap().is_none());
        let head_before = forge.head(repo_id).unwrap();

        // Legacy restore path still works while unmigrated.
        std::fs::remove_dir_all(&path).unwrap();
        assert!(forge.restore_from_store(repo_id, &store).unwrap());
        assert_eq!(forge.head(repo_id).unwrap(), head_before);

        // A seal migrates the repo: a manifest appears and the legacy object is dropped.
        forge.seal_to_store(repo_id, &store).unwrap();
        assert!(store.get_manifest(repo_id).unwrap().is_some());
        assert_eq!(
            store.get(repo_id, LEGACY_BUNDLE_KEY).unwrap(),
            None,
            "legacy monolithic bundle removed after migration"
        );

        // Segmented restore works post-migration.
        std::fs::remove_dir_all(&path).unwrap();
        assert!(forge.restore_from_store(repo_id, &store).unwrap());
        assert_eq!(forge.head(repo_id).unwrap(), head_before);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compaction_folds_segments_into_a_fresh_base() {
        let _guard = SEAL_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("compact");
        std::fs::create_dir_all(&root).unwrap();
        let forge = Forge::new(&root).unwrap();
        let store = EncryptedStore::open(root.join("store"), SymKey::generate().unwrap()).unwrap();
        let repo_id = "compact-repo";
        std::fs::create_dir_all(forge.repo_path(repo_id).parent().unwrap()).unwrap();

        let work = root.join("work");
        run_git(&root, &["init", "--quiet", work.to_str().unwrap()]).unwrap();
        run_git(&work, &["config", "user.email", "t@t"]).unwrap();
        run_git(&work, &["config", "user.name", "t"]).unwrap();

        // Force compaction on the 3rd seal.
        std::env::set_var("SECGIT_SEAL_MAX_SEGMENTS", "2");

        for i in 0..3 {
            std::fs::write(work.join(format!("f{i}.txt")), format!("v{i}")).unwrap();
            run_git(&work, &["add", "."]).unwrap();
            run_git(&work, &["commit", "--quiet", "-m", &format!("c{i}")]).unwrap();
            mirror_and_seal(&forge, &store, repo_id, &work);
        }
        std::env::remove_var("SECGIT_SEAL_MAX_SEGMENTS");

        let m = load_manifest_for_test(&store, repo_id);
        assert_eq!(
            m.segments.len(),
            1,
            "compaction resets to a single base segment"
        );
        assert_eq!(m.segments[0].index, 0);
        // Dropped delta objects are gone.
        assert_eq!(store.get_segment(repo_id, 1).unwrap(), None);

        // Restore still yields all three commits.
        let expected_head = forge.head(repo_id).unwrap();
        std::fs::remove_dir_all(forge.repo_path(repo_id)).unwrap();
        assert!(forge.restore_from_store(repo_id, &store).unwrap());
        assert_eq!(forge.head(repo_id).unwrap(), expected_head);
        assert_eq!(forge.log(repo_id, "HEAD", 10).unwrap().len(), 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `exec_with_timeout` must kill the child's whole process group on timeout, so a
    /// grandchild (standing in for the `pack-objects` a `git bundle` spawns) cannot linger.
    #[cfg(unix)]
    #[test]
    fn timeout_kills_whole_process_group() {
        let dir = tmp("pgroup");
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("grandchild.pid");

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("sleep 300 & echo $! > {}; wait", pidfile.display()));
        let start = Instant::now();
        let res = exec_with_timeout(cmd, Duration::from_millis(300));
        assert!(res.is_err(), "expected a wall-clock timeout error");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout should fire promptly"
        );

        // Read the recorded grandchild pid.
        let mut pid = None;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                if let Ok(p) = s.trim().parse::<i32>() {
                    pid = Some(p);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = pid.expect("grandchild never recorded its pid");

        // Confirm the grandchild was killed (ESRCH), polling to let the reaper clear it.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut alive = true;
        while Instant::now() < deadline {
            // SAFETY: signal 0 is an existence/permission check only.
            if unsafe { libc::kill(pid, 0) } != 0 {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive, "grandchild pid {pid} must be killed with the group");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
