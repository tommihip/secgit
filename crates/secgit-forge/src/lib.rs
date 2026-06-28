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

use secgit_store::EncryptedStore;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

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
}

pub type Result<T> = core::result::Result<T, ForgeError>;

const BUNDLE_KEY: &str = "repo.bundle";

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

    /// Seal the repo to encrypted storage: `git bundle --all` -> encrypted object.
    pub fn seal_to_store(&self, repo_id: &str, store: &EncryptedStore) -> Result<()> {
        let path = self.repo_path(repo_id);
        if !path.exists() {
            return Err(ForgeError::NotFound(repo_id.into()));
        }
        let bundle_path = path.with_extension("bundle.tmp");
        run_git(
            &path,
            &["bundle", "create", bundle_path.to_str().unwrap(), "--all"],
        )?;
        let bytes = std::fs::read(&bundle_path)?;
        let _ = std::fs::remove_file(&bundle_path);
        store.init_repo(repo_id)?;
        store.put(repo_id, BUNDLE_KEY, &bytes)?;
        Ok(())
    }

    /// Restore a repo from encrypted storage by decrypting its bundle and cloning it
    /// bare onto the working path. Returns false if no bundle exists.
    pub fn restore_from_store(&self, repo_id: &str, store: &EncryptedStore) -> Result<bool> {
        let Some(bytes) = store.get(repo_id, BUNDLE_KEY)? else {
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
pub fn run_git_bytes(cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(cwd).args(args).output()?;
    if !output.status.success() {
        return Err(ForgeError::Git(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
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
}
