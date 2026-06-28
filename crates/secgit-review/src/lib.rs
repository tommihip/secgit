//! # secgit-review
//!
//! The pull-request / code-review workflow engine. It is **storage-driven and
//! framework-agnostic**: all state (PRs, review threads, line comments, suggestions,
//! approvals, status checks, branch-protection rules) is persisted through
//! [`secgit_store::EncryptedStore`], so every byte of review metadata is ciphertext on the
//! operator's disk. The server/API layers render and mutate this; the merge-gating policy
//! lives here and is unit-tested.

pub mod model;

pub use model::{
    BranchProtection, CheckState, Comment, Issue, IssueState, PrState, PullRequest, Review,
    ReviewState, ReviewThread, StatusCheck,
};

use secgit_store::EncryptedStore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReviewError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = core::result::Result<T, ReviewError>;

/// Review-engine handle over a borrowed encrypted store.
pub struct Reviews<'a> {
    store: &'a EncryptedStore,
}

/// Why a PR can or cannot be merged (the gating result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeStatus {
    pub mergeable: bool,
    pub approvals: u32,
    pub required_approvals: u32,
    pub changes_requested: bool,
    pub failing_or_missing_checks: Vec<String>,
    pub reasons: Vec<String>,
}

impl<'a> Reviews<'a> {
    pub fn new(store: &'a EncryptedStore) -> Self {
        Self { store }
    }

    // ---- Pull requests -------------------------------------------------------

    /// Open a new PR, assigning the next per-repo number.
    #[allow(clippy::too_many_arguments)]
    pub fn open_pr(
        &self,
        repo_id: &str,
        author_id: &str,
        title: &str,
        description: &str,
        source_branch: &str,
        target_branch: &str,
        head_sha: &str,
        now: u64,
    ) -> Result<PullRequest> {
        let number = self.next_number(repo_id)?;
        let pr = PullRequest {
            id: format!("pr_{repo_id}_{number}"),
            repo_id: repo_id.to_string(),
            number,
            title: title.to_string(),
            description: description.to_string(),
            author_id: author_id.to_string(),
            source_branch: source_branch.to_string(),
            target_branch: target_branch.to_string(),
            head_sha: head_sha.to_string(),
            state: PrState::Open,
            created_at: now,
            updated_at: now,
        };
        self.put(repo_id, &okey("pr", &pr.id), &pr)?;
        self.index_add(repo_id, "pr/index", &pr.id)?;
        Ok(pr)
    }

    pub fn get_pr(&self, repo_id: &str, pr_id: &str) -> Result<Option<PullRequest>> {
        self.get(repo_id, &okey("pr", pr_id))
    }

    /// Insert or replace a PR verbatim (used by the GitHub importer to preserve upstream
    /// numbers/ids). Unlike [`Self::open_pr`], it does not allocate a new number.
    pub fn put_pr(&self, pr: &PullRequest) -> Result<()> {
        self.put(&pr.repo_id, &okey("pr", &pr.id), pr)?;
        self.index_add(&pr.repo_id, "pr/index", &pr.id)
    }

    pub fn list_prs(&self, repo_id: &str) -> Result<Vec<PullRequest>> {
        let mut out = vec![];
        for id in self.index(repo_id, "pr/index")? {
            if let Some(pr) = self.get_pr(repo_id, &id)? {
                out.push(pr);
            }
        }
        out.sort_by(|a, b| b.number.cmp(&a.number));
        Ok(out)
    }

    /// Record a new head SHA (e.g. after a push to the PR branch). When the target's
    /// protection requests it, prior approvals become stale (handled in [`Self::merge_status`]).
    pub fn update_head(&self, repo_id: &str, pr_id: &str, head_sha: &str, now: u64) -> Result<()> {
        let mut pr = self
            .get_pr(repo_id, pr_id)?
            .ok_or_else(|| ReviewError::NotFound(pr_id.into()))?;
        pr.head_sha = head_sha.to_string();
        pr.updated_at = now;
        self.put(repo_id, &okey("pr", pr_id), &pr)
    }

    pub fn set_pr_state(&self, repo_id: &str, pr_id: &str, state: PrState, now: u64) -> Result<()> {
        let mut pr = self
            .get_pr(repo_id, pr_id)?
            .ok_or_else(|| ReviewError::NotFound(pr_id.into()))?;
        pr.state = state;
        pr.updated_at = now;
        self.put(repo_id, &okey("pr", pr_id), &pr)
    }

    // ---- Issues --------------------------------------------------------------

    /// Insert or replace an issue (used by native issue creation and the GitHub importer,
    /// which preserves the upstream issue number).
    pub fn put_issue(&self, issue: &Issue) -> Result<()> {
        self.put(&issue.repo_id, &okey("issue", &issue.id), issue)?;
        self.index_add(&issue.repo_id, "issue/index", &issue.id)
    }

    pub fn get_issue(&self, repo_id: &str, issue_id: &str) -> Result<Option<Issue>> {
        self.get(repo_id, &okey("issue", issue_id))
    }

    pub fn list_issues(&self, repo_id: &str) -> Result<Vec<Issue>> {
        let mut out = vec![];
        for id in self.index(repo_id, "issue/index")? {
            if let Some(i) = self.get_issue(repo_id, &id)? {
                out.push(i);
            }
        }
        out.sort_by(|a, b| b.number.cmp(&a.number));
        Ok(out)
    }

    // ---- Threads & comments --------------------------------------------------

    pub fn add_thread(&self, repo_id: &str, thread: &ReviewThread) -> Result<()> {
        self.put(repo_id, &okey("thread", &thread.id), thread)?;
        self.index_add(
            repo_id,
            &format!("thread/index/{}", thread.pr_id),
            &thread.id,
        )
    }

    pub fn add_comment(&self, repo_id: &str, thread_id: &str, comment: Comment) -> Result<()> {
        let mut thread: ReviewThread = self
            .get(repo_id, &okey("thread", thread_id))?
            .ok_or_else(|| ReviewError::NotFound(thread_id.into()))?;
        thread.comments.push(comment);
        self.put(repo_id, &okey("thread", thread_id), &thread)
    }

    pub fn resolve_thread(&self, repo_id: &str, thread_id: &str, resolved: bool) -> Result<()> {
        let mut thread: ReviewThread = self
            .get(repo_id, &okey("thread", thread_id))?
            .ok_or_else(|| ReviewError::NotFound(thread_id.into()))?;
        thread.resolved = resolved;
        self.put(repo_id, &okey("thread", thread_id), &thread)
    }

    pub fn list_threads(&self, repo_id: &str, pr_id: &str) -> Result<Vec<ReviewThread>> {
        let mut out = vec![];
        for id in self.index(repo_id, &format!("thread/index/{pr_id}"))? {
            if let Some(t) = self.get::<ReviewThread>(repo_id, &okey("thread", &id))? {
                out.push(t);
            }
        }
        Ok(out)
    }

    // ---- Reviews -------------------------------------------------------------

    pub fn submit_review(&self, repo_id: &str, review: &Review) -> Result<()> {
        self.put(repo_id, &okey("review", &review.id), review)?;
        self.index_add(
            repo_id,
            &format!("review/index/{}", review.pr_id),
            &review.id,
        )
    }

    pub fn list_reviews(&self, repo_id: &str, pr_id: &str) -> Result<Vec<Review>> {
        let mut out = vec![];
        for id in self.index(repo_id, &format!("review/index/{pr_id}"))? {
            if let Some(r) = self.get::<Review>(repo_id, &okey("review", &id))? {
                out.push(r);
            }
        }
        Ok(out)
    }

    // ---- Status checks -------------------------------------------------------

    pub fn report_check(&self, repo_id: &str, check: &StatusCheck) -> Result<()> {
        let key = format!("check/{}/{}", check.pr_id, check.context);
        self.put(repo_id, &key, check)?;
        self.index_add(
            repo_id,
            &format!("check/index/{}", check.pr_id),
            &check.context,
        )
    }

    pub fn list_checks(&self, repo_id: &str, pr_id: &str) -> Result<Vec<StatusCheck>> {
        let mut out = vec![];
        for ctx in self.index(repo_id, &format!("check/index/{pr_id}"))? {
            if let Some(c) = self.get::<StatusCheck>(repo_id, &format!("check/{pr_id}/{ctx}"))? {
                out.push(c);
            }
        }
        Ok(out)
    }

    // ---- Branch protection ---------------------------------------------------

    pub fn set_protection(&self, p: &BranchProtection) -> Result<()> {
        self.put(&p.repo_id, &format!("protection/{}", p.branch), p)
    }

    pub fn get_protection(&self, repo_id: &str, branch: &str) -> Result<Option<BranchProtection>> {
        self.get(repo_id, &format!("protection/{branch}"))
    }

    /// Whether a direct (non-PR) push to `branch` is allowed.
    pub fn direct_push_allowed(&self, repo_id: &str, branch: &str) -> Result<bool> {
        Ok(match self.get_protection(repo_id, branch)? {
            Some(p) => !p.block_direct_push,
            None => true,
        })
    }

    // ---- Merge gating (the policy core) -------------------------------------

    /// Compute whether `pr` may be merged given its target branch's protection.
    pub fn merge_status(&self, pr: &PullRequest) -> Result<MergeStatus> {
        let protection = self
            .get_protection(&pr.repo_id, &pr.target_branch)?
            .unwrap_or_else(|| BranchProtection::unprotected(&pr.repo_id, &pr.target_branch));

        // Latest review per reviewer (optionally only those matching the current head).
        let reviews = self.list_reviews(&pr.repo_id, &pr.id)?;
        let mut latest: HashMap<String, &Review> = HashMap::new();
        for r in &reviews {
            if protection.dismiss_stale_approvals && r.head_sha != pr.head_sha {
                continue;
            }
            latest
                .entry(r.reviewer_id.clone())
                .and_modify(|cur| {
                    if r.created_at >= cur.created_at {
                        *cur = r;
                    }
                })
                .or_insert(r);
        }
        let approvals = latest
            .values()
            .filter(|r| r.state == ReviewState::Approved)
            .count() as u32;
        let changes_requested = latest
            .values()
            .any(|r| r.state == ReviewState::ChangesRequested);

        // Required checks must be green at the current head.
        let checks = self.list_checks(&pr.repo_id, &pr.id)?;
        let mut failing = vec![];
        for ctx in &protection.required_checks {
            let ok = checks.iter().any(|c| {
                &c.context == ctx && c.state == CheckState::Success && c.head_sha == pr.head_sha
            });
            if !ok {
                failing.push(ctx.clone());
            }
        }

        let mut reasons = vec![];
        if pr.state != PrState::Open {
            reasons.push("pull request is not open".to_string());
        }
        if changes_requested {
            reasons.push("changes requested by a reviewer".to_string());
        }
        if approvals < protection.required_approvals {
            reasons.push(format!(
                "needs {} approval(s), has {}",
                protection.required_approvals, approvals
            ));
        }
        if !failing.is_empty() {
            reasons.push(format!("required checks not green: {}", failing.join(", ")));
        }

        Ok(MergeStatus {
            mergeable: reasons.is_empty(),
            approvals,
            required_approvals: protection.required_approvals,
            changes_requested,
            failing_or_missing_checks: failing,
            reasons,
        })
    }

    // ---- internals -----------------------------------------------------------

    fn next_number(&self, repo_id: &str) -> Result<u64> {
        let cur: Option<u64> = self.get(repo_id, "pr/counter")?;
        let next = cur.unwrap_or(0) + 1;
        self.put(repo_id, "pr/counter", &next)?;
        Ok(next)
    }

    fn put<T: Serialize>(&self, repo_id: &str, key: &str, v: &T) -> Result<()> {
        let bytes = serde_json::to_vec(v).map_err(|e| ReviewError::Serde(e.to_string()))?;
        self.store
            .put(repo_id, key, &bytes)
            .map_err(|e| ReviewError::Storage(e.to_string()))
    }

    fn get<T: DeserializeOwned>(&self, repo_id: &str, key: &str) -> Result<Option<T>> {
        match self
            .store
            .get(repo_id, key)
            .map_err(|e| ReviewError::Storage(e.to_string()))?
        {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| ReviewError::Serde(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn index(&self, repo_id: &str, key: &str) -> Result<Vec<String>> {
        Ok(self.get(repo_id, key)?.unwrap_or_default())
    }

    fn index_add(&self, repo_id: &str, key: &str, id: &str) -> Result<()> {
        let mut ids = self.index(repo_id, key)?;
        if !ids.iter().any(|x| x == id) {
            ids.push(id.to_string());
            self.put(repo_id, key, &ids)?;
        }
        Ok(())
    }
}

fn okey(kind: &str, id: &str) -> String {
    format!("{kind}/{id}")
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
            std::env::temp_dir().join(format!("secgit-review-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (
            EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap(),
            dir,
        )
    }

    fn review(pr: &str, reviewer: &str, state: ReviewState, head: &str, t: u64) -> Review {
        Review {
            id: format!("rv_{reviewer}_{t}"),
            pr_id: pr.to_string(),
            reviewer_id: reviewer.to_string(),
            state,
            head_sha: head.to_string(),
            created_at: t,
        }
    }

    #[test]
    fn pr_lifecycle_and_threads() {
        let (s, dir) = store("life");
        let r = Reviews::new(&s);
        let pr = r
            .open_pr(
                "repo",
                "u_a",
                "Add feature",
                "desc",
                "feat",
                "main",
                "sha1",
                1,
            )
            .unwrap();
        assert_eq!(pr.number, 1);
        let pr2 = r
            .open_pr("repo", "u_a", "Another", "", "x", "main", "sha2", 2)
            .unwrap();
        assert_eq!(pr2.number, 2);
        assert_eq!(r.list_prs("repo").unwrap().len(), 2);

        let thread = ReviewThread {
            id: "t1".into(),
            pr_id: pr.id.clone(),
            path: "src/main.rs".into(),
            line: 10,
            resolved: false,
            comments: vec![Comment {
                id: "c1".into(),
                author_id: "u_b".into(),
                body: "nit".into(),
                suggestion: Some("let y = 1;".into()),
                created_at: 3,
            }],
        };
        r.add_thread("repo", &thread).unwrap();
        r.add_comment(
            "repo",
            "t1",
            Comment {
                id: "c2".into(),
                author_id: "u_a".into(),
                body: "fixed".into(),
                suggestion: None,
                created_at: 4,
            },
        )
        .unwrap();
        r.resolve_thread("repo", "t1", true).unwrap();
        let threads = r.list_threads("repo", &pr.id).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].comments.len(), 2);
        assert!(threads[0].resolved);
        assert_eq!(
            threads[0].comments[0].suggestion.as_deref(),
            Some("let y = 1;")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_gating_requires_approvals_and_checks() {
        let (s, dir) = store("gate");
        let r = Reviews::new(&s);
        let pr = r
            .open_pr("repo", "u_a", "t", "", "feat", "main", "sha1", 1)
            .unwrap();
        r.set_protection(&BranchProtection {
            repo_id: "repo".into(),
            branch: "main".into(),
            required_approvals: 2,
            required_checks: vec!["ci".into()],
            block_direct_push: true,
            dismiss_stale_approvals: true,
        })
        .unwrap();

        // No approvals, no checks -> not mergeable.
        let st = r.merge_status(&pr).unwrap();
        assert!(!st.mergeable);
        assert_eq!(st.approvals, 0);
        assert!(st.failing_or_missing_checks.contains(&"ci".to_string()));

        // One approval, changes requested by another -> still blocked.
        r.submit_review(
            "repo",
            &review(&pr.id, "u_b", ReviewState::Approved, "sha1", 5),
        )
        .unwrap();
        r.submit_review(
            "repo",
            &review(&pr.id, "u_c", ReviewState::ChangesRequested, "sha1", 6),
        )
        .unwrap();
        let st = r.merge_status(&pr).unwrap();
        assert!(st.changes_requested);
        assert!(!st.mergeable);

        // u_c re-approves (newer review supersedes), add a second approver, green check.
        r.submit_review(
            "repo",
            &review(&pr.id, "u_c", ReviewState::Approved, "sha1", 7),
        )
        .unwrap();
        r.report_check(
            "repo",
            &StatusCheck {
                pr_id: pr.id.clone(),
                context: "ci".into(),
                state: CheckState::Success,
                description: "passed".into(),
                head_sha: "sha1".into(),
            },
        )
        .unwrap();
        let st = r.merge_status(&pr).unwrap();
        assert_eq!(st.approvals, 2, "latest review per reviewer counts");
        assert!(!st.changes_requested);
        assert!(
            st.mergeable,
            "two approvals + green check should merge: {:?}",
            st.reasons
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_push_dismisses_stale_approvals() {
        let (s, dir) = store("stale");
        let r = Reviews::new(&s);
        let pr = r
            .open_pr("repo", "u_a", "t", "", "feat", "main", "sha1", 1)
            .unwrap();
        r.set_protection(&BranchProtection {
            repo_id: "repo".into(),
            branch: "main".into(),
            required_approvals: 1,
            required_checks: vec![],
            block_direct_push: true,
            dismiss_stale_approvals: true,
        })
        .unwrap();
        r.submit_review(
            "repo",
            &review(&pr.id, "u_b", ReviewState::Approved, "sha1", 5),
        )
        .unwrap();
        assert!(r.merge_status(&pr).unwrap().mergeable);

        // New push -> head changes -> old approval (for sha1) is dismissed.
        r.update_head("repo", &pr.id, "sha2", 6).unwrap();
        let pr = r.get_pr("repo", &pr.id).unwrap().unwrap();
        let st = r.merge_status(&pr).unwrap();
        assert_eq!(st.approvals, 0);
        assert!(!st.mergeable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_branch_blocks_direct_push() {
        let (s, dir) = store("prot");
        let r = Reviews::new(&s);
        assert!(
            r.direct_push_allowed("repo", "main").unwrap(),
            "unprotected by default"
        );
        r.set_protection(&BranchProtection {
            repo_id: "repo".into(),
            branch: "main".into(),
            required_approvals: 1,
            required_checks: vec![],
            block_direct_push: true,
            dismiss_stale_approvals: false,
        })
        .unwrap();
        assert!(!r.direct_push_allowed("repo", "main").unwrap());
        assert!(r.direct_push_allowed("repo", "feature").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn review_metadata_is_ciphertext_on_disk() {
        use secgit_leaktest::{assert_dir_ciphertext_nonempty, Canary};
        let canary = Canary::new("pr-title");
        let dir = std::env::temp_dir().join(format!("secgit-review-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
            let r = Reviews::new(&s);
            r.open_pr(
                "repo",
                "u_a",
                canary.as_str(),
                "",
                "feat",
                "main",
                "sha1",
                1,
            )
            .unwrap();
        }
        assert_dir_ciphertext_nonempty(&dir, &[canary.as_bytes()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
