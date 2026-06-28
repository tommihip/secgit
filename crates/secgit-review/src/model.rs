//! Data model for pull requests and code review.
//!
//! All of this is **sensitive metadata** (who reviewed what, comment text, branch names),
//! so it is persisted through the encrypted store like every other forge object.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrState {
    Open,
    Merged,
    Closed,
}

/// A pull request from `source_branch` into `target_branch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: String,
    pub repo_id: String,
    pub number: u64,
    pub title: String,
    pub description: String,
    pub author_id: String,
    pub source_branch: String,
    pub target_branch: String,
    pub head_sha: String,
    pub state: PrState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueState {
    Open,
    Closed,
}

/// A tracker issue (used for native issues and for GitHub-imported issues).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    pub repo_id: String,
    pub number: u64,
    pub title: String,
    pub body: String,
    pub author_id: String,
    pub state: IssueState,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub comments: Vec<Comment>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// A single review comment, optionally carrying a suggested replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    pub author_id: String,
    pub body: String,
    /// A code suggestion (the proposed replacement text), if this is a suggestion comment.
    #[serde(default)]
    pub suggestion: Option<String>,
    pub created_at: u64,
}

/// A review thread anchored to a file + line (or PR-level when `path` is empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewThread {
    pub id: String,
    pub pr_id: String,
    /// File path the thread is anchored to (empty = general PR discussion).
    pub path: String,
    /// 1-based line number in the file (0 = file/PR-level).
    pub line: u32,
    pub resolved: bool,
    pub comments: Vec<Comment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewState {
    Approved,
    ChangesRequested,
    Commented,
}

/// A reviewer's verdict on a PR (latest verdict per reviewer wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub id: String,
    pub pr_id: String,
    pub reviewer_id: String,
    pub state: ReviewState,
    /// The PR head SHA this review applies to (so new pushes can dismiss stale approvals).
    pub head_sha: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckState {
    Pending,
    Success,
    Failure,
}

/// An external/CI status check reported against a PR head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCheck {
    pub pr_id: String,
    pub context: String,
    pub state: CheckState,
    pub description: String,
    pub head_sha: String,
}

/// Protection rules for a branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchProtection {
    pub repo_id: String,
    pub branch: String,
    pub required_approvals: u32,
    /// Status-check contexts that must be green before merge.
    pub required_checks: Vec<String>,
    /// Disallow direct pushes (force changes through PRs).
    pub block_direct_push: bool,
    /// A new push to the PR head dismisses prior approvals.
    pub dismiss_stale_approvals: bool,
}

impl BranchProtection {
    pub fn unprotected(repo_id: &str, branch: &str) -> Self {
        Self {
            repo_id: repo_id.to_string(),
            branch: branch.to_string(),
            required_approvals: 0,
            required_checks: vec![],
            block_direct_push: false,
            dismiss_stale_approvals: false,
        }
    }
}
