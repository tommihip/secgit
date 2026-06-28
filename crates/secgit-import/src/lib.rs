//! # secgit-import
//!
//! GitHub importer that runs **inside the CVM**. It is split into a transport-agnostic
//! core (this crate) and the server wiring (which provides the actual in-CVM HTTPS client
//! and the encrypted stores). The core:
//!
//! - models the subset of GitHub REST resources we import (repo, issues, pull requests,
//!   comments) in a normalized, serializable form;
//! - parses GitHub JSON into those models;
//! - drives **pagination** over a caller-supplied `Fetch` (so the network — and the secret
//!   GitHub token — stays in the server's audited in-CVM HTTPS path, and so this logic is
//!   unit-testable offline).
//!
//! The git history itself is mirror-cloned by the forge and sealed into the encrypted
//! store; this crate handles only the metadata graph. The GitHub token is used only to
//! authenticate outbound calls in memory and is never written to disk by SecGit.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ImportError {
    #[error("fetch error: {0}")]
    Fetch(String),
    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = core::result::Result<T, ImportError>;

/// Normalized repository metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedRepo {
    pub full_name: String,
    pub name: String,
    pub description: String,
    pub private: bool,
    pub default_branch: String,
    pub clone_url: String,
}

/// Normalized actor (issue/PR/comment author).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportedUser {
    pub login: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedComment {
    pub id: u64,
    pub author: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedIssue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub author: String,
    pub state: String,
    pub labels: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub comments: Vec<ImportedComment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedPull {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub author: String,
    pub state: String,
    pub merged: bool,
    pub head_ref: String,
    pub base_ref: String,
    pub head_sha: String,
    pub created_at: String,
    pub updated_at: String,
}

/// The complete metadata graph produced by a metadata import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPlan {
    pub repo: ImportedRepo,
    pub issues: Vec<ImportedIssue>,
    pub pulls: Vec<ImportedPull>,
}

/// Outbound HTTP GET, returning the body bytes. Implemented by the server over its in-CVM
/// HTTPS client (with the GitHub token + User-Agent headers applied).
pub trait Fetch {
    fn get(&self, url: &str) -> Result<Vec<u8>>;
}

impl<F> Fetch for F
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        self(url)
    }
}

/// GitHub REST client over a [`Fetch`]. `api_base` defaults to `https://api.github.com`.
pub struct GithubClient<F: Fetch> {
    fetch: F,
    api_base: String,
    per_page: u32,
    max_pages: u32,
}

impl<F: Fetch> GithubClient<F> {
    pub fn new(fetch: F) -> Self {
        Self {
            fetch,
            api_base: "https://api.github.com".to_string(),
            per_page: 100,
            max_pages: 100,
        }
    }

    /// Override the API base (e.g. for GitHub Enterprise or tests).
    pub fn with_api_base(mut self, base: &str) -> Self {
        self.api_base = base.trim_end_matches('/').to_string();
        self
    }

    fn get_json(&self, url: &str) -> Result<serde_json::Value> {
        let bytes = self.fetch.get(url)?;
        serde_json::from_slice(&bytes).map_err(|e| ImportError::Parse(e.to_string()))
    }

    /// Page through an array endpoint, accumulating until an empty page or `max_pages`.
    fn paginate(&self, path_with_query: &str) -> Result<Vec<serde_json::Value>> {
        let mut out = vec![];
        for page in 1..=self.max_pages {
            let sep = if path_with_query.contains('?') {
                '&'
            } else {
                '?'
            };
            let url = format!(
                "{}{}{}per_page={}&page={}",
                self.api_base, path_with_query, sep, self.per_page, page
            );
            let v = self.get_json(&url)?;
            let arr = v
                .as_array()
                .ok_or_else(|| ImportError::Parse("expected JSON array".into()))?;
            if arr.is_empty() {
                break;
            }
            out.extend(arr.iter().cloned());
            if (arr.len() as u32) < self.per_page {
                break;
            }
        }
        Ok(out)
    }

    pub fn repo(&self, owner: &str, name: &str) -> Result<ImportedRepo> {
        let v = self.get_json(&format!("{}/repos/{owner}/{name}", self.api_base))?;
        Ok(parse_repo(&v))
    }

    /// Issues (GitHub returns PRs in the issues endpoint too; those are filtered out).
    pub fn issues(&self, owner: &str, name: &str) -> Result<Vec<ImportedIssue>> {
        let raw = self.paginate(&format!("/repos/{owner}/{name}/issues?state=all"))?;
        let mut issues = vec![];
        for v in raw {
            if v.get("pull_request").is_some() {
                continue; // it's a PR, handled separately
            }
            let mut issue = parse_issue(&v);
            let number = issue.number;
            issue.comments = self.issue_comments(owner, name, number)?;
            issues.push(issue);
        }
        Ok(issues)
    }

    fn issue_comments(&self, owner: &str, name: &str, number: u64) -> Result<Vec<ImportedComment>> {
        let raw = self.paginate(&format!("/repos/{owner}/{name}/issues/{number}/comments"))?;
        Ok(raw.iter().map(parse_comment).collect())
    }

    pub fn pulls(&self, owner: &str, name: &str) -> Result<Vec<ImportedPull>> {
        let raw = self.paginate(&format!("/repos/{owner}/{name}/pulls?state=all"))?;
        Ok(raw.iter().map(parse_pull).collect())
    }

    /// Fetch the full metadata graph for `owner/name`.
    pub fn import_plan(&self, owner: &str, name: &str) -> Result<ImportPlan> {
        Ok(ImportPlan {
            repo: self.repo(owner, name)?,
            issues: self.issues(owner, name)?,
            pulls: self.pulls(owner, name)?,
        })
    }
}

// ---- parsing ----------------------------------------------------------------

fn s(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}
fn login(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|u| u.get("login"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn parse_repo(v: &serde_json::Value) -> ImportedRepo {
    ImportedRepo {
        full_name: s(v, "full_name"),
        name: s(v, "name"),
        description: s(v, "description"),
        private: v.get("private").and_then(|x| x.as_bool()).unwrap_or(true),
        default_branch: {
            let b = s(v, "default_branch");
            if b.is_empty() {
                "main".to_string()
            } else {
                b
            }
        },
        clone_url: s(v, "clone_url"),
    }
}

pub fn parse_issue(v: &serde_json::Value) -> ImportedIssue {
    ImportedIssue {
        number: v.get("number").and_then(|x| x.as_u64()).unwrap_or(0),
        title: s(v, "title"),
        body: s(v, "body"),
        author: login(v, "user"),
        state: s(v, "state"),
        labels: v
            .get("labels")
            .and_then(|l| l.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        x.get("name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                            .or_else(|| x.as_str().map(String::from))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        created_at: s(v, "created_at"),
        updated_at: s(v, "updated_at"),
        comments: vec![],
    }
}

pub fn parse_comment(v: &serde_json::Value) -> ImportedComment {
    ImportedComment {
        id: v.get("id").and_then(|x| x.as_u64()).unwrap_or(0),
        author: login(v, "user"),
        body: s(v, "body"),
        created_at: s(v, "created_at"),
    }
}

pub fn parse_pull(v: &serde_json::Value) -> ImportedPull {
    ImportedPull {
        number: v.get("number").and_then(|x| x.as_u64()).unwrap_or(0),
        title: s(v, "title"),
        body: s(v, "body"),
        author: login(v, "user"),
        state: s(v, "state"),
        merged: v.get("merged_at").map(|m| !m.is_null()).unwrap_or(false),
        head_ref: v.get("head").map(|h| s(h, "ref")).unwrap_or_default(),
        base_ref: v.get("base").map(|h| s(h, "ref")).unwrap_or_default(),
        head_sha: v.get("head").map(|h| s(h, "sha")).unwrap_or_default(),
        created_at: s(v, "created_at"),
        updated_at: s(v, "updated_at"),
    }
}

/// Parse an ISO8601 instant (`2026-06-28T17:00:00Z`) to unix seconds; 0 on failure.
pub fn instant_to_unix(s: &str) -> u64 {
    let b = s.as_bytes();
    if s.len() < 19 || b.get(4) != Some(&b'-') || b.get(10) != Some(&b'T') {
        return 0;
    }
    let n = |a: usize, c: usize| s.get(a..c).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
    let (y, mo, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (h, mi, se) = (n(11, 13), n(14, 16), n(17, 19));
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days * 86400 + h * 3600 + mi * 60 + se).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A canned Fetch backed by a URL->JSON map for offline testing.
    struct CannedFetch {
        responses: HashMap<String, String>,
        log: RefCell<Vec<String>>,
    }
    impl Fetch for CannedFetch {
        fn get(&self, url: &str) -> Result<Vec<u8>> {
            self.log.borrow_mut().push(url.to_string());
            self.responses
                .get(url)
                .map(|s| s.clone().into_bytes())
                .ok_or_else(|| ImportError::Fetch(format!("no canned response for {url}")))
        }
    }

    fn empty_page(base: &str, path: &str) -> String {
        format!("{base}{path}per_page=100&page=1")
    }

    #[test]
    fn instant_parsing() {
        assert_eq!(instant_to_unix("1970-01-01T00:00:00Z"), 0);
        assert_eq!(instant_to_unix("2000-01-01T00:00:00Z"), 946684800);
    }

    #[test]
    fn parses_repo_issue_pull_shapes() {
        let repo = serde_json::json!({
            "full_name": "octo/hello", "name": "hello", "description": "hi",
            "private": true, "default_branch": "main",
            "clone_url": "https://github.com/octo/hello.git"
        });
        let r = parse_repo(&repo);
        assert_eq!(r.name, "hello");
        assert_eq!(r.default_branch, "main");

        let issue = serde_json::json!({
            "number": 7, "title": "bug", "body": "broken",
            "user": {"login": "alice"}, "state": "open",
            "labels": [{"name": "bug"}, {"name": "p1"}],
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z"
        });
        let i = parse_issue(&issue);
        assert_eq!(i.number, 7);
        assert_eq!(i.author, "alice");
        assert_eq!(i.labels, vec!["bug", "p1"]);

        let pr = serde_json::json!({
            "number": 12, "title": "feature", "body": "",
            "user": {"login": "bob"}, "state": "closed", "merged_at": "2026-01-03T00:00:00Z",
            "head": {"ref": "feat", "sha": "abc123"}, "base": {"ref": "main"},
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-03T00:00:00Z"
        });
        let p = parse_pull(&pr);
        assert_eq!(p.number, 12);
        assert!(p.merged);
        assert_eq!(p.head_ref, "feat");
        assert_eq!(p.head_sha, "abc123");
    }

    #[test]
    fn import_plan_paginates_and_separates_prs_from_issues() {
        let base = "https://api.test";
        let mut responses = HashMap::new();
        // repo
        responses.insert(
            format!("{base}/repos/octo/hello"),
            serde_json::json!({
                "full_name":"octo/hello","name":"hello","description":"",
                "private":true,"default_branch":"main","clone_url":"https://github.com/octo/hello.git"
            })
            .to_string(),
        );
        // issues page 1: one issue + one PR (filtered out)
        responses.insert(
            empty_page(base, "/repos/octo/hello/issues?state=all&"),
            serde_json::json!([
                {"number":1,"title":"real issue","body":"x","user":{"login":"alice"},
                 "state":"open","labels":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
                {"number":2,"title":"a PR","body":"","user":{"login":"bob"},"state":"open",
                 "pull_request":{"url":"x"},"labels":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
            ])
            .to_string(),
        );
        // comments for issue 1 (empty)
        responses.insert(
            empty_page(base, "/repos/octo/hello/issues/1/comments?"),
            "[]".to_string(),
        );
        // pulls page 1
        responses.insert(
            empty_page(base, "/repos/octo/hello/pulls?state=all&"),
            serde_json::json!([
                {"number":2,"title":"a PR","body":"","user":{"login":"bob"},"state":"open",
                 "head":{"ref":"feat","sha":"deadbeef"},"base":{"ref":"main"},
                 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
            ])
            .to_string(),
        );

        let fetch = CannedFetch {
            responses,
            log: RefCell::new(vec![]),
        };
        let client = GithubClient::new(fetch).with_api_base(base);
        let plan = client.import_plan("octo", "hello").unwrap();
        assert_eq!(plan.repo.name, "hello");
        assert_eq!(plan.issues.len(), 1, "PR filtered out of issues");
        assert_eq!(plan.issues[0].number, 1);
        assert_eq!(plan.pulls.len(), 1);
        assert_eq!(plan.pulls[0].head_sha, "deadbeef");
    }
}
