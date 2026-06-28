//! Server wiring for the GitHub importer.
//!
//! The whole import executes **inside the CVM**: metadata is fetched over the audited
//! in-CVM HTTPS client, the git history is mirror-cloned and immediately sealed into the
//! encrypted store, and issues/PRs land in the encrypted review store. The GitHub token is
//! used only in memory for outbound auth and is never persisted (the durable repo artifact
//! is the encrypted bundle, which contains only git objects).

use crate::http::{Request, Response};
use crate::App;
use secgit_identity::model::{Repo, RepoOwner};
use secgit_import::{instant_to_unix, GithubClient};
use secgit_review::{Comment, Issue, IssueState, PrState, PullRequest, Reviews};

/// `POST /api/v1/import/github` — body: `{owner, repo, token, target_repo_id?}`.
pub fn import_github(app: &App, req: &Request, user: &str) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::text(400, "Bad Request", "invalid JSON body"),
    };
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("");
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("");
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if owner.is_empty() || repo.is_empty() || token.is_empty() {
        return Response::text(400, "Bad Request", "owner, repo and token are required");
    }

    // Resolve the importing user's name to derive a default repo id.
    let username = {
        let id = app.identity.lock().unwrap();
        id.dir
            .get_user(user)
            .map(|u| u.username.clone())
            .unwrap_or_else(|| user.to_string())
    };
    let repo_id = body
        .get("target_repo_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("{username}/{repo}"));

    {
        let id = app.identity.lock().unwrap();
        if id.dir.get_repo(&repo_id).is_some() {
            return Response::text(409, "Conflict", "target repo already exists");
        }
    }

    // Build the authenticated in-CVM fetcher and pull the metadata graph.
    let auth = format!("Bearer {token}");
    let fetch = |url: &str| -> secgit_import::Result<Vec<u8>> {
        let headers = vec![
            ("Authorization".to_string(), auth.clone()),
            ("User-Agent".to_string(), "secgit-server".to_string()),
            (
                "Accept".to_string(),
                "application/vnd.github+json".to_string(),
            ),
        ];
        secgit_net::https_get_with_headers(url, &headers)
            .map_err(|e| secgit_import::ImportError::Fetch(e.to_string()))
    };
    let client = GithubClient::new(fetch);
    let plan = match client.import_plan(owner, repo) {
        Ok(p) => p,
        Err(e) => return Response::text(502, "Bad Gateway", &format!("github import failed: {e}")),
    };

    // Mirror-clone the git history and seal it encrypted at rest.
    let clone_url = format!("https://x-access-token:{token}@github.com/{owner}/{repo}.git");
    if let Err(e) = app.forge.clone_mirror(&repo_id, &clone_url) {
        return Response::text(502, "Bad Gateway", &format!("git clone failed: {e}"));
    }
    if let Err(e) = app.forge.seal_to_store(&repo_id, &app.store) {
        return Response::text(500, "Internal Server Error", &format!("seal failed: {e}"));
    }

    // Register the repo under the importing user.
    {
        let mut id = app.identity.lock().unwrap();
        let r = Repo {
            id: repo_id.clone(),
            owner: RepoOwner::User(user.to_string()),
            name: plan.repo.name.clone(),
            private: plan.repo.private,
            collaborators: vec![],
        };
        if let Err(e) = id.dir.create_repo(r) {
            return Response::text(500, "Internal Server Error", &format!("register repo: {e}"));
        }
    }
    // Track the imported repo in quota accounting (best-effort).
    {
        let bytes = app
            .store
            .get(&repo_id, "repo.bundle")
            .ok()
            .flatten()
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        app.quota
            .lock()
            .unwrap()
            .preload(user, secgit_api::Tier::Light, &repo_id, bytes);
    }

    // Persist issues and pull requests into the encrypted review store.
    let reviews = Reviews::new(&app.store);
    let mut issue_count = 0usize;
    for gi in &plan.issues {
        let issue = Issue {
            id: format!("issue_{repo_id}_{}", gi.number),
            repo_id: repo_id.clone(),
            number: gi.number,
            title: gi.title.clone(),
            body: gi.body.clone(),
            author_id: format!("gh:{}", gi.author),
            state: if gi.state == "closed" {
                IssueState::Closed
            } else {
                IssueState::Open
            },
            labels: gi.labels.clone(),
            comments: gi
                .comments
                .iter()
                .map(|c| Comment {
                    id: format!("ghc_{}", c.id),
                    author_id: format!("gh:{}", c.author),
                    body: c.body.clone(),
                    suggestion: None,
                    created_at: instant_to_unix(&c.created_at),
                })
                .collect(),
            created_at: instant_to_unix(&gi.created_at),
            updated_at: instant_to_unix(&gi.updated_at),
        };
        if reviews.put_issue(&issue).is_ok() {
            issue_count += 1;
        }
    }

    let mut pr_count = 0usize;
    for gp in &plan.pulls {
        let state = if gp.merged {
            PrState::Merged
        } else if gp.state == "closed" {
            PrState::Closed
        } else {
            PrState::Open
        };
        let pr = PullRequest {
            id: format!("pr_{repo_id}_{}", gp.number),
            repo_id: repo_id.clone(),
            number: gp.number,
            title: gp.title.clone(),
            description: gp.body.clone(),
            author_id: format!("gh:{}", gp.author),
            source_branch: gp.head_ref.clone(),
            target_branch: gp.base_ref.clone(),
            head_sha: gp.head_sha.clone(),
            state,
            created_at: instant_to_unix(&gp.created_at),
            updated_at: instant_to_unix(&gp.updated_at),
        };
        if reviews.put_pr(&pr).is_ok() {
            pr_count += 1;
        }
    }

    // Index for search and record the import.
    let _ = crate::index_repo_head(app, &repo_id);
    if let Ok(mut log) = app.audit.lock() {
        let _ = log.append(secgit_audit::AuditEvent::RepoCreated {
            repo_id: repo_id.clone(),
            owner: user.to_string(),
        });
    }
    let _ = crate::events::Events::new(&app.store).notify(
        user,
        "import",
        &repo_id,
        "GitHub import complete",
        &format!(
            "Imported {} ({issue_count} issues, {pr_count} pull requests)",
            plan.repo.full_name
        ),
    );

    Response::json(&serde_json::json!({
        "imported": true,
        "repo_id": repo_id,
        "name": plan.repo.name,
        "default_branch": plan.repo.default_branch,
        "issues": issue_count,
        "pull_requests": pr_count,
    }))
}
