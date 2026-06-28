//! REST + (minimal) GraphQL API, served **inside the CVM**.
//!
//! Everything is rendered from the confidential layer: callers authenticate (session
//! bearer token or HTTP Basic against local accounts), and every repo-scoped request is
//! access-controlled through `secgit-identity` exactly like the git transport. Responses
//! are JSON; repo contents are read from the in-TEE working tree (materialized on demand
//! from the encrypted store).
//!
//! Two surfaces:
//! - `GET/POST /api/v1/...` — a conventional REST API (users, repos, refs, commits, tree,
//!   blob, pull requests, webhooks, notifications, search).
//! - `POST /api/graphql` — a **deliberately small** GraphQL subset (viewer, repositories,
//!   repository(id) with pullRequests). It is documented as a subset, not a full schema;
//!   the REST surface is the complete one.

use crate::events::Events;
use crate::http::{Request, Response};
use crate::App;
use secgit_identity::Role;

/// Entry point: returns `Some(Response)` if `req` targets the API, else `None`.
pub fn route_api(app: &App, req: &Request) -> Option<Response> {
    let path = req.path.clone();
    if path == "/api/graphql" && req.method == "POST" {
        return Some(graphql(app, req));
    }
    let rest = path.strip_prefix("/api/v1/")?;
    Some(rest_v1(app, req, rest))
}

fn unauthorized() -> Response {
    Response::text(401, "Unauthorized", "authentication required")
        .with_header("WWW-Authenticate", "Basic realm=\"secgit\"")
}
fn forbidden() -> Response {
    Response::text(403, "Forbidden", "insufficient access")
}
fn not_found() -> Response {
    Response::text(404, "Not Found", "not found")
}
fn bad_request(msg: &str) -> Response {
    Response::text(400, "Bad Request", msg)
}

/// Resolve the authenticated user id, or `None`.
fn auth(app: &App, req: &Request) -> Option<String> {
    app.identity.lock().unwrap().authenticate(req)
}

fn ensure_materialized(app: &App, repo_id: &str) {
    if !app.forge.exists(repo_id) {
        let _ = app.forge.restore_from_store(repo_id, &app.store);
    }
}

/// Split `repos/<id...>/<action>/<tail...>` into `(repo_id, action, tail)`.
/// The repo id may itself contain `/` (e.g. `alice/secret`), so we locate the first
/// known action keyword and treat everything before it as the id.
fn split_repo_path(rest: &str) -> Option<(String, String, Vec<String>)> {
    let after = rest.strip_prefix("repos/")?;
    const ACTIONS: &[&str] = &["refs", "commits", "tree", "blob", "pulls", "hooks"];
    let segs: Vec<&str> = after.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return None;
    }
    for (i, s) in segs.iter().enumerate() {
        if i > 0 && ACTIONS.contains(s) {
            let repo_id = segs[..i].join("/");
            let action = segs[i].to_string();
            let tail = segs[i + 1..].iter().map(|s| s.to_string()).collect();
            return Some((repo_id, action, tail));
        }
    }
    Some((segs.join("/"), String::new(), vec![]))
}

fn rest_v1(app: &App, req: &Request, rest: &str) -> Response {
    let Some(user) = auth(app, req) else {
        return unauthorized();
    };

    // Top-level, non-repo resources.
    match (req.method.as_str(), rest) {
        ("GET", "user") => return current_user(app, &user),
        ("GET", "repos") => return list_repos(app, &user),
        ("POST", "repos") => return create_repo(app, req, &user),
        ("GET", "limits") => return limits(app, &user),
        ("GET", "search") => return search(app, req, &user),
        ("GET", "notifications") => return list_notifications(app, &user),
        ("POST", "import/github") => return crate::importer::import_github(app, req, &user),
        _ => {}
    }
    if let Some(id) = rest.strip_prefix("notifications/") {
        if let Some(nid) = id.strip_suffix("/read") {
            if req.method == "POST" {
                let _ = Events::new(&app.store).mark_read(&user, nid);
                return Response::json(&serde_json::json!({"ok": true}));
            }
        }
    }

    let Some((repo_id, action, tail)) = split_repo_path(rest) else {
        return not_found();
    };

    // Access control: existence + role on the repo (read for GET, admin for hook mgmt).
    {
        let id = app.identity.lock().unwrap();
        if id.dir.get_repo(&repo_id).is_none() {
            return not_found();
        }
        let need = if action == "hooks" && req.method != "GET" {
            Role::Admin
        } else if req.method == "GET" {
            Role::Read
        } else {
            Role::Write
        };
        if !id.dir.can(&user, &repo_id, need) {
            return forbidden();
        }
    }

    match (req.method.as_str(), action.as_str()) {
        ("GET", "") => repo_meta(app, &repo_id),
        ("GET", "refs") => repo_refs(app, &repo_id),
        ("GET", "commits") => repo_commits(app, req, &repo_id),
        ("GET", "tree") => repo_tree(app, req, &repo_id),
        ("GET", "blob") => repo_blob(app, req, &repo_id),
        ("GET", "pulls") => {
            if let Some(num) = tail.first() {
                pull_detail(app, &repo_id, num)
            } else {
                list_pulls(app, &repo_id)
            }
        }
        ("POST", "pulls") => open_pull(app, req, &repo_id, &user),
        ("GET", "hooks") => list_hooks(app, &repo_id),
        ("POST", "hooks") => create_hook(app, req, &repo_id),
        ("DELETE", "hooks") => {
            if let Some(id) = tail.first() {
                delete_hook(app, &repo_id, id)
            } else {
                bad_request("hook id required")
            }
        }
        _ => not_found(),
    }
}

// ---- handlers ---------------------------------------------------------------

fn current_user(app: &App, user: &str) -> Response {
    let id = app.identity.lock().unwrap();
    match id.dir.get_user(user) {
        Some(u) => Response::json(&serde_json::json!({
            "id": u.id, "username": u.username, "email": u.email
        })),
        None => Response::json(&serde_json::json!({"id": user})),
    }
}

fn repo_json(r: &secgit_identity::Repo) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "name": r.name,
        "private": r.private,
        "resource_id": r.resource_id(),
    })
}

fn list_repos(app: &App, user: &str) -> Response {
    let id = app.identity.lock().unwrap();
    let repos: Vec<_> = id
        .dir
        .repos_visible_to(user)
        .iter()
        .map(|r| repo_json(r))
        .collect();
    Response::json(&serde_json::json!({ "repositories": repos }))
}

/// Map an HTTP status code to a static reason phrase for the small set we emit.
pub(crate) fn status_reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        403 => "Forbidden",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

/// Shared core for creating a persistent (Light-tier) repository owned by `user` (a user
/// id), gated by the account's repo-count quota. Used by both the REST API and the web UI.
///
/// On success returns the new repo id (`<username>/<name>`). On failure returns an
/// `(http_status, message)` pair the caller can render however it likes. The repo is
/// registered in the identity directory (so it appears in `/ui` and is push-authorized)
/// and a bare repo is created + sealed to the encrypted store.
pub(crate) fn create_named_repo(
    app: &App,
    user: &str,
    name: &str,
    private: bool,
) -> std::result::Result<String, (u16, String)> {
    let name = name.trim();
    if name.is_empty() || name.contains('/') {
        return Err((400, "a non-empty repo name without '/' is required".into()));
    }
    let username = {
        let id = app.identity.lock().unwrap();
        id.dir
            .get_user(user)
            .map(|u| u.username.clone())
            .unwrap_or_else(|| user.to_string())
    };
    let repo_id = format!("{username}/{name}");

    // Quota gate (repo-count cap) for the Light tier.
    {
        let mut q = app.quota.lock().unwrap();
        if q.ensure_account(user, secgit_api::Tier::Light).is_err() {
            return Err((403, "your tier cannot create repositories".into()));
        }
        if q.authorize_create_repo(user, &repo_id).is_err() {
            return Err((403, "repository quota exceeded for your tier".into()));
        }
    }

    {
        let mut id = app.identity.lock().unwrap();
        if id.dir.get_repo(&repo_id).is_some() {
            // Roll back the quota reservation we just made.
            let _ = app.quota.lock().unwrap().remove_repo(user, &repo_id);
            return Err((409, "repository already exists".into()));
        }
        let repo = secgit_identity::Repo {
            id: repo_id.clone(),
            owner: secgit_identity::RepoOwner::User(user.to_string()),
            name: name.to_string(),
            private,
            collaborators: vec![],
        };
        if let Err(e) = id.dir.create_repo(repo) {
            let _ = app.quota.lock().unwrap().remove_repo(user, &repo_id);
            return Err((500, e.to_string()));
        }
    }
    if let Err(e) = app.forge.create_bare(&repo_id) {
        return Err((500, format!("create repo: {e}")));
    }
    let _ = app.store.init_repo(&repo_id);
    let _ = app.forge.seal_to_store(&repo_id, &app.store);
    if let Ok(mut log) = app.audit.lock() {
        let _ = log.append(secgit_audit::AuditEvent::RepoCreated {
            repo_id: repo_id.clone(),
            owner: user.to_string(),
        });
    }
    Ok(repo_id)
}

/// Create a persistent (Light-tier) repository owned by the authenticated user, gated by
/// the account's quota. This completes the Light tier: authenticated, capped, persistent.
fn create_repo(app: &App, req: &Request, user: &str) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid JSON body"),
    };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let private = body
        .get("private")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    match create_named_repo(app, user, name, private) {
        Ok(repo_id) => {
            let id = app.identity.lock().unwrap();
            Response::json(&repo_json(id.dir.get_repo(&repo_id).unwrap()))
        }
        Err((code, msg)) => Response::text(code, status_reason(code), &msg),
    }
}

/// Report the deployment's tier limits and the caller's current usage.
fn limits(app: &App, user: &str) -> Response {
    let cfg = &app.config;
    let light = cfg.limits_for(secgit_api::Tier::Light);
    let (repos, bytes) = {
        let q = app.quota.lock().unwrap();
        (q.repo_count(user) as u64, q.total_bytes(user))
    };
    Response::json(&serde_json::json!({
        "sandbox_mode": cfg.sandbox_mode,
        "tiers": {
            "anonymous": cfg.anonymous_enabled,
            "light": cfg.light_enabled,
            "managed": cfg.managed_enabled,
        },
        "light_limits": {
            "max_repos": light.max_repos,
            "max_bytes_per_repo": light.max_bytes_per_repo,
            "max_total_bytes": light.max_total_bytes,
        },
        "your_usage": { "repos": repos, "total_bytes": bytes },
    }))
}

fn repo_meta(app: &App, repo_id: &str) -> Response {
    let id = app.identity.lock().unwrap();
    match id.dir.get_repo(repo_id) {
        Some(r) => Response::json(&repo_json(r)),
        None => not_found(),
    }
}

fn repo_refs(app: &App, repo_id: &str) -> Response {
    ensure_materialized(app, repo_id);
    match app.forge.list_refs(repo_id) {
        Ok(refs) => {
            let items: Vec<_> = refs
                .iter()
                .map(|r| serde_json::json!({"name": r.name, "target": r.target}))
                .collect();
            Response::json(&serde_json::json!({ "refs": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn repo_commits(app: &App, req: &Request, repo_id: &str) -> Response {
    ensure_materialized(app, repo_id);
    let rev = req.query.get("rev").map(String::as_str).unwrap_or("HEAD");
    let limit = req
        .query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50usize)
        .min(500);
    match app.forge.log(repo_id, rev, limit) {
        Ok(commits) => {
            let items: Vec<_> = commits
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id, "short": c.short,
                        "author_name": c.author_name, "author_email": c.author_email,
                        "time_unix": c.time_unix, "summary": c.summary,
                    })
                })
                .collect();
            Response::json(&serde_json::json!({ "commits": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn repo_tree(app: &App, req: &Request, repo_id: &str) -> Response {
    ensure_materialized(app, repo_id);
    let rev = req.query.get("rev").map(String::as_str).unwrap_or("HEAD");
    let dir = req.query.get("path").map(String::as_str).unwrap_or("");
    match app.forge.list_tree(repo_id, rev, dir) {
        Ok(entries) => {
            let items: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "mode": e.mode, "kind": e.kind, "id": e.id, "name": e.name
                    })
                })
                .collect();
            Response::json(&serde_json::json!({ "entries": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn repo_blob(app: &App, req: &Request, repo_id: &str) -> Response {
    ensure_materialized(app, repo_id);
    let rev = req.query.get("rev").map(String::as_str).unwrap_or("HEAD");
    let Some(file) = req.query.get("path") else {
        return bad_request("path query parameter required");
    };
    match app.forge.read_blob(repo_id, rev, file) {
        Ok(bytes) => match String::from_utf8(bytes.clone()) {
            Ok(text) => Response::json(&serde_json::json!({
                "path": file, "encoding": "utf-8", "content": text
            })),
            Err(_) => Response::json(&serde_json::json!({
                "path": file, "encoding": "base64", "content": b64encode(&bytes)
            })),
        },
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn list_pulls(app: &App, repo_id: &str) -> Response {
    let reviews = secgit_review::Reviews::new(&app.store);
    match reviews.list_prs(repo_id) {
        Ok(prs) => {
            let items: Vec<_> = prs.iter().map(pr_json).collect();
            Response::json(&serde_json::json!({ "pull_requests": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn pull_detail(app: &App, repo_id: &str, num: &str) -> Response {
    let reviews = secgit_review::Reviews::new(&app.store);
    let pr_id = format!("pr_{repo_id}_{num}");
    match reviews.get_pr(repo_id, &pr_id) {
        Ok(Some(pr)) => {
            let status = reviews.merge_status(&pr).ok();
            let mut v = pr_json(&pr);
            if let Some(s) = status {
                v["merge_status"] = serde_json::json!({
                    "mergeable": s.mergeable,
                    "approvals": s.approvals,
                    "required_approvals": s.required_approvals,
                    "changes_requested": s.changes_requested,
                    "failing_or_missing_checks": s.failing_or_missing_checks,
                    "reasons": s.reasons,
                });
            }
            Response::json(&v)
        }
        Ok(None) => not_found(),
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn open_pull(app: &App, req: &Request, repo_id: &str, user: &str) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid JSON body"),
    };
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
    let desc = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let src = body
        .get("source_branch")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tgt = body
        .get("target_branch")
        .and_then(|v| v.as_str())
        .unwrap_or("main");
    if title.is_empty() || src.is_empty() {
        return bad_request("title and source_branch are required");
    }
    ensure_materialized(app, repo_id);
    let head = app
        .forge
        .log(repo_id, src, 1)
        .ok()
        .and_then(|c| c.first().map(|c| c.id.clone()))
        .unwrap_or_default();
    let reviews = secgit_review::Reviews::new(&app.store);
    match reviews.open_pr(
        repo_id,
        user,
        title,
        desc,
        src,
        tgt,
        &head,
        crate::events::now_secs(),
    ) {
        Ok(pr) => {
            // Fan out notifications + webhooks (best-effort).
            let events = Events::new(&app.store);
            notify_repo_members(
                app,
                repo_id,
                user,
                "pull_request",
                "Pull request opened",
                title,
            );
            let _ = events.deliver(
                repo_id,
                "pull_request",
                &serde_json::json!({"action": "opened", "pull_request": pr_json(&pr)}),
            );
            Response::json(&pr_json(&pr))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e.to_string()),
    }
}

fn pr_json(pr: &secgit_review::PullRequest) -> serde_json::Value {
    serde_json::json!({
        "id": pr.id,
        "number": pr.number,
        "title": pr.title,
        "description": pr.description,
        "author_id": pr.author_id,
        "source_branch": pr.source_branch,
        "target_branch": pr.target_branch,
        "head_sha": pr.head_sha,
        "state": format!("{:?}", pr.state),
        "created_at": pr.created_at,
        "updated_at": pr.updated_at,
    })
}

fn list_hooks(app: &App, repo_id: &str) -> Response {
    let events = Events::new(&app.store);
    match events.list_hooks(repo_id) {
        Ok(hooks) => {
            let items: Vec<_> = hooks.iter().map(|h| h.public_json()).collect();
            Response::json(&serde_json::json!({ "hooks": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e),
    }
}

fn create_hook(app: &App, req: &Request, repo_id: &str) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid JSON body"),
    };
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let events_list: Vec<String> = body
        .get("events")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["*".to_string()]);
    if secret.is_empty() {
        return bad_request("secret is required (used to HMAC-sign deliveries)");
    }
    let events = Events::new(&app.store);
    match events.create_hook(repo_id, url, secret, events_list) {
        Ok(h) => Response::json(&h.public_json()),
        Err(e) => bad_request(&e),
    }
}

fn delete_hook(app: &App, repo_id: &str, id: &str) -> Response {
    let events = Events::new(&app.store);
    match events.delete_hook(repo_id, id) {
        Ok(()) => Response::json(&serde_json::json!({"ok": true})),
        Err(e) => Response::text(500, "Internal Server Error", &e),
    }
}

fn list_notifications(app: &App, user: &str) -> Response {
    let events = Events::new(&app.store);
    match events.list_notifications(user) {
        Ok(ns) => {
            let items: Vec<_> = ns.iter().map(|n| n.json()).collect();
            let unread = ns.iter().filter(|n| !n.read).count();
            Response::json(&serde_json::json!({ "unread": unread, "notifications": items }))
        }
        Err(e) => Response::text(500, "Internal Server Error", &e),
    }
}

fn search(app: &App, req: &Request, user: &str) -> Response {
    let query = req.query.get("q").cloned().unwrap_or_default();
    if query.trim().is_empty() {
        return Response::json(&serde_json::json!({ "hits": [] }));
    }
    let repo_ids: Vec<String> = {
        let id = app.identity.lock().unwrap();
        id.dir
            .repos_visible_to(user)
            .iter()
            .map(|r| r.id.clone())
            .collect()
    };
    let idx = secgit_search::SearchIndex::new(&app.search_store);
    let mut hits = vec![];
    for repo_id in &repo_ids {
        ensure_materialized(app, repo_id);
        let _ = crate::index_repo_head(app, repo_id);
        let fetch = |r: &str, p: &str| {
            app.forge
                .read_blob(r, "HEAD", p)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        };
        if let Ok(mut h) = idx.search_repo(repo_id, &query, 50, &fetch) {
            hits.append(&mut h);
        }
    }
    let items: Vec<_> = hits
        .iter()
        .take(200)
        .map(|h| {
            serde_json::json!({
                "repo_id": h.repo_id, "path": h.path, "line": h.line, "snippet": h.snippet
            })
        })
        .collect();
    Response::json(&serde_json::json!({ "hits": items }))
}

/// Notify every user with at least Read on `repo_id` (except the actor).
fn notify_repo_members(
    app: &App,
    repo_id: &str,
    actor: &str,
    kind: &str,
    subject: &str,
    body: &str,
) {
    let recipients: Vec<String> = {
        let id = app.identity.lock().unwrap();
        id.dir
            .list_users()
            .iter()
            .filter(|u| u.id != actor && id.dir.can(&u.id, repo_id, Role::Read))
            .map(|u| u.id.clone())
            .collect()
    };
    let events = Events::new(&app.store);
    for uid in recipients {
        let _ = events.notify(&uid, kind, repo_id, subject, body);
    }
}

// ---- minimal GraphQL --------------------------------------------------------

/// A tiny GraphQL endpoint supporting a fixed subset of queries. This is intentionally
/// not a full GraphQL engine (no schema introspection, fragments, variables); it covers
/// the read paths integrators most want while keeping the in-CVM TCB small. The REST API
/// is the complete surface.
fn graphql(app: &App, req: &Request) -> Response {
    let Some(user) = auth(app, req) else {
        return unauthorized();
    };
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid JSON body"),
    };
    let query = body.get("query").and_then(|v| v.as_str()).unwrap_or("");

    let mut data = serde_json::Map::new();
    if query.contains("viewer") {
        let id = app.identity.lock().unwrap();
        let v = match id.dir.get_user(&user) {
            Some(u) => serde_json::json!({"id": u.id, "username": u.username, "email": u.email}),
            None => serde_json::json!({"id": user}),
        };
        data.insert("viewer".to_string(), v);
    }
    if query.contains("repositories") {
        let id = app.identity.lock().unwrap();
        let repos: Vec<_> = id
            .dir
            .repos_visible_to(&user)
            .iter()
            .map(|r| serde_json::json!({"id": r.id, "name": r.name, "private": r.private}))
            .collect();
        data.insert("repositories".to_string(), serde_json::Value::Array(repos));
    }
    if let Some(repo_id) = graphql_repo_arg(query) {
        let allowed = {
            let id = app.identity.lock().unwrap();
            id.dir.get_repo(&repo_id).is_some() && id.dir.can(&user, &repo_id, Role::Read)
        };
        if allowed {
            let mut obj = serde_json::Map::new();
            {
                let id = app.identity.lock().unwrap();
                if let Some(r) = id.dir.get_repo(&repo_id) {
                    obj.insert("id".into(), serde_json::json!(r.id));
                    obj.insert("name".into(), serde_json::json!(r.name));
                }
            }
            if query.contains("pullRequests") {
                let reviews = secgit_review::Reviews::new(&app.store);
                let prs: Vec<_> = reviews
                    .list_prs(&repo_id)
                    .unwrap_or_default()
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "number": p.number, "title": p.title, "state": format!("{:?}", p.state)
                        })
                    })
                    .collect();
                obj.insert("pullRequests".into(), serde_json::Value::Array(prs));
            }
            data.insert("repository".to_string(), serde_json::Value::Object(obj));
        } else {
            data.insert("repository".to_string(), serde_json::Value::Null);
        }
    }

    Response::json(&serde_json::json!({ "data": data }))
}

/// Extract the `id:` argument from `repository(id: "...")` if present.
fn graphql_repo_arg(query: &str) -> Option<String> {
    let i = query.find("repository(")?;
    let rest = &query[i..];
    let q1 = rest.find('"')?;
    let after = &rest[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

fn b64encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
