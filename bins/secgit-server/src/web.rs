//! In-CVM, server-side-rendered web UX.
//!
//! Per the settled web-stack decision, the plaintext-touching renderer lives **inside the
//! CVM** (SSR Rust, no separate JS build, tight trust surface). Every byte rendered here is
//! produced on the decrypted side of the in-CVM PQC-TLS connection and travels straight to
//! the authenticated user; the operator never sees it. There are no template-engine or
//! highlighter dependencies — keeping the TCB minimal — so HTML is built with explicit
//! escaping and a small, self-contained syntax highlighter.

use crate::authz::{required_role, ServerIdentity};
use crate::http::{Request, Response};
use secgit_forge::{BlameLine, CommitInfo, Forge, TreeEntry};
use secgit_identity::Role;

/// HTML-escape text for safe interpolation into element content / attributes.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1c1e21;background:#fff}
header{background:#0d1117;color:#e6edf3;padding:10px 18px}
header a{color:#58a6ff;text-decoration:none;margin-right:14px}
main{max-width:1000px;margin:18px auto;padding:0 16px}
h1,h2{font-weight:600}
table.list{border-collapse:collapse;width:100%}
table.list td{padding:5px 8px;border-bottom:1px solid #eaecef}
a{color:#0969da;text-decoration:none}
a:hover{text-decoration:underline}
.code{border:1px solid #d0d7de;border-radius:6px;overflow:auto}
.code table{border-collapse:collapse;width:100%;font:12px/1.45 SFMono-Regular,Consolas,monospace}
.code td.ln{color:#8c959f;text-align:right;padding:0 10px;user-select:none;border-right:1px solid #eaecef;width:1%;white-space:nowrap}
.code td.src{padding:0 12px;white-space:pre}
.kw{color:#cf222e}.str{color:#0a3069}.com{color:#6e7781;font-style:italic}.num{color:#0550ae}
.diff .add{background:#e6ffec}.diff .del{background:#ffebe9}.diff .hunk{color:#0550ae;background:#f6f8fa}
.muted{color:#6e7781}
.crumb{margin-bottom:12px}
"#;

/// Wrap body content in the standard page chrome.
pub fn page(title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{t}</title><style>{s}</style></head>\
         <body><header><a href=\"/ui\">SecGit</a><span class=\"muted\">confidential code hosting</span></header>\
         <main>{b}</main></body></html>",
        t = escape(title),
        s = STYLE,
        b = body
    );
    Response::new(200, "OK", "text/html; charset=utf-8", html.into_bytes())
}

fn require_auth(identity: &mut ServerIdentity, req: &Request) -> Result<String, Response> {
    identity.authenticate(req).ok_or_else(|| {
        Response::text(401, "Unauthorized", "authentication required")
            .with_header("WWW-Authenticate", "Basic realm=\"secgit\"")
    })
}

fn require_read(
    identity: &mut ServerIdentity,
    repo: &str,
    req: &Request,
) -> Result<String, Response> {
    let user = require_auth(identity, req)?;
    if identity.dir.get_repo(repo).is_none() {
        return Err(page_404());
    }
    if !identity.dir.can(&user, repo, required_role(false)) {
        return Err(Response::text(403, "Forbidden", "insufficient access"));
    }
    Ok(user)
}

fn page_404() -> Response {
    let mut r = page(
        "Not found",
        "<h1>404</h1><p class=\"muted\">No such repository.</p>",
    );
    r.status = 404;
    r.reason = "Not Found";
    r
}

/// Entry point for `/ui...` routes. Returns `None` if the path is not a UI route.
pub fn route_ui(forge: &Forge, identity: &mut ServerIdentity, req: &Request) -> Option<Response> {
    let path = req.path.as_str();
    if path != "/ui" && !path.starts_with("/ui/") {
        return None;
    }
    let q = |k: &str| req.query.get(k).cloned().unwrap_or_default();
    let rev = |r: String| if r.is_empty() { "HEAD".to_string() } else { r };

    Some(match path {
        "/ui" => render_repo_list(identity, req),
        "/ui/orgs" => render_org_list(identity, req),
        "/ui/org" => render_org(identity, req, &q("org")),
        "/ui/tree" => match require_read(identity, &q("repo"), req) {
            Ok(_) => render_tree(forge, &q("repo"), &rev(q("rev")), &q("path")),
            Err(r) => r,
        },
        "/ui/blob" => match require_read(identity, &q("repo"), req) {
            Ok(_) => render_blob(forge, &q("repo"), &rev(q("rev")), &q("path")),
            Err(r) => r,
        },
        "/ui/raw" => match require_read(identity, &q("repo"), req) {
            Ok(_) => match forge.read_blob(&q("repo"), &rev(q("rev")), &q("path")) {
                Ok(bytes) => Response::new(200, "OK", "application/octet-stream", bytes),
                Err(e) => Response::text(404, "Not Found", &format!("{e}")),
            },
            Err(r) => r,
        },
        "/ui/log" => match require_read(identity, &q("repo"), req) {
            Ok(_) => render_log(forge, &q("repo"), &rev(q("rev"))),
            Err(r) => r,
        },
        "/ui/commit" => match require_read(identity, &q("repo"), req) {
            Ok(_) => render_commit(forge, &q("repo"), &rev(q("rev"))),
            Err(r) => r,
        },
        "/ui/blame" => match require_read(identity, &q("repo"), req) {
            Ok(_) => render_blame(forge, &q("repo"), &rev(q("rev")), &q("path")),
            Err(r) => r,
        },
        _ => page_404(),
    })
}

/// Handle POST `/ui/...` admin mutations (org/team/collaborator management). Returns
/// `None` for non-matching paths.
pub fn route_ui_post(identity: &mut ServerIdentity, req: &Request) -> Option<Response> {
    let path = req.path.as_str();
    if !path.starts_with("/ui/") {
        return None;
    }
    let user = match require_auth(identity, req) {
        Ok(u) => u,
        Err(r) => return Some(r),
    };
    let f = req.form();
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();

    Some(match path {
        "/ui/org/member" => {
            let org = get("org");
            if !identity.dir.is_org_owner(&org, &user) {
                return Some(Response::text(403, "Forbidden", "must be an org owner"));
            }
            let role = if get("role") == "owner" {
                secgit_identity::OrgRole::Owner
            } else {
                secgit_identity::OrgRole::Member
            };
            let res = if get("action") == "remove" {
                identity.dir.remove_org_member(&org, &get("user"))
            } else {
                identity.dir.set_org_member(&org, &get("user"), role)
            };
            match res {
                Ok(()) => redirect(&format!("/ui/org?org={}", urlencode(&org))),
                Err(e) => Response::text(400, "Bad Request", &format!("{e}")),
            }
        }
        "/ui/org/team-member" => {
            let org = get("org");
            if !identity.dir.is_org_owner(&org, &user) {
                return Some(Response::text(403, "Forbidden", "must be an org owner"));
            }
            let res = if get("action") == "remove" {
                identity.dir.remove_team_member(&get("team"), &get("user"))
            } else {
                identity.dir.add_team_member(&get("team"), &get("user"))
            };
            match res {
                Ok(()) => redirect(&format!("/ui/org?org={}", urlencode(&org))),
                Err(e) => Response::text(400, "Bad Request", &format!("{e}")),
            }
        }
        "/ui/repo/collaborator" => {
            let repo = get("repo");
            // Only repo admins may change collaborators.
            if !identity.dir.can(&user, &repo, Role::Admin) {
                return Some(Response::text(403, "Forbidden", "must be a repo admin"));
            }
            let role = match get("role").as_str() {
                "admin" => Role::Admin,
                "write" => Role::Write,
                _ => Role::Read,
            };
            let res = if get("action") == "remove" {
                identity.dir.remove_collaborator(&repo, &get("user"))
            } else {
                identity.dir.set_collaborator(&repo, &get("user"), role)
            };
            match res {
                Ok(()) => redirect(&format!("/ui/tree?repo={}", urlencode(&repo))),
                Err(e) => Response::text(400, "Bad Request", &format!("{e}")),
            }
        }
        _ => return None,
    })
}

fn redirect(location: &str) -> Response {
    Response::new(303, "See Other", "text/plain", b"redirecting".to_vec())
        .with_header("Location", location)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn render_org_list(identity: &mut ServerIdentity, req: &Request) -> Response {
    let user = match require_auth(identity, req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let mut rows = String::new();
    for o in identity.dir.orgs_for_user(&user) {
        rows.push_str(&format!(
            "<tr><td><a href=\"/ui/org?org={id}\">{slug}</a></td><td class=\"muted\">{n} member(s)</td></tr>",
            id = escape(&o.id),
            slug = escape(&o.slug),
            n = o.members.len()
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td class=\"muted\">You are not a member of any organization.</td></tr>".into();
    }
    page(
        "Organizations",
        &format!("<h1>Organizations</h1><table class=\"list\">{rows}</table>"),
    )
}

fn render_org(identity: &mut ServerIdentity, req: &Request, org_id: &str) -> Response {
    let user = match require_auth(identity, req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Some(org) = identity.dir.get_org(org_id).cloned() else {
        return page_404();
    };
    if !org.members.iter().any(|(u, _)| u == &user) {
        return Response::text(403, "Forbidden", "not a member of this organization");
    }
    let is_owner = identity.dir.is_org_owner(org_id, &user);

    let mut members = String::new();
    for (uid, role) in &org.members {
        members.push_str(&format!(
            "<tr><td>{u}</td><td class=\"muted\">{r:?}</td></tr>",
            u = escape(uid),
            r = role
        ));
    }
    let mut teams = String::new();
    for t in identity.dir.teams_in_org(org_id) {
        teams.push_str(&format!(
            "<tr><td>{name}</td><td class=\"muted\">{n} member(s), {g} grant(s)</td></tr>",
            name = escape(&t.name),
            n = t.member_ids.len(),
            g = t.repo_grants.len()
        ));
    }

    let admin_form = if is_owner {
        format!(
            "<h2>Manage members</h2>\
             <form method=\"post\" action=\"/ui/org/member\">\
             <input type=\"hidden\" name=\"org\" value=\"{org}\">\
             user id <input name=\"user\"> \
             role <select name=\"role\"><option value=\"member\">member</option><option value=\"owner\">owner</option></select> \
             <button name=\"action\" value=\"set\">set</button> \
             <button name=\"action\" value=\"remove\">remove</button>\
             </form>",
            org = escape(org_id)
        )
    } else {
        String::new()
    };

    page(
        &org.slug,
        &format!(
            "<h1>Organization: {slug}</h1>\
             <h2>Members</h2><table class=\"list\">{members}</table>\
             <h2>Teams</h2><table class=\"list\">{teams}</table>{admin_form}",
            slug = escape(&org.slug),
        ),
    )
}

fn render_repo_list(identity: &mut ServerIdentity, req: &Request) -> Response {
    let user = match require_auth(identity, req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let repos = identity.dir.repos_visible_to(&user);
    let mut rows = String::new();
    for r in &repos {
        rows.push_str(&format!(
            "<tr><td><a href=\"/ui/tree?repo={id}\">{name}</a></td>\
             <td class=\"muted\">{owner}</td>\
             <td><a href=\"/ui/log?repo={id}\">history</a></td></tr>",
            id = escape(&r.id),
            name = escape(&r.name),
            owner = escape(&r.kek_owner()),
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td class=\"muted\">No repositories visible to you.</td></tr>".into();
    }
    let new_form = "<h2>New repository</h2>\
         <form method=\"post\" action=\"/ui/repo/new\">\
         <input name=\"name\" placeholder=\"repository name\" pattern=\"[^/]+\" required> \
         <button>Create</button>\
         <span class=\"muted\">&nbsp;private (v1 repos are always private)</span>\
         </form>";
    page(
        "Repositories",
        &format!("<h1>Your repositories</h1><table class=\"list\">{rows}</table>{new_form}"),
    )
}

fn breadcrumb(repo: &str, rev: &str, path: &str) -> String {
    let mut out = format!(
        "<div class=\"crumb\"><a href=\"/ui/tree?repo={r}\">{r}</a> @ <span class=\"muted\">{rev}</span> &nbsp; \
         <a href=\"/ui/log?repo={r}&rev={rev}\">commits</a>",
        r = escape(repo),
        rev = escape(rev)
    );
    if !path.is_empty() {
        out.push_str(&format!(" &nbsp;/&nbsp; {}", escape(path)));
    }
    out.push_str("</div>");
    out
}

fn render_tree(forge: &Forge, repo: &str, rev: &str, dir: &str) -> Response {
    let entries = match forge.list_tree(repo, rev, dir) {
        Ok(e) => e,
        // A freshly created repo has no commits yet, so there is no tree to list. Detect
        // that (no HEAD) and show a friendly "push to get started" page instead of a 404.
        Err(e) => {
            if matches!(forge.head(repo), Ok(None)) {
                return render_empty_repo(repo);
            }
            return Response::text(404, "Not Found", &format!("{e}"));
        }
    };
    let mut rows = String::new();
    if !dir.is_empty() {
        let parent = dir.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        rows.push_str(&format!(
            "<tr><td><a href=\"/ui/tree?repo={r}&rev={rev}&path={p}\">..</a></td></tr>",
            r = escape(repo),
            rev = escape(rev),
            p = escape(parent)
        ));
    }
    for e in &entries {
        rows.push_str(&entry_row(repo, rev, dir, e));
    }
    page(
        repo,
        &format!(
            "{}<h2>Files</h2><table class=\"list\">{rows}</table>",
            breadcrumb(repo, rev, dir)
        ),
    )
}

/// Friendly empty-state for a repo that exists but has no commits yet, with the exact
/// push command to seed it.
fn render_empty_repo(repo: &str) -> Response {
    let body = format!(
        "<h1>{r}</h1>\
         <p class=\"muted\">This repository is empty.</p>\
         <h2>Push your first commit</h2>\
         <div class=\"code\"><table>\
         <tr><td class=\"src\">git init &amp;&amp; git add -A &amp;&amp; git commit -m \"init\"</td></tr>\
         <tr><td class=\"src\">git push http://&lt;user&gt;:&lt;pass&gt;@&lt;host&gt;/{r} HEAD:refs/heads/main</td></tr>\
         </table></div>\
         <p class=\"muted\">Once you push, files, history, and blame will appear here.</p>",
        r = escape(repo)
    );
    page(repo, &body)
}

fn entry_row(repo: &str, rev: &str, dir: &str, e: &TreeEntry) -> String {
    let child = if dir.is_empty() {
        e.name.clone()
    } else {
        format!("{dir}/{}", e.name)
    };
    let kind = if e.kind == "tree" { "tree" } else { "blob" };
    let icon = if e.kind == "tree" {
        "\u{1F4C1}"
    } else {
        "\u{1F4C4}"
    };
    format!(
        "<tr><td>{icon} <a href=\"/ui/{kind}?repo={r}&rev={rev}&path={c}\">{name}</a></td></tr>",
        r = escape(repo),
        rev = escape(rev),
        c = escape(&child),
        name = escape(&e.name),
    )
}

fn render_blob(forge: &Forge, repo: &str, rev: &str, path: &str) -> Response {
    let bytes = match forge.read_blob(repo, rev, path) {
        Ok(b) => b,
        Err(e) => return Response::text(404, "Not Found", &format!("{e}")),
    };
    let actions = format!(
        "<p><a href=\"/ui/raw?repo={r}&rev={rev}&path={p}\">raw</a> &middot; \
         <a href=\"/ui/blame?repo={r}&rev={rev}&path={p}\">blame</a></p>",
        r = escape(repo),
        rev = escape(rev),
        p = escape(path)
    );
    let body = if let Ok(text) = std::str::from_utf8(&bytes) {
        format!(
            "{}{}{}",
            breadcrumb(repo, rev, path),
            actions,
            highlight_block(text, language_for(path))
        )
    } else {
        format!(
            "{}{}<p class=\"muted\">Binary file ({} bytes).</p>",
            breadcrumb(repo, rev, path),
            actions,
            bytes.len()
        )
    };
    page(path, &body)
}

fn render_log(forge: &Forge, repo: &str, rev: &str) -> Response {
    let commits = match forge.log(repo, rev, 100) {
        Ok(c) => c,
        Err(e) => return Response::text(404, "Not Found", &format!("{e}")),
    };
    page(
        &format!("{repo} commits"),
        &format!(
            "{}<h2>Commits</h2>{}",
            breadcrumb(repo, rev, ""),
            commit_table(repo, &commits)
        ),
    )
}

fn commit_table(repo: &str, commits: &[CommitInfo]) -> String {
    let mut rows = String::new();
    for c in commits {
        rows.push_str(&format!(
            "<tr><td><a href=\"/ui/commit?repo={r}&rev={id}\"><code>{short}</code></a></td>\
             <td>{summary}</td><td class=\"muted\">{author}</td></tr>",
            r = escape(repo),
            id = escape(&c.id),
            short = escape(&c.short),
            summary = escape(&c.summary),
            author = escape(&c.author_name),
        ));
    }
    format!("<table class=\"list\">{rows}</table>")
}

fn render_commit(forge: &Forge, repo: &str, rev: &str) -> Response {
    let diff = match forge.commit_diff(repo, rev) {
        Ok(d) => d,
        Err(e) => return Response::text(404, "Not Found", &format!("{e}")),
    };
    page(
        &format!("commit {rev}"),
        &format!(
            "{}<h2>Commit {}</h2>{}",
            breadcrumb(repo, rev, ""),
            escape(rev),
            render_diff(&diff)
        ),
    )
}

/// Render a unified diff with added/removed/hunk line coloring.
pub fn render_diff(diff: &str) -> String {
    let mut out = String::from("<div class=\"code diff\"><table>");
    for (i, line) in diff.lines().enumerate() {
        let class = if line.starts_with("+++") || line.starts_with("---") {
            ""
        } else if line.starts_with('+') {
            "add"
        } else if line.starts_with('-') {
            "del"
        } else if line.starts_with("@@") {
            "hunk"
        } else {
            ""
        };
        out.push_str(&format!(
            "<tr><td class=\"ln\">{}</td><td class=\"src {}\">{}</td></tr>",
            i + 1,
            class,
            escape(line)
        ));
    }
    out.push_str("</table></div>");
    out
}

fn render_blame(forge: &Forge, repo: &str, rev: &str, path: &str) -> Response {
    let lines = match forge.blame(repo, rev, path) {
        Ok(l) => l,
        Err(e) => return Response::text(404, "Not Found", &format!("{e}")),
    };
    page(
        &format!("blame {path}"),
        &format!(
            "{}<h2>Blame: {}</h2>{}",
            breadcrumb(repo, rev, path),
            escape(path),
            blame_table(repo, &lines)
        ),
    )
}

fn blame_table(repo: &str, lines: &[BlameLine]) -> String {
    let mut out = String::from("<div class=\"code\"><table>");
    for l in lines {
        out.push_str(&format!(
            "<tr><td class=\"ln\"><a href=\"/ui/commit?repo={r}&rev={c}\"><code>{c}</code></a></td>\
             <td class=\"ln\">{n}</td><td class=\"src\">{content}</td></tr>",
            r = escape(repo),
            c = escape(&l.commit_short),
            n = l.lineno,
            content = highlight_line(&l.content, Lang::None),
        ));
    }
    out.push_str("</table></div>");
    out
}

// ---- Minimal syntax highlighter -------------------------------------------------

/// Recognized language families for highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    CLike,
    Python,
    Shell,
    None,
}

/// Pick a language from a filename extension.
pub fn language_for(path: &str) -> Lang {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "rs" => Lang::Rust,
        "c" | "h" | "cpp" | "cc" | "hpp" | "js" | "ts" | "go" | "java" | "json" => Lang::CLike,
        "py" => Lang::Python,
        "sh" | "bash" | "zsh" | "toml" | "yaml" | "yml" => Lang::Shell,
        _ => Lang::None,
    }
}

fn keywords(lang: Lang) -> &'static [&'static str] {
    match lang {
        Lang::Rust => &[
            "fn", "let", "mut", "pub", "use", "mod", "struct", "enum", "impl", "trait", "for",
            "while", "loop", "if", "else", "match", "return", "self", "Self", "crate", "super",
            "as", "const", "static", "ref", "move", "where", "async", "await", "dyn", "type",
        ],
        Lang::CLike => &[
            "function", "var", "let", "const", "if", "else", "for", "while", "return", "class",
            "new", "import", "export", "from", "int", "char", "void", "struct", "switch", "case",
            "break", "continue", "func", "package", "public", "private", "static",
        ],
        Lang::Python => &[
            "def", "class", "import", "from", "return", "if", "elif", "else", "for", "while",
            "try", "except", "finally", "with", "as", "lambda", "yield", "pass", "None", "True",
            "False", "and", "or", "not", "in", "is",
        ],
        Lang::Shell => &[
            "if", "then", "else", "fi", "for", "in", "do", "done", "while", "case", "esac",
            "function", "echo", "export", "local", "return",
        ],
        Lang::None => &[],
    }
}

fn line_comment(lang: Lang) -> Option<&'static str> {
    match lang {
        Lang::Rust | Lang::CLike => Some("//"),
        Lang::Python | Lang::Shell => Some("#"),
        Lang::None => None,
    }
}

/// Render a code block (with line numbers) for `text` in `lang`.
pub fn highlight_block(text: &str, lang: Lang) -> String {
    let mut out = String::from("<div class=\"code\"><table>");
    for (i, line) in text.split('\n').enumerate() {
        out.push_str(&format!(
            "<tr><td class=\"ln\">{}</td><td class=\"src\">{}</td></tr>",
            i + 1,
            highlight_line(line, lang)
        ));
    }
    out.push_str("</table></div>");
    out
}

/// Highlight a single line, returning escaped HTML with `<span>` token classes.
pub fn highlight_line(line: &str, lang: Lang) -> String {
    if let Some(lc) = line_comment(lang) {
        if let Some(pos) = find_comment_start(line, lc) {
            let (code, comment) = line.split_at(pos);
            return format!(
                "{}<span class=\"com\">{}</span>",
                highlight_code(code, lang),
                escape(comment)
            );
        }
    }
    highlight_code(line, lang)
}

/// Find a line-comment start that is not inside a string literal.
fn find_comment_start(line: &str, marker: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let m = marker.as_bytes();
    let mut i = 0;
    let mut in_str: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match in_str {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    in_str = Some(c);
                } else if bytes[i..].starts_with(m) {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn highlight_code(code: &str, lang: Lang) -> String {
    let kws = keywords(lang);
    let mut out = String::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let s: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&format!("<span class=\"str\">{}</span>", escape(&s)));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == '_')
            {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            out.push_str(&format!("<span class=\"num\">{}</span>", escape(&s)));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if kws.contains(&word.as_str()) {
                out.push_str(&format!("<span class=\"kw\">{}</span>", escape(&word)));
            } else {
                out.push_str(&escape(&word));
            }
        } else {
            out.push_str(&escape(&c.to_string()));
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(escape("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn highlights_keywords_strings_comments_and_escapes() {
        let html = highlight_line("let x = \"a<b\"; // note", Lang::Rust);
        assert!(html.contains("<span class=\"kw\">let</span>"));
        assert!(html.contains("<span class=\"str\">&quot;a&lt;b&quot;</span>"));
        assert!(html.contains("<span class=\"com\">// note</span>"));
        // The dangerous '<' inside the string must be escaped, never raw.
        assert!(!html.contains("a<b"));
    }

    #[test]
    fn comment_marker_inside_string_is_not_a_comment() {
        let html = highlight_line("let u = \"http://x\";", Lang::Rust);
        assert!(
            !html.contains("<span class=\"com\">"),
            "URL slashes are not a comment"
        );
    }

    #[test]
    fn language_detection() {
        assert_eq!(language_for("src/main.rs"), Lang::Rust);
        assert_eq!(language_for("a/b/app.py"), Lang::Python);
        assert_eq!(language_for("x.unknown"), Lang::None);
    }

    #[test]
    fn diff_colors_added_and_removed() {
        let html = render_diff("@@ -1 +1 @@\n-old\n+new\n");
        assert!(html.contains("class=\"src hunk\""));
        assert!(html.contains("class=\"src del\""));
        assert!(html.contains("class=\"src add\""));
    }
}
