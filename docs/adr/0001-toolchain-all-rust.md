# ADR 0001: All-Rust toolchain; minimal forge on gitoxide

Status: accepted (settled decision; not re-litigated here)

## Decision
The forge floor is a minimal forge built in Rust on gitoxide (`gix`), not a
Forgejo/Gitea (Go) fork. The one conscious exception to all-Rust is the production PQC
path (aws-lc-rs / rustls), chosen for audited, C-backed crypto (see ADR 0004).

## Implementation reality (`[VERIFY]`)
gitoxide currently has **no server-side `receive-pack` (push)** and only a nascent,
unmerged `upload-pack`. Therefore:

- **Reads** (refs, HEAD, browse, diff, metadata) use `gix` — `crates/secgit-forge`.
- **Transfer / pack work** shells out to canonical `git` via `--stateless-rpc`
  (`git-upload-pack` / `git-receive-pack`) — `crates/secgit-git`. This is the proven
  pack engine and keeps the wire protocol correct.

This does not reopen the settled gitoxide-over-Forgejo decision: the forge is Rust;
git is used as the pack engine. Forgejo-wrap remains a schedule-only fallback if the
git-CLI transfer path proves operationally unacceptable.

## Gaps we build ourselves
Access control in front of the git CLI, repo lifecycle/quotas, smart-HTTP
advertisement wrapping, server hooks that emit audit-log entries, and encrypted-at-rest
persistence (`git bundle` through the encrypted store).

## Re-check at implementation time
gitoxide `crate-status.md` for server-side `upload-pack`/`receive-pack` progress; if it
matures, migrate transfer off the git CLI.
