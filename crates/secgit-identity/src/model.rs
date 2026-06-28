//! Core identity model: Users -> Organizations (with Teams) -> Repos.
//!
//! v1 is **private repos only**. A repo is owned by a user (personal) or an org. KEK
//! ownership maps to the org (or the user, for personal repos), matching the key
//! hierarchy in `secgit-store`.

use serde::{Deserialize, Serialize};

/// Access level on a repo. Ordered: Read < Write < Admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Read = 1,
    Write = 2,
    Admin = 3,
}

/// Membership level within an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgRole {
    Member,
    Owner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: String,
    pub slug: String,
    /// (user_id, role) membership.
    pub members: Vec<(String, OrgRole)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub member_ids: Vec<String>,
    /// Per-repo role grants this team confers on its members.
    pub repo_grants: Vec<(String, Role)>,
}

/// Who owns a repo: a user (personal) or an org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id")]
pub enum RepoOwner {
    User(String),
    Org(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    pub id: String,
    pub owner: RepoOwner,
    pub name: String,
    /// Always true in v1 (no public repos).
    pub private: bool,
    /// Direct collaborator grants (user_id, role) — mainly for personal repos.
    pub collaborators: Vec<(String, Role)>,
}

impl Repo {
    /// Stable storage/KEK resource id, e.g. `org:acme/widgets` or `user:alice/dots`.
    pub fn resource_id(&self) -> String {
        match &self.owner {
            RepoOwner::User(u) => format!("user:{u}/{}", self.name),
            RepoOwner::Org(o) => format!("org:{o}/{}", self.name),
        }
    }
    /// The KEK owner id (org for org repos, user for personal repos).
    pub fn kek_owner(&self) -> String {
        match &self.owner {
            RepoOwner::User(u) => format!("user:{u}"),
            RepoOwner::Org(o) => format!("org:{o}"),
        }
    }
}
