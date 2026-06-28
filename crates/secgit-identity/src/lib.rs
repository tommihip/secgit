//! # secgit-identity
//!
//! The identity model and access-control resolver for SecGit, plus the pluggable auth
//! abstraction (OIDC + local). See [`model`] for the data model and [`auth`] for
//! authentication.

pub mod auth;
pub mod model;
pub mod session;
pub mod store;
pub mod totp;

pub use auth::{
    Authenticator, JwksOidcVerifier, LocalAuthenticator, OidcClaims, OidcVerifier, PasswordHash,
};
pub use model::{Org, OrgRole, Repo, RepoOwner, Role, Team, User};
pub use session::{Session, SessionStore};
pub use store::PersistentDirectory;
pub use totp::TotpSecret;

use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    Exists(String),
    #[error("crypto error")]
    Crypto,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

pub type Result<T> = core::result::Result<T, IdentityError>;

/// In-memory directory of identities and the access-control resolver over it.
///
/// Persistence is intentionally out of scope here; a deployment backs this with the
/// encrypted store. The value of this type is the *authorization logic*.
#[derive(Default)]
pub struct Directory {
    users: HashMap<String, User>,
    orgs: HashMap<String, Org>,
    teams: HashMap<String, Team>,
    repos: HashMap<String, Repo>,
}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_user(&mut self, user: User) -> Result<()> {
        if self.users.contains_key(&user.id) {
            return Err(IdentityError::Exists(user.id));
        }
        self.users.insert(user.id.clone(), user);
        Ok(())
    }
    pub fn add_org(&mut self, org: Org) -> Result<()> {
        if self.orgs.contains_key(&org.id) {
            return Err(IdentityError::Exists(org.id));
        }
        self.orgs.insert(org.id.clone(), org);
        Ok(())
    }
    pub fn add_team(&mut self, team: Team) -> Result<()> {
        self.teams.insert(team.id.clone(), team);
        Ok(())
    }
    pub fn add_repo(&mut self, repo: Repo) -> Result<()> {
        if self.repos.contains_key(&repo.id) {
            return Err(IdentityError::Exists(repo.id));
        }
        self.repos.insert(repo.id.clone(), repo);
        Ok(())
    }

    pub fn user(&self, id: &str) -> Option<&User> {
        self.users.get(id)
    }
    pub fn org(&self, id: &str) -> Option<&Org> {
        self.orgs.get(id)
    }
    pub fn team(&self, id: &str) -> Option<&Team> {
        self.teams.get(id)
    }
    pub fn repo(&self, id: &str) -> Option<&Repo> {
        self.repos.get(id)
    }

    /// Replace an existing entity (errors if it does not exist).
    pub fn update_user(&mut self, user: User) -> Result<()> {
        if !self.users.contains_key(&user.id) {
            return Err(IdentityError::NotFound(user.id));
        }
        self.users.insert(user.id.clone(), user);
        Ok(())
    }
    pub fn update_org(&mut self, org: Org) -> Result<()> {
        if !self.orgs.contains_key(&org.id) {
            return Err(IdentityError::NotFound(org.id));
        }
        self.orgs.insert(org.id.clone(), org);
        Ok(())
    }
    pub fn update_team(&mut self, team: Team) -> Result<()> {
        if !self.teams.contains_key(&team.id) {
            return Err(IdentityError::NotFound(team.id));
        }
        self.teams.insert(team.id.clone(), team);
        Ok(())
    }
    pub fn update_repo(&mut self, repo: Repo) -> Result<()> {
        if !self.repos.contains_key(&repo.id) {
            return Err(IdentityError::NotFound(repo.id));
        }
        self.repos.insert(repo.id.clone(), repo);
        Ok(())
    }

    pub fn remove_user(&mut self, id: &str) -> Result<()> {
        self.users
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
    pub fn remove_org(&mut self, id: &str) -> Result<()> {
        self.orgs
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
    pub fn remove_team(&mut self, id: &str) -> Result<()> {
        self.teams
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
    pub fn remove_repo(&mut self, id: &str) -> Result<()> {
        self.repos
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }

    pub fn list_users(&self) -> Vec<&User> {
        self.users.values().collect()
    }
    pub fn list_orgs(&self) -> Vec<&Org> {
        self.orgs.values().collect()
    }
    pub fn list_teams(&self) -> Vec<&Team> {
        self.teams.values().collect()
    }
    pub fn list_repos(&self) -> Vec<&Repo> {
        self.repos.values().collect()
    }

    /// Repos a user can see at `Read` or above (for listing UIs).
    pub fn repos_visible_to(&self, user_id: &str) -> Vec<&Repo> {
        self.repos
            .values()
            .filter(|r| self.can(user_id, &r.id, Role::Read))
            .collect()
    }

    fn org_role(&self, org_id: &str, user_id: &str) -> Option<OrgRole> {
        self.orgs.get(org_id).and_then(|o| {
            o.members
                .iter()
                .find(|(u, _)| u == user_id)
                .map(|(_, r)| *r)
        })
    }

    /// Resolve the effective [`Role`] a user has on a repo, if any.
    ///
    /// The effective role is the maximum granted by: personal ownership, org
    /// ownership, direct collaboration, and team grants (for team members).
    pub fn effective_role(&self, user_id: &str, repo_id: &str) -> Option<Role> {
        let repo = self.repos.get(repo_id)?;
        let mut best: Option<Role> = None;
        let bump = |r: Role, best: &mut Option<Role>| {
            if best.map(|b| r > b).unwrap_or(true) {
                *best = Some(r);
            }
        };

        match &repo.owner {
            RepoOwner::User(owner) if owner == user_id => bump(Role::Admin, &mut best),
            RepoOwner::Org(org_id) => {
                if matches!(self.org_role(org_id, user_id), Some(OrgRole::Owner)) {
                    bump(Role::Admin, &mut best);
                }
            }
            _ => {}
        }

        // Direct collaborators.
        for (u, r) in &repo.collaborators {
            if u == user_id {
                bump(*r, &mut best);
            }
        }

        // Team grants (only for repos in the team's org and for team members).
        for team in self.teams.values() {
            if !team.member_ids.iter().any(|m| m == user_id) {
                continue;
            }
            if let RepoOwner::Org(org_id) = &repo.owner {
                if &team.org_id != org_id {
                    continue;
                }
            } else {
                continue;
            }
            for (rid, r) in &team.repo_grants {
                if rid == repo_id {
                    bump(*r, &mut best);
                }
            }
        }

        best
    }

    /// Authorize an action requiring at least `required` role on `repo_id`.
    pub fn can(&self, user_id: &str, repo_id: &str, required: Role) -> bool {
        self.effective_role(user_id, repo_id)
            .map(|r| r >= required)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> Directory {
        let mut d = Directory::new();
        d.add_user(User {
            id: "u_alice".into(),
            username: "alice".into(),
            email: "a@x".into(),
        })
        .unwrap();
        d.add_user(User {
            id: "u_bob".into(),
            username: "bob".into(),
            email: "b@x".into(),
        })
        .unwrap();
        d.add_user(User {
            id: "u_carol".into(),
            username: "carol".into(),
            email: "c@x".into(),
        })
        .unwrap();
        d.add_org(Org {
            id: "o_acme".into(),
            slug: "acme".into(),
            members: vec![
                ("u_alice".into(), OrgRole::Owner),
                ("u_bob".into(), OrgRole::Member),
            ],
        })
        .unwrap();
        d.add_repo(Repo {
            id: "r_widgets".into(),
            owner: RepoOwner::Org("o_acme".into()),
            name: "widgets".into(),
            private: true,
            collaborators: vec![],
        })
        .unwrap();
        d.add_repo(Repo {
            id: "r_dots".into(),
            owner: RepoOwner::User("u_carol".into()),
            name: "dotfiles".into(),
            private: true,
            collaborators: vec![("u_bob".into(), Role::Read)],
        })
        .unwrap();
        d
    }

    #[test]
    fn org_owner_is_admin() {
        let d = directory();
        assert_eq!(d.effective_role("u_alice", "r_widgets"), Some(Role::Admin));
    }

    #[test]
    fn org_member_without_team_has_no_access() {
        let d = directory();
        assert_eq!(d.effective_role("u_bob", "r_widgets"), None);
        assert!(!d.can("u_bob", "r_widgets", Role::Read));
    }

    #[test]
    fn team_grant_confers_role() {
        let mut d = directory();
        d.add_team(Team {
            id: "t_eng".into(),
            org_id: "o_acme".into(),
            name: "eng".into(),
            member_ids: vec!["u_bob".into()],
            repo_grants: vec![("r_widgets".into(), Role::Write)],
        })
        .unwrap();
        assert_eq!(d.effective_role("u_bob", "r_widgets"), Some(Role::Write));
        assert!(d.can("u_bob", "r_widgets", Role::Write));
        assert!(!d.can("u_bob", "r_widgets", Role::Admin));
    }

    #[test]
    fn personal_owner_and_collaborator() {
        let d = directory();
        assert_eq!(d.effective_role("u_carol", "r_dots"), Some(Role::Admin));
        assert_eq!(d.effective_role("u_bob", "r_dots"), Some(Role::Read));
        assert_eq!(d.effective_role("u_alice", "r_dots"), None);
    }

    #[test]
    fn resource_id_mapping() {
        let d = directory();
        assert_eq!(
            d.repo("r_widgets").unwrap().resource_id(),
            "org:o_acme/widgets"
        );
        assert_eq!(d.repo("r_dots").unwrap().kek_owner(), "user:u_carol");
    }
}
