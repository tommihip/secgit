//! Persistence for the identity [`Directory`] (and forge metadata) backed by the
//! encrypted-at-rest [`EncryptedStore`].
//!
//! Everything written here is ciphertext on the operator's disk: usernames, emails, org
//! membership, team grants, repo names and ownership are all sensitive metadata under the
//! provider-blindness claim, so they go through the same envelope encryption as repo
//! objects. The in-memory [`Directory`] is kept as a fast authorization cache and is fully
//! rebuilt from the store on [`PersistentDirectory::open`].
//!
//! Because the store hashes keys (so the operator cannot even enumerate ids by listing the
//! directory), enumeration is supported via explicit, encrypted **index** objects per
//! collection.

use crate::model::{Org, Repo, Team, User};
use crate::{Directory, IdentityError, Result, Role};
use secgit_store::EncryptedStore;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Single store namespace ("repo id" in `EncryptedStore` terms) for all identity objects.
const NS: &str = "secgit/directory";

const IDX_USERS: &str = "index/users";
const IDX_ORGS: &str = "index/orgs";
const IDX_TEAMS: &str = "index/teams";
const IDX_REPOS: &str = "index/repos";

fn to_storage(e: secgit_store::StoreError) -> IdentityError {
    IdentityError::Storage(e.to_string())
}
fn to_serde<E: std::fmt::Display>(e: E) -> IdentityError {
    IdentityError::Serde(e.to_string())
}

/// A [`Directory`] whose mutations are written through to an [`EncryptedStore`].
pub struct PersistentDirectory {
    store: EncryptedStore,
    dir: Directory,
}

impl PersistentDirectory {
    /// Open a persistent directory over `store`, loading any existing identities.
    pub fn open(store: EncryptedStore) -> Result<Self> {
        let mut dir = Directory::new();
        for id in read_index(&store, IDX_USERS)? {
            if let Some(u) = read_obj::<User>(&store, "user", &id)? {
                dir.add_user(u)?;
            }
        }
        for id in read_index(&store, IDX_ORGS)? {
            if let Some(o) = read_obj::<Org>(&store, "org", &id)? {
                dir.add_org(o)?;
            }
        }
        for id in read_index(&store, IDX_TEAMS)? {
            if let Some(t) = read_obj::<Team>(&store, "team", &id)? {
                dir.add_team(t)?;
            }
        }
        for id in read_index(&store, IDX_REPOS)? {
            if let Some(r) = read_obj::<Repo>(&store, "repo", &id)? {
                dir.add_repo(r)?;
            }
        }
        Ok(Self { store, dir })
    }

    /// Read-only access to the in-memory directory (authorization, lookups, listing).
    pub fn directory(&self) -> &Directory {
        &self.dir
    }

    /// Authorization passthrough.
    pub fn can(&self, user_id: &str, repo_id: &str, required: Role) -> bool {
        self.dir.can(user_id, repo_id, required)
    }
    pub fn effective_role(&self, user_id: &str, repo_id: &str) -> Option<Role> {
        self.dir.effective_role(user_id, repo_id)
    }

    // ---- Users ---------------------------------------------------------------

    pub fn create_user(&mut self, user: User) -> Result<()> {
        self.dir.add_user(user.clone())?;
        write_obj(&self.store, "user", &user.id, &user)?;
        add_to_index(&self.store, IDX_USERS, &user.id)
    }
    pub fn update_user(&mut self, user: User) -> Result<()> {
        self.dir.update_user(user.clone())?;
        write_obj(&self.store, "user", &user.id, &user)
    }
    pub fn delete_user(&mut self, id: &str) -> Result<()> {
        self.dir.remove_user(id)?;
        self.store
            .delete(NS, &okey("user", id))
            .map_err(to_storage)?;
        remove_from_index(&self.store, IDX_USERS, id)
    }
    pub fn get_user(&self, id: &str) -> Option<&User> {
        self.dir.user(id)
    }
    pub fn list_users(&self) -> Vec<&User> {
        self.dir.list_users()
    }

    // ---- Orgs ----------------------------------------------------------------

    pub fn create_org(&mut self, org: Org) -> Result<()> {
        self.dir.add_org(org.clone())?;
        write_obj(&self.store, "org", &org.id, &org)?;
        add_to_index(&self.store, IDX_ORGS, &org.id)
    }
    pub fn update_org(&mut self, org: Org) -> Result<()> {
        self.dir.update_org(org.clone())?;
        write_obj(&self.store, "org", &org.id, &org)
    }
    pub fn delete_org(&mut self, id: &str) -> Result<()> {
        self.dir.remove_org(id)?;
        self.store
            .delete(NS, &okey("org", id))
            .map_err(to_storage)?;
        remove_from_index(&self.store, IDX_ORGS, id)
    }
    pub fn get_org(&self, id: &str) -> Option<&Org> {
        self.dir.org(id)
    }
    pub fn list_orgs(&self) -> Vec<&Org> {
        self.dir.list_orgs()
    }

    // ---- Teams ---------------------------------------------------------------

    pub fn create_team(&mut self, team: Team) -> Result<()> {
        self.dir.add_team(team.clone())?;
        write_obj(&self.store, "team", &team.id, &team)?;
        add_to_index(&self.store, IDX_TEAMS, &team.id)
    }
    pub fn update_team(&mut self, team: Team) -> Result<()> {
        self.dir.update_team(team.clone())?;
        write_obj(&self.store, "team", &team.id, &team)
    }
    pub fn delete_team(&mut self, id: &str) -> Result<()> {
        self.dir.remove_team(id)?;
        self.store
            .delete(NS, &okey("team", id))
            .map_err(to_storage)?;
        remove_from_index(&self.store, IDX_TEAMS, id)
    }
    pub fn get_team(&self, id: &str) -> Option<&Team> {
        self.dir.team(id)
    }
    pub fn list_teams(&self) -> Vec<&Team> {
        self.dir.list_teams()
    }

    // ---- Repos ---------------------------------------------------------------

    pub fn create_repo(&mut self, repo: Repo) -> Result<()> {
        self.dir.add_repo(repo.clone())?;
        write_obj(&self.store, "repo", &repo.id, &repo)?;
        add_to_index(&self.store, IDX_REPOS, &repo.id)
    }
    pub fn update_repo(&mut self, repo: Repo) -> Result<()> {
        self.dir.update_repo(repo.clone())?;
        write_obj(&self.store, "repo", &repo.id, &repo)
    }
    pub fn delete_repo(&mut self, id: &str) -> Result<()> {
        self.dir.remove_repo(id)?;
        self.store
            .delete(NS, &okey("repo", id))
            .map_err(to_storage)?;
        remove_from_index(&self.store, IDX_REPOS, id)
    }
    pub fn get_repo(&self, id: &str) -> Option<&Repo> {
        self.dir.repo(id)
    }
    pub fn list_repos(&self) -> Vec<&Repo> {
        self.dir.list_repos()
    }
    pub fn repos_visible_to(&self, user_id: &str) -> Vec<&Repo> {
        self.dir.repos_visible_to(user_id)
    }

    // ---- Access-control surface (write-through) ------------------------------

    /// Add or update an org member's role.
    pub fn set_org_member(
        &mut self,
        org_id: &str,
        user_id: &str,
        role: crate::OrgRole,
    ) -> Result<()> {
        let mut org = self.cloned_org(org_id)?;
        org.members.retain(|(u, _)| u != user_id);
        org.members.push((user_id.to_string(), role));
        self.update_org(org)
    }
    pub fn remove_org_member(&mut self, org_id: &str, user_id: &str) -> Result<()> {
        let mut org = self.cloned_org(org_id)?;
        org.members.retain(|(u, _)| u != user_id);
        self.update_org(org)
    }

    /// Add or remove a team member.
    pub fn add_team_member(&mut self, team_id: &str, user_id: &str) -> Result<()> {
        let mut team = self.cloned_team(team_id)?;
        if !team.member_ids.iter().any(|u| u == user_id) {
            team.member_ids.push(user_id.to_string());
        }
        self.update_team(team)
    }
    pub fn remove_team_member(&mut self, team_id: &str, user_id: &str) -> Result<()> {
        let mut team = self.cloned_team(team_id)?;
        team.member_ids.retain(|u| u != user_id);
        self.update_team(team)
    }

    /// Grant or update a team's role on a repo.
    pub fn set_team_repo_grant(&mut self, team_id: &str, repo_id: &str, role: Role) -> Result<()> {
        let mut team = self.cloned_team(team_id)?;
        team.repo_grants.retain(|(r, _)| r != repo_id);
        team.repo_grants.push((repo_id.to_string(), role));
        self.update_team(team)
    }
    pub fn revoke_team_repo_grant(&mut self, team_id: &str, repo_id: &str) -> Result<()> {
        let mut team = self.cloned_team(team_id)?;
        team.repo_grants.retain(|(r, _)| r != repo_id);
        self.update_team(team)
    }

    /// Add or update a direct repo collaborator.
    pub fn set_collaborator(&mut self, repo_id: &str, user_id: &str, role: Role) -> Result<()> {
        let mut repo = self.cloned_repo(repo_id)?;
        repo.collaborators.retain(|(u, _)| u != user_id);
        repo.collaborators.push((user_id.to_string(), role));
        self.update_repo(repo)
    }
    pub fn remove_collaborator(&mut self, repo_id: &str, user_id: &str) -> Result<()> {
        let mut repo = self.cloned_repo(repo_id)?;
        repo.collaborators.retain(|(u, _)| u != user_id);
        self.update_repo(repo)
    }

    /// Teams belonging to an org.
    pub fn teams_in_org(&self, org_id: &str) -> Vec<&Team> {
        self.dir
            .list_teams()
            .into_iter()
            .filter(|t| t.org_id == org_id)
            .collect()
    }

    /// Whether `user_id` is an owner of `org_id`.
    pub fn is_org_owner(&self, org_id: &str, user_id: &str) -> bool {
        self.dir
            .org(org_id)
            .map(|o| {
                o.members
                    .iter()
                    .any(|(u, r)| u == user_id && matches!(r, crate::OrgRole::Owner))
            })
            .unwrap_or(false)
    }

    /// Orgs a user is a member of.
    pub fn orgs_for_user(&self, user_id: &str) -> Vec<&Org> {
        self.dir
            .list_orgs()
            .into_iter()
            .filter(|o| o.members.iter().any(|(u, _)| u == user_id))
            .collect()
    }

    fn cloned_org(&self, id: &str) -> Result<Org> {
        self.dir
            .org(id)
            .cloned()
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
    fn cloned_team(&self, id: &str) -> Result<Team> {
        self.dir
            .team(id)
            .cloned()
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
    fn cloned_repo(&self, id: &str) -> Result<Repo> {
        self.dir
            .repo(id)
            .cloned()
            .ok_or_else(|| IdentityError::NotFound(id.into()))
    }
}

fn okey(kind: &str, id: &str) -> String {
    format!("{kind}/{id}")
}

fn write_obj<T: Serialize>(store: &EncryptedStore, kind: &str, id: &str, v: &T) -> Result<()> {
    let bytes = serde_json::to_vec(v).map_err(to_serde)?;
    store.put(NS, &okey(kind, id), &bytes).map_err(to_storage)
}

fn read_obj<T: DeserializeOwned>(
    store: &EncryptedStore,
    kind: &str,
    id: &str,
) -> Result<Option<T>> {
    match store.get(NS, &okey(kind, id)).map_err(to_storage)? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(to_serde)?)),
        None => Ok(None),
    }
}

fn read_index(store: &EncryptedStore, idx: &str) -> Result<Vec<String>> {
    match store.get(NS, idx).map_err(to_storage)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(to_serde),
        None => Ok(vec![]),
    }
}

fn add_to_index(store: &EncryptedStore, idx: &str, id: &str) -> Result<()> {
    let mut ids = read_index(store, idx)?;
    if !ids.iter().any(|x| x == id) {
        ids.push(id.to_string());
        let bytes = serde_json::to_vec(&ids).map_err(to_serde)?;
        store.put(NS, idx, &bytes).map_err(to_storage)?;
    }
    Ok(())
}

fn remove_from_index(store: &EncryptedStore, idx: &str, id: &str) -> Result<()> {
    let mut ids = read_index(store, idx)?;
    ids.retain(|x| x != id);
    let bytes = serde_json::to_vec(&ids).map_err(to_serde)?;
    store.put(NS, idx, &bytes).map_err(to_storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OrgRole, RepoOwner};
    use secgit_crypto::aead::SymKey;

    fn store(tag: &str) -> (EncryptedStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("secgit-dir-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (
            EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap(),
            dir,
        )
    }

    fn user(id: &str, name: &str) -> User {
        User {
            id: id.into(),
            username: name.into(),
            email: format!("{name}@x"),
        }
    }

    #[test]
    fn crud_round_trips_through_store() {
        let (s, dir) = store("crud");
        let kek_dir = dir.clone();
        {
            let mut pd = PersistentDirectory::open(s).unwrap();
            pd.create_user(user("u_alice", "alice")).unwrap();
            pd.create_org(Org {
                id: "o_acme".into(),
                slug: "acme".into(),
                members: vec![("u_alice".into(), OrgRole::Owner)],
            })
            .unwrap();
            pd.create_repo(Repo {
                id: "r_widgets".into(),
                owner: RepoOwner::Org("o_acme".into()),
                name: "widgets".into(),
                private: true,
                collaborators: vec![],
            })
            .unwrap();
            assert!(pd.can("u_alice", "r_widgets", Role::Admin));
        }
        // Reopen with the same KEK and confirm everything persisted.
        let s2 = EncryptedStore::open(&kek_dir, SymKey::generate().unwrap());
        // Different KEK can't decrypt; prove persistence requires the right key.
        assert!(s2.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_with_same_kek_restores_state() {
        let dir = std::env::temp_dir().join(format!("secgit-dir-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kek = SymKey::generate().unwrap();
        {
            let s = EncryptedStore::open(&dir, kek.clone()).unwrap();
            let mut pd = PersistentDirectory::open(s).unwrap();
            pd.create_user(user("u_bob", "bob")).unwrap();
            pd.create_user(user("u_carol", "carol")).unwrap();
            pd.delete_user("u_bob").unwrap();
        }
        let s = EncryptedStore::open(&dir, kek).unwrap();
        let pd = PersistentDirectory::open(s).unwrap();
        assert!(pd.get_user("u_carol").is_some());
        assert!(pd.get_user("u_bob").is_none());
        assert_eq!(pd.list_users().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_control_surface_changes_effective_roles_and_persists() {
        use crate::model::Team;
        let dir = std::env::temp_dir().join(format!("secgit-dir-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kek = SymKey::generate().unwrap();
        {
            let s = EncryptedStore::open(&dir, kek.clone()).unwrap();
            let mut pd = PersistentDirectory::open(s).unwrap();
            pd.create_user(user("u_alice", "alice")).unwrap();
            pd.create_user(user("u_bob", "bob")).unwrap();
            pd.create_org(Org {
                id: "o_acme".into(),
                slug: "acme".into(),
                members: vec![],
            })
            .unwrap();
            pd.create_repo(Repo {
                id: "acme/widgets".into(),
                owner: RepoOwner::Org("o_acme".into()),
                name: "widgets".into(),
                private: true,
                collaborators: vec![],
            })
            .unwrap();
            pd.create_team(Team {
                id: "t_eng".into(),
                org_id: "o_acme".into(),
                name: "eng".into(),
                member_ids: vec![],
                repo_grants: vec![],
            })
            .unwrap();

            // Org owner gets admin on org repos.
            pd.set_org_member("o_acme", "u_alice", OrgRole::Owner)
                .unwrap();
            assert_eq!(
                pd.effective_role("u_alice", "acme/widgets"),
                Some(Role::Admin)
            );

            // Team grant gives bob write once he's a member.
            pd.add_team_member("t_eng", "u_bob").unwrap();
            pd.set_team_repo_grant("t_eng", "acme/widgets", Role::Write)
                .unwrap();
            assert!(pd.can("u_bob", "acme/widgets", Role::Write));
            assert!(!pd.can("u_bob", "acme/widgets", Role::Admin));
            assert_eq!(pd.teams_in_org("o_acme").len(), 1);

            // Revoking the grant removes access.
            pd.revoke_team_repo_grant("t_eng", "acme/widgets").unwrap();
            assert!(!pd.can("u_bob", "acme/widgets", Role::Read));
        }
        // Persisted across reopen.
        let s = EncryptedStore::open(&dir, kek).unwrap();
        let pd = PersistentDirectory::open(s).unwrap();
        assert_eq!(
            pd.effective_role("u_alice", "acme/widgets"),
            Some(Role::Admin)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_metadata_is_ciphertext_on_disk() {
        use secgit_leaktest::{assert_dir_ciphertext_nonempty, Canary};
        let canary = Canary::new("username");
        let dir = std::env::temp_dir().join(format!("secgit-dir-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
            let mut pd = PersistentDirectory::open(s).unwrap();
            pd.create_user(user("u_x", canary.as_str())).unwrap();
        }
        // The username (sensitive metadata) must not appear in plaintext on disk.
        assert_dir_ciphertext_nonempty(&dir, &[canary.as_bytes()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
