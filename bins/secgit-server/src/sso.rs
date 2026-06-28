//! Server wiring for enterprise SSO (SAML) and provisioning (SCIM), all in-CVM.
//!
//! - SCIM: `/scim/v2/...` is gated by a provisioning bearer token and dispatched to a
//!   [`ServerScimBackend`] that persists into the encrypted identity directory (users) and
//!   an encrypted SCIM-group/profile side-store. Deactivation/deletion revokes the user's
//!   live sessions, so deprovisioning takes effect immediately.
//! - SAML: `POST /sso/saml/acs` verifies an IdP-signed assertion against the pinned IdP
//!   cert, just-in-time provisions the user, and mints a session.

use crate::authz::ServerIdentity;
use crate::http::{Request, Response};
use crate::App;
use secgit_identity::model::User;
use secgit_sso::scim::{Scim, ScimBackend, ScimError, ScimGroup, ScimUser};
use secgit_store::EncryptedStore;
use serde::{Deserialize, Serialize};

const SCIM_NS: &str = "_scim";

fn rand_id(prefix: &str) -> String {
    let v = secgit_crypto::primitives::random_vec(8).unwrap_or_else(|_| vec![0u8; 8]);
    format!("{prefix}{}", hex::encode(v))
}

#[derive(Default, Serialize, Deserialize)]
struct ScimProfile {
    active: bool,
    external_id: Option<String>,
    display_name: Option<String>,
}

/// SCIM backend over the server's identity directory + an encrypted side-store.
pub struct ServerScimBackend<'a> {
    identity: &'a mut ServerIdentity,
    store: &'a EncryptedStore,
}

impl<'a> ServerScimBackend<'a> {
    pub fn new(identity: &'a mut ServerIdentity, store: &'a EncryptedStore) -> Self {
        Self { identity, store }
    }

    fn profile(&self, uid: &str) -> ScimProfile {
        self.store
            .get(SCIM_NS, &format!("profile/{uid}"))
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(ScimProfile {
                active: true,
                external_id: None,
                display_name: None,
            })
    }
    fn write_profile(&self, uid: &str, p: &ScimProfile) {
        if let Ok(b) = serde_json::to_vec(p) {
            let _ = self.store.put(SCIM_NS, &format!("profile/{uid}"), &b);
        }
    }
    fn to_scim(&self, u: &User) -> ScimUser {
        let p = self.profile(&u.id);
        ScimUser {
            id: u.id.clone(),
            user_name: u.username.clone(),
            display_name: p.display_name,
            email: if u.email.is_empty() {
                None
            } else {
                Some(u.email.clone())
            },
            external_id: p.external_id,
            active: p.active,
        }
    }

    fn group_get(&self, id: &str) -> Option<ScimGroup> {
        let b = self
            .store
            .get(SCIM_NS, &format!("group/{id}"))
            .ok()
            .flatten()?;
        serde_json::from_slice::<StoredGroup>(&b)
            .ok()
            .map(|g| g.into())
    }
    fn group_index(&self) -> Vec<String> {
        self.store
            .get(SCIM_NS, "group/index")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    fn group_put(&self, g: &ScimGroup) {
        if let Ok(b) = serde_json::to_vec(&StoredGroup::from(g)) {
            let _ = self.store.put(SCIM_NS, &format!("group/{}", g.id), &b);
        }
        let mut idx = self.group_index();
        if !idx.contains(&g.id) {
            idx.push(g.id.clone());
            if let Ok(b) = serde_json::to_vec(&idx) {
                let _ = self.store.put(SCIM_NS, "group/index", &b);
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredGroup {
    id: String,
    display_name: String,
    external_id: Option<String>,
    member_ids: Vec<String>,
}
impl From<&ScimGroup> for StoredGroup {
    fn from(g: &ScimGroup) -> Self {
        Self {
            id: g.id.clone(),
            display_name: g.display_name.clone(),
            external_id: g.external_id.clone(),
            member_ids: g.member_ids.clone(),
        }
    }
}
impl From<StoredGroup> for ScimGroup {
    fn from(g: StoredGroup) -> Self {
        Self {
            id: g.id,
            display_name: g.display_name,
            external_id: g.external_id,
            member_ids: g.member_ids,
        }
    }
}

impl ScimBackend for ServerScimBackend<'_> {
    fn create_user(&mut self, u: &ScimUser) -> Result<ScimUser, ScimError> {
        let uid = rand_id("u_");
        let user = User {
            id: uid.clone(),
            username: u.user_name.clone(),
            email: u.email.clone().unwrap_or_default(),
        };
        self.identity
            .dir
            .create_user(user)
            .map_err(|e| ScimError::Backend(e.to_string()))?;
        self.write_profile(
            &uid,
            &ScimProfile {
                active: u.active,
                external_id: u.external_id.clone(),
                display_name: u.display_name.clone(),
            },
        );
        Ok(self.get_user(&uid).unwrap())
    }

    fn get_user(&self, id: &str) -> Option<ScimUser> {
        self.identity.dir.get_user(id).map(|u| self.to_scim(u))
    }

    fn find_user_by_username(&self, user_name: &str) -> Option<ScimUser> {
        let uid = self
            .identity
            .dir
            .list_users()
            .into_iter()
            .find(|u| u.username == user_name)
            .map(|u| u.id.clone())?;
        self.get_user(&uid)
    }

    fn list_users(&self) -> Vec<ScimUser> {
        self.identity
            .dir
            .list_users()
            .into_iter()
            .map(|u| self.to_scim(u))
            .collect()
    }

    fn replace_user(&mut self, id: &str, u: &ScimUser) -> Result<ScimUser, ScimError> {
        if self.identity.dir.get_user(id).is_none() {
            return Err(ScimError::NotFound);
        }
        let user = User {
            id: id.to_string(),
            username: u.user_name.clone(),
            email: u.email.clone().unwrap_or_default(),
        };
        self.identity
            .dir
            .update_user(user)
            .map_err(|e| ScimError::Backend(e.to_string()))?;
        self.write_profile(
            id,
            &ScimProfile {
                active: u.active,
                external_id: u.external_id.clone(),
                display_name: u.display_name.clone(),
            },
        );
        if !u.active {
            self.identity.sessions.revoke_all_for(id);
        }
        Ok(self.get_user(id).unwrap())
    }

    fn set_user_active(&mut self, id: &str, active: bool) -> Result<ScimUser, ScimError> {
        if self.identity.dir.get_user(id).is_none() {
            return Err(ScimError::NotFound);
        }
        let mut p = self.profile(id);
        p.active = active;
        self.write_profile(id, &p);
        if !active {
            self.identity.sessions.revoke_all_for(id);
        }
        Ok(self.get_user(id).unwrap())
    }

    fn delete_user(&mut self, id: &str) -> Result<(), ScimError> {
        self.identity
            .dir
            .delete_user(id)
            .map_err(|_| ScimError::NotFound)?;
        let _ = self.store.delete(SCIM_NS, &format!("profile/{id}"));
        self.identity.sessions.revoke_all_for(id);
        Ok(())
    }

    fn create_group(&mut self, g: &ScimGroup) -> Result<ScimGroup, ScimError> {
        let mut g = g.clone();
        g.id = rand_id("g_");
        self.group_put(&g);
        Ok(g)
    }
    fn get_group(&self, id: &str) -> Option<ScimGroup> {
        self.group_get(id)
    }
    fn list_groups(&self) -> Vec<ScimGroup> {
        self.group_index()
            .iter()
            .filter_map(|id| self.group_get(id))
            .collect()
    }
    fn replace_group(&mut self, id: &str, g: &ScimGroup) -> Result<ScimGroup, ScimError> {
        if self.group_get(id).is_none() {
            return Err(ScimError::NotFound);
        }
        let mut g = g.clone();
        g.id = id.to_string();
        self.group_put(&g);
        Ok(g)
    }
    fn delete_group(&mut self, id: &str) -> Result<(), ScimError> {
        if self.group_get(id).is_none() {
            return Err(ScimError::NotFound);
        }
        let _ = self.store.delete(SCIM_NS, &format!("group/{id}"));
        let mut idx = self.group_index();
        idx.retain(|x| x != id);
        if let Ok(b) = serde_json::to_vec(&idx) {
            let _ = self.store.put(SCIM_NS, "group/index", &b);
        }
        Ok(())
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

/// Route `/scim/v2/...` requests. Returns `None` if the path is not SCIM.
pub fn route_scim(app: &App, req: &Request) -> Option<Response> {
    let rest = req.path.strip_prefix("/scim/v2/")?;
    // Provisioning auth: a dedicated bearer token (not user sessions).
    let Some(expected) = app.scim_token.as_deref() else {
        return Some(Response::text(
            503,
            "Service Unavailable",
            "SCIM not configured",
        ));
    };
    let presented = req.bearer_token().unwrap_or_default();
    if presented.is_empty()
        || !secgit_crypto::primitives::ct_eq(presented.as_bytes(), expected.as_bytes())
    {
        return Some(
            Response::text(401, "Unauthorized", "invalid provisioning token")
                .with_header("WWW-Authenticate", "Bearer"),
        );
    }

    let filter = req.query.get("filter").map(String::as_str);
    let mut identity = app.identity.lock().unwrap();
    let mut backend = ServerScimBackend::new(&mut identity, &app.store);
    let base = format!("{}/scim/v2", app.external_base_url);
    let mut scim = Scim::new(&mut backend, &base);
    let r = scim.dispatch(&req.method, rest, filter, &req.body);
    let body = if r.body.is_null() {
        vec![]
    } else {
        r.body.to_string().into_bytes()
    };
    Some(Response::new(
        r.status,
        status_reason(r.status),
        "application/scim+json",
        body,
    ))
}

/// Handle the SAML assertion-consumer POST. On success, mints a session and returns the
/// bearer token (a browser SP would set a cookie + redirect; this minimal server returns
/// JSON so any client can complete login).
pub fn route_saml_acs(app: &App, req: &Request) -> Response {
    let Some(sp) = app.saml.as_ref() else {
        return Response::text(503, "Service Unavailable", "SAML not configured");
    };
    let form = req.form();
    let Some(saml_response) = form.get("SAMLResponse") else {
        return Response::text(400, "Bad Request", "missing SAMLResponse");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let assertion = match sp.verify_b64_response(saml_response, now) {
        Ok(a) => a,
        Err(e) => return Response::text(401, "Unauthorized", &format!("SAML rejected: {e}")),
    };

    // JIT provisioning: map NameID/email to a user, creating one if needed.
    let username = assertion
        .email()
        .unwrap_or_else(|| assertion.name_id.clone());
    let mut identity = app.identity.lock().unwrap();
    let existing = identity
        .dir
        .list_users()
        .into_iter()
        .find(|u| u.username == username)
        .map(|u| u.id.clone());
    let uid = match existing {
        Some(id) => id,
        None => {
            let id = rand_id("u_");
            let user = User {
                id: id.clone(),
                username: username.clone(),
                email: assertion.email().unwrap_or_default(),
            };
            if let Err(e) = identity.dir.create_user(user) {
                return Response::text(500, "Internal Server Error", &format!("provision: {e}"));
            }
            id
        }
    };
    match identity.sessions.create(&uid, true) {
        Ok(token) => Response::json(&serde_json::json!({
            "authenticated": true,
            "user_id": uid,
            "username": username,
            "session_token": token,
            "usage": "Send as 'Authorization: Bearer <session_token>' or as the HTTP Basic password for git.",
        })),
        Err(e) => Response::text(500, "Internal Server Error", &format!("session: {e}")),
    }
}

/// Minimal SP metadata so an admin can register SecGit with their IdP.
pub fn saml_metadata(app: &App) -> Response {
    let Some(sp) = app.saml.as_ref() else {
        return Response::text(503, "Service Unavailable", "SAML not configured");
    };
    let xml = format!(
        r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
        entity = sp.sp_entity_id,
        acs = sp.acs_url,
    );
    Response::new(200, "OK", "application/samlmetadata+xml", xml.into_bytes())
}
