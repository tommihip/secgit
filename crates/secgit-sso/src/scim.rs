//! SCIM 2.0 (RFC 7643/7644) provisioning — Users and Groups.
//!
//! This is the JSON provisioning surface IdPs (Okta, Azure AD, etc.) use to create,
//! update, deactivate, and delete users/groups in SecGit. It is **storage-agnostic**: the
//! protocol logic (resource shapes, list envelopes, filters, PATCH for active-toggle,
//! error bodies) lives here behind a [`ScimBackend`] trait, which the server implements
//! over the encrypted identity directory. All provisioned metadata therefore lands in the
//! encrypted store like every other identity record.

use serde_json::{json, Value};

/// A SCIM User in SecGit's normalized form (the subset we map to the identity model).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimUser {
    pub id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub external_id: Option<String>,
    pub active: bool,
}

/// A SCIM Group with member user ids.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub member_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScimError {
    NotFound,
    Conflict(String),
    BadRequest(String),
    Backend(String),
}

impl ScimError {
    fn status(&self) -> u16 {
        match self {
            ScimError::NotFound => 404,
            ScimError::Conflict(_) => 409,
            ScimError::BadRequest(_) => 400,
            ScimError::Backend(_) => 500,
        }
    }
    fn detail(&self) -> String {
        match self {
            ScimError::NotFound => "Resource not found".into(),
            ScimError::Conflict(s) => s.clone(),
            ScimError::BadRequest(s) => s.clone(),
            ScimError::Backend(s) => s.clone(),
        }
    }
    fn body(&self) -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": self.status().to_string(),
            "detail": self.detail(),
        })
    }
}

/// The persistence seam SCIM operates over (implemented by the server).
pub trait ScimBackend {
    fn create_user(&mut self, u: &ScimUser) -> Result<ScimUser, ScimError>;
    fn get_user(&self, id: &str) -> Option<ScimUser>;
    fn find_user_by_username(&self, user_name: &str) -> Option<ScimUser>;
    fn list_users(&self) -> Vec<ScimUser>;
    fn replace_user(&mut self, id: &str, u: &ScimUser) -> Result<ScimUser, ScimError>;
    fn set_user_active(&mut self, id: &str, active: bool) -> Result<ScimUser, ScimError>;
    fn delete_user(&mut self, id: &str) -> Result<(), ScimError>;

    fn create_group(&mut self, g: &ScimGroup) -> Result<ScimGroup, ScimError>;
    fn get_group(&self, id: &str) -> Option<ScimGroup>;
    fn list_groups(&self) -> Vec<ScimGroup>;
    fn replace_group(&mut self, id: &str, g: &ScimGroup) -> Result<ScimGroup, ScimError>;
    fn delete_group(&mut self, id: &str) -> Result<(), ScimError>;
}

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// SCIM service: routes a SCIM HTTP request to the backend and renders SCIM JSON.
pub struct Scim<'a, B: ScimBackend> {
    backend: &'a mut B,
    base_url: String,
}

/// A rendered SCIM response: HTTP status + JSON body.
pub struct ScimResponse {
    pub status: u16,
    pub body: Value,
}

impl<'a, B: ScimBackend> Scim<'a, B> {
    pub fn new(backend: &'a mut B, base_url: &str) -> Self {
        Self {
            backend,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Dispatch a SCIM request. `path` is the part after `/scim/v2/` (e.g. `Users`,
    /// `Users/abc`, `Groups`). `query` provides the optional `filter`.
    pub fn dispatch(
        &mut self,
        method: &str,
        path: &str,
        query_filter: Option<&str>,
        body: &[u8],
    ) -> ScimResponse {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let result = match (method, segs.as_slice()) {
            ("GET", ["Users"]) => Ok(self.list_users(query_filter)),
            ("POST", ["Users"]) => self.create_user(body),
            ("GET", ["Users", id]) => self.get_user(id),
            ("PUT", ["Users", id]) => self.replace_user(id, body),
            ("PATCH", ["Users", id]) => self.patch_user(id, body),
            ("DELETE", ["Users", id]) => self.delete_user(id),
            ("GET", ["Groups"]) => Ok(self.list_groups()),
            ("POST", ["Groups"]) => self.create_group(body),
            ("GET", ["Groups", id]) => self.get_group(id),
            ("PUT", ["Groups", id]) => self.replace_group(id, body),
            ("DELETE", ["Groups", id]) => self.delete_group(id),
            ("GET", ["ServiceProviderConfig"]) => Ok(ScimResponse {
                status: 200,
                body: service_provider_config(),
            }),
            _ => Err(ScimError::NotFound),
        };
        match result {
            Ok(r) => r,
            Err(e) => ScimResponse {
                status: e.status(),
                body: e.body(),
            },
        }
    }

    // ---- Users ---------------------------------------------------------------

    fn create_user(&mut self, body: &[u8]) -> Result<ScimResponse, ScimError> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| ScimError::BadRequest(e.to_string()))?;
        let u = parse_user(&v)?;
        if u.user_name.is_empty() {
            return Err(ScimError::BadRequest("userName is required".into()));
        }
        if self.backend.find_user_by_username(&u.user_name).is_some() {
            return Err(ScimError::Conflict("userName already exists".into()));
        }
        let created = self.backend.create_user(&u)?;
        Ok(ScimResponse {
            status: 201,
            body: self.user_json(&created),
        })
    }

    fn get_user(&self, id: &str) -> Result<ScimResponse, ScimError> {
        let u = self.backend.get_user(id).ok_or(ScimError::NotFound)?;
        Ok(ScimResponse {
            status: 200,
            body: self.user_json(&u),
        })
    }

    fn list_users(&self, filter: Option<&str>) -> ScimResponse {
        let users = if let Some(f) = filter.and_then(parse_eq_filter) {
            if f.0 == "userName" {
                self.backend
                    .find_user_by_username(&f.1)
                    .into_iter()
                    .collect()
            } else {
                self.backend
                    .list_users()
                    .into_iter()
                    .filter(|u| match f.0.as_str() {
                        "externalId" => u.external_id.as_deref() == Some(f.1.as_str()),
                        _ => false,
                    })
                    .collect()
            }
        } else {
            self.backend.list_users()
        };
        let resources: Vec<Value> = users.iter().map(|u| self.user_json(u)).collect();
        ScimResponse {
            status: 200,
            body: list_response(resources),
        }
    }

    fn replace_user(&mut self, id: &str, body: &[u8]) -> Result<ScimResponse, ScimError> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| ScimError::BadRequest(e.to_string()))?;
        let mut u = parse_user(&v)?;
        u.id = id.to_string();
        let updated = self.backend.replace_user(id, &u)?;
        Ok(ScimResponse {
            status: 200,
            body: self.user_json(&updated),
        })
    }

    /// Minimal PATCH: supports the near-universal `active` replace used for deprovisioning.
    fn patch_user(&mut self, id: &str, body: &[u8]) -> Result<ScimResponse, ScimError> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| ScimError::BadRequest(e.to_string()))?;
        let ops = v
            .get("Operations")
            .and_then(|o| o.as_array())
            .ok_or(ScimError::BadRequest("missing Operations".into()))?;
        let mut updated = self.backend.get_user(id).ok_or(ScimError::NotFound)?;
        for op in ops {
            let path = op.get("path").and_then(|p| p.as_str()).unwrap_or("");
            let value = op.get("value");
            if path.eq_ignore_ascii_case("active") {
                let active = match value {
                    Some(Value::Bool(b)) => *b,
                    Some(Value::String(s)) => s == "true",
                    _ => continue,
                };
                updated = self.backend.set_user_active(id, active)?;
            } else if path.is_empty() {
                // Body-style PATCH: {"value": {"active": false}}
                if let Some(Value::Object(map)) = value {
                    if let Some(Value::Bool(b)) = map.get("active") {
                        updated = self.backend.set_user_active(id, *b)?;
                    }
                }
            }
        }
        Ok(ScimResponse {
            status: 200,
            body: self.user_json(&updated),
        })
    }

    fn delete_user(&mut self, id: &str) -> Result<ScimResponse, ScimError> {
        self.backend.delete_user(id)?;
        Ok(ScimResponse {
            status: 204,
            body: Value::Null,
        })
    }

    // ---- Groups --------------------------------------------------------------

    fn create_group(&mut self, body: &[u8]) -> Result<ScimResponse, ScimError> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| ScimError::BadRequest(e.to_string()))?;
        let g = parse_group(&v)?;
        if g.display_name.is_empty() {
            return Err(ScimError::BadRequest("displayName is required".into()));
        }
        let created = self.backend.create_group(&g)?;
        Ok(ScimResponse {
            status: 201,
            body: self.group_json(&created),
        })
    }

    fn get_group(&self, id: &str) -> Result<ScimResponse, ScimError> {
        let g = self.backend.get_group(id).ok_or(ScimError::NotFound)?;
        Ok(ScimResponse {
            status: 200,
            body: self.group_json(&g),
        })
    }

    fn list_groups(&self) -> ScimResponse {
        let resources: Vec<Value> = self
            .backend
            .list_groups()
            .iter()
            .map(|g| self.group_json(g))
            .collect();
        ScimResponse {
            status: 200,
            body: list_response(resources),
        }
    }

    fn replace_group(&mut self, id: &str, body: &[u8]) -> Result<ScimResponse, ScimError> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| ScimError::BadRequest(e.to_string()))?;
        let mut g = parse_group(&v)?;
        g.id = id.to_string();
        let updated = self.backend.replace_group(id, &g)?;
        Ok(ScimResponse {
            status: 200,
            body: self.group_json(&updated),
        })
    }

    fn delete_group(&mut self, id: &str) -> Result<ScimResponse, ScimError> {
        self.backend.delete_group(id)?;
        Ok(ScimResponse {
            status: 204,
            body: Value::Null,
        })
    }

    // ---- rendering -----------------------------------------------------------

    fn user_json(&self, u: &ScimUser) -> Value {
        let mut emails = vec![];
        if let Some(e) = &u.email {
            emails.push(json!({"value": e, "primary": true}));
        }
        json!({
            "schemas": [USER_SCHEMA],
            "id": u.id,
            "userName": u.user_name,
            "displayName": u.display_name,
            "externalId": u.external_id,
            "active": u.active,
            "emails": emails,
            "meta": {
                "resourceType": "User",
                "location": format!("{}/Users/{}", self.base_url, u.id),
            }
        })
    }

    fn group_json(&self, g: &ScimGroup) -> Value {
        let members: Vec<Value> = g
            .member_ids
            .iter()
            .map(|m| json!({"value": m, "$ref": format!("{}/Users/{}", self.base_url, m)}))
            .collect();
        json!({
            "schemas": [GROUP_SCHEMA],
            "id": g.id,
            "displayName": g.display_name,
            "externalId": g.external_id,
            "members": members,
            "meta": {
                "resourceType": "Group",
                "location": format!("{}/Groups/{}", self.base_url, g.id),
            }
        })
    }
}

fn list_response(resources: Vec<Value>) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

fn service_provider_config() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": true},
        "bulk": {"supported": false},
        "filter": {"supported": true, "maxResults": 200},
        "changePassword": {"supported": false},
        "sort": {"supported": false},
        "etag": {"supported": false},
        "authenticationSchemes": [{
            "name": "OAuth Bearer Token",
            "description": "Authentication via a provisioning bearer token",
            "type": "oauthbearertoken",
            "primary": true
        }]
    })
}

fn parse_user(v: &Value) -> Result<ScimUser, ScimError> {
    let user_name = v
        .get("userName")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let display_name = v
        .get("displayName")
        .and_then(|x| x.as_str())
        .map(String::from)
        .or_else(|| {
            let n = v.get("name")?;
            let g = n.get("givenName").and_then(|x| x.as_str()).unwrap_or("");
            let f = n.get("familyName").and_then(|x| x.as_str()).unwrap_or("");
            let full = format!("{g} {f}").trim().to_string();
            if full.is_empty() {
                None
            } else {
                Some(full)
            }
        });
    let email = v
        .get("emails")
        .and_then(|e| e.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("primary").and_then(|p| p.as_bool()).unwrap_or(false))
                .or_else(|| arr.first())
        })
        .and_then(|e| e.get("value"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let external_id = v
        .get("externalId")
        .and_then(|x| x.as_str())
        .map(String::from);
    let active = v.get("active").and_then(|x| x.as_bool()).unwrap_or(true);
    Ok(ScimUser {
        id: v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        user_name,
        display_name,
        email,
        external_id,
        active,
    })
}

fn parse_group(v: &Value) -> Result<ScimGroup, ScimError> {
    let display_name = v
        .get("displayName")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let external_id = v
        .get("externalId")
        .and_then(|x| x.as_str())
        .map(String::from);
    let member_ids = v
        .get("members")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("value").and_then(|x| x.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(ScimGroup {
        id: v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        display_name,
        external_id,
        member_ids,
    })
}

/// Parse a trivial SCIM filter of the form `attr eq "value"`.
fn parse_eq_filter(filter: &str) -> Option<(String, String)> {
    let f = filter.trim();
    let lower = f.to_ascii_lowercase();
    let pos = lower.find(" eq ")?;
    let attr = f[..pos].trim().to_string();
    let val = f[pos + 4..].trim().trim_matches('"').to_string();
    if attr.is_empty() || val.is_empty() {
        return None;
    }
    Some((attr, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemBackend {
        users: HashMap<String, ScimUser>,
        groups: HashMap<String, ScimGroup>,
        seq: u64,
    }
    impl ScimBackend for MemBackend {
        fn create_user(&mut self, u: &ScimUser) -> Result<ScimUser, ScimError> {
            self.seq += 1;
            let mut u = u.clone();
            u.id = format!("u{}", self.seq);
            self.users.insert(u.id.clone(), u.clone());
            Ok(u)
        }
        fn get_user(&self, id: &str) -> Option<ScimUser> {
            self.users.get(id).cloned()
        }
        fn find_user_by_username(&self, user_name: &str) -> Option<ScimUser> {
            self.users
                .values()
                .find(|u| u.user_name == user_name)
                .cloned()
        }
        fn list_users(&self) -> Vec<ScimUser> {
            self.users.values().cloned().collect()
        }
        fn replace_user(&mut self, id: &str, u: &ScimUser) -> Result<ScimUser, ScimError> {
            if !self.users.contains_key(id) {
                return Err(ScimError::NotFound);
            }
            let mut u = u.clone();
            u.id = id.to_string();
            self.users.insert(id.to_string(), u.clone());
            Ok(u)
        }
        fn set_user_active(&mut self, id: &str, active: bool) -> Result<ScimUser, ScimError> {
            let u = self.users.get_mut(id).ok_or(ScimError::NotFound)?;
            u.active = active;
            Ok(u.clone())
        }
        fn delete_user(&mut self, id: &str) -> Result<(), ScimError> {
            self.users.remove(id).map(|_| ()).ok_or(ScimError::NotFound)
        }
        fn create_group(&mut self, g: &ScimGroup) -> Result<ScimGroup, ScimError> {
            self.seq += 1;
            let mut g = g.clone();
            g.id = format!("g{}", self.seq);
            self.groups.insert(g.id.clone(), g.clone());
            Ok(g)
        }
        fn get_group(&self, id: &str) -> Option<ScimGroup> {
            self.groups.get(id).cloned()
        }
        fn list_groups(&self) -> Vec<ScimGroup> {
            self.groups.values().cloned().collect()
        }
        fn replace_group(&mut self, id: &str, g: &ScimGroup) -> Result<ScimGroup, ScimError> {
            if !self.groups.contains_key(id) {
                return Err(ScimError::NotFound);
            }
            let mut g = g.clone();
            g.id = id.to_string();
            self.groups.insert(id.to_string(), g.clone());
            Ok(g)
        }
        fn delete_group(&mut self, id: &str) -> Result<(), ScimError> {
            self.groups
                .remove(id)
                .map(|_| ())
                .ok_or(ScimError::NotFound)
        }
    }

    #[test]
    fn user_provisioning_lifecycle() {
        let mut be = MemBackend::default();
        let mut scim = Scim::new(&mut be, "https://sp.example/scim/v2");

        // Create.
        let body = br#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName":"alice","name":{"givenName":"Alice","familyName":"A"},
            "emails":[{"value":"alice@x","primary":true}],"externalId":"ext-1"}"#;
        let r = scim.dispatch("POST", "Users", None, body);
        assert_eq!(r.status, 201);
        let id = r.body["id"].as_str().unwrap().to_string();
        assert_eq!(r.body["userName"], "alice");
        assert_eq!(r.body["active"], true);

        // Duplicate userName -> conflict.
        let dup = scim.dispatch("POST", "Users", None, body);
        assert_eq!(dup.status, 409);

        // Get + filter.
        let g = scim.dispatch("GET", &format!("Users/{id}"), None, b"");
        assert_eq!(g.status, 200);
        let f = scim.dispatch("GET", "Users", Some("userName eq \"alice\""), b"");
        assert_eq!(f.body["totalResults"], 1);

        // PATCH deactivate (deprovision).
        let patch = br#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations":[{"op":"replace","path":"active","value":false}]}"#;
        let p = scim.dispatch("PATCH", &format!("Users/{id}"), None, patch);
        assert_eq!(p.status, 200);
        assert_eq!(p.body["active"], false);

        // Delete.
        let d = scim.dispatch("DELETE", &format!("Users/{id}"), None, b"");
        assert_eq!(d.status, 204);
        let missing = scim.dispatch("GET", &format!("Users/{id}"), None, b"");
        assert_eq!(missing.status, 404);
    }

    #[test]
    fn group_provisioning() {
        let mut be = MemBackend::default();
        let mut scim = Scim::new(&mut be, "https://sp.example/scim/v2");
        let body = br#"{"displayName":"eng","members":[{"value":"u1"},{"value":"u2"}]}"#;
        let r = scim.dispatch("POST", "Groups", None, body);
        assert_eq!(r.status, 201);
        assert_eq!(r.body["displayName"], "eng");
        assert_eq!(r.body["members"].as_array().unwrap().len(), 2);
        let list = scim.dispatch("GET", "Groups", None, b"");
        assert_eq!(list.body["totalResults"], 1);
    }

    #[test]
    fn unknown_route_404_and_spc() {
        let mut be = MemBackend::default();
        let mut scim = Scim::new(&mut be, "https://sp.example/scim/v2");
        assert_eq!(scim.dispatch("GET", "Nope", None, b"").status, 404);
        let spc = scim.dispatch("GET", "ServiceProviderConfig", None, b"");
        assert_eq!(spc.status, 200);
        assert_eq!(spc.body["patch"]["supported"], true);
    }
}
