//! # secgit-api
//!
//! Framework-agnostic API logic. The public instance is the *same* OSS build run in
//! **sandbox mode** (a config, not a fork), exposing three interaction tiers:
//!
//! - **Anonymous (tier a)**: run the attestation-verification flow against a live repo
//!   AND create an anonymous *ephemeral* repo (throwaway push token, auto-expiring,
//!   size-capped) to push your own code and confirm "they can't read MY repo". This is
//!   the frictionless viral path. See [`EphemeralRepos`].
//! - **Light (tier b)**: OIDC/local account, persistent capped sandbox repos.
//! - **Managed (tier c)**: org + BYOK-to-customer-KMS + IdP (enterprise, later).
//!
//! This crate holds the tier policy, ephemeral-repo lifecycle, and abuse controls; the
//! transport (HTTP) lives in `secgit-server`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("feature disabled in this deployment mode: {0}")]
    Disabled(&'static str),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("invalid or expired ephemeral token")]
    BadToken,
    #[error("size cap exceeded")]
    SizeCap,
    #[error("crypto error")]
    Crypto,
}

pub type Result<T> = core::result::Result<T, ApiError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Anonymous,
    Light,
    Managed,
}

/// Per-tier resource limits.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TierLimits {
    /// Max persistent repos an account may own (`u32::MAX` = effectively unlimited).
    pub max_repos: u32,
    /// Size cap (bytes) per repo.
    pub max_bytes_per_repo: u64,
    /// Total storage (bytes) across the account's repos.
    pub max_total_bytes: u64,
}

impl TierLimits {
    /// Limits for the public-sandbox Light tier (capped, persistent).
    pub fn light_sandbox() -> Self {
        Self {
            max_repos: 10,
            max_bytes_per_repo: 100 * 1024 * 1024,
            max_total_bytes: 500 * 1024 * 1024,
        }
    }
    /// Managed tier: no platform-imposed caps (governed by the customer's plan instead).
    pub fn managed() -> Self {
        Self {
            max_repos: u32::MAX,
            max_bytes_per_repo: u64::MAX,
            max_total_bytes: u64::MAX,
        }
    }
}

/// Deployment configuration. The public sandbox sets `sandbox_mode = true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub sandbox_mode: bool,
    pub anonymous_enabled: bool,
    pub light_enabled: bool,
    pub managed_enabled: bool,
    /// Auto-expiry for anonymous ephemeral repos.
    pub ephemeral_ttl_secs: u64,
    /// Size cap (bytes) for an anonymous ephemeral repo.
    pub ephemeral_max_bytes: u64,
    /// Max anonymous repos created per client window (abuse control).
    pub anon_creates_per_window: u32,
    pub rate_window_secs: u64,
    /// Per-account limits for the Light tier.
    pub light_limits: TierLimits,
    /// Per-account limits for the Managed tier.
    pub managed_limits: TierLimits,
    /// Managed tier requires customer-supplied (BYOK) key material.
    pub managed_requires_byok: bool,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            sandbox_mode: true,
            anonymous_enabled: true,
            light_enabled: true,
            managed_enabled: false,
            ephemeral_ttl_secs: 3600,
            ephemeral_max_bytes: 50 * 1024 * 1024,
            anon_creates_per_window: 5,
            rate_window_secs: 3600,
            light_limits: TierLimits::light_sandbox(),
            managed_limits: TierLimits::managed(),
            managed_requires_byok: true,
        }
    }
}

impl DeploymentConfig {
    /// Whether a tier is enabled in this deployment.
    pub fn tier_enabled(&self, tier: Tier) -> bool {
        match tier {
            Tier::Anonymous => self.anonymous_enabled,
            Tier::Light => self.light_enabled,
            Tier::Managed => self.managed_enabled,
        }
    }
    /// Resource limits applicable to a tier (Anonymous uses the ephemeral cap).
    pub fn limits_for(&self, tier: Tier) -> TierLimits {
        match tier {
            Tier::Anonymous => TierLimits {
                max_repos: self.anon_creates_per_window,
                max_bytes_per_repo: self.ephemeral_max_bytes,
                max_total_bytes: self.ephemeral_max_bytes,
            },
            Tier::Light => self.light_limits,
            Tier::Managed => self.managed_limits,
        }
    }
}

/// An issued ephemeral repo: a throwaway repo id + push token, auto-expiring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralRepo {
    pub repo_id: String,
    pub push_token: String,
    pub expires_at: u64,
    pub max_bytes: u64,
}

struct EphemeralState {
    token: String,
    expires_at: u64,
    max_bytes: u64,
    used_bytes: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Manager for anonymous ephemeral repos with TTL, size caps, and creation rate limits.
pub struct EphemeralRepos {
    cfg: DeploymentConfig,
    repos: HashMap<String, EphemeralState>,
    /// client key -> (window_start, count) for create rate limiting.
    creates: HashMap<String, (u64, u32)>,
}

impl EphemeralRepos {
    pub fn new(cfg: DeploymentConfig) -> Self {
        Self {
            cfg,
            repos: HashMap::new(),
            creates: HashMap::new(),
        }
    }

    /// Create an anonymous ephemeral repo for `client_key` (e.g. hashed IP).
    pub fn create(&mut self, client_key: &str) -> Result<EphemeralRepo> {
        if !self.cfg.anonymous_enabled {
            return Err(ApiError::Disabled("anonymous tier"));
        }
        self.enforce_rate(client_key)?;
        self.gc();

        let token = secgit_crypto::primitives::random_vec(24).map_err(|_| ApiError::Crypto)?;
        let id_suffix = secgit_crypto::primitives::random_vec(8).map_err(|_| ApiError::Crypto)?;
        let repo_id = format!("ephemeral/{}", hex::encode(id_suffix));
        let expires_at = now() + self.cfg.ephemeral_ttl_secs;

        self.repos.insert(
            repo_id.clone(),
            EphemeralState {
                token: hex::encode(&token),
                expires_at,
                max_bytes: self.cfg.ephemeral_max_bytes,
                used_bytes: 0,
            },
        );
        Ok(EphemeralRepo {
            repo_id,
            push_token: hex::encode(&token),
            expires_at,
            max_bytes: self.cfg.ephemeral_max_bytes,
        })
    }

    /// Authorize a push to an ephemeral repo (token + expiry).
    pub fn authorize_push(&mut self, repo_id: &str, token: &str) -> Result<()> {
        self.gc();
        let st = self.repos.get(repo_id).ok_or(ApiError::BadToken)?;
        if st.expires_at <= now() {
            return Err(ApiError::BadToken);
        }
        if !secgit_crypto::primitives::ct_eq(st.token.as_bytes(), token.as_bytes()) {
            return Err(ApiError::BadToken);
        }
        Ok(())
    }

    /// Account for bytes pushed; enforce the size cap.
    pub fn account_bytes(&mut self, repo_id: &str, bytes: u64) -> Result<()> {
        let st = self.repos.get_mut(repo_id).ok_or(ApiError::BadToken)?;
        let new_total = st.used_bytes.saturating_add(bytes);
        if new_total > st.max_bytes {
            return Err(ApiError::SizeCap);
        }
        st.used_bytes = new_total;
        Ok(())
    }

    pub fn is_ephemeral(&self, repo_id: &str) -> bool {
        self.repos.contains_key(repo_id)
    }

    /// Remove expired repos; returns the ids that expired (caller wipes their storage).
    pub fn gc(&mut self) -> Vec<String> {
        let t = now();
        let expired: Vec<String> = self
            .repos
            .iter()
            .filter(|(_, s)| s.expires_at <= t)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            self.repos.remove(k);
        }
        expired
    }

    fn enforce_rate(&mut self, client_key: &str) -> Result<()> {
        let t = now();
        let entry = self.creates.entry(client_key.to_string()).or_insert((t, 0));
        if t.saturating_sub(entry.0) >= self.cfg.rate_window_secs {
            *entry = (t, 0);
        }
        if entry.1 >= self.cfg.anon_creates_per_window {
            return Err(ApiError::RateLimited);
        }
        entry.1 += 1;
        Ok(())
    }
}

/// Per-account quota accounting for the persistent tiers (Light, Managed).
///
/// Unlike [`EphemeralRepos`] (anonymous, TTL'd, throwaway), accounts here are
/// authenticated and their repos persist; this tracks repo count and byte usage against
/// the tier limits so a Light sandbox account cannot exceed its cap. The actual repo
/// objects live (encrypted) in the store and identity/access-control lives in
/// `secgit-identity`; this type owns only the *quota policy*.
pub struct AccountQuota {
    cfg: DeploymentConfig,
    /// account_id -> (tier, repo_id -> used_bytes)
    accounts: HashMap<String, (Tier, HashMap<String, u64>)>,
}

impl AccountQuota {
    pub fn new(cfg: DeploymentConfig) -> Self {
        Self {
            cfg,
            accounts: HashMap::new(),
        }
    }

    /// Preload an existing repo into quota accounting (used at startup to rebuild state
    /// from the persisted directory + stored bundle sizes, so caps survive restarts).
    /// Bypasses limit checks — it reflects reality rather than authorizing new growth.
    pub fn preload(&mut self, account_id: &str, tier: Tier, repo_id: &str, used_bytes: u64) {
        let entry = self
            .accounts
            .entry(account_id.to_string())
            .or_insert((tier, HashMap::new()));
        entry.0 = tier;
        entry.1.insert(repo_id.to_string(), used_bytes);
    }

    /// Register (or update) an account's tier. Errors if the tier is disabled here.
    pub fn ensure_account(&mut self, account_id: &str, tier: Tier) -> Result<()> {
        if !self.cfg.tier_enabled(tier) {
            return Err(ApiError::Disabled(match tier {
                Tier::Anonymous => "anonymous tier",
                Tier::Light => "light tier",
                Tier::Managed => "managed tier",
            }));
        }
        self.accounts
            .entry(account_id.to_string())
            .and_modify(|(t, _)| *t = tier)
            .or_insert((tier, HashMap::new()));
        Ok(())
    }

    /// Authorize creating a new persistent repo under the account's repo-count limit.
    pub fn authorize_create_repo(&mut self, account_id: &str, repo_id: &str) -> Result<()> {
        let limits = self.cfg.limits_for(self.tier_of(account_id)?);
        let (_, repos) = self.account_mut(account_id)?;
        if repos.len() as u64 >= limits.max_repos as u64 {
            return Err(ApiError::SizeCap);
        }
        repos.entry(repo_id.to_string()).or_insert(0);
        Ok(())
    }

    /// Account for bytes written to a repo, enforcing per-repo and total caps.
    pub fn account_bytes(&mut self, account_id: &str, repo_id: &str, bytes: u64) -> Result<()> {
        let limits = self.cfg.limits_for(self.tier_of(account_id)?);
        let (_, repos) = self.account_mut(account_id)?;
        let current = *repos.get(repo_id).ok_or(ApiError::BadToken)?;
        let new_repo_total = current.saturating_add(bytes);
        if new_repo_total > limits.max_bytes_per_repo {
            return Err(ApiError::SizeCap);
        }
        let others: u64 = repos
            .iter()
            .filter(|(k, _)| k.as_str() != repo_id)
            .map(|(_, v)| *v)
            .sum();
        if others.saturating_add(new_repo_total) > limits.max_total_bytes {
            return Err(ApiError::SizeCap);
        }
        repos.insert(repo_id.to_string(), new_repo_total);
        Ok(())
    }

    /// Remove a repo from the account's quota accounting.
    pub fn remove_repo(&mut self, account_id: &str, repo_id: &str) -> Result<()> {
        let (_, repos) = self.account_mut(account_id)?;
        repos.remove(repo_id);
        Ok(())
    }

    /// Bytes currently accounted for a specific repo, if the repo is tracked.
    pub fn repo_bytes(&self, account_id: &str, repo_id: &str) -> Option<u64> {
        self.accounts
            .get(account_id)
            .and_then(|(_, r)| r.get(repo_id).copied())
    }

    pub fn repo_count(&self, account_id: &str) -> usize {
        self.accounts
            .get(account_id)
            .map(|(_, r)| r.len())
            .unwrap_or(0)
    }
    pub fn total_bytes(&self, account_id: &str) -> u64 {
        self.accounts
            .get(account_id)
            .map(|(_, r)| r.values().sum())
            .unwrap_or(0)
    }

    fn account_mut(&mut self, account_id: &str) -> Result<&mut (Tier, HashMap<String, u64>)> {
        self.accounts.get_mut(account_id).ok_or(ApiError::BadToken)
    }

    fn tier_of(&self, account_id: &str) -> Result<Tier> {
        self.accounts
            .get(account_id)
            .map(|(t, _)| *t)
            .ok_or(ApiError::BadToken)
    }
}

/// Managed-tier admission: verify a customer org satisfies the Managed prerequisites
/// (enabled + BYOK present when required). Returns the limits to apply.
pub fn admit_managed(cfg: &DeploymentConfig, byok_present: bool) -> Result<TierLimits> {
    if !cfg.managed_enabled {
        return Err(ApiError::Disabled("managed tier"));
    }
    if cfg.managed_requires_byok && !byok_present {
        return Err(ApiError::Disabled("managed tier requires BYOK"));
    }
    Ok(cfg.managed_limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_create_and_push_auth() {
        let mut m = EphemeralRepos::new(DeploymentConfig::default());
        let r = m.create("client-1").unwrap();
        assert!(m.is_ephemeral(&r.repo_id));
        assert!(m.authorize_push(&r.repo_id, &r.push_token).is_ok());
        assert!(m.authorize_push(&r.repo_id, "wrong").is_err());
    }

    #[test]
    fn size_cap_enforced() {
        let cfg = DeploymentConfig {
            ephemeral_max_bytes: 100,
            ..Default::default()
        };
        let mut m = EphemeralRepos::new(cfg);
        let r = m.create("c").unwrap();
        assert!(m.account_bytes(&r.repo_id, 60).is_ok());
        assert!(matches!(
            m.account_bytes(&r.repo_id, 60),
            Err(ApiError::SizeCap)
        ));
    }

    #[test]
    fn create_rate_limited() {
        let cfg = DeploymentConfig {
            anon_creates_per_window: 2,
            ..Default::default()
        };
        let mut m = EphemeralRepos::new(cfg);
        assert!(m.create("c").is_ok());
        assert!(m.create("c").is_ok());
        assert!(matches!(m.create("c"), Err(ApiError::RateLimited)));
        // A different client is unaffected.
        assert!(m.create("other").is_ok());
    }

    #[test]
    fn expired_repo_rejected_and_gced() {
        // immediate expiry
        let cfg = DeploymentConfig {
            ephemeral_ttl_secs: 0,
            ..Default::default()
        };
        let mut m = EphemeralRepos::new(cfg);
        let r = m.create("c").unwrap();
        assert!(m.authorize_push(&r.repo_id, &r.push_token).is_err());
        assert!(!m.is_ephemeral(&r.repo_id));
    }

    #[test]
    fn anonymous_disabled_blocks_create() {
        let cfg = DeploymentConfig {
            anonymous_enabled: false,
            ..Default::default()
        };
        let mut m = EphemeralRepos::new(cfg);
        assert!(matches!(m.create("c"), Err(ApiError::Disabled(_))));
    }

    #[test]
    fn light_account_repo_count_capped() {
        let cfg = DeploymentConfig {
            light_limits: TierLimits {
                max_repos: 2,
                ..TierLimits::light_sandbox()
            },
            ..Default::default()
        };
        let mut q = AccountQuota::new(cfg);
        q.ensure_account("acct", Tier::Light).unwrap();
        q.authorize_create_repo("acct", "r1").unwrap();
        q.authorize_create_repo("acct", "r2").unwrap();
        assert!(matches!(
            q.authorize_create_repo("acct", "r3"),
            Err(ApiError::SizeCap)
        ));
        assert_eq!(q.repo_count("acct"), 2);
    }

    #[test]
    fn light_account_byte_caps_enforced() {
        let cfg = DeploymentConfig {
            light_limits: TierLimits {
                max_repos: 10,
                max_bytes_per_repo: 100,
                max_total_bytes: 150,
            },
            ..Default::default()
        };
        let mut q = AccountQuota::new(cfg);
        q.ensure_account("a", Tier::Light).unwrap();
        q.authorize_create_repo("a", "r1").unwrap();
        q.authorize_create_repo("a", "r2").unwrap();
        q.account_bytes("a", "r1", 90).unwrap();
        // per-repo cap
        assert!(matches!(
            q.account_bytes("a", "r1", 20),
            Err(ApiError::SizeCap)
        ));
        // total cap across repos (90 + 70 > 150)
        assert!(matches!(
            q.account_bytes("a", "r2", 70),
            Err(ApiError::SizeCap)
        ));
        q.account_bytes("a", "r2", 50).unwrap();
        assert_eq!(q.total_bytes("a"), 140);
    }

    #[test]
    fn preload_reflects_existing_repos_and_caps_further_growth() {
        let cfg = DeploymentConfig {
            light_limits: TierLimits {
                max_repos: 2,
                max_bytes_per_repo: 100,
                max_total_bytes: 150,
            },
            ..Default::default()
        };
        let mut q = AccountQuota::new(cfg);
        q.preload("a", Tier::Light, "r1", 90);
        q.preload("a", Tier::Light, "r2", 40);
        assert_eq!(q.repo_count("a"), 2);
        assert_eq!(q.total_bytes("a"), 130);
        // At the repo-count cap already -> a third is refused.
        assert!(matches!(
            q.authorize_create_repo("a", "r3"),
            Err(ApiError::SizeCap)
        ));
        // Total-cap respected against preloaded usage (130 + 30 > 150).
        assert!(matches!(
            q.account_bytes("a", "r2", 30),
            Err(ApiError::SizeCap)
        ));
    }

    #[test]
    fn disabled_tier_blocks_account() {
        let cfg = DeploymentConfig {
            light_enabled: false,
            ..Default::default()
        };
        let mut q = AccountQuota::new(cfg);
        assert!(matches!(
            q.ensure_account("a", Tier::Light),
            Err(ApiError::Disabled(_))
        ));
    }

    #[test]
    fn managed_admission_requires_byok() {
        let cfg = DeploymentConfig {
            managed_enabled: true,
            managed_requires_byok: true,
            ..Default::default()
        };
        assert!(admit_managed(&cfg, false).is_err());
        assert!(admit_managed(&cfg, true).is_ok());

        let disabled = DeploymentConfig {
            managed_enabled: false,
            ..Default::default()
        };
        assert!(admit_managed(&disabled, true).is_err());
    }
}
