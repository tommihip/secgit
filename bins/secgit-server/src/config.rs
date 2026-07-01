//! Runtime configuration for the public-sandbox hardening controls.
//!
//! Every knob is environment-driven so the *same* OSS build runs as a locked-down public
//! sandbox or a permissive local dev instance purely by configuration (ADR 0007: sandbox
//! is a config, not a fork). Defaults are chosen to survive a hostile internet: bounded
//! connections, request timeouts, body/header caps, aggressive per-IP rate limits, git
//! subprocess bounds, and a bounded seal concurrency.

use secgit_api::{DeploymentConfig, TierLimits};
use secgit_git::GitLimits;
use std::time::Duration;

/// Transport- and abuse-control limits enforced by the server (outside the tier policy in
/// `secgit-api`, which owns quotas/ephemeral lifecycle).
#[derive(Debug, Clone)]
pub struct ServerLimits {
    // --- connection / transport ---
    pub max_connections: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_body_bytes: usize,

    // --- rate limiting (token bucket: capacity = burst, refill = steady tokens/sec) ---
    pub ip_req_capacity: f64,
    pub ip_req_refill: f64,
    pub ip_git_capacity: f64,
    pub ip_git_refill: f64,
    pub account_capacity: f64,
    pub account_refill: f64,
    /// Per-repo push bucket — directly bounds `seal_to_store` re-bundle frequency.
    pub push_capacity: f64,
    pub push_refill: f64,
    pub rl_max_keys: usize,
    pub rl_idle_evict: Duration,

    // --- expensive-work bounds ---
    pub seal_concurrency: usize,
    pub git: GitLimits,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(60),
            max_header_bytes: 64 * 1024,
            max_header_count: 100,
            max_body_bytes: 128 * 1024 * 1024,

            ip_req_capacity: 60.0,
            ip_req_refill: 10.0,
            ip_git_capacity: 10.0,
            ip_git_refill: 2.0,
            account_capacity: 30.0,
            account_refill: 5.0,
            push_capacity: 3.0,
            push_refill: 0.2,
            rl_max_keys: 100_000,
            rl_idle_evict: Duration::from_secs(3600),

            seal_concurrency: 2,
            git: GitLimits::default(),
        }
    }
}

/// Proof-of-work challenge gate for the anonymous ephemeral-create path.
#[derive(Debug, Clone)]
pub struct PowConfig {
    pub enabled: bool,
    pub difficulty_bits: u32,
    pub ttl_secs: u64,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            difficulty_bits: 20,
            ttl_secs: 300,
        }
    }
}

/// Content-free metrics exposure. Bound to localhost by default and (optionally)
/// token-gated; never publicly exposed unless explicitly configured.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Address for the dedicated metrics listener. `None` disables it.
    pub addr: Option<String>,
    /// Bearer token required to read `/metrics` (on either listener). `None` = no token.
    pub token: Option<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            addr: Some("127.0.0.1:9090".to_string()),
            token: None,
        }
    }
}

// ---- env helpers ------------------------------------------------------------

fn env_present(key: &str) -> bool {
    std::env::var(key).is_ok()
}

/// A boolean env var: unset -> `default`; set -> true unless it is `0`/`false`/`off`/`no`.
fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Err(_) => default,
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no" | ""
        ),
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl ServerLimits {
    pub fn from_env() -> Self {
        let d = ServerLimits::default();
        let git = GitLimits {
            wall_clock: Duration::from_secs(env_u64("SECGIT_GIT_TIMEOUT_SECS", 120)),
            max_output_bytes: env_usize("SECGIT_MAX_FETCH_BYTES", d.git.max_output_bytes),
            max_input_bytes: env_u64("SECGIT_MAX_PACK_BYTES", d.git.max_input_bytes),
        };
        Self {
            max_connections: env_usize("SECGIT_MAX_CONNECTIONS", d.max_connections),
            read_timeout: Duration::from_secs(env_u64("SECGIT_READ_TIMEOUT_SECS", 30)),
            write_timeout: Duration::from_secs(env_u64("SECGIT_WRITE_TIMEOUT_SECS", 60)),
            max_header_bytes: env_usize("SECGIT_MAX_HEADER_BYTES", d.max_header_bytes),
            max_header_count: env_usize("SECGIT_MAX_HEADER_COUNT", d.max_header_count),
            max_body_bytes: env_usize("SECGIT_MAX_BODY_BYTES", d.max_body_bytes),

            ip_req_capacity: env_f64("SECGIT_RL_IP_BURST", d.ip_req_capacity),
            ip_req_refill: env_f64("SECGIT_RL_IP_RPS", d.ip_req_refill),
            ip_git_capacity: env_f64("SECGIT_RL_GIT_BURST", d.ip_git_capacity),
            ip_git_refill: env_f64("SECGIT_RL_GIT_RPS", d.ip_git_refill),
            account_capacity: env_f64("SECGIT_RL_ACCOUNT_BURST", d.account_capacity),
            account_refill: env_f64("SECGIT_RL_ACCOUNT_RPS", d.account_refill),
            push_capacity: env_f64("SECGIT_RL_PUSH_BURST", d.push_capacity),
            push_refill: env_f64("SECGIT_RL_PUSH_RPS", d.push_refill),
            rl_max_keys: env_usize("SECGIT_RL_MAX_KEYS", d.rl_max_keys),
            rl_idle_evict: Duration::from_secs(env_u64("SECGIT_RL_IDLE_EVICT_SECS", 3600)),

            seal_concurrency: env_usize("SECGIT_SEAL_CONCURRENCY", d.seal_concurrency).max(1),
            git,
        }
    }

    /// The HTTP parse limits, in the shape the parser wants.
    pub fn http_limits(&self) -> crate::http::HttpLimits {
        crate::http::HttpLimits {
            max_header_bytes: self.max_header_bytes,
            max_header_count: self.max_header_count,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

impl PowConfig {
    pub fn from_env() -> Self {
        let d = PowConfig::default();
        PowConfig {
            enabled: env_bool("SECGIT_POW", false),
            difficulty_bits: env_usize("SECGIT_POW_BITS", d.difficulty_bits as usize) as u32,
            ttl_secs: env_u64("SECGIT_POW_TTL_SECS", d.ttl_secs),
        }
    }
}

impl MetricsConfig {
    pub fn from_env() -> Self {
        let addr = match std::env::var("SECGIT_METRICS_ADDR") {
            Ok(v) if v.trim().eq_ignore_ascii_case("off") || v.trim().is_empty() => None,
            Ok(v) => Some(v),
            Err(_) => Some("127.0.0.1:9090".to_string()),
        };
        let token = std::env::var("SECGIT_METRICS_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        MetricsConfig { addr, token }
    }
}

/// Build the tier [`DeploymentConfig`] from the environment, overriding the hardened
/// defaults. Existing behavior is preserved: anonymous is opt-in via
/// `SECGIT_ENABLE_ANONYMOUS`; the other knobs simply become tunable.
pub fn deployment_from_env() -> DeploymentConfig {
    let d = DeploymentConfig::default();
    let light_limits = TierLimits {
        max_repos: env_usize("SECGIT_LIGHT_MAX_REPOS", d.light_limits.max_repos as usize) as u32,
        max_bytes_per_repo: env_u64(
            "SECGIT_LIGHT_MAX_BYTES_PER_REPO",
            d.light_limits.max_bytes_per_repo,
        ),
        max_total_bytes: env_u64(
            "SECGIT_LIGHT_MAX_TOTAL_BYTES",
            d.light_limits.max_total_bytes,
        ),
    };
    DeploymentConfig {
        sandbox_mode: env_bool("SECGIT_SANDBOX_MODE", d.sandbox_mode),
        anonymous_enabled: env_present("SECGIT_ENABLE_ANONYMOUS"),
        light_enabled: env_bool("SECGIT_ENABLE_LIGHT", d.light_enabled),
        managed_enabled: env_bool("SECGIT_ENABLE_MANAGED", d.managed_enabled),
        ephemeral_ttl_secs: env_u64("SECGIT_EPHEMERAL_TTL_SECS", d.ephemeral_ttl_secs),
        ephemeral_max_bytes: env_u64("SECGIT_EPHEMERAL_MAX_BYTES", d.ephemeral_max_bytes),
        anon_creates_per_window: env_usize(
            "SECGIT_ANON_CREATES_PER_WINDOW",
            d.anon_creates_per_window as usize,
        ) as u32,
        rate_window_secs: env_u64("SECGIT_RATE_WINDOW_SECS", d.rate_window_secs),
        light_limits,
        managed_limits: d.managed_limits,
        managed_requires_byok: env_bool("SECGIT_MANAGED_REQUIRES_BYOK", d.managed_requires_byok),
    }
}
