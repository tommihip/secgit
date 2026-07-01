//! `secgit-server` — the binary that runs **inside the confidential VM**.
//!
//! Startup honors the M1 build order: it obtains its KEK through the
//! attestation-gated key-release flow *before* opening the encrypted store. Then it
//! serves a small control plane (health, attestation evidence, sandbox ephemeral
//! repos) and the git smart-HTTP endpoints, recording security-relevant actions in the
//! PQC-signed transparency log.
//!
//! This is intentionally a lean reference server; see `docs/adr/0007-deployment.md`
//! for the demo-as-sandbox model and `docs/adr/0009-milestones.md` for what is
//! deferred (confidential CI is v2).

mod abuse;
mod api;
mod authz;
mod config;
mod events;
mod http;
mod importer;
mod kbs;
mod metrics;
mod pow;
mod ratelimit;
mod ssh;
mod sso;
mod tls;
mod web;

use anyhow::{Context, Result};
use config::{MetricsConfig, ServerLimits};
use http::{ParseOutcome, Request, Response};
use metrics::Metrics;
use ratelimit::{RateLimiter, Semaphore};
use secgit_api::{AccountQuota, DeploymentConfig, EphemeralRepos, Tier};
use secgit_attest::{detect_attester, Policy, ReportData};
use secgit_audit::{AuditEvent, TransparencyLog};
use secgit_crypto::aead::SymKey;
use secgit_forge::Forge;
use secgit_git::Service;
use secgit_identity::model::RepoOwner;
use secgit_keybroker::{attest_and_unwrap, InMemoryKekProvider, LocalKeyBroker};
use secgit_store::EncryptedStore;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// Per-key rate limiters guarding the public sandbox. All are memory-bounded token buckets.
struct Limiters {
    /// Per-IP request rate across all endpoints.
    ip_req: RateLimiter,
    /// Per-IP git smart-HTTP operation rate.
    ip_git: RateLimiter,
    /// Per-account operation rate (repo create, authenticated pushes).
    account: RateLimiter,
    /// Per-repo push rate — directly bounds `seal_to_store` re-bundle frequency.
    push: RateLimiter,
}

impl Limiters {
    fn from_limits(l: &ServerLimits) -> Self {
        Self {
            ip_req: RateLimiter::new(
                l.ip_req_capacity,
                l.ip_req_refill,
                l.rl_max_keys,
                l.rl_idle_evict,
            ),
            ip_git: RateLimiter::new(
                l.ip_git_capacity,
                l.ip_git_refill,
                l.rl_max_keys,
                l.rl_idle_evict,
            ),
            account: RateLimiter::new(
                l.account_capacity,
                l.account_refill,
                l.rl_max_keys,
                l.rl_idle_evict,
            ),
            push: RateLimiter::new(
                l.push_capacity,
                l.push_refill,
                l.rl_max_keys,
                l.rl_idle_evict,
            ),
        }
    }
}

/// RAII guard that decrements the active-connection gauge when a connection handler exits.
struct ConnGuard {
    metrics: Arc<Metrics>,
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct App {
    forge: Forge,
    store: EncryptedStore,
    search_store: EncryptedStore,
    audit: Mutex<TransparencyLog>,
    ephemeral: Mutex<EphemeralRepos>,
    identity: Mutex<authz::ServerIdentity>,
    /// Per-account persistent-tier quota accounting (Light/Managed), seeded at startup
    /// from the directory so caps survive restarts.
    quota: Mutex<AccountQuota>,
    config: DeploymentConfig,
    /// SHA-256 (hex) of the in-CVM TLS cert SPKI, bound into attestation `report_data`
    /// so a client proves it is talking TLS to the exact attested TEE. `None` only in
    /// the explicit `SECGIT_INSECURE_HTTP` dev mode.
    tls_spki_sha256_hex: Option<String>,
    /// Configured SAML 2.0 SP (pinned IdP cert), enabling `/sso/saml/*`. `None` disables.
    saml: Option<secgit_sso::SamlSp>,
    /// Provisioning bearer token gating `/scim/v2/*`. `None` disables SCIM.
    scim_token: Option<String>,
    /// Public base URL used to render SCIM `meta.location` / SP metadata.
    external_base_url: String,
    /// Transport + abuse-control limits for the public sandbox.
    limits: ServerLimits,
    /// Per-IP / per-account / per-repo rate limiters.
    rl: Limiters,
    /// Bounds concurrent (expensive) repo seals.
    seal_sem: Semaphore,
    /// Optional proof-of-work gate for anonymous ephemeral creation.
    pow: pow::PowGate,
    /// Content-free metrics registry (shared with the metrics listener).
    metrics: Arc<Metrics>,
    /// Metrics exposure config (token gate for `/metrics`).
    metrics_cfg: MetricsConfig,
    /// Serializes read-modify-write on the encrypted abuse/waitlist queues.
    queue_lock: Mutex<()>,
    /// Operator token gating `/admin/*` (takedown, abuse review). `None` disables admin.
    admin_token: Option<String>,
}

fn data_dir() -> std::path::PathBuf {
    std::env::var("SECGIT_DATA")
        .map(Into::into)
        .unwrap_or_else(|_| ".secgit-data".into())
}

/// Obtain the KEK via the attestation-gated key-release flow.
///
/// Three paths, selected by environment and hardware:
/// 1. `SECGIT_KBS_URL` set -> the KEK lives in a self-hosted key broker: we send SNP/TDX
///    evidence and receive the KEK KEM-sealed to our ephemeral key (production model).
/// 2. `configfs-tsm` present (no KBS) -> in-process broker doing the FULL SNP verify
///    (VCEK chain to the pinned AMD root + measurement policy); KEK material from env.
/// 3. Neither (dev/CI) -> mock verifier + local KEK, with a loud warning.
fn acquire_kek() -> Result<SymKey> {
    let attester = detect_attester();
    let snp = secgit_attest::snp::SnpAttester::available();

    // Path 1: self-hosted KBS holds the KEK.
    if let Ok(kbs_url) = std::env::var("SECGIT_KBS_URL") {
        let client = kbs::HttpKbsClient::new(&kbs_url, &["snp".into(), "tdx".into()])
            .map_err(|e| anyhow::anyhow!("KBS config rejected: {e}"))?;
        let resource =
            std::env::var("SECGIT_KEK_RESOURCE").unwrap_or_else(|_| "secgit/instance-kek".into());
        let released = attest_and_unwrap(&resource, attester.as_ref(), &client)
            .map_err(|e| anyhow::anyhow!("KBS attestation-gated KEK release failed: {e}"))?;
        println!("secgit-server: KEK released by self-hosted KBS at {kbs_url}");
        return Ok(released);
    }

    // Paths 2 & 3: in-process broker.
    let mut provider = InMemoryKekProvider::new();
    provider.insert("secgit/instance-kek", local_kek_material()?);
    let policy = snp_policy(snp)?;
    let verifier: Box<dyn secgit_attest::Verifier> = if snp {
        println!("secgit-server: configfs-tsm present — using real SEV-SNP verifier (VCEK chain + measurement policy)");
        Box::new(build_snp_verifier()?)
    } else {
        eprintln!("secgit-server: WARNING no configfs-tsm — using MOCK verifier (DEV/CI ONLY, not secure)");
        Box::new(secgit_attest::mock::MockVerifier::new())
    };
    // Durable replay/freshness guard for the release path (refuses replayed/stale evidence).
    let ttl = std::env::var("SECGIT_REPLAY_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let guard =
        secgit_keybroker::replay::ReplayGuard::open(data_dir().join("replay-guard.json"), ttl)
            .map_err(|e| anyhow::anyhow!("opening replay guard: {e}"))?;
    let broker = LocalKeyBroker::new(verifier, policy, Box::new(provider)).with_replay_guard(guard);
    let released = attest_and_unwrap("secgit/instance-kek", attester.as_ref(), &broker)
        .map_err(|e| anyhow::anyhow!("attestation-gated KEK release failed: {e}"))?;
    Ok(released)
}

/// Local KEK material for the in-process broker (dev/local-SNP paths).
fn local_kek_material() -> Result<SymKey> {
    match std::env::var("SECGIT_DEV_KEK_HEX") {
        Ok(h) => {
            let b = hex::decode(h).context("SECGIT_DEV_KEK_HEX must be hex")?;
            anyhow::ensure!(b.len() == 32, "SECGIT_DEV_KEK_HEX must be 32 bytes");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Ok(SymKey::from_bytes(a))
        }
        Err(_) => {
            eprintln!(
                "warning: SECGIT_DEV_KEK_HEX not set; using an ephemeral KEK (data won't persist)"
            );
            SymKey::generate()
        }
    }
    .map_err(|e| anyhow::anyhow!("KEK material: {e}"))
}

/// Build the verification policy. On SNP we require a genuine vendor root and pin the
/// launch measurement to a published reference (`SECGIT_SNP_REFERENCE` -> the JSON written
/// by `xtask snp-measure`, also published to the transparency log).
fn snp_policy(snp: bool) -> Result<Policy> {
    let allowed_measurements = match std::env::var("SECGIT_SNP_REFERENCE") {
        Ok(path) => {
            let json: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&path).with_context(|| format!("reading {path}"))?,
            )?;
            let hex_m = json
                .get("measurement_hex")
                .and_then(|v| v.as_str())
                .context("snp-reference.json missing measurement_hex")?;
            let m = hex::decode(hex_m).context("measurement_hex not hex")?;
            anyhow::ensure!(m.len() == 48, "measurement must be 48 bytes");
            println!("secgit-server: pinned launch measurement {hex_m}");
            vec![m]
        }
        Err(_) => {
            if snp {
                eprintln!(
                    "secgit-server: WARNING no SECGIT_SNP_REFERENCE — vendor root required but \
                     launch measurement NOT pinned (set it to a transparency-logged reference)"
                );
            }
            vec![]
        }
    };
    Ok(Policy {
        allowed_measurements,
        require_vendor_root: snp,
        // The in-CVM TEE runs at VMPL0; require it on real SNP so a less-privileged
        // context cannot supply attestation for the KEK release. Allow an override for
        // unusual topologies via SECGIT_SNP_EXPECTED_VMPL.
        expected_vmpl: if snp {
            Some(
                std::env::var("SECGIT_SNP_EXPECTED_VMPL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            )
        } else {
            None
        },
    })
}

/// Build an SNP verifier that resolves+validates each report's VCEK from AMD KDS (with an
/// offline cache), chaining to the pinned ARK.
fn build_snp_verifier() -> Result<secgit_attest::snp::SnpVerifier> {
    use secgit_attest::vcek::{Product, RevocationConfig, VcekCache};
    let product =
        Product::parse(&std::env::var("SECGIT_SNP_PRODUCT").unwrap_or_else(|_| "Milan".into()))
            .context("SECGIT_SNP_PRODUCT must be Milan or Genoa")?;
    let cache_dir = std::env::var("SECGIT_VCEK_CACHE")
        .unwrap_or_else(|_| data_dir().join("vcek-cache").to_string_lossy().into_owned());
    let cache = VcekCache::new(cache_dir);
    // Revocation fails CLOSED by default. The offline-cache window is configurable for
    // air-gapped installs via SECGIT_CRL_MAX_AGE_SECS.
    let revocation = RevocationConfig {
        enabled: std::env::var("SECGIT_DISABLE_REVOCATION").is_err(),
        max_crl_age_secs: std::env::var("SECGIT_CRL_MAX_AGE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(RevocationConfig::default().max_crl_age_secs),
    };
    Ok(secgit_attest::snp::SnpVerifier::with_resolver(
        move |chip_id, tcb| {
            secgit_attest::vcek::resolve_vcek(
                product,
                chip_id,
                tcb,
                &cache,
                |url| {
                    secgit_net::https_get(url)
                        .map_err(|e| secgit_attest::AttestError::Io(e.to_string()))
                },
                &revocation,
            )
        },
    ))
}

fn main() -> Result<()> {
    if let Err(e) = run() {
        let msg = format!("{e:#}");
        if msg.contains("authentication failed")
            || msg.contains("wrong key")
            || msg.contains("tampered ciphertext")
        {
            let dir = data_dir();
            eprintln!();
            eprintln!(
                "secgit-server: could not decrypt the existing state in {}.",
                dir.display()
            );
            eprintln!(
                "This almost always means the data dir was written with a DIFFERENT key than the"
            );
            eprintln!(
                "one in use now — e.g. SECGIT_DEV_KEK_HEX changed, or an earlier run used a random"
            );
            eprintln!(
                "ephemeral key because SECGIT_DEV_KEK_HEX was unset. By design, SecGit cannot"
            );
            eprintln!("read data it cannot authenticate. Resolve it one of two ways:");
            eprintln!();
            eprintln!("  1. Reuse the SAME key that wrote the data:");
            eprintln!("       export SECGIT_DEV_KEK_HEX=<original-32-byte-hex>");
            eprintln!("  2. Start fresh (DELETES existing repos, accounts, and audit log):");
            eprintln!("       rm -rf {}", dir.display());
            eprintln!();
        }
        return Err(e);
    }
    Ok(())
}

fn run() -> Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;

    println!("secgit-server: acquiring KEK via attestation-gated release...");
    let kek = acquire_kek()?;

    // Derive domain-separated at-rest keys from the instance KEK so the transparency log's
    // event metadata and the identity directory are ciphertext on the operator's disk too
    // (the metadata confidentiality boundary). The KEK itself never touches disk.
    let audit_key = derive_subkey(&kek, b"secgit/audit-at-rest/v1")?;
    let directory_key = derive_subkey(&kek, b"secgit/directory-at-rest/v1")?;
    let search_key = derive_subkey(&kek, b"secgit/search-at-rest/v1")?;

    let store = EncryptedStore::open(dir.join("store"), kek)?;
    let search_store = EncryptedStore::open(dir.join("search"), search_key)?;
    let forge = Forge::new(dir.join("repos"))?;

    // Identity directory + accounts (encrypted at rest, separate store).
    let dir_store = EncryptedStore::open(dir.join("directory"), directory_key)?;
    let directory = secgit_identity::PersistentDirectory::open(dir_store)
        .map_err(|e| anyhow::anyhow!("opening identity directory: {e}"))?;
    let mut local = secgit_identity::LocalAuthenticator::new();
    bootstrap_admin(&mut local)?;
    let mut identity = authz::ServerIdentity::new(
        directory,
        local,
        secgit_identity::SessionStore::new(12 * 3600),
    );
    // Mirror the bootstrap account into the (encrypted) identity directory so repos it
    // creates are owned by a real user record (clean `<username>/<repo>` ids, visible in
    // `/ui`). Idempotent across restarts.
    ensure_bootstrap_directory_user(&mut identity)?;

    // Audit log signer: load a persisted bundle or create one.
    let signer = load_or_create_signer(&dir)?;
    let audit = TransparencyLog::open_encrypted(
        dir.join("audit.log"),
        "secgit-instance",
        signer,
        audit_key,
    )?;

    // PQC-TLS terminates IN-PROCESS inside the CVM (no operator-visible plaintext hop).
    // The dev-only SECGIT_INSECURE_HTTP escape hatch serves plaintext for local testing.
    let tls = if std::env::var("SECGIT_INSECURE_HTTP").is_ok() {
        eprintln!(
            "secgit-server: WARNING SECGIT_INSECURE_HTTP set — serving plaintext HTTP; \
             this is NOT provider-blind on the wire. Dev/local use only."
        );
        None
    } else {
        Some(tls::load_or_generate()?)
    };

    // One repo model by default: persistent, account-owned repos (visible in /ui, push-to-
    // create). The anonymous *ephemeral* "viral sandbox" path creates a second, throwaway,
    // owner-less repo kind that never shows in /ui — so it is OFF unless explicitly enabled.
    // The public sandbox turns it back on with SECGIT_ENABLE_ANONYMOUS=1 (config, not a fork).
    // All tier/limit knobs are environment-overridable (see config.rs).
    let config = config::deployment_from_env();
    if config.anonymous_enabled {
        eprintln!(
            "secgit-server: anonymous ephemeral repos ENABLED (SECGIT_ENABLE_ANONYMOUS) — \
             these are throwaway and intentionally not shown in /ui"
        );
    }

    // Public-sandbox abuse/DoS controls.
    let limits = ServerLimits::from_env();
    let pow_cfg = config::PowConfig::from_env();
    let metrics_cfg = MetricsConfig::from_env();
    let admin_token = std::env::var("SECGIT_ADMIN_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let server_metrics = Arc::new(Metrics::new());
    if pow_cfg.enabled {
        println!(
            "secgit-server: anonymous ephemeral PoW gate ENABLED ({} bits)",
            pow_cfg.difficulty_bits
        );
    }

    let (saml, scim_token, external_base_url) = load_sso_config()?;

    // Rebuild persistent-tier quota state from the directory + stored seal sizes so the
    // Light-tier caps hold across restarts. `sealed_size` sums the incremental seal
    // segments (or the legacy monolithic bundle) without decrypting anything.
    let mut quota = AccountQuota::new(config.clone());
    for repo in identity.dir.list_repos() {
        if let RepoOwner::User(uid) = &repo.owner {
            let bytes = forge.sealed_size(&repo.id, &store).unwrap_or(0);
            quota.preload(uid, Tier::Light, &repo.id, bytes);
        }
    }

    let rl = Limiters::from_limits(&limits);
    let seal_sem = Semaphore::new(limits.seal_concurrency);

    let app = Arc::new(App {
        forge,
        store,
        search_store,
        audit: Mutex::new(audit),
        ephemeral: Mutex::new(EphemeralRepos::new(config.clone())),
        identity: Mutex::new(identity),
        quota: Mutex::new(quota),
        config,
        tls_spki_sha256_hex: tls.as_ref().map(|t| t.spki_sha256_hex.clone()),
        saml,
        scim_token,
        external_base_url,
        limits,
        rl,
        seal_sem,
        pow: pow::PowGate::new(pow_cfg),
        metrics: Arc::clone(&server_metrics),
        metrics_cfg: metrics_cfg.clone(),
        queue_lock: Mutex::new(()),
        admin_token,
    });

    // Reclaim storage for anonymous ephemeral repos orphaned by a crash/restart: ephemeral
    // state is in-memory only, so any `ephemeral/*` working set/store entry on boot is an
    // orphan (its TTL guard is gone). Persistent repos are protected by a directory check.
    wipe_orphaned_ephemeral(&app);

    // Background GC: expire ephemeral repos and wipe their working set + encrypted storage.
    spawn_ephemeral_gc(Arc::clone(&app));

    // Dedicated, content-free metrics listener (localhost by default; never public unless
    // configured). Separate from the main serving port and optionally token-gated.
    if let Some(maddr) = metrics_cfg.addr.clone() {
        let metrics = Arc::clone(&server_metrics);
        let token = metrics_cfg.token.clone();
        std::thread::spawn(move || serve_metrics(&maddr, metrics, token));
    }

    let addr = std::env::var("SECGIT_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    println!(
        "secgit-server: listening on {scheme}://{addr} (sandbox_mode={}, pq_tls={}, max_conns={})",
        app.config.sandbox_mode,
        tls.is_some() && tls::post_quantum_preferred(),
        app.limits.max_connections,
    );

    let tls_config = tls.map(|t| t.config);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Connection cap: bound concurrent handlers so a flood cannot spawn unbounded
        // threads / memory. Increment-then-check keeps the gauge honest under races.
        let prev = app
            .metrics
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev as usize >= app.limits.max_connections {
            app.metrics
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            Metrics::inc(&app.metrics.conn_rejected_total);
            drop(stream); // close immediately; cheaper than serving 503 under flood
            continue;
        }
        Metrics::inc(&app.metrics.conn_accepted_total);
        let app = Arc::clone(&app);
        let tls_config = tls_config.clone();
        std::thread::spawn(move || {
            let _guard = ConnGuard {
                metrics: Arc::clone(&app.metrics),
            };
            handle_conn(&app, stream, tls_config);
        });
    }
    Ok(())
}

/// Serve only the content-free metrics + health on a dedicated (plaintext, localhost by
/// default) listener. Content-free by construction, so plaintext is acceptable; still
/// optionally token-gated. Never serves repo content or any other route.
fn serve_metrics(addr: &str, metrics: Arc<Metrics>, token: Option<String>) {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("secgit-server: metrics listener disabled (bind {addr}: {e})");
            return;
        }
    };
    println!("secgit-server: content-free metrics on http://{addr}/metrics");
    let limits = http::HttpLimits::default();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
        let resp = match http::parse_request(&mut stream, &limits) {
            Ok(ParseOutcome::Request(req)) => match req.path.as_str() {
                "/metrics" => {
                    if metrics_authorized(&token, &req) {
                        Response::new(
                            200,
                            "OK",
                            "text/plain; version=0.0.4",
                            metrics.render().into_bytes(),
                        )
                    } else {
                        Response::text(401, "Unauthorized", "metrics token required")
                    }
                }
                "/healthz" => Response::text(200, "OK", "ok"),
                _ => Response::text(404, "Not Found", "not found"),
            },
            Ok(ParseOutcome::Reject(resp)) => resp,
            _ => continue,
        };
        let _ = http::write_response(&mut stream, &resp);
    }
}

fn metrics_authorized(token: &Option<String>, req: &Request) -> bool {
    match token {
        None => true,
        Some(t) => req
            .bearer_token()
            .map(|got| secgit_crypto::primitives::ct_eq(got.as_bytes(), t.as_bytes()))
            .unwrap_or(false),
    }
}

/// Delete every anonymous ephemeral repo left on disk (working set + encrypted store),
/// skipping any id that is a real persistent repo in the identity directory.
fn wipe_orphaned_ephemeral(app: &App) {
    let mut wiped = 0u64;
    for stem in app.forge.working_dir_stems() {
        // Anonymous ephemeral ids are `ephemeral/<hex>` -> sanitized stem `ephemeral_<hex>`.
        let Some(hex) = stem.strip_prefix("ephemeral_") else {
            continue;
        };
        let repo_id = format!("ephemeral/{hex}");
        let is_persistent = app
            .identity
            .lock()
            .unwrap()
            .dir
            .get_repo(&repo_id)
            .is_some();
        if is_persistent {
            continue;
        }
        let _ = app.forge.delete(&repo_id);
        let _ = app.store.delete_repo(&repo_id);
        wiped += 1;
    }
    if wiped > 0 {
        println!("secgit-server: reclaimed {wiped} orphaned ephemeral repo(s) at startup");
    }
}

/// Spawn the background GC loop that expires ephemeral repos and wipes their storage.
fn spawn_ephemeral_gc(app: Arc<App>) {
    // Sweep at a fraction of the TTL so expired repos are reclaimed promptly, clamped to a
    // sane range so a tiny TTL doesn't busy-loop.
    let ttl = app.config.ephemeral_ttl_secs.max(1);
    let interval = (ttl / 4).clamp(30, 3600);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        let expired = app.ephemeral.lock().unwrap().gc();
        for repo_id in expired {
            let _ = app.forge.delete(&repo_id);
            let _ = app.store.delete_repo(&repo_id);
            Metrics::inc(&app.metrics.ephemeral_gc_total);
        }
    });
}

/// Serve one connection, terminating TLS in-process when configured.
///
/// Socket read/write timeouts are set before the (TLS) handshake so a slowloris cannot pin
/// the connection during the handshake or while trickling headers/body.
fn handle_conn(app: &App, stream: TcpStream, tls: Option<Arc<rustls::ServerConfig>>) {
    let _ = stream.set_read_timeout(Some(app.limits.read_timeout));
    let _ = stream.set_write_timeout(Some(app.limits.write_timeout));
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    match tls {
        Some(cfg) => {
            let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                return;
            };
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);
            serve_stream(app, &mut tls_stream, &peer_ip);
        }
        None => {
            let mut stream = stream;
            serve_stream(app, &mut stream, &peer_ip);
        }
    }
}

/// Parse one request from `s`, enforce the per-IP request-rate limit, route it, and write
/// the response — recording content-free metrics along the way.
fn serve_stream<S: std::io::Read + std::io::Write>(app: &App, s: &mut S, peer_ip: &str) {
    let resp = match http::parse_request(s, &app.limits.http_limits()) {
        Ok(ParseOutcome::Request(mut req)) => {
            req.peer_ip = peer_ip.to_string();
            if !app.rl.ip_req.check(peer_ip) {
                Metrics::inc(&app.metrics.rate_limited_total);
                Response::text(429, "Too Many Requests", "rate limit exceeded")
                    .with_header("Retry-After", "1")
            } else {
                route(app, &req)
            }
        }
        Ok(ParseOutcome::Reject(resp)) => {
            match resp.status {
                413 => Metrics::inc(&app.metrics.body_rejected_total),
                431 => Metrics::inc(&app.metrics.header_rejected_total),
                _ => {}
            }
            resp
        }
        _ => return,
    };
    app.metrics.record_status(resp.status);
    let _ = http::write_response(s, &resp);
}

/// Derive a domain-separated subkey from the instance KEK via HKDF. Each subsystem
/// (audit log, identity directory) gets its own at-rest key, all living only in TEE memory;
/// the KEK itself never touches disk.
fn derive_subkey(kek: &SymKey, info: &[u8]) -> Result<SymKey> {
    let okm =
        secgit_crypto::primitives::hkdf_sha384(kek.expose(), b"secgit/subkey-salt/v1", info, 32)
            .map_err(|e| anyhow::anyhow!("deriving subkey: {e}"))?;
    let mut b = [0u8; 32];
    b.copy_from_slice(&okm);
    Ok(SymKey::from_bytes(b))
}

/// Optionally register a bootstrap local account from the environment, so an operator can
/// seed the first identity without a chicken-and-egg problem. No-op if unset.
fn bootstrap_admin(local: &mut secgit_identity::LocalAuthenticator) -> Result<()> {
    if let (Ok(user), Ok(pass)) = (
        std::env::var("SECGIT_BOOTSTRAP_USER"),
        std::env::var("SECGIT_BOOTSTRAP_PASS"),
    ) {
        let uid = format!("u_{user}");
        local
            .register(&user, &uid, &pass)
            .map_err(|e| anyhow::anyhow!("bootstrap account: {e}"))?;
        println!("secgit-server: registered bootstrap account '{user}' (id={uid})");
    }
    Ok(())
}

/// Ensure the bootstrap account also exists as a directory `User`, so repos it creates are
/// owned by a real record and show up in `/ui`. No-op if `SECGIT_BOOTSTRAP_USER` is unset
/// or the user already exists (e.g. on a restart over persistent data).
fn ensure_bootstrap_directory_user(identity: &mut authz::ServerIdentity) -> Result<()> {
    let Ok(user) = std::env::var("SECGIT_BOOTSTRAP_USER") else {
        return Ok(());
    };
    if user.is_empty() {
        return Ok(());
    }
    let uid = format!("u_{user}");
    if identity.dir.get_user(&uid).is_some() {
        return Ok(());
    }
    let email = std::env::var("SECGIT_BOOTSTRAP_EMAIL").unwrap_or_else(|_| format!("{user}@local"));
    identity
        .dir
        .create_user(secgit_identity::User {
            id: uid.clone(),
            username: user.clone(),
            email,
        })
        .map_err(|e| anyhow::anyhow!("registering bootstrap user in directory: {e}"))?;
    println!("secgit-server: registered bootstrap user '{user}' in identity directory (id={uid})");
    Ok(())
}

/// Load optional enterprise SSO/provisioning config from the environment.
///
/// SAML (all required to enable): `SECGIT_SAML_SP_ENTITY_ID`, `SECGIT_SAML_ACS_URL`,
/// `SECGIT_SAML_IDP_ENTITY_ID`, `SECGIT_SAML_IDP_CERT` (path to the pinned IdP cert,
/// PEM or DER). SCIM: `SECGIT_SCIM_TOKEN`. Public URL: `SECGIT_EXTERNAL_URL`.
fn load_sso_config() -> Result<(Option<secgit_sso::SamlSp>, Option<String>, String)> {
    let external_base_url =
        std::env::var("SECGIT_EXTERNAL_URL").unwrap_or_else(|_| "https://localhost:8080".into());

    let saml = match (
        std::env::var("SECGIT_SAML_SP_ENTITY_ID"),
        std::env::var("SECGIT_SAML_ACS_URL"),
        std::env::var("SECGIT_SAML_IDP_ENTITY_ID"),
        std::env::var("SECGIT_SAML_IDP_CERT"),
    ) {
        (Ok(sp), Ok(acs), Ok(idp), Ok(cert_path)) => {
            let cert = std::fs::read(&cert_path)
                .with_context(|| format!("reading SAML IdP cert {cert_path}"))?;
            let sp = secgit_sso::SamlSp::new(&sp, &acs, &idp, &cert)
                .map_err(|e| anyhow::anyhow!("SAML SP config: {e}"))?;
            println!("secgit-server: SAML SSO enabled (idp={idp})");
            Some(sp)
        }
        _ => None,
    };

    let scim_token = std::env::var("SECGIT_SCIM_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    if scim_token.is_some() {
        println!("secgit-server: SCIM provisioning enabled");
    }

    Ok((saml, scim_token, external_base_url))
}

fn load_or_create_signer(dir: &std::path::Path) -> Result<secgit_crypto::sig::SigningKey> {
    let path = dir.join("audit-signer.json");
    if path.exists() {
        let bundle: secgit_crypto::sig::SigningKeyBundle =
            serde_json::from_slice(&std::fs::read(&path)?)?;
        Ok(secgit_crypto::sig::SigningKey::from_bundle(&bundle)?)
    } else {
        let (signer, bundle) =
            secgit_crypto::sig::SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?;
        std::fs::write(&path, serde_json::to_vec_pretty(&bundle)?)?;
        Ok(signer)
    }
}

fn route(app: &App, req: &Request) -> Response {
    let path = req.path.clone();
    if path.starts_with("/scim/v2/") {
        if let Some(resp) = sso::route_scim(app, req) {
            return resp;
        }
    }
    if req.method == "POST" && path == "/sso/saml/acs" {
        return sso::route_saml_acs(app, req);
    }
    if req.method == "GET" && path == "/sso/saml/metadata" {
        return sso::saml_metadata(app);
    }
    if path == "/api/graphql" || path.starts_with("/api/v1/") {
        if let Some(resp) = api::route_api(app, req) {
            return resp;
        }
    }
    if req.method == "GET" && path == "/ui/search" {
        return search_route(app, req);
    }
    if req.method == "GET" && (path == "/ui" || path.starts_with("/ui/")) {
        // Materialize the working repo from encrypted storage on demand (plaintext only
        // on the in-CVM working path).
        if let Some(repo) = req.query.get("repo") {
            if !app.forge.exists(repo) {
                let _ = app.forge.restore_from_store(repo, &app.store);
            }
        }
        let mut identity = app.identity.lock().unwrap();
        if let Some(resp) = web::route_ui(&app.forge, &mut identity, req) {
            return resp;
        }
    }
    if req.method == "POST" && path == "/ui/repo/new" {
        return ui_create_repo(app, req);
    }
    if req.method == "POST" && path.starts_with("/ui/") {
        let mut identity = app.identity.lock().unwrap();
        if let Some(resp) = web::route_ui_post(&mut identity, req) {
            return resp;
        }
    }
    match (req.method.as_str(), path.as_str()) {
        ("GET", "/") => landing(app),
        ("GET", "/healthz") => Response::text(200, "OK", "ok"),
        ("GET", "/metrics") => metrics_endpoint(app, req),
        ("GET", "/sbom") => transparency_file("SECGIT_SBOM"),
        ("GET", "/image-manifest") => transparency_file("SECGIT_IMAGE_MANIFEST"),
        ("GET", "/attestation") => attestation(app),
        ("GET", "/sandbox/pow-challenge") => pow_challenge(app, req),
        ("POST", "/sandbox/ephemeral") => create_ephemeral(app, req),
        ("POST", "/abuse/report") => abuse_report(app, req),
        ("POST", "/waitlist") => waitlist_signup(app, req),
        ("GET", "/admin/abuse") => admin_list_abuse(app, req),
        ("POST", "/admin/repos/delete") => admin_takedown(app, req),
        _ => git_route(app, req),
    }
}

/// Content-free metrics on the main serving port. Only exposed when a metrics token is
/// configured AND presented — so the public port never leaks an open metrics endpoint. The
/// dedicated localhost listener ([`serve_metrics`]) is the normal scrape path.
fn metrics_endpoint(app: &App, req: &Request) -> Response {
    match &app.metrics_cfg.token {
        Some(_) if metrics_authorized(&app.metrics_cfg.token, req) => Response::new(
            200,
            "OK",
            "text/plain; version=0.0.4",
            app.metrics.render().into_bytes(),
        ),
        _ => Response::text(404, "Not Found", "not found"),
    }
}

/// Issue a proof-of-work challenge for the anonymous ephemeral-create path.
fn pow_challenge(app: &App, req: &Request) -> Response {
    if !app.pow.enabled() {
        return Response::json(&serde_json::json!({ "enabled": false }));
    }
    Metrics::inc(&app.metrics.pow_challenges_total);
    let challenge = app.pow.issue(&req.peer_ip);
    Response::json(&serde_json::json!({
        "enabled": true,
        "difficulty_bits": app.pow.difficulty_bits(),
        "challenge": challenge,
        "solve": "find NONCE s.t. sha256(\"<challenge>:<NONCE>\") has >= difficulty_bits leading zero bits; \
                  submit header 'X-SecGit-PoW: <challenge>:<NONCE>' to POST /sandbox/ephemeral",
    }))
}

/// Accept an abuse report for a repo id. Stored encrypted; operator stays content-blind.
/// Aggressively rate-limited (per-IP) since it is an unauthenticated public endpoint.
fn abuse_report(app: &App, req: &Request) -> Response {
    if !app.rl.ip_git.check(&req.peer_ip) {
        Metrics::inc(&app.metrics.rate_limited_total);
        return Response::text(429, "Too Many Requests", "rate limit exceeded");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
    let repo_id = body.get("repo_id").and_then(|v| v.as_str()).unwrap_or("");
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    if repo_id.is_empty() {
        return Response::text(400, "Bad Request", "repo_id is required");
    }
    match abuse::report(&app.store, &app.queue_lock, repo_id, reason, &req.peer_ip) {
        Ok(rep) => {
            Metrics::inc(&app.metrics.abuse_reports_total);
            if let Ok(mut log) = app.audit.lock() {
                let _ = log.append(AuditEvent::Admin {
                    action: format!("abuse_report:{repo_id}"),
                    actor: "anonymous".into(),
                });
            }
            Response::new(202, "Accepted", "application/json", {
                serde_json::json!({ "accepted": true, "report_id": rep.id })
                    .to_string()
                    .into_bytes()
            })
        }
        Err(e) => Response::text(500, "Internal Server Error", &e),
    }
}

/// Capture a managed-tier waitlist signup (email) into the encrypted queue.
fn waitlist_signup(app: &App, req: &Request) -> Response {
    if !app.rl.ip_git.check(&req.peer_ip) {
        Metrics::inc(&app.metrics.rate_limited_total);
        return Response::text(429, "Too Many Requests", "rate limit exceeded");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if email.is_empty() || !email.contains('@') || email.len() > 320 {
        return Response::text(400, "Bad Request", "a valid email is required");
    }
    match abuse::waitlist_add(&app.store, &app.queue_lock, email) {
        Ok(()) => Response::new(
            202,
            "Accepted",
            "application/json",
            serde_json::json!({ "waitlisted": true })
                .to_string()
                .into_bytes(),
        ),
        Err(e) => Response::text(500, "Internal Server Error", &e),
    }
}

/// Operator-only: verify the admin token (constant-time). `None` config disables `/admin/*`.
fn admin_authorized(app: &App, req: &Request) -> bool {
    match &app.admin_token {
        None => false,
        Some(t) => req
            .bearer_token()
            .map(|got| secgit_crypto::primitives::ct_eq(got.as_bytes(), t.as_bytes()))
            .unwrap_or(false),
    }
}

/// Operator-only: list queued abuse reports (decrypted inside the TEE, served over TLS).
fn admin_list_abuse(app: &App, req: &Request) -> Response {
    if !admin_authorized(app, req) {
        return Response::text(401, "Unauthorized", "admin token required");
    }
    let reports = abuse::list(&app.store);
    Response::json(&serde_json::json!({ "reports": reports }))
}

/// Operator-only: force-delete a repo by id (takedown). Wipes the working set + encrypted
/// storage + directory record + ephemeral state, and records the takedown in the audit log.
fn admin_takedown(app: &App, req: &Request) -> Response {
    if !admin_authorized(app, req) {
        return Response::text(401, "Unauthorized", "admin token required");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
    let repo_id = body.get("repo_id").and_then(|v| v.as_str()).unwrap_or("");
    if repo_id.is_empty() {
        return Response::text(400, "Bad Request", "repo_id is required");
    }
    let _ = app.forge.delete(repo_id);
    let _ = app.store.delete_repo(repo_id);
    {
        let mut identity = app.identity.lock().unwrap();
        if let Some(RepoOwner::User(uid)) = identity.dir.get_repo(repo_id).map(|r| r.owner.clone())
        {
            let _ = app.quota.lock().unwrap().remove_repo(&uid, repo_id);
        }
        let _ = identity.dir.delete_repo(repo_id);
    }
    Metrics::inc(&app.metrics.takedowns_total);
    if let Ok(mut log) = app.audit.lock() {
        let _ = log.append(AuditEvent::Admin {
            action: format!("takedown:{repo_id}"),
            actor: "operator".into(),
        });
    }
    Response::json(&serde_json::json!({ "deleted": true, "repo_id": repo_id }))
}

/// Serve a public image-transparency artifact (SBOM / image manifest) from the path in
/// the given env var. These are deterministic build outputs, not secrets.
fn transparency_file(env_var: &str) -> Response {
    let path = match std::env::var(env_var) {
        Ok(p) if !p.is_empty() => p,
        _ => return Response::text(404, "Not Found", "transparency artifact not configured"),
    };
    match std::fs::read(&path) {
        Ok(bytes) => Response::new(200, "OK", "application/json", bytes),
        Err(_) => Response::text(404, "Not Found", "transparency artifact unavailable"),
    }
}

/// Public landing page for the sandbox instance: the wedge, how to verify, and the tiers.
fn landing(app: &App) -> Response {
    let cfg = &app.config;
    let pq = app.tls_spki_sha256_hex.is_some();
    let sandbox_banner = if cfg.sandbox_mode {
        "<p style=\"background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:10px 12px\">\
         <strong>Public sandbox — do not push production secrets.</strong> This is a shared demo \
         instance running in sandbox mode: repos are capped, anonymous repos auto-expire, and abuse \
         controls are aggressive. Confidentiality still holds (that is the point you can verify), but \
         treat it as ephemeral.</p>"
    } else {
        ""
    };
    let pow_note = if app.pow.enabled() {
        format!(
            "<li><a href=\"/sandbox/pow-challenge\">/sandbox/pow-challenge</a> — a lightweight \
             proof-of-work ({} bits) is required before creating an anonymous repo.</li>",
            app.pow.difficulty_bits()
        )
    } else {
        String::new()
    };
    let body = format!(
        "{banner}\
         <h1>SecGit</h1>\
         <p class=\"muted\">Confidential, attestation-backed, post-quantum hosting for private code. \
         The operator can't read your code, can't train on it, can't be subpoenaed into surrendering \
         it, and it's safe from harvest-now-decrypt-later — and all of this is <em>verifiable</em>.</p>\
         <h2>Verify it yourself</h2>\
         <ol>\
         <li><a href=\"/attestation\">/attestation</a> — fetch a fresh SEV-SNP report bound to this \
             instance's TLS key (verify the chain to AMD roots with <code>secgit-verify</code>).</li>\
         {pow}\
         <li><code>POST /sandbox/ephemeral</code> — get a throwaway, auto-expiring repo + push token, \
             push your own code over PQC-TLS, then confirm it's ciphertext-only on the host.</li>\
         <li><a href=\"/ui\">/ui</a> — browse repositories you can access.</li>\
         </ol>\
         <h2>Interaction tiers</h2>\
         <ul>\
         <li><strong>Anonymous</strong>: {anon} — ephemeral capped repos (TTL {ttl}s, {cap} MiB).</li>\
         <li><strong>Light</strong>: {light} — account-backed persistent capped repos.</li>\
         <li><strong>Managed</strong>: {managed} — org + BYOK + IdP (enterprise).</li>\
         </ul>\
         <h2>Managed-tier waitlist</h2>\
         <p class=\"muted\">Want a private org instance with BYOK-to-your-KMS and your IdP? Join the \
         waitlist (your email is stored encrypted at rest, like everything else here):</p>\
         <form method=\"post\" action=\"/waitlist\" onsubmit=\"event.preventDefault();fetch('/waitlist',\
         {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:this.email.value}})}})\
         .then(r=>{{this.nextElementSibling.textContent=r.ok?'Thanks — you are on the list.':'Please enter a valid email.';}});\">\
         <input name=\"email\" type=\"email\" placeholder=\"you@company.com\" size=\"30\" required> \
         <button>Join waitlist</button></form><p class=\"muted\"></p>\
         <h2>Report abuse</h2>\
         <p class=\"muted\">This instance can't read repo contents, so takedowns are by repo id: \
         <code>POST /abuse/report</code> with <code>{{\"repo_id\":\"...\",\"reason\":\"...\"}}</code>.</p>\
         <p class=\"muted\">PQC-TLS in-CVM: {pq}. This public instance is the same OSS build run in \
         sandbox mode (a config, not a fork).</p>",
        banner = sandbox_banner,
        pow = pow_note,
        anon = on_off(cfg.anonymous_enabled),
        light = on_off(cfg.light_enabled),
        managed = on_off(cfg.managed_enabled),
        ttl = cfg.ephemeral_ttl_secs,
        cap = cfg.ephemeral_max_bytes / (1024 * 1024),
        pq = on_off(pq),
    );
    web::page("SecGit", &body)
}

fn on_off(b: bool) -> &'static str {
    if b {
        "enabled"
    } else {
        "disabled"
    }
}

fn attestation(app: &App) -> Response {
    // Produce fresh evidence bound to a server-chosen nonce so a caller can verify.
    // Channel binding: when in-CVM TLS is active we fold the cert SPKI fingerprint into
    // report_data, so a client proves the attested TEE *is* its TLS peer (defeats a
    // man-in-the-middle relaying attestation from a real TEE).
    let attester = detect_attester();
    let nonce = secgit_crypto::primitives::random_vec(32).unwrap_or_default();
    let channel = match &app.tls_spki_sha256_hex {
        Some(spki) => format!("secgit-tls-spki-sha256:{spki}"),
        None => "secgit-server-attestation-insecure-http".to_string(),
    };
    let rd = ReportData::bind(&nonce, channel.as_bytes());
    match attester.get_evidence(&rd) {
        Ok(ev) => Response::json(&serde_json::json!({
            "backend": format!("{:?}", ev.backend),
            "nonce_hex": hex::encode(&nonce),
            "evidence": ev,
            "channel_binding": channel,
            "tls_spki_sha256_hex": app.tls_spki_sha256_hex,
            "note": "Verify with secgit-verify; bind = SHA512(nonce || tee_pubkey); \
                     report_data also commits to the TLS cert SPKI (channel_binding).",
            "sandbox_mode": app.config.sandbox_mode,
        })),
        Err(e) => Response::json(&serde_json::json!({
            "backend": "unavailable",
            "error": e.to_string(),
            "note": "No TEE present; this build would attest on SEV-SNP silicon.",
        })),
    }
}

fn create_ephemeral(app: &App, req: &Request) -> Response {
    if !app.config.anonymous_enabled {
        return Response::text(403, "Forbidden", "anonymous tier disabled");
    }
    // Optional proof-of-work gate (default off): raises the cost of automated spam beyond
    // the per-IP rate limit. The challenge is bound to this client's IP.
    if app.pow.enabled() {
        let submission = req.header("x-secgit-pow").unwrap_or_default();
        if !app.pow.verify(submission, &req.peer_ip) {
            Metrics::inc(&app.metrics.pow_failures_total);
            return Response::text(
                402,
                "Payment Required",
                "proof-of-work required: GET /sandbox/pow-challenge, solve it, and resend with \
                 header 'X-SecGit-PoW: <challenge>:<nonce>'",
            );
        }
    }
    // Rate-limit identity is the TCP peer IP (XFF is attacker-controlled; ADR 0007 forbids
    // a trusted plaintext proxy). Falls back to a constant for local/unknown peers.
    let client_key = if req.peer_ip.is_empty() {
        "local".to_string()
    } else {
        req.peer_ip.clone()
    };
    let mut eph = app.ephemeral.lock().unwrap();
    match eph.create(&client_key) {
        Ok(repo) => {
            Metrics::inc(&app.metrics.ephemeral_created_total);
            if let Err(e) = app.forge.create_bare(&repo.repo_id) {
                return Response::text(500, "Internal Server Error", &format!("create repo: {e}"));
            }
            let _ = app.store.init_repo(&repo.repo_id);
            if let Ok(mut log) = app.audit.lock() {
                let _ = log.append(AuditEvent::RepoCreated {
                    repo_id: repo.repo_id.clone(),
                    owner: "anonymous".into(),
                });
            }
            Response::json(&serde_json::json!({
                "repo_id": repo.repo_id,
                "push_token": repo.push_token,
                "expires_at": repo.expires_at,
                "max_bytes": repo.max_bytes,
                "push_hint": "git remote add secgit http://<host>/<repo_id> && git -c http.extraHeader='Authorization: Bearer <push_token>' push secgit HEAD",
            }))
        }
        Err(e) => Response::text(429, "Too Many Requests", &format!("{e}")),
    }
}

/// Handle the `/ui` "New repository" form: create a persistent repo owned by the
/// authenticated user (v1 repos are always private), then redirect back to the repo list
/// where it now appears.
fn ui_create_repo(app: &App, req: &Request) -> Response {
    let user = {
        let mut identity = app.identity.lock().unwrap();
        match identity.authenticate(req) {
            Some(u) => u,
            None => {
                return Response::text(401, "Unauthorized", "authentication required")
                    .with_header("WWW-Authenticate", "Basic realm=\"secgit\"")
            }
        }
    };
    let name = req.form().get("name").cloned().unwrap_or_default();
    match api::create_named_repo(app, &user, &name, true) {
        Ok(_repo_id) => Response::new(303, "See Other", "text/plain", b"created".to_vec())
            .with_header("Location", "/ui"),
        Err((code, msg)) => Response::text(code, api::status_reason(code), &msg),
    }
}

/// Push-to-create: if `user` is pushing to a not-yet-existing repo in their own namespace
/// (`<username>/<name>`), create a persistent repo owned by them. Returns `Ok(true)` if the
/// repo now exists (created here, or concurrently), `Ok(false)` if the path is not eligible
/// (wrong namespace / bad name) so the caller should 404, or `Err((status, msg))` on a real
/// failure such as an exceeded quota.
fn push_to_create(
    app: &App,
    repo_id: &str,
    user: &str,
) -> std::result::Result<bool, (u16, String)> {
    let username = {
        let id = app.identity.lock().unwrap();
        id.dir
            .get_user(user)
            .map(|u| u.username.clone())
            .unwrap_or_else(|| user.to_string())
    };
    let Some(name) = repo_id.strip_prefix(&format!("{username}/")) else {
        return Ok(false);
    };
    if name.is_empty() || name.contains('/') {
        return Ok(false);
    }
    match api::create_named_repo(app, user, name, true) {
        Ok(_) => Ok(true),
        // Lost a race with a concurrent create — the repo exists now, so proceed.
        Err((409, _)) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Recursively index a repo's HEAD tree into the encrypted search index.
pub(crate) fn index_repo_head(app: &App, repo_id: &str) -> Result<()> {
    let idx = secgit_search::SearchIndex::new(&app.search_store);
    let mut stack = vec![String::new()];
    while let Some(dir) = stack.pop() {
        let entries = app
            .forge
            .list_tree(repo_id, "HEAD", &dir)
            .unwrap_or_default();
        for e in entries {
            let child = if dir.is_empty() {
                e.name.clone()
            } else {
                format!("{dir}/{}", e.name)
            };
            if e.kind == "tree" {
                stack.push(child);
            } else if e.kind == "blob" {
                if let Ok(bytes) = app.forge.read_blob(repo_id, "HEAD", &child) {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        let _ = idx.index_document(repo_id, &child, text);
                    }
                }
            }
        }
    }
    Ok(())
}

/// In-CVM, access-controlled code search across the user's repositories.
fn search_route(app: &App, req: &Request) -> Response {
    let mut identity = app.identity.lock().unwrap();
    let Some(user) = identity.authenticate(req) else {
        return Response::text(401, "Unauthorized", "authentication required")
            .with_header("WWW-Authenticate", "Basic realm=\"secgit\"");
    };
    let query = req.query.get("q").cloned().unwrap_or_default();
    let repo_ids: Vec<String> = identity
        .dir
        .repos_visible_to(&user)
        .iter()
        .map(|r| r.id.clone())
        .collect();
    drop(identity);

    let mut results_html = String::new();
    if !query.trim().is_empty() {
        let idx = secgit_search::SearchIndex::new(&app.search_store);
        let mut hits = vec![];
        for repo_id in &repo_ids {
            // Materialize + index on demand (idempotent re-index keeps it fresh).
            if !app.forge.exists(repo_id) {
                let _ = app.forge.restore_from_store(repo_id, &app.store);
            }
            let _ = index_repo_head(app, repo_id);
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
        if hits.is_empty() {
            results_html = "<p class=\"muted\">No matches.</p>".into();
        } else {
            for h in hits.iter().take(200) {
                results_html.push_str(&format!(
                    "<tr><td><a href=\"/ui/blob?repo={r}&path={p}\">{r}: {p}</a></td>\
                     <td class=\"muted\">L{n}</td><td><code>{snip}</code></td></tr>",
                    r = web::escape(&h.repo_id),
                    p = web::escape(&h.path),
                    n = h.line,
                    snip = web::escape(&h.snippet),
                ));
            }
            results_html = format!("<table class=\"list\">{results_html}</table>");
        }
    }
    let body = format!(
        "<h1>Code search</h1>\
         <form method=\"get\" action=\"/ui/search\">\
         <input name=\"q\" value=\"{q}\" placeholder=\"search your repositories\" size=\"40\"> \
         <button>Search</button></form>{results}",
        q = web::escape(&query),
        results = results_html
    );
    web::page("Search", &body)
}

/// Enforce the per-account Light-tier quota for a push to a user-owned persistent repo.
/// Org-owned (Managed) repos are uncapped. Returns `true` if the push is within quota.
pub(crate) fn quota_check_push(app: &App, repo_id: &str, bytes: u64) -> bool {
    let owner = {
        let id = app.identity.lock().unwrap();
        match id.dir.get_repo(repo_id).map(|r| r.owner.clone()) {
            Some(RepoOwner::User(uid)) => uid,
            _ => return true, // org-owned or unknown -> no Light cap here
        }
    };
    let mut q = app.quota.lock().unwrap();
    if q.ensure_account(&owner, Tier::Light).is_err() {
        return true; // tier disabled -> don't block (sandbox policy decides elsewhere)
    }
    // Ensure the repo is tracked (e.g. created after startup) before accounting.
    if q.repo_bytes(&owner, repo_id).is_none() {
        q.preload(&owner, Tier::Light, repo_id, 0);
    }
    q.account_bytes(&owner, repo_id, bytes).is_ok()
}

/// Route git smart-HTTP requests of the form `/<repo_id>/info/refs` and
/// `/<repo_id>/git-(upload|receive)-pack`.
fn git_route(app: &App, req: &Request) -> Response {
    let path = req.path.trim_start_matches('/');

    let (repo_id, endpoint) = if let Some(r) = path.strip_suffix("/info/refs") {
        (r.to_string(), "info-refs")
    } else if let Some(r) = path.strip_suffix("/git-upload-pack") {
        (r.to_string(), "upload-pack")
    } else if let Some(r) = path.strip_suffix("/git-receive-pack") {
        (r.to_string(), "receive-pack")
    } else {
        return Response::text(404, "Not Found", "not found");
    };

    // Per-IP git-operation rate limit (in addition to the global per-IP request limit).
    if !app.rl.ip_git.check(&req.peer_ip) {
        Metrics::inc(&app.metrics.rate_limited_total);
        return Response::text(429, "Too Many Requests", "git rate limit exceeded")
            .with_header("Retry-After", "1");
    }

    // Determine whether this operation writes (push) so we can require the right role.
    let write = match endpoint {
        "receive-pack" => true,
        "upload-pack" => false,
        // info/refs: the requested service decides read vs write.
        _ => req.query.get("service").map(String::as_str) == Some("git-receive-pack"),
    };

    // Two gates: anonymous ephemeral repos (throwaway token) OR identity-backed repos
    // (authenticated + access-controlled via secgit-identity).
    let is_ephemeral = app.ephemeral.lock().unwrap().is_ephemeral(&repo_id);
    if is_ephemeral {
        let token = req.bearer_token().unwrap_or_default();
        let mut eph = app.ephemeral.lock().unwrap();
        if eph.authorize_push(&repo_id, &token).is_err() {
            return Response::text(401, "Unauthorized", "invalid or expired token");
        }
    } else {
        // Identity-backed repo. Support **push-to-create**: an authenticated user pushing to
        // a not-yet-existing repo in their own namespace (`<username>/<name>`) creates it on
        // the fly, so no UI/API pre-creation step is required.
        if write {
            let (exists, user) = {
                let mut identity = app.identity.lock().unwrap();
                (
                    identity.dir.get_repo(&repo_id).is_some(),
                    identity.authenticate(req),
                )
            };
            if !exists {
                match user {
                    // Prompt for credentials so a client without embedded creds retries with
                    // auth (which then creates the repo). git's first request is anonymous.
                    None => {
                        return Response::text(401, "Unauthorized", "authentication required")
                            .with_header("WWW-Authenticate", "Basic realm=\"secgit\"");
                    }
                    Some(user) => match push_to_create(app, &repo_id, &user) {
                        Ok(true) => {}
                        Ok(false) => return Response::text(404, "Not Found", "unknown repo"),
                        Err((code, msg)) => {
                            return Response::text(code, api::status_reason(code), &msg)
                        }
                    },
                }
            }
        }
        let mut identity = app.identity.lock().unwrap();
        match authz::decide_identity(&mut identity, &repo_id, write, req) {
            authz::Decision::Allow(user) => {
                drop(identity);
                // Per-account operation rate limit for authenticated repo access.
                if !app.rl.account.check(&user) {
                    Metrics::inc(&app.metrics.rate_limited_total);
                    return Response::text(429, "Too Many Requests", "account rate limit exceeded")
                        .with_header("Retry-After", "1");
                }
            }
            authz::Decision::NotFound => return Response::text(404, "Not Found", "unknown repo"),
            authz::Decision::Unauthenticated => {
                return Response::text(401, "Unauthorized", "authentication required")
                    .with_header("WWW-Authenticate", "Basic realm=\"secgit\"");
            }
            authz::Decision::Forbidden => {
                return Response::text(403, "Forbidden", "insufficient access")
            }
        }
    }
    if !app.forge.exists(&repo_id) {
        let _ = app.forge.restore_from_store(&repo_id, &app.store);
    }
    let repo_path = app.forge.repo_path(&repo_id);

    match endpoint {
        "info-refs" => {
            let svc = match req.query.get("service").map(String::as_str) {
                Some(s) => match Service::parse(s) {
                    Ok(s) => s,
                    Err(_) => return Response::text(400, "Bad Request", "bad service"),
                },
                None => return Response::text(400, "Bad Request", "dumb http not supported"),
            };
            match secgit_git::advertise_refs_with_limits(&repo_path, svc, &app.limits.git) {
                Ok(body) => Response::new(200, "OK", &svc.advertise_content_type(), body)
                    .with_header("Cache-Control", "no-cache"),
                Err(e) => Response::text(500, "Internal Server Error", &format!("{e}")),
            }
        }
        "upload-pack" => run_rpc(app, &repo_id, &repo_path, Service::UploadPack, req),
        "receive-pack" => run_rpc(app, &repo_id, &repo_path, Service::ReceivePack, req),
        _ => Response::text(404, "Not Found", "not found"),
    }
}

fn run_rpc(
    app: &App,
    repo_id: &str,
    repo_path: &std::path::Path,
    svc: Service,
    req: &Request,
) -> Response {
    if svc == Service::ReceivePack {
        // Per-repo push rate limit: directly bounds how often the O(repo-size)
        // `seal_to_store` re-bundle can be triggered for a given repo.
        if !app.rl.push.check(repo_id) {
            Metrics::inc(&app.metrics.rate_limited_total);
            return Response::text(429, "Too Many Requests", "push rate limit exceeded")
                .with_header("Retry-After", "2");
        }
        let is_ephemeral = app.ephemeral.lock().unwrap().is_ephemeral(repo_id);
        if is_ephemeral {
            let mut eph = app.ephemeral.lock().unwrap();
            if eph.account_bytes(repo_id, req.body.len() as u64).is_err() {
                Metrics::inc(&app.metrics.push_rejected_total);
                return Response::text(413, "Payload Too Large", "ephemeral size cap exceeded");
            }
        } else if !quota_check_push(app, repo_id, req.body.len() as u64) {
            Metrics::inc(&app.metrics.push_rejected_total);
            return Response::text(413, "Payload Too Large", "account storage cap exceeded");
        }
    }
    match secgit_git::rpc_with_limits(repo_path, svc, &req.body, &app.limits.git) {
        Ok(body) => {
            if svc == Service::ReceivePack {
                // Persist the updated repo encrypted, and record the push. The seal is now
                // incremental (an O(delta) bundle appended as a segment; a periodic
                // compaction folds segments back into a base), but still bound how many can
                // run at once so a burst of pushes cannot exhaust CPU/memory.
                {
                    let _permit = app.seal_sem.acquire();
                    let started = std::time::Instant::now();
                    let _ = app.forge.seal_to_store(repo_id, &app.store);
                    Metrics::inc(&app.metrics.seal_total);
                    Metrics::add(
                        &app.metrics.seal_millis_total,
                        started.elapsed().as_millis() as u64,
                    );
                }
                Metrics::inc(&app.metrics.push_total);
                if let Ok(mut log) = app.audit.lock() {
                    let _ = log.append(AuditEvent::RefUpdated {
                        repo_id: repo_id.to_string(),
                        reference: "(push)".into(),
                        old: String::new(),
                        new: String::new(),
                        actor: "anonymous".into(),
                    });
                }
                // Refresh the search index and fan out a push webhook (best-effort;
                // payload is event metadata only — never file contents).
                let _ = index_repo_head(app, repo_id);
                let _ = events::Events::new(&app.store).deliver(
                    repo_id,
                    "push",
                    &serde_json::json!({ "repo_id": repo_id, "ref": "(push)" }),
                );
            }
            Response::new(200, "OK", &svc.result_content_type(), body)
        }
        Err(secgit_git::GitHttpError::LimitExceeded(msg)) => {
            if svc == Service::ReceivePack {
                Metrics::inc(&app.metrics.push_rejected_total);
            }
            Response::text(
                413,
                "Payload Too Large",
                &format!("git limit exceeded: {msg}"),
            )
        }
        Err(e) => Response::text(500, "Internal Server Error", &format!("{e}")),
    }
}
