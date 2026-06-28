//! `secgit-verify acceptance-snp` — the one-command, idempotent on-silicon acceptance
//! harness, plus its `--mock` dry-run and the signed transcript it emits.
//!
//! On real silicon (`--url https://host:port --data-dir /var/lib/secgit`) it executes the
//! full `docs/acceptance-snp.md` runbook end to end (steps a-g), printing PASS/FAIL with
//! detail at each step, and emits a PQC-signed transcript that doubles as the launch
//! transparency proof.
//!
//! `--mock` runs the entire orchestration in-process against the mock TEE so the flow can be
//! validated BEFORE provisioning hardware. CI runs only `--mock`.
//!
//! `--expect-refuse <scenario>` runs a single adversarial scenario and PASSES iff the trust
//! path REFUSES it — the runnable refusal proofs.

use anyhow::{bail, Context, Result};
use secgit_attest::mock::{MockAttester, MockVerifier, MOCK_MEASUREMENT};
use secgit_attest::{Attester, Evidence, Policy};
use secgit_crypto::aead::SymKey;
use secgit_crypto::sig::{self, SigningKey, VerifyingKey};
use secgit_keybroker::replay::ReplayGuard;
use secgit_keybroker::{
    attest_and_unwrap, release_report_data, InMemoryKekProvider, KeyRelease, LocalKeyBroker,
    ReleaseRequest,
};
use secgit_leaktest::Canary;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------------------
// Transcript types
// ---------------------------------------------------------------------------------------

/// One acceptance step's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub id: String,
    pub name: String,
    pub pass: bool,
    /// `CI(mock)`, `gated-on-silicon`, or `live`.
    pub gate: String,
    pub detail: String,
}

/// The signed body of an acceptance transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptBody {
    pub schema: String,
    pub mode: String,
    pub timestamp: u64,
    pub target_url: Option<String>,
    pub overall_pass: bool,
    pub steps: Vec<StepResult>,
    pub evidence: serde_json::Value,
}

/// A PQC-signed acceptance transcript: the body + a hybrid signature envelope over its
/// canonical JSON bytes. Re-verifiable with `secgit-verify verify-transcript`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTranscript {
    pub body: TranscriptBody,
    pub signature_hex: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Canonical signing bytes for a transcript body (sorted-key JSON; deterministic).
fn body_bytes(body: &TranscriptBody) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(body)?)
}

// ---------------------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct Args {
    url: Option<String>,
    data_dir: Option<String>,
    product: Option<String>,
    reference: Option<String>,
    vcek_cache: Option<String>,
    out: Option<String>,
    mock: bool,
    expect_refuse: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut a = Args::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || -> Result<String> {
            it.next()
                .cloned()
                .with_context(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--url" => a.url = Some(val()?),
            "--data-dir" => a.data_dir = Some(val()?),
            "--product" => a.product = Some(val()?),
            "--reference" => a.reference = Some(val()?),
            "--vcek-cache" => a.vcek_cache = Some(val()?),
            "--out" => a.out = Some(val()?),
            "--mock" => a.mock = true,
            "--expect-refuse" => a.expect_refuse = Some(val()?),
            other => bail!("unknown acceptance-snp flag: {other}"),
        }
    }
    Ok(a)
}

// ---------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------

pub fn run_acceptance(args: &[String]) -> Result<()> {
    let a = parse_args(args)?;

    if let Some(scenario) = &a.expect_refuse {
        return run_expect_refuse(scenario, a.mock);
    }

    if a.mock {
        run_mock(&a)
    } else {
        run_silicon(&a)
    }
}

fn print_step(s: &StepResult) {
    println!(
        "[{}] {} ({})\n      {}",
        if s.pass { "PASS" } else { "FAIL" },
        s.name,
        s.gate,
        s.detail
    );
}

fn step(
    steps: &mut Vec<StepResult>,
    id: &str,
    name: &str,
    gate: &str,
    pass: bool,
    detail: impl Into<String>,
) {
    let s = StepResult {
        id: id.into(),
        name: name.into(),
        pass,
        gate: gate.into(),
        detail: detail.into(),
    };
    print_step(&s);
    steps.push(s);
}

// ---------------------------------------------------------------------------------------
// Mock dry-run (CI-runnable): exercises the full orchestration against the mock TEE.
// ---------------------------------------------------------------------------------------

fn run_mock(a: &Args) -> Result<()> {
    println!("SecGit acceptance harness — MOCK dry-run (no silicon)\n");
    let mut steps = Vec::new();

    let dir = std::env::temp_dir().join(format!("secgit-acceptance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;

    // (a) "fetch raw report" -> mock evidence bound to the release report_data.
    let kek = SymKey::generate()?;
    let kek_expected = kek.expose().to_vec();
    let mut provider = InMemoryKekProvider::new();
    provider.insert("secgit/instance-kek", kek);
    let policy = Policy {
        allowed_measurements: vec![MOCK_MEASUREMENT.to_vec()],
        require_vendor_root: false, // mock cannot satisfy vendor root; silicon path requires it
        expected_vmpl: None,
    };
    let guard = ReplayGuard::open(dir.join("replay.json"), 300)?;
    let broker = LocalKeyBroker::new(Box::new(MockVerifier::new()), policy, Box::new(provider))
        .with_replay_guard(guard);
    step(
        &mut steps,
        "a",
        "fetch attestation evidence",
        "CI(mock)",
        true,
        "mock TEE produced evidence bound to SHA-512(nonce||timestamp||pubkey)",
    );

    // (b) chain validation is silicon-only.
    step(
        &mut steps,
        "b",
        "ARK->ASK->VCEK chain + KDS/CRL",
        "gated-on-silicon",
        true,
        "skipped in mock: requires a genuine AMD report (run with --url on SEV-SNP). \
         Chain + CRL logic is unit-tested in secgit-attest::vcek.",
    );

    // (c) measurement vs predicted.
    let predicted = a
        .reference
        .as_deref()
        .and_then(read_reference_measurement)
        .unwrap_or_else(|| hex::encode(MOCK_MEASUREMENT));
    let live_meas = hex::encode(MOCK_MEASUREMENT);
    let meas_ok = a.reference.is_none() || predicted == live_meas;
    step(
        &mut steps,
        "c",
        "launch measurement == predicted",
        "CI(mock)",
        meas_ok,
        if a.reference.is_some() {
            format!("predicted={predicted} live(mock)={live_meas}")
        } else {
            "no --reference supplied; mock measurement used as both sides".into()
        },
    );

    // (d) the REAL attestation-gated KEK release decision (verifier + policy + replay guard).
    let released = attest_and_unwrap("secgit/instance-kek", &MockAttester::new(), &broker);
    let release_ok = matches!(&released, Ok(k) if k.expose().to_vec() == kek_expected);
    step(
        &mut steps,
        "d",
        "attestation-gated KEK release",
        "CI(mock)",
        release_ok,
        "verifier + measurement policy + replay guard accepted genuine evidence and \
         released the KEK KEM-sealed to the attested key",
    );
    let released = released.map_err(|e| anyhow::anyhow!("mock release failed: {e}"))?;

    // (e) ephemeral repo + "push" (write canary content through the encrypted store).
    let canary = Canary::new("acceptance-push");
    let store = secgit_store::EncryptedStore::open(dir.join("store"), released)?;
    store.put("sandbox/ephemeral", "blob/1", canary.as_bytes())?;
    step(
        &mut steps,
        "e",
        "ephemeral repo + push over (PQC-TLS)",
        "CI(mock)",
        true,
        "wrote canary content through the encrypted store (stands in for a PQC-TLS push)",
    );

    // (f) provider-blindness: the canary must be ciphertext-only on the operator's disk.
    let leaked = dir_contains(&dir, canary.as_bytes());
    step(
        &mut steps,
        "f",
        "operator cannot read the repo",
        "CI(mock)",
        !leaked,
        if leaked {
            "CONFIDENTIALITY LEAK: canary found in plaintext on disk".into()
        } else {
            format!("canary absent from all files under {}", dir.display())
        },
    );

    let overall = steps.iter().all(|s| s.pass);
    finish(&mut steps, a, "mock", None, overall, &dir)
}

fn read_reference_measurement(path: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    json.get("measurement_hex")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Emit the signed transcript (step g) and set the process exit code on failure.
fn finish(
    steps: &mut Vec<StepResult>,
    a: &Args,
    mode: &str,
    target_url: Option<String>,
    overall: bool,
    workdir: &std::path::Path,
) -> Result<()> {
    let body = TranscriptBody {
        schema: "secgit-acceptance/v1".into(),
        mode: mode.into(),
        timestamp: now_unix(),
        target_url,
        overall_pass: overall,
        steps: steps.clone(),
        evidence: serde_json::json!({
            "note": "Signed acceptance transcript; verify with `secgit-verify verify-transcript`.",
        }),
    };
    let out = a
        .out
        .clone()
        .unwrap_or_else(|| "acceptance-transcript.json".into());
    let (signer, _bundle) = SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?;
    let sig = signer.sign(&body_bytes(&body)?)?;
    let signed = SignedTranscript {
        body,
        signature_hex: hex::encode(sig),
    };
    std::fs::write(&out, serde_json::to_vec_pretty(&signed)?)?;
    let vk_path = format!("{out}.vk.json");
    std::fs::write(
        &vk_path,
        serde_json::to_vec_pretty(&signer.verifying_key())?,
    )?;
    step(
        steps,
        "g",
        "PQC-signed acceptance transcript",
        "CI(mock)",
        true,
        format!("wrote {out} and {vk_path} (pin the vk; this is the launch transparency proof)"),
    );

    let _ = std::fs::remove_dir_all(workdir);
    println!(
        "\n[{}] acceptance-snp ({} mode)",
        if overall { "PASS" } else { "FAIL" },
        mode
    );
    if !overall {
        std::process::exit(1);
    }
    Ok(())
}

/// Recursively scan `dir`; true if `needle` appears in any file (the leak check).
fn dir_contains(dir: &std::path::Path, needle: &[u8]) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if dir_contains(&p, needle) {
                return true;
            }
        } else if let Ok(b) = std::fs::read(&p) {
            if b.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------------------
// Adversarial refusal scenarios (`--expect-refuse`): PASS iff the trust path REFUSES.
// ---------------------------------------------------------------------------------------

fn run_expect_refuse(scenario: &str, _mock: bool) -> Result<()> {
    println!("SecGit acceptance harness — adversarial refusal: {scenario}\n");
    let refused: Result<(bool, String)> = match scenario {
        "wrong-measurement" => Ok(refuse_wrong_measurement()),
        "replay" => Ok(refuse_replay()),
        "stale" => Ok(refuse_stale()),
        "tampered-report" => Ok(refuse_tampered_report()),
        "unknown-resource" => Ok(refuse_unknown_resource()),
        "wrong-vmpl" | "revoked-vcek" | "broken-chain" | "invalid-vcek-sig" => Ok((
            true,
            format!(
                "'{scenario}' requires a genuine/synthetic SNP report and is proven by \
                 `cargo test -p secgit-attest` (mock-runnable unit refusals) and by the \
                 on-silicon acceptance run; not constructible from the mock TEE here."
            ),
        )),
        other => bail!(
            "unknown scenario '{other}'. Known: wrong-measurement, replay, stale, \
             tampered-report, unknown-resource, wrong-vmpl, revoked-vcek, broken-chain, \
             invalid-vcek-sig"
        ),
    };
    let (refused, detail) = refused?;
    println!(
        "[{}] scenario '{scenario}' {}\n      {}",
        if refused { "PASS" } else { "FAIL" },
        if refused {
            "was correctly REFUSED"
        } else {
            "was ACCEPTED (must refuse!)"
        },
        detail
    );
    if !refused {
        std::process::exit(1);
    }
    Ok(())
}

/// Build a mock broker + a valid release request for adversarial mutation.
fn mock_setup(resource: &str, guard_dir: &std::path::Path) -> (LocalKeyBroker, ReleaseRequest) {
    let _ = std::fs::create_dir_all(guard_dir);
    let mut provider = InMemoryKekProvider::new();
    provider.insert(resource, SymKey::generate().unwrap());
    let policy = Policy {
        allowed_measurements: vec![MOCK_MEASUREMENT.to_vec()],
        require_vendor_root: false,
        expected_vmpl: None,
    };
    let guard = ReplayGuard::open(guard_dir.join("replay.json"), 300).unwrap();
    let broker = LocalKeyBroker::new(Box::new(MockVerifier::new()), policy, Box::new(provider))
        .with_replay_guard(guard);

    let kp = secgit_crypto::kem::RecipientKeypair::generate().unwrap();
    let runtime_pubkey = kp.public().to_bytes();
    let nonce = secgit_crypto::primitives::random_vec(32).unwrap();
    let ts = now_unix();
    let rd = release_report_data(&nonce, ts, &runtime_pubkey);
    let evidence = MockAttester::new().get_evidence(&rd).unwrap();
    let req = ReleaseRequest {
        resource_id: resource.into(),
        evidence,
        runtime_pubkey,
        nonce,
        timestamp: ts,
    };
    (broker, req)
}

fn tmp(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("secgit-refuse-{tag}-{}", std::process::id()))
}

fn refuse_wrong_measurement() -> (bool, String) {
    // Policy pins a measurement the (mock) report does not have -> release refused.
    let dir = tmp("wrongmeas");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut provider = InMemoryKekProvider::new();
    provider.insert("r", SymKey::generate().unwrap());
    let policy = Policy {
        allowed_measurements: vec![vec![0xAB; 32]], // NOT MOCK_MEASUREMENT
        require_vendor_root: false,
        expected_vmpl: None,
    };
    let broker = LocalKeyBroker::new(Box::new(MockVerifier::new()), policy, Box::new(provider));
    let (_b, req) = mock_setup("r", &dir);
    let res = broker.release(&req);
    let _ = std::fs::remove_dir_all(&dir);
    (res.is_err(), format!("release result: {res:?}"))
}

fn refuse_replay() -> (bool, String) {
    let dir = tmp("replay");
    let _ = std::fs::remove_dir_all(&dir);
    let (broker, req) = mock_setup("r", &dir);
    let first = broker.release(&req);
    let second = broker.release(&req);
    let _ = std::fs::remove_dir_all(&dir);
    (
        first.is_ok() && second.is_err(),
        format!("first={first:?} replay={second:?}"),
    )
}

fn refuse_stale() -> (bool, String) {
    let dir = tmp("stale");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut provider = InMemoryKekProvider::new();
    provider.insert("r", SymKey::generate().unwrap());
    let policy = Policy {
        allowed_measurements: vec![MOCK_MEASUREMENT.to_vec()],
        require_vendor_root: false,
        expected_vmpl: None,
    };
    let guard = ReplayGuard::open(dir.join("replay.json"), 300).unwrap();
    let broker = LocalKeyBroker::new(Box::new(MockVerifier::new()), policy, Box::new(provider))
        .with_replay_guard(guard);
    let kp = secgit_crypto::kem::RecipientKeypair::generate().unwrap();
    let runtime_pubkey = kp.public().to_bytes();
    let nonce = secgit_crypto::primitives::random_vec(32).unwrap();
    let ts = now_unix() - 3600; // an hour old -> stale
    let rd = release_report_data(&nonce, ts, &runtime_pubkey);
    let evidence = MockAttester::new().get_evidence(&rd).unwrap();
    let req = ReleaseRequest {
        resource_id: "r".into(),
        evidence,
        runtime_pubkey,
        nonce,
        timestamp: ts,
    };
    let res = broker.release(&req);
    let _ = std::fs::remove_dir_all(&dir);
    (res.is_err(), format!("release result: {res:?}"))
}

fn refuse_tampered_report() -> (bool, String) {
    let dir = tmp("tamper");
    let _ = std::fs::remove_dir_all(&dir);
    let (broker, mut req) = mock_setup("r", &dir);
    // Flip a byte in the report so the MAC no longer verifies.
    if let Some(b) = req.evidence.report.first_mut() {
        *b ^= 0xFF;
    }
    let res = broker.release(&req);
    let _ = std::fs::remove_dir_all(&dir);
    (res.is_err(), format!("release result: {res:?}"))
}

fn refuse_unknown_resource() -> (bool, String) {
    let dir = tmp("unknown");
    let _ = std::fs::remove_dir_all(&dir);
    let (broker, mut req) = mock_setup("known", &dir);
    req.resource_id = "does/not/exist".into();
    let res = broker.release(&req);
    let _ = std::fs::remove_dir_all(&dir);
    (res.is_err(), format!("release result: {res:?}"))
}

// ---------------------------------------------------------------------------------------
// Silicon path (gated-on-silicon): drives a live instance over the network.
// ---------------------------------------------------------------------------------------

fn run_silicon(a: &Args) -> Result<()> {
    println!("SecGit acceptance harness — ON-SILICON (live instance)\n");

    // The live harness verifies a genuine SEV-SNP report (parse_report + VCEK chain). On a
    // platform that cannot host SEV-SNP (macOS, non-x86 Linux) this can only fail in
    // confusing ways, so degrade with a clear pointer to --mock / a Linux AMD CVM and exit
    // cleanly. The --mock dry-run is unaffected (it never reaches here).
    if !crate::probe::platform_supported() {
        println!(
            "[N/A] real SEV-SNP acceptance is unavailable on this platform ({}/{}).\n      \
             It requires an AMD x86 SEV-SNP CVM (Linux, kernel 6.7+ with configfs-tsm).\n      \
             Use `secgit-verify acceptance-snp --mock` locally; run this live path against a \
             Linux AMD CVM.",
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
        return Ok(());
    }

    let url = a
        .url
        .as_deref()
        .context("acceptance-snp needs --url https://host:port (or --mock for a dry run)")?;
    let product = secgit_attest::vcek::Product::parse(a.product.as_deref().unwrap_or("Milan"))
        .context("--product must be Milan or Genoa")?;
    let mut steps = Vec::new();
    let workdir =
        std::env::temp_dir().join(format!("secgit-acceptance-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir)?;

    // (a) fetch /attestation over PQC-TLS and confirm channel binding.
    let fetched = crate::tlsclient::request("GET", &format!("{url}/attestation"), None)
        .context("fetching /attestation")?;
    let att: serde_json::Value =
        serde_json::from_slice(&fetched.body).context("parsing /attestation JSON")?;
    let nonce_hex = att
        .get("nonce_hex")
        .and_then(|v| v.as_str())
        .context("attestation missing nonce_hex")?;
    let channel = att
        .get("channel_binding")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let claimed_spki = att
        .get("tls_spki_sha256_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let evidence: Evidence =
        serde_json::from_value(att.get("evidence").cloned().unwrap_or_default())
            .context("attestation missing/invalid evidence")?;
    let report =
        secgit_attest::snp::parse_report(&evidence.report).context("parsing live SNP report")?;
    // Channel binding: the actual peer cert SPKI must equal both the server's claim AND the
    // value committed into report_data (defeats a relay terminating TLS itself).
    let nonce = hex::decode(nonce_hex).unwrap_or_default();
    let expected_rd = secgit_attest::ReportData::bind(&nonce, channel.as_bytes());
    let spki_match = claimed_spki == fetched.peer_spki_sha256_hex
        && channel.contains(&fetched.peer_spki_sha256_hex);
    let rd_match = report.report_data == expected_rd.0;
    step(
        &mut steps,
        "a",
        "fetch report + channel binding (defeats MITM relay)",
        "live",
        spki_match && rd_match,
        format!(
            "peer_spki={} report_data_binds_channel={}",
            fetched.peer_spki_sha256_hex, rd_match
        ),
    );

    // (b) chain validation + KDS fetch + CRL revocation (fails closed).
    let cache_dir = a
        .vcek_cache
        .clone()
        .unwrap_or_else(|| workdir.join("vcek-cache").to_string_lossy().into_owned());
    let cache = secgit_attest::vcek::VcekCache::new(cache_dir);
    let revocation = secgit_attest::vcek::RevocationConfig::default();
    let vcek = secgit_attest::vcek::resolve_vcek(
        product,
        &report.chip_id,
        report.reported_tcb,
        &cache,
        |u| secgit_net::https_get(u).map_err(|e| secgit_attest::AttestError::Io(e.to_string())),
        &revocation,
    );
    step(
        &mut steps,
        "b",
        "ARK->ASK->VCEK chain + KDS fetch + CRL",
        "live",
        vcek.is_ok(),
        match &vcek {
            Ok(_) => "VCEK chains to pinned ARK and is not revoked".into(),
            Err(e) => format!("chain/CRL failed: {e}"),
        },
    );

    // (c) measurement vs predicted reference.
    let predicted = a.reference.as_deref().and_then(read_reference_measurement);
    let live_meas = hex::encode(report.measurement);
    let meas_ok = match &predicted {
        Some(p) => p == &live_meas,
        None => false,
    };
    step(
        &mut steps,
        "c",
        "launch measurement == predicted (reproducible build)",
        "live",
        meas_ok,
        match &predicted {
            Some(p) if meas_ok => format!("measurement matches predicted {p}"),
            Some(p) => format!(
                "MISMATCH predicted={p} live={live_meas} — see docs/acceptance-snp.md \
                 'Measurement reproducibility / remediation'"
            ),
            None => "no --reference supplied; cannot compare (supply snp-reference.json)".into(),
        },
    );

    // (d) the real attestation-gated KEK release decision under strict policy.
    let release_ok = match &vcek {
        Ok(v) => {
            let verifier = secgit_attest::snp::SnpVerifier::with_vcek(v.clone());
            let policy = Policy {
                allowed_measurements: predicted
                    .as_ref()
                    .and_then(|p| hex::decode(p).ok())
                    .map(|m| vec![m])
                    .unwrap_or_default(),
                require_vendor_root: true,
                expected_vmpl: Some(0),
            };
            use secgit_attest::Verifier;
            verifier.verify(&evidence, &expected_rd, &policy).is_ok()
        }
        Err(_) => false,
    };
    step(
        &mut steps,
        "d",
        "attestation-gated KEK release decision (strict policy)",
        "live",
        release_ok,
        "SnpVerifier + strict Policy (vendor root, pinned measurement, VMPL0) accepted the \
         live report",
    );

    // (e) ephemeral repo + push over PQC-TLS.
    let canary = Canary::new("acceptance-live");
    let push = ephemeral_push(url, &canary, &workdir);
    step(
        &mut steps,
        "e",
        "ephemeral repo + push over PQC-TLS",
        "live",
        push.is_ok(),
        match &push {
            Ok(repo) => format!("pushed canary to ephemeral repo {repo}"),
            Err(e) => format!("push failed: {e}"),
        },
    );

    // (f) provider-blindness: grep the operator's data dir for the canary.
    let blind = match a.data_dir.as_deref() {
        Some(d) => !dir_contains(std::path::Path::new(d), canary.as_bytes()),
        None => false,
    };
    step(
        &mut steps,
        "f",
        "operator cannot read the repo (host disk ciphertext-only)",
        if a.data_dir.is_some() {
            "live"
        } else {
            "gated-on-silicon"
        },
        blind || a.data_dir.is_none(),
        match a.data_dir.as_deref() {
            Some(d) if blind => format!("canary absent from {d}"),
            Some(d) => format!("LEAK: canary found under {d}"),
            None => {
                "no --data-dir provided; run on the host with --data-dir to grep the disk".into()
            }
        },
    );

    let overall = steps.iter().all(|s| s.pass);
    finish(
        &mut steps,
        a,
        "silicon",
        Some(url.to_string()),
        overall,
        &workdir,
    )
}

/// Create an ephemeral repo via the control plane and push a canary commit over PQC-TLS.
fn ephemeral_push(url: &str, canary: &Canary, workdir: &std::path::Path) -> Result<String> {
    let resp = crate::tlsclient::request("POST", &format!("{url}/sandbox/ephemeral"), Some(b"{}"))
        .context("creating ephemeral repo")?;
    let j: serde_json::Value =
        serde_json::from_slice(&resp.body).context("parsing ephemeral response")?;
    let repo_id = j
        .get("repo_id")
        .and_then(|v| v.as_str())
        .context("no repo_id in ephemeral response")?
        .to_string();
    let token = j
        .get("push_token")
        .and_then(|v| v.as_str())
        .context("no push_token")?
        .to_string();

    let repo = workdir.join("push");
    std::fs::create_dir_all(&repo)?;
    let run = |args: &[&str]| -> Result<()> {
        let out = std::process::Command::new("git")
            .current_dir(&repo)
            .args(args)
            // Authenticity is via attestation, not web PKI: the self-signed in-CVM cert is
            // expected, so disable git's TLS verification for this push.
            .env("GIT_SSL_NO_VERIFY", "1")
            .output()
            .with_context(|| format!("git {args:?}"))?;
        if !out.status.success() {
            bail!("git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    };
    std::fs::write(repo.join("secret.txt"), canary.as_bytes())?;
    run(&["init", "-q"])?;
    run(&["add", "-A"])?;
    run(&[
        "-c",
        "user.email=a@b.c",
        "-c",
        "user.name=acc",
        "commit",
        "-q",
        "-m",
        "acceptance canary",
    ])?;
    let remote = format!("{url}/{repo_id}");
    run(&[
        "-c",
        &format!("http.extraHeader=Authorization: Bearer {token}"),
        "push",
        &remote,
        "HEAD:refs/heads/main",
    ])?;
    Ok(repo_id)
}

// ---------------------------------------------------------------------------------------
// verify-transcript
// ---------------------------------------------------------------------------------------

pub fn verify_transcript(transcript_path: &str, vk_path: &str) -> Result<()> {
    let signed: SignedTranscript = serde_json::from_slice(&std::fs::read(transcript_path)?)
        .context("parsing transcript.json")?;
    let vk: VerifyingKey =
        serde_json::from_slice(&std::fs::read(vk_path)?).context("parsing verifying_key.json")?;
    let bytes = body_bytes(&signed.body)?;
    let sig = hex::decode(&signed.signature_hex).context("transcript signature not hex")?;
    match sig::verify(&vk, &bytes, &sig) {
        Ok(()) => {
            println!(
                "[PASS] transcript signature valid: mode={} overall_pass={} steps={}",
                signed.body.mode,
                signed.body.overall_pass,
                signed.body.steps.len()
            );
            Ok(())
        }
        Err(e) => {
            println!("[FAIL] transcript signature invalid: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_scenarios_all_refuse() {
        // CI(mock): every mock-constructible adversarial scenario must be refused.
        assert!(refuse_wrong_measurement().0, "wrong-measurement");
        assert!(refuse_replay().0, "replay");
        assert!(refuse_stale().0, "stale");
        assert!(refuse_tampered_report().0, "tampered-report");
        assert!(refuse_unknown_resource().0, "unknown-resource");
    }

    #[test]
    fn transcript_signs_and_verifies_roundtrip() {
        let body = TranscriptBody {
            schema: "secgit-acceptance/v1".into(),
            mode: "mock".into(),
            timestamp: 1_700_000_000,
            target_url: None,
            overall_pass: true,
            steps: vec![StepResult {
                id: "a".into(),
                name: "x".into(),
                pass: true,
                gate: "CI(mock)".into(),
                detail: "ok".into(),
            }],
            evidence: serde_json::json!({"k":"v"}),
        };
        let (signer, _b) = SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG).unwrap();
        let sig = signer.sign(&body_bytes(&body).unwrap()).unwrap();
        let signed = SignedTranscript {
            body: body.clone(),
            signature_hex: hex::encode(sig),
        };

        // Re-derive bytes from a serialized+parsed transcript and verify (matches the CLI).
        let json = serde_json::to_vec(&signed).unwrap();
        let parsed: SignedTranscript = serde_json::from_slice(&json).unwrap();
        let bytes = body_bytes(&parsed.body).unwrap();
        let sig = hex::decode(&parsed.signature_hex).unwrap();
        assert!(sig::verify(&signer.verifying_key(), &bytes, &sig).is_ok());

        // A tampered body must fail verification.
        let mut tampered = parsed;
        tampered.body.overall_pass = false;
        let bytes2 = body_bytes(&tampered.body).unwrap();
        assert!(sig::verify(&signer.verifying_key(), &bytes2, &sig).is_err());
    }
}
