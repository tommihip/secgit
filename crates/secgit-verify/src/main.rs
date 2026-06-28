//! `secgit-verify` — the standalone tool a *user* runs to check SecGit's claims for
//! themselves, without trusting the operator.
//!
//! Subcommands:
//! - `selftest` — runs the full M1 vertical slice in-process against the mock TEE:
//!   attestation-gated KEK release -> encrypted store -> PQC-signed audit log. This is
//!   the runnable demonstration that the confidentiality machinery actually composes.
//! - `verify-checkpoint <checkpoint.json> <verifying_key.json>` — verifies a
//!   transparency-log signed tree head (PQC signature) the way a relying party would.
//!
//! On real silicon the attestation step is swapped for the SEV-SNP backend; the trust
//! decisions (report_data binding, vendor-root, measurement policy) are identical.

mod acceptance;
mod probe;
mod tlsclient;

use anyhow::{bail, Context, Result};
use secgit_attest::mock::{MockAttester, MockVerifier};
use secgit_attest::Policy;
use secgit_audit::{Checkpoint, TransparencyLog};
use secgit_crypto::aead::SymKey;
use secgit_crypto::sig::VerifyingKey;
use secgit_keybroker::{attest_and_unwrap, InMemoryKekProvider, LocalKeyBroker};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("selftest") => selftest(),
        Some("verify-checkpoint") => {
            let cp = args
                .get(2)
                .context("usage: verify-checkpoint <checkpoint.json> <vk.json>")?;
            let vk = args
                .get(3)
                .context("usage: verify-checkpoint <checkpoint.json> <vk.json>")?;
            verify_checkpoint(cp, vk)
        }
        Some("probe-snp") => {
            let verdict = probe::run()?;
            // Pass and NotApplicable (wrong platform, e.g. macOS) are non-failure exits;
            // only a genuine unusable-host verdict on SNP-capable hardware is an error.
            if !verdict.is_ok_exit() {
                std::process::exit(1);
            }
            Ok(())
        }
        Some("acceptance-snp") => acceptance::run_acceptance(&args[2..]),
        Some("verify-transcript") => {
            let t = args
                .get(2)
                .context("usage: verify-transcript <transcript.json> <vk.json>")?;
            let vk = args
                .get(3)
                .context("usage: verify-transcript <transcript.json> <vk.json>")?;
            acceptance::verify_transcript(t, vk)
        }
        _ => {
            eprintln!("secgit-verify <command>");
            eprintln!("  selftest");
            eprintln!("  verify-checkpoint <checkpoint.json> <verifying_key.json>");
            eprintln!("  probe-snp");
            eprintln!("  acceptance-snp [--url U] [--data-dir D] [--product Milan|Genoa]");
            eprintln!("                 [--reference snp-reference.json] [--vcek-cache DIR]");
            eprintln!("                 [--out acceptance-transcript.json] [--mock]");
            eprintln!("                 [--expect-refuse SCENARIO]");
            eprintln!("  verify-transcript <transcript.json> <verifying_key.json>");
            std::process::exit(2);
        }
    }
}

fn step(ok: bool, msg: &str) -> Result<()> {
    println!("[{}] {}", if ok { "PASS" } else { "FAIL" }, msg);
    if !ok {
        bail!("step failed: {msg}");
    }
    Ok(())
}

fn selftest() -> Result<()> {
    println!("SecGit vertical-slice self-test (mock TEE)\n");

    // 1. Attestation-gated KEK release.
    let kek = SymKey::generate()?;
    let kek_expected = kek.expose().to_vec();
    let mut provider = InMemoryKekProvider::new();
    provider.insert("demo/repo", kek);
    let broker = LocalKeyBroker::new(
        Box::new(MockVerifier::new()),
        Policy::dev_permissive(),
        Box::new(provider),
    );
    let released = attest_and_unwrap("demo/repo", &MockAttester::new(), &broker)?;
    step(
        released.expose().to_vec() == kek_expected,
        "attested KEK released into TEE matches",
    )?;

    let unknown = attest_and_unwrap("does/not/exist", &MockAttester::new(), &broker);
    step(unknown.is_err(), "unknown resource is denied by the broker")?;

    // 2. Encrypted store unlocked by the released KEK.
    let dir = std::env::temp_dir().join(format!("secgit-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = secgit_store::EncryptedStore::open(&dir, released)?;
    let secret = b"my private repo contents";
    store.put("demo/repo", "blob/1", secret)?;
    let got = store.get("demo/repo", "blob/1")?;
    step(
        got.as_deref() == Some(secret.as_slice()),
        "round-trips through encrypted store",
    )?;

    let mut plaintext_on_disk = false;
    for f in walk(&dir) {
        if let Ok(b) = std::fs::read(&f) {
            if b.windows(secret.len()).any(|w| w == secret) {
                plaintext_on_disk = true;
            }
        }
    }
    step(
        !plaintext_on_disk,
        "no plaintext written to disk (provider-blind at rest)",
    )?;

    // 3. PQC-signed transparency log.
    let log_path = dir.join("audit.log");
    let signer =
        secgit_crypto::sig::SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?.0;
    let mut log = TransparencyLog::open(&log_path, "secgit-selftest", signer)?;
    log.append(secgit_audit::AuditEvent::KeyReleased {
        resource_id: "demo/repo".into(),
        measurement_hex: hex::encode(secgit_attest::mock::MOCK_MEASUREMENT),
    })?;
    log.append(secgit_audit::AuditEvent::RefUpdated {
        repo_id: "demo/repo".into(),
        reference: "refs/heads/main".into(),
        old: "0".repeat(40),
        new: "a".repeat(40),
        actor: "anonymous".into(),
    })?;
    let cp = log.checkpoint()?;
    step(
        cp.verify(&log.verifying_key()).is_ok(),
        "audit checkpoint PQC signature verifies",
    )?;

    let (leaf, proof) = log.inclusion_proof(0).context("inclusion proof")?;
    let included = secgit_audit::merkle::verify_inclusion(&leaf, 0, log.len(), &proof, &log.root());
    step(
        included,
        "audit inclusion proof verifies against the signed root",
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    println!("\nAll checks passed. The confidentiality machinery composes end-to-end.");
    Ok(())
}

fn verify_checkpoint(cp_path: &str, vk_path: &str) -> Result<()> {
    let cp: Checkpoint =
        serde_json::from_slice(&std::fs::read(cp_path)?).context("parsing checkpoint.json")?;
    let vk: VerifyingKey =
        serde_json::from_slice(&std::fs::read(vk_path)?).context("parsing verifying_key.json")?;
    match cp.verify(&vk) {
        Ok(()) => {
            println!(
                "[PASS] checkpoint signature valid: log={} size={} root={}",
                cp.log_id,
                cp.tree_size,
                hex::encode(cp.root_hash)
            );
            Ok(())
        }
        Err(e) => {
            println!("[FAIL] checkpoint signature invalid: {e}");
            std::process::exit(1);
        }
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}
