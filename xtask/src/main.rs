//! `xtask` — reproducible-build and image-transparency tooling.
//!
//! The verifiability claim ("the running image == the audited OSS build") rests on:
//!   1. a **reproducible build** (pinned toolchain, `SOURCE_DATE_EPOCH`, no embedded
//!      timestamps/paths) so anyone rebuilding from source gets byte-identical
//!      artifacts;
//!   2. a deterministic **measurement** of the guest launch context that ends up in
//!      the attestation report's `MEASUREMENT` field;
//!   3. publishing that measurement to a **transparency log** so a verifier can check
//!      the attested measurement against the published OSS-build value.
//!
//! `[VERIFY]` The real SEV-SNP launch measurement is SHA-384 over the VM launch
//! context (firmware/OVMF + kernel + initrd + cmdline), produced by tooling such as
//! `sev-snp-measure`. This `xtask` computes deterministic content digests of build
//! artifacts and manages the manifest + transparency emission around them; wiring the
//! exact launch-context measurement is an M5 task on real silicon.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ImageManifest {
    artifacts: Vec<ArtifactDigest>,
    source_date_epoch: Option<String>,
    note: String,
}

#[derive(Serialize, Deserialize)]
struct ArtifactDigest {
    path: String,
    sha384_hex: String,
    len: u64,
}

/// The launch-context inputs whose SHA-384 fold IS the SEV-SNP `MEASUREMENT`.
#[derive(Default, Serialize, Deserialize)]
struct SnpMeasureParams {
    ovmf: String,
    kernel: Option<String>,
    initrd: Option<String>,
    append: Option<String>,
    vcpus: Option<u32>,
    vcpu_type: Option<String>,
    /// How the guest is launched, recorded so the predicted side matches the launcher.
    /// e.g. `sev-snp-measure-direct-boot` (OVMF + kernel-hashes) vs an IGVM path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vmm_launch_method: Option<String>,
    /// Path to the pinned OVMF firmware provenance (`deploy/guest/ovmf.pin.json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ovmf_pin: Option<String>,
    /// The launch-input artifacts, each with its pinned SHA-384. `snp-measure` recomputes
    /// these from the files on disk and refuses to emit a reference on any mismatch, so the
    /// measurement is bound to the exact bytes (not an abstract path).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    expected_artifacts: Vec<ExpectedArtifact>,
}

/// A pinned launch-input artifact (OVMF / UKI / kernel / initrd) with its expected digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpectedArtifact {
    role: String,
    path: String,
    sha384_hex: String,
}

/// A published, transparency-logged reference launch measurement that the verifier pins
/// into `Policy.allowed_measurements`. Commit-bound: it names the exact source revision and
/// the recomputed digests of every launch input, so a third party can rebuild from that
/// commit and confirm the reference themselves.
#[derive(Serialize, Deserialize)]
struct SnpReference {
    measurement_hex: String,
    mode: String,
    params: SnpMeasureParams,
    tool: String,
    note: String,
    /// The source git commit the reference was produced from (`git rev-parse HEAD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    git_commit: Option<String>,
    /// The launcher method this measurement corresponds to (mirrors `params`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vmm_launch_method: Option<String>,
    /// Recomputed digests of the launch inputs that were present on disk at reference time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    launch_artifacts: Vec<ArtifactDigest>,
}

/// Crates whose presence in the dependency graph would contradict the "no AI training"
/// invariant (ML/inference/training frameworks, embedding/vector clients, outbound LLM
/// API clients) or open a plaintext/metadata exfiltration channel (telemetry SDKs).
/// Kept in sync with `deny.toml`; this check also runs when cargo-deny is unavailable.
/// See `docs/no-ai-training.md`.
const FORBIDDEN_ML_TELEMETRY: &[&str] = &[
    "tch",
    "torch-sys",
    "tensorflow",
    "tensorflow-sys",
    "onnxruntime",
    "onnxruntime-sys",
    "ort",
    "candle-core",
    "candle-nn",
    "candle-transformers",
    "llm",
    "llama-cpp-2",
    "llama_cpp",
    "burn",
    "dfdx",
    "linfa",
    "smartcore",
    "rust-bert",
    "tokenizers",
    "tiktoken-rs",
    "openai-api-rs",
    "async-openai",
    "qdrant-client",
    "pinecone-sdk",
    "sentry",
    "opentelemetry-otlp",
    "segment",
];

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("measure") => measure(&args[2..]),
        Some("emit-transparency") => emit_transparency(&args[2..]),
        Some("verify-image") => verify_image(&args[2..]),
        Some("egress-check") => egress_check("Cargo.lock"),
        Some("sbom") => sbom(&args[2..]),
        Some("snp-measure") => snp_measure(&args[2..]),
        Some("provenance") => provenance(&args[2..]),
        Some("provenance-keygen") => provenance_keygen(&args[2..]),
        _ => {
            eprintln!("xtask <command>");
            eprintln!("  measure <artifact>...                     -> writes image-manifest.json");
            eprintln!("  emit-transparency <manifest.json> <log>   -> append to PQC-signed log");
            eprintln!("  verify-image <manifest.json> <sha384_hex> -> check an artifact digest");
            eprintln!("  egress-check                              -> no ML/telemetry deps (no-ai-training)");
            eprintln!("  sbom [Cargo.lock] [out.json]              -> CycloneDX SBOM for image transparency");
            eprintln!(
                "  snp-measure [--inputs snp-inputs.json] [--ovmf f --kernel f --initrd f --append s --vcpus n --vcpu-type t]"
            );
            eprintln!("              [--measurement HEX] [--image-manifest image-manifest.json] [--log path] [--out snp-reference.json]");
            eprintln!("                                            -> compute/record a commit-bound SNP launch measurement");
            eprintln!(
                "  provenance --reference snp-reference.json [--image-manifest m.json] [--sbom sbom.json]"
            );
            eprintln!(
                "             [--oci-image-digest sha256:HEX] [--out provenance.json] [--log path]"
            );
            eprintln!("                                            -> PQC-sign an in-toto/SLSA provenance statement");
            eprintln!(
                "  provenance-keygen [--bundle-out f] [--vk-out deploy/provenance.vk.json] [--force]"
            );
            eprintln!("                                            -> offline ceremony: long-lived hybrid PQC signing key + published vk");
            std::process::exit(2);
        }
    }
}

/// An in-toto Statement subject: a named artifact and its content digest(s). Digest keys are
/// algorithm names (`sha256`/`sha384`) mapping to lowercase hex, per the in-toto spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Subject {
    name: String,
    digest: std::collections::BTreeMap<String, String>,
}

/// The SecGit build predicate: the facts that let a verifier tie the published artifact set to
/// the reproducible OSS build and the attestable CVM launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvenancePredicate {
    build_type: String,
    builder_id: String,
    snp_measurement_hex: String,
    vmm_launch_method: String,
    git_commit: String,
    source_date_epoch: String,
}

/// A minimal in-toto v1 Statement over the SecGit artifact set. Signed with the long-lived
/// hybrid PQC key; the canonical signed bytes are `serde_json::to_vec(&Statement)` (compact,
/// struct-field order), so a verifier reconstructs them by parsing and re-serializing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvenanceStatement {
    #[serde(rename = "_type")]
    type_: String,
    predicate_type: String,
    subject: Vec<Subject>,
    predicate: ProvenancePredicate,
}

fn digest_map(alg: &str, hex_val: &str) -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(alg.to_string(), hex_val.to_lowercase());
    m
}

/// PQC-sign an in-toto/SLSA-style provenance statement binding the OCI image, the guest launch
/// artifacts (OVMF + UKI), the SBOM, and the predicted SNP measurement to a git commit. No
/// external transparency service (no sigstore/Fulcio/Rekor): the signature is our hybrid PQC
/// signature and the statement is (optionally) anchored in OUR transparency log.
fn provenance(args: &[String]) -> Result<()> {
    let mut reference_path: Option<String> = None;
    let mut image_manifest_path: Option<String> = None;
    let mut sbom_path: Option<String> = None;
    let mut oci_image_digest: Option<String> = None;
    let mut out = "provenance.json".to_string();
    let mut log_path: Option<String> = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || -> Result<String> {
            it.next()
                .cloned()
                .with_context(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--reference" => reference_path = Some(val()?),
            "--image-manifest" => image_manifest_path = Some(val()?),
            "--sbom" => sbom_path = Some(val()?),
            "--oci-image-digest" => oci_image_digest = Some(val()?),
            "--out" => out = val()?,
            "--log" => log_path = Some(val()?),
            other => bail!("unknown provenance flag: {other}"),
        }
    }

    let reference_path = reference_path
        .context("provenance requires --reference snp-reference.json (from snp-measure)")?;
    let reference: SnpReference = serde_json::from_slice(
        &std::fs::read(&reference_path).with_context(|| format!("reading {reference_path}"))?,
    )
    .with_context(|| format!("parsing {reference_path}"))?;

    let mut subjects: Vec<Subject> = Vec::new();

    // OCI image digest (sha256), if the caller captured it from `docker build`/buildx.
    if let Some(d) = &oci_image_digest {
        let hexpart = d.strip_prefix("sha256:").unwrap_or(d);
        subjects.push(Subject {
            name: "oci-image".into(),
            digest: digest_map("sha256", hexpart),
        });
    }

    // Guest launch artifacts (OVMF + UKI) come straight from the commit-bound reference, so
    // the provenance and the measurement pin the exact same bytes.
    for a in &reference.launch_artifacts {
        let name = std::path::Path::new(&a.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&a.path)
            .to_string();
        subjects.push(Subject {
            name,
            digest: digest_map("sha384", &a.sha384_hex),
        });
    }

    // Binary digests from the image manifest (secgit-server / secgit-verify).
    if let Some(path) = &image_manifest_path {
        let manifest: ImageManifest = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {path}"))?,
        )
        .with_context(|| format!("parsing {path}"))?;
        for a in &manifest.artifacts {
            let name = std::path::Path::new(&a.path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&a.path)
                .to_string();
            subjects.push(Subject {
                name,
                digest: digest_map("sha384", &a.sha384_hex),
            });
        }
    }

    // SBOM digest (recomputed from the file), so the published bill of materials is bound too.
    if let Some(path) = &sbom_path {
        let (sha, _len) = sha384_file(path)?;
        subjects.push(Subject {
            name: "sbom.json".into(),
            digest: digest_map("sha384", &sha),
        });
    }

    if subjects.is_empty() {
        bail!("no subjects to attest — the reference has no launch_artifacts and no --image-manifest/--sbom/--oci-image-digest was given");
    }

    let predicate = ProvenancePredicate {
        build_type: "https://secgit.dev/reproducible-oci-cvm/v1".into(),
        builder_id: "secgit-xtask".into(),
        snp_measurement_hex: reference.measurement_hex.to_lowercase(),
        vmm_launch_method: reference
            .vmm_launch_method
            .clone()
            .unwrap_or_else(|| "sev-snp-measure-direct-boot".into()),
        git_commit: reference
            .git_commit
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        source_date_epoch: std::env::var("SOURCE_DATE_EPOCH").unwrap_or_default(),
    };

    let statement = ProvenanceStatement {
        type_: "https://in-toto.io/Statement/v1".into(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        subject: subjects,
        predicate,
    };

    // Canonical signed bytes = compact serialization (stable field order); the human-readable
    // file is pretty-printed but the signature is over the compact form.
    let canonical = serde_json::to_vec(&statement).context("serializing provenance statement")?;

    // Sign with the long-lived hybrid PQC parameter set. Production releases pin a persistent
    // key via SECGIT_PROVENANCE_KEY (a SigningKeyBundle JSON); otherwise an ephemeral key is
    // generated and its verifying key published alongside the statement.
    let signer = match std::env::var("SECGIT_PROVENANCE_KEY") {
        Ok(p) => {
            let bundle: secgit_crypto::sig::SigningKeyBundle =
                serde_json::from_slice(&std::fs::read(&p).with_context(|| format!("reading {p}"))?)
                    .with_context(|| format!("parsing signing bundle {p}"))?;
            secgit_crypto::sig::SigningKey::from_bundle(&bundle)?
        }
        Err(_) => {
            eprintln!(
                "[NOTE] SECGIT_PROVENANCE_KEY unset: using an EPHEMERAL provenance key. For a \
                 release, run `xtask provenance-keygen` once (offline), then set \
                 SECGIT_PROVENANCE_KEY=<bundle> so the signature matches the published \
                 deploy/provenance.vk.json."
            );
            secgit_crypto::sig::SigningKey::generate(secgit_crypto::LONG_LIVED_SIG)?
        }
    };
    let sig = signer.sign(&canonical)?;

    std::fs::write(&out, serde_json::to_vec_pretty(&statement)?)
        .with_context(|| format!("writing {out}"))?;
    let sig_path = format!("{out}.sig");
    std::fs::write(&sig_path, hex::encode(&sig))?;
    let vk_path = format!("{out}.vk.json");
    std::fs::write(
        &vk_path,
        serde_json::to_vec_pretty(&signer.verifying_key())?,
    )?;

    println!(
        "wrote {out} ({} subject(s)), {sig_path} (hybrid PQC signature), {vk_path}",
        statement.subject.len()
    );
    println!(
        "  measurement={} commit={}",
        statement.predicate.snp_measurement_hex, statement.predicate.git_commit
    );
    println!("verify with: secgit-verify verify-provenance {out} {sig_path} {vk_path}");

    // Anchor the provenance in our own PQC-signed transparency log (auditable, no external
    // service). The entry binds commit -> measurement, same as snp-measure's reference entry.
    if let Some(log) = log_path {
        append_transparency(
            &log,
            "secgit-provenance",
            format!(
                "provenance measurement={} commit={} subjects={}",
                statement.predicate.snp_measurement_hex,
                statement.predicate.git_commit,
                statement.subject.len()
            ),
            "ci-reproducible-build",
        )?;
    }
    Ok(())
}

/// Offline provenance signing-key ceremony.
///
/// Generates the long-lived hybrid PQC signing key ONCE and splits it: the PRIVATE bundle
/// (`--bundle-out`, default `provenance-signing-key.json`) is what a release feeds back in via
/// `SECGIT_PROVENANCE_KEY` and MUST be moved offline / into an HSM and never committed; the
/// PUBLIC verifying key (`--vk-out`, default `deploy/provenance.vk.json`) is committed and
/// published so any verifier can check a release's `provenance.json` without trusting us.
fn provenance_keygen(args: &[String]) -> Result<()> {
    let mut bundle_out = "provenance-signing-key.json".to_string();
    let mut vk_out = "deploy/provenance.vk.json".to_string();
    let mut force = false;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || -> Result<String> {
            it.next()
                .cloned()
                .with_context(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--bundle-out" => bundle_out = val()?,
            "--vk-out" => vk_out = val()?,
            "--force" => force = true,
            other => bail!("unknown provenance-keygen flag: {other}"),
        }
    }

    if std::path::Path::new(&bundle_out).exists() && !force {
        bail!("{bundle_out} exists; refusing to overwrite an existing signing key (pass --force)");
    }

    let (signer, bundle) =
        secgit_crypto::sig::SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?;

    // Private material: write with restrictive permissions on Unix.
    std::fs::write(&bundle_out, serde_json::to_vec_pretty(&bundle)?)
        .with_context(|| format!("writing {bundle_out}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bundle_out, std::fs::Permissions::from_mode(0o600));
    }

    if let Some(parent) = std::path::Path::new(&vk_out).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&vk_out, serde_json::to_vec_pretty(&signer.verifying_key())?)
        .with_context(|| format!("writing {vk_out}"))?;

    println!("wrote PRIVATE signing bundle -> {bundle_out}");
    println!("  MOVE THIS OFFLINE (HSM / air-gapped vault). NEVER commit it. Anyone with it can");
    println!("  forge SecGit release provenance.");
    println!(
        "wrote PUBLIC verifying key   -> {vk_out}  (commit + publish; verifiers default to it)"
    );
    println!(
        "release signing: export SECGIT_PROVENANCE_KEY={bundle_out} before `xtask provenance`"
    );
    Ok(())
}

/// Parse the `name = "..."` entries from a Cargo.lock.
fn locked_package_names(lock_path: &str) -> Result<Vec<String>> {
    let content =
        std::fs::read_to_string(lock_path).with_context(|| format!("reading {lock_path}"))?;
    let mut names = Vec::new();
    for line in content.lines() {
        if let Some(rest) = line.trim().strip_prefix("name = ") {
            names.push(rest.trim().trim_matches('"').to_string());
        }
    }
    Ok(names)
}

/// Fail if any forbidden ML/telemetry crate is present in the locked dependency graph.
fn egress_check(lock_path: &str) -> Result<()> {
    let names = locked_package_names(lock_path)?;
    let hits: Vec<&str> = FORBIDDEN_ML_TELEMETRY
        .iter()
        .copied()
        .filter(|f| names.iter().any(|n| n == f))
        .collect();
    if hits.is_empty() {
        println!(
            "[PASS] no-ai-training egress-check: none of {} forbidden ML/telemetry crates present ({} deps scanned)",
            FORBIDDEN_ML_TELEMETRY.len(),
            names.len()
        );
        Ok(())
    } else {
        bail!(
            "no-ai-training egress-check FAILED: forbidden crate(s) in dependency graph: {}",
            hits.join(", ")
        );
    }
}

fn sha384_file(path: &str) -> Result<(String, u64)> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let digest = secgit_crypto::primitives::sha384(&bytes);
    Ok((hex::encode(digest), bytes.len() as u64))
}

fn measure(paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        bail!("measure needs at least one artifact path");
    }
    let mut artifacts = vec![];
    for p in paths {
        let (sha, len) = sha384_file(p)?;
        println!("{sha}  {p}");
        artifacts.push(ArtifactDigest {
            path: p.clone(),
            sha384_hex: sha,
            len,
        });
    }
    let manifest = ImageManifest {
        artifacts,
        source_date_epoch: std::env::var("SOURCE_DATE_EPOCH").ok(),
        note: "Deterministic content digests; real SNP MEASUREMENT via sev-snp-measure over launch context.".into(),
    };
    std::fs::write("image-manifest.json", serde_json::to_vec_pretty(&manifest)?)?;
    println!("wrote image-manifest.json");
    Ok(())
}

fn emit_transparency(args: &[String]) -> Result<()> {
    let manifest_path = args
        .first()
        .context("usage: emit-transparency <manifest.json> <log>")?;
    let log_path = args
        .get(1)
        .context("usage: emit-transparency <manifest.json> <log>")?;
    let manifest: ImageManifest =
        serde_json::from_slice(&std::fs::read(manifest_path)?).context("parsing manifest")?;

    // Sign image-transparency entries with the long-lived PQC parameter set.
    let signer =
        secgit_crypto::sig::SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?.0;
    let mut log =
        secgit_audit::TransparencyLog::open(log_path, "secgit-image-transparency", signer)?;
    for a in &manifest.artifacts {
        log.append(secgit_audit::AuditEvent::Admin {
            action: format!("image-artifact {} sha384={}", a.path, a.sha384_hex),
            actor: "ci-reproducible-build".into(),
        })?;
    }
    let cp = log.checkpoint()?;
    println!(
        "appended {} artifact(s); checkpoint size={} root={}",
        manifest.artifacts.len(),
        cp.tree_size,
        hex::encode(cp.root_hash)
    );
    std::fs::write(
        "image-transparency-vk.json",
        serde_json::to_vec_pretty(&log.verifying_key())?,
    )?;
    println!("wrote image-transparency-vk.json (pin this to verify checkpoints)");
    Ok(())
}

/// Build the `sev-snp-measure` argument vector from launch params (pure; unit-tested).
fn build_sev_snp_measure_args(p: &SnpMeasureParams) -> Result<Vec<String>> {
    if p.ovmf.is_empty() {
        bail!("snp-measure requires --ovmf <firmware> (or use --measurement <hex>)");
    }
    let mut a = vec![
        "--mode".into(),
        "snp".into(),
        "--output-format".into(),
        "hex".into(),
        "--ovmf".into(),
        p.ovmf.clone(),
    ];
    if let Some(v) = p.vcpus {
        a.push("--vcpus".into());
        a.push(v.to_string());
    }
    if let Some(t) = &p.vcpu_type {
        a.push("--vcpu-type".into());
        a.push(t.clone());
    }
    if let Some(k) = &p.kernel {
        a.push("--kernel".into());
        a.push(k.clone());
    }
    if let Some(i) = &p.initrd {
        a.push("--initrd".into());
        a.push(i.clone());
    }
    if let Some(s) = &p.append {
        a.push("--append".into());
        a.push(s.clone());
    }
    Ok(a)
}

/// Run the canonical `sev-snp-measure` tool and return the measurement hex.
fn run_sev_snp_measure(p: &SnpMeasureParams) -> Result<String> {
    let args = build_sev_snp_measure_args(p)?;
    let out = std::process::Command::new("sev-snp-measure")
        .args(&args)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "could not run `sev-snp-measure` ({e}). Install it (`pip install sev-snp-measure`) \
                 or pass a known value with --measurement <hex>."
            )
        })?;
    if !out.status.success() {
        bail!(
            "sev-snp-measure failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Validate a 48-byte (SHA-384) measurement in hex.
fn validate_measurement_hex(m: &str) -> Result<()> {
    let bytes = hex::decode(m).map_err(|_| anyhow::anyhow!("measurement is not valid hex"))?;
    if bytes.len() != 48 {
        bail!(
            "SNP measurement must be 48 bytes (SHA-384), got {}",
            bytes.len()
        );
    }
    Ok(())
}

/// The source revision this reference is built from. Best-effort: `None` outside a git
/// checkout (e.g. an unpacked source tarball), which is recorded honestly rather than faked.
fn git_commit() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// A digest field still carrying its scaffold placeholder (not yet pinned to real bytes).
fn is_placeholder_digest(h: &str) -> bool {
    h.is_empty() || h.to_ascii_uppercase().starts_with("REPLACE")
}

/// Recompute the SHA-384 of every declared launch input and bind it:
///   - if the descriptor pins a real digest, the file MUST match it (fail-closed);
///   - if an `image-manifest.json` is supplied, any overlapping path MUST agree with it;
///   - missing files (guest image not built yet) and unpinned placeholders are skipped with
///     a loud NOTE so a partial/scaffold reference is never mistaken for a bound one.
///
/// Returns the digests actually computed (present files), for embedding in the reference.
fn verify_and_collect_artifacts(
    params: &SnpMeasureParams,
    manifest: Option<&ImageManifest>,
) -> Result<Vec<ArtifactDigest>> {
    let mut collected = vec![];
    for ea in &params.expected_artifacts {
        if !std::path::Path::new(&ea.path).exists() {
            eprintln!(
                "[NOTE] launch artifact '{}' ({}) not present on disk — skipping digest bind \
                 (expected until the guest image is assembled in M7).",
                ea.role, ea.path
            );
            continue;
        }
        let (sha, len) = sha384_file(&ea.path)?;
        if is_placeholder_digest(&ea.sha384_hex) {
            eprintln!(
                "[NOTE] launch artifact '{}' has an UNPINNED digest in the descriptor; \
                 recording computed sha384={sha}. Pin it to make the reference tamper-evident.",
                ea.role
            );
        } else if !ea.sha384_hex.eq_ignore_ascii_case(&sha) {
            bail!(
                "launch artifact '{}' ({}) sha384 MISMATCH: descriptor pins {}, file is {}",
                ea.role,
                ea.path,
                ea.sha384_hex,
                sha
            );
        }
        if let Some(m) = manifest {
            if let Some(mm) = m.artifacts.iter().find(|a| a.path == ea.path) {
                if !mm.sha384_hex.eq_ignore_ascii_case(&sha) {
                    bail!(
                        "launch artifact '{}' ({}) sha384 {} disagrees with image-manifest.json ({})",
                        ea.role,
                        ea.path,
                        sha,
                        mm.sha384_hex
                    );
                }
            }
        }
        println!("[bind] {} {} sha384={}", ea.role, ea.path, sha);
        collected.push(ArtifactDigest {
            path: ea.path.clone(),
            sha384_hex: sha,
            len,
        });
    }
    Ok(collected)
}

/// Append one event to a PQC-signed transparency log and print/record the checkpoint.
fn append_transparency(log_path: &str, log_id: &str, action: String, actor: &str) -> Result<()> {
    let signer =
        secgit_crypto::sig::SigningKey::generate_with_bundle(secgit_crypto::LONG_LIVED_SIG)?.0;
    let mut log = secgit_audit::TransparencyLog::open(log_path, log_id, signer)?;
    log.append(secgit_audit::AuditEvent::Admin {
        action,
        actor: actor.into(),
    })?;
    let cp = log.checkpoint()?;
    println!(
        "transparency: appended to {log_path}; size={} root={}",
        cp.tree_size,
        hex::encode(cp.root_hash)
    );
    let vk_path = format!("{log_path}.vk.json");
    std::fs::write(&vk_path, serde_json::to_vec_pretty(&log.verifying_key())?)?;
    println!("wrote {vk_path} (pin this to verify checkpoints)");
    Ok(())
}

/// Compute (via `sev-snp-measure`) or record (via `--measurement`) the SEV-SNP launch
/// measurement, write a reference JSON, and optionally publish it to a transparency log
/// so verifiers can pin `Policy.allowed_measurements` to an auditable value.
fn snp_measure(args: &[String]) -> Result<()> {
    let mut p = SnpMeasureParams::default();
    let mut measurement_override: Option<String> = None;
    let mut log_path: Option<String> = None;
    let mut image_manifest_path: Option<String> = None;
    let mut out = "snp-reference.json".to_string();

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || -> Result<String> {
            it.next()
                .cloned()
                .with_context(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            // Load all launch-context inputs from a single JSON file so the predicted
            // measurement for the EXACT reproducible image is one command. Explicit flags
            // after --inputs override individual fields.
            "--inputs" => {
                let path = val()?;
                p = serde_json::from_slice(
                    &std::fs::read(&path).with_context(|| format!("reading {path}"))?,
                )
                .with_context(|| format!("parsing snp inputs {path}"))?;
            }
            "--ovmf" => p.ovmf = val()?,
            "--kernel" => p.kernel = Some(val()?),
            "--initrd" => p.initrd = Some(val()?),
            "--append" => p.append = Some(val()?),
            "--vcpus" => p.vcpus = Some(val()?.parse().context("--vcpus must be a number")?),
            "--vcpu-type" => p.vcpu_type = Some(val()?),
            "--measurement" => measurement_override = Some(val()?),
            "--log" => log_path = Some(val()?),
            "--image-manifest" => image_manifest_path = Some(val()?),
            "--out" => out = val()?,
            other => bail!("unknown snp-measure flag: {other}"),
        }
    }

    // Bind the reference to the launch inputs: recompute each declared artifact's digest and
    // refuse on any mismatch with the descriptor or the image manifest. This is what makes
    // the measurement "the ACTUAL guest," not an abstract input file.
    let manifest = match &image_manifest_path {
        Some(path) => Some(
            serde_json::from_slice::<ImageManifest>(
                &std::fs::read(path).with_context(|| format!("reading {path}"))?,
            )
            .with_context(|| format!("parsing image manifest {path}"))?,
        ),
        None => None,
    };
    let launch_artifacts = verify_and_collect_artifacts(&p, manifest.as_ref())?;

    let (measurement_hex, tool) = match measurement_override {
        Some(m) => (m, "recorded (on-silicon / external)".to_string()),
        None => (run_sev_snp_measure(&p)?, "sev-snp-measure".to_string()),
    };
    validate_measurement_hex(&measurement_hex)?;

    let commit = git_commit();
    let launch_method = p.vmm_launch_method.clone();
    let reference = SnpReference {
        measurement_hex: measurement_hex.clone(),
        mode: "snp".into(),
        params: p,
        tool,
        note: "Pin into Policy.allowed_measurements; published to the transparency log so \
               a third party can rebuild from git_commit and confirm the operator did not \
               silently change it."
            .into(),
        git_commit: commit.clone(),
        vmm_launch_method: launch_method,
        launch_artifacts,
    };
    std::fs::write(&out, serde_json::to_vec_pretty(&reference)?)?;
    println!(
        "wrote {out} (measurement={measurement_hex}, commit={})",
        commit.as_deref().unwrap_or("unknown")
    );

    if let Some(log) = log_path {
        // The transparency entry binds commit -> measurement so the chain
        // (git commit -> reproducible image -> predicted measurement) is auditable.
        append_transparency(
            &log,
            "secgit-snp-reference",
            format!(
                "snp-measurement sha384={measurement_hex} commit={}",
                commit.as_deref().unwrap_or("unknown")
            ),
            "ci-reproducible-build",
        )?;
    }
    Ok(())
}

/// One resolved dependency from `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Parse `Cargo.lock` `[[package]]` blocks into structured entries.
fn parse_lockfile(lock_path: &str) -> Result<Vec<LockedPackage>> {
    let content =
        std::fs::read_to_string(lock_path).with_context(|| format!("reading {lock_path}"))?;
    let mut pkgs = vec![];
    let mut cur: Option<LockedPackage> = None;
    let field = |line: &str, key: &str| -> Option<String> {
        line.trim()
            .strip_prefix(key)
            .and_then(|r| r.trim().strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
    };
    for line in content.lines() {
        if line.trim() == "[[package]]" {
            if let Some(p) = cur.take() {
                pkgs.push(p);
            }
            cur = Some(LockedPackage {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
            });
        } else if let Some(p) = cur.as_mut() {
            if let Some(v) = field(line, "name") {
                p.name = v;
            } else if let Some(v) = field(line, "version") {
                p.version = v;
            } else if let Some(v) = field(line, "source") {
                p.source = Some(v);
            } else if let Some(v) = field(line, "checksum") {
                p.checksum = Some(v);
            }
        }
    }
    if let Some(p) = cur.take() {
        pkgs.push(p);
    }
    Ok(pkgs)
}

/// Build a minimal CycloneDX 1.5 SBOM document from the locked dependency graph.
fn build_sbom(lock_path: &str) -> Result<serde_json::Value> {
    let pkgs = parse_lockfile(lock_path)?;
    let components: Vec<serde_json::Value> = pkgs
        .iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| {
            let purl = format!("pkg:cargo/{}@{}", p.name, p.version);
            let mut c = serde_json::json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": purl,
            });
            if let Some(src) = &p.source {
                c["properties"] = serde_json::json!([{ "name": "cargo:source", "value": src }]);
            }
            if let Some(sum) = &p.checksum {
                c["hashes"] = serde_json::json!([{ "alg": "SHA-256", "content": sum }]);
            }
            c
        })
        .collect();
    Ok(serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": { "type": "application", "name": "secgit" },
            "properties": [{ "name": "source_date_epoch",
                             "value": std::env::var("SOURCE_DATE_EPOCH").unwrap_or_default() }],
        },
        "components": components,
    }))
}

/// Generate a CycloneDX SBOM from `Cargo.lock` (image-transparency input).
fn sbom(args: &[String]) -> Result<()> {
    let lock = args.first().map(String::as_str).unwrap_or("Cargo.lock");
    let out = args.get(1).map(String::as_str).unwrap_or("sbom.json");
    let doc = build_sbom(lock)?;
    let n = doc
        .get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    std::fs::write(out, serde_json::to_vec_pretty(&doc)?)?;
    println!("wrote {out} ({n} components from {lock})");
    Ok(())
}

fn verify_image(args: &[String]) -> Result<()> {
    let manifest_path = args
        .first()
        .context("usage: verify-image <manifest.json> <sha384_hex>")?;
    let expected = args
        .get(1)
        .context("usage: verify-image <manifest.json> <sha384_hex>")?;
    let manifest: ImageManifest = serde_json::from_slice(&std::fs::read(manifest_path)?)?;
    let found = manifest.artifacts.iter().any(|a| &a.sha384_hex == expected);
    if found {
        println!("[PASS] digest {expected} is present in the manifest");
        Ok(())
    } else {
        println!("[FAIL] digest {expected} not found in manifest");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_lock() -> String {
        format!("{}/../Cargo.lock", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn no_ml_or_telemetry_deps_in_graph() {
        // Enforces the "no AI training" invariant at build time, independent of
        // cargo-deny: the workspace must not pull in any ML/inference/telemetry crate.
        egress_check(&workspace_lock()).unwrap();
    }

    #[test]
    fn sbom_contains_workspace_and_pinned_deps() {
        let doc = build_sbom(&workspace_lock()).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        let comps = doc["components"].as_array().unwrap();
        assert!(comps.iter().any(|c| c["name"] == "secgit-server"));
        // Registry deps carry a SHA-256 checksum + purl; ensure at least one does.
        assert!(comps.iter().any(|c| {
            c["purl"].as_str().map(|p| p.starts_with("pkg:cargo/")) == Some(true)
                && c.get("hashes").is_some()
        }));
    }

    #[test]
    fn sev_snp_measure_args_are_well_formed() {
        let p = SnpMeasureParams {
            ovmf: "OVMF.fd".into(),
            kernel: Some("vmlinuz".into()),
            initrd: Some("initrd.img".into()),
            append: Some("console=ttyS0".into()),
            vcpus: Some(4),
            vcpu_type: Some("EpycV4".into()),
            ..Default::default()
        };
        let a = build_sev_snp_measure_args(&p).unwrap();
        assert!(a.windows(2).any(|w| w[0] == "--mode" && w[1] == "snp"));
        assert!(a.windows(2).any(|w| w[0] == "--ovmf" && w[1] == "OVMF.fd"));
        assert!(a.windows(2).any(|w| w[0] == "--vcpus" && w[1] == "4"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--append" && w[1] == "console=ttyS0"));
    }

    #[test]
    fn measure_args_require_ovmf() {
        assert!(build_sev_snp_measure_args(&SnpMeasureParams::default()).is_err());
    }

    #[test]
    fn measurement_hex_validation() {
        validate_measurement_hex(&"ab".repeat(48)).unwrap(); // 48 bytes
        assert!(validate_measurement_hex(&"ab".repeat(32)).is_err()); // 32 bytes
        assert!(validate_measurement_hex("nothex").is_err());
    }

    #[test]
    fn snp_inputs_json_deserializes_into_params() {
        // The `--inputs snp-inputs.json` one-command path: a single JSON file fully
        // describes the launch context for the predicted measurement.
        let json = serde_json::json!({
            "ovmf": "OVMF.fd",
            "kernel": "vmlinuz",
            "initrd": "initrd.img",
            "append": "console=ttyS0 systemd.verity=yes ro",
            "vcpus": 4,
            "vcpu_type": "EPYC-v4"
        });
        let p: SnpMeasureParams = serde_json::from_value(json).unwrap();
        let a = build_sev_snp_measure_args(&p).unwrap();
        assert!(a.windows(2).any(|w| w[0] == "--ovmf" && w[1] == "OVMF.fd"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--kernel" && w[1] == "vmlinuz"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--vcpu-type" && w[1] == "EPYC-v4"));
    }

    #[test]
    fn snp_reference_roundtrips() {
        let r = SnpReference {
            measurement_hex: "cd".repeat(48),
            mode: "snp".into(),
            params: SnpMeasureParams {
                ovmf: "OVMF.fd".into(),
                ..Default::default()
            },
            tool: "sev-snp-measure".into(),
            note: "n".into(),
            git_commit: Some("deadbeef".into()),
            vmm_launch_method: Some("sev-snp-measure-direct-boot".into()),
            launch_artifacts: vec![ArtifactDigest {
                path: "OVMF.fd".into(),
                sha384_hex: "ab".repeat(48),
                len: 42,
            }],
        };
        let j = serde_json::to_vec(&r).unwrap();
        let back: SnpReference = serde_json::from_slice(&j).unwrap();
        assert_eq!(back.measurement_hex, r.measurement_hex);
        assert_eq!(back.params.ovmf, "OVMF.fd");
        assert_eq!(back.git_commit.as_deref(), Some("deadbeef"));
        assert_eq!(back.launch_artifacts.len(), 1);
    }

    #[test]
    fn launch_descriptor_parses_pinned_fields() {
        // The `deploy/snp-inputs.example.json` shape: launch method + pinned artifacts.
        let json = serde_json::json!({
            "vmm_launch_method": "sev-snp-measure-direct-boot",
            "ovmf": "deploy/guest/out/OVMF.fd",
            "kernel": "deploy/guest/out/secgit-guest.efi",
            "append": "console=ttyS0 systemd.verity=yes ro",
            "vcpus": 4,
            "vcpu_type": "EPYC-v4",
            "ovmf_pin": "deploy/guest/ovmf.pin.json",
            "expected_artifacts": [
                { "role": "ovmf", "path": "deploy/guest/out/OVMF.fd", "sha384_hex": "REPLACE_ME" },
                { "role": "uki", "path": "deploy/guest/out/secgit-guest.efi", "sha384_hex": "REPLACE_ME" }
            ]
        });
        let p: SnpMeasureParams = serde_json::from_value(json).unwrap();
        assert_eq!(
            p.vmm_launch_method.as_deref(),
            Some("sev-snp-measure-direct-boot")
        );
        assert_eq!(p.expected_artifacts.len(), 2);
        assert_eq!(p.expected_artifacts[0].role, "ovmf");
        // The measure arg builder ignores the binding fields but still works.
        let a = build_sev_snp_measure_args(&p).unwrap();
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--ovmf" && w[1] == "deploy/guest/out/OVMF.fd"));
    }

    #[test]
    fn artifact_bind_matches_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("secgit-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("OVMF.fd");
        std::fs::write(&f, b"pretend-firmware-bytes").unwrap();
        let (real, _len) = sha384_file(f.to_str().unwrap()).unwrap();

        // Correctly-pinned digest binds and is collected.
        let ok = SnpMeasureParams {
            ovmf: f.to_string_lossy().into(),
            expected_artifacts: vec![ExpectedArtifact {
                role: "ovmf".into(),
                path: f.to_string_lossy().into(),
                sha384_hex: real.clone(),
            }],
            ..Default::default()
        };
        let collected = verify_and_collect_artifacts(&ok, None).unwrap();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].sha384_hex, real);

        // A wrong pinned digest must fail closed.
        let bad = SnpMeasureParams {
            expected_artifacts: vec![ExpectedArtifact {
                role: "ovmf".into(),
                path: f.to_string_lossy().into(),
                sha384_hex: "00".repeat(48),
            }],
            ..Default::default()
        };
        assert!(verify_and_collect_artifacts(&bad, None).is_err());

        // A placeholder digest is tolerated (unpinned scaffold) and still records the file.
        let ph = SnpMeasureParams {
            expected_artifacts: vec![ExpectedArtifact {
                role: "ovmf".into(),
                path: f.to_string_lossy().into(),
                sha384_hex: "REPLACE_WITH_SHA384".into(),
            }],
            ..Default::default()
        };
        assert_eq!(verify_and_collect_artifacts(&ph, None).unwrap().len(), 1);

        // A missing file is skipped (not an error) — the guest image isn't built yet.
        let missing = SnpMeasureParams {
            expected_artifacts: vec![ExpectedArtifact {
                role: "uki".into(),
                path: dir.join("does-not-exist").to_string_lossy().into(),
                sha384_hex: "REPLACE".into(),
            }],
            ..Default::default()
        };
        assert!(verify_and_collect_artifacts(&missing, None)
            .unwrap()
            .is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_bind_cross_checks_image_manifest() {
        let dir = std::env::temp_dir().join(format!("secgit-bindmf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("secgit-server");
        std::fs::write(&f, b"binary-bytes").unwrap();
        let (real, len) = sha384_file(f.to_str().unwrap()).unwrap();
        let path = f.to_string_lossy().to_string();

        let params = SnpMeasureParams {
            expected_artifacts: vec![ExpectedArtifact {
                role: "server".into(),
                path: path.clone(),
                sha384_hex: real.clone(),
            }],
            ..Default::default()
        };

        // Manifest agrees -> ok.
        let agree = ImageManifest {
            artifacts: vec![ArtifactDigest {
                path: path.clone(),
                sha384_hex: real.clone(),
                len,
            }],
            source_date_epoch: None,
            note: String::new(),
        };
        assert!(verify_and_collect_artifacts(&params, Some(&agree)).is_ok());

        // Manifest disagrees on the same path -> fail closed.
        let disagree = ImageManifest {
            artifacts: vec![ArtifactDigest {
                path: path.clone(),
                sha384_hex: "11".repeat(48),
                len,
            }],
            source_date_epoch: None,
            note: String::new(),
        };
        assert!(verify_and_collect_artifacts(&params, Some(&disagree)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn provenance_statement_signs_and_verifies_over_canonical_bytes() {
        // The signed bytes are the COMPACT serialization; a verifier that parses the pretty
        // file and re-serializes compactly must reproduce the exact bytes (stable field order).
        let statement = ProvenanceStatement {
            type_: "https://in-toto.io/Statement/v1".into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            subject: vec![Subject {
                name: "OVMF.fd".into(),
                digest: digest_map("sha384", &"ab".repeat(48)),
            }],
            predicate: ProvenancePredicate {
                build_type: "https://secgit.dev/reproducible-oci-cvm/v1".into(),
                builder_id: "secgit-xtask".into(),
                snp_measurement_hex: "cd".repeat(48),
                vmm_launch_method: "sev-snp-measure-direct-boot".into(),
                git_commit: "deadbeef".into(),
                source_date_epoch: "1700000000".into(),
            },
        };
        let canonical = serde_json::to_vec(&statement).unwrap();
        let sk = secgit_crypto::sig::SigningKey::generate(secgit_crypto::LONG_LIVED_SIG).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(&canonical).unwrap();

        // Round-trip through the on-disk (pretty) form, then re-serialize compact.
        let pretty = serde_json::to_vec_pretty(&statement).unwrap();
        let parsed: ProvenanceStatement = serde_json::from_slice(&pretty).unwrap();
        let recanon = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(canonical, recanon, "canonicalization must be stable");
        assert!(secgit_crypto::sig::verify(&vk, &recanon, &sig).is_ok());
        // Tamper detection: flipping a digest breaks the signature.
        let mut tampered = parsed;
        tampered.subject[0].digest = digest_map("sha384", &"ff".repeat(48));
        let tcanon = serde_json::to_vec(&tampered).unwrap();
        assert!(secgit_crypto::sig::verify(&vk, &tcanon, &sig).is_err());
    }

    #[test]
    fn guest_egress_allowlist_is_default_drop() {
        // Packaging-layer leak-test companion to `egress-check`: prove the in-guest nftables
        // policy stays default-drop and only permits the KDS/KBS (443) + DNS + service ingress.
        // A regression that flips a chain to `policy accept` or opens a wildcard egress port
        // would silently break the no-plaintext-egress invariant; catch it here.
        let path = format!(
            "{}/../deploy/guest/nftables.conf",
            env!("CARGO_MANIFEST_DIR")
        );
        let conf = std::fs::read_to_string(&path).expect("read nftables.conf");
        assert!(
            !conf.contains("policy accept"),
            "no chain may default to accept (found `policy accept`)"
        );
        // All three base chains must default-drop.
        assert_eq!(
            conf.matches("policy drop;").count(),
            3,
            "input/forward/output must all be `policy drop`"
        );
        // The only permitted outbound application port is 443 (KDS/KBS); DNS is 53.
        assert!(
            conf.contains("tcp dport 443 accept"),
            "KDS/KBS egress must be allowed"
        );
        assert!(
            !conf.contains("tcp dport 80 accept"),
            "plaintext HTTP egress must never be allowed"
        );
    }

    #[test]
    fn egress_check_detects_a_planted_dependency() {
        // Sanity: the check actually catches a forbidden crate if one appears.
        let tmp = std::env::temp_dir().join(format!("secgit-egress-{}.lock", std::process::id()));
        std::fs::write(
            &tmp,
            "[[package]]\nname = \"candle-core\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert!(egress_check(tmp.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&tmp);
    }
}
