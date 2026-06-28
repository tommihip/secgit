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
}

/// A published, transparency-logged reference launch measurement that the verifier pins
/// into `Policy.allowed_measurements`.
#[derive(Serialize, Deserialize)]
struct SnpReference {
    measurement_hex: String,
    mode: String,
    params: SnpMeasureParams,
    tool: String,
    note: String,
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
            eprintln!("              [--measurement HEX] [--log path] [--out snp-reference.json]");
            eprintln!("                                            -> compute/record SNP launch measurement");
            std::process::exit(2);
        }
    }
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
            "--out" => out = val()?,
            other => bail!("unknown snp-measure flag: {other}"),
        }
    }

    let (measurement_hex, tool) = match measurement_override {
        Some(m) => (m, "recorded (on-silicon / external)".to_string()),
        None => (run_sev_snp_measure(&p)?, "sev-snp-measure".to_string()),
    };
    validate_measurement_hex(&measurement_hex)?;

    let reference = SnpReference {
        measurement_hex: measurement_hex.clone(),
        mode: "snp".into(),
        params: p,
        tool,
        note: "Pin into Policy.allowed_measurements; published to the transparency log so \
               a third party can confirm the operator did not silently change it."
            .into(),
    };
    std::fs::write(&out, serde_json::to_vec_pretty(&reference)?)?;
    println!("wrote {out} (measurement={measurement_hex})");

    if let Some(log) = log_path {
        append_transparency(
            &log,
            "secgit-snp-reference",
            format!("snp-measurement sha384={measurement_hex}"),
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
            "append": "console=ttyS0 root=/dev/vda1 ro",
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
        };
        let j = serde_json::to_vec(&r).unwrap();
        let back: SnpReference = serde_json::from_slice(&j).unwrap();
        assert_eq!(back.measurement_hex, r.measurement_hex);
        assert_eq!(back.params.ovmf, "OVMF.fd");
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
