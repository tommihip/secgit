//! `secgit-verify probe-snp` — a standalone capability probe.
//!
//! Run this on a *candidate* host to decide whether it can back SecGit's provider-neutral
//! trust root: a **raw** SEV-SNP guest attestation report obtained through the cross-vendor
//! Linux `configfs-tsm` interface (or `/dev/sev-guest`). It deliberately does NOT accept a
//! cloud vTPM attestation path — that would route trust through a hypervisor/cloud service
//! and violate provider-neutrality (ADR 0002 / 0010).
//!
//! Verdict:
//! - `PASS` — a raw guest report was fetched and parses as an SNP report.
//! - `FAIL` — only a cloud vTPM path exists (unusable), or no attestation path at all.
//!
//! No network is used; this is a pure local capability check.

use anyhow::Result;

const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
const SEV_GUEST_DEV: &str = "/dev/sev-guest";

/// What the probe observed on the host.
#[derive(Debug, Clone, Copy, Default)]
pub struct Findings {
    /// `configfs-tsm` report interface present (`/sys/kernel/config/tsm/report`).
    pub configfs_tsm: bool,
    /// Legacy `/dev/sev-guest` ioctl device present.
    pub sev_guest_dev: bool,
    /// A raw guest report was actually fetched AND parsed as an SNP report.
    pub raw_report_ok: bool,
    /// A TPM resource-manager / TPM device is present (cloud vTPM attestation signal).
    pub vtpm_present: bool,
}

/// Final verdict, independent of how the findings were gathered (so it is unit-testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Raw SEV-SNP guest report available — usable, provider-neutral.
    Pass,
    /// Only a cloud vTPM path is available — unusable (violates provider-neutrality).
    FailVtpmOnly,
    /// No usable attestation path at all.
    FailNone,
    /// This platform cannot physically host SEV-SNP (e.g. macOS, or non-x86 Linux), so the
    /// probe does not apply. Not a failure — use `acceptance-snp --mock` here and run the
    /// live path on a Linux AMD CVM.
    NotApplicable,
}

/// True only on a platform that can physically back SEV-SNP: Linux on x86-64 (AMD).
/// Everywhere else (macOS, non-x86 Linux) the live probe is not applicable.
pub const fn platform_supported() -> bool {
    cfg!(all(target_os = "linux", target_arch = "x86_64"))
}

/// Decide the verdict from findings. Pure: the security-relevant policy lives here.
///
/// A raw report is the only acceptable outcome. The presence of a vTPM is reported as the
/// *reason* a host without a raw report is rejected, but a vTPM is NEVER a substitute.
pub fn decide(f: &Findings) -> Verdict {
    if f.raw_report_ok {
        Verdict::Pass
    } else if f.vtpm_present {
        Verdict::FailVtpmOnly
    } else {
        Verdict::FailNone
    }
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
    /// True if the verdict should NOT be treated as a process failure: a genuine `Pass`,
    /// or `NotApplicable` (wrong platform — an honest "not here", not an error).
    pub fn is_ok_exit(&self) -> bool {
        self.is_pass() || matches!(self, Verdict::NotApplicable)
    }
    fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::FailVtpmOnly | Verdict::FailNone => "FAIL",
            Verdict::NotApplicable => "N/A",
        }
    }
    fn detail(&self) -> &'static str {
        match self {
            Verdict::Pass => "raw SEV-SNP guest report available (provider-neutral root usable)",
            Verdict::FailVtpmOnly => {
                "only a cloud vTPM attestation path is present — UNUSABLE: routing trust through \
                 a hypervisor/cloud vTPM violates provider-neutrality. Need a raw guest report \
                 via configfs-tsm or /dev/sev-guest."
            }
            Verdict::FailNone => {
                "no SEV-SNP guest attestation path found (need an AMD SEV-SNP guest, kernel 6.7+ \
                 with configfs-tsm, or /dev/sev-guest)."
            }
            Verdict::NotApplicable => {
                "real SEV-SNP attestation is unavailable on this platform — it requires an AMD \
                 x86 SEV-SNP CVM (Linux, kernel 6.7+ with configfs-tsm). Use \
                 `secgit-verify acceptance-snp --mock` locally and run the live path on a \
                 Linux AMD CVM."
            }
        }
    }
}

/// Gather findings by inspecting the live host (filesystem + an actual report fetch).
fn gather() -> Findings {
    let configfs_tsm = std::path::Path::new(TSM_REPORT_DIR).exists();
    let sev_guest_dev = std::path::Path::new(SEV_GUEST_DEV).exists();
    let vtpm_present =
        std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists();

    // Try to actually obtain and parse a raw report — presence of the interface is not
    // enough; it must produce a parseable SNP report.
    let raw_report_ok = try_fetch_raw_report();

    Findings {
        configfs_tsm,
        sev_guest_dev,
        raw_report_ok,
        vtpm_present,
    }
}

/// Attempt a real raw SNP report fetch via the provider-neutral attester and confirm it
/// parses. Returns false on any failure (interface absent, permission, malformed).
fn try_fetch_raw_report() -> bool {
    use secgit_attest::snp::{parse_report, SnpAttester};
    use secgit_attest::{Attester, ReportData};
    if !SnpAttester::available() {
        return false;
    }
    let rd = ReportData::bind(b"secgit-probe-snp", b"capability-probe");
    match SnpAttester::new().get_evidence(&rd) {
        Ok(ev) => parse_report(&ev.report).is_ok(),
        Err(_) => false,
    }
}

/// Run the probe against the live host and print a clear, itemized verdict. Returns the
/// verdict so the caller can set the process exit code.
pub fn run() -> Result<Verdict> {
    println!("SecGit SEV-SNP capability probe (provider-neutrality gate)\n");

    // Short-circuit on platforms that cannot physically host SEV-SNP (macOS, non-x86
    // Linux). Probing the filesystem there only yields a confusing FAIL; instead report
    // a clear, non-alarming N/A and point at the mock + Linux-AMD-CVM paths.
    if !platform_supported() {
        let verdict = Verdict::NotApplicable;
        println!(
            "[{}] platform is {}/{} — cannot host AMD SEV-SNP.",
            verdict.label(),
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
        println!("\n[{}] {}", verdict.label(), verdict.detail());
        return Ok(verdict);
    }

    let f = gather();

    let item = |ok: bool, yes: &str, no: &str| -> String {
        format!(
            "[{}] {}",
            if ok { "ok" } else { "--" },
            if ok { yes } else { no }
        )
    };
    println!(
        "{}",
        item(
            f.configfs_tsm,
            "configfs-tsm present (/sys/kernel/config/tsm/report)",
            "configfs-tsm absent (/sys/kernel/config/tsm/report)"
        )
    );
    println!(
        "{}",
        item(
            f.sev_guest_dev,
            "/dev/sev-guest present",
            "/dev/sev-guest absent"
        )
    );
    println!(
        "{}",
        item(
            f.raw_report_ok,
            "raw SNP guest report fetched and parsed",
            "no raw SNP guest report could be fetched/parsed"
        )
    );
    if f.vtpm_present {
        println!("[!!] vTPM device present (/dev/tpm*) — a cloud vTPM path is NOT acceptable");
    }

    let verdict = decide(&f);
    println!("\n[{}] {}", verdict.label(), verdict.detail());
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_report_passes_even_with_vtpm() {
        // A raw report is decisive; an incidental vTPM does not downgrade a usable host.
        let f = Findings {
            configfs_tsm: true,
            sev_guest_dev: true,
            raw_report_ok: true,
            vtpm_present: true,
        };
        assert_eq!(decide(&f), Verdict::Pass);
    }

    #[test]
    fn vtpm_only_is_rejected() {
        let f = Findings {
            configfs_tsm: false,
            sev_guest_dev: false,
            raw_report_ok: false,
            vtpm_present: true,
        };
        assert_eq!(decide(&f), Verdict::FailVtpmOnly);
        assert!(!decide(&f).is_pass());
    }

    #[test]
    fn nothing_present_is_fail_none() {
        let f = Findings::default();
        assert_eq!(decide(&f), Verdict::FailNone);
    }

    #[test]
    fn interface_without_report_is_not_a_pass() {
        // The configfs interface existing is not enough; a parseable report is required.
        let f = Findings {
            configfs_tsm: true,
            sev_guest_dev: true,
            raw_report_ok: false,
            vtpm_present: false,
        };
        assert_eq!(decide(&f), Verdict::FailNone);
    }
}
