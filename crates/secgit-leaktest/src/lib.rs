//! Reusable confidentiality leak-test harness.
//!
//! SecGit's central claim — *the operator cannot read your code or metadata* — is only as
//! strong as the tests that hold every plaintext-touching feature to it. This crate is the
//! shared harness those tests use, generalizing the original
//! `secgit-store::data_on_disk_is_ciphertext` and
//! `secgit-audit::encrypted_log_hides_metadata_but_stays_verifiable` patterns.
//!
//! The rule (see `docs/threat-model.md`): **every feature that ever holds plaintext must
//! ship a test that produces a unique [`Canary`], drives the feature, and then asserts the
//! canary (and any sensitive metadata) is absent from every operator-visible surface** —
//! the at-rest data directory ([`assert_dir_ciphertext`]) and any on-wire buffer
//! ([`assert_bytes_absent`]).
//!
//! These are *negative* tests: they fail loudly if plaintext leaks. A green run is not a
//! proof of confidentiality, but a leak is a definitive disproof, and wiring this into CI
//! makes regressions in the trust-critical path observable.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide monotonic counter mixed into every canary. This is what *guarantees*
/// uniqueness: the address/pid/clock inputs can all repeat across two rapid calls (same stack
/// frame, same pid, and a clock that may not advance within a nanosecond), so without a
/// strictly-increasing term two `Canary::new` calls can collide.
static CANARY_SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique, high-entropy marker embedded into test content so a search for it on an
/// operator-visible surface is unambiguous (no false positives from incidental bytes).
#[derive(Debug, Clone)]
pub struct Canary {
    value: String,
}

impl Canary {
    /// Create a canary with the given human label and process-unique entropy.
    ///
    /// Uniqueness is guaranteed by a strictly-increasing process-wide counter ([`CANARY_SEQ`]),
    /// placed in the high bits so it cannot be cancelled by the low-bit entropy. The
    /// address-space-randomized stack address, the process id, and a monotonic clock are folded
    /// in as well so canaries are also unpredictable, not just distinct.
    pub fn new(label: &str) -> Self {
        let stack = 0u8;
        let addr = (&stack as *const u8) as usize;
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = CANARY_SEQ.fetch_add(1, Ordering::Relaxed);
        // Low bits: unpredictable per-call entropy (addr/pid/clock). High bits: the monotonic
        // sequence, which occupies bit 96+ (above where addr, pid<<64, and the added nanos land)
        // so two calls always differ even when every other input repeats.
        let raw = (((addr as u128) ^ ((pid as u128) << 64)).wrapping_add(nanos))
            ^ ((seq as u128) << 96);
        Self {
            value: format!("SECGIT-CANARY-{label}-{:032x}", raw),
        }
    }

    /// The canary string, to be embedded into file contents, commit messages, etc.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The canary as bytes (what we scan for on disk / on the wire).
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

/// Assert that `needle` does not appear anywhere in `haystack`.
///
/// `context` is included in the failure message to identify the leaking surface.
pub fn assert_bytes_absent(haystack: &[u8], needle: &[u8], context: &str) {
    assert!(
        !needle.is_empty(),
        "leak-test misuse: empty needle for {context}"
    );
    if contains(haystack, needle) {
        panic!(
            "CONFIDENTIALITY LEAK: plaintext {:?} found in {context} ({} bytes scanned)",
            String::from_utf8_lossy(needle),
            haystack.len()
        );
    }
}

/// Assert that none of `needles` appear in `haystack`.
pub fn assert_all_absent(haystack: &[u8], needles: &[&[u8]], context: &str) {
    for n in needles {
        assert_bytes_absent(haystack, n, context);
    }
}

/// Recursively scan every regular file under `dir` and assert that none of `needles`
/// appears in any of them. This is the at-rest (operator's-disk) leak check.
///
/// Returns the number of files scanned (a `0` likely means the test wired the directory
/// wrong, so callers should assert it is non-zero).
pub fn assert_dir_ciphertext(dir: &Path, needles: &[&[u8]]) -> usize {
    let mut scanned = 0usize;
    visit_files(dir, &mut |path, bytes| {
        scanned += 1;
        let ctx = format!("on-disk file {}", path.display());
        for n in needles {
            assert_bytes_absent(bytes, n, &ctx);
        }
    });
    scanned
}

/// Like [`assert_dir_ciphertext`] but also fails if no files were scanned, guarding against
/// a test that points at an empty/wrong directory and therefore proves nothing.
pub fn assert_dir_ciphertext_nonempty(dir: &Path, needles: &[&[u8]]) {
    let n = assert_dir_ciphertext(dir, needles);
    assert!(
        n > 0,
        "leak-test misuse: no files scanned under {} (nothing proven)",
        dir.display()
    );
}

fn visit_files(dir: &Path, f: &mut impl FnMut(&Path, &[u8])) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => visit_files(&path, f),
            Ok(ft) if ft.is_file() => {
                if let Ok(bytes) = std::fs::read(&path) {
                    f(&path, &bytes);
                }
            }
            _ => {}
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canaries_are_unique() {
        // Many rapid same-label calls: the monotonic sequence must keep them all distinct even
        // when the stack address, pid, and clock inputs repeat within the loop.
        use std::collections::HashSet;
        let n = 10_000;
        let mut seen = HashSet::with_capacity(n);
        for _ in 0..n {
            let c = Canary::new("repo");
            assert!(c.as_str().starts_with("SECGIT-CANARY-repo-"));
            assert!(seen.insert(c.value.clone()), "duplicate canary: {}", c.as_str());
        }
    }

    #[test]
    fn absent_passes_present_fails() {
        assert_bytes_absent(b"ciphertext-only", b"secret", "buffer");
        let r = std::panic::catch_unwind(|| {
            assert_bytes_absent(b"...secret...", b"secret", "buffer");
        });
        assert!(r.is_err(), "expected a leak to be detected");
    }

    #[test]
    fn scans_directory_recursively() {
        let dir = std::env::temp_dir().join(format!("leaktest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.bin"), b"opaque-ciphertext").unwrap();
        std::fs::write(dir.join("sub/b.bin"), b"more-ciphertext").unwrap();

        let scanned = assert_dir_ciphertext(&dir, &[b"plaintext-canary"]);
        assert_eq!(scanned, 2);

        let canary = Canary::new("file");
        std::fs::write(dir.join("leak.txt"), canary.as_bytes()).unwrap();
        let r = std::panic::catch_unwind(|| {
            assert_dir_ciphertext(&dir, &[canary.as_bytes()]);
        });
        assert!(r.is_err(), "expected on-disk leak to be detected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonempty_guard_trips_on_empty_dir() {
        let dir = std::env::temp_dir().join(format!("leaktest-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = std::panic::catch_unwind(|| {
            assert_dir_ciphertext_nonempty(&dir, &[b"x"]);
        });
        assert!(
            r.is_err(),
            "expected guard to trip when nothing was scanned"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
