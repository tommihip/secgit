//! Per-tier confidentiality leak-tests for the public sandbox (M6).
//!
//! The wedge — *the operator cannot read your code or metadata* — must hold in **every**
//! interaction tier, not just in aggregate. These tests drive each tier's storage path
//! (anonymous ephemeral, Light, Managed) with a unique canary and assert the canary and the
//! repo id are ciphertext on the operator's disk at rest.
//!
//! All three tiers share the same `Forge::seal_to_store` -> `EncryptedStore` path but with
//! different repo-id shapes (`ephemeral/<hex>`, `<user>/<repo>`, `<org>/<repo>`); we prove
//! the invariant holds for each shape. On-wire confidentiality is proven generically by
//! `tls::loopback_observer_sees_only_ciphertext` (in-CVM PQC-TLS terminates the plaintext).

use secgit_crypto::aead::SymKey;
use secgit_forge::Forge;
use secgit_leaktest::{assert_dir_ciphertext_nonempty, Canary};
use secgit_store::EncryptedStore;
use std::path::Path;
use std::process::Command;

fn git(cwd: &Path, args: &[&str]) {
    let st = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        st.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&st.stderr)
    );
}

/// Seed a bare repo at `forge.repo_path(repo_id)` containing a file whose contents include
/// `canary` (mirroring how a real push lands objects), then seal it to the encrypted store.
fn seed_and_seal(
    forge: &Forge,
    store: &EncryptedStore,
    root: &Path,
    repo_id: &str,
    canary: &Canary,
) {
    let work = root.join("work");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "--quiet", "."]);
    git(&work, &["config", "user.email", "t@t"]);
    git(&work, &["config", "user.name", "t"]);
    std::fs::write(work.join("secret.txt"), canary.as_bytes()).unwrap();
    git(&work, &["add", "."]);
    git(&work, &["commit", "--quiet", "-m", canary.as_str()]);

    let bare = forge.repo_path(repo_id);
    git(
        root,
        &[
            "clone",
            "--bare",
            "--quiet",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    store.init_repo(repo_id).unwrap();
    forge.seal_to_store(repo_id, store).unwrap();
    let _ = std::fs::remove_dir_all(&work);
}

fn tier_case(tag: &str, repo_id: &str) {
    let root = std::env::temp_dir().join(format!("secgit-tier-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let forge = Forge::new(root.join("repos")).unwrap();
    let store_dir = root.join("store");
    let store = EncryptedStore::open(&store_dir, SymKey::generate().unwrap()).unwrap();

    let canary = Canary::new(tag);
    seed_and_seal(&forge, &store, &root, repo_id, &canary);

    // At-rest leak check: neither the file content (canary) nor the repo id may appear in
    // any operator-visible byte on disk in the encrypted store.
    assert_dir_ciphertext_nonempty(&store_dir, &[canary.as_bytes(), repo_id.as_bytes()]);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn anonymous_ephemeral_tier_is_ciphertext_at_rest() {
    // Anonymous tier: throwaway `ephemeral/<hex>` id.
    tier_case("ephemeral", "ephemeral/deadbeefcafe1234");
}

#[test]
fn light_tier_is_ciphertext_at_rest() {
    // Light tier: authenticated user-owned `<user>/<repo>` id.
    tier_case("light", "alice/private-notes");
}

#[test]
fn managed_tier_is_ciphertext_at_rest() {
    // Managed tier: org-owned `<org>/<repo>` id (skips Light quota, same encrypted store).
    tier_case("managed", "acme-corp/monorepo");
}
