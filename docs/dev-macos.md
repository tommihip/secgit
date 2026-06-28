# Native dev on macOS (Apple Silicon)

This is the **mock/dev** loop for hacking on SecGit directly on an Apple M-series Mac —
no Docker, no Linux VM. The whole workspace builds, tests, and runs natively on
`aarch64-apple-darwin` against the **mock TEE**.

> **Confidentiality is NOT enforced on macOS.** Apple Silicon has no AMD SEV-SNP, so the
> attestation backend here is the software **MockVerifier**, which provides **no security**.
> On macOS every confidentiality claim is **MOCK-VERIFIED only** (the logic composes and
> refuses bad input, but no real silicon is involved). The real, operator-blind,
> **SILICON-VERIFIED** guarantee still requires running the published reproducible image on
> a **Linux AMD SEV-SNP CVM** — see [`acceptance-snp.md`](acceptance-snp.md) and the ledger
> in [`STATUS.md`](STATUS.md). macOS is for development and UI/forge work, not for proving
> the wedge.

The real Linux/AMD SEV-SNP path is unchanged: the guest-side `configfs-tsm` report fetch is
gated behind `#[cfg(target_os = "linux")]`, so non-Linux targets compile the mock/stub path
while the Linux build is byte-for-byte identical.

## Prerequisites

`aws-lc-rs` (our audited, C-backed PQC provider for ML-KEM / ML-DSA / AES) builds from C,
so it needs a C toolchain and CMake:

- **Xcode Command Line Tools** (provides `clang`):

```bash
xcode-select --install
```

- **CMake**:

```bash
brew install cmake
```

- **Rust** is pinned by [`rust-toolchain.toml`](../rust-toolchain.toml) (1.89.0 with
  `rustfmt` + `clippy`); `rustup` will install it automatically on first `cargo` invocation.

Sanity check: `clang --version` and `cmake --version` should both succeed.

## The native dev loop

From the workspace root:

```bash
# 1. Build + test the whole workspace (mock backend is automatic on macOS).
cargo build --workspace
cargo test --workspace

# 2. Run the in-process vertical-slice self-test (attestation-gated KEK release ->
#    encrypted store -> PQC-signed transparency log), all against the mock TEE.
cargo run -p secgit-verify -- selftest

# 3. Dry-run the full acceptance harness against the mock TEE (no silicon required).
cargo run -p secgit-verify -- acceptance-snp --mock
```

### Run the server and push a repo

Inside a real CVM the server terminates PQC-TLS in-process. For local macOS dev you can use
the plaintext escape hatch (loud warning — local use only) so a plain `git`/`curl` works
without a self-signed cert dance:

```bash
# One-time: pick a STABLE 32-byte dev KEK so encrypted data survives restarts.
export SECGIT_DEV_KEK_HEX=$(openssl rand -hex 32)
echo "KEK=$SECGIT_DEV_KEK_HEX"   # save this; reuse the SAME value on later runs

# Seed a local account and serve plaintext HTTP on 127.0.0.1:8080.
SECGIT_INSECURE_HTTP=1 \
SECGIT_DEV_KEK_HEX=$SECGIT_DEV_KEK_HEX \
SECGIT_BOOTSTRAP_USER=dev SECGIT_BOOTSTRAP_PASS=devpass \
  cargo run -p secgit-server
```

> **Important — KEK ↔ data dir coupling.** The data dir defaults to the **relative**
> `./.secgit-data`. Everything in it is encrypted under the instance KEK. If you start the
> server with a *different* KEK than the one that wrote an existing `.secgit-data` (including
> the random ephemeral KEK you get when `SECGIT_DEV_KEK_HEX` is unset), startup fails with
> `authentication failed (tampered ciphertext or wrong key)` — by design; that is the
> confidentiality guarantee working. Either reuse the **same** `SECGIT_DEV_KEK_HEX`, or start
> fresh with `rm -rf .secgit-data`. The server now prints actionable guidance when this
> happens.

Then, in another shell:

```bash
# The web UI and verification surfaces.
open http://127.0.0.1:8080/            # landing page (the wedge + how to verify)
open http://127.0.0.1:8080/ui          # browse repositories (log in: dev / devpass)
curl  http://127.0.0.1:8080/attestation  # mock evidence (backend: "Mock" on macOS)

# Create a repo and push to it in one step (push-to-create). This is the ONE repo type:
# persistent, owned by you, and visible in /ui.
mkdir /tmp/demo && cd /tmp/demo && git init -q && echo hi > a.txt
git add -A && git -c user.email=a@b.c -c user.name=dev commit -qm init
git push http://dev:devpass@127.0.0.1:8080/dev/demo HEAD:refs/heads/main
# -> "* [new branch] HEAD -> main"; now refresh /ui and you'll see dev/demo.
```

Useful env vars (all optional):

- `SECGIT_ADDR` — listen address (default `127.0.0.1:8080`).
- `SECGIT_DATA` — data directory (default `.secgit-data`, relative to the server's cwd).
- `SECGIT_DEV_KEK_HEX` — 32-byte hex KEK so encrypted data persists across restarts
  (otherwise an ephemeral KEK is used and data won't survive a restart; reuse the SAME value
  against an existing data dir — see the KEK note above).
- `SECGIT_BOOTSTRAP_USER` / `SECGIT_BOOTSTRAP_PASS` — seed a local account at boot. There are
  no default credentials; this account is what you log into `/ui` with. It's also registered
  in the (encrypted) identity directory so repos you create are owned by it.
- `SECGIT_INSECURE_HTTP` — serve plaintext HTTP (dev only; NOT provider-blind on the wire).
  Omit it to exercise the in-process PQC-TLS path (self-signed cert; clients must skip web
  PKI verification, e.g. `GIT_SSL_NO_VERIFY=1`).
- `SECGIT_ENABLE_ANONYMOUS` — opt in to the anonymous *ephemeral* sandbox path
  (`POST /sandbox/ephemeral`). Off by default so there is a single repo model; see below.

### Create a repo and see it in the UI

There is **one repo model**: a persistent repository owned by your account. You create it,
it shows in `/ui`, you push to it, and you browse it — consistently. There are three
interchangeable ways to create it; all produce the same repo and all appear in `/ui`.

**Push-to-create (recommended — no pre-creation).** Just push to a repo in *your own*
namespace (`<your-username>/<name>`) and the server creates it on first push:

```bash
cd /tmp && rm -rf demo && mkdir demo && cd demo && git init -q
echo "hello" > README.md
git add -A && git -c user.email=a@b.c -c user.name=dev commit -qm init
git push http://dev:devpass@127.0.0.1:8080/dev/demo HEAD:refs/heads/main
# -> "* [new branch] HEAD -> main"; the repo dev/demo is created and owned by you.
```

Notes:
- The path must be `<username>/<name>` (here `dev/demo`). Pushing to another user's
  namespace is refused (`unknown repo`); you can only create under your own.
- Credentials are required. Embed them in the URL as above, or let git's credential helper
  supply them — the first anonymous request returns `401` so the client retries with auth.
- The same Light-tier repo-count quota applies; if exceeded the push fails with a clear
  message instead of creating the repo.

**From the UI.** Log into `/ui`, use the **New repository** form (enter `demo`, submit); it
appears immediately (empty, with a push hint) and you can push to it as above.

**From the API.**

```bash
curl -u dev:devpass -X POST http://127.0.0.1:8080/api/v1/repos \
  -H 'Content-Type: application/json' -d '{"name":"demo"}'
```

After pushing, refresh `/ui` and click into `dev/demo` — files, history, and blame are all
served from inside the (mock) TEE.

> **Optional: the anonymous ephemeral path.** The public sandbox also offers a *throwaway*,
> auto-expiring, owner-less repo (`POST /sandbox/ephemeral`) for the "they can't read MY
> code" drive-by demo. Because it belongs to no account, it intentionally does **not** appear
> in `/ui`. It is **disabled by default** to keep a single repo model; enable it only if you
> specifically want that path by starting the server with `SECGIT_ENABLE_ANONYMOUS=1`.

### How a permanent repo is encrypted

Creating a persistent repo is not just a metadata row — it provisions the repo's own
encryption key. On first use (`init_repo`) the store generates a **fresh random per-repo DEK**,
writes it to disk only wrapped by the instance KEK (`repos/<sha256(repo_id)>/dek.wrapped`), and
from then on every read/write of that repo's bytes is AEAD-encrypted under that DEK, bound to
`(repo_id, key)`:

```text
KEK (released into the TEE after attestation; memory-only, never on disk)
  └─ wraps ─> per-repo DEK (dek.wrapped on disk)
                └─ encrypts ─> repo objects (AES-256-GCM / ChaCha20-Poly1305)
```

So each repository has its own generated key required to decrypt and access it; on disk
outside the TEE only ciphertext exists. See `crates/secgit-store` and `docs/adr/0003-key-hierarchy.md`.
(Per-owner / customer-controlled KEKs and BYOK — wrapping each owner's DEKs under their own
KEK instead of the shared instance KEK — are the designed-but-not-yet-wired enterprise step.)

## What does NOT work on macOS (by design)

- **`secgit-verify probe-snp`** prints a clear `N/A` (real SEV-SNP requires an AMD x86 CVM)
  and exits `0` — it is not a failure, just the wrong platform.
- **`secgit-verify acceptance-snp --url ...`** (the live, on-silicon run) likewise reports
  `N/A` and exits `0`. Use `--mock` here; run the live path on a Linux AMD CVM.

## Gates (run before pushing)

These are the same gates CI runs on the macOS leg (mock path only):

```bash
cargo fmt --all --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p secgit-verify -- selftest
cargo run -p secgit-verify -- acceptance-snp --mock
```
