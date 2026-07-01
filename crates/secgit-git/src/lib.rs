//! # secgit-git
//!
//! Git "smart HTTP" transport primitives. Because gitoxide can't yet serve
//! `receive-pack` (push), we implement the protocol by shelling out to canonical
//! `git`'s `--stateless-rpc` mode — the proven pack engine — behind the confidential
//! boundary. These are pure functions over `(repo_path, body) -> bytes`; the API/
//! server layer handles authentication, authorization, and audit *before* calling
//! [`rpc`], and re-seals the repo to encrypted storage *after* a successful push.
//!
//! Endpoints a server maps onto these:
//! - `GET  /<repo>/info/refs?service=git-(upload|receive)-pack` -> [`advertise_refs`]
//! - `POST /<repo>/git-upload-pack`                              -> [`rpc`] (fetch)
//! - `POST /<repo>/git-receive-pack`                             -> [`rpc`] (push)

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitHttpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("git service failed: {0}")]
    Service(String),
    #[error("unknown service: {0}")]
    UnknownService(String),
    #[error("git service exceeded a resource limit: {0}")]
    LimitExceeded(String),
}

pub type Result<T> = core::result::Result<T, GitHttpError>;

/// Resource bounds applied to a git smart-HTTP subprocess so the public sandbox cannot be
/// wedged by a pathological pack, a decompression bomb, or a hanging process.
#[derive(Debug, Clone, Copy)]
pub struct GitLimits {
    /// Wall-clock cap; the subprocess is killed if it runs longer.
    pub wall_clock: Duration,
    /// Cap on bytes read back from the subprocess (defends fetch/clone amplification).
    pub max_output_bytes: usize,
    /// Max accepted pushed pack size in bytes (mapped to git `receive.maxInputSize`).
    pub max_input_bytes: u64,
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            wall_clock: Duration::from_secs(120),
            max_output_bytes: 512 * 1024 * 1024,
            max_input_bytes: 128 * 1024 * 1024,
        }
    }
}

/// The two git smart-HTTP services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }
    pub fn subcommand(self) -> &'static str {
        match self {
            Service::UploadPack => "upload-pack",
            Service::ReceivePack => "receive-pack",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "git-upload-pack" => Ok(Service::UploadPack),
            "git-receive-pack" => Ok(Service::ReceivePack),
            other => Err(GitHttpError::UnknownService(other.to_string())),
        }
    }
    /// MIME content type for the advertisement response.
    pub fn advertise_content_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }
    /// MIME content type for the RPC result response.
    pub fn result_content_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

/// Encode a single git pkt-line (4-hex length prefix including the prefix itself).
pub fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() + 4;
    let mut out = format!("{len:04x}").into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The pkt-line flush packet.
pub fn flush_pkt() -> &'static [u8] {
    b"0000"
}

/// Build the smart-HTTP ref advertisement for `GET /info/refs`.
pub fn advertise_refs(repo: &Path, service: Service) -> Result<Vec<u8>> {
    advertise_refs_with_limits(repo, service, &GitLimits::default())
}

/// [`advertise_refs`] under an explicit wall-clock / output cap.
pub fn advertise_refs_with_limits(
    repo: &Path,
    service: Service,
    limits: &GitLimits,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args([service.subcommand(), "--stateless-rpc", "--advertise-refs"])
        .arg(repo);
    let output = run_bounded(cmd, None, limits)?;
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(
        format!("# service={}\n", service.name()).as_bytes(),
    ));
    body.extend_from_slice(flush_pkt());
    body.extend_from_slice(&output);
    Ok(body)
}

/// Drive a stateless-rpc exchange: feed `body` to the service and return its output.
///
/// For [`Service::ReceivePack`] this performs the actual ref update (push). Callers
/// MUST authorize the request first and re-seal the repo to encrypted storage after.
/// Runs under [`GitLimits::default`]; use [`rpc_with_limits`] to override.
pub fn rpc(repo: &Path, service: Service, body: &[u8]) -> Result<Vec<u8>> {
    rpc_with_limits(repo, service, body, &GitLimits::default())
}

/// [`rpc`] under explicit resource bounds. Applies git-side hardening config for pushes
/// (`receive.maxInputSize`, `transfer.fsckObjects`) so a decompression bomb or oversized
/// pack is rejected by git itself, in addition to the wall-clock and output caps here.
pub fn rpc_with_limits(
    repo: &Path,
    service: Service,
    body: &[u8],
    limits: &GitLimits,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    if service == Service::ReceivePack {
        cmd.arg("-c")
            .arg(format!("receive.maxInputSize={}", limits.max_input_bytes));
        // Fsck incoming objects: rejects malformed/oversized objects (decompression-bomb
        // and malformed-object defense) before they are written into the repo.
        cmd.arg("-c").arg("transfer.fsckObjects=true");
    }
    cmd.args([service.subcommand(), "--stateless-rpc"])
        .arg(repo);
    run_bounded(cmd, Some(body), limits)
}

/// Spawn `cmd`, optionally writing `input` to stdin, and collect stdout under the given
/// wall-clock and output-size bounds. stdin write and stdout/stderr reads run in dedicated
/// threads (no pipe-buffer deadlock); the child is killed on timeout or when the output
/// cap is exceeded.
fn run_bounded(mut cmd: Command, input: Option<&[u8]>, limits: &GitLimits) -> Result<Vec<u8>> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put the child in its OWN process group (pgid == child pid) so that when we hit the
    // wall-clock or output cap we can kill the whole group — not just the direct `git`
    // child, which would leave grandchildren like `pack-objects` running.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd.spawn()?;

    // Feed stdin (if any) from a thread; dropping the handle sends EOF.
    let stdin = child.stdin.take().expect("piped stdin");
    let input_owned = input.map(|b| b.to_vec());
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        if let Some(bytes) = input_owned {
            let _ = stdin.write_all(&bytes);
        }
        // stdin dropped here -> EOF to the child.
    });

    let over_cap = Arc::new(AtomicBool::new(false));
    let max_out = limits.max_output_bytes;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader_flag = Arc::clone(&over_cap);
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > max_out {
                        reader_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        buf
    });

    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let err_reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut b);
        b
    });

    let deadline = Instant::now() + limits.wall_clock;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(s) => break Some(s),
            None => {
                if over_cap.load(Ordering::SeqCst) {
                    kill_group_and_reap(&mut child);
                    break None;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    kill_group_and_reap(&mut child);
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };

    let _ = writer.join();
    let out = reader.join().unwrap_or_default();
    let err = err_reader.join().unwrap_or_default();

    if timed_out {
        return Err(GitHttpError::LimitExceeded(format!(
            "git subprocess exceeded the {}s wall-clock cap",
            limits.wall_clock.as_secs()
        )));
    }
    if over_cap.load(Ordering::SeqCst) || out.len() > max_out {
        return Err(GitHttpError::LimitExceeded(format!(
            "git output exceeded the {}-byte cap",
            max_out
        )));
    }
    match status {
        Some(s) if s.success() => Ok(out),
        _ => Err(GitHttpError::Service(
            String::from_utf8_lossy(&err).into_owned(),
        )),
    }
}

/// Kill the child's entire process group, then reap the direct child.
///
/// The child was spawned as its own group leader (`process_group(0)`), so its pgid equals
/// its pid and a `kill(-pid, SIGKILL)` reaches every descendant git spawned (e.g.
/// `pack-objects`). On non-Unix we fall back to a direct child kill.
fn kill_group_and_reap(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // SAFETY: a negative pid signals the process group `pid`. The child leads its own
        // group; the raw FFI call has no memory-safety obligations.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(cwd: &Path, args: &[&str]) {
        let st = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&st.stderr)
        );
    }

    #[test]
    fn pkt_line_framing() {
        assert_eq!(pkt_line(b"a"), b"0005a");
        assert_eq!(&pkt_line(b"# service=git-upload-pack\n")[..4], b"001e");
    }

    #[test]
    fn upload_pack_advertisement_has_service_header() {
        let dir = std::env::temp_dir().join(format!("secgit-git-adv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bare = dir.join("repo.git");
        git(&dir, &["init", "--bare", "--quiet", bare.to_str().unwrap()]);

        let adv = advertise_refs(&bare, Service::UploadPack).unwrap();
        // An empty bare repo yields a short advertisement, so scan the whole body
        // rather than a fixed-length prefix.
        let head = String::from_utf8_lossy(&adv);
        assert!(head.contains("# service=git-upload-pack"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn service_parse_and_content_types() {
        assert_eq!(
            Service::parse("git-receive-pack").unwrap(),
            Service::ReceivePack
        );
        assert!(Service::parse("git-evil").is_err());
        assert_eq!(
            Service::UploadPack.advertise_content_type(),
            "application/x-git-upload-pack-advertisement"
        );
    }

    /// On timeout, `run_bounded` must kill the whole process group, not just the direct
    /// child — so a backgrounded grandchild (standing in for `git pack-objects`) dies too.
    #[cfg(unix)]
    #[test]
    fn timeout_kills_whole_process_group() {
        let dir = std::env::temp_dir().join(format!("secgit-git-pgroup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("grandchild.pid");

        // The direct child (`sh`) backgrounds a long `sleep` (the grandchild), records its
        // pid, then blocks in `wait`. Only a process-group kill reaches the grandchild.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("sleep 300 & echo $! > {}; wait", pidfile.display()));
        let limits = GitLimits {
            wall_clock: Duration::from_millis(300),
            ..GitLimits::default()
        };
        let start = Instant::now();
        let res = run_bounded(cmd, None, &limits);
        assert!(res.is_err(), "expected a wall-clock timeout error");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout should fire promptly"
        );

        let pid = read_pid(&pidfile);
        assert!(
            !pid_alive_within(pid, Duration::from_secs(3)),
            "grandchild pid {pid} must be killed with the group"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn read_pid(pidfile: &Path) -> i32 {
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(pidfile) {
                if let Ok(pid) = s.trim().parse::<i32>() {
                    return pid;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("grandchild never recorded its pid");
    }

    /// Returns false once `kill(pid, 0)` reports the pid is gone (ESRCH), polling up to
    /// `budget` to allow the reaper to clear the zombie after SIGKILL.
    #[cfg(unix)]
    fn pid_alive_within(pid: i32, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            // SAFETY: signal 0 performs existence/permission checks only, no delivery.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return false;
            }
            if Instant::now() >= deadline {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
