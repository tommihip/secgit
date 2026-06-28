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

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitHttpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("git service failed: {0}")]
    Service(String),
    #[error("unknown service: {0}")]
    UnknownService(String),
}

pub type Result<T> = core::result::Result<T, GitHttpError>;

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
    let output = Command::new("git")
        .args([service.subcommand(), "--stateless-rpc", "--advertise-refs"])
        .arg(repo)
        .output()?;
    if !output.status.success() {
        return Err(GitHttpError::Service(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(
        format!("# service={}\n", service.name()).as_bytes(),
    ));
    body.extend_from_slice(flush_pkt());
    body.extend_from_slice(&output.stdout);
    Ok(body)
}

/// Drive a stateless-rpc exchange: feed `body` to the service and return its output.
///
/// For [`Service::ReceivePack`] this performs the actual ref update (push). Callers
/// MUST authorize the request first and re-seal the repo to encrypted storage after.
pub fn rpc(repo: &Path, service: Service, body: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args([service.subcommand(), "--stateless-rpc"])
        .arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("piped stdin").write_all(body)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(GitHttpError::Service(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(output.stdout)
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
}
