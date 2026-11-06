//! Verifies a COMAR publication the way a TAF client would, using `tough` as the TUF client.
//!
//! A TAF "authentication repository" is a git repository whose tree holds ordinary TUF
//! metadata (`metadata/*.json`) and target files (`targets/...`). For each content repository
//! there is a target file such as `targets/maryland-dsd/law-xml-codified` containing the git
//! commit the publisher signed off on. So verification is:
//!
//! 1. fetch the authentication repository and take the tip of its branch,
//! 2. run a full TUF client update against the files in that commit (root rotation, threshold
//!    signatures, snapshot/timestamp consistency, delegations, target hashes),
//! 3. read the signed target for the content repository to learn the authenticated commit,
//! 4. fetch the content repository from the signed mirror list and read files only from that
//!    commit's tree, which git content-addresses.

use crate::git::{self, ObjectId};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use jiff::Timestamp;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tough::{
    ExpirationEnforcement, IntoVec, Repository, RepositoryLoader, TargetName, Transport,
    TransportError, TransportErrorKind, TransportStream,
};
use url::Url;

const SCHEME: &str = "taf-git";

/// What to do about expired TUF metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExpirationPolicy {
    /// Standard TUF: refuse to serve if any role has expired.
    Strict,
    /// Require the online `timestamp` and `snapshot` roles to be current (which shows the
    /// publisher is still signing), but only warn about expired offline roles. This matches how
    /// legal publishers using TAF treat signatures as archival attestations.
    Archival,
    /// Verify signatures and hashes but ignore every expiration date.
    Ignore,
}

#[derive(Debug, Clone)]
pub struct TafConfig {
    pub auth_repo_url: String,
    pub auth_branch: String,
    pub content_repo: String,
    pub trusted_root: Vec<u8>,
    pub data_dir: PathBuf,
    pub expiration: ExpirationPolicy,
    pub fetch: bool,
}

/// Metadata about one TUF role as it was verified.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoleStatus {
    pub role: String,
    pub version: u64,
    pub expires: Timestamp,
    pub expired: bool,
}

/// The result of a successful verification.
#[derive(Clone)]
pub struct Publication {
    pub auth_repo_url: String,
    pub auth_commit: ObjectId,
    pub auth_commit_time: Timestamp,
    pub content_repo: String,
    pub content_repo_url: String,
    pub content_commit: ObjectId,
    /// The rest of the signed target file (branch, build-date, codified-date, ...).
    pub content_target: BTreeMap<String, serde_json::Value>,
    pub roles: Vec<RoleStatus>,
    pub verified_at: Timestamp,
    pub warnings: Vec<String>,
    pub content: gix::ThreadSafeRepository,
}

impl Publication {
    pub fn target_field(&self, key: &str) -> Option<&str> {
        self.content_target.get(key).and_then(|v| v.as_str())
    }
}

#[derive(Deserialize)]
struct CommitTarget {
    commit: String,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Repositories {
    repositories: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Mirrors {
    mirrors: Vec<String>,
}

/// Serves `taf-git:///<path>` from the tree of one commit of the authentication repository.
#[derive(Clone)]
struct GitCommitTransport {
    repo: gix::ThreadSafeRepository,
    commit: ObjectId,
}

impl std::fmt::Debug for GitCommitTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitCommitTransport")
            .field("commit", &self.commit)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Transport for GitCommitTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        if url.scheme() != SCHEME {
            return Err(TransportError::new(TransportErrorKind::UnsupportedUrlScheme, url));
        }
        let path = percent_encoding::percent_decode_str(url.path().trim_start_matches('/'))
            .decode_utf8()
            .map_err(|e| TransportError::new_with_cause(TransportErrorKind::Other, url.clone(), e))?
            .into_owned();
        let (repo, commit) = (self.repo.clone(), self.commit);
        let result =
            tokio::task::spawn_blocking(move || git::read_file(&repo.to_thread_local(), commit, &path))
                .await
                .map_err(|e| TransportError::new_with_cause(TransportErrorKind::Other, url.clone(), e))?;
        match result {
            Ok(Some(data)) => Ok(Box::pin(futures::stream::iter([Ok(Bytes::from(data))]))),
            Ok(None) => Err(TransportError::new(TransportErrorKind::FileNotFound, url)),
            Err(e) => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url,
                std::io::Error::other(format!("{e:#}")),
            )),
        }
    }
}

pub async fn verify(cfg: &TafConfig) -> Result<Publication> {
    let auth_dir = cfg.data_dir.join("repos").join(repo_dir_name(&cfg.auth_repo_url));
    let (auth_url, fetch) = (cfg.auth_repo_url.clone(), cfg.fetch);
    let auth = tokio::task::spawn_blocking(move || git::open_or_clone(&auth_url, &auth_dir, fetch))
        .await??;
    let (auth_commit, auth_commit_time) = {
        let repo = auth.to_thread_local();
        let commit = git::branch_tip(&repo, &cfg.auth_branch)?;
        (commit, Timestamp::from_second(git::commit_time(&repo, commit)?)?)
    };
    tracing::info!(%auth_commit, "verifying authentication repository");

    let datastore = cfg.data_dir.join("tuf-datastore");
    std::fs::create_dir_all(&datastore)?;
    let tuf = RepositoryLoader::new(
        &cfg.trusted_root,
        Url::parse(&format!("{SCHEME}:///metadata/"))?,
        Url::parse(&format!("{SCHEME}:///targets/"))?,
    )
    .transport(GitCommitTransport { repo: auth.clone(), commit: auth_commit })
    // Expiration is enforced below according to the configured policy, so that an archival
    // deployment still verifies every signature and hash.
    .expiration_enforcement(ExpirationEnforcement::Unsafe)
    .datastore(datastore)
    .load()
    .await
    .context("TUF verification of the authentication repository failed")?;

    let now = Timestamp::now();
    let roles = role_statuses(&tuf, &cfg.content_repo, now)?;
    let mut warnings = Vec::new();
    for r in roles.iter().filter(|r| r.expired) {
        let online = r.role == "timestamp" || r.role == "snapshot";
        let fatal = match cfg.expiration {
            ExpirationPolicy::Strict => true,
            ExpirationPolicy::Archival => online,
            ExpirationPolicy::Ignore => false,
        };
        let msg = format!("TUF role '{}' v{} expired at {}", r.role, r.version, r.expires);
        if fatal {
            bail!("{msg} (expiration policy: {:?})", cfg.expiration);
        }
        warnings.push(msg);
    }

    let repos: Repositories = read_json_target(&tuf, "repositories.json").await?;
    if !repos.repositories.contains_key(&cfg.content_repo) {
        bail!("{} is not listed in the signed repositories.json", cfg.content_repo);
    }
    let target: CommitTarget = read_json_target(&tuf, &cfg.content_repo).await?;
    let content_commit = ObjectId::from_hex(target.commit.as_bytes())
        .with_context(|| format!("bad commit in signed target: {}", target.commit))?;
    let mirrors: Mirrors = read_json_target(&tuf, "mirrors.json").await?;
    let content_repo_url = https_mirror(&mirrors, &cfg.content_repo)?;

    let content_dir = cfg.data_dir.join("repos").join(&cfg.content_repo);
    let url = content_repo_url.clone();
    let content = tokio::task::spawn_blocking(move || {
        let repo = git::open_or_clone(&url, &content_dir, fetch)?;
        repo.to_thread_local()
            .find_commit(content_commit)
            .with_context(|| format!("signed commit {content_commit} is not available from {url}"))?;
        anyhow::Ok(repo)
    })
    .await??;

    Ok(Publication {
        auth_repo_url: cfg.auth_repo_url.clone(),
        auth_commit,
        auth_commit_time,
        content_repo: cfg.content_repo.clone(),
        content_repo_url,
        content_commit,
        content_target: target.rest,
        roles,
        verified_at: now,
        warnings,
        content,
    })
}

async fn read_json_target<T: serde::de::DeserializeOwned>(tuf: &Repository, name: &str) -> Result<T> {
    let target = TargetName::new(name)?;
    let stream = tuf
        .read_target(&target)
        .await?
        .ok_or_else(|| anyhow!("target {name} is not signed by any TUF role"))?;
    // into_vec fails if the length or hashes don't match the signed metadata.
    let bytes = stream.into_vec().await.with_context(|| format!("target {name} failed verification"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing target {name}"))
}

fn role_statuses(tuf: &Repository, content_repo: &str, now: Timestamp) -> Result<Vec<RoleStatus>> {
    let status = |role: &str, version: std::num::NonZeroU64, expires: Timestamp| RoleStatus {
        role: role.to_owned(),
        version: version.get(),
        expires,
        expired: expires <= now,
    };
    let mut roles = vec![
        status("root", tuf.root().signed.version, tuf.root().signed.expires),
        status("timestamp", tuf.timestamp().signed.version, tuf.timestamp().signed.expires),
        status("snapshot", tuf.snapshot().signed.version, tuf.snapshot().signed.expires),
        status("targets", tuf.targets().signed.version, tuf.targets().signed.expires),
    ];
    // Include the delegated role that signs the content repository's target, if any.
    let name = TargetName::new(content_repo)?;
    for role in tuf.targets().signed.delegations.iter().flat_map(|d| &d.roles) {
        if let Some(t) = role.targets.as_ref().filter(|t| t.signed.targets.contains_key(&name)) {
            roles.push(status(&role.name, t.signed.version, t.signed.expires));
        }
    }
    Ok(roles)
}

fn https_mirror(mirrors: &Mirrors, repo: &str) -> Result<String> {
    let (org, name) = repo
        .split_once('/')
        .ok_or_else(|| anyhow!("repository name {repo} is not org/name"))?;
    mirrors
        .mirrors
        .iter()
        .find(|m| m.starts_with("https://"))
        .map(|m| m.replace("{org_name}", org).replace("{repo_name}", name))
        .ok_or_else(|| anyhow!("signed mirrors.json has no https mirror"))
}

fn repo_dir_name(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit('/')
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/")
}
