//! Local bare mirrors of TAF repositories, read directly from the object database.
//!
//! Nothing is ever checked out. Every file we use is looked up by path inside the tree of a
//! specific commit, so the bytes we read are bound to that commit's hash.

use anyhow::{Context, Result, anyhow, bail};
use std::path::Path;
use std::sync::atomic::AtomicBool;

pub use gix::ObjectId;

/// Opens the bare mirror at `dir`, cloning it from `url` if it does not exist yet.
/// When `fetch` is true an existing mirror is brought up to date first.
pub fn open_or_clone(url: &str, dir: &Path, fetch: bool) -> Result<gix::ThreadSafeRepository> {
    if dir.join("HEAD").exists() {
        let repo = gix::open(dir).with_context(|| format!("opening {}", dir.display()))?;
        if fetch {
            fetch_all(&repo).with_context(|| format!("fetching {url}"))?;
        }
        return Ok(repo.into_sync());
    }
    if !fetch {
        bail!("no local copy of {url} at {} (and fetching is disabled)", dir.display());
    }
    std::fs::create_dir_all(dir)?;
    tracing::info!(%url, dir = %dir.display(), "cloning");
    let mut prepare = gix::prepare_clone_bare(url, dir)?;
    let (repo, _) = prepare
        .fetch_only(gix::progress::Discard, &AtomicBool::new(false))
        .with_context(|| format!("cloning {url}"))?;
    Ok(repo.into_sync())
}

fn fetch_all(repo: &gix::Repository) -> Result<()> {
    // A bare clone doesn't persist its refspec, so mirror the branches explicitly. History
    // rewrites upstream are fine here: TUF's own version checks catch rollbacks.
    let remote = repo
        .find_default_remote(gix::remote::Direction::Fetch)
        .ok_or_else(|| anyhow!("repository has no remote"))??
        .with_refspecs(["+refs/heads/*:refs/heads/*"], gix::remote::Direction::Fetch)?;
    remote
        .connect(gix::remote::Direction::Fetch)?
        .prepare_fetch(gix::progress::Discard, Default::default())?
        .receive(gix::progress::Discard, &AtomicBool::new(false))?;
    Ok(())
}

/// Resolves a branch name to the commit it currently points at.
pub fn branch_tip(repo: &gix::Repository, branch: &str) -> Result<ObjectId> {
    for name in [
        format!("refs/heads/{branch}"),
        format!("refs/remotes/origin/{branch}"),
    ] {
        if let Some(mut reference) = repo.try_find_reference(name.as_str())? {
            return Ok(reference.peel_to_id()?.detach());
        }
    }
    bail!("branch {branch} not found")
}

/// Returns the contents of `path` in the tree of `commit`, or `None` if there is no such file.
pub fn read_file(repo: &gix::Repository, commit: ObjectId, path: &str) -> Result<Option<Vec<u8>>> {
    let tree = repo
        .find_commit(commit)
        .with_context(|| format!("commit {commit} is not in the local mirror"))?
        .tree()?;
    let Some(entry) = tree.lookup_entry_by_path(path)? else {
        return Ok(None);
    };
    if !entry.mode().is_blob() {
        return Ok(None);
    }
    Ok(Some(entry.object()?.detach().data))
}

/// One entry of a git tree.
pub struct DirEntry {
    pub name: String,
    pub id: ObjectId,
    pub is_dir: bool,
}

/// Lists the tree found at `path` (relative to the commit root).
pub fn list_dir(repo: &gix::Repository, commit: ObjectId, path: &str) -> Result<Vec<DirEntry>> {
    let root = repo.find_commit(commit)?.tree()?;
    let entry = root
        .lookup_entry_by_path(path)?
        .ok_or_else(|| anyhow!("{path} not found in commit {commit}"))?;
    list_tree(repo, entry.object_id())
}

pub fn list_tree(repo: &gix::Repository, tree: ObjectId) -> Result<Vec<DirEntry>> {
    let tree = repo.find_tree(tree)?;
    let mut out = Vec::new();
    for entry in tree.iter() {
        let entry = entry?;
        out.push(DirEntry {
            name: entry.filename().to_string(),
            id: entry.oid().to_owned(),
            is_dir: entry.mode().is_tree(),
        });
    }
    Ok(out)
}

pub fn read_blob(repo: &gix::Repository, id: ObjectId) -> Result<Vec<u8>> {
    Ok(repo.find_blob(id)?.detach().data)
}

/// The committer time of `commit`, as seconds since the epoch.
pub fn commit_time(repo: &gix::Repository, commit: ObjectId) -> Result<i64> {
    Ok(repo.find_commit(commit)?.time()?.seconds)
}
