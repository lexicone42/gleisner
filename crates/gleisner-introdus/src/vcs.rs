//! Git state capture for attestation materials.
//!
//! Captures the current git commit, branch, dirty state, and remote URL
//! to include as materials in the attestation statement.

use std::path::Path;
use std::process::Command;

use gix::discover;

use crate::error::AttestationError;
use crate::provenance::Material;
use crate::statement::DigestSet;

/// Snapshot of git repository state at a point in time.
#[derive(Debug, Clone)]
pub struct GitState {
    /// Full commit hash (hex-encoded SHA-1).
    pub commit: String,
    /// Current branch name, if on a branch (detached HEAD → `None`).
    pub branch: Option<String>,
    /// Whether the working tree has uncommitted changes.
    pub dirty: bool,
    /// Remote URL of `origin`, if configured.
    pub remote_url: Option<String>,
}

impl GitState {
    /// Convert this git state into an in-toto [`Material`].
    ///
    /// The URI follows the `git+{remote}@{commit}` convention.
    /// If no remote is configured, uses `git+local@{commit}`.
    #[must_use]
    pub fn to_material(&self) -> Material {
        let base = self.remote_url.as_deref().unwrap_or("local");
        Material {
            uri: format!("git+{base}@{}", self.commit),
            digest: DigestSet {
                sha256: self.commit.clone(),
            },
        }
    }
}

/// Capture the current git state for a project directory.
///
/// Uses `gix` for commit hash, branch, and remote URL discovery,
/// and shells out to `git status --porcelain` for dirty detection
/// (gix "basic" feature lacks working-tree status).
///
/// # Errors
///
/// Returns [`AttestationError::GitError`] if the directory is not
/// a git repository or the HEAD commit cannot be read.
pub fn capture(project_dir: &Path) -> Result<GitState, AttestationError> {
    let repo = discover(project_dir)
        .map_err(|e| AttestationError::GitError(format!("failed to discover git repo: {e}")))?;

    // HEAD commit hash
    let head = repo
        .head_commit()
        .map_err(|e| AttestationError::GitError(format!("failed to read HEAD commit: {e}")))?;
    let commit = head.id.to_hex().to_string();

    // Branch name (None if detached HEAD)
    let branch = repo
        .head_name()
        .map_err(|e| AttestationError::GitError(format!("failed to read HEAD ref: {e}")))?
        .map(|name| name.shorten().to_string());

    // Remote URL for "origin"
    let remote_url = repo.find_remote("origin").ok().and_then(|remote| {
        remote
            .url(gix::remote::Direction::Fetch)
            .map(|url| url.to_bstring().to_string())
    });

    // Dirty detection via git CLI (gix basic doesn't support status)
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(project_dir)
        .output()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);

    Ok(GitState {
        commit,
        branch,
        dirty,
        remote_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Create a temporary git repo with an initial commit.
    fn init_test_repo(dir: &Path) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .expect("git init failed");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .expect("git config email failed");

        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .expect("git config name failed");

        std::fs::write(dir.join("README.md"), "# test\n").expect("write failed");

        Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add failed");

        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir)
            .output()
            .expect("git commit failed");
    }

    #[test]
    fn capture_clean_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        init_test_repo(tmp.path());

        let state = capture(tmp.path()).expect("capture should succeed");

        assert_eq!(state.commit.len(), 40, "commit should be a 40-char hex SHA");
        assert!(
            state.commit.chars().all(|c| c.is_ascii_hexdigit()),
            "commit should be hex"
        );
        assert!(!state.dirty, "clean repo should not be dirty");
        // Default branch varies (main/master), but should be present
        assert!(state.branch.is_some(), "should be on a branch");
    }

    #[test]
    fn capture_dirty_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        init_test_repo(tmp.path());

        // Create an untracked file to make it dirty
        std::fs::write(tmp.path().join("dirty.txt"), "dirty\n").expect("write failed");

        let state = capture(tmp.path()).expect("capture should succeed");
        assert!(state.dirty, "repo with untracked file should be dirty");
    }

    #[test]
    fn to_material_with_no_remote() {
        let state = GitState {
            commit: "abc123def456".to_owned(),
            branch: Some("main".to_owned()),
            dirty: false,
            remote_url: None,
        };

        let mat = state.to_material();
        assert_eq!(mat.uri, "git+local@abc123def456");
        assert_eq!(mat.digest.sha256, "abc123def456");
    }

    #[test]
    fn to_material_with_remote() {
        let state = GitState {
            commit: "abc123".to_owned(),
            branch: Some("main".to_owned()),
            dirty: false,
            remote_url: Some("https://github.com/user/repo.git".to_owned()),
        };

        let mat = state.to_material();
        assert_eq!(mat.uri, "git+https://github.com/user/repo.git@abc123");
    }

    #[test]
    fn capture_not_a_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = capture(tmp.path());
        assert!(result.is_err(), "non-repo should fail");
    }
}
