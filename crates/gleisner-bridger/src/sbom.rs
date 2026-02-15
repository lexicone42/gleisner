//! Top-level SBOM generation.
//!
//! Orchestrates lockfile discovery, parsing, and `CycloneDX` output.

use std::path::{Path, PathBuf};

use crate::cargo_lock;
use crate::cyclonedx::{self, CycloneDxBom};
use crate::error::SbomError;

/// Find `Cargo.lock` starting from `dir`, walking up to the filesystem root.
fn find_cargo_lock(dir: &Path) -> Option<PathBuf> {
    let mut current = dir.to_path_buf();
    loop {
        let candidate = current.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Generate a `CycloneDX` 1.5 SBOM for the project at `project_dir`.
///
/// Finds and parses `Cargo.lock`, then converts to `CycloneDX` format.
/// Walks up from `project_dir` to find the lockfile if it isn't in
/// the given directory directly.
pub fn generate(project_dir: &Path) -> Result<CycloneDxBom, SbomError> {
    let lock_path = find_cargo_lock(project_dir).ok_or_else(|| SbomError::ParseError {
        path: project_dir.display().to_string(),
        reason: "no Cargo.lock found in directory or any parent".to_owned(),
    })?;

    let packages = cargo_lock::parse_cargo_lock(&lock_path)?;
    Ok(cyclonedx::to_cyclonedx(&packages))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn generate_from_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("Cargo.lock");
        let mut f = std::fs::File::create(&lock_path).unwrap();
        write!(
            f,
            r#"
version = 4

[[package]]
name = "example"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"
"#
        )
        .unwrap();

        let bom = generate(dir.path()).unwrap();
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.components[0].name, "example");
        assert_eq!(bom.components[0].purl, "pkg:cargo/example@0.1.0");
    }

    #[test]
    fn find_lock_in_parent() {
        let parent = tempfile::tempdir().unwrap();
        let child = parent.path().join("subdir");
        std::fs::create_dir(&child).unwrap();

        let lock_path = parent.path().join("Cargo.lock");
        let mut f = std::fs::File::create(&lock_path).unwrap();
        write!(
            f,
            r#"
version = 4

[[package]]
name = "parent-dep"
version = "2.0.0"
"#
        )
        .unwrap();

        let bom = generate(&child).unwrap();
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.components[0].name, "parent-dep");
    }

    #[test]
    fn no_cargo_lock_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate(dir.path());
        assert!(result.is_err());
    }
}
