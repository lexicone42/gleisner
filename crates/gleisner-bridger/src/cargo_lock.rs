//! Cargo.lock parser.
//!
//! Extracts package entries from a Cargo.lock file. Each entry records the
//! package name, version, source (crates.io, git, or path), and optional
//! checksum.

use std::path::Path;

use serde::Deserialize;

use crate::error::SbomError;

/// A single package entry from Cargo.lock.
#[derive(Debug, Clone)]
pub struct CargoPackage {
    /// Crate name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// Source URL (e.g. `registry+https://github.com/rust-lang/crates.io-index`).
    /// `None` for path dependencies.
    pub source: Option<String>,
    /// SHA-256 checksum from the registry, if present.
    pub checksum: Option<String>,
}

impl CargoPackage {
    /// Whether this package comes from crates.io.
    pub fn is_crates_io(&self) -> bool {
        self.source
            .as_deref()
            .is_some_and(|s| s.contains("crates.io-index"))
    }

    /// Whether this package is a path dependency.
    pub const fn is_path_dep(&self) -> bool {
        self.source.is_none()
    }

    /// Whether this package is a git dependency.
    pub fn is_git_dep(&self) -> bool {
        self.source
            .as_deref()
            .is_some_and(|s| s.starts_with("git+"))
    }
}

/// Raw TOML structure of a Cargo.lock file.
#[derive(Deserialize)]
struct CargoLockFile {
    package: Vec<RawPackage>,
}

/// A raw `[[package]]` entry in Cargo.lock.
#[derive(Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Parse a Cargo.lock file and return the list of packages.
pub fn parse_cargo_lock(path: &Path) -> Result<Vec<CargoPackage>, SbomError> {
    let content = std::fs::read_to_string(path).map_err(|e| SbomError::ParseError {
        path: path.display().to_string(),
        reason: format!("cannot read file: {e}"),
    })?;

    let lock_file: CargoLockFile = toml::from_str(&content).map_err(|e| SbomError::ParseError {
        path: path.display().to_string(),
        reason: format!("invalid TOML: {e}"),
    })?;

    let packages = lock_file
        .package
        .into_iter()
        .map(|raw| CargoPackage {
            name: raw.name,
            version: raw.version,
            source: raw.source,
            checksum: raw.checksum,
        })
        .collect();

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_minimal_lock() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"
version = 4

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "bar"
version = "0.2.0"
"#
        )
        .unwrap();

        let packages = parse_cargo_lock(tmp.path()).unwrap();
        assert_eq!(packages.len(), 2);

        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.0.0");
        assert!(packages[0].is_crates_io());
        assert_eq!(packages[0].checksum.as_deref(), Some("abc123"));

        assert_eq!(packages[1].name, "bar");
        assert_eq!(packages[1].version, "0.2.0");
        assert!(packages[1].is_path_dep());
    }

    #[test]
    fn parse_git_dependency() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"
version = 4

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/example/repo#abc123"
"#
        )
        .unwrap();

        let packages = parse_cargo_lock(tmp.path()).unwrap();
        assert_eq!(packages.len(), 1);
        assert!(packages[0].is_git_dep());
        assert!(!packages[0].is_crates_io());
    }

    #[test]
    fn missing_file_returns_error() {
        let result = parse_cargo_lock(Path::new("/nonexistent/Cargo.lock"));
        assert!(result.is_err());
    }
}
