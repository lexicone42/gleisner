//! `CycloneDX` 1.5 output format.
//!
//! Generates SBOM documents conforming to the `CycloneDX` 1.5 specification
//! in JSON format. Covers the subset needed for Cargo dependency reporting:
//! components with Package URLs and SHA-256 hashes.

use chrono::Utc;
use serde::Serialize;

use crate::cargo_lock::CargoPackage;

/// Top-level `CycloneDX` 1.5 BOM document.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    /// Always `"CycloneDX"`.
    pub bom_format: &'static str,
    /// Specification version.
    pub spec_version: &'static str,
    /// BOM version (incremented on updates).
    pub version: u32,
    /// Unique serial number for this BOM instance.
    pub serial_number: String,
    /// BOM metadata.
    pub metadata: Metadata,
    /// List of components (dependencies).
    pub components: Vec<Component>,
}

/// BOM metadata block.
#[derive(Debug, Serialize)]
pub struct Metadata {
    /// ISO-8601 timestamp of generation.
    pub timestamp: String,
    /// Tool that generated the BOM.
    pub tools: Vec<Tool>,
}

/// Tool descriptor.
#[derive(Debug, Serialize)]
pub struct Tool {
    /// Tool vendor.
    pub vendor: String,
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
}

/// A single software component in the BOM.
#[derive(Debug, Serialize)]
pub struct Component {
    /// Component type (always `"library"` for Cargo dependencies).
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Package URL.
    pub purl: String,
    /// Cryptographic hashes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
}

/// A cryptographic hash.
#[derive(Debug, Serialize)]
pub struct Hash {
    /// Algorithm name (e.g. `"SHA-256"`).
    pub alg: String,
    /// Hex-encoded hash value.
    pub content: String,
}

/// Generate a Package URL for a Cargo package.
///
/// For crates.io packages: `pkg:cargo/name@version`
/// For git deps: `pkg:cargo/name@version?vcs_url=<source>`
/// For path deps: `pkg:cargo/name@version` (no qualifier)
pub fn to_purl(pkg: &CargoPackage) -> String {
    let base = format!("pkg:cargo/{}@{}", pkg.name, pkg.version);
    if pkg.is_git_dep() {
        if let Some(source) = &pkg.source {
            // Strip "git+" prefix for the VCS URL
            let vcs_url = source.strip_prefix("git+").unwrap_or(source);
            return format!("{base}?vcs_url={vcs_url}");
        }
    }
    base
}

/// Generate a deterministic serial number from the BOM content.
///
/// Uses a SHA-256 hash of the component list formatted as a UUID v4-style URN.
fn generate_serial_number(packages: &[CargoPackage]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for pkg in packages {
        hasher.update(pkg.name.as_bytes());
        hasher.update(b"@");
        hasher.update(pkg.version.as_bytes());
        hasher.update(b"\n");
    }
    let hash = hasher.finalize();
    let hex = hex::encode(&hash[..16]);
    // Format as urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..28]
    )
}

/// Convert a list of Cargo packages into a `CycloneDX` 1.5 BOM.
pub fn to_cyclonedx(packages: &[CargoPackage]) -> CycloneDxBom {
    let components = packages
        .iter()
        .map(|pkg| {
            let hashes = pkg
                .checksum
                .as_ref()
                .map(|c| {
                    vec![Hash {
                        alg: "SHA-256".to_owned(),
                        content: c.clone(),
                    }]
                })
                .unwrap_or_default();

            Component {
                type_: "library",
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                purl: to_purl(pkg),
                hashes,
            }
        })
        .collect();

    CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        serial_number: generate_serial_number(packages),
        metadata: Metadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![Tool {
                vendor: "Gleisner".to_owned(),
                name: "gleisner-bridger".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }],
        },
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packages() -> Vec<CargoPackage> {
        vec![
            CargoPackage {
                name: "serde".to_owned(),
                version: "1.0.200".to_owned(),
                source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
                checksum: Some("abcdef1234567890".to_owned()),
            },
            CargoPackage {
                name: "my-local".to_owned(),
                version: "0.1.0".to_owned(),
                source: None,
                checksum: None,
            },
        ]
    }

    #[test]
    fn purl_crates_io() {
        let pkg = &sample_packages()[0];
        assert_eq!(to_purl(pkg), "pkg:cargo/serde@1.0.200");
    }

    #[test]
    fn purl_path_dep() {
        let pkg = &sample_packages()[1];
        assert_eq!(to_purl(pkg), "pkg:cargo/my-local@0.1.0");
    }

    #[test]
    fn purl_git_dep() {
        let pkg = CargoPackage {
            name: "gitcrate".to_owned(),
            version: "0.1.0".to_owned(),
            source: Some("git+https://github.com/example/repo#abc123".to_owned()),
            checksum: None,
        };
        assert_eq!(
            to_purl(&pkg),
            "pkg:cargo/gitcrate@0.1.0?vcs_url=https://github.com/example/repo#abc123"
        );
    }

    #[test]
    fn cyclonedx_structure() {
        let bom = to_cyclonedx(&sample_packages());
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert_eq!(bom.version, 1);
        assert!(bom.serial_number.starts_with("urn:uuid:"));
        assert_eq!(bom.components.len(), 2);
        assert_eq!(bom.components[0].type_, "library");
        assert_eq!(bom.components[0].name, "serde");
        assert_eq!(bom.components[0].hashes.len(), 1);
        assert_eq!(bom.components[1].hashes.len(), 0);
    }

    #[test]
    fn cyclonedx_serializes_to_json() {
        let bom = to_cyclonedx(&sample_packages());
        let json = serde_json::to_string_pretty(&bom).unwrap();
        assert!(json.contains("\"bomFormat\""));
        assert!(json.contains("\"specVersion\""));
        assert!(json.contains("\"pkg:cargo/serde@1.0.200\""));
    }

    #[test]
    fn serial_number_is_deterministic() {
        let pkgs = sample_packages();
        let s1 = generate_serial_number(&pkgs);
        let s2 = generate_serial_number(&pkgs);
        assert_eq!(s1, s2);
    }
}
