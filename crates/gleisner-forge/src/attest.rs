//! Attestation material/subject extraction from forge evaluation results.
//!
//! Converts the content-addressed store entries and source declarations
//! from Nickel packages into SLSA-compatible materials and subjects that
//! gleisner-introdus can assemble into an `InTotoStatement`.
//!
//! # Package metadata enrichment
//!
//! The minimal.dev package format declares structured supply chain metadata
//! in `attrs` fields:
//! - `source_provenance`: Authoritative source (GitHub repo, GNU project)
//! - `upstream_version`: The software version from upstream
//! - `repology_project`: Cross-distro version tracking identifier
//!
//! These are extracted per-package and collected into [`PackageMetadata`]
//! for SBOM enrichment and provenance attestation.

use std::collections::HashMap;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::compose::ComposedEnvironment;
use crate::orchestrate::ForgeOutput;

/// A material (input artifact) for attestation.
///
/// Compatible with `gleisner_introdus::provenance::Material`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForgeMaterial {
    /// URI identifying the material.
    pub uri: String,
    /// SHA-256 hex digest of the material.
    pub sha256: String,
}

/// A subject (output artifact) for attestation.
///
/// Compatible with `gleisner_introdus::statement::Subject`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForgeSubject {
    /// Artifact name or path.
    pub name: String,
    /// SHA-256 hex digest of the subject.
    pub sha256: String,
}

/// Attestation data extracted from a forge evaluation run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForgeAttestation {
    /// Input materials: source tarballs declared in packages + Nickel source files.
    pub materials: Vec<ForgeMaterial>,
    /// Output subjects: content-addressed evaluation results.
    pub subjects: Vec<ForgeSubject>,
    /// Builder identifier.
    pub builder_id: String,
    /// Packages that contributed to this attestation.
    pub packages: Vec<String>,
    /// Per-package supply chain metadata extracted from `attrs`.
    pub package_metadata: Vec<PackageMetadata>,
}

/// Source provenance for a package.
///
/// Mirrors minimal.dev's `source_provenance` attr classes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "category")]
pub enum SourceProvenance {
    /// Hosted on GitHub.
    #[serde(rename = "GithubRepo")]
    GithubRepo {
        /// Repository owner (user or org).
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// A GNU project.
    #[serde(rename = "GnuProject")]
    GnuProject {
        /// GNU project name.
        name: String,
    },
}

/// Per-package supply chain metadata extracted from minimal.dev `attrs`.
///
/// Contains the structured provenance fields that minimal.dev's type system
/// guarantees: upstream version, source provenance (GitHub/GNU), and
/// repology cross-distro tracking. These feed into SBOM components and
/// attestation materials.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageMetadata {
    /// Package name.
    pub name: String,
    /// Upstream software version (from `attrs.upstream_version`).
    pub upstream_version: Option<String>,
    /// Authoritative source repository (from `attrs.source_provenance`).
    pub source_provenance: Option<SourceProvenance>,
    /// Repology project name for cross-distro version tracking.
    pub repology_project: Option<String>,
    /// Package URL (PURL) derived from source provenance.
    ///
    /// For GitHub-hosted packages: `pkg:github/owner/repo@version`
    /// For GNU projects: `pkg:gnu/name@version`
    /// Fallback: `pkg:generic/minimal.dev/name@version`
    pub purl: String,
    /// Source tarball URLs with SHA-256 digests (from `build_deps`).
    pub source_urls: Vec<ForgeMaterial>,
}

/// Extract attestation data from a forge output and the composed environment.
///
/// # Materials
///
/// Materials come from two sources:
/// 1. **Source tarballs**: Extracted from each package's `build_deps[]` entries
///    that have `url` + `sha256` fields (i.e., `Source` type in minimal's model).
/// 2. **Composed environment file**: The JSON output itself, hashed.
///
/// # Subjects
///
/// Each successfully evaluated package produces a content-addressed store entry.
/// The composed environment JSON is the primary subject.
///
/// # Package metadata
///
/// When `package_results` is provided, per-package supply chain metadata
/// (`source_provenance`, `upstream_version`, `repology_project`) is extracted
/// and included for SBOM enrichment.
pub fn extract_attestation(
    output: &ForgeOutput,
    composed_json: &serde_json::Value,
) -> ForgeAttestation {
    extract_attestation_with_results(output, composed_json, &HashMap::new())
}

/// Extract attestation with access to individual package evaluation results.
///
/// This is the richer variant that also extracts per-package metadata from
/// the evaluated JSON (source provenance, upstream version, repology project).
pub fn extract_attestation_with_results(
    output: &ForgeOutput,
    composed_json: &serde_json::Value,
    package_results: &HashMap<String, serde_json::Value>,
) -> ForgeAttestation {
    let mut materials = Vec::new();
    let mut subjects = Vec::new();
    let mut package_metadata = Vec::new();

    // Extract source materials from the composed environment's packages
    extract_source_materials(&output.environment, &mut materials);

    // Extract per-package metadata from evaluation results
    for pkg_name in &output.environment.packages {
        if let Some(json) = package_results.get(pkg_name) {
            package_metadata.push(extract_package_metadata(pkg_name, json));
        }
    }

    // The composed environment JSON is the primary subject
    let composed_bytes = serde_json::to_string(composed_json).unwrap_or_default();
    let composed_hash = sha256_hex(composed_bytes.as_bytes());
    subjects.push(ForgeSubject {
        name: "composed-env.json".to_string(),
        sha256: composed_hash,
    });

    // Store directory as a subject (for provenance tracking)
    if output.store_dir.exists() {
        subjects.push(ForgeSubject {
            name: format!("forge-store:{}", output.store_dir.display()),
            sha256: hash_directory_manifest(&output.store_dir),
        });
    }

    ForgeAttestation {
        materials,
        subjects,
        builder_id: format!("gleisner-forge/{}", env!("CARGO_PKG_VERSION")),
        packages: output.environment.packages.clone(),
        package_metadata,
    }
}

/// Extract source tarballs from evaluated package JSON stored in the environment.
///
/// Packages declare their source inputs as `build_deps` entries with `url` and
/// `sha256` fields. These are the supply chain anchors.
fn extract_source_materials(env: &ComposedEnvironment, materials: &mut Vec<ForgeMaterial>) {
    // Source materials are tracked per-package at eval time. Since the
    // ComposedEnvironment only contains merged attrs/needs (not full build_deps),
    // we note the package names as provenance anchors. The full source
    // extraction happens at the store level during `gleisner forge --record`.
    //
    // For now, record each contributing package as a material with a
    // pkg:// URI scheme (like PURL for package URLs).
    for pkg_name in &env.packages {
        materials.push(ForgeMaterial {
            uri: format!("pkg://minimal.dev/{pkg_name}"),
            sha256: String::new(), // Hash populated from store at record time
        });
    }
}

/// Extract structured supply chain metadata from an evaluated package's JSON.
///
/// Reads the `attrs.source_provenance`, `attrs.upstream_version`, and
/// `attrs.repology_project` fields that minimal.dev's type system enforces.
/// Generates a PURL (Package URL) from the provenance data.
pub fn extract_package_metadata(name: &str, json: &serde_json::Value) -> PackageMetadata {
    let attrs = json.get("attrs");

    let upstream_version = attrs
        .and_then(|a| a.get("upstream_version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let repology_project = attrs
        .and_then(|a| a.get("repology_project"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let source_provenance = attrs
        .and_then(|a| a.get("source_provenance"))
        .and_then(parse_source_provenance);

    let purl = make_purl(name, upstream_version.as_deref(), &source_provenance);
    let source_urls = extract_sources_from_package(name, json);

    PackageMetadata {
        name: name.to_string(),
        upstream_version,
        source_provenance,
        repology_project,
        purl,
        source_urls,
    }
}

/// Parse a `source_provenance` JSON value into our enum.
fn parse_source_provenance(value: &serde_json::Value) -> Option<SourceProvenance> {
    let category = value.get("category")?;
    // Nickel enum tags can serialize as "GithubRepo" or {"GithubRepo": {}}
    let cat_str = match category {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(map) => map.keys().next().map(String::as_str)?,
        _ => return None,
    };

    match cat_str {
        "GithubRepo" => {
            let owner = value.get("owner")?.as_str()?.to_string();
            let repo = value.get("repo")?.as_str()?.to_string();
            Some(SourceProvenance::GithubRepo { owner, repo })
        }
        "GnuProject" => {
            let name = value.get("name")?.as_str()?.to_string();
            Some(SourceProvenance::GnuProject { name })
        }
        _ => None,
    }
}

/// Generate a PURL from source provenance and version.
fn make_purl(name: &str, version: Option<&str>, provenance: &Option<SourceProvenance>) -> String {
    let version_suffix = version.map_or(String::new(), |v| format!("@{v}"));

    match provenance {
        Some(SourceProvenance::GithubRepo { owner, repo }) => {
            format!("pkg:github/{owner}/{repo}{version_suffix}")
        }
        Some(SourceProvenance::GnuProject { name: gnu_name }) => {
            format!("pkg:gnu/{gnu_name}{version_suffix}")
        }
        None => {
            format!("pkg:generic/minimal.dev/{name}{version_suffix}")
        }
    }
}

/// Extract source URLs and SHA-256 digests from evaluated package JSON.
///
/// Call this on individual package evaluation results (not the composed env)
/// to get fine-grained source material attestation.
pub fn extract_sources_from_package(name: &str, json: &serde_json::Value) -> Vec<ForgeMaterial> {
    let mut materials = Vec::new();

    // Look for build_deps entries with url + sha256 (Source type)
    if let Some(deps) = json.get("build_deps").and_then(|d| d.as_array()) {
        for dep in deps {
            if let (Some(url), Some(sha256)) = (
                dep.get("url").and_then(|u| u.as_str()),
                dep.get("sha256").and_then(|s| s.as_str()),
            ) {
                materials.push(ForgeMaterial {
                    uri: url.to_string(),
                    sha256: sha256.to_string(),
                });
            }
        }
    }

    // The package itself is a material
    materials.push(ForgeMaterial {
        uri: format!("pkg://minimal.dev/{name}"),
        sha256: String::new(),
    });

    materials
}

/// SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Hash a directory by listing all files and hashing their names + sizes.
///
/// This is a lightweight manifest hash — not a full content hash of every file.
fn hash_directory_manifest(dir: &PathBuf) -> String {
    let mut hasher = Sha256::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|e| {
                let meta = e.metadata().ok();
                let size = meta.map_or(0, |m| m.len());
                format!("{}:{size}", e.file_name().to_string_lossy())
            })
            .collect();
        names.sort();
        for name in &names {
            hasher.update(name.as_bytes());
            hasher.update(b"\n");
        }
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sources_from_package_json() {
        let json = serde_json::json!({
            "name": "curl",
            "build_deps": [
                {"file": "build.sh"},
                {
                    "url": "https://storage.googleapis.com/minimal-os/curl-8.17.0.tar.gz",
                    "sha256": "abc123def456",
                    "extract": true,
                }
            ]
        });

        let materials = extract_sources_from_package("curl", &json);

        // Source tarball + package itself
        assert_eq!(materials.len(), 2);
        assert!(materials[0].uri.contains("curl-8.17.0.tar.gz"));
        assert_eq!(materials[0].sha256, "abc123def456");
        assert_eq!(materials[1].uri, "pkg://minimal.dev/curl");
    }

    #[test]
    fn extract_attestation_produces_subjects() {
        let output = ForgeOutput {
            environment: ComposedEnvironment::new(),
            evaluated: 5,
            failed: 0,
            failed_packages: Vec::new(),
            elapsed: std::time::Duration::from_secs(1),
            store_dir: PathBuf::from("/nonexistent"), // Won't hash
            package_results: HashMap::new(),
        };

        let composed = serde_json::json!({"test": true});
        let attestation = extract_attestation(&output, &composed);

        // Should have the composed-env.json subject (store dir doesn't exist)
        assert_eq!(attestation.subjects.len(), 1);
        assert_eq!(attestation.subjects[0].name, "composed-env.json");
        assert!(!attestation.subjects[0].sha256.is_empty());
        assert!(attestation.builder_id.starts_with("gleisner-forge/"));
        assert!(attestation.package_metadata.is_empty()); // No results passed
    }

    #[test]
    fn extract_metadata_github_provenance() {
        let json = serde_json::json!({
            "name": "openssh",
            "attrs": {
                "upstream_version": "10.2p1",
                "repology_project": "openssh",
                "source_provenance": {
                    "category": "GithubRepo",
                    "owner": "openssh",
                    "repo": "openssh-portable",
                },
            },
            "build_deps": [
                {"file": "build.sh"},
                {
                    "url": "gs://minimal-staging-archives/openssh-10.2p1.tar.gz",
                    "sha256": "ccc42c04199",
                },
            ],
        });

        let meta = extract_package_metadata("openssh", &json);
        assert_eq!(meta.name, "openssh");
        assert_eq!(meta.upstream_version.as_deref(), Some("10.2p1"));
        assert_eq!(meta.repology_project.as_deref(), Some("openssh"));
        assert_eq!(
            meta.source_provenance,
            Some(SourceProvenance::GithubRepo {
                owner: "openssh".to_string(),
                repo: "openssh-portable".to_string(),
            })
        );
        assert_eq!(meta.purl, "pkg:github/openssh/openssh-portable@10.2p1");
        assert_eq!(meta.source_urls.len(), 2); // tarball + pkg://
    }

    #[test]
    fn extract_metadata_no_provenance_fallback() {
        let json = serde_json::json!({
            "name": "claude-code",
            "attrs": {},
        });

        let meta = extract_package_metadata("claude-code", &json);
        assert!(meta.upstream_version.is_none());
        assert!(meta.source_provenance.is_none());
        assert_eq!(meta.purl, "pkg:generic/minimal.dev/claude-code");
    }

    #[test]
    fn extract_metadata_gnu_provenance() {
        let json = serde_json::json!({
            "name": "bash",
            "attrs": {
                "upstream_version": "5.2",
                "repology_project": "bash",
                "source_provenance": {
                    "category": "GnuProject",
                    "name": "bash",
                },
            },
        });

        let meta = extract_package_metadata("bash", &json);
        assert_eq!(
            meta.source_provenance,
            Some(SourceProvenance::GnuProject {
                name: "bash".to_string()
            })
        );
        assert_eq!(meta.purl, "pkg:gnu/bash@5.2");
    }

    #[test]
    fn attestation_with_results_collects_metadata() {
        let output = ForgeOutput {
            environment: {
                let mut env = ComposedEnvironment::new();
                env.packages = vec!["openssh".to_string(), "claude-code".to_string()];
                env
            },
            evaluated: 2,
            failed: 0,
            failed_packages: Vec::new(),
            elapsed: std::time::Duration::from_secs(1),
            store_dir: PathBuf::from("/nonexistent"),
            package_results: HashMap::new(),
        };

        let mut results = HashMap::new();
        results.insert(
            "openssh".to_string(),
            serde_json::json!({
                "name": "openssh",
                "attrs": {
                    "upstream_version": "10.2p1",
                    "source_provenance": {
                        "category": "GithubRepo",
                        "owner": "openssh",
                        "repo": "openssh-portable",
                    },
                },
            }),
        );
        results.insert(
            "claude-code".to_string(),
            serde_json::json!({
                "name": "claude-code",
                "attrs": {},
            }),
        );

        let composed = serde_json::json!({"test": true});
        let attestation = extract_attestation_with_results(&output, &composed, &results);

        assert_eq!(attestation.package_metadata.len(), 2);
        assert_eq!(attestation.package_metadata[0].name, "openssh");
        assert_eq!(
            attestation.package_metadata[0].purl,
            "pkg:github/openssh/openssh-portable@10.2p1"
        );
        assert_eq!(attestation.package_metadata[1].name, "claude-code");
        assert_eq!(
            attestation.package_metadata[1].purl,
            "pkg:generic/minimal.dev/claude-code"
        );
    }
}
