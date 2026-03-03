//! Attestation material/subject extraction from forge evaluation results.
//!
//! Converts the content-addressed store entries and source declarations
//! from Nickel packages into SLSA-compatible materials and subjects that
//! gleisner-introdus can assemble into an `InTotoStatement`.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::compose::ComposedEnvironment;
use crate::orchestrate::ForgeOutput;

/// A material (input artifact) for attestation.
///
/// Compatible with `gleisner_introdus::provenance::Material`.
#[derive(Debug, Clone, serde::Serialize)]
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
pub fn extract_attestation(
    output: &ForgeOutput,
    composed_json: &serde_json::Value,
) -> ForgeAttestation {
    let mut materials = Vec::new();
    let mut subjects = Vec::new();

    // Extract source materials from the composed environment's packages
    extract_source_materials(&output.environment, &mut materials);

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
        };

        let composed = serde_json::json!({"test": true});
        let attestation = extract_attestation(&output, &composed);

        // Should have the composed-env.json subject (store dir doesn't exist)
        assert_eq!(attestation.subjects.len(), 1);
        assert_eq!(attestation.subjects[0].name, "composed-env.json");
        assert!(!attestation.subjects[0].sha256.is_empty());
        assert!(attestation.builder_id.starts_with("gleisner-forge/"));
    }
}
