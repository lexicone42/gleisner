//! Proof verification for packages declaring `verified_properties`.
//!
//! When a package's `attrs.verified_properties` includes proof artifacts,
//! the verify step invokes a trusted proof kernel (e.g. `lean --check`) to
//! confirm the proofs are valid. Results are recorded in the attestation's
//! `VerifiedProperty::verified_by_forge` field and `VerificationSummary`.
//!
//! # Architecture
//!
//! ```text
//! PackageMetadata ──> VerifyConfig ──> spawn kernel ──> VerifyResult
//!   (from attest)       (lean path)    (exit code)      (pass/fail/skip)
//! ```
//!
//! The verifier does NOT trust the `proof_hash` or `specification_hash` fields —
//! it re-checks the proof artifact against the kernel. The hashes are for
//! caching and audit trail only.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::attest::{PackageMetadata, VerifiedProperty};

/// Configuration for the proof verification step.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct VerifyConfig {
    /// Path to the Lean 4 binary. If None, verification is skipped.
    pub lean_bin: Option<PathBuf>,
    /// Whether to treat verification failure as a hard error.
    /// When true, any failed verification stops the pipeline.
    /// When false, failures are recorded but the pipeline continues.
    pub strict: bool,
    /// Maximum time (seconds) to allow for a single proof check.
    pub timeout_secs: u64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            lean_bin: None,
            strict: false,
            timeout_secs: 300,
        }
    }
}

/// Result of verifying a single property.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PropertyVerification {
    /// Proof checked successfully by the kernel.
    Verified,
    /// Proof check failed (kernel returned non-zero).
    Failed { reason: String },
    /// Verification skipped (no kernel available, unsupported proof system, etc.).
    Skipped { reason: String },
}

/// Result of verifying all properties for a single package.
#[derive(Debug, Clone)]
pub struct PackageVerification {
    /// Name of the verified package.
    pub package_name: String,
    /// Per-property verification results.
    pub results: Vec<(VerifiedProperty, PropertyVerification)>,
}

impl PackageVerification {
    /// Number of properties that were verified successfully.
    pub fn verified_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, v)| matches!(v, PropertyVerification::Verified))
            .count()
    }

    /// Number of properties that failed verification.
    pub fn failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, v)| matches!(v, PropertyVerification::Failed { .. }))
            .count()
    }

    /// Whether all properties were either verified or skipped (none failed).
    pub fn all_passed(&self) -> bool {
        self.failed_count() == 0
    }
}

/// Detect the Lean binary on the system.
///
/// Checks for `lean` in PATH, then common installation locations.
pub fn detect_lean() -> Option<PathBuf> {
    // Check PATH first
    if let Ok(output) = Command::new("which").arg("lean").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Common elan-managed locations
    let home = std::env::var("HOME").ok()?;
    let elan_path = PathBuf::from(&home).join(".elan/bin/lean");
    if elan_path.exists() {
        return Some(elan_path);
    }

    None
}

/// Verify a proof artifact using the Lean kernel.
///
/// Invokes `lean --check <proof_uri>` when the `proof_uri` points to a local
/// `.lean` file. For remote URIs (https://), returns `Skipped` with a note
/// that the proof needs to be fetched first.
pub fn verify_property(property: &VerifiedProperty, config: &VerifyConfig) -> PropertyVerification {
    // Only lean4 proofs are supported
    if property.proof_system != "lean4" {
        return PropertyVerification::Skipped {
            reason: format!("unsupported proof system: {}", property.proof_system),
        };
    }

    let lean_bin = match &config.lean_bin {
        Some(p) => p,
        None => {
            return PropertyVerification::Skipped {
                reason: "lean binary not configured".to_string(),
            };
        }
    };

    let proof_path = match &property.proof_uri {
        Some(uri) if !uri.starts_with("http://") && !uri.starts_with("https://") => {
            PathBuf::from(uri)
        }
        Some(uri) => {
            return PropertyVerification::Skipped {
                reason: format!("remote proof URI not yet supported for local verification: {uri}"),
            };
        }
        None => {
            return PropertyVerification::Skipped {
                reason: "no proof_uri specified".to_string(),
            };
        }
    };

    if !proof_path.exists() {
        return PropertyVerification::Skipped {
            reason: format!("proof file not found: {}", proof_path.display()),
        };
    }

    check_lean_proof(lean_bin, &proof_path, config.timeout_secs)
}

/// Run `lean --check` on a proof file and return the result.
fn check_lean_proof(lean_bin: &Path, proof_path: &Path, timeout_secs: u64) -> PropertyVerification {
    let result = Command::new(lean_bin)
        .arg("--check")
        .arg(proof_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    // Note: timeout enforcement is left to the caller's environment for now.
    // A proper implementation would spawn + poll, but `lean --check` on a
    // single .olean file is typically fast (< 1s). The timeout_secs field
    // is reserved for future use with `wait-timeout` or async spawn.
    let _ = timeout_secs;

    match result {
        Ok(output) if output.status.success() => PropertyVerification::Verified,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            PropertyVerification::Failed {
                reason: format!(
                    "lean --check exited with {}: {}",
                    output.status.code().unwrap_or(-1),
                    stderr.chars().take(500).collect::<String>(),
                ),
            }
        }
        Err(e) => PropertyVerification::Failed {
            reason: format!("failed to invoke lean: {e}"),
        },
    }
}

/// Verify all properties across a set of packages.
///
/// Returns verification results for each package that has `verified_properties`.
/// Packages without `verified_properties` are skipped.
pub fn verify_packages(
    packages: &[PackageMetadata],
    config: &VerifyConfig,
) -> Vec<PackageVerification> {
    packages
        .iter()
        .filter(|p| !p.verified_properties.is_empty())
        .map(|pkg| {
            let results: Vec<_> = pkg
                .verified_properties
                .iter()
                .map(|prop| {
                    let result = verify_property(prop, config);
                    tracing::info!(
                        package = %pkg.name,
                        property = %prop.property,
                        result = ?result,
                        "property verification"
                    );
                    (prop.clone(), result)
                })
                .collect();

            PackageVerification {
                package_name: pkg.name.clone(),
                results,
            }
        })
        .collect()
}

/// Apply verification results back to package metadata, setting
/// `verified_by_forge` on each property.
pub fn apply_verification_results(
    metadata: &mut [PackageMetadata],
    verifications: &[PackageVerification],
) {
    for verification in verifications {
        if let Some(pkg) = metadata
            .iter_mut()
            .find(|p| p.name == verification.package_name)
        {
            for (verified_prop, result) in &verification.results {
                if let Some(prop) = pkg
                    .verified_properties
                    .iter_mut()
                    .find(|p| p.property == verified_prop.property)
                {
                    prop.verified_by_forge = match result {
                        PropertyVerification::Verified => Some(true),
                        PropertyVerification::Failed { .. } => Some(false),
                        PropertyVerification::Skipped { .. } => None,
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_property() -> VerifiedProperty {
        VerifiedProperty {
            property: "roundtrip".to_string(),
            description: "decompress(compress(data)) = data".to_string(),
            proof_system: "lean4".to_string(),
            kernel_version: "leanprover/lean4:v4.29.0-rc2".to_string(),
            specification_hash: "sha256:abc123".to_string(),
            proof_hash: "sha256:def456".to_string(),
            proof_uri: None,
            verified_by_forge: None,
        }
    }

    fn sample_metadata(name: &str, with_proofs: bool) -> PackageMetadata {
        PackageMetadata {
            name: name.to_string(),
            purl: String::new(),
            upstream_version: None,
            source_provenance: None,
            repology_project: None,
            source_urls: vec![],
            verified_properties: if with_proofs {
                vec![sample_property()]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn skip_when_no_lean() {
        let config = VerifyConfig::default();
        let prop = sample_property();
        let result = verify_property(&prop, &config);
        assert!(matches!(result, PropertyVerification::Skipped { .. }));
    }

    #[test]
    fn skip_unsupported_proof_system() {
        let config = VerifyConfig {
            lean_bin: Some(PathBuf::from("/usr/bin/lean")),
            ..Default::default()
        };
        let mut prop = sample_property();
        prop.proof_system = "coq".to_string();
        let result = verify_property(&prop, &config);
        assert!(matches!(
            result,
            PropertyVerification::Skipped { reason } if reason.contains("unsupported")
        ));
    }

    #[test]
    fn skip_remote_uri() {
        let config = VerifyConfig {
            lean_bin: Some(PathBuf::from("/usr/bin/lean")),
            ..Default::default()
        };
        let mut prop = sample_property();
        prop.proof_uri = Some("https://github.com/example/proof.lean".to_string());
        let result = verify_property(&prop, &config);
        assert!(matches!(
            result,
            PropertyVerification::Skipped { reason } if reason.contains("remote")
        ));
    }

    #[test]
    fn skip_missing_proof_file() {
        let config = VerifyConfig {
            lean_bin: Some(PathBuf::from("/usr/bin/lean")),
            ..Default::default()
        };
        let mut prop = sample_property();
        prop.proof_uri = Some("/nonexistent/proof.lean".to_string());
        let result = verify_property(&prop, &config);
        assert!(matches!(
            result,
            PropertyVerification::Skipped { reason } if reason.contains("not found")
        ));
    }

    #[test]
    fn skip_no_proof_uri() {
        let config = VerifyConfig {
            lean_bin: Some(PathBuf::from("/usr/bin/lean")),
            ..Default::default()
        };
        let prop = sample_property();
        let result = verify_property(&prop, &config);
        assert!(matches!(
            result,
            PropertyVerification::Skipped { reason } if reason.contains("no proof_uri")
        ));
    }

    #[test]
    fn package_verification_counts() {
        let prop = sample_property();
        let ver = PackageVerification {
            package_name: "zlib".to_string(),
            results: vec![
                (prop.clone(), PropertyVerification::Verified),
                (
                    prop.clone(),
                    PropertyVerification::Failed {
                        reason: "bad".to_string(),
                    },
                ),
                (
                    prop,
                    PropertyVerification::Skipped {
                        reason: "no kernel".to_string(),
                    },
                ),
            ],
        };
        assert_eq!(ver.verified_count(), 1);
        assert_eq!(ver.failed_count(), 1);
        assert!(!ver.all_passed());
    }

    #[test]
    fn apply_results_sets_verified_by_forge() {
        let mut metadata = vec![sample_metadata("zlib", true)];

        let verifications = vec![PackageVerification {
            package_name: "zlib".to_string(),
            results: vec![(sample_property(), PropertyVerification::Verified)],
        }];

        apply_verification_results(&mut metadata, &verifications);
        assert_eq!(
            metadata[0].verified_properties[0].verified_by_forge,
            Some(true)
        );
    }

    #[test]
    fn apply_results_marks_failed() {
        let mut metadata = vec![sample_metadata("test", true)];

        let verifications = vec![PackageVerification {
            package_name: "test".to_string(),
            results: vec![(
                sample_property(),
                PropertyVerification::Failed {
                    reason: "proof error".to_string(),
                },
            )],
        }];

        apply_verification_results(&mut metadata, &verifications);
        assert_eq!(
            metadata[0].verified_properties[0].verified_by_forge,
            Some(false)
        );
    }

    #[test]
    fn verify_packages_filters_empty() {
        let packages = vec![
            sample_metadata("zlib", true),
            sample_metadata("bash", false),
        ];

        let config = VerifyConfig::default();
        let results = verify_packages(&packages, &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].package_name, "zlib");
    }
}
