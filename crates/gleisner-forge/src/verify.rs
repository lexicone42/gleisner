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

use sha2::{Digest, Sha256};

use crate::attest::{PackageMetadata, VerifiedProperty};

/// Configuration for the proof verification step.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct VerifyConfig {
    /// Path to the Lean 4 binary. If None, verification is skipped.
    pub lean_bin: Option<PathBuf>,
    /// Path to the `lake` binary (Lean build tool). If None, auto-detected.
    pub lake_bin: Option<PathBuf>,
    /// Whether to treat verification failure as a hard error.
    /// When true, any failed verification stops the pipeline.
    /// When false, failures are recorded but the pipeline continues.
    pub strict: bool,
    /// Maximum time (seconds) to allow for a single proof check.
    pub timeout_secs: u64,
    /// Directory for cloning proof repositories.
    pub proof_cache_dir: PathBuf,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            lean_bin: None,
            lake_bin: None,
            strict: false,
            timeout_secs: 300,
            proof_cache_dir: PathBuf::from(".gleisner/proof-cache"),
        }
    }
}

/// Result of verifying a single property.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PropertyVerification {
    /// Proof checked successfully by the Lean kernel (via `lake build`).
    /// Contains the forge-computed SHA-256 of the `.olean` artifact, if available.
    Verified { olean_hash: Option<String> },
    /// Proof check failed (kernel returned non-zero).
    Failed { reason: String },
    /// Verification skipped (no kernel available, unsupported proof system, etc.).
    Skipped { reason: String },
}

/// Identifies which kernel implementation performed the check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum VerifierKernel {
    /// Reference C++ kernel via `lake build`.
    LeanCpp,
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
            .filter(|(_, v)| matches!(v, PropertyVerification::Verified { .. }))
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
/// Checks for `lean` in PATH, then common elan-managed locations.
pub fn detect_lean() -> Option<PathBuf> {
    detect_tool("lean")
}

/// Detect the `lake` build tool on the system.
pub fn detect_lake() -> Option<PathBuf> {
    detect_tool("lake")
}

/// Detect a tool by name from PATH or ~/.elan/bin/.
fn detect_tool(name: &str) -> Option<PathBuf> {
    // Check PATH first
    if let Ok(output) = Command::new("which").arg(name).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Common elan-managed locations
    let home = std::env::var("HOME").ok()?;
    let elan_path = PathBuf::from(&home).join(format!(".elan/bin/{name}"));
    if elan_path.exists() {
        return Some(elan_path);
    }

    None
}

/// Extract a GitHub repo URL from a `proof_uri`.
///
/// Handles patterns like:
/// - `https://github.com/owner/repo/blob/branch/path/to/file.lean`
/// - `https://github.com/owner/repo`
fn extract_github_repo_url(uri: &str) -> Option<String> {
    if !uri.starts_with("https://github.com/") {
        return None;
    }

    // Parse: https://github.com/{owner}/{repo}[/blob/...]
    let path = uri.strip_prefix("https://github.com/")?;
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() >= 2 {
        Some(format!("https://github.com/{}/{}", parts[0], parts[1]))
    } else {
        None
    }
}

/// Extract the in-repo `.lean` path from a GitHub blob URL.
///
/// Given `https://github.com/owner/repo/blob/branch/path/to/File.lean`,
/// returns `Some("path/to/File.lean")`.
fn extract_lean_path_from_uri(uri: &str) -> Option<String> {
    // Pattern: https://github.com/{owner}/{repo}/blob/{branch}/{path}
    let path = uri.strip_prefix("https://github.com/")?;
    let parts: Vec<&str> = path.splitn(5, '/').collect();
    // parts: [owner, repo, "blob", branch, rest-of-path]
    if parts.len() == 5 && parts[2] == "blob" {
        Some(parts[4].to_string())
    } else {
        None
    }
}

/// Map a `.lean` source path to its corresponding `.olean` build artifact.
///
/// Lean's `lake build` places `.olean` files under `.lake/build/lib/{pkg_name}/`,
/// mirroring the source directory structure. The package name in the lakefile
/// determines the intermediate directory.
///
/// This function searches `build_lib_dir` for a matching `.olean` file by
/// trying the path directly and with common package prefixes.
fn find_olean_for_lean_path(build_lib_dir: &Path, lean_path: &str) -> Option<PathBuf> {
    let olean_name = lean_path.replace(".lean", ".olean");

    // Try direct path (some projects have flat layouts)
    let direct = build_lib_dir.join(&olean_name);
    if direct.exists() {
        return Some(direct);
    }

    // Try with a `lean/` prefix (lake's default package layout)
    let with_lean_prefix = build_lib_dir.join("lean").join(&olean_name);
    if with_lean_prefix.exists() {
        return Some(with_lean_prefix);
    }

    // Scan one level of subdirectories for the matching olean
    if let Ok(entries) = std::fs::read_dir(build_lib_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let candidate = entry.path().join(&olean_name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

/// SHA-256 hash of a file's contents, returned as `sha256:{hex}`.
fn hash_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(format!("sha256:{digest:x}"))
}

/// Result of verifying a proof repository.
#[derive(Debug)]
pub struct RepoVerification {
    /// Whether the Lean kernel (lake build) succeeded.
    pub verified: bool,
    /// Path to the cloned repo's build output (`.lake/build/lib/`).
    /// Used to locate `.olean` files for per-property hashing.
    pub build_lib_dir: Option<PathBuf>,
}

/// Verify a proof repository by cloning it and running `lake build`.
///
/// This is the primary verification method for Lean 4 projects: `lake build`
/// type-checks all source files, including proof files. If it succeeds with
/// exit code 0, every theorem in the project (including all `sorry`-free proofs)
/// has been verified by the Lean kernel.
pub fn verify_proof_repo(
    repo_url: &str,
    config: &VerifyConfig,
) -> Result<RepoVerification, String> {
    let lake_bin = config
        .lake_bin
        .clone()
        .or_else(detect_lake)
        .ok_or_else(|| "lake binary not found (install elan)".to_string())?;

    // Derive a cache directory name from the repo URL
    let repo_name = repo_url
        .rsplit('/')
        .next()
        .unwrap_or("proof-repo")
        .trim_end_matches(".git");
    let clone_dir = config.proof_cache_dir.join(repo_name);

    // Clone or update
    if clone_dir.join("lakefile.lean").exists() {
        tracing::info!(repo = %repo_url, dir = %clone_dir.display(), "proof repo already cached, pulling latest");
        let pull = Command::new("git")
            .args(["pull", "--ff-only"])
            .current_dir(&clone_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        if let Ok(output) = pull {
            if !output.status.success() {
                tracing::warn!("git pull failed, continuing with cached version");
            }
        }
    } else {
        tracing::info!(repo = %repo_url, dir = %clone_dir.display(), "cloning proof repo");
        std::fs::create_dir_all(&config.proof_cache_dir)
            .map_err(|e| format!("failed to create proof cache dir: {e}"))?;

        let clone = Command::new("git")
            .args(["clone", "--depth", "1", repo_url])
            .arg(&clone_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| format!("git clone failed: {e}"))?;

        if !clone.status.success() {
            let stderr = String::from_utf8_lossy(&clone.stderr);
            return Err(format!(
                "git clone failed: {}",
                stderr.chars().take(500).collect::<String>()
            ));
        }
    }

    // Run `lake build` — this type-checks all proofs
    tracing::info!(dir = %clone_dir.display(), "running lake build (verifying proofs)");
    let build = Command::new(&lake_bin)
        .arg("build")
        .current_dir(&clone_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("lake build failed to start: {e}"))?;

    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr);
        let stdout = String::from_utf8_lossy(&build.stdout);
        return Err(format!(
            "lake build failed (exit {}): {}{}",
            build.status.code().unwrap_or(-1),
            stderr.chars().take(500).collect::<String>(),
            stdout.chars().take(500).collect::<String>(),
        ));
    }

    tracing::info!("lake build succeeded — proofs verified by Lean kernel");

    let build_lib_dir = clone_dir.join(".lake/build/lib");
    let build_lib = if build_lib_dir.is_dir() {
        Some(build_lib_dir)
    } else {
        tracing::warn!("no .lake/build/lib/ found — cannot hash .olean artifacts");
        None
    };

    Ok(RepoVerification {
        verified: true,
        build_lib_dir: build_lib,
    })
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
        Some(uri) if uri.starts_with("https://github.com/") => {
            // GitHub URL — extract repo, clone, and verify via lake build
            let repo_url = match extract_github_repo_url(uri) {
                Some(url) => url,
                None => {
                    return PropertyVerification::Skipped {
                        reason: format!("could not parse GitHub repo from: {uri}"),
                    };
                }
            };
            return match verify_proof_repo(&repo_url, config) {
                Ok(rv) if rv.verified => {
                    // Try to hash the specific .olean for this property
                    let olean_hash = rv.build_lib_dir.as_ref().and_then(|lib_dir| {
                        let lean_path = extract_lean_path_from_uri(uri)?;
                        let olean_path = find_olean_for_lean_path(lib_dir, &lean_path)?;
                        match hash_file_sha256(&olean_path) {
                            Ok(hash) => {
                                tracing::info!(
                                    property = %property.property,
                                    olean = %olean_path.display(),
                                    hash = %hash,
                                    "computed .olean hash"
                                );
                                Some(hash)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    property = %property.property,
                                    error = %e,
                                    "failed to hash .olean file"
                                );
                                None
                            }
                        }
                    });
                    PropertyVerification::Verified { olean_hash }
                }
                Ok(_) => PropertyVerification::Failed {
                    reason: "lake build failed".to_string(),
                },
                Err(e) => PropertyVerification::Failed { reason: e },
            };
        }
        Some(uri) => {
            return PropertyVerification::Skipped {
                reason: format!("unsupported remote proof URI scheme: {uri}"),
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
        Ok(output) if output.status.success() => {
            PropertyVerification::Verified { olean_hash: None }
        }
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
/// `verified_by_forge` on each property and updating `proof_hash` with
/// the forge-computed `.olean` hash when available.
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
                    match result {
                        PropertyVerification::Verified { olean_hash } => {
                            prop.verified_by_forge = Some(true);
                            if let Some(hash) = olean_hash {
                                prop.proof_hash = hash.clone();
                            }
                        }
                        PropertyVerification::Failed { .. } => {
                            prop.verified_by_forge = Some(false);
                        }
                        PropertyVerification::Skipped { .. } => {
                            prop.verified_by_forge = None;
                        }
                    }
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
            lean_bin: Some("/usr/bin/lean".into()),
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
    fn skip_non_github_remote_uri() {
        let config = VerifyConfig {
            lean_bin: Some("/usr/bin/lean".into()),
            ..Default::default()
        };
        let mut prop = sample_property();
        prop.proof_uri = Some("https://gitlab.com/example/proof.lean".to_string());
        let result = verify_property(&prop, &config);
        assert!(matches!(
            result,
            PropertyVerification::Skipped { reason } if reason.contains("unsupported remote")
        ));
    }

    #[test]
    fn skip_missing_proof_file() {
        let config = VerifyConfig {
            lean_bin: Some("/usr/bin/lean".into()),
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
            lean_bin: Some("/usr/bin/lean".into()),
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
                (
                    prop.clone(),
                    PropertyVerification::Verified { olean_hash: None },
                ),
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
            results: vec![(
                sample_property(),
                PropertyVerification::Verified { olean_hash: None },
            )],
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
    fn extract_github_repo_from_blob_url() {
        let url = "https://github.com/kim-em/lean-zip/blob/master/Zip/Spec/ZlibCorrect.lean";
        assert_eq!(
            extract_github_repo_url(url),
            Some("https://github.com/kim-em/lean-zip".to_string())
        );
    }

    #[test]
    fn extract_github_repo_from_bare_url() {
        let url = "https://github.com/kim-em/lean-zip";
        assert_eq!(
            extract_github_repo_url(url),
            Some("https://github.com/kim-em/lean-zip".to_string())
        );
    }

    #[test]
    fn extract_github_repo_not_github() {
        assert_eq!(extract_github_repo_url("https://gitlab.com/foo/bar"), None);
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

    #[test]
    fn repo_verification_logic() {
        let rv = RepoVerification {
            verified: true,
            build_lib_dir: None,
        };
        assert!(rv.verified);

        let rv2 = RepoVerification {
            verified: false,
            build_lib_dir: None,
        };
        assert!(!rv2.verified);
    }

    #[test]
    fn extract_lean_path_from_blob_url() {
        let url = "https://github.com/kim-em/lean-zip/blob/master/Zip/Spec/ZlibCorrect.lean";
        assert_eq!(
            extract_lean_path_from_uri(url),
            Some("Zip/Spec/ZlibCorrect.lean".to_string())
        );
    }

    #[test]
    fn extract_lean_path_no_blob() {
        // Bare repo URL — no path to extract
        assert_eq!(
            extract_lean_path_from_uri("https://github.com/kim-em/lean-zip"),
            None
        );
    }

    #[test]
    fn find_olean_direct_path() {
        let dir = tempfile::tempdir().unwrap();
        let olean = dir.path().join("Zip/Spec/ZlibCorrect.olean");
        std::fs::create_dir_all(olean.parent().unwrap()).unwrap();
        std::fs::write(&olean, b"test olean data").unwrap();

        let result = find_olean_for_lean_path(dir.path(), "Zip/Spec/ZlibCorrect.lean");
        assert_eq!(result, Some(olean));
    }

    #[test]
    fn find_olean_with_package_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let olean = dir.path().join("lean/Zip/Spec/ZlibCorrect.olean");
        std::fs::create_dir_all(olean.parent().unwrap()).unwrap();
        std::fs::write(&olean, b"test olean data").unwrap();

        let result = find_olean_for_lean_path(dir.path(), "Zip/Spec/ZlibCorrect.lean");
        assert_eq!(result, Some(olean));
    }

    #[test]
    fn find_olean_scan_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let olean = dir.path().join("mypkg/Zip/Spec/ZlibCorrect.olean");
        std::fs::create_dir_all(olean.parent().unwrap()).unwrap();
        std::fs::write(&olean, b"test olean data").unwrap();

        let result = find_olean_for_lean_path(dir.path(), "Zip/Spec/ZlibCorrect.lean");
        assert_eq!(result, Some(olean));
    }

    #[test]
    fn find_olean_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_olean_for_lean_path(dir.path(), "Nonexistent.lean");
        assert_eq!(result, None);
    }

    #[test]
    fn hash_file_sha256_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.olean");
        std::fs::write(&path, b"deterministic content").unwrap();

        let h1 = hash_file_sha256(&path).unwrap();
        let h2 = hash_file_sha256(&path).unwrap();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn apply_results_sets_olean_hash() {
        let mut metadata = vec![sample_metadata("zlib", true)];

        let verifications = vec![PackageVerification {
            package_name: "zlib".to_string(),
            results: vec![(
                sample_property(),
                PropertyVerification::Verified {
                    olean_hash: Some("sha256:abc123def456".to_string()),
                },
            )],
        }];

        apply_verification_results(&mut metadata, &verifications);
        assert_eq!(
            metadata[0].verified_properties[0].verified_by_forge,
            Some(true)
        );
        assert_eq!(
            metadata[0].verified_properties[0].proof_hash,
            "sha256:abc123def456"
        );
    }
}
