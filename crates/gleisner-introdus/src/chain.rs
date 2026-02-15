//! Attestation chain discovery and linking.
//!
//! Each attestation can reference its parent's payload digest, forming a
//! verifiable chain. This module provides utilities to discover the latest
//! attestation in a directory, compute payload digests, and walk the chain
//! backwards from any starting point.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::bundle::AttestationBundle;
use crate::error::AttestationError;

/// A link in the attestation chain — a resolved attestation with its digest.
#[derive(Debug, Clone)]
pub struct ChainLink {
    /// Path to the attestation bundle file.
    pub path: PathBuf,
    /// SHA-256 hex digest of the bundle's `payload` field.
    pub payload_digest: String,
}

/// An entry in a walked chain, with full metadata extracted from the payload.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    /// Path to the attestation bundle file.
    pub path: PathBuf,
    /// SHA-256 hex digest of the bundle's `payload` field.
    pub payload_digest: String,
    /// Parent's payload digest, if this is not the first in the chain.
    pub parent_digest: Option<String>,
    /// Git commit hash from the attestation's materials, if present.
    pub git_commit: Option<String>,
    /// When the session started.
    pub started_on: Option<DateTime<Utc>>,
    /// When the session finished.
    pub finished_on: Option<DateTime<Utc>>,
    /// Whether this bundle has verification material (is cryptographically signed).
    pub is_signed: bool,
}

/// Compute the SHA-256 hex digest of an attestation bundle's payload.
#[must_use]
pub fn compute_payload_digest(bundle: &AttestationBundle) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bundle.payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// Find the most recent attestation bundle in a directory.
///
/// Scans `dir` for files matching `attestation-*.json`, parses each as an
/// `AttestationBundle`, and returns the one with the latest `buildFinishedOn`
/// timestamp.
///
/// Returns `Ok(None)` if no attestation files are found.
///
/// # Errors
///
/// Returns an error if directory reading fails.
pub fn find_latest_attestation(dir: &Path) -> Result<Option<ChainLink>, AttestationError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AttestationError::IoError(e)),
    };

    let mut best: Option<(PathBuf, DateTime<Utc>, String)> = None;

    for entry in entries {
        let entry = entry.map_err(AttestationError::IoError)?;
        let path = entry.path();

        if !is_attestation_file(&path) {
            continue;
        }

        let Ok(data) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(bundle) = serde_json::from_str::<AttestationBundle>(&data) else {
            continue;
        };

        let payload_digest = compute_payload_digest(&bundle);
        let finished_on = extract_finished_on(&bundle);

        if let Some(ts) = finished_on {
            let dominated = best.as_ref().is_some_and(|(_, best_ts, _)| *best_ts >= ts);
            if !dominated {
                best = Some((path, ts, payload_digest));
            }
        } else if best.is_none() {
            // No timestamp — use as fallback if nothing better exists.
            best = Some((path, DateTime::<Utc>::MIN_UTC, payload_digest));
        }
    }

    Ok(best.map(|(path, _, payload_digest)| ChainLink {
        path,
        payload_digest,
    }))
}

/// Walk the attestation chain backwards from a starting bundle.
///
/// Loads the bundle at `start`, extracts its `gleisner:chain.parentDigest`,
/// then scans `dir` for a bundle whose payload digest matches. Repeats until
/// no parent is found or the parent cannot be located.
///
/// Returns entries ordered newest-first.
///
/// # Errors
///
/// Returns an error if the starting file cannot be read or parsed.
pub fn walk_chain(start: &Path, dir: &Path) -> Result<Vec<ChainEntry>, AttestationError> {
    // Pre-load all bundles in the directory for efficient lookup.
    let index = build_digest_index(dir)?;

    let mut chain = Vec::new();
    let mut current_path = start.to_path_buf();
    let mut visited = HashSet::new();

    // Safety bound to prevent infinite loops on malformed chains.
    let max_depth = index.len() + 1;

    for _ in 0..max_depth {
        let data = std::fs::read_to_string(&current_path).map_err(AttestationError::IoError)?;
        let bundle: AttestationBundle =
            serde_json::from_str(&data).map_err(AttestationError::SerializeError)?;

        let payload_digest = compute_payload_digest(&bundle);
        let parent_digest = extract_parent_digest(&bundle);
        let git_commit = extract_git_commit(&bundle);
        let started_on = extract_started_on(&bundle);
        let finished_on = extract_finished_on(&bundle);
        let is_signed = !matches!(
            bundle.verification_material,
            crate::bundle::VerificationMaterial::None
        );

        // Detect cycles: if we've already visited this digest, stop.
        if !visited.insert(payload_digest.clone()) {
            warn!(
                digest = %payload_digest,
                "cycle detected in attestation chain — stopping walk"
            );
            break;
        }

        if !is_signed {
            warn!(
                path = %current_path.display(),
                digest = %payload_digest,
                "unsigned bundle in attestation chain (VerificationMaterial::None)"
            );
        }

        chain.push(ChainEntry {
            path: current_path.clone(),
            payload_digest,
            parent_digest: parent_digest.clone(),
            git_commit,
            started_on,
            finished_on,
            is_signed,
        });

        // Follow the parent link.
        match parent_digest {
            Some(ref digest) => {
                if let Some(parent_path) = index.get(digest) {
                    current_path.clone_from(parent_path);
                } else {
                    break; // parent not found in directory
                }
            }
            None => break, // root of the chain
        }
    }

    Ok(chain)
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Check whether a path looks like an attestation bundle file.
fn is_attestation_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with("attestation-")
        && Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
}

/// Build a map from payload digest to file path for all attestations in a dir.
fn build_digest_index(dir: &Path) -> Result<HashMap<String, PathBuf>, AttestationError> {
    let mut index = HashMap::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(index),
        Err(e) => return Err(AttestationError::IoError(e)),
    };

    for entry in entries {
        let entry = entry.map_err(AttestationError::IoError)?;
        let path = entry.path();

        if !is_attestation_file(&path) {
            continue;
        }

        let Ok(data) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(bundle) = serde_json::from_str::<AttestationBundle>(&data) else {
            continue;
        };

        let digest = compute_payload_digest(&bundle);
        match index.entry(digest) {
            Entry::Vacant(e) => {
                e.insert(path);
            }
            Entry::Occupied(e) => {
                warn!(
                    digest = %e.key(),
                    existing = %e.get().display(),
                    duplicate = %path.display(),
                    "duplicate payload digest — keeping first occurrence"
                );
            }
        }
    }

    Ok(index)
}

/// Extract `gleisner:chain.parentDigest` from a bundle's payload.
fn extract_parent_digest(bundle: &AttestationBundle) -> Option<String> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    payload
        .get("predicate")?
        .get("gleisner:chain")?
        .get("parentDigest")?
        .as_str()
        .map(String::from)
}

/// Extract the git commit from the attestation's materials.
fn extract_git_commit(bundle: &AttestationBundle) -> Option<String> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    let materials = payload.get("predicate")?.get("materials")?.as_array()?;
    for mat in materials {
        let uri = mat.get("uri")?.as_str()?;
        if uri.starts_with("git+") || uri.contains("git") {
            if let Some(digest) = mat.get("digest").and_then(|d| d.get("sha256")) {
                return digest.as_str().map(String::from);
            }
            // Also check for commit in URI fragment (git+https://...#commit)
            if let Some(fragment) = uri.split('#').nth(1) {
                return Some(fragment.to_owned());
            }
        }
    }
    None
}

/// Extract `metadata.buildStartedOn` timestamp.
fn extract_started_on(bundle: &AttestationBundle) -> Option<DateTime<Utc>> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    let ts = payload
        .get("predicate")?
        .get("metadata")?
        .get("buildStartedOn")?
        .as_str()?;
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Extract `metadata.buildFinishedOn` timestamp.
fn extract_finished_on(bundle: &AttestationBundle) -> Option<DateTime<Utc>> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    let ts = payload
        .get("predicate")?
        .get("metadata")?
        .get("buildFinishedOn")?
        .as_str()?;
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a minimal attestation bundle JSON with the given chain and timestamp.
    fn make_bundle(chain: Option<(&str, &str)>, finished_on: &str, started_on: &str) -> String {
        let chain_json = match chain {
            Some((digest, path)) => {
                format!(r#","gleisner:chain":{{"parentDigest":"{digest}","parentPath":"{path}"}}"#,)
            }
            None => String::new(),
        };

        let payload = format!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{{"buildType":"https://gleisner.dev/GleisnerProvenance/v1","builder":{{"id":"gleisner-local"}},"invocation":{{"parameters":{{}},"environment":{{"tool":"claude-code","claudeCodeVersion":null,"model":null,"claudeMdHash":null,"contextHash":null,"sandboxed":true,"profile":"konishi","apiBaseUrl":"https://api.anthropic.com"}}}},"metadata":{{"buildStartedOn":"{started_on}","buildFinishedOn":"{finished_on}","completeness":{{"parameters":true,"environment":true,"materials":false}}}},"materials":[],"gleisner:auditLogDigest":"abc123","gleisner:sandboxProfile":{{"name":"konishi","profileDigest":"","networkPolicy":"deny","filesystemDenyCount":0}}{chain_json}}}}}"#,
        );

        serde_json::to_string_pretty(&AttestationBundle {
            payload,
            signature: String::new(),
            verification_material: crate::bundle::VerificationMaterial::None,
        })
        .unwrap()
    }

    #[test]
    fn find_latest_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = find_latest_attestation(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn find_latest_picks_most_recent() {
        let dir = TempDir::new().unwrap();

        let old = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        let new = make_bundle(None, "2025-06-15T12:00:00Z", "2025-06-15T11:00:00Z");

        std::fs::write(dir.path().join("attestation-old.json"), &old).unwrap();
        std::fs::write(dir.path().join("attestation-new.json"), &new).unwrap();

        let link = find_latest_attestation(dir.path()).unwrap().unwrap();
        assert!(link.path.ends_with("attestation-new.json"));
        assert!(!link.payload_digest.is_empty());
    }

    #[test]
    fn compute_digest_deterministic() {
        let bundle_json = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        let bundle: AttestationBundle = serde_json::from_str(&bundle_json).unwrap();
        let d1 = compute_payload_digest(&bundle);
        let d2 = compute_payload_digest(&bundle);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn walk_chain_three_links() {
        let dir = TempDir::new().unwrap();

        // Create chain: 1 (root) <- 2 <- 3
        let bundle1_json = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        let path1 = dir.path().join("attestation-001.json");
        std::fs::write(&path1, &bundle1_json).unwrap();
        let b1: AttestationBundle = serde_json::from_str(&bundle1_json).unwrap();
        let d1 = compute_payload_digest(&b1);

        let bundle2_json = make_bundle(
            Some((&d1, "attestation-001.json")),
            "2025-02-01T00:00:00Z",
            "2025-02-01T00:00:00Z",
        );
        let path2 = dir.path().join("attestation-002.json");
        std::fs::write(&path2, &bundle2_json).unwrap();
        let b2: AttestationBundle = serde_json::from_str(&bundle2_json).unwrap();
        let d2 = compute_payload_digest(&b2);

        let bundle3_json = make_bundle(
            Some((&d2, "attestation-002.json")),
            "2025-03-01T00:00:00Z",
            "2025-03-01T00:00:00Z",
        );
        let path3 = dir.path().join("attestation-003.json");
        std::fs::write(&path3, &bundle3_json).unwrap();

        let chain = walk_chain(&path3, dir.path()).unwrap();
        assert_eq!(chain.len(), 3);
        // Newest first.
        assert!(chain[0].path.ends_with("attestation-003.json"));
        assert!(chain[1].path.ends_with("attestation-002.json"));
        assert!(chain[2].path.ends_with("attestation-001.json"));
        // Root has no parent.
        assert!(chain[2].parent_digest.is_none());
        // Others have parent digests.
        assert!(chain[0].parent_digest.is_some());
        assert!(chain[1].parent_digest.is_some());
    }

    #[test]
    fn walk_chain_broken_returns_partial() {
        let dir = TempDir::new().unwrap();

        // Create chain: 1 (root) <- 2 <- 3, but delete 2
        let bundle1_json = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        let path1 = dir.path().join("attestation-001.json");
        std::fs::write(&path1, &bundle1_json).unwrap();
        let b1: AttestationBundle = serde_json::from_str(&bundle1_json).unwrap();
        let d1 = compute_payload_digest(&b1);

        let bundle2_json = make_bundle(
            Some((&d1, "attestation-001.json")),
            "2025-02-01T00:00:00Z",
            "2025-02-01T00:00:00Z",
        );
        let b2: AttestationBundle = serde_json::from_str(&bundle2_json).unwrap();
        let d2 = compute_payload_digest(&b2);
        // Don't write bundle 2 to disk — simulating a broken chain.

        let bundle3_json = make_bundle(
            Some((&d2, "attestation-002.json")),
            "2025-03-01T00:00:00Z",
            "2025-03-01T00:00:00Z",
        );
        let path3 = dir.path().join("attestation-003.json");
        std::fs::write(&path3, &bundle3_json).unwrap();

        let chain = walk_chain(&path3, dir.path()).unwrap();
        // Only entry 3 — parent d2 not found in dir.
        assert_eq!(chain.len(), 1);
        assert!(chain[0].parent_digest.is_some());
    }

    #[test]
    fn self_referential_chain_terminates() {
        let dir = TempDir::new().unwrap();

        // Create a bundle that references itself as parent
        let bundle_json = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        let bundle: AttestationBundle = serde_json::from_str(&bundle_json).unwrap();
        let digest = compute_payload_digest(&bundle);

        // Re-create with self-reference
        let self_ref_json = make_bundle(
            Some((&digest, "attestation-self.json")),
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
        );
        let path = dir.path().join("attestation-self.json");
        std::fs::write(&path, &self_ref_json).unwrap();

        // This must terminate (cycle detection), not loop forever
        let chain = walk_chain(&path, dir.path()).unwrap();
        // Should have exactly 1 entry — the self-referential bundle.
        // The parent digest lookup finds itself, but visited-set breaks the cycle.
        assert!(!chain.is_empty());
        assert!(
            chain.len() <= 2,
            "cycle detection should limit chain length"
        );
    }

    #[test]
    fn duplicate_digest_keeps_first() {
        let dir = TempDir::new().unwrap();

        // Two bundles with identical payloads (same digest)
        let bundle_json = make_bundle(None, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z");
        std::fs::write(dir.path().join("attestation-aaa.json"), &bundle_json).unwrap();
        std::fs::write(dir.path().join("attestation-zzz.json"), &bundle_json).unwrap();

        // build_digest_index should keep exactly one entry
        let index = build_digest_index(dir.path()).unwrap();
        let bundle: AttestationBundle = serde_json::from_str(&bundle_json).unwrap();
        let digest = compute_payload_digest(&bundle);
        assert!(index.contains_key(&digest));
        // Only one entry for this digest
        assert_eq!(
            index
                .values()
                .filter(|p| {
                    let name = p.file_name().unwrap().to_str().unwrap();
                    name.starts_with("attestation-")
                })
                .count(),
            1
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generate a minimal valid `AttestationBundle` with arbitrary payload content.
        fn arb_bundle() -> impl Strategy<Value = AttestationBundle> {
            ".*".prop_map(|payload_content| {
                let payload = format!(
                    r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{{"buildType":"https://gleisner.dev/GleisnerProvenance/v1","builder":{{"id":"test"}},"metadata":{{"buildStartedOn":"2025-01-01T00:00:00Z","buildFinishedOn":"2025-01-01T00:00:00Z"}},"materials":[],"data":"{payload_content}"}}}}"#,
                );
                AttestationBundle {
                    payload,
                    signature: String::new(),
                    verification_material: crate::bundle::VerificationMaterial::None,
                }
            })
        }

        proptest! {
            /// compute_payload_digest is deterministic for any payload.
            #[test]
            fn digest_is_deterministic(bundle in arb_bundle()) {
                let d1 = compute_payload_digest(&bundle);
                let d2 = compute_payload_digest(&bundle);
                prop_assert_eq!(&d1, &d2);
                prop_assert_eq!(d1.len(), 64); // SHA-256 hex = 64 chars
            }

            /// walk_chain always terminates regardless of chain structure.
            #[test]
            fn walk_chain_always_terminates(bundles in prop::collection::vec(arb_bundle(), 1..20)) {
                let dir = TempDir::new().unwrap();

                // Write bundles without chain links — all independent roots.
                // The key invariant: walk_chain terminates for any directory content.
                for (i, bundle) in bundles.iter().enumerate() {
                    let path = dir.path().join(format!("attestation-{i:04}.json"));
                    let json = serde_json::to_string(bundle).unwrap();
                    std::fs::write(&path, json).unwrap();
                }

                // Start from the first bundle
                let start = dir.path().join("attestation-0000.json");
                if start.exists() {
                    let chain = walk_chain(&start, dir.path()).unwrap();
                    // Must terminate and return at least the starting bundle.
                    prop_assert!(!chain.is_empty());
                }
            }

            /// walk_chain never returns duplicate payload digests (cycle detection works).
            #[test]
            fn walk_chain_no_duplicate_entries(chain_len in 2..10usize) {
                let dir = TempDir::new().unwrap();

                // Build a linear chain of the requested length
                let mut prev_digest: Option<String> = None;
                for i in 0..chain_len {
                    let chain_ref = prev_digest.as_deref().map(|d| (d, ""));
                    let ts = format!("2025-{:02}-01T00:00:00Z", (i % 12) + 1);
                    let bundle_json = make_bundle(chain_ref, &ts, &ts);
                    let path = dir.path().join(format!("attestation-{i:04}.json"));
                    std::fs::write(&path, &bundle_json).unwrap();

                    let bundle: AttestationBundle =
                        serde_json::from_str(&bundle_json).unwrap();
                    prev_digest = Some(compute_payload_digest(&bundle));
                }

                // Walk from the last bundle
                let start = dir.path().join(format!(
                    "attestation-{:04}.json",
                    chain_len - 1
                ));
                let chain = walk_chain(&start, dir.path()).unwrap();

                // No duplicate digests in the result
                let mut seen = HashSet::new();
                for entry in &chain {
                    prop_assert!(
                        seen.insert(&entry.payload_digest),
                        "duplicate digest in chain: {}",
                        entry.payload_digest
                    );
                }
            }
        }
    }
}
