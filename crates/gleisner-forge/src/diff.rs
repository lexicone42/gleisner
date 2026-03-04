//! Forge attestation diff — compare two evaluation runs.
//!
//! Takes two forge attestation JSON outputs and reports:
//! - Packages added or removed
//! - Packages whose evaluation hash changed
//! - Verification status changes
//! - Source URL or hash changes

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A diff between two forge attestation outputs.
#[derive(Debug, Clone, Serialize)]
pub struct ForgeDiff {
    /// Packages present in `after` but not `before`.
    pub packages_added: Vec<String>,
    /// Packages present in `before` but not `after`.
    pub packages_removed: Vec<String>,
    /// Packages whose source hashes changed.
    pub source_changes: Vec<SourceChange>,
    /// Packages whose verification status changed.
    pub verification_changes: Vec<VerificationChange>,
    /// Summary statistics.
    pub summary: DiffSummary,
}

/// A source material change for a package.
#[derive(Debug, Clone, Serialize)]
pub struct SourceChange {
    /// Package name.
    pub package: String,
    /// Sources added.
    pub added: Vec<SourceEntry>,
    /// Sources removed.
    pub removed: Vec<SourceEntry>,
    /// Sources whose hash changed.
    pub hash_changed: Vec<HashChange>,
}

/// A source entry (URI + hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SourceEntry {
    /// Source URI.
    pub uri: String,
    /// SHA-256 hash.
    pub sha256: String,
}

/// A hash change for a source.
#[derive(Debug, Clone, Serialize)]
pub struct HashChange {
    /// Source URI.
    pub uri: String,
    /// Hash in the `before` attestation.
    pub before: String,
    /// Hash in the `after` attestation.
    pub after: String,
}

/// A verification status change.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationChange {
    /// Package name.
    pub package: String,
    /// Property name.
    pub property: String,
    /// Status in `before` (true/false/null/missing).
    pub before: Option<bool>,
    /// Status in `after`.
    pub after: Option<bool>,
    /// Proof hash change, if any.
    pub proof_hash_change: Option<HashChange>,
}

/// Summary of the diff.
#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    /// Total packages in `before`.
    pub before_count: usize,
    /// Total packages in `after`.
    pub after_count: usize,
    /// Number of packages added.
    pub added: usize,
    /// Number of packages removed.
    pub removed: usize,
    /// Number of packages with source changes.
    pub source_changed: usize,
    /// Number of properties with verification changes.
    pub verification_changed: usize,
    /// Whether anything changed at all.
    pub unchanged: bool,
}

impl ForgeDiff {
    /// Whether the two attestations are identical.
    pub const fn is_empty(&self) -> bool {
        self.summary.unchanged
    }
}

/// Compare two forge attestation JSON outputs.
pub fn diff_attestations(
    before_json: &serde_json::Value,
    after_json: &serde_json::Value,
) -> ForgeDiff {
    let before_pkgs = extract_package_map(before_json);
    let after_pkgs = extract_package_map(after_json);

    let before_names: BTreeSet<&str> = before_pkgs.keys().copied().collect();
    let after_names: BTreeSet<&str> = after_pkgs.keys().copied().collect();

    let packages_added: Vec<String> = after_names
        .difference(&before_names)
        .map(ToString::to_string)
        .collect();
    let packages_removed: Vec<String> = before_names
        .difference(&after_names)
        .map(ToString::to_string)
        .collect();

    // Compare sources for packages present in both
    let mut source_changes = Vec::new();
    let mut verification_changes = Vec::new();

    for name in before_names.intersection(&after_names) {
        let before_pkg = &before_pkgs[name];
        let after_pkg = &after_pkgs[name];

        // Compare source URLs
        if let Some(sc) = diff_sources(name, before_pkg, after_pkg) {
            source_changes.push(sc);
        }

        // Compare verification status
        let mut vc = diff_verification(name, before_pkg, after_pkg);
        verification_changes.append(&mut vc);
    }

    let summary = DiffSummary {
        before_count: before_pkgs.len(),
        after_count: after_pkgs.len(),
        added: packages_added.len(),
        removed: packages_removed.len(),
        source_changed: source_changes.len(),
        verification_changed: verification_changes.len(),
        unchanged: packages_added.is_empty()
            && packages_removed.is_empty()
            && source_changes.is_empty()
            && verification_changes.is_empty(),
    };

    ForgeDiff {
        packages_added,
        packages_removed,
        source_changes,
        verification_changes,
        summary,
    }
}

/// Format a diff for human-readable output.
pub fn format_diff(diff: &ForgeDiff) -> String {
    if diff.is_empty() {
        return "No changes between attestations.\n".to_string();
    }

    let mut out = String::new();

    out.push_str(&format!(
        "Forge diff: {} before, {} after\n",
        diff.summary.before_count, diff.summary.after_count,
    ));
    out.push('\n');

    if !diff.packages_added.is_empty() {
        out.push_str(&format!(
            "  + {} packages added: {}\n",
            diff.packages_added.len(),
            diff.packages_added.join(", ")
        ));
    }
    if !diff.packages_removed.is_empty() {
        out.push_str(&format!(
            "  - {} packages removed: {}\n",
            diff.packages_removed.len(),
            diff.packages_removed.join(", ")
        ));
    }

    if !diff.source_changes.is_empty() {
        out.push_str(&format!(
            "\n  {} packages with source changes:\n",
            diff.source_changes.len()
        ));
        for sc in &diff.source_changes {
            out.push_str(&format!("    {}:\n", sc.package));
            for a in &sc.added {
                out.push_str(&format!("      + {}\n", a.uri));
            }
            for r in &sc.removed {
                out.push_str(&format!("      - {}\n", r.uri));
            }
            for h in &sc.hash_changed {
                out.push_str(&format!(
                    "      ~ {} hash: {}..{} -> {}..{}\n",
                    h.uri,
                    &h.before[..12.min(h.before.len())],
                    &h.before[h.before.len().saturating_sub(4)..],
                    &h.after[..12.min(h.after.len())],
                    &h.after[h.after.len().saturating_sub(4)..],
                ));
            }
        }
    }

    if !diff.verification_changes.is_empty() {
        out.push_str(&format!(
            "\n  {} verification changes:\n",
            diff.verification_changes.len()
        ));
        for vc in &diff.verification_changes {
            let before_str = match vc.before {
                Some(true) => "verified",
                Some(false) => "failed",
                None => "unchecked",
            };
            let after_str = match vc.after {
                Some(true) => "verified",
                Some(false) => "failed",
                None => "unchecked",
            };
            out.push_str(&format!(
                "    {}/{}: {} -> {}\n",
                vc.package, vc.property, before_str, after_str
            ));
            if let Some(hc) = &vc.proof_hash_change {
                out.push_str(&format!(
                    "      proof_hash: {}.. -> {}.. \n",
                    &hc.before[..20.min(hc.before.len())],
                    &hc.after[..20.min(hc.after.len())],
                ));
            }
        }
    }

    out
}

/// Extract `package_metadata` from attestation JSON into a name-keyed map.
fn extract_package_map(json: &serde_json::Value) -> BTreeMap<&str, &serde_json::Value> {
    let mut map = BTreeMap::new();
    if let Some(metadata) = json
        .get("attestation")
        .and_then(|a| a.get("package_metadata"))
        .and_then(|m| m.as_array())
    {
        for pkg in metadata {
            if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                map.insert(name, pkg);
            }
        }
    }
    map
}

/// Compare source URLs between two package entries.
fn diff_sources(
    name: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Option<SourceChange> {
    let before_sources = extract_sources(before);
    let after_sources = extract_sources(after);

    let before_uris: BTreeMap<&str, &str> = before_sources
        .iter()
        .map(|(u, h)| (u.as_str(), h.as_str()))
        .collect();
    let after_uris: BTreeMap<&str, &str> = after_sources
        .iter()
        .map(|(u, h)| (u.as_str(), h.as_str()))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut hash_changed = Vec::new();

    for (uri, hash) in &after_uris {
        match before_uris.get(uri) {
            None => added.push(SourceEntry {
                uri: uri.to_string(),
                sha256: hash.to_string(),
            }),
            Some(before_hash) if before_hash != hash => {
                hash_changed.push(HashChange {
                    uri: uri.to_string(),
                    before: before_hash.to_string(),
                    after: hash.to_string(),
                });
            }
            _ => {}
        }
    }
    for (uri, hash) in &before_uris {
        if !after_uris.contains_key(uri) {
            removed.push(SourceEntry {
                uri: uri.to_string(),
                sha256: hash.to_string(),
            });
        }
    }

    if added.is_empty() && removed.is_empty() && hash_changed.is_empty() {
        None
    } else {
        Some(SourceChange {
            package: name.to_string(),
            added,
            removed,
            hash_changed,
        })
    }
}

/// Extract (uri, sha256) pairs from a package's `source_urls`.
fn extract_sources(pkg: &serde_json::Value) -> Vec<(String, String)> {
    pkg.get("source_urls")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let uri = entry.get("uri")?.as_str()?.to_string();
                    let sha = entry.get("sha256")?.as_str()?.to_string();
                    Some((uri, sha))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Compare verification status between two package entries.
fn diff_verification(
    name: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Vec<VerificationChange> {
    let before_props = extract_verified_props(before);
    let after_props = extract_verified_props(after);

    let mut changes = Vec::new();

    // Check all properties in after
    for (prop_name, after_status, after_hash) in &after_props {
        let before_entry = before_props.iter().find(|(n, _, _)| n == prop_name);

        let (before_status, before_hash) = match before_entry {
            Some((_, s, h)) => (*s, h.clone()),
            None => (None, None),
        };

        if before_status != *after_status || before_hash != *after_hash {
            let proof_hash_change = match (&before_hash, after_hash) {
                (Some(bh), Some(ah)) if bh != ah => Some(HashChange {
                    uri: prop_name.clone(),
                    before: bh.clone(),
                    after: ah.clone(),
                }),
                (None, Some(ah)) => Some(HashChange {
                    uri: prop_name.clone(),
                    before: "(none)".to_string(),
                    after: ah.clone(),
                }),
                _ => None,
            };

            changes.push(VerificationChange {
                package: name.to_string(),
                property: prop_name.clone(),
                before: before_status,
                after: *after_status,
                proof_hash_change,
            });
        }
    }

    // Check for properties removed in after
    for (prop_name, before_status, _) in &before_props {
        if !after_props.iter().any(|(n, _, _)| n == prop_name) {
            changes.push(VerificationChange {
                package: name.to_string(),
                property: prop_name.clone(),
                before: *before_status,
                after: None,
                proof_hash_change: None,
            });
        }
    }

    changes
}

/// Extract (`property_name`, `verified_by_forge`, `proof_hash`) tuples.
fn extract_verified_props(pkg: &serde_json::Value) -> Vec<(String, Option<bool>, Option<String>)> {
    pkg.get("verified_properties")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|prop| {
                    let name = prop.get("property")?.as_str()?.to_string();
                    let verified = prop
                        .get("verified_by_forge")
                        .and_then(serde_json::Value::as_bool);
                    let hash = prop
                        .get("proof_hash")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    Some((name, verified, hash))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(packages: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "attestation": {
                "package_metadata": packages,
                "verification": null,
            }
        })
    }

    fn make_pkg(name: &str, source_hash: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "source_urls": [
                { "uri": format!("gs://archives/{name}.tar.gz"), "sha256": source_hash }
            ],
            "verified_properties": [],
        })
    }

    fn make_pkg_with_proof(
        name: &str,
        prop: &str,
        verified: Option<bool>,
        hash: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "source_urls": [],
            "verified_properties": [{
                "property": prop,
                "verified_by_forge": verified,
                "proof_hash": hash,
            }],
        })
    }

    #[test]
    fn identical_attestations_empty_diff() {
        let a = make_attestation(serde_json::json!([make_pkg("zlib", "abc123")]));
        let diff = diff_attestations(&a, &a);
        assert!(diff.is_empty());
        assert!(diff.summary.unchanged);
    }

    #[test]
    fn package_added() {
        let before = make_attestation(serde_json::json!([make_pkg("zlib", "abc")]));
        let after = make_attestation(serde_json::json!([
            make_pkg("zlib", "abc"),
            make_pkg("curl", "def"),
        ]));
        let diff = diff_attestations(&before, &after);
        assert_eq!(diff.packages_added, vec!["curl"]);
        assert!(diff.packages_removed.is_empty());
        assert!(!diff.is_empty());
    }

    #[test]
    fn package_removed() {
        let before = make_attestation(serde_json::json!([
            make_pkg("zlib", "abc"),
            make_pkg("curl", "def"),
        ]));
        let after = make_attestation(serde_json::json!([make_pkg("zlib", "abc")]));
        let diff = diff_attestations(&before, &after);
        assert!(diff.packages_added.is_empty());
        assert_eq!(diff.packages_removed, vec!["curl"]);
    }

    #[test]
    fn source_hash_changed() {
        let before = make_attestation(serde_json::json!([make_pkg("zlib", "abc123")]));
        let after = make_attestation(serde_json::json!([make_pkg("zlib", "def456")]));
        let diff = diff_attestations(&before, &after);
        assert_eq!(diff.source_changes.len(), 1);
        assert_eq!(diff.source_changes[0].package, "zlib");
        assert_eq!(diff.source_changes[0].hash_changed.len(), 1);
        assert_eq!(diff.source_changes[0].hash_changed[0].before, "abc123");
        assert_eq!(diff.source_changes[0].hash_changed[0].after, "def456");
    }

    #[test]
    fn verification_status_changed() {
        let before = make_attestation(serde_json::json!([make_pkg_with_proof(
            "zlib",
            "roundtrip",
            None,
            "sha256:old"
        ),]));
        let after = make_attestation(serde_json::json!([make_pkg_with_proof(
            "zlib",
            "roundtrip",
            Some(true),
            "sha256:new"
        ),]));
        let diff = diff_attestations(&before, &after);
        assert_eq!(diff.verification_changes.len(), 1);
        assert_eq!(diff.verification_changes[0].before, None);
        assert_eq!(diff.verification_changes[0].after, Some(true));
        assert!(diff.verification_changes[0].proof_hash_change.is_some());
    }

    #[test]
    fn format_diff_no_changes() {
        let a = make_attestation(serde_json::json!([make_pkg("zlib", "abc")]));
        let diff = diff_attestations(&a, &a);
        let output = format_diff(&diff);
        assert!(output.contains("No changes"));
    }

    #[test]
    fn format_diff_shows_additions_and_removals() {
        let before = make_attestation(serde_json::json!([make_pkg("old", "x")]));
        let after = make_attestation(serde_json::json!([make_pkg("new", "y")]));
        let diff = diff_attestations(&before, &after);
        let output = format_diff(&diff);
        assert!(output.contains("+ 1 packages added"));
        assert!(output.contains("- 1 packages removed"));
        assert!(output.contains("new"));
        assert!(output.contains("old"));
    }
}
