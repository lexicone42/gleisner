//! Semantic diff between two attestation bundles.
//!
//! Compares attestation bundles at a structural level rather than raw
//! JSON diff. Reports changes in subjects, materials, environment,
//! timing, and chain linkage.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde::Serialize;

use crate::error::VerificationError;

/// A semantic diff between two attestation bundles.
#[derive(Debug, Serialize)]
pub struct AttestationDiff {
    /// Subjects added in the "after" bundle.
    pub subjects_added: Vec<NamedDigest>,
    /// Subjects removed from the "before" bundle.
    pub subjects_removed: Vec<NamedDigest>,
    /// Subjects present in both but with different digests.
    pub subjects_changed: Vec<DigestChange>,
    /// Materials added in the "after" bundle.
    pub materials_added: Vec<String>,
    /// Materials removed from the "before" bundle.
    pub materials_removed: Vec<String>,
    /// Environment field changes.
    pub environment_changes: Vec<FieldChange>,
    /// Timing changes.
    pub timing: Option<TimingDiff>,
}

/// A named artifact with its digest.
#[derive(Debug, Clone, Serialize)]
pub struct NamedDigest {
    /// Artifact name (e.g., file path).
    pub name: String,
    /// SHA-256 hex digest.
    pub sha256: String,
}

/// A digest that changed between bundles.
#[derive(Debug, Clone, Serialize)]
pub struct DigestChange {
    /// Artifact name.
    pub name: String,
    /// Digest in the "before" bundle.
    pub before: String,
    /// Digest in the "after" bundle.
    pub after: String,
}

/// A scalar field that changed.
#[derive(Debug, Clone, Serialize)]
pub struct FieldChange {
    /// Field name.
    pub field: String,
    /// Value in the "before" bundle.
    pub before: String,
    /// Value in the "after" bundle.
    pub after: String,
}

/// Timing comparison.
#[derive(Debug, Clone, Serialize)]
pub struct TimingDiff {
    /// Build start time of the "before" bundle.
    pub before_started: String,
    /// Build finish time of the "before" bundle.
    pub before_finished: String,
    /// Build start time of the "after" bundle.
    pub after_started: String,
    /// Build finish time of the "after" bundle.
    pub after_finished: String,
    /// Duration in seconds of the "before" session.
    pub before_duration_secs: Option<f64>,
    /// Duration in seconds of the "after" session.
    pub after_duration_secs: Option<f64>,
}

impl AttestationDiff {
    /// True if the two bundles are semantically identical.
    pub fn is_empty(&self) -> bool {
        self.subjects_added.is_empty()
            && self.subjects_removed.is_empty()
            && self.subjects_changed.is_empty()
            && self.materials_added.is_empty()
            && self.materials_removed.is_empty()
            && self.environment_changes.is_empty()
            && self.timing.is_none()
    }
}

/// Compare two attestation bundle JSON strings and produce a semantic diff.
pub fn diff_bundles(
    before_json: &str,
    after_json: &str,
) -> Result<AttestationDiff, VerificationError> {
    let before_payload = extract_payload(before_json)?;
    let after_payload = extract_payload(after_json)?;

    let subjects_diff = diff_subjects(&before_payload, &after_payload);
    let materials_diff = diff_materials(&before_payload, &after_payload);
    let env_changes = diff_environment(&before_payload, &after_payload);
    let timing = diff_timing(&before_payload, &after_payload);

    Ok(AttestationDiff {
        subjects_added: subjects_diff.0,
        subjects_removed: subjects_diff.1,
        subjects_changed: subjects_diff.2,
        materials_added: materials_diff.0,
        materials_removed: materials_diff.1,
        environment_changes: env_changes,
        timing,
    })
}

/// Format a diff as human-readable text.
pub fn format_diff(diff: &AttestationDiff) -> String {
    if diff.is_empty() {
        return "No differences.\n".to_owned();
    }

    let mut out = String::new();

    if !diff.subjects_added.is_empty()
        || !diff.subjects_removed.is_empty()
        || !diff.subjects_changed.is_empty()
    {
        let _ = writeln!(out, "Subjects:");
        for s in &diff.subjects_added {
            let _ = writeln!(
                out,
                "  + {} ({})",
                s.name,
                &s.sha256[..12.min(s.sha256.len())]
            );
        }
        for s in &diff.subjects_removed {
            let _ = writeln!(
                out,
                "  - {} ({})",
                s.name,
                &s.sha256[..12.min(s.sha256.len())]
            );
        }
        for c in &diff.subjects_changed {
            let _ = writeln!(
                out,
                "  ~ {} ({} -> {})",
                c.name,
                &c.before[..12.min(c.before.len())],
                &c.after[..12.min(c.after.len())]
            );
        }
        let _ = writeln!(out);
    }

    if !diff.materials_added.is_empty() || !diff.materials_removed.is_empty() {
        let _ = writeln!(out, "Materials:");
        for m in &diff.materials_added {
            let _ = writeln!(out, "  + {m}");
        }
        for m in &diff.materials_removed {
            let _ = writeln!(out, "  - {m}");
        }
        let _ = writeln!(out);
    }

    if !diff.environment_changes.is_empty() {
        let _ = writeln!(out, "Environment:");
        for c in &diff.environment_changes {
            let _ = writeln!(out, "  {}: {} -> {}", c.field, c.before, c.after);
        }
        let _ = writeln!(out);
    }

    if let Some(t) = &diff.timing {
        let _ = writeln!(out, "Timing:");
        let _ = writeln!(
            out,
            "  before: {} .. {}",
            t.before_started, t.before_finished
        );
        let _ = writeln!(out, "  after:  {} .. {}", t.after_started, t.after_finished);
        if let (Some(bd), Some(ad)) = (t.before_duration_secs, t.after_duration_secs) {
            let delta = ad - bd;
            let sign = if delta >= 0.0 { "+" } else { "" };
            let _ = writeln!(out, "  duration: {bd:.0}s -> {ad:.0}s ({sign}{delta:.0}s)");
        }
        let _ = writeln!(out);
    }

    out
}

// ── Internal helpers ─────────────────────────────────────────────────

fn extract_payload(bundle_json: &str) -> Result<serde_json::Value, VerificationError> {
    let bundle: serde_json::Value = serde_json::from_str(bundle_json)?;
    let payload_str = bundle
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| VerificationError::InvalidBundle("missing payload field".to_owned()))?;
    serde_json::from_str(payload_str).map_err(VerificationError::from)
}

fn diff_subjects(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> (Vec<NamedDigest>, Vec<NamedDigest>, Vec<DigestChange>) {
    let before_map = subjects_to_map(before);
    let after_map = subjects_to_map(after);

    let before_names: BTreeSet<&String> = before_map.keys().collect();
    let after_names: BTreeSet<&String> = after_map.keys().collect();

    let added: Vec<NamedDigest> = after_names
        .difference(&before_names)
        .map(|name| NamedDigest {
            name: (*name).clone(),
            sha256: after_map[*name].clone(),
        })
        .collect();

    let removed: Vec<NamedDigest> = before_names
        .difference(&after_names)
        .map(|name| NamedDigest {
            name: (*name).clone(),
            sha256: before_map[*name].clone(),
        })
        .collect();

    let changed: Vec<DigestChange> = before_names
        .intersection(&after_names)
        .filter(|name| before_map[**name] != after_map[**name])
        .map(|name| DigestChange {
            name: (*name).clone(),
            before: before_map[*name].clone(),
            after: after_map[*name].clone(),
        })
        .collect();

    (added, removed, changed)
}

fn subjects_to_map(payload: &serde_json::Value) -> BTreeMap<String, String> {
    payload
        .get("subject")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let name = s.get("name")?.as_str()?;
                    let digest = s.get("digest")?.get("sha256")?.as_str()?;
                    Some((name.to_owned(), digest.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn diff_materials(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> (Vec<String>, Vec<String>) {
    let before_uris = materials_to_set(before);
    let after_uris = materials_to_set(after);

    let added = after_uris.difference(&before_uris).cloned().collect();
    let removed = before_uris.difference(&after_uris).cloned().collect();

    (added, removed)
}

fn materials_to_set(payload: &serde_json::Value) -> BTreeSet<String> {
    payload
        .get("predicate")
        .and_then(|p| p.get("materials"))
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("uri")?.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn diff_environment(before: &serde_json::Value, after: &serde_json::Value) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    let fields: &[(&[&str], &str)] = &[
        (&["invocation", "environment", "sandboxed"], "sandboxed"),
        (&["invocation", "environment", "profile"], "profile"),
        (&["invocation", "environment", "model"], "model"),
        (
            &["invocation", "environment", "claudeCodeVersion"],
            "claude_code_version",
        ),
        (&["gleisner:sandboxProfile", "name"], "sandbox_profile"),
        (
            &["gleisner:sandboxProfile", "networkPolicy"],
            "network_policy",
        ),
    ];

    let bp = before.get("predicate");
    let ap = after.get("predicate");

    for (path, label) in fields {
        let bv = nav_str(bp, path);
        let av = nav_str(ap, path);
        if bv != av {
            changes.push(FieldChange {
                field: (*label).to_owned(),
                before: bv,
                after: av,
            });
        }
    }

    // Compare chain linkage
    let before_chain = bp
        .and_then(|p| p.get("gleisner:chain"))
        .and_then(|c| c.get("parentDigest"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_owned();
    let after_chain = ap
        .and_then(|p| p.get("gleisner:chain"))
        .and_then(|c| c.get("parentDigest"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_owned();
    if before_chain != after_chain {
        changes.push(FieldChange {
            field: "chain_parent".to_owned(),
            before: if before_chain.is_empty() {
                "(none)".to_owned()
            } else {
                before_chain
            },
            after: if after_chain.is_empty() {
                "(none)".to_owned()
            } else {
                after_chain
            },
        });
    }

    changes
}

fn nav_str(root: Option<&serde_json::Value>, path: &[&str]) -> String {
    let mut current = root;
    for key in path {
        current = current.and_then(|v| v.get(*key));
    }
    match current {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Null) | None => "(absent)".to_owned(),
        Some(other) => other.to_string(),
    }
}

fn diff_timing(before: &serde_json::Value, after: &serde_json::Value) -> Option<TimingDiff> {
    let bp = before.get("predicate")?.get("metadata")?;
    let ap = after.get("predicate")?.get("metadata")?;

    let bs = bp.get("buildStartedOn")?.as_str()?.to_owned();
    let bf = bp.get("buildFinishedOn")?.as_str()?.to_owned();
    let as_ = ap.get("buildStartedOn")?.as_str()?.to_owned();
    let af = ap.get("buildFinishedOn")?.as_str()?.to_owned();

    // If all four timestamps are identical, no timing diff
    if bs == as_ && bf == af {
        return None;
    }

    let parse_dur = |started: &str, finished: &str| -> Option<f64> {
        let s = chrono::DateTime::parse_from_rfc3339(started).ok()?;
        let f = chrono::DateTime::parse_from_rfc3339(finished).ok()?;
        #[expect(
            clippy::cast_precision_loss,
            reason = "session durations don't approach 2^52 ms"
        )]
        Some(f.signed_duration_since(s).num_milliseconds() as f64 / 1000.0)
    };

    Some(TimingDiff {
        before_duration_secs: parse_dur(&bs, &bf),
        after_duration_secs: parse_dur(&as_, &af),
        before_started: bs,
        before_finished: bf,
        after_started: as_,
        after_finished: af,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle(payload: &serde_json::Value) -> String {
        let bundle = serde_json::json!({
            "payload": payload.to_string(),
            "signature": "",
            "verification_material": { "type": "none" }
        });
        serde_json::to_string(&bundle).unwrap()
    }

    fn base_payload() -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                { "name": "src/main.rs", "digest": { "sha256": "aaa111" } },
                { "name": "src/lib.rs", "digest": { "sha256": "bbb222" } }
            ],
            "predicateType": "https://gleisner.dev/provenance/v1",
            "predicate": {
                "buildType": "https://gleisner.dev/claude-code/v1",
                "builder": { "id": "gleisner-cli/0.1.0" },
                "invocation": {
                    "environment": {
                        "sandboxed": true,
                        "profile": "konishi",
                        "model": "claude-sonnet-4-5-20250929"
                    }
                },
                "metadata": {
                    "buildStartedOn": "2025-01-01T00:00:00Z",
                    "buildFinishedOn": "2025-01-01T00:05:00Z"
                },
                "materials": [
                    { "uri": "git+https://github.com/example/repo@abc123" }
                ],
                "gleisner:sandboxProfile": {
                    "name": "konishi",
                    "networkPolicy": "deny"
                }
            }
        })
    }

    #[test]
    fn identical_bundles_produce_empty_diff() {
        let json = make_bundle(&base_payload());
        let diff = diff_bundles(&json, &json).unwrap();
        assert!(diff.is_empty());
    }

    #[test]
    fn added_subject_detected() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["subject"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name": "src/new.rs",
                "digest": { "sha256": "ccc333" }
            }));
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        assert_eq!(diff.subjects_added.len(), 1);
        assert_eq!(diff.subjects_added[0].name, "src/new.rs");
        assert!(diff.subjects_removed.is_empty());
    }

    #[test]
    fn removed_subject_detected() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["subject"].as_array_mut().unwrap().pop();
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        assert!(diff.subjects_added.is_empty());
        assert_eq!(diff.subjects_removed.len(), 1);
        assert_eq!(diff.subjects_removed[0].name, "src/lib.rs");
    }

    #[test]
    fn changed_subject_detected() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["subject"][0]["digest"]["sha256"] = serde_json::json!("xxx999");
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        assert_eq!(diff.subjects_changed.len(), 1);
        assert_eq!(diff.subjects_changed[0].name, "src/main.rs");
        assert_eq!(diff.subjects_changed[0].before, "aaa111");
        assert_eq!(diff.subjects_changed[0].after, "xxx999");
    }

    #[test]
    fn profile_change_detected() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["predicate"]["invocation"]["environment"]["profile"] =
            serde_json::json!("developer");
        after_payload["predicate"]["gleisner:sandboxProfile"]["name"] =
            serde_json::json!("developer");
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        let profile_change = diff
            .environment_changes
            .iter()
            .find(|c| c.field == "profile")
            .expect("profile field should change");
        assert_eq!(profile_change.before, "konishi");
        assert_eq!(profile_change.after, "developer");
    }

    #[test]
    fn timing_diff_with_duration() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["predicate"]["metadata"]["buildStartedOn"] =
            serde_json::json!("2025-01-02T00:00:00Z");
        after_payload["predicate"]["metadata"]["buildFinishedOn"] =
            serde_json::json!("2025-01-02T00:10:00Z");
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        let timing = diff.timing.as_ref().expect("timing should differ");
        assert!((timing.before_duration_secs.unwrap() - 300.0).abs() < 1.0);
        assert!((timing.after_duration_secs.unwrap() - 600.0).abs() < 1.0);
    }

    #[test]
    fn material_added() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["predicate"]["materials"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "uri": "file:///new-dep.lock"
            }));
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        assert_eq!(diff.materials_added.len(), 1);
        assert_eq!(diff.materials_added[0], "file:///new-dep.lock");
    }

    #[test]
    fn format_diff_empty() {
        let json = make_bundle(&base_payload());
        let diff = diff_bundles(&json, &json).unwrap();
        let output = format_diff(&diff);
        assert_eq!(output, "No differences.\n");
    }

    #[test]
    fn format_diff_shows_changes() {
        let before = make_bundle(&base_payload());
        let mut after_payload = base_payload();
        after_payload["subject"][0]["digest"]["sha256"] = serde_json::json!("xxx999");
        after_payload["predicate"]["invocation"]["environment"]["profile"] =
            serde_json::json!("developer");
        let after = make_bundle(&after_payload);

        let diff = diff_bundles(&before, &after).unwrap();
        let output = format_diff(&diff);
        assert!(output.contains("Subjects:"));
        assert!(output.contains("~ src/main.rs"));
        assert!(output.contains("Environment:"));
        assert!(output.contains("developer"));
    }
}
