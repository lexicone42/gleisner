//! Human-readable attestation display.
//!
//! Extracts key fields from an attestation bundle and formats them
//! for terminal display.

use std::fmt::Write;

use crate::error::VerificationError;

/// Extracted summary of an attestation bundle.
#[derive(Debug)]
pub struct AttestationSummary {
    /// The in-toto statement type URI.
    pub statement_type: String,
    /// The predicate type URI.
    pub predicate_type: String,
    /// Builder ID.
    pub builder_id: String,
    /// Build type.
    pub build_type: String,
    /// Build started timestamp.
    pub build_started: String,
    /// Build finished timestamp.
    pub build_finished: String,
    /// Number of subjects.
    pub subject_count: usize,
    /// Number of materials.
    pub material_count: usize,
    /// Sandbox profile name.
    pub sandbox_profile: String,
    /// Whether the session was sandboxed.
    pub sandboxed: bool,
    /// Verification material type.
    pub material_type: String,
    /// Whether an audit log digest is present.
    pub has_audit_log: bool,
}

/// Extract a summary from a bundle JSON string.
pub fn summarize(bundle_json: &str) -> Result<AttestationSummary, VerificationError> {
    let bundle: serde_json::Value = serde_json::from_str(bundle_json)?;
    let payload_str = bundle
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| VerificationError::InvalidBundle("missing payload field".to_owned()))?;

    let payload: serde_json::Value = serde_json::from_str(payload_str)?;
    let predicate = payload.get("predicate");

    let str_field = |obj: Option<&serde_json::Value>, keys: &[&str]| -> String {
        let mut current = obj;
        for key in keys {
            current = current.and_then(|v| v.get(*key));
        }
        current.and_then(|v| v.as_str()).unwrap_or("").to_owned()
    };

    let material_type = bundle
        .get("verification_material")
        .and_then(|vm| vm.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_owned();

    let has_audit_log = predicate
        .and_then(|p| p.get("gleisner:auditLogDigest"))
        .and_then(|d| d.as_str())
        .is_some_and(|s| !s.is_empty());

    Ok(AttestationSummary {
        statement_type: str_field(Some(&payload), &["_type"]),
        predicate_type: str_field(Some(&payload), &["predicateType"]),
        builder_id: str_field(predicate, &["builder", "id"]),
        build_type: str_field(predicate, &["buildType"]),
        build_started: str_field(predicate, &["metadata", "buildStartedOn"]),
        build_finished: str_field(predicate, &["metadata", "buildFinishedOn"]),
        subject_count: payload
            .get("subject")
            .and_then(|s| s.as_array())
            .map_or(0, Vec::len),
        material_count: predicate
            .and_then(|p| p.get("materials"))
            .and_then(|m| m.as_array())
            .map_or(0, Vec::len),
        sandbox_profile: str_field(predicate, &["gleisner:sandboxProfile", "name"]),
        sandboxed: predicate
            .and_then(|p| p.get("invocation"))
            .and_then(|i| i.get("environment"))
            .and_then(|e| e.get("sandboxed"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        material_type,
        has_audit_log,
    })
}

/// Format a summary as a human-readable string.
pub fn format_summary(summary: &AttestationSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Attestation Summary");
    let _ = writeln!(out, "-------------------");
    let _ = writeln!(out, "Statement type:  {}", summary.statement_type);
    let _ = writeln!(out, "Predicate type:  {}", summary.predicate_type);
    let _ = writeln!(out, "Builder:         {}", summary.builder_id);
    let _ = writeln!(out, "Build type:      {}", summary.build_type);
    let _ = writeln!(out, "Started:         {}", summary.build_started);
    let _ = writeln!(out, "Finished:        {}", summary.build_finished);
    let _ = writeln!(out, "Subjects:        {}", summary.subject_count);
    let _ = writeln!(out, "Materials:       {}", summary.material_count);
    let _ = writeln!(out, "Sandbox profile: {}", summary.sandbox_profile);
    let _ = writeln!(
        out,
        "Sandboxed:       {}",
        if summary.sandboxed { "yes" } else { "no" }
    );
    let _ = writeln!(out, "Signing method:  {}", summary.material_type);
    let _ = writeln!(
        out,
        "Audit log:       {}",
        if summary.has_audit_log {
            "present"
        } else {
            "absent"
        }
    );
    out
}

/// Format a detailed view of the full bundle.
pub fn format_detailed(bundle_json: &str) -> Result<String, VerificationError> {
    let bundle: serde_json::Value = serde_json::from_str(bundle_json)?;
    let payload_str = bundle
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| VerificationError::InvalidBundle("missing payload field".to_owned()))?;

    let payload: serde_json::Value = serde_json::from_str(payload_str)?;

    let summary = summarize(bundle_json)?;
    let mut out = format_summary(&summary);

    // Subjects
    if let Some(subjects) = payload.get("subject").and_then(|s| s.as_array()) {
        let _ = writeln!(out);
        let _ = writeln!(out, "Subjects:");
        for subject in subjects {
            let name = subject.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let digest = subject
                .get("digest")
                .and_then(|d| d.get("sha256"))
                .and_then(|h| h.as_str())
                .unwrap_or("?");
            let _ = writeln!(out, "  {name}  sha256:{digest}");
        }
    }

    // Materials
    let predicate = payload.get("predicate");
    if let Some(materials) = predicate
        .and_then(|p| p.get("materials"))
        .and_then(|m| m.as_array())
    {
        let _ = writeln!(out);
        let _ = writeln!(out, "Materials:");
        for material in materials {
            let uri = material.get("uri").and_then(|u| u.as_str()).unwrap_or("?");
            let _ = writeln!(out, "  {uri}");
        }
    }

    // Verification material
    let _ = writeln!(out);
    let _ = writeln!(out, "Verification Material:");
    if let Some(vm) = bundle.get("verification_material") {
        let vm_type = vm.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
        let _ = writeln!(out, "  Type: {vm_type}");
        match vm_type {
            "local_key" => {
                if let Some(pk) = vm.get("public_key").and_then(|p| p.as_str()) {
                    let _ = writeln!(out, "  Public key:");
                    for line in pk.lines() {
                        let _ = writeln!(out, "    {line}");
                    }
                }
            }
            "sigstore" => {
                if let Some(log_id) = vm.get("rekor_log_id").and_then(|l| l.as_str()) {
                    let _ = writeln!(out, "  Rekor log ID: {log_id}");
                }
            }
            _ => {}
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bundle_json() -> String {
        let payload = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://gleisner.dev/provenance/v1",
            "subject": [
                { "name": "output.txt", "digest": { "sha256": "abc123" } }
            ],
            "predicate": {
                "buildType": "https://gleisner.dev/ClaudeCodeSession/v1",
                "builder": { "id": "gleisner-cli/0.1.0" },
                "invocation": {
                    "environment": { "sandboxed": true }
                },
                "metadata": {
                    "buildStartedOn": "2025-01-01T00:00:00Z",
                    "buildFinishedOn": "2025-01-01T00:05:00Z"
                },
                "gleisner:auditLogDigest": "deadbeef",
                "gleisner:sandboxProfile": { "name": "strict" },
                "materials": [
                    { "uri": "git+https://github.com/example/repo@abc123" }
                ]
            }
        });

        let bundle = serde_json::json!({
            "payload": payload.to_string(),
            "signature": "dGVzdA==",
            "verification_material": {
                "type": "local_key",
                "public_key": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
            }
        });

        serde_json::to_string(&bundle).expect("serialize")
    }

    #[test]
    fn summarize_valid_bundle() {
        let json = test_bundle_json();
        let summary = summarize(&json).expect("summarize");

        assert_eq!(summary.statement_type, "https://in-toto.io/Statement/v1");
        assert_eq!(summary.builder_id, "gleisner-cli/0.1.0");
        assert_eq!(summary.subject_count, 1);
        assert_eq!(summary.material_count, 1);
        assert!(summary.sandboxed);
        assert_eq!(summary.sandbox_profile, "strict");
        assert_eq!(summary.material_type, "local_key");
        assert!(summary.has_audit_log);
    }

    #[test]
    fn format_summary_contains_fields() {
        let json = test_bundle_json();
        let summary = summarize(&json).expect("summarize");
        let formatted = format_summary(&summary);

        assert!(formatted.contains("gleisner-cli/0.1.0"));
        assert!(formatted.contains("yes")); // sandboxed
        assert!(formatted.contains("strict"));
        assert!(formatted.contains("local_key"));
    }

    #[test]
    fn format_detailed_includes_subjects() {
        let json = test_bundle_json();
        let detailed = format_detailed(&json).expect("detailed");

        assert!(detailed.contains("output.txt"));
        assert!(detailed.contains("abc123"));
        assert!(detailed.contains("git+https://github.com/example/repo"));
    }
}
