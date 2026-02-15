//! Policy evaluation for attestation bundles.
//!
//! The `PolicyEngine` trait defines the interface for policy evaluation.
//! `BuiltinPolicy` provides JSON-configurable rules without requiring
//! an external policy engine.

use serde::{Deserialize, Serialize};

use crate::error::VerificationError;

/// Input to a policy engine — extracted from the attestation payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyInput {
    /// Whether the session was sandboxed.
    pub sandboxed: Option<bool>,
    /// The sandbox profile name.
    pub sandbox_profile: Option<String>,
    /// Session duration in seconds.
    pub session_duration_secs: Option<f64>,
    /// Whether an audit log digest is present.
    pub has_audit_log: bool,
    /// The builder ID string.
    pub builder_id: Option<String>,
    /// Whether verification materials are present.
    pub has_materials: bool,
    /// Whether this attestation has a parent (is part of a chain).
    pub has_parent_attestation: bool,
    /// Number of links in the attestation chain (if verified).
    pub chain_length: Option<u64>,
}

/// Result of a single policy rule evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    /// Name of the rule that was evaluated.
    pub rule: String,
    /// Whether the rule passed.
    pub passed: bool,
    /// Human-readable description of the outcome.
    pub message: String,
}

/// A policy engine evaluates attestation data against a set of rules.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate the policy against the given input.
    fn evaluate(&self, input: &PolicyInput) -> Result<Vec<PolicyResult>, VerificationError>;
}

/// Built-in policy engine with JSON-configurable rules.
///
/// All fields are `Option` — absent rules are skipped (not failed).
/// This provides opt-in strictness: you only fail on rules you explicitly set.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BuiltinPolicy {
    /// Require that the session was sandboxed.
    pub require_sandbox: Option<bool>,
    /// Allowed sandbox profile names.
    pub allowed_profiles: Option<Vec<String>>,
    /// Maximum session duration in seconds.
    pub max_session_duration_secs: Option<f64>,
    /// Require that an audit log digest is present.
    pub require_audit_log: Option<bool>,
    /// Allowed builder ID patterns (exact match).
    pub allowed_builders: Option<Vec<String>>,
    /// Require that verification materials are present.
    pub require_materials: Option<bool>,
    /// Require that the attestation has a parent (is part of a chain).
    pub require_parent_attestation: Option<bool>,
}

impl BuiltinPolicy {
    /// Load a policy from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, VerificationError> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(VerificationError::from)
    }
}

impl PolicyEngine for BuiltinPolicy {
    fn evaluate(&self, input: &PolicyInput) -> Result<Vec<PolicyResult>, VerificationError> {
        let mut results = Vec::new();

        if self.require_sandbox == Some(true) {
            let sandboxed = input.sandboxed.unwrap_or(false);
            results.push(PolicyResult {
                rule: "require_sandbox".to_owned(),
                passed: sandboxed,
                message: if sandboxed {
                    "session was sandboxed".to_owned()
                } else {
                    "session was NOT sandboxed".to_owned()
                },
            });
        }

        if let Some(allowed) = &self.allowed_profiles {
            let profile = input.sandbox_profile.as_deref().unwrap_or("");
            let passed = allowed.iter().any(|p| p == profile);
            results.push(PolicyResult {
                rule: "allowed_profiles".to_owned(),
                passed,
                message: if passed {
                    format!("profile '{profile}' is allowed")
                } else {
                    format!("profile '{profile}' is not in allowed list: {allowed:?}")
                },
            });
        }

        if let Some(max_secs) = self.max_session_duration_secs {
            if max_secs <= 0.0 {
                results.push(PolicyResult {
                    rule: "max_session_duration_secs".to_owned(),
                    passed: false,
                    message: format!(
                        "invalid policy: max_session_duration_secs must be positive, got {max_secs}"
                    ),
                });
            } else if let Some(duration) = input.session_duration_secs {
                let passed = duration <= max_secs;
                results.push(PolicyResult {
                    rule: "max_session_duration_secs".to_owned(),
                    passed,
                    message: if passed {
                        format!("session duration {duration:.0}s within limit {max_secs:.0}s")
                    } else {
                        format!("session duration {duration:.0}s exceeds limit {max_secs:.0}s")
                    },
                });
            }
        }

        if self.require_audit_log == Some(true) {
            results.push(PolicyResult {
                rule: "require_audit_log".to_owned(),
                passed: input.has_audit_log,
                message: if input.has_audit_log {
                    "audit log digest present".to_owned()
                } else {
                    "audit log digest missing".to_owned()
                },
            });
        }

        if let Some(allowed) = &self.allowed_builders {
            let builder = input.builder_id.as_deref().unwrap_or("");
            let passed = allowed.iter().any(|b| b == builder);
            results.push(PolicyResult {
                rule: "allowed_builders".to_owned(),
                passed,
                message: if passed {
                    format!("builder '{builder}' is allowed")
                } else {
                    format!("builder '{builder}' is not in allowed list: {allowed:?}")
                },
            });
        }

        if self.require_materials == Some(true) {
            results.push(PolicyResult {
                rule: "require_materials".to_owned(),
                passed: input.has_materials,
                message: if input.has_materials {
                    "verification materials present".to_owned()
                } else {
                    "verification materials missing".to_owned()
                },
            });
        }

        if self.require_parent_attestation == Some(true) {
            results.push(PolicyResult {
                rule: "require_parent_attestation".to_owned(),
                passed: input.has_parent_attestation,
                message: if input.has_parent_attestation {
                    "parent attestation present (part of chain)".to_owned()
                } else {
                    "no parent attestation (not part of a chain)".to_owned()
                },
            });
        }

        Ok(results)
    }
}

/// Extract `PolicyInput` from an attestation payload JSON value.
pub fn extract_policy_input(payload: &serde_json::Value) -> PolicyInput {
    let predicate = payload.get("predicate");

    let sandboxed = predicate
        .and_then(|p| p.get("invocation"))
        .and_then(|i| i.get("environment"))
        .and_then(|e| e.get("sandboxed"))
        .and_then(serde_json::Value::as_bool);

    let sandbox_profile = predicate
        .and_then(|p| p.get("gleisner:sandboxProfile"))
        .and_then(|sp| sp.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from);

    let session_duration_secs = {
        let started = predicate
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("buildStartedOn"))
            .and_then(|t| t.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
        let finished = predicate
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("buildFinishedOn"))
            .and_then(|t| t.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
        match (started, finished) {
            (Some(s), Some(f)) => {
                let dur = f.signed_duration_since(s);
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "session durations don't approach 2^52 ms"
                )]
                Some(dur.num_milliseconds() as f64 / 1000.0)
            }
            _ => None,
        }
    };

    let has_audit_log = predicate
        .and_then(|p| p.get("gleisner:auditLogDigest"))
        .and_then(|d| d.as_str())
        .is_some_and(|s| !s.is_empty());

    let builder_id = predicate
        .and_then(|p| p.get("builder"))
        .and_then(|b| b.get("id"))
        .and_then(|id| id.as_str())
        .map(String::from);

    let has_materials = predicate
        .and_then(|p| p.get("materials"))
        .and_then(|m| m.as_array())
        .is_some_and(|arr| !arr.is_empty());

    let has_parent_attestation = predicate
        .and_then(|p| p.get("gleisner:chain"))
        .and_then(|c| c.get("parentDigest"))
        .and_then(|d| d.as_str())
        .is_some_and(|s| !s.is_empty());

    PolicyInput {
        sandboxed,
        sandbox_profile,
        session_duration_secs,
        has_audit_log,
        builder_id,
        has_materials,
        has_parent_attestation,
        chain_length: None, // only set during chain verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(sandboxed: bool, profile: &str, audit: bool) -> PolicyInput {
        PolicyInput {
            sandboxed: Some(sandboxed),
            sandbox_profile: Some(profile.to_owned()),
            session_duration_secs: Some(120.0),
            has_audit_log: audit,
            builder_id: Some("gleisner-cli/0.1.0".to_owned()),
            has_materials: true,
            has_parent_attestation: false,
            chain_length: None,
        }
    }

    #[test]
    fn empty_policy_passes_everything() {
        let policy = BuiltinPolicy::default();
        let input = make_input(false, "none", false);
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(results.is_empty(), "no rules = no results");
    }

    #[test]
    fn require_sandbox_pass() {
        let policy = BuiltinPolicy {
            require_sandbox: Some(true),
            ..Default::default()
        };
        let input = make_input(true, "default", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn require_sandbox_fail() {
        let policy = BuiltinPolicy {
            require_sandbox: Some(true),
            ..Default::default()
        };
        let input = make_input(false, "default", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    #[test]
    fn allowed_profiles_pass() {
        let policy = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned(), "default".to_owned()]),
            ..Default::default()
        };
        let input = make_input(true, "strict", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(results[0].passed);
    }

    #[test]
    fn allowed_profiles_fail() {
        let policy = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned()]),
            ..Default::default()
        };
        let input = make_input(true, "permissive", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(!results[0].passed);
    }

    #[test]
    fn max_duration_pass() {
        let policy = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            ..Default::default()
        };
        let input = make_input(true, "default", true); // 120s
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(results[0].passed);
    }

    #[test]
    fn max_duration_fail() {
        let policy = BuiltinPolicy {
            max_session_duration_secs: Some(60.0),
            ..Default::default()
        };
        let input = make_input(true, "default", true); // 120s
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(!results[0].passed);
    }

    #[test]
    fn require_audit_log_fail() {
        let policy = BuiltinPolicy {
            require_audit_log: Some(true),
            ..Default::default()
        };
        let input = make_input(true, "default", false);
        let results = policy.evaluate(&input).expect("evaluate");
        assert!(!results[0].passed);
    }

    #[test]
    fn multiple_rules() {
        let policy = BuiltinPolicy {
            require_sandbox: Some(true),
            require_audit_log: Some(true),
            allowed_builders: Some(vec!["gleisner-cli/0.1.0".to_owned()]),
            ..Default::default()
        };
        let input = make_input(true, "default", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn extract_policy_input_from_payload() {
        let payload = serde_json::json!({
            "predicate": {
                "builder": { "id": "gleisner-cli/0.1.0" },
                "invocation": {
                    "environment": {
                        "sandboxed": true
                    }
                },
                "metadata": {
                    "buildStartedOn": "2025-01-01T00:00:00Z",
                    "buildFinishedOn": "2025-01-01T00:02:00Z"
                },
                "gleisner:auditLogDigest": "abc123",
                "gleisner:sandboxProfile": {
                    "name": "strict"
                },
                "materials": [{ "uri": "git+https://example.com" }]
            }
        });

        let input = extract_policy_input(&payload);
        assert_eq!(input.sandboxed, Some(true));
        assert_eq!(input.sandbox_profile.as_deref(), Some("strict"));
        assert!(input.session_duration_secs.is_some());
        let dur = input.session_duration_secs.unwrap();
        assert!((dur - 120.0).abs() < 1.0);
        assert!(input.has_audit_log);
        assert_eq!(input.builder_id.as_deref(), Some("gleisner-cli/0.1.0"));
        assert!(input.has_materials);
    }

    #[test]
    fn require_parent_attestation_pass() {
        let mut input = make_input(true, "konishi", true);
        input.has_parent_attestation = true;

        let policy = BuiltinPolicy {
            require_parent_attestation: Some(true),
            ..Default::default()
        };
        let results = policy.evaluate(&input).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn require_parent_attestation_fail() {
        let input = make_input(true, "konishi", true);
        // has_parent_attestation defaults to false in make_input

        let policy = BuiltinPolicy {
            require_parent_attestation: Some(true),
            ..Default::default()
        };
        let results = policy.evaluate(&input).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    #[test]
    fn extract_chain_from_payload() {
        let payload = serde_json::json!({
            "predicate": {
                "builder": { "id": "gleisner-cli/0.1.0" },
                "invocation": {
                    "environment": { "sandboxed": true }
                },
                "metadata": {
                    "buildStartedOn": "2025-01-01T00:00:00Z",
                    "buildFinishedOn": "2025-01-01T00:02:00Z"
                },
                "gleisner:auditLogDigest": "abc123",
                "gleisner:sandboxProfile": { "name": "strict" },
                "materials": [],
                "gleisner:chain": {
                    "parentDigest": "deadbeef",
                    "parentPath": "attestation-001.json"
                }
            }
        });

        let input = extract_policy_input(&payload);
        assert!(input.has_parent_attestation);
    }

    #[test]
    fn negative_duration_fails() {
        let policy = BuiltinPolicy {
            max_session_duration_secs: Some(-100.0),
            ..Default::default()
        };
        let input = make_input(true, "default", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert!(results[0].message.contains("must be positive"));
    }

    #[test]
    fn zero_duration_fails() {
        let policy = BuiltinPolicy {
            max_session_duration_secs: Some(0.0),
            ..Default::default()
        };
        let input = make_input(true, "default", true);
        let results = policy.evaluate(&input).expect("evaluate");
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert!(results[0].message.contains("must be positive"));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_policy_input() -> impl Strategy<Value = PolicyInput> {
            (
                any::<bool>(),
                ".*",
                prop::option::of(0.0..1e6f64),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(|(sandboxed, profile, duration, audit, parent)| {
                    PolicyInput {
                        sandboxed: Some(sandboxed),
                        sandbox_profile: Some(profile),
                        session_duration_secs: duration,
                        has_audit_log: audit,
                        builder_id: Some("test-builder".to_owned()),
                        has_materials: true,
                        has_parent_attestation: parent,
                        chain_length: None,
                    }
                })
        }

        proptest! {
            /// Any policy with require_sandbox=true rejects unsandboxed sessions.
            #[test]
            fn require_sandbox_always_rejects_unsandboxed(
                profile in ".*",
                duration in 0.0..1e6f64,
            ) {
                let policy = BuiltinPolicy {
                    require_sandbox: Some(true),
                    ..Default::default()
                };
                let input = PolicyInput {
                    sandboxed: Some(false),
                    sandbox_profile: Some(profile),
                    session_duration_secs: Some(duration),
                    has_audit_log: true,
                    builder_id: Some("test".to_owned()),
                    has_materials: true,
                    has_parent_attestation: false,
                    chain_length: None,
                };
                let results = policy.evaluate(&input).unwrap();
                prop_assert!(!results.is_empty());
                let sandbox_result = results.iter().find(|r| r.rule == "require_sandbox").unwrap();
                prop_assert!(!sandbox_result.passed, "unsandboxed session must fail require_sandbox");
            }

            /// max_session_duration_secs: non-positive values always produce a failing result.
            #[test]
            fn non_positive_duration_always_fails(max in -1000.0..=0.0f64, actual in 0.0..1e6f64) {
                let policy = BuiltinPolicy {
                    max_session_duration_secs: Some(max),
                    ..Default::default()
                };
                let input = PolicyInput {
                    sandboxed: Some(true),
                    sandbox_profile: None,
                    session_duration_secs: Some(actual),
                    has_audit_log: true,
                    builder_id: None,
                    has_materials: true,
                    has_parent_attestation: false,
                    chain_length: None,
                };
                let results = policy.evaluate(&input).unwrap();
                let dur_result = results.iter().find(|r| r.rule == "max_session_duration_secs").unwrap();
                prop_assert!(!dur_result.passed, "non-positive duration limit must always fail");
            }

            /// Empty policy always returns empty results.
            #[test]
            fn empty_policy_always_empty(input in arb_policy_input()) {
                let policy = BuiltinPolicy::default();
                let results = policy.evaluate(&input).unwrap();
                prop_assert!(results.is_empty(), "default policy has no rules");
            }
        }
    }
}
