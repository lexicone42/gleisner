//! Top-level verification orchestrator.
//!
//! The `Verifier` coordinates signature verification, digest checking,
//! and policy evaluation into a single `VerificationReport`.

use std::path::{Path, PathBuf};

use gleisner_introdus::bundle::AttestationBundle;

use crate::digest;
use crate::error::VerificationError;
use crate::policy::{self, BuiltinPolicy, PolicyEngine, PolicyResult};
use crate::signature;

/// Configuration for a verification run.
#[derive(Default)]
pub struct VerifyConfig {
    /// Override the public key (PEM file path) instead of using the
    /// key embedded in the bundle.
    pub public_key_override: Option<PathBuf>,
    /// Path to the audit log for digest verification.
    pub audit_log_path: Option<PathBuf>,
    /// Base directory for resolving subject file paths.
    pub check_files_base: Option<PathBuf>,
    /// Policy engines to evaluate.
    pub policies: Vec<Box<dyn PolicyEngine>>,
}

/// Outcome of a single verification check.
#[derive(Debug, Clone)]
pub enum VerificationOutcome {
    /// The check passed.
    Pass(String),
    /// The check failed.
    Fail(String),
    /// The check was skipped (not enough information).
    Skip(String),
}

impl VerificationOutcome {
    /// Returns `true` if this outcome is a failure.
    pub const fn is_fail(&self) -> bool {
        matches!(self, Self::Fail(_))
    }

    /// Get the message for this outcome.
    pub fn message(&self) -> &str {
        match self {
            Self::Pass(m) | Self::Fail(m) | Self::Skip(m) => m,
        }
    }
}

/// The result of a full verification run.
#[derive(Debug)]
pub struct VerificationReport {
    /// Individual check outcomes.
    pub outcomes: Vec<VerificationOutcome>,
    /// Policy evaluation results.
    pub policy_results: Vec<PolicyResult>,
    /// Overall pass/fail.
    pub passed: bool,
}

/// Orchestrates all verification checks.
pub struct Verifier {
    config: VerifyConfig,
}

impl Verifier {
    /// Create a new verifier with the given configuration.
    pub const fn new(config: VerifyConfig) -> Self {
        Self { config }
    }

    /// Verify an attestation bundle.
    pub fn verify(&self, bundle: &AttestationBundle) -> VerificationReport {
        let mut outcomes = Vec::new();
        let mut policy_results = Vec::new();

        self.verify_signature(bundle, &mut outcomes);

        let payload_value: serde_json::Value = match serde_json::from_str(&bundle.payload) {
            Ok(v) => v,
            Err(e) => {
                outcomes.push(VerificationOutcome::Fail(format!(
                    "failed to parse payload JSON: {e}"
                )));
                return VerificationReport {
                    passed: false,
                    outcomes,
                    policy_results,
                };
            }
        };

        self.verify_digests(&payload_value, &mut outcomes);
        self.verify_policies(&payload_value, &mut outcomes, &mut policy_results);

        let passed = !outcomes.iter().any(VerificationOutcome::is_fail);
        VerificationReport {
            outcomes,
            policy_results,
            passed,
        }
    }

    fn verify_signature(
        &self,
        bundle: &AttestationBundle,
        outcomes: &mut Vec<VerificationOutcome>,
    ) {
        let sig_result = self.config.public_key_override.as_ref().map_or_else(
            || {
                signature::verify_signature(
                    bundle.payload.as_bytes(),
                    &bundle.signature,
                    &bundle.verification_material,
                )
            },
            |key_path| match std::fs::read_to_string(key_path) {
                Ok(pem) => signature::verify_signature_with_key(
                    bundle.payload.as_bytes(),
                    &bundle.signature,
                    &pem,
                ),
                Err(e) => Err(VerificationError::IoError(e)),
            },
        );

        match sig_result {
            Ok(()) => outcomes.push(VerificationOutcome::Pass(
                "signature verification passed".to_owned(),
            )),
            Err(e) => outcomes.push(VerificationOutcome::Fail(format!(
                "signature verification failed: {e}"
            ))),
        }
    }

    fn verify_digests(&self, payload: &serde_json::Value, outcomes: &mut Vec<VerificationOutcome>) {
        if let Some(ref base_dir) = self.config.check_files_base {
            let subject_results = digest::check_subjects(payload, base_dir);
            if subject_results.is_empty() {
                outcomes.push(VerificationOutcome::Skip(
                    "no subjects found in payload".to_owned(),
                ));
            } else {
                for result in subject_results {
                    match result {
                        Ok(()) => outcomes
                            .push(VerificationOutcome::Pass("subject digest match".to_owned())),
                        Err(e) => {
                            outcomes
                                .push(VerificationOutcome::Fail(format!("subject digest: {e}")));
                        }
                    }
                }
            }
        } else {
            outcomes.push(VerificationOutcome::Skip(
                "file digest check skipped (no --base-dir)".to_owned(),
            ));
        }

        if let Some(ref audit_path) = self.config.audit_log_path {
            match digest::check_audit_log(payload, audit_path) {
                Ok(()) => outcomes.push(VerificationOutcome::Pass(
                    "audit log digest match".to_owned(),
                )),
                Err(e) => {
                    outcomes.push(VerificationOutcome::Fail(format!("audit log: {e}")));
                }
            }
        } else {
            outcomes.push(VerificationOutcome::Skip(
                "audit log check skipped (no --audit-log)".to_owned(),
            ));
        }
    }

    fn verify_policies(
        &self,
        payload: &serde_json::Value,
        outcomes: &mut Vec<VerificationOutcome>,
        policy_results: &mut Vec<PolicyResult>,
    ) {
        if self.config.policies.is_empty() {
            outcomes.push(VerificationOutcome::Skip(
                "no policies configured".to_owned(),
            ));
            return;
        }

        let input = policy::extract_policy_input(payload);
        for engine in &self.config.policies {
            match engine.evaluate(&input) {
                Ok(results) => {
                    for result in results {
                        let outcome = if result.passed {
                            VerificationOutcome::Pass(format!(
                                "policy '{}': {}",
                                result.rule, result.message
                            ))
                        } else {
                            VerificationOutcome::Fail(format!(
                                "policy '{}': {}",
                                result.rule, result.message
                            ))
                        };
                        outcomes.push(outcome);
                        policy_results.push(result);
                    }
                }
                Err(e) => {
                    outcomes.push(VerificationOutcome::Fail(format!("policy error: {e}")));
                }
            }
        }
    }

    /// Load a bundle from a file and verify it.
    pub fn verify_file(&self, path: &Path) -> Result<VerificationReport, VerificationError> {
        let data = std::fs::read_to_string(path)?;
        let bundle: AttestationBundle = serde_json::from_str(&data)?;
        Ok(self.verify(&bundle))
    }
}

/// Load a policy from a file, auto-detecting JSON vs WASM.
pub fn load_policy(path: &Path) -> Result<Box<dyn PolicyEngine>, VerificationError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "wasm" {
        let p = crate::policy_wasm::WasmPolicy::from_file(path)?;
        Ok(Box::new(p))
    } else {
        let p = BuiltinPolicy::from_file(path)?;
        Ok(Box::new(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use base64::Engine;
    use gleisner_introdus::bundle::VerificationMaterial;
    use gleisner_introdus::signer::{der_to_pem, encode_p256_spki};

    fn sign_payload(payload: &str) -> (AttestationBundle, String) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keygen");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("parse");
        let sig = key_pair.sign(&rng, payload.as_bytes()).expect("sign");
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
        let pub_pem = der_to_pem(
            &encode_p256_spki(key_pair.public_key().as_ref()),
            "PUBLIC KEY",
        );

        let bundle = AttestationBundle {
            payload: payload.to_owned(),
            signature: sig_b64,
            verification_material: VerificationMaterial::LocalKey {
                public_key: pub_pem.clone(),
            },
        };

        (bundle, pub_pem)
    }

    fn minimal_payload() -> String {
        serde_json::json!({
            "subject": [],
            "predicate": {
                "builder": { "id": "test/0.1.0" },
                "invocation": { "environment": { "sandboxed": true } },
                "metadata": {
                    "buildStartedOn": "2025-01-01T00:00:00Z",
                    "buildFinishedOn": "2025-01-01T00:01:00Z"
                },
                "gleisner:auditLogDigest": "",
                "gleisner:sandboxProfile": { "name": "default" },
                "materials": []
            }
        })
        .to_string()
    }

    #[test]
    fn end_to_end_verify_pass() {
        let payload = minimal_payload();
        let (bundle, _pub_pem) = sign_payload(&payload);

        let verifier = Verifier::new(VerifyConfig::default());
        let report = verifier.verify(&bundle);

        // Signature should pass; digests and policy skipped
        assert!(report.passed, "report should pass: {report:?}");
    }

    #[test]
    fn verify_with_policy() {
        let payload = minimal_payload();
        let (bundle, _) = sign_payload(&payload);

        let policy = BuiltinPolicy {
            require_sandbox: Some(true),
            ..Default::default()
        };

        let verifier = Verifier::new(VerifyConfig {
            policies: vec![Box::new(policy)],
            ..Default::default()
        });
        let report = verifier.verify(&bundle);
        assert!(report.passed);
        assert!(!report.policy_results.is_empty());
    }

    #[test]
    fn verify_with_failing_policy() {
        let payload = minimal_payload();
        let (bundle, _) = sign_payload(&payload);

        let policy = BuiltinPolicy {
            require_audit_log: Some(true), // audit log digest is empty
            ..Default::default()
        };

        let verifier = Verifier::new(VerifyConfig {
            policies: vec![Box::new(policy)],
            ..Default::default()
        });
        let report = verifier.verify(&bundle);
        assert!(!report.passed, "should fail due to missing audit log");
    }

    #[test]
    fn verify_file_round_trip() {
        let payload = minimal_payload();
        let (bundle, _) = sign_payload(&payload);

        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let bundle_json = serde_json::to_string_pretty(&bundle).expect("serialize");
        std::fs::write(tmp.path(), &bundle_json).expect("write");

        let verifier = Verifier::new(VerifyConfig::default());
        let report = verifier.verify_file(tmp.path()).expect("verify_file");
        assert!(report.passed);
    }

    #[test]
    fn verify_with_key_override() {
        let payload = minimal_payload();
        let (bundle, pub_pem) = sign_payload(&payload);

        let key_file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(key_file.path(), &pub_pem).expect("write");

        let verifier = Verifier::new(VerifyConfig {
            public_key_override: Some(key_file.path().to_path_buf()),
            ..Default::default()
        });
        let report = verifier.verify(&bundle);
        assert!(report.passed);
    }
}
