//! Z3-based policy verification for container configurations.
//!
//! When the `lattice` feature is enabled, you can formally verify that a
//! [`Sandbox`] configuration satisfies a reference security policy. This uses
//! Z3 to prove that every attestation produced by the sandbox would pass the
//! policy's requirements — **before** running any code.
//!
//! ```ignore
//! use gleisner_container::verify::PolicyVerification;
//!
//! let verification = sandbox.verify_against_policy(&konishi_policy);
//! assert!(verification.satisfies, "sandbox must be at least as strict as konishi");
//! ```

use gleisner_lacerta::policy::BuiltinPolicy;
use gleisner_lacerta::policy_lattice::{SubsumptionResult, check_subsumption};

use crate::builder::Sandbox;

/// Result of verifying a sandbox configuration against a security policy.
#[derive(Debug)]
pub struct PolicyVerification {
    /// Whether the sandbox satisfies the policy.
    pub satisfies: bool,
    /// The Z3 subsumption result with details.
    pub subsumption: SubsumptionResult,
    /// The policy that was derived from the sandbox configuration.
    pub derived_policy: BuiltinPolicy,
}

impl Sandbox {
    /// Verify that this sandbox configuration satisfies a reference policy.
    ///
    /// Converts the builder's security configuration into a [`BuiltinPolicy`],
    /// then uses Z3 to check that the derived policy's accepting set is a
    /// subset of the reference policy's accepting set.
    ///
    /// Returns a [`PolicyVerification`] with the result, including a concrete
    /// counterexample if the sandbox is **less** restrictive than the reference.
    pub fn verify_against_policy(&self, reference: &BuiltinPolicy) -> PolicyVerification {
        let derived = self.to_builtin_policy();
        let subsumption = check_subsumption(&derived, reference);
        PolicyVerification {
            satisfies: subsumption.is_subset,
            subsumption,
            derived_policy: derived,
        }
    }

    /// Derive a [`BuiltinPolicy`] from this sandbox's configuration.
    ///
    /// Maps the builder's security settings into attestation-level policy
    /// rules that Z3 can reason about.
    pub fn to_builtin_policy(&self) -> BuiltinPolicy {
        BuiltinPolicy {
            // Sandbox is always required (we are a sandbox builder)
            require_sandbox: Some(true),
            // The profile name used
            allowed_profiles: Some(vec!["container".to_owned()]),
            // No session duration limit from the builder
            max_session_duration_secs: None,
            // Audit log is not required by default
            require_audit_log: None,
            // Builder ID
            allowed_builders: None,
            // Materials not required
            require_materials: None,
            // Chain not required
            require_parent_attestation: None,
            // Landlock enabled means we expect zero denials in well-configured runs
            max_denial_count: if self.is_landlock_enabled() {
                Some(0)
            } else {
                None
            },
        }
    }
}
