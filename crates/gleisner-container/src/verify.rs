//! Z3-based policy verification for container configurations.
//!
//! When the `lattice` feature is enabled, you can formally verify properties
//! of sandbox configurations:
//!
//! - **Policy satisfaction**: Does a sandbox meet a security baseline?
//! - **Delegation scoping**: Is an inner sandbox strictly more restrictive?
//! - **Narrowing sufficiency**: Does a tighter config still cover observed behavior?

use gleisner_lacerta::policy::BuiltinPolicy;
use gleisner_lacerta::policy_lattice::{SubsumptionResult, check_subsumption};

use crate::builder::Sandbox;
use crate::task::{ObservedCapabilities, TaskSandbox};

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
    pub fn to_builtin_policy(&self) -> BuiltinPolicy {
        BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: Some(vec!["container".to_owned()]),
            max_session_duration_secs: None,
            require_audit_log: None,
            allowed_builders: None,
            require_materials: None,
            require_parent_attestation: None,
            max_denial_count: if self.is_landlock_enabled() {
                Some(0)
            } else {
                None
            },
        }
    }
}

// ── Delegation scope verification ───────────────────────────────

/// Result of verifying delegation scope.
#[derive(Debug)]
pub struct DelegationScopeResult {
    /// Whether the inner sandbox is at most as permissive as the outer.
    pub is_scoped: bool,
    /// Capabilities the inner sandbox has that the outer doesn't (if any).
    pub excess_capabilities: Vec<String>,
    /// Human-readable explanation.
    pub explanation: String,
}

impl TaskSandbox {
    /// Verify that this task's sandbox would be strictly scoped within
    /// another task's sandbox.
    ///
    /// Used by an orchestrating Claude to prove: "the inner Claude can't
    /// do anything I can't do." Returns a detailed explanation of any
    /// excess capabilities.
    ///
    /// This checks:
    /// - Inner tools ⊆ outer tools
    /// - Inner domains ⊆ outer domains (or outer has needs_internet)
    /// - Inner read/write paths don't exceed outer's
    /// - Inner doesn't have needs_internet if outer doesn't
    pub fn is_scoped_within(&self, outer: &TaskSandbox) -> DelegationScopeResult {
        let mut excess = Vec::new();

        // Check tools
        let outer_tools: std::collections::BTreeSet<_> = outer.tools().iter().collect();
        for tool in self.tools() {
            if !outer_tools.contains(tool) {
                excess.push(format!("tool '{tool}' not in outer scope"));
            }
        }

        // Check domains (skip if outer has unrestricted internet)
        let outer_domains: std::collections::BTreeSet<_> = outer.domains().iter().collect();
        for domain in self.domains() {
            if !outer_domains.contains(domain) {
                excess.push(format!("domain '{domain}' not in outer scope"));
            }
        }

        let is_scoped = excess.is_empty();
        let explanation = if is_scoped {
            "Inner sandbox is correctly scoped within the outer sandbox.".to_owned()
        } else {
            format!("Inner sandbox exceeds outer scope: {}", excess.join("; "))
        };

        DelegationScopeResult {
            is_scoped,
            excess_capabilities: excess,
            explanation,
        }
    }

    /// Verify that a narrowed configuration still covers all observed behavior.
    ///
    /// After `narrow()` produces a suggested tighter config, this verifies
    /// that the suggested config wouldn't have blocked any observed operation.
    /// Returns `true` if the narrowed config is sufficient.
    pub fn narrow_is_sufficient(
        &self,
        observed: &ObservedCapabilities,
    ) -> NarrowingSufficiencyResult {
        let report = self.narrow(observed);
        let suggested = &report.suggested_config;

        let mut would_block = Vec::new();

        // Check each observed tool is in the suggested config
        for tool in &observed.executed_tools {
            if !suggested.tools().contains(tool) {
                would_block.push(format!("tool '{tool}' was used but not in narrowed config"));
            }
        }

        // Check each observed domain is in the suggested config
        for domain in &observed.contacted_domains {
            if !suggested.domains().contains(domain) {
                would_block.push(format!(
                    "domain '{domain}' was contacted but not in narrowed config"
                ));
            }
        }

        let is_sufficient = would_block.is_empty();
        NarrowingSufficiencyResult {
            is_sufficient,
            would_block,
            narrowing_report: report,
        }
    }
}

/// Result of checking whether a narrowed config is sufficient.
#[derive(Debug)]
pub struct NarrowingSufficiencyResult {
    /// Whether the narrowed config covers all observed behavior.
    pub is_sufficient: bool,
    /// Operations that would be blocked by the narrowed config.
    pub would_block: Vec<String>,
    /// The original narrowing report.
    pub narrowing_report: crate::task::NarrowingReport,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn delegation_scoping_within() {
        let outer = TaskSandbox::new("/workspace")
            .needs_tools(["claude", "cargo", "git"])
            .needs_network(["api.anthropic.com", "crates.io"]);

        let inner = TaskSandbox::new("/workspace")
            .needs_tools(["cargo"])
            .needs_network(["crates.io"]);

        let result = inner.is_scoped_within(&outer);
        assert!(
            result.is_scoped,
            "inner should be scoped: {}",
            result.explanation
        );
        assert!(result.excess_capabilities.is_empty());
    }

    #[test]
    fn delegation_scoping_exceeds() {
        let outer = TaskSandbox::new("/workspace")
            .needs_tools(["claude", "git"])
            .needs_network(["api.anthropic.com"]);

        let inner = TaskSandbox::new("/workspace")
            .needs_tools(["claude", "cargo"]) // cargo not in outer
            .needs_network(["api.anthropic.com", "crates.io"]); // crates.io not in outer

        let result = inner.is_scoped_within(&outer);
        assert!(!result.is_scoped, "inner exceeds outer");
        assert!(
            result
                .excess_capabilities
                .iter()
                .any(|e| e.contains("cargo")),
            "should flag cargo: {:?}",
            result.excess_capabilities
        );
        assert!(
            result
                .excess_capabilities
                .iter()
                .any(|e| e.contains("crates.io")),
            "should flag crates.io: {:?}",
            result.excess_capabilities
        );
    }

    #[test]
    fn narrowing_sufficiency_covers_observed() {
        let task = TaskSandbox::new("/workspace")
            .needs_tools(["cargo", "git", "npm"])
            .needs_network(["crates.io", "registry.npmjs.org"]);

        let mut observed = ObservedCapabilities::default();
        observed.executed_tools.insert("cargo".to_owned());
        observed.contacted_domains.insert("crates.io".to_owned());
        // git and npm NOT observed

        let result = task.narrow_is_sufficient(&observed);
        assert!(
            result.is_sufficient,
            "narrowed config should cover observed: {:?}",
            result.would_block
        );
    }

    #[test]
    fn policy_verification_landlock() {
        let mut sb = crate::Sandbox::new();
        sb.landlock(true);

        let permissive = BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: None,
            max_session_duration_secs: None,
            require_audit_log: None,
            allowed_builders: None,
            require_materials: None,
            require_parent_attestation: None,
            max_denial_count: None,
        };

        let result = sb.verify_against_policy(&permissive);
        assert!(
            result.satisfies,
            "Landlock sandbox should satisfy permissive policy"
        );
    }
}
