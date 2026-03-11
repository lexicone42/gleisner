//! Policy lattice analysis via Z3 SMT solver.
//!
//! Encodes [`BuiltinPolicy`] rules as Z3 constraints to answer questions
//! that runtime evaluation cannot:
//!
//! - **Subsumption**: is every input accepted by policy A also accepted by B?
//! - **Comparison**: full lattice ordering between two policies
//! - **Witnesses**: concrete counterexample inputs when subsumption fails
//!
//! # Encoding
//!
//! Each [`PolicyInput`] field becomes a Z3 variable (Bool or Int).
//! Optional input fields (duration, denial count) use a "present" boolean
//! plus a value variable — rules that reference absent fields pass vacuously,
//! matching the runtime evaluator's skip-when-absent semantics.
//!
//! String fields (profile, builder ID) are encoded as integers over a
//! finite universe of strings mentioned in both policies, plus a sentinel
//! for "any other string."

use z3::ast::{Bool, Int};
use z3::{SatResult, Solver};

use crate::policy::{BuiltinPolicy, PolicyInput};

// ── Public types ─────────────────────────────────────────────

/// Result of checking whether one policy's accepting set ⊆ another's.
#[derive(Debug)]
pub struct SubsumptionResult {
    /// `true` when every input accepted by `candidate` is also accepted
    /// by `baseline`.
    pub is_subset: bool,
    /// Concrete counterexample when `is_subset` is `false`.
    pub witness: Option<PolicyInput>,
    /// Human-readable explanation of the result.
    pub explanation: String,
}

/// Lattice relationship between two policies.
#[derive(Debug)]
pub enum LatticeRelation {
    /// A accepts strictly fewer inputs than B (A ⊂ B).
    StrictlyStricter,
    /// B accepts strictly fewer inputs than A (B ⊂ A).
    StrictlyLooser,
    /// Both accept exactly the same set of inputs (A = B).
    Equivalent,
    /// Neither is a subset of the other — they differ on orthogonal axes.
    Incomparable {
        /// An input accepted by A but rejected by B.
        a_not_b: Box<PolicyInput>,
        /// An input accepted by B but rejected by A.
        b_not_a: Box<PolicyInput>,
    },
}

// ── Private helpers ──────────────────────────────────────────

/// Maps string values (profile names, builder IDs) to integer indices
/// for Z3 encoding. Always includes `""` at index 0 (the default when
/// the input field is `None`) and a sentinel at the last index for
/// "any string not explicitly named."
struct StringUniverse {
    entries: Vec<String>,
}

impl StringUniverse {
    /// Build from zero or more optional string allowlists.
    fn new(lists: &[Option<&Vec<String>>]) -> Self {
        let mut entries = vec![String::new()]; // index 0 = "" (None → unwrap_or(""))
        for l in lists.iter().flatten() {
            for s in *l {
                if !entries.contains(s) {
                    entries.push(s.clone());
                }
            }
        }
        entries.push("__z3_other__".to_owned());
        Self { entries }
    }

    fn index_of(&self, s: &str) -> Option<usize> {
        self.entries.iter().position(|e| e == s)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Convert a Z3 model integer back to the original string.
    /// Returns `None` for index 0 ("") and the sentinel.
    fn resolve(&self, idx: i64) -> Option<String> {
        let i = usize::try_from(idx).ok()?;
        self.entries
            .get(i)
            .filter(|s| *s != "__z3_other__" && !s.is_empty())
            .cloned()
    }
}

/// Z3 variables representing a symbolic [`PolicyInput`].
struct InputVars {
    sandboxed: Bool,
    profile_id: Int,
    has_duration: Bool,
    /// Duration in milliseconds (avoids floating-point in Z3).
    duration_ms: Int,
    has_audit_log: Bool,
    builder_id: Int,
    has_materials: Bool,
    has_parent: Bool,
    has_denial_count: Bool,
    denial_count: Int,
}

fn create_vars() -> InputVars {
    InputVars {
        sandboxed: Bool::new_const("sandboxed"),
        profile_id: Int::new_const("profile_id"),
        has_duration: Bool::new_const("has_duration"),
        duration_ms: Int::new_const("duration_ms"),
        has_audit_log: Bool::new_const("has_audit_log"),
        builder_id: Int::new_const("builder_id"),
        has_materials: Bool::new_const("has_materials"),
        has_parent: Bool::new_const("has_parent"),
        has_denial_count: Bool::new_const("has_denial_count"),
        denial_count: Int::new_const("denial_count"),
    }
}

/// Domain constraints: valid ranges for integer-encoded variables.
#[expect(
    clippy::cast_possible_wrap,
    reason = "string universes are tiny — a few entries at most"
)]
fn encode_domain(vars: &InputVars, profiles: &StringUniverse, builders: &StringUniverse) -> Bool {
    let zero = Int::from_i64(0);
    Bool::and(&[
        // profile_id ∈ [0, |profiles|)
        vars.profile_id.ge(&zero),
        vars.profile_id.lt(Int::from_i64(profiles.len() as i64)),
        // builder_id ∈ [0, |builders|)
        vars.builder_id.ge(&zero),
        vars.builder_id.lt(Int::from_i64(builders.len() as i64)),
        // duration_ms ≥ 0 when present
        Bool::or(&[vars.has_duration.not(), vars.duration_ms.ge(&zero)]),
        // denial_count ≥ 0 when present
        Bool::or(&[vars.has_denial_count.not(), vars.denial_count.ge(&zero)]),
    ])
}

/// Encode the conjunction of all active rules in a policy.
///
/// Returns a Bool that is `true` exactly when the symbolic input
/// would pass every rule in the policy.
fn encode_policy(
    policy: &BuiltinPolicy,
    vars: &InputVars,
    profiles: &StringUniverse,
    builders: &StringUniverse,
) -> Bool {
    let mut conjuncts: Vec<Bool> = Vec::new();

    // ── require_sandbox ──────────────────────────────────────
    // Runtime: input.sandboxed.unwrap_or(false) must be true
    if policy.require_sandbox == Some(true) {
        conjuncts.push(vars.sandboxed.clone());
    }

    // ── allowed_profiles ─────────────────────────────────────
    // Runtime: input.sandbox_profile.unwrap_or("") ∈ allowed
    if let Some(allowed) = &policy.allowed_profiles {
        encode_allowlist(allowed, &vars.profile_id, profiles, &mut conjuncts);
    }

    // ── max_session_duration_secs ────────────────────────────
    // Runtime: skipped when input.duration is None; fails when max ≤ 0
    if let Some(max) = policy.max_session_duration_secs {
        if max <= 0.0 {
            conjuncts.push(Bool::from_bool(false));
        } else {
            // Convert to milliseconds for sub-second precision within i64 range.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "session durations don't approach i64::MAX ms"
            )]
            let max_ms = (max * 1000.0).round() as i64;
            let bound = vars.duration_ms.le(Int::from_i64(max_ms));
            conjuncts.push(Bool::or(&[vars.has_duration.not(), bound]));
        }
    }

    // ── require_audit_log ────────────────────────────────────
    if policy.require_audit_log == Some(true) {
        conjuncts.push(vars.has_audit_log.clone());
    }

    // ── allowed_builders ─────────────────────────────────────
    // Runtime: input.builder_id.unwrap_or("") ∈ allowed
    if let Some(allowed) = &policy.allowed_builders {
        encode_allowlist(allowed, &vars.builder_id, builders, &mut conjuncts);
    }

    // ── require_materials ────────────────────────────────────
    if policy.require_materials == Some(true) {
        conjuncts.push(vars.has_materials.clone());
    }

    // ── require_parent_attestation ───────────────────────────
    if policy.require_parent_attestation == Some(true) {
        conjuncts.push(vars.has_parent.clone());
    }

    // ── max_denial_count ─────────────────────────────────────
    // Runtime: skipped when input.denial_count is None
    if let Some(max) = policy.max_denial_count {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "denial counts don't approach i64::MAX"
        )]
        let bound = vars.denial_count.le(Int::from_i64(max as i64));
        conjuncts.push(Bool::or(&[vars.has_denial_count.not(), bound]));
    }

    if conjuncts.is_empty() {
        Bool::from_bool(true)
    } else {
        Bool::and(&conjuncts)
    }
}

/// Encode a string allowlist as `var ∈ {idx(s) | s ∈ allowed}`.
#[expect(
    clippy::cast_possible_wrap,
    reason = "string universe indices are tiny"
)]
fn encode_allowlist(
    allowed: &[String],
    var: &Int,
    universe: &StringUniverse,
    conjuncts: &mut Vec<Bool>,
) {
    let options: Vec<Bool> = allowed
        .iter()
        .filter_map(|s| universe.index_of(s))
        .map(|idx| var.eq(Int::from_i64(idx as i64)))
        .collect();
    if options.is_empty() {
        // Empty allowlist → nothing can match → always fails
        conjuncts.push(Bool::from_bool(false));
    } else {
        conjuncts.push(Bool::or(&options));
    }
}

/// Extract a concrete [`PolicyInput`] witness from a Z3 satisfying model.
fn extract_witness(
    model: &z3::Model,
    vars: &InputVars,
    profiles: &StringUniverse,
    builders: &StringUniverse,
) -> PolicyInput {
    let sandboxed = model.eval(&vars.sandboxed, true).and_then(|v| v.as_bool());

    let profile_idx = model
        .eval(&vars.profile_id, true)
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let sandbox_profile = profiles.resolve(profile_idx);

    let has_dur = model
        .eval(&vars.has_duration, true)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    #[expect(
        clippy::cast_precision_loss,
        reason = "witness durations don't approach 2^52 ms"
    )]
    let session_duration_secs = if has_dur {
        model
            .eval(&vars.duration_ms, true)
            .and_then(|v| v.as_i64())
            .map(|ms| ms as f64 / 1000.0)
    } else {
        None
    };

    let has_audit_log = model
        .eval(&vars.has_audit_log, true)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let builder_idx = model
        .eval(&vars.builder_id, true)
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let builder_id = builders.resolve(builder_idx);

    let has_materials = model
        .eval(&vars.has_materials, true)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let has_parent_attestation = model
        .eval(&vars.has_parent, true)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let has_dc = model
        .eval(&vars.has_denial_count, true)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    #[expect(clippy::cast_sign_loss, reason = "domain constrains denial_count ≥ 0")]
    let denial_count = if has_dc {
        model
            .eval(&vars.denial_count, true)
            .and_then(|v| v.as_i64())
            .map(|c| c as u64)
    } else {
        None
    };

    PolicyInput {
        sandboxed,
        sandbox_profile,
        session_duration_secs,
        has_audit_log,
        builder_id,
        has_materials,
        has_parent_attestation,
        chain_length: None,
        denial_count,
    }
}

// ── Public API ───────────────────────────────────────────────

/// Check whether every input accepted by `candidate` is also accepted
/// by `baseline`.
///
/// Returns `is_subset = true` when `candidate` is at least as strict as
/// `baseline`. When `false`, the `witness` field contains a concrete
/// [`PolicyInput`] that passes `candidate` but fails `baseline`.
///
/// This encodes both policies as Z3 constraints over symbolic input
/// variables and checks `∃ input : passes(candidate) ∧ ¬passes(baseline)`.
///
/// # Panics
///
/// Panics if Z3 returns SAT but fails to produce a model (Z3 invariant violation).
pub fn check_subsumption(candidate: &BuiltinPolicy, baseline: &BuiltinPolicy) -> SubsumptionResult {
    let solver = Solver::new();

    let profiles = StringUniverse::new(&[
        candidate.allowed_profiles.as_ref(),
        baseline.allowed_profiles.as_ref(),
    ]);
    let builders = StringUniverse::new(&[
        candidate.allowed_builders.as_ref(),
        baseline.allowed_builders.as_ref(),
    ]);

    let vars = create_vars();
    let domain = encode_domain(&vars, &profiles, &builders);
    let passes_candidate = encode_policy(candidate, &vars, &profiles, &builders);
    let passes_baseline = encode_policy(baseline, &vars, &profiles, &builders);

    // Assert: ∃ input ∈ domain where candidate passes ∧ baseline fails
    solver.assert(&domain);
    solver.assert(&passes_candidate);
    solver.assert(passes_baseline.not());

    match solver.check() {
        SatResult::Unsat => SubsumptionResult {
            is_subset: true,
            witness: None,
            explanation: "Every input accepted by the candidate is also accepted by the baseline."
                .to_owned(),
        },
        SatResult::Sat => {
            let model = solver.get_model().expect("SAT result must have a model");
            let witness = extract_witness(&model, &vars, &profiles, &builders);
            SubsumptionResult {
                is_subset: false,
                witness: Some(witness),
                explanation:
                    "Found an input accepted by the candidate but rejected by the baseline."
                        .to_owned(),
            }
        }
        SatResult::Unknown => SubsumptionResult {
            is_subset: false,
            witness: None,
            explanation: "Z3 returned Unknown — subsumption could not be determined.".to_owned(),
        },
    }
}

/// Determine the full lattice relationship between two policies.
///
/// Performs two subsumption checks (A⊆B and B⊆A) and combines the results:
/// - Both hold → [`Equivalent`](LatticeRelation::Equivalent)
/// - Only A⊆B → [`StrictlyStricter`](LatticeRelation::StrictlyStricter)
/// - Only B⊆A → [`StrictlyLooser`](LatticeRelation::StrictlyLooser)
/// - Neither → [`Incomparable`](LatticeRelation::Incomparable) with witnesses
///
/// # Panics
///
/// Panics if Z3 returns SAT but fails to produce a model or witness.
pub fn compare(a: &BuiltinPolicy, b: &BuiltinPolicy) -> LatticeRelation {
    let a_sub_b = check_subsumption(a, b);
    let b_sub_a = check_subsumption(b, a);

    match (a_sub_b.is_subset, b_sub_a.is_subset) {
        (true, true) => LatticeRelation::Equivalent,
        (true, false) => LatticeRelation::StrictlyStricter,
        (false, true) => LatticeRelation::StrictlyLooser,
        (false, false) => LatticeRelation::Incomparable {
            a_not_b: Box::new(a_sub_b.witness.expect("SAT result must produce witness")),
            b_not_a: Box::new(b_sub_a.witness.expect("SAT result must produce witness")),
        },
    }
}

// ── Standard baselines ────────────────────────────────────────

/// A named baseline policy for compliance checking.
#[derive(Debug, Clone)]
pub struct NamedBaseline {
    /// Machine-readable identifier (e.g., `"slsa-build-l1"`).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// The baseline policy.
    pub policy: BuiltinPolicy,
}

/// Standard baseline policies for SLSA Build Levels and Gleisner strict mode.
///
/// Returns four baselines in order of increasing strictness:
/// 1. **SLSA Build L1** — materials present
/// 2. **SLSA Build L2** — sandbox + audit log + materials
/// 3. **SLSA Build L3** — L2 + attestation chain + zero denials
/// 4. **Gleisner Strict** — all rules, strict profile, 1h max, zero denials
pub fn standard_baselines() -> Vec<NamedBaseline> {
    vec![
        NamedBaseline {
            name: "slsa-build-l1",
            description: "SLSA Build Level 1: materials present",
            policy: BuiltinPolicy {
                require_materials: Some(true),
                ..Default::default()
            },
        },
        NamedBaseline {
            name: "slsa-build-l2",
            description: "SLSA Build Level 2: sandbox + audit log + materials",
            policy: BuiltinPolicy {
                require_sandbox: Some(true),
                require_audit_log: Some(true),
                require_materials: Some(true),
                ..Default::default()
            },
        },
        NamedBaseline {
            name: "slsa-build-l3",
            description: "SLSA Build Level 3: L2 + attestation chain + zero denials",
            policy: BuiltinPolicy {
                require_sandbox: Some(true),
                require_audit_log: Some(true),
                require_materials: Some(true),
                require_parent_attestation: Some(true),
                max_denial_count: Some(0),
                ..Default::default()
            },
        },
        NamedBaseline {
            name: "gleisner-strict",
            description: "Gleisner strict: all rules, strict profile, 1h max, zero denials",
            policy: BuiltinPolicy {
                require_sandbox: Some(true),
                allowed_profiles: Some(vec!["strict".to_owned()]),
                max_session_duration_secs: Some(3600.0),
                require_audit_log: Some(true),
                require_materials: Some(true),
                require_parent_attestation: Some(true),
                max_denial_count: Some(0),
                ..Default::default()
            },
        },
    ]
}

/// Check a session policy against all standard baselines.
///
/// Returns one result per baseline, pairing the baseline metadata with
/// the Z3 subsumption result. The caller converts these into
/// `PolicyComplianceProof` entries for SBOM embedding.
///
/// # Panics
///
/// Panics if Z3 returns SAT but fails to produce a model.
pub fn check_against_standard_baselines(
    session_policy: &BuiltinPolicy,
) -> Vec<(NamedBaseline, SubsumptionResult)> {
    standard_baselines()
        .into_iter()
        .map(|baseline| {
            let result = check_subsumption(session_policy, &baseline.policy);
            (baseline, result)
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;

    // ── Subsumption ──────────────────────────────────────────

    #[test]
    fn empty_policies_are_equivalent() {
        let a = BuiltinPolicy::default();
        let b = BuiltinPolicy::default();
        assert!(matches!(compare(&a, &b), LatticeRelation::Equivalent));
    }

    #[test]
    fn require_sandbox_is_stricter_than_empty() {
        let strict = BuiltinPolicy {
            require_sandbox: Some(true),
            ..Default::default()
        };
        let empty = BuiltinPolicy::default();
        assert!(matches!(
            compare(&strict, &empty),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn lower_denial_limit_is_stricter() {
        let strict = BuiltinPolicy {
            max_denial_count: Some(5),
            ..Default::default()
        };
        let loose = BuiltinPolicy {
            max_denial_count: Some(10),
            ..Default::default()
        };
        assert!(matches!(
            compare(&strict, &loose),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn same_denial_limit_is_equivalent() {
        let a = BuiltinPolicy {
            max_denial_count: Some(5),
            ..Default::default()
        };
        let b = BuiltinPolicy {
            max_denial_count: Some(5),
            ..Default::default()
        };
        assert!(matches!(compare(&a, &b), LatticeRelation::Equivalent));
    }

    #[test]
    fn narrower_profile_list_is_stricter() {
        let strict = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned()]),
            ..Default::default()
        };
        let loose = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned(), "developer".to_owned()]),
            ..Default::default()
        };
        assert!(matches!(
            compare(&strict, &loose),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn shorter_duration_is_stricter() {
        let strict = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            ..Default::default()
        };
        let loose = BuiltinPolicy {
            max_session_duration_secs: Some(600.0),
            ..Default::default()
        };
        assert!(matches!(
            compare(&strict, &loose),
            LatticeRelation::StrictlyStricter
        ));
    }

    // ── Incomparable ─────────────────────────────────────────

    #[test]
    fn orthogonal_rules_are_incomparable() {
        // A: tight on duration, loose on denials
        let a = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            max_denial_count: Some(10),
            ..Default::default()
        };
        // B: loose on duration, tight on denials
        let b = BuiltinPolicy {
            max_session_duration_secs: Some(600.0),
            max_denial_count: Some(5),
            ..Default::default()
        };
        assert!(matches!(
            compare(&a, &b),
            LatticeRelation::Incomparable { .. }
        ));
    }

    #[test]
    fn disjoint_profile_lists_are_incomparable() {
        let a = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned()]),
            ..Default::default()
        };
        let b = BuiltinPolicy {
            allowed_profiles: Some(vec!["developer".to_owned()]),
            ..Default::default()
        };
        assert!(matches!(
            compare(&a, &b),
            LatticeRelation::Incomparable { .. }
        ));
    }

    // ── Witness validation ───────────────────────────────────

    #[test]
    fn witness_passes_candidate_but_fails_baseline() {
        let candidate = BuiltinPolicy {
            max_denial_count: Some(10),
            ..Default::default()
        };
        let baseline = BuiltinPolicy {
            max_denial_count: Some(5),
            ..Default::default()
        };
        let result = check_subsumption(&candidate, &baseline);
        assert!(!result.is_subset);

        let witness = result.witness.expect("should have witness");

        // Witness must pass candidate (runtime check)
        let candidate_results = candidate.evaluate(&witness).unwrap();
        assert!(
            candidate_results.iter().all(|r| r.passed),
            "witness must pass candidate: {candidate_results:?}"
        );

        // Witness must fail baseline (runtime check)
        let baseline_results = baseline.evaluate(&witness).unwrap();
        assert!(
            baseline_results.iter().any(|r| !r.passed),
            "witness must fail baseline: {baseline_results:?}"
        );
    }

    #[test]
    fn witness_for_profile_mismatch() {
        let candidate = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned(), "developer".to_owned()]),
            ..Default::default()
        };
        let baseline = BuiltinPolicy {
            allowed_profiles: Some(vec!["strict".to_owned()]),
            ..Default::default()
        };
        let result = check_subsumption(&candidate, &baseline);
        assert!(!result.is_subset);

        let witness = result.witness.expect("should have witness");
        assert_eq!(
            witness.sandbox_profile.as_deref(),
            Some("developer"),
            "witness should use the profile that candidate allows but baseline rejects"
        );
    }

    #[test]
    fn witness_for_incomparable_validates_both_directions() {
        let a = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            max_denial_count: Some(10),
            ..Default::default()
        };
        let b = BuiltinPolicy {
            max_session_duration_secs: Some(600.0),
            max_denial_count: Some(5),
            ..Default::default()
        };

        if let LatticeRelation::Incomparable { a_not_b, b_not_a } = compare(&a, &b) {
            // a_not_b passes A, fails B
            let a_results = a.evaluate(&a_not_b).unwrap();
            assert!(a_results.iter().all(|r| r.passed), "a_not_b must pass A");
            let b_results = b.evaluate(&a_not_b).unwrap();
            assert!(b_results.iter().any(|r| !r.passed), "a_not_b must fail B");

            // b_not_a passes B, fails A
            let b_results2 = b.evaluate(&b_not_a).unwrap();
            assert!(b_results2.iter().all(|r| r.passed), "b_not_a must pass B");
            let a_results2 = a.evaluate(&b_not_a).unwrap();
            assert!(a_results2.iter().any(|r| !r.passed), "b_not_a must fail A");
        } else {
            panic!("expected Incomparable");
        }
    }

    // ── Edge cases ───────────────────────────────────────────

    #[test]
    fn empty_allowlist_is_unsatisfiable() {
        let impossible = BuiltinPolicy {
            allowed_profiles: Some(vec![]),
            ..Default::default()
        };
        let empty = BuiltinPolicy::default();
        // impossible accepts nothing, empty accepts everything
        // impossible ⊂ empty (trivially — empty set is subset of any set)
        assert!(matches!(
            compare(&impossible, &empty),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn all_boolean_rules_combined() {
        let maximal = BuiltinPolicy {
            require_sandbox: Some(true),
            require_audit_log: Some(true),
            require_materials: Some(true),
            require_parent_attestation: Some(true),
            ..Default::default()
        };
        let partial = BuiltinPolicy {
            require_sandbox: Some(true),
            ..Default::default()
        };
        assert!(matches!(
            compare(&maximal, &partial),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn identical_complex_policies_are_equivalent() {
        let policy = BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: Some(vec!["strict".to_owned()]),
            max_session_duration_secs: Some(300.0),
            require_audit_log: Some(true),
            allowed_builders: Some(vec!["gleisner-cli/0.1.0".to_owned()]),
            require_materials: Some(true),
            require_parent_attestation: Some(true),
            max_denial_count: Some(5),
        };
        assert!(matches!(
            compare(&policy, &policy),
            LatticeRelation::Equivalent
        ));
    }

    #[test]
    fn subsumption_with_none_vs_some_false() {
        // require_sandbox: None and require_sandbox: Some(false)
        // should be equivalent (both skip the rule)
        let a = BuiltinPolicy {
            require_sandbox: None,
            ..Default::default()
        };
        let b = BuiltinPolicy {
            require_sandbox: Some(false),
            ..Default::default()
        };
        assert!(matches!(compare(&a, &b), LatticeRelation::Equivalent));
    }

    #[test]
    fn duration_absent_in_input_passes_any_duration_rule() {
        // A policy with max_duration but no other rules
        // should be stricter than empty because inputs with duration > max
        // pass empty but fail with_dur.
        let with_dur = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            ..Default::default()
        };
        let empty = BuiltinPolicy::default();
        assert!(matches!(
            compare(&with_dur, &empty),
            LatticeRelation::StrictlyStricter
        ));
    }

    // ── Baseline ordering ───────────────────────────────────

    #[test]
    fn baselines_form_strict_chain_l1_l2_l3() {
        let baselines = standard_baselines();
        let l1 = &baselines[0].policy;
        let l2 = &baselines[1].policy;
        let l3 = &baselines[2].policy;

        // L2 ⊂ L1 (L2 is strictly stricter than L1)
        assert!(matches!(compare(l2, l1), LatticeRelation::StrictlyStricter));
        // L3 ⊂ L2 (L3 is strictly stricter than L2)
        assert!(matches!(compare(l3, l2), LatticeRelation::StrictlyStricter));
        // Transitivity: L3 ⊂ L1
        assert!(matches!(compare(l3, l1), LatticeRelation::StrictlyStricter));
    }

    #[test]
    fn gleisner_strict_is_stricter_than_l3() {
        let baselines = standard_baselines();
        let l3 = &baselines[2].policy;
        let strict = &baselines[3].policy;

        assert!(matches!(
            compare(strict, l3),
            LatticeRelation::StrictlyStricter
        ));
    }

    #[test]
    fn check_against_baselines_full_compliance() {
        // A policy that meets all baselines including gleisner-strict
        let session = BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: Some(vec!["strict".to_owned()]),
            max_session_duration_secs: Some(1800.0), // 30 min < 1h
            require_audit_log: Some(true),
            require_materials: Some(true),
            require_parent_attestation: Some(true),
            max_denial_count: Some(0),
            ..Default::default()
        };

        let results = check_against_standard_baselines(&session);
        assert_eq!(results.len(), 4);
        for (baseline, result) in &results {
            assert!(
                result.is_subset,
                "session should meet {}: {}",
                baseline.name, result.explanation
            );
        }
    }

    #[test]
    fn check_against_baselines_partial_compliance() {
        // A policy that meets L1 and L2 but not L3 (no parent attestation)
        let session = BuiltinPolicy {
            require_sandbox: Some(true),
            require_audit_log: Some(true),
            require_materials: Some(true),
            ..Default::default()
        };

        let results = check_against_standard_baselines(&session);
        assert_eq!(results.len(), 4);
        assert!(results[0].1.is_subset, "should meet L1");
        assert!(results[1].1.is_subset, "should meet L2");
        assert!(!results[2].1.is_subset, "should NOT meet L3");
        assert!(!results[3].1.is_subset, "should NOT meet gleisner-strict");
    }
}
