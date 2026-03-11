//! End-to-end tests for the Z3 policy lattice module.
//!
//! These tests exercise the full pipeline:
//! 1. Define a session policy
//! 2. Run Z3 subsumption against standard baselines
//! 3. Serialize compliance results to JSON (as forge would consume them)
//! 4. Cross-validate Z3 witnesses against the runtime policy evaluator
//! 5. Verify the baseline ordering invariant (L1 ⊃ L2 ⊃ L3 ⊂ Strict)

#[cfg(feature = "lattice")]
mod lattice_e2e {
    use gleisner_lacerta::policy::{BuiltinPolicy, PolicyEngine};
    use gleisner_lacerta::policy_lattice::{
        LatticeRelation, check_against_standard_baselines, check_subsumption, compare,
        standard_baselines,
    };

    /// Simulate what the forge orchestrator does: run Z3, serialize results,
    /// deserialize, and verify the structure is intact.
    #[test]
    fn e2e_lattice_to_serialized_compliance_proof() {
        // A realistic session policy: sandboxed, audited, has materials,
        // but no parent attestation (not part of a chain).
        let session_policy = BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: Some(vec!["developer".to_owned()]),
            max_session_duration_secs: Some(7200.0),
            require_audit_log: Some(true),
            require_materials: Some(true),
            // No require_parent_attestation → won't meet L3
            // No max_denial_count → won't meet L3
            ..Default::default()
        };

        let results = check_against_standard_baselines(&session_policy);
        assert_eq!(results.len(), 4);

        // Convert to the serializable format forge uses
        let proofs: Vec<serde_json::Value> = results
            .iter()
            .map(|(baseline, result)| {
                let witness_json = result
                    .witness
                    .as_ref()
                    .and_then(|w| serde_json::to_value(w).ok());

                serde_json::json!({
                    "baseline_name": baseline.name,
                    "baseline_description": baseline.description,
                    "is_compliant": result.is_subset,
                    "witness": witness_json,
                    "explanation": result.explanation,
                })
            })
            .collect();

        // Serialize to JSON string (simulates crossing crate boundary)
        let json_str = serde_json::to_string_pretty(&proofs).unwrap();

        // Deserialize back (simulates forge reading it)
        let roundtripped: Vec<serde_json::Value> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtripped.len(), 4);

        // Verify expected compliance pattern: L1 ✓, L2 ✓, L3 ✗, Strict ✗
        assert_eq!(roundtripped[0]["baseline_name"], "slsa-build-l1");
        assert_eq!(roundtripped[0]["is_compliant"], true);
        assert!(roundtripped[0]["witness"].is_null());

        assert_eq!(roundtripped[1]["baseline_name"], "slsa-build-l2");
        assert_eq!(roundtripped[1]["is_compliant"], true);

        assert_eq!(roundtripped[2]["baseline_name"], "slsa-build-l3");
        assert_eq!(roundtripped[2]["is_compliant"], false);
        assert!(!roundtripped[2]["witness"].is_null());

        assert_eq!(roundtripped[3]["baseline_name"], "gleisner-strict");
        assert_eq!(roundtripped[3]["is_compliant"], false);
        assert!(!roundtripped[3]["witness"].is_null());
    }

    /// Cross-validate every Z3 witness against the runtime evaluator.
    /// This is the encoding fidelity proof: if Z3 says an input passes
    /// policy A but fails policy B, the runtime evaluator must agree.
    #[test]
    fn e2e_witness_cross_validation_against_all_baselines() {
        let session_policy = BuiltinPolicy {
            require_sandbox: Some(true),
            require_audit_log: Some(true),
            require_materials: Some(true),
            max_session_duration_secs: Some(1800.0),
            max_denial_count: Some(3),
            ..Default::default()
        };

        let results = check_against_standard_baselines(&session_policy);

        for (baseline, result) in &results {
            if let Some(witness) = &result.witness {
                // Witness must pass the session policy
                let session_results = session_policy.evaluate(witness).unwrap();
                assert!(
                    session_results.iter().all(|r| r.passed),
                    "witness for {} must pass session policy, but failed: {:?}",
                    baseline.name,
                    session_results
                        .iter()
                        .filter(|r| !r.passed)
                        .collect::<Vec<_>>()
                );

                // Witness must fail the baseline
                let baseline_results = baseline.policy.evaluate(witness).unwrap();
                assert!(
                    baseline_results.iter().any(|r| !r.passed),
                    "witness for {} must fail baseline, but all passed: {:?}",
                    baseline.name,
                    baseline_results
                );
            }
        }
    }

    /// Verify the invariant: baselines form a strict chain.
    /// L1 ⊃ L2 ⊃ L3 ⊂ Gleisner Strict
    #[test]
    fn e2e_baseline_chain_invariant() {
        let baselines = standard_baselines();

        for i in 0..baselines.len() - 1 {
            let stricter = &baselines[i + 1].policy;
            let looser = &baselines[i].policy;
            let result = check_subsumption(stricter, looser);
            assert!(
                result.is_subset,
                "{} should subsume {}, but doesn't: {}",
                baselines[i + 1].name,
                baselines[i].name,
                result.explanation
            );
        }
    }

    /// End-to-end: a policy that meets ALL baselines including gleisner-strict.
    #[test]
    fn e2e_full_compliance_no_witnesses() {
        let maximal_policy = BuiltinPolicy {
            require_sandbox: Some(true),
            allowed_profiles: Some(vec!["strict".to_owned()]),
            max_session_duration_secs: Some(1800.0),
            require_audit_log: Some(true),
            require_materials: Some(true),
            require_parent_attestation: Some(true),
            max_denial_count: Some(0),
            ..Default::default()
        };

        let results = check_against_standard_baselines(&maximal_policy);

        for (baseline, result) in &results {
            assert!(
                result.is_subset,
                "maximal policy should meet {}: {}",
                baseline.name, result.explanation
            );
            assert!(
                result.witness.is_none(),
                "compliant baseline {} should have no witness",
                baseline.name
            );
        }
    }

    /// End-to-end: an empty policy meets nothing except... actually it
    /// does meet L1 vacuously? No — L1 requires materials, and an empty
    /// policy accepts inputs where has_materials=false.
    #[test]
    fn e2e_empty_policy_meets_nothing() {
        let empty = BuiltinPolicy::default();
        let results = check_against_standard_baselines(&empty);

        for (baseline, result) in &results {
            assert!(
                !result.is_subset,
                "empty policy should NOT meet {}: {}",
                baseline.name, result.explanation
            );
            // Each non-compliant result should have a witness
            assert!(
                result.witness.is_some(),
                "non-compliant {} should have a witness",
                baseline.name
            );
        }
    }

    /// Incomparable policies: two policies that are strictly incomparable
    /// (neither subsumes the other). Verify both witnesses are valid.
    #[test]
    fn e2e_incomparable_policies_bidirectional_witnesses() {
        // Policy A: tight on duration, loose on denials
        let a = BuiltinPolicy {
            max_session_duration_secs: Some(300.0),
            max_denial_count: Some(100),
            require_sandbox: Some(true),
            ..Default::default()
        };
        // Policy B: loose on duration, tight on denials
        let b = BuiltinPolicy {
            max_session_duration_secs: Some(3600.0),
            max_denial_count: Some(0),
            require_sandbox: Some(true),
            ..Default::default()
        };

        let relation = compare(&a, &b);
        match relation {
            LatticeRelation::Incomparable { a_not_b, b_not_a } => {
                // a_not_b: passes A but fails B
                let a_results = a.evaluate(&a_not_b).unwrap();
                assert!(a_results.iter().all(|r| r.passed));
                let b_results = b.evaluate(&a_not_b).unwrap();
                assert!(b_results.iter().any(|r| !r.passed));

                // b_not_a: passes B but fails A
                let b_results2 = b.evaluate(&b_not_a).unwrap();
                assert!(b_results2.iter().all(|r| r.passed));
                let a_results2 = a.evaluate(&b_not_a).unwrap();
                assert!(a_results2.iter().any(|r| !r.passed));

                // Serialize both witnesses to verify they're well-formed JSON
                let a_json = serde_json::to_value(&*a_not_b).unwrap();
                let b_json = serde_json::to_value(&*b_not_a).unwrap();
                assert!(a_json.is_object());
                assert!(b_json.is_object());
            }
            other => panic!("expected Incomparable, got {other:?}"),
        }
    }
}
