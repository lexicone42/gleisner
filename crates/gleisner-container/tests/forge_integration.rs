//! Integration tests exercising the full forge → container pipeline.
//!
//! These tests require:
//! - gominimal/pkgs cloned at /datar/workspace/pkgs
//! - gominimal/std cloned at /datar/workspace/minimal-std

#![cfg(feature = "forge")]

use gleisner_container::{ForgeComposition, detect_harness, resolve_harness};
use gleisner_forge::bridge::compose_to_policy;
use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};
use std::path::{Path, PathBuf};

fn pkgs_dir() -> Option<PathBuf> {
    let p = PathBuf::from("/datar/workspace/pkgs/packages");
    p.is_dir().then_some(p)
}

fn stdlib_dir() -> Option<PathBuf> {
    let p = PathBuf::from("/datar/workspace/minimal-std");
    p.is_dir().then_some(p)
}

fn harnesses_dir() -> Option<PathBuf> {
    let p = PathBuf::from("/datar/workspace/pkgs/harnesses");
    p.is_dir().then_some(p)
}

#[test]
fn forge_composition_produces_valid_sandbox_config() {
    let Some(pkgs) = pkgs_dir() else {
        eprintln!("skipping: gominimal/pkgs not available");
        return;
    };
    let Some(stdlib) = stdlib_dir() else {
        eprintln!("skipping: gominimal/std not available");
        return;
    };

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: stdlib,
        store_dir: PathBuf::from("/tmp/gleisner-container-test-store"),
        filter: vec!["bash".to_owned(), "glibc".to_owned()],
    };

    let output = evaluate_packages(&config).expect("evaluate packages");
    assert!(
        output.failed == 0,
        "packages should evaluate without errors"
    );
    assert!(
        output.evaluated >= 2,
        "should evaluate at least bash + glibc"
    );

    let report = compose_to_policy(&output.environment);
    let composition = ForgeComposition::new(report, "/tmp/test-project");
    let sandbox = composition
        .sandbox()
        .expect("build sandbox from composition");

    // Verify the sandbox was configured — just building the command is enough
    match sandbox.command_with_args("/bin/true", &[] as &[&str]) {
        Ok(_cmd) => {}
        Err(gleisner_container::ContainerError::Sandbox(_)) => {
            // sandbox-init not found — fine for this test
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn harness_detection_matches_rust_project() {
    let Some(stdlib) = stdlib_dir() else {
        eprintln!("skipping: gominimal/std not available");
        return;
    };
    let Some(harnesses) = harnesses_dir() else {
        eprintln!("skipping: harnesses dir not available");
        return;
    };

    let import_paths: Vec<&Path> = vec![stdlib.as_path()];
    let eval_ctx =
        gleisner_forge::eval::EvalContext::new(&import_paths).expect("create eval context");
    let harness_specs =
        gleisner_forge::harness::load_harnesses(&harnesses, &eval_ctx).expect("load harnesses");

    // Detect against the gleisner project itself (which is Rust)
    let project = Path::new("/datar/workspace/claude_code_experiments/gleisner");
    let matched = detect_harness(&harness_specs, project);

    assert!(
        matched.is_some(),
        "should detect a harness for a Rust project"
    );
    let harness = matched.unwrap();
    assert_eq!(harness.name, "rust", "should match the 'rust' harness");
    assert!(
        harness.build_packages.contains(&"rust".to_owned()),
        "rust harness should include 'rust' package"
    );
}

#[test]
fn full_pipeline_forge_to_sandbox() {
    let Some(pkgs) = pkgs_dir() else {
        eprintln!("skipping: gominimal/pkgs not available");
        return;
    };
    let Some(stdlib) = stdlib_dir() else {
        eprintln!("skipping: gominimal/std not available");
        return;
    };
    let Some(harnesses) = harnesses_dir() else {
        eprintln!("skipping: harnesses dir not available");
        return;
    };

    let project_dir = Path::new("/datar/workspace/claude_code_experiments/gleisner");

    // 1. Detect harness
    let import_paths: Vec<&Path> = vec![stdlib.as_path()];
    let eval_ctx =
        gleisner_forge::eval::EvalContext::new(&import_paths).expect("create eval context");
    let harness_specs =
        gleisner_forge::harness::load_harnesses(&harnesses, &eval_ctx).expect("load harnesses");
    let harness = detect_harness(&harness_specs, project_dir).expect("should match a harness");

    // 2. Evaluate harness packages
    let mut packages: Vec<String> = harness.build_packages.clone();
    packages.extend(harness.runtime_packages.clone());
    packages.dedup();

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: stdlib,
        store_dir: PathBuf::from("/tmp/gleisner-container-test-store"),
        filter: packages,
    };

    let output = evaluate_packages(&config).expect("evaluate packages");
    assert_eq!(output.failed, 0, "all harness packages should evaluate");

    // 3. Bridge to policy
    let report = compose_to_policy(&output.environment);

    // 4. Create ForgeComposition and resolve harness
    let composition = ForgeComposition::new(report, project_dir);
    let harness_match = resolve_harness(
        harness,
        composition.report().state_wirings.as_slice(),
        &project_dir.join(".gleisner/state"),
    );

    // 5. Build sandbox
    let mut sandbox = composition.sandbox().expect("build sandbox");
    composition.apply_harness(&mut sandbox, &harness_match);

    eprintln!(
        "Full pipeline: {} harness, {} packages evaluated, {} env vars",
        harness.name,
        output.evaluated,
        harness_match.env_vars.len(),
    );
}
