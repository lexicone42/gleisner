//! Integration tests for the full forge pipeline.
//!
//! These tests construct synthetic package trees that mirror the structure of
//! real `gominimal/pkgs` packages and exercise the full DAG → eval → store →
//! compose → bridge → attest pipeline.

use std::collections::HashMap;
use std::path::Path;

use gleisner_forge::attest::{
    extract_attestation_with_results, extract_package_metadata, extract_sources_from_package,
};
use gleisner_forge::bridge::compose_to_policy;
use gleisner_forge::compose::ComposedEnvironment;
use gleisner_forge::dag::PackageGraph;
use gleisner_forge::eval::{EvalContext, eval_package};
use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};
use gleisner_forge::store::Store;

/// Helper: write a package tree to a temp directory.
fn write_packages(dir: &Path, packages: &[(&str, &str)]) {
    for (name, content) in packages {
        let pkg_dir = dir.join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("build.ncl"), content).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Full pipeline: claude-code-like package
// ---------------------------------------------------------------------------

/// Simulates evaluating a claude-code-like package that declares
/// `env_dir_mappings`, `env_file_mappings`, and source tarballs.
///
/// This mirrors the real `gominimal/pkgs/packages/claude-code/build.ncl`.
#[test]
fn full_pipeline_claude_code_like() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");
    let store_dir = tmp.path().join("store");

    // Simplified claude-code-like package without the real minimal.ncl imports.
    // Uses plain Nickel records that produce the same JSON shape.
    write_packages(
        &pkgs,
        &[
            ("bash", r#"{ name = "bash", ty = "Builder", outputs = {} }"#),
            (
                "glibc",
                r#"{ name = "glibc", ty = "Builder", outputs = {} }"#,
            ),
            (
                "ripgrep",
                r#"{ name = "ripgrep", ty = "Builder", outputs = {} }"#,
            ),
            (
                "base",
                r#"let bash = import "../bash/build.ncl" in
                { name = "base", ty = "Builder", runtime_deps = [bash], outputs = {} }"#,
            ),
            (
                "claude-code",
                r#"let base = import "../base/build.ncl" in
let bash = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let ripgrep = import "../ripgrep/build.ncl" in
{
  name = "claude-code",
  ty = "Builder",
  build_deps = [
    { file = "build.sh" },
    {
      url = "https://storage.googleapis.com/claude-code-dist/v2.1.37/linux-x64/claude",
      sha256 = "f967a4d06e16a32436b6329e2dbed459a9fa4d34f07635a1fb271b74f706c91f",
    },
    base,
  ],
  runtime_deps = [bash, glibc, ripgrep],
  attrs = {
    env_dir_mappings = [
      { read_only = false, path = "~/.claude", class = "State" },
    ],
    env_file_mappings = [
      { read_only = false, path = "~/.claude.json", class = "Credential" },
    ],
  },
  outputs = {
    claude = { glob = "usr/bin/claude" },
  },
}"#,
            ),
        ],
    );

    // Run the full pipeline
    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"), // Empty — no minimal.ncl needed for plain records
        store_dir,
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();

    // --- Verify evaluation ---
    assert_eq!(output.evaluated, 5);
    assert_eq!(output.failed, 0);
    assert!(output.failed_packages.is_empty());

    // --- Verify composed environment ---
    let env = &output.environment;
    assert_eq!(env.packages.len(), 5);
    assert!(env.packages.contains(&"claude-code".to_string()));

    // claude-code declares env_dir_mappings = [{ rw, ~/.claude, State }]
    assert_eq!(env.dir_mappings.len(), 1);
    assert_eq!(env.dir_mappings[0].path, "~/.claude");
    assert!(!env.dir_mappings[0].read_only);
    assert_eq!(env.dir_mappings[0].class, "State");

    // claude-code declares env_file_mappings = [{ rw, ~/.claude.json, Credential }]
    assert_eq!(env.file_mappings.len(), 1);
    assert_eq!(env.file_mappings[0].path, "~/.claude.json");
    assert_eq!(env.file_mappings[0].class, "Credential");

    // --- Verify bridge ---
    let report = compose_to_policy(env);

    // ~/.claude should be in rw binds (State)
    assert_eq!(report.filesystem.readwrite_bind.len(), 1);
    assert!(
        report.filesystem.readwrite_bind[0]
            .to_string_lossy()
            .contains(".claude")
    );

    // ~/.claude.json is a Credential → NOT in binds, but in credential_paths
    assert_eq!(report.credential_paths, vec!["~/.claude.json"]);

    // DNS is implicitly required (source URLs need domain resolution)
    assert!(report.network.allow_dns);
    assert!(!report.network.allow_internet);

    // Source domain extracted from build_deps URL
    assert_eq!(report.network.allow_domains, vec!["storage.googleapis.com"]);

    // --- Verify attestation ---
    let composed_json = serde_json::json!({
        "environment": output.environment,
        "policy": {
            "filesystem": report.filesystem,
            "network": report.network,
        },
    });
    let attestation =
        extract_attestation_with_results(&output, &composed_json, &output.package_results);

    // Materials: one per package in the composed env
    assert_eq!(attestation.materials.len(), 5);
    assert!(
        attestation
            .materials
            .iter()
            .any(|m| m.uri == "pkg://minimal.dev/claude-code")
    );

    // Subjects: composed-env.json + store directory
    assert!(!attestation.subjects.is_empty());
    assert_eq!(attestation.subjects[0].name, "composed-env.json");
    assert!(!attestation.subjects[0].sha256.is_empty());

    assert!(attestation.builder_id.starts_with("gleisner-forge/"));

    // --- Verify package metadata extraction ---
    // All 5 packages should have metadata (even without source_provenance)
    assert_eq!(attestation.package_metadata.len(), 5);
    let cc_meta = attestation
        .package_metadata
        .iter()
        .find(|m| m.name == "claude-code")
        .expect("claude-code metadata");
    // claude-code has build_deps with a Source tarball
    assert!(
        cc_meta
            .source_urls
            .iter()
            .any(|s| s.uri.contains("claude-code-dist"))
    );
    // Fallback PURL since no source_provenance declared
    assert_eq!(cc_meta.purl, "pkg:generic/minimal.dev/claude-code");
}

/// Test package metadata extraction with real-ish attrs
#[test]
fn package_metadata_with_provenance() {
    let json = serde_json::json!({
        "name": "cosign",
        "attrs": {
            "upstream_version": "3.0.4",
            "repology_project": "cosign",
            "source_provenance": {
                "category": "GithubRepo",
                "owner": "sigstore",
                "repo": "cosign",
            },
        },
        "build_deps": [
            { "file": "build.sh" },
            {
                "url": "gs://minimal-staging-archives/sigstore/cosign/v3.0.4.tar.gz",
                "sha256": "8096c07e9a3ae21fa600c19cc8ff8c6f15b027184858d0bc0edde5f74589a01a",
            },
        ],
    });

    let meta = extract_package_metadata("cosign", &json);
    assert_eq!(meta.upstream_version.as_deref(), Some("3.0.4"));
    assert_eq!(meta.repology_project.as_deref(), Some("cosign"));
    assert_eq!(meta.purl, "pkg:github/sigstore/cosign@3.0.4");
    assert_eq!(meta.source_urls.len(), 2); // tarball + pkg://
    assert_eq!(
        meta.source_urls[0].sha256,
        "8096c07e9a3ae21fa600c19cc8ff8c6f15b027184858d0bc0edde5f74589a01a"
    );
}

/// Test `extract_sources_from_package` with a claude-code-shaped JSON.
#[test]
fn claude_code_source_extraction() {
    let json = serde_json::json!({
        "name": "claude-code",
        "build_deps": [
            { "file": "build.sh" },
            {
                "url": "https://storage.googleapis.com/claude-code-dist/v2.1.37/linux-x64/claude",
                "sha256": "f967a4d06e16a32436b6329e2dbed459a9fa4d34f07635a1fb271b74f706c91f",
            },
            { "name": "base", "ty": "Builder", "_stub": true },
        ],
        "runtime_deps": [
            { "name": "bash", "ty": "Builder", "_stub": true },
            { "name": "glibc", "ty": "Builder", "_stub": true },
        ],
    });

    let materials = extract_sources_from_package("claude-code", &json);

    // Should have: source tarball + package itself
    assert_eq!(materials.len(), 2);

    // First: the GCS download
    assert!(materials[0].uri.contains("claude-code-dist"));
    assert_eq!(
        materials[0].sha256,
        "f967a4d06e16a32436b6329e2dbed459a9fa4d34f07635a1fb271b74f706c91f"
    );

    // Second: the package URI
    assert_eq!(materials[1].uri, "pkg://minimal.dev/claude-code");
}

// ---------------------------------------------------------------------------
// Bridge: source domains → domain allowlist
// ---------------------------------------------------------------------------

/// End-to-end test: packages with source URLs produce a domain allowlist
/// that gets merged into a bridge report. This is the full path from
/// Nickel declarations → compose → bridge that drives sandbox network policy.
#[test]
fn source_domains_e2e_multi_package() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");

    // Three packages with source URLs from different domains
    write_packages(
        &pkgs,
        &[
            (
                "zlib",
                r#"{
                    name = "zlib",
                    ty = "Builder",
                    build_deps = [
                        { file = "build.sh" },
                        {
                            url = "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                            sha256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
                        },
                    ],
                    outputs = {},
                }"#,
            ),
            (
                "curl",
                r#"let zlib = import "../zlib/build.ncl" in
                {
                    name = "curl",
                    ty = "Builder",
                    build_deps = [
                        { file = "build.sh" },
                        {
                            url = "https://curl.se/download/curl-8.11.0.tar.gz",
                            sha256 = "264537d350cce5e05b9a60e7ee940e06e4a5e9dba72ef81c3e303e30f7688e7f",
                        },
                        zlib,
                    ],
                    needs = { dns = {} },
                    attrs = {
                        env_dir_mappings = [
                            { read_only = true, path = "/etc/ssl/certs", class = "State" },
                        ],
                    },
                    outputs = {},
                }"#,
            ),
            (
                "openssh",
                r#"let zlib = import "../zlib/build.ncl" in
                {
                    name = "openssh",
                    ty = "Builder",
                    build_deps = [
                        { file = "build.sh" },
                        {
                            url = "gs://minimal-staging-archives/openssh-10.2p1.tar.gz",
                            sha256 = "ccc42c04199",
                        },
                        zlib,
                    ],
                    outputs = {},
                }"#,
            ),
        ],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();
    assert_eq!(output.evaluated, 3);
    assert_eq!(output.failed, 0);

    // --- Verify source domains in composed environment ---
    let env = &output.environment;

    // Should have 3 unique domains: github.com, curl.se, storage.googleapis.com
    assert_eq!(env.source_domains.len(), 3);
    let domains: Vec<&str> = env
        .source_domains
        .iter()
        .map(|d| d.domain.as_str())
        .collect();
    assert!(
        domains.contains(&"github.com"),
        "missing github.com in {domains:?}"
    );
    assert!(
        domains.contains(&"curl.se"),
        "missing curl.se in {domains:?}"
    );
    assert!(
        domains.contains(&"storage.googleapis.com"),
        "missing storage.googleapis.com in {domains:?}"
    );

    // github.com should be attributed to zlib (first occurrence)
    let gh = env
        .source_domains
        .iter()
        .find(|d| d.domain == "github.com")
        .unwrap();
    assert_eq!(gh.package, "zlib");
    assert!(gh.source_url.contains("madler/zlib"));

    // --- Verify bridge ---
    let report = compose_to_policy(env);

    // Domain allowlist should be sorted and include all 3
    assert_eq!(report.network.allow_domains.len(), 3);
    assert_eq!(report.network.allow_domains[0], "curl.se");
    assert_eq!(report.network.allow_domains[1], "github.com");
    assert_eq!(report.network.allow_domains[2], "storage.googleapis.com");

    // DNS must be enabled (source domains need resolution + curl declares needs.dns)
    assert!(report.network.allow_dns);

    // No package declared needs.internet
    assert!(!report.network.allow_internet);

    // curl's /etc/ssl/certs should be in readonly binds
    assert!(
        report
            .filesystem
            .readonly_bind
            .iter()
            .any(|p| p.to_string_lossy().contains("ssl/certs")),
        "missing /etc/ssl/certs in readonly binds"
    );

    // --- Verify domain provenance (blast radius) ---
    assert_eq!(report.domain_provenance.len(), 3);

    // Provenance is sorted by blast radius (most packages first).
    // github.com is used by both zlib and curl (2 packages).
    let gh_prov = report
        .domain_provenance
        .iter()
        .find(|dp| dp.domain == "github.com")
        .unwrap();
    assert_eq!(gh_prov.packages.len(), 1); // only zlib has a github URL
    assert_eq!(gh_prov.url_count, 1);

    // storage.googleapis.com is used by openssh (via gs://)
    let gcs_prov = report
        .domain_provenance
        .iter()
        .find(|dp| dp.domain == "storage.googleapis.com")
        .unwrap();
    assert_eq!(gcs_prov.packages, vec!["openssh"]);
    assert_eq!(gcs_prov.url_count, 1);

    // curl.se is used by curl only
    let curl_prov = report
        .domain_provenance
        .iter()
        .find(|dp| dp.domain == "curl.se")
        .unwrap();
    assert_eq!(curl_prov.packages, vec!["curl"]);

    // --- Verify the network section appears in composed JSON ---
    let policy_json = serde_json::to_value(&report.network).unwrap();
    let domains_json = policy_json["allow_domains"].as_array().unwrap();
    assert_eq!(domains_json.len(), 3);
}

// ---------------------------------------------------------------------------
// DAG ordering with real-ish dependency shapes
// ---------------------------------------------------------------------------

/// Diamond dependency: claude-code → base → bash, claude-code → bash
#[test]
fn dag_diamond_with_claude_code() {
    let tmp = tempfile::tempdir().unwrap();
    write_packages(
        tmp.path(),
        &[
            ("bash", r#"{ name = "bash" }"#),
            ("glibc", r#"{ name = "glibc" }"#),
            (
                "base",
                r#"let bash = import "../bash/build.ncl" in { name = "base" }"#,
            ),
            (
                "claude-code",
                r#"let base = import "../base/build.ncl" in
                 let bash = import "../bash/build.ncl" in
                 let glibc = import "../glibc/build.ncl" in
                 { name = "claude-code" }"#,
            ),
        ],
    );

    let graph = PackageGraph::from_directory(tmp.path()).unwrap();
    let order = graph.topological_order().unwrap();
    let names: Vec<&str> = order.iter().map(|n| n.name.as_str()).collect();

    // bash and glibc must come before base and claude-code
    let pos_bash = names.iter().position(|&n| n == "bash").unwrap();
    let pos_base = names.iter().position(|&n| n == "base").unwrap();
    let pos_cc = names.iter().position(|&n| n == "claude-code").unwrap();
    assert!(pos_bash < pos_base);
    assert!(pos_base < pos_cc);
}

// ---------------------------------------------------------------------------
// Filtered evaluation
// ---------------------------------------------------------------------------

/// Test --packages filter: only evaluate requested packages
#[test]
fn filtered_evaluation() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");

    write_packages(
        &pkgs,
        &[
            ("a", r#"{ name = "a", value = 1 }"#),
            ("b", r#"{ name = "b", value = 2 }"#),
            ("c", r#"{ name = "c", value = 3 }"#),
        ],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec!["a".to_string(), "c".to_string()],
    };

    let output = evaluate_packages(&config).unwrap();
    assert_eq!(output.evaluated, 2);
    assert_eq!(output.environment.packages.len(), 2);
    assert!(output.environment.packages.contains(&"a".to_string()));
    assert!(output.environment.packages.contains(&"c".to_string()));
    assert!(!output.environment.packages.contains(&"b".to_string()));
}

// ---------------------------------------------------------------------------
// Store content-addressing
// ---------------------------------------------------------------------------

/// Verify that re-evaluating a package produces a store cache hit.
#[test]
fn store_caching_across_evaluations() {
    let tmp = tempfile::tempdir().unwrap();
    let build_file = tmp.path().join("pkg").join("build.ncl");
    std::fs::create_dir_all(build_file.parent().unwrap()).unwrap();
    std::fs::write(&build_file, r#"{ name = "test", version = "1.0" }"#).unwrap();

    let store = Store::new(tmp.path().join("store")).unwrap();
    let ctx = EvalContext::new(&[]).unwrap();

    let r1 = eval_package(&build_file, &HashMap::new(), &store, &ctx).unwrap();
    let r2 = eval_package(&build_file, &HashMap::new(), &store, &ctx).unwrap();

    // Same content → same hash (store hit)
    assert_eq!(r1.store_ref.hash, r2.store_ref.hash);
    assert!(store.contains(&r1.store_ref));
}

// ---------------------------------------------------------------------------
// Bridge: needs → network policy
// ---------------------------------------------------------------------------

/// Package declaring DNS + internet needs
#[test]
fn bridge_network_needs() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");

    // A package that needs DNS and internet (like a package manager)
    write_packages(
        &pkgs,
        &[(
            "npm-pkg",
            r#"{
                name = "npm-pkg",
                needs = { dns = {}, internet = {} },
                attrs = {
                    env_dir_mappings = [
                        { read_only = false, path = "~/.npm", class = "State" },
                    ],
                },
            }"#,
        )],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();
    let report = compose_to_policy(&output.environment);

    assert!(report.network.allow_dns);
    assert!(report.network.allow_internet);
    assert_eq!(report.filesystem.readwrite_bind.len(), 1);
}

// ---------------------------------------------------------------------------
// Compose: multi-package environment merging
// ---------------------------------------------------------------------------

/// Multiple packages contributing different dir mappings — should merge
#[test]
fn compose_multi_package_merge() {
    let mut env = ComposedEnvironment::new();

    // Package 1: editor state
    let j1 = serde_json::json!({
        "attrs": {
            "env_dir_mappings": [
                { "read_only": false, "path": "~/.config/helix", "class": "State" },
            ],
        },
    });
    env.merge_package("helix", &j1);

    // Package 2: claude-code state + credentials
    let j2 = serde_json::json!({
        "attrs": {
            "env_dir_mappings": [
                { "read_only": false, "path": "~/.claude", "class": "State" },
            ],
            "env_file_mappings": [
                { "read_only": false, "path": "~/.claude.json", "class": "Credential" },
            ],
        },
    });
    env.merge_package("claude-code", &j2);

    // Package 3: git credentials + config
    let j3 = serde_json::json!({
        "attrs": {
            "env_dir_mappings": [
                { "read_only": true, "path": "~/.ssh", "class": "Credential" },
                { "read_only": true, "path": "~/.config/git", "class": "State" },
            ],
        },
        "needs": { "dns": {} },
    });
    env.merge_package("git", &j3);

    assert_eq!(env.packages.len(), 3);
    assert_eq!(env.dir_mappings.len(), 4);
    assert_eq!(env.file_mappings.len(), 1);
    assert!(env.needs.dns);
    assert!(!env.needs.internet);

    // Bridge should separate credentials from binds
    let report = compose_to_policy(&env);

    // ~/.ssh (Credential) + ~/.claude.json (Credential) → credential_paths
    assert_eq!(report.credential_paths.len(), 2);

    // ~/.config/helix (State rw) + ~/.claude (State rw) → readwrite
    assert_eq!(report.filesystem.readwrite_bind.len(), 2);

    // ~/.config/git (State ro) → readonly
    assert_eq!(report.filesystem.readonly_bind.len(), 1);
}

// ---------------------------------------------------------------------------
// Error resilience
// ---------------------------------------------------------------------------

/// A package with invalid Nickel should fail gracefully, not crash the run.
#[test]
fn invalid_package_doesnt_crash_run() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");

    write_packages(
        &pkgs,
        &[
            ("good", r#"{ name = "good", value = 42 }"#),
            ("bad", r#"{ name = "bad", value = let in }"#), // invalid Nickel
            ("also-good", r#"{ name = "also-good", value = 99 }"#),
        ],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();
    assert_eq!(output.evaluated, 2);
    assert_eq!(output.failed, 1);
    assert_eq!(output.failed_packages, vec!["bad"]);
}

// ---------------------------------------------------------------------------
// Orchestrate: auto-detect packages/ subdirectory
// ---------------------------------------------------------------------------

/// `evaluate_packages` should auto-detect a `packages/` subdirectory.
/// If `pkgs_dir` points to a parent dir that contains `packages/`, it uses that.
#[test]
fn orchestrate_auto_detects_packages_subdir() {
    let tmp = tempfile::tempdir().unwrap();
    // Write packages inside a `packages/` subdirectory
    let pkgs = tmp.path().join("packages");
    write_packages(
        &pkgs,
        &[
            ("alpha", r#"{ name = "alpha", value = 1 }"#),
            ("beta", r#"{ name = "beta", value = 2 }"#),
        ],
    );

    // Point pkgs_dir at the parent (not the packages/ subdir directly)
    let config = ForgeConfig {
        pkgs_dir: tmp.path().to_path_buf(),
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();
    assert_eq!(output.evaluated, 2);
    assert!(output.environment.packages.contains(&"alpha".to_string()));
    assert!(output.environment.packages.contains(&"beta".to_string()));
}

// ---------------------------------------------------------------------------
// Orchestrate: package_results populated
// ---------------------------------------------------------------------------

/// Verify that `ForgeOutput::package_results` contains the evaluated JSON
/// for each successful package, and excludes failed packages.
#[test]
fn orchestrate_package_results_populated() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");
    write_packages(
        &pkgs,
        &[
            ("ok", r#"{ name = "ok", version = "1.0" }"#),
            ("broken", r#"{ name = "broken", value = ??? }"#), // invalid
        ],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();

    // Successful package should be in package_results
    assert!(output.package_results.contains_key("ok"));
    let ok_json = &output.package_results["ok"];
    assert_eq!(ok_json["name"], "ok");
    assert_eq!(ok_json["version"], "1.0");

    // Failed package should NOT be in package_results
    assert!(!output.package_results.contains_key("broken"));
    assert_eq!(output.failed_packages, vec!["broken"]);
}

// ---------------------------------------------------------------------------
// Orchestrate: dependency injection between packages
// ---------------------------------------------------------------------------

/// Verify that a package can consume a dependency's evaluated result.
/// The dep result is flattened and injected via the import mechanism.
#[test]
fn orchestrate_dependency_injection() {
    let tmp = tempfile::tempdir().unwrap();
    let pkgs = tmp.path().join("packages");
    write_packages(
        &pkgs,
        &[
            ("lib", r#"{ name = "lib", version = "2.0" }"#),
            (
                "app",
                r#"let lib = import "../lib/build.ncl" in
                { name = "app", lib_name = lib.name }"#,
            ),
        ],
    );

    let config = ForgeConfig {
        pkgs_dir: pkgs,
        stdlib_dir: tmp.path().join("std"),
        store_dir: tmp.path().join("store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).unwrap();
    assert_eq!(output.evaluated, 2);
    assert_eq!(output.failed, 0);

    // app should have resolved lib.name
    let app_json = &output.package_results["app"];
    assert_eq!(app_json["lib_name"], "lib");
}

// ---------------------------------------------------------------------------
// SBOM e2e: policy compliance proofs → CycloneDX 1.6 Declarations
// ---------------------------------------------------------------------------

/// End-to-end test: construct a `ForgeAttestation` with both proof properties
/// and policy compliance data, generate `CycloneDX` SBOM, and verify the
/// Declarations structure carries both Lean proof claims and Z3 policy
/// compliance claims.
#[test]
fn e2e_sbom_with_policy_compliance_and_proofs() {
    use gleisner_forge::attest::{
        ForgeAttestation, ForgeMaterial, PackageMetadata, PolicyComplianceProof, SourceProvenance,
        VerificationSummary, VerifiedProperty,
    };
    use gleisner_forge::sbom::forge_to_cyclonedx;

    // Build a realistic attestation with both proofs and compliance data
    let attestation = ForgeAttestation {
        materials: vec![ForgeMaterial {
            uri: "pkg://minimal.dev/zlib".to_owned(),
            sha256: String::new(),
        }],
        subjects: vec![],
        builder_id: "gleisner-forge/0.1.0".to_owned(),
        packages: vec!["zlib".to_owned()],
        package_metadata: vec![PackageMetadata {
            name: "zlib".to_owned(),
            upstream_version: Some("1.3.1".to_owned()),
            source_provenance: Some(SourceProvenance::GithubRepo {
                owner: "madler".to_owned(),
                repo: "zlib".to_owned(),
            }),
            repology_project: Some("zlib".to_owned()),
            purl: "pkg:github/madler/zlib@1.3.1".to_owned(),
            source_urls: vec![],
            verified_properties: vec![VerifiedProperty {
                property: "roundtrip".to_owned(),
                description: "decompress(compress(data)) = data".to_owned(),
                proof_system: "lean4".to_owned(),
                kernel_version: "leanprover/lean4:v4.29.0-rc2".to_owned(),
                specification_hash: "sha256:spec1111".to_owned(),
                proof_hash: "sha256:proof2222".to_owned(),
                declared_proof_hash: None,
                proof_uri: Some("https://github.com/kim-em/lean-zip".to_owned()),
                verified_by_forge: Some(true),
                forge_kernel_version: Some("leanprover/lean4:v4.29.0-rc2".to_owned()),
            }],
        }],
        verification: Some(VerificationSummary {
            total_properties: 1,
            forge_verified: 1,
            unchecked: 0,
            packages_with_proofs: 1,
            packages_without_proofs: 0,
        }),
        policy_compliance: vec![
            PolicyComplianceProof {
                baseline_name: "slsa-build-l1".to_owned(),
                baseline_description: "SLSA Build Level 1: materials present".to_owned(),
                is_compliant: true,
                witness: None,
                explanation:
                    "Every input accepted by the candidate is also accepted by the baseline."
                        .to_owned(),
            },
            PolicyComplianceProof {
                baseline_name: "slsa-build-l2".to_owned(),
                baseline_description: "SLSA Build Level 2: sandbox + audit log + materials"
                    .to_owned(),
                is_compliant: true,
                witness: None,
                explanation:
                    "Every input accepted by the candidate is also accepted by the baseline."
                        .to_owned(),
            },
            PolicyComplianceProof {
                baseline_name: "slsa-build-l3".to_owned(),
                baseline_description: "SLSA Build Level 3: L2 + attestation chain + zero denials"
                    .to_owned(),
                is_compliant: false,
                witness: Some(serde_json::json!({
                    "sandboxed": true,
                    "has_audit_log": true,
                    "has_materials": true,
                    "has_parent_attestation": false,
                    "denial_count": null,
                })),
                explanation:
                    "Found an input accepted by the candidate but rejected by the baseline."
                        .to_owned(),
            },
        ],
    };

    let bom = forge_to_cyclonedx(&attestation);

    // ── CycloneDX structure ──
    assert_eq!(bom.spec_version, "1.6");
    assert_eq!(bom.components.len(), 1);
    assert_eq!(bom.components[0].name, "zlib");

    // ── Declarations must exist ──
    let decl = bom.declarations.as_ref().expect("should have declarations");

    // Three assessors: forge + lean4 kernel + z3 smt
    assert_eq!(decl.assessors.len(), 3);
    let assessor_refs: Vec<&str> = decl.assessors.iter().map(|a| a.bom_ref.as_str()).collect();
    assert!(assessor_refs.contains(&"assessor-gleisner-forge"));
    assert!(assessor_refs.contains(&"assessor-kernel-lean4"));
    assert!(assessor_refs.contains(&"assessor-z3-smt"));

    // Two attestation groups
    assert_eq!(decl.attestations.len(), 2);

    // ── Group 1: Formal verification ──
    let proof_group = &decl.attestations[0];
    assert!(proof_group.summary.contains("1 properties"));
    assert_eq!(proof_group.assessor, "assessor-gleisner-forge");
    assert_eq!(proof_group.map.len(), 1);
    assert_eq!(
        proof_group.map[0].requirement,
        "formal-verification/zlib/roundtrip"
    );
    assert_eq!(proof_group.map[0].conformance.score, 1.0);

    // ── Group 2: Policy compliance ──
    let compliance_group = &decl.attestations[1];
    assert!(compliance_group.summary.contains("2/3 baselines met"));
    assert_eq!(compliance_group.assessor, "assessor-z3-smt");
    assert_eq!(compliance_group.map.len(), 3);

    // L1: compliant → claim
    let l1 = &compliance_group.map[0];
    assert_eq!(l1.requirement, "policy-compliance/slsa-build-l1");
    assert_eq!(l1.claims.len(), 1);
    assert!(l1.counter_claims.is_empty());
    assert_eq!(l1.conformance.score, 1.0);

    // L2: compliant → claim
    let l2 = &compliance_group.map[1];
    assert_eq!(l2.requirement, "policy-compliance/slsa-build-l2");
    assert_eq!(l2.conformance.score, 1.0);

    // L3: non-compliant → counter-claim with witness
    let l3 = &compliance_group.map[2];
    assert_eq!(l3.requirement, "policy-compliance/slsa-build-l3");
    assert!(l3.claims.is_empty());
    assert_eq!(l3.counter_claims.len(), 1);
    assert_eq!(l3.conformance.score, 0.0);
    assert_eq!(l3.conformance.confidence, Some(1.0));

    // Counter-claim evidence has the witness
    let evidence = &l3.counter_claims[0].evidence[0];
    let data = evidence.data.as_ref().expect("should have evidence data");
    assert_eq!(data[0].name, "counterexample-witness");
    assert!(data[0].value.contains("has_parent_attestation"));

    // Z3 proof method in evidence properties
    let proof_method = evidence
        .properties
        .iter()
        .find(|p| p.name == "cdx:forge:proof-method")
        .expect("should have proof-method property");
    assert_eq!(proof_method.value, "z3-smt-qf-lia");

    // ── Full JSON roundtrip ──
    let json = serde_json::to_string_pretty(&bom).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify key paths exist in the serialized output
    assert_eq!(parsed["specVersion"], "1.6");
    assert!(
        parsed["declarations"]["attestations"]
            .as_array()
            .unwrap()
            .len()
            == 2
    );

    // Verify the JSON contains both proof and compliance evidence
    assert!(json.contains("formal-verification/zlib/roundtrip"));
    assert!(json.contains("policy-compliance/slsa-build-l1"));
    assert!(json.contains("z3-smt-qf-lia"));
    assert!(json.contains("lean4"));
    assert!(json.contains("counterexample-witness"));
}
