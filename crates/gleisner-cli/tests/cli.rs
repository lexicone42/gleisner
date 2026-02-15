//! Integration tests for the Gleisner CLI.
//!
//! Each test creates fixture data in a temporary directory, invokes the
//! `gleisner` binary via `assert_cmd`, and checks outputs and exit codes.

#![allow(deprecated)] // cargo_bin deprecation — macro replacement not yet stable

use std::io::Write;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

/// Convenience: get a `Command` for the `gleisner` binary.
fn gleisner() -> Command {
    Command::cargo_bin("gleisner").expect("gleisner binary not found")
}

/// Helper: generate a keypair, sign a payload, and write the bundle to a file.
/// Returns (`bundle_path`, `public_key_pem_path`).
fn create_signed_bundle(dir: &Path, payload: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use base64::Engine;
    use gleisner_introdus::bundle::{AttestationBundle, VerificationMaterial};
    use gleisner_introdus::signer::{der_to_pem, encode_p256_spki};

    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keygen");
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).expect("parse");
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

    let bundle_path = dir.join("bundle.json");
    let bundle_json = serde_json::to_string_pretty(&bundle).expect("serialize bundle");
    std::fs::write(&bundle_path, &bundle_json).expect("write bundle");

    let key_path = dir.join("public.pem");
    std::fs::write(&key_path, &pub_pem).expect("write key");

    (bundle_path, key_path)
}

/// A minimal in-toto-style payload for testing.
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

// ─── verify tests ───────────────────────────────────────────

#[test]
fn verify_valid_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    gleisner()
        .args(["verify", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification PASSED"));
}

#[test]
fn verify_invalid_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    // Tamper with the bundle signature
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bundle_path).unwrap()).unwrap();
    bundle["signature"] = serde_json::Value::String("dGFtcGVyZWQ=".to_owned());
    std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();

    gleisner()
        .args(["verify", bundle_path.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Verification FAILED"));
}

#[test]
fn verify_with_policy_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    // Write a policy that matches our test payload (sandboxed = true)
    let policy_path = dir.path().join("policy.json");
    let policy = serde_json::json!({
        "require_sandbox": true
    });
    std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();

    gleisner()
        .args([
            "verify",
            bundle_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification PASSED"));
}

#[test]
fn verify_with_policy_fail() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    // Require audit log, which our minimal payload doesn't have
    let policy_path = dir.path().join("policy.json");
    let policy = serde_json::json!({
        "require_audit_log": true
    });
    std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();

    gleisner()
        .args([
            "verify",
            bundle_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Verification FAILED"));
}

#[test]
fn verify_json_output() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    let output = gleisner()
        .args(["verify", "--json", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    assert_eq!(json["passed"], serde_json::Value::Bool(true));
    assert!(json["outcomes"].is_array());
}

// ─── inspect tests ──────────────────────────────────────────

#[test]
fn inspect_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    gleisner()
        .args(["inspect", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test/0.1.0"));
}

#[test]
fn inspect_detailed() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    gleisner()
        .args(["inspect", "--detailed", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification Material"));
}

#[test]
fn inspect_json() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle_path, _) = create_signed_bundle(dir.path(), &minimal_payload());

    let output = gleisner()
        .args(["inspect", "--json", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    assert!(json["payload"].is_object());
    assert!(json["signature"].is_string());
}

// ─── sbom tests ─────────────────────────────────────────────

#[test]
fn sbom_generates_output() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("Cargo.lock");
    let mut f = std::fs::File::create(&lock_path).unwrap();
    write!(
        f,
        r#"
version = 4

[[package]]
name = "test-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeefcafebabe"

[[package]]
name = "local-dep"
version = "0.1.0"
"#
    )
    .unwrap();

    gleisner()
        .args(["sbom", "--project-dir", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-crate").and(predicate::str::contains("local-dep")));
}

#[test]
fn sbom_json_output() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("Cargo.lock");
    let mut f = std::fs::File::create(&lock_path).unwrap();
    write!(
        f,
        r#"
version = 4

[[package]]
name = "example"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"
"#
    )
    .unwrap();

    let output = gleisner()
        .args([
            "sbom",
            "--json",
            "--project-dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["bomFormat"], "CycloneDX");
    assert_eq!(json["specVersion"], "1.5");
    assert!(json["components"].is_array());
    assert_eq!(json["components"][0]["purl"], "pkg:cargo/example@2.0.0");
}

#[test]
fn sbom_output_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("Cargo.lock");
    let mut f = std::fs::File::create(&lock_path).unwrap();
    write!(
        f,
        r#"
version = 4

[[package]]
name = "file-test"
version = "0.1.0"
"#
    )
    .unwrap();

    let output_path = dir.path().join("sbom.json");
    gleisner()
        .args([
            "sbom",
            "--json",
            "--project-dir",
            dir.path().to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON file");
    assert_eq!(json["bomFormat"], "CycloneDX");
}

// ─── chain verification tests ───────────────────────────────

/// Create an unsigned attestation bundle with optional chain metadata.
fn create_unsigned_bundle(
    dir: &Path,
    filename: &str,
    chain: Option<(&str, &str)>,
    finished_on: &str,
) -> std::path::PathBuf {
    let chain_json = match chain {
        Some((digest, path)) => {
            format!(r#","gleisner:chain":{{"parentDigest":"{digest}","parentPath":"{path}"}}"#,)
        }
        None => String::new(),
    };

    let payload = format!(
        r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{{"buildType":"https://gleisner.dev/GleisnerProvenance/v1","builder":{{"id":"test/0.1.0"}},"invocation":{{"parameters":{{}},"environment":{{"sandboxed":true}}}},"metadata":{{"buildStartedOn":"{finished_on}","buildFinishedOn":"{finished_on}","completeness":{{"parameters":true,"environment":true,"materials":false}}}},"materials":[],"gleisner:auditLogDigest":"","gleisner:sandboxProfile":{{"name":"default"}}{chain_json}}}}}"#,
    );

    let bundle = gleisner_introdus::bundle::AttestationBundle {
        payload,
        signature: String::new(),
        verification_material: gleisner_introdus::bundle::VerificationMaterial::None,
    };

    let bundle_path = dir.join(filename);
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    std::fs::write(&bundle_path, &json).unwrap();
    bundle_path
}

#[test]
fn verify_chain_walks_linked_attestations() {
    let dir = tempfile::tempdir().unwrap();

    // Create a 3-link chain of unsigned bundles.
    let path1 = create_unsigned_bundle(
        dir.path(),
        "attestation-001.json",
        None,
        "2025-01-01T00:00:00Z",
    );
    let b1: gleisner_introdus::bundle::AttestationBundle =
        serde_json::from_str(&std::fs::read_to_string(&path1).unwrap()).unwrap();
    let d1 = gleisner_introdus::chain::compute_payload_digest(&b1);

    let path2 = create_unsigned_bundle(
        dir.path(),
        "attestation-002.json",
        Some((&d1, "attestation-001.json")),
        "2025-02-01T00:00:00Z",
    );
    let b2: gleisner_introdus::bundle::AttestationBundle =
        serde_json::from_str(&std::fs::read_to_string(&path2).unwrap()).unwrap();
    let d2 = gleisner_introdus::chain::compute_payload_digest(&b2);

    let path3 = create_unsigned_bundle(
        dir.path(),
        "attestation-003.json",
        Some((&d2, "attestation-002.json")),
        "2025-03-01T00:00:00Z",
    );

    // Verify chain from the latest link (signature will fail, but chain should work).
    gleisner()
        .args(["verify", "--chain", path3.to_str().unwrap()])
        .assert()
        // Verification will fail due to unsigned bundles, but chain output should appear.
        .failure()
        .stdout(predicate::str::contains("3 link(s) verified"));
}

#[test]
fn verify_chain_reports_broken_link() {
    let dir = tempfile::tempdir().unwrap();

    // Create bundle 3 pointing to a nonexistent parent.
    let path3 = create_unsigned_bundle(
        dir.path(),
        "attestation-003.json",
        Some(("deadbeefdeadbeef", "attestation-002.json")),
        "2025-03-01T00:00:00Z",
    );

    gleisner()
        .args(["verify", "--chain", path3.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("broken chain").or(predicate::str::contains("1 link(s)")));
}
