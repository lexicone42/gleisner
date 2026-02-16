//! Integration tests for the Gleisner CLI.
//!
//! Each test creates fixture data in a temporary directory, invokes the
//! `gleisner` binary via `assert_cmd`, and checks outputs and exit codes.

#![allow(deprecated)] // cargo_bin deprecation — macro replacement not yet stable

use std::io::Write;
use std::path::Path;

use assert_cmd::Command;
use chrono::DateTime;
use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult, JsonlWriter};
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

// ─── learn tests ────────────────────────────────────────────

/// Helper: create a JSONL audit log from a list of events using the real writer.
fn write_audit_log(dir: &Path, events: &[AuditEvent]) -> std::path::PathBuf {
    let log_path = dir.join("audit.jsonl");
    let file = std::fs::File::create(&log_path).expect("create audit log");
    let mut writer = JsonlWriter::new(std::io::BufWriter::new(file));
    for event in events {
        writer.write_event(event).expect("write event");
    }
    log_path
}

fn make_audit_event(seq: u64, kind: EventKind, result: EventResult) -> AuditEvent {
    AuditEvent {
        timestamp: DateTime::from_timestamp(
            1_700_000_000 + i64::try_from(seq).expect("seq fits i64"),
            0,
        )
        .expect("valid timestamp"),
        sequence: seq,
        event: kind,
        result,
    }
}

#[test]
fn learn_generates_profile_from_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let events = vec![
        make_audit_event(
            0,
            EventKind::FileRead {
                path: "/home/testuser/.rustup/toolchains/stable/lib/libstd.so".into(),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ),
        make_audit_event(
            1,
            EventKind::NetworkConnect {
                target: "api.anthropic.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ),
        make_audit_event(
            2,
            EventKind::FileWrite {
                path: "/home/testuser/.cargo/registry/cache/foo".into(),
                sha256_before: None,
                sha256_after: "def".to_owned(),
            },
            EventResult::Allowed,
        ),
        make_audit_event(
            3,
            EventKind::ProcessExec {
                command: "cargo".to_owned(),
                args: vec!["build".to_owned()],
                cwd: "/home/testuser/project".into(),
            },
            EventResult::Allowed,
        ),
    ];
    let log_path = write_audit_log(dir.path(), &events);

    let output = gleisner()
        .args([
            "learn",
            "--audit-log",
            log_path.to_str().unwrap(),
            "--name",
            "integration-test",
            "--project-dir",
            "/home/testuser/project",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("valid UTF-8");

    // Profile name and description
    assert!(stdout.contains("integration-test"));
    // Network allowlist
    assert!(stdout.contains("api.anthropic.com"));
    // Home-relative paths
    assert!(stdout.contains(".rustup"));
    assert!(stdout.contains(".cargo"));
    // Command allowlist
    assert!(stdout.contains("cargo"));
    // Credential deny list
    assert!(stdout.contains(".ssh"));
}

#[test]
fn learn_writes_profile_to_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let events = vec![make_audit_event(
        0,
        EventKind::FileRead {
            path: "/home/testuser/.npm/cache/pkg".into(),
            sha256: "abc".to_owned(),
        },
        EventResult::Allowed,
    )];
    let log_path = write_audit_log(dir.path(), &events);
    let output_path = dir.path().join("learned.toml");

    gleisner()
        .args([
            "learn",
            "--audit-log",
            log_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--project-dir",
            "/home/testuser/project",
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).expect("read output file");
    // Should be valid TOML that parses as a profile
    assert!(content.contains("name = \"learned\""));
    assert!(content.contains(".npm"));
    // File should start with the header comment
    assert!(content.starts_with("# learned"));
}

#[test]
fn learn_quiet_suppresses_summary() {
    let dir = tempfile::tempdir().unwrap();
    let events = vec![make_audit_event(
        0,
        EventKind::FileRead {
            path: "/home/testuser/.rustup/bin/rustc".into(),
            sha256: "abc".to_owned(),
        },
        EventResult::Allowed,
    )];
    let log_path = write_audit_log(dir.path(), &events);

    let assert = gleisner()
        .args([
            "learn",
            "--audit-log",
            log_path.to_str().unwrap(),
            "--quiet",
            "--project-dir",
            "/home/testuser/project",
        ])
        .assert()
        .success();

    // stdout should have the TOML profile
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("name = \"learned\""));

    // stderr should NOT have the summary
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("Profile Learning Summary"),
        "quiet mode should suppress summary, got: {stderr}"
    );
}

#[test]
fn learn_empty_audit_log_produces_minimal_profile() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = write_audit_log(dir.path(), &[]);

    let output = gleisner()
        .args([
            "learn",
            "--audit-log",
            log_path.to_str().unwrap(),
            "--name",
            "empty",
            "--project-dir",
            "/tmp/nonexistent",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    // Should still produce a valid profile with system prefixes
    assert!(stdout.contains("name = \"empty\""));
    assert!(stdout.contains("/usr"));
    assert!(stdout.contains("/lib"));
}

#[test]
fn learn_with_base_profile_merges() {
    let dir = tempfile::tempdir().unwrap();

    // Write a base profile TOML
    let profile_path = dir.path().join("base.toml");
    std::fs::write(
        &profile_path,
        r#"
name = "base"
description = "base profile"

[filesystem]
readonly_bind = ["/usr"]
readwrite_bind = []
deny = ["~/.ssh"]
tmpfs = ["/tmp"]

[network]
default = "deny"
allow_domains = ["api.anthropic.com"]
allow_ports = [443]
allow_dns = true

[process]
pid_namespace = true
no_new_privileges = true
command_allowlist = []

[resources]
max_memory_mb = 4096
max_cpu_percent = 100
max_pids = 256
max_file_descriptors = 1024
max_disk_write_mb = 10240
"#,
    )
    .unwrap();

    // Create events with a new domain
    let events = vec![make_audit_event(
        0,
        EventKind::NetworkConnect {
            target: "registry.npmjs.org".to_owned(),
            port: 443,
        },
        EventResult::Allowed,
    )];
    let log_path = write_audit_log(dir.path(), &events);

    let output = gleisner()
        .args([
            "learn",
            "--audit-log",
            log_path.to_str().unwrap(),
            "--base-profile",
            profile_path.to_str().unwrap(),
            "--name",
            "merged",
            "--project-dir",
            "/home/testuser/project",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    // Should have both the original and new domain
    assert!(stdout.contains("api.anthropic.com"));
    assert!(stdout.contains("registry.npmjs.org"));
    // Should keep original readonly
    assert!(stdout.contains("/usr"));
}

#[test]
fn learn_missing_audit_log_fails() {
    gleisner()
        .args(["learn", "--audit-log", "/nonexistent/audit.jsonl"])
        .assert()
        .failure();
}
