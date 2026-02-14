//! SHA-256 digest verification for attestation subjects and audit logs.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::VerificationError;

/// Compute the SHA-256 hex digest of a file.
pub fn sha256_file(path: &Path) -> Result<String, VerificationError> {
    let data = std::fs::read(path)?;
    Ok(sha256_bytes(&data))
}

/// Compute the SHA-256 hex digest of a byte slice.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Check that a file's digest matches the expected value.
pub fn check_file_digest(
    path: &Path,
    expected: &str,
    artifact_name: &str,
) -> Result<(), VerificationError> {
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(VerificationError::DigestMismatch {
            artifact: artifact_name.to_owned(),
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// Check all subjects in an in-toto statement payload against files on disk.
///
/// The payload should be a JSON `Value` containing an in-toto v1 statement.
/// Returns a `Vec` of results — one per subject. Subjects that match get `Ok(())`,
/// mismatches get `Err(DigestMismatch)`.
pub fn check_subjects(
    payload: &serde_json::Value,
    base_dir: &Path,
) -> Vec<Result<(), VerificationError>> {
    let Some(subjects) = payload.get("subject").and_then(|s| s.as_array()) else {
        return vec![];
    };

    subjects
        .iter()
        .filter_map(|subject| {
            let name = subject.get("name")?.as_str()?;
            let expected = subject
                .get("digest")
                .and_then(|d| d.get("sha256"))
                .and_then(|h| h.as_str())?;

            let path = base_dir.join(name);
            Some(check_file_digest(&path, expected, name))
        })
        .collect()
}

/// Check the audit log digest embedded in the provenance predicate.
pub fn check_audit_log(
    payload: &serde_json::Value,
    audit_log_path: &Path,
) -> Result<(), VerificationError> {
    let expected = payload
        .get("predicate")
        .and_then(|p| p.get("gleisner:auditLogDigest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| {
            VerificationError::InvalidBundle(
                "missing gleisner:auditLogDigest in predicate".to_owned(),
            )
        })?;

    check_file_digest(audit_log_path, expected, "audit-log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string
        let hash = sha256_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = sha256_bytes(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn file_digest_match() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), b"hello").expect("write");

        let expected = sha256_bytes(b"hello");
        check_file_digest(tmp.path(), &expected, "test.txt").expect("should match");
    }

    #[test]
    fn file_digest_mismatch() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), b"hello").expect("write");

        let result = check_file_digest(tmp.path(), "0000", "test.txt");
        assert!(matches!(
            result,
            Err(VerificationError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn check_subjects_from_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        std::fs::write(dir.path().join("b.txt"), b"world").expect("write");

        let hash_a = sha256_bytes(b"hello");
        let hash_b = sha256_bytes(b"world");

        let payload = serde_json::json!({
            "subject": [
                { "name": "a.txt", "digest": { "sha256": hash_a } },
                { "name": "b.txt", "digest": { "sha256": hash_b } },
            ]
        });

        let results = check_subjects(&payload, dir.path());
        assert_eq!(results.len(), 2);
        for r in &results {
            r.as_ref().expect("should match");
        }
    }

    #[test]
    fn check_subjects_with_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"hello").expect("write");

        let payload = serde_json::json!({
            "subject": [
                { "name": "a.txt", "digest": { "sha256": "wrong" } },
            ]
        });

        let results = check_subjects(&payload, dir.path());
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn check_audit_log_valid() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), b"log data").expect("write");
        let hash = sha256_bytes(b"log data");

        let payload = serde_json::json!({
            "predicate": {
                "gleisner:auditLogDigest": hash
            }
        });

        check_audit_log(&payload, tmp.path()).expect("should match");
    }
}
