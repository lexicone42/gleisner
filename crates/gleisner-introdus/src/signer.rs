//! Signing backends for attestation bundles.
//!
//! Supports Sigstore keyless signing (Fulcio + Rekor) and local
//! ECDSA P-256 keys for air-gapped environments.
//!
//! Uses `aws-lc-rs` as the cryptographic provider — formally verified
//! C crypto from AWS-LC. Post-quantum signing (ML-DSA / FIPS 204)
//! can be added when the verification ecosystem supports it.

use std::path::Path;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine;

use crate::bundle::{AttestationBundle, VerificationMaterial};
use crate::error::AttestationError;
use crate::statement::InTotoStatement;

/// A backend that can sign in-toto attestation statements.
///
/// Implementors produce a verifiable [`AttestationBundle`] containing
/// the statement, signature, and verification material.
///
/// Note: `async fn` in traits is stable in Rust 2024 — no `async-trait`
/// crate needed. We suppress `async_fn_in_trait` because this trait is
/// internal and all implementors will be `Send`.
#[expect(async_fn_in_trait, reason = "internal trait — all impls are Send")]
pub trait Signer: Send + Sync {
    /// Sign the given statement and return a verifiable bundle.
    async fn sign(
        &self,
        statement: &InTotoStatement,
    ) -> Result<AttestationBundle, AttestationError>;

    /// A human-readable description of this signing backend.
    fn description(&self) -> &'static str;
}

/// Local ECDSA P-256 signer backed by `aws-lc-rs`.
///
/// Loads or generates a signing key stored as PKCS#8 DER on disk,
/// wrapped in PEM encoding. The key file is created with mode `0o600`
/// (owner-only read/write).
pub struct LocalSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl LocalSigner {
    /// Load an existing key from `key_path`, or generate a new one if
    /// the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::KeyError`] if:
    /// - The key file exists but cannot be parsed as PKCS#8
    /// - The key file cannot be created or written
    pub fn load_or_generate(key_path: &Path) -> Result<Self, AttestationError> {
        let rng = SystemRandom::new();

        if key_path.exists() {
            let pem = std::fs::read_to_string(key_path)
                .map_err(|e| AttestationError::KeyError(format!("failed to read key file: {e}")))?;

            let der = pem_to_der(&pem)
                .ok_or_else(|| AttestationError::KeyError("invalid PEM format".to_owned()))?;

            let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der)
                .map_err(|e| {
                    AttestationError::KeyError(format!("failed to parse PKCS#8 key: {e}"))
                })?;

            tracing::info!(path = %key_path.display(), "loaded existing signing key");
            Ok(Self { key_pair, rng })
        } else {
            let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .map_err(|e| AttestationError::KeyError(format!("failed to generate key: {e}")))?;

            // Ensure parent directory exists
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AttestationError::KeyError(format!(
                        "failed to create key directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            // Write key as PEM-wrapped PKCS#8
            let pem = der_to_pem(pkcs8_doc.as_ref(), "PRIVATE KEY");
            std::fs::write(key_path, pem.as_bytes()).map_err(|e| {
                AttestationError::KeyError(format!("failed to write key file: {e}"))
            })?;

            // Set file permissions to 0o600 (owner-only read/write)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(key_path, perms).map_err(|e| {
                    AttestationError::KeyError(format!("failed to set key file permissions: {e}"))
                })?;
            }

            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_doc.as_ref())
                    .map_err(|e| {
                        AttestationError::KeyError(format!("failed to load generated key: {e}"))
                    })?;

            tracing::info!(path = %key_path.display(), "generated new signing key");
            Ok(Self { key_pair, rng })
        }
    }

    /// Get the public key as PEM-encoded SPKI.
    fn public_key_pem(&self) -> String {
        // aws-lc-rs public_key() returns the uncompressed EC point.
        // We need to wrap it in an SPKI ASN.1 structure for PEM.
        let pub_bytes = self.key_pair.public_key().as_ref();
        let spki_der = encode_p256_spki(pub_bytes);
        der_to_pem(&spki_der, "PUBLIC KEY")
    }
}

impl Signer for LocalSigner {
    async fn sign(
        &self,
        statement: &InTotoStatement,
    ) -> Result<AttestationBundle, AttestationError> {
        let payload = serde_json::to_string(statement)?;

        // Sign the canonical JSON payload with ECDSA-P256-SHA256
        let sig = self
            .key_pair
            .sign(&self.rng, payload.as_bytes())
            .map_err(|e| AttestationError::SigningFailed(format!("ECDSA sign failed: {e}")))?;

        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());

        let public_key = self.public_key_pem();

        Ok(AttestationBundle {
            payload,
            signature: signature_b64,
            verification_material: VerificationMaterial::LocalKey { public_key },
        })
    }

    fn description(&self) -> &'static str {
        "local ECDSA P-256 (aws-lc)"
    }
}

/// Default key path: `~/.config/gleisner/keys/local.pem`.
pub fn default_key_path() -> std::path::PathBuf {
    directories::ProjectDirs::from("dev", "gleisner", "gleisner").map_or_else(
        || {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
            std::path::PathBuf::from(home).join(".config/gleisner/keys/local.pem")
        },
        |dirs| dirs.config_dir().join("keys/local.pem"),
    )
}

// ── PEM helpers ──────────────────────────────────────────────────────

/// Wrap DER bytes in PEM with the given label.
///
/// # Panics
///
/// Cannot panic — base64 output is always valid ASCII.
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    use std::fmt::Write;

    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

/// Extract DER bytes from a PEM string.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut b64 = String::new();
    let mut in_body = false;

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END ") {
            break;
        }
        if in_body {
            b64.push_str(trimmed);
        }
    }

    base64::engine::general_purpose::STANDARD.decode(&b64).ok()
}

/// Encode a raw P-256 public key (uncompressed point, 65 bytes) as
/// `SubjectPublicKeyInfo` (SPKI) DER.
///
/// The SPKI structure for P-256 has a fixed 26-byte header:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OID 1.2.840.10045.2.1  (id-ecPublicKey)
///     OID 1.2.840.10045.3.1.7 (prime256v1)
///   }
///   BIT STRING <public key>
/// }
/// ```
pub fn encode_p256_spki(pub_key: &[u8]) -> Vec<u8> {
    // Fixed SPKI header for P-256 uncompressed public key
    #[rustfmt::skip]
    const SPKI_HEADER: [u8; 26] = [
        0x30, 0x59,                                     // SEQUENCE (89 bytes total)
        0x30, 0x13,                                     // SEQUENCE (19 bytes)
        0x06, 0x07,                                     // OID (7 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,     // 1.2.840.10045.2.1
        0x06, 0x08,                                     // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
        0x03, 0x42, 0x00,                               // BIT STRING (66 bytes, 0 unused bits)
    ];

    let mut spki = Vec::with_capacity(SPKI_HEADER.len() + pub_key.len());
    spki.extend_from_slice(&SPKI_HEADER);
    spki.extend_from_slice(pub_key);
    spki
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::*;
    use crate::statement::*;
    use chrono::Utc;

    fn test_statement() -> InTotoStatement {
        InTotoStatement {
            statement_type: InTotoStatement::TYPE,
            subject: vec![Subject {
                name: "test.txt".to_owned(),
                digest: DigestSet {
                    sha256: "abc123".to_owned(),
                },
            }],
            predicate_type: InTotoStatement::PREDICATE_TYPE,
            predicate: GleisnerProvenance {
                build_type: GleisnerProvenance::BUILD_TYPE,
                builder: Builder {
                    id: "test-builder/0.1.0".to_owned(),
                },
                invocation: Invocation {
                    parameters: serde_json::json!({}),
                    environment: ClaudeCodeEnvironment {
                        tool: "claude-code",
                        claude_code_version: None,
                        model: None,
                        claude_md_hash: None,
                        context_hash: None,
                        sandboxed: true,
                        profile: "test".to_owned(),
                        api_base_url: "https://api.anthropic.com".to_owned(),
                    },
                },
                metadata: BuildMetadata {
                    build_started_on: Utc::now(),
                    build_finished_on: Utc::now(),
                    completeness: Completeness {
                        parameters: true,
                        environment: true,
                        materials: false,
                    },
                },
                materials: vec![],
                audit_log_digest: "deadbeef".to_owned(),
                sandbox_profile: SandboxProfileSummary {
                    name: "test".to_owned(),
                    profile_digest: "cafebabe".to_owned(),
                    network_policy: "deny".to_owned(),
                    filesystem_deny_count: 4,
                },
                chain: None,
            },
        }
    }

    #[test]
    fn generate_key_in_tempdir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("keys/local.pem");

        let signer = LocalSigner::load_or_generate(&key_path).expect("key gen should succeed");

        assert!(key_path.exists(), "key file should be created");
        assert_eq!(signer.description(), "local ECDSA P-256 (aws-lc)");

        // Verify file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn load_existing_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("local.pem");

        // Generate
        let signer1 = LocalSigner::load_or_generate(&key_path).expect("gen");
        let pk1 = signer1.public_key_pem();

        // Load
        let signer2 = LocalSigner::load_or_generate(&key_path).expect("load");
        let pk2 = signer2.public_key_pem();

        assert_eq!(pk1, pk2, "reloaded key should produce same public key");
    }

    #[tokio::test]
    async fn sign_and_verify_round_trip() {
        use aws_lc_rs::signature::{self, ECDSA_P256_SHA256_ASN1};

        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("local.pem");

        let signer = LocalSigner::load_or_generate(&key_path).expect("gen");
        let statement = test_statement();

        let bundle = signer.sign(&statement).await.expect("sign should succeed");

        // Verify: decode signature, get public key, verify
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&bundle.signature)
            .expect("base64 decode");

        let pub_key_bytes = signer.key_pair.public_key().as_ref();

        let public_key = signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key_bytes);

        public_key
            .verify(bundle.payload.as_bytes(), &sig_bytes)
            .expect("signature verification should succeed");
    }

    #[test]
    fn pem_round_trip() {
        let data = b"hello world";
        let pem = der_to_pem(data, "TEST");
        let recovered = pem_to_der(&pem).expect("should parse PEM");
        assert_eq!(recovered, data);
    }

    #[test]
    fn default_key_path_is_sensible() {
        let path = default_key_path();
        let path_str = path.display().to_string();
        assert!(
            path_str.contains("gleisner"),
            "key path should contain 'gleisner': {path_str}"
        );
        assert!(
            path_str.ends_with("local.pem"),
            "key path should end with 'local.pem': {path_str}"
        );
    }
}
