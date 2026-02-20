//! Signing backends for attestation bundles.
//!
//! Two signing backends are available:
//!
//! - **`LocalSigner`**: ECDSA P-256 keys for air-gapped environments.
//!   Uses `aws-lc-rs` (formally verified C crypto from AWS-LC).
//! - **`SigstoreSigner`** (feature `keyless`): Sigstore keyless signing
//!   via Fulcio certificates + Rekor transparency log. Requires an
//!   interactive browser OIDC flow or CI environment token.
//!
//! Post-quantum signing (ML-DSA / FIPS 204) can be added when the
//! verification ecosystem supports it.

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

// ── Sigstore keyless signer ──────────────────────────────────────────

/// Sigstore keyless signer using Fulcio + Rekor (public-good instance).
///
/// Authentication order:
/// 1. If a pre-supplied OIDC JWT is provided, use it directly.
/// 2. Try ambient credential detection (GitHub Actions, GitLab CI, etc.).
/// 3. Fall back to interactive browser OIDC flow.
///
/// The signed Sigstore bundle (v0.3) is written to a sibling `.sigstore.json`
/// file for `cosign` and `gh attestation verify` compatibility.
///
/// Requires the `keyless` feature.
#[cfg(feature = "keyless")]
pub struct SigstoreSigner {
    /// Optional path to write the raw Sigstore bundle alongside our format.
    sigstore_bundle_path: Option<std::path::PathBuf>,
    /// Pre-supplied OIDC token JWT (e.g., from `--sigstore-token`).
    oidc_token: Option<String>,
}

#[cfg(feature = "keyless")]
impl SigstoreSigner {
    /// Create a new keyless signer.
    ///
    /// - `sigstore_bundle_path`: if `Some`, writes the raw Sigstore bundle JSON
    ///   there (for `cosign verify-blob` / `gh attestation`).
    /// - `oidc_token`: if `Some`, uses this JWT directly instead of interactive auth.
    pub fn new(
        sigstore_bundle_path: Option<std::path::PathBuf>,
        oidc_token: Option<String>,
    ) -> Self {
        Self {
            sigstore_bundle_path,
            oidc_token,
        }
    }
}

#[cfg(feature = "keyless")]
impl SigstoreSigner {
    /// Sign a pre-serialized in-toto statement payload with Sigstore keyless.
    ///
    /// This is the core signing method. Use this when you already have the
    /// statement JSON (e.g., cosigning an existing attestation bundle).
    /// The `Signer::sign` trait method delegates here after serialization.
    pub async fn sign_payload(
        &self,
        payload_json: &str,
    ) -> Result<AttestationBundle, AttestationError> {
        use sigstore_sign::SigningContext;

        // 1. Try pre-supplied token
        let token = if let Some(ref jwt) = self.oidc_token {
            tracing::info!("using pre-supplied OIDC token");
            sigstore_oidc::parse_identity_token(jwt)
                .map_err(|e| AttestationError::SigningFailed(format!("invalid OIDC token: {e}")))?
        } else {
            // 2. Try ambient detection (CI environments)
            tracing::info!("attempting ambient OIDC credential detection...");
            match sigstore_oidc::IdentityToken::detect_ambient().await {
                Ok(Some(token)) => {
                    tracing::info!("detected ambient OIDC token (CI environment)");
                    token
                }
                Ok(None) | Err(_) => {
                    // 3. Fall back to interactive browser flow
                    tracing::info!("no ambient credentials — opening browser for OIDC...");
                    sigstore_oidc::get_identity_token_with_options(sigstore_oidc::AuthOptions {
                        force_oob: false,
                    })
                    .await
                    .map_err(|e| {
                        AttestationError::SigningFailed(format!(
                            "OIDC authentication failed: {e}\n\
                             Hint: In headless environments, use --sigstore-token with a \
                             pre-obtained JWT, or run in GitHub Actions for ambient detection."
                        ))
                    })?
                }
            }
        };

        // 2. Create production signing context (Fulcio + Rekor)
        let context = SigningContext::production();
        let signer = context.signer(token);

        // 3. Sign the in-toto statement as a DSSE envelope
        let bundle = signer
            .sign_raw_statement(payload_json.as_bytes())
            .await
            .map_err(|e| {
                AttestationError::SigningFailed(format!("Sigstore signing failed: {e}"))
            })?;

        // 4. Serialize the native Sigstore bundle
        let bundle_json = serde_json::to_string_pretty(&bundle).map_err(|e| {
            AttestationError::SigningFailed(format!("bundle serialization failed: {e}"))
        })?;

        // 5. Optionally write the raw Sigstore bundle for cosign/gh compatibility
        if let Some(ref path) = self.sigstore_bundle_path {
            std::fs::write(path, &bundle_json).map_err(|e| {
                AttestationError::SigningFailed(format!(
                    "failed to write Sigstore bundle to {}: {e}",
                    path.display()
                ))
            })?;
            tracing::info!(path = %path.display(), "wrote native Sigstore bundle (v0.3)");
        }

        // 6. Extract verification material for our attestation format
        let bundle_value: serde_json::Value = serde_json::from_str(&bundle_json)?;
        let certificate_chain = bundle_value
            .pointer("/verificationMaterial/certificate/rawBytes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let rekor_log_id = bundle_value
            .pointer("/verificationMaterial/tlogEntries/0/logIndex")
            .and_then(|v| v.as_str().or_else(|| v.as_i64().map(|_| "")))
            .unwrap_or("")
            .to_owned();

        // Decode the base64 certificate to PEM for our format
        let cert_pem = if !certificate_chain.is_empty() {
            if let Ok(cert_der) =
                base64::engine::general_purpose::STANDARD.decode(&certificate_chain)
            {
                der_to_pem(&cert_der, "CERTIFICATE")
            } else {
                certificate_chain.clone()
            }
        } else {
            String::new()
        };

        Ok(AttestationBundle {
            payload: payload_json.to_owned(),
            signature: String::new(), // signature is in the DSSE envelope inside the Sigstore bundle
            verification_material: VerificationMaterial::Sigstore {
                certificate_chain: cert_pem,
                rekor_log_id,
            },
        })
    }
}

#[cfg(feature = "keyless")]
impl Signer for SigstoreSigner {
    async fn sign(
        &self,
        statement: &InTotoStatement,
    ) -> Result<AttestationBundle, AttestationError> {
        let payload = serde_json::to_string(statement)?;
        self.sign_payload(&payload).await
    }

    fn description(&self) -> &'static str {
        "Sigstore keyless (Fulcio + Rekor)"
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
///
/// Returns `None` if the PEM has no BEGIN/END markers, contains no
/// base64 content between the markers, or the base64 is invalid.
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

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()?;

    // Reject empty PEM bodies — valid PEM markers with no content between them
    // would produce an empty DER that confuses downstream crypto code.
    if decoded.is_empty() {
        return None;
    }

    Some(decoded)
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
                denial_count: 0,
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
    fn pem_to_der_rejects_empty_body() {
        let empty_pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
        assert!(
            pem_to_der(empty_pem).is_none(),
            "empty PEM body should return None"
        );
    }

    #[test]
    fn pem_to_der_rejects_no_markers() {
        assert!(
            pem_to_der("just some text").is_none(),
            "PEM without markers should return None"
        );
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
