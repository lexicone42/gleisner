//! Attestation bundle packaging.
//!
//! A bundle contains the in-toto statement, its cryptographic signature,
//! and the verification material needed to validate it.

use serde::{Deserialize, Serialize};

/// A signed attestation bundle ready for distribution.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationBundle {
    /// The canonical JSON of the signed statement.
    pub payload: String,
    /// The signature over the payload.
    pub signature: String,
    /// The verification material (certificate chain or public key).
    pub verification_material: VerificationMaterial,
}

/// Material needed to verify the bundle's signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerificationMaterial {
    /// Sigstore keyless: Fulcio certificate + Rekor log entry.
    #[serde(rename = "sigstore")]
    Sigstore {
        /// PEM-encoded certificate chain from Fulcio.
        certificate_chain: String,
        /// Rekor transparency log entry ID.
        rekor_log_id: String,
    },
    /// Local ECDSA key: public key in PEM format.
    #[serde(rename = "local_key")]
    LocalKey {
        /// PEM-encoded public key.
        public_key: String,
    },
}
