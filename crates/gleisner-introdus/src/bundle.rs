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
    /// No verification material (unsigned bundle, used in testing/chains).
    #[serde(rename = "none")]
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// AttestationBundle survives JSON roundtrip for any payload and signature.
        #[test]
        fn bundle_json_roundtrip(
            payload in ".*",
            sig in "[a-zA-Z0-9+/=]*",
        ) {
            let bundle = AttestationBundle {
                payload: payload.clone(),
                signature: sig.clone(),
                verification_material: VerificationMaterial::None,
            };

            let json = serde_json::to_string(&bundle).unwrap();
            let restored: AttestationBundle = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&restored.payload, &payload);
            prop_assert_eq!(&restored.signature, &sig);
            assert!(matches!(restored.verification_material, VerificationMaterial::None));
        }

        /// AttestationBundle with LocalKey material survives JSON roundtrip.
        #[test]
        fn bundle_local_key_roundtrip(
            payload in ".*",
            key in "-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----",
        ) {
            let bundle = AttestationBundle {
                payload: payload.clone(),
                signature: "dGVzdA==".to_owned(),
                verification_material: VerificationMaterial::LocalKey {
                    public_key: key.clone(),
                },
            };

            let json = serde_json::to_string(&bundle).unwrap();
            let restored: AttestationBundle = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&restored.payload, &payload);
            match &restored.verification_material {
                VerificationMaterial::LocalKey { public_key } => {
                    prop_assert_eq!(public_key, &key);
                }
                other => prop_assert!(false, "expected LocalKey, got {:?}", other),
            }
        }
    }
}
