//! Signature verification for attestation bundles.
//!
//! Supports two verification paths:
//! - **`LocalKey`**: ECDSA P-256 verification using `aws-lc-rs` (offline, no dependencies).
//! - **`Sigstore`**: Certificate-based verification using the `sigstore` crate.
//!   Extracts the public key from the leaf certificate in the chain and verifies
//!   the signature. Rekor transparency log verification is logged but not verified
//!   online (would require async HTTP).

use aws_lc_rs::signature::{self, ECDSA_P256_SHA256_ASN1};
use base64::Engine;
use der::{Decode, Encode};
use gleisner_introdus::bundle::VerificationMaterial;
use gleisner_introdus::signer::pem_to_der;
use sigstore::crypto::{CosignVerificationKey, Signature};
use x509_cert::Certificate;

use crate::error::VerificationError;

/// The fixed size of the SPKI ASN.1 header for P-256 keys.
const P256_SPKI_HEADER_LEN: usize = 26;

/// Verify a signature over `payload` using the given verification material.
///
/// Dispatches to the appropriate verification path based on material type.
pub fn verify_signature(
    payload: &[u8],
    signature_b64: &str,
    material: &VerificationMaterial,
) -> Result<(), VerificationError> {
    match material {
        VerificationMaterial::LocalKey { public_key } => {
            verify_signature_with_key(payload, signature_b64, public_key)
        }
        VerificationMaterial::Sigstore {
            certificate_chain,
            rekor_log_id,
        } => verify_signature_with_certificate(
            payload,
            signature_b64,
            certificate_chain,
            rekor_log_id,
        ),
        VerificationMaterial::None => Err(VerificationError::InvalidSignature(
            "no verification material — unsigned bundle".to_owned(),
        )),
    }
}

/// Verify a signature over `payload` using a PEM-encoded public key.
///
/// The key must be an ECDSA P-256 public key in SPKI format.
pub fn verify_signature_with_key(
    payload: &[u8],
    signature_b64: &str,
    public_key_pem: &str,
) -> Result<(), VerificationError> {
    if signature_b64.is_empty() {
        return Err(VerificationError::InvalidSignature(
            "empty signature".to_owned(),
        ));
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| {
            VerificationError::InvalidSignature(format!("invalid base64 signature: {e}"))
        })?;

    let spki_der = pem_to_der(public_key_pem)
        .ok_or_else(|| VerificationError::InvalidSignature("invalid PEM public key".to_owned()))?;

    // Strip the 26-byte SPKI header to get the raw EC point
    if spki_der.len() <= P256_SPKI_HEADER_LEN {
        return Err(VerificationError::InvalidSignature(
            "public key DER too short for SPKI".to_owned(),
        ));
    }
    let raw_point = &spki_der[P256_SPKI_HEADER_LEN..];

    let public_key = signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, raw_point);

    public_key
        .verify(payload, &sig_bytes)
        .map_err(|e| VerificationError::InvalidSignature(format!("ECDSA verification failed: {e}")))
}

/// Verify a signature using a Sigstore certificate chain.
///
/// Extracts the public key from the first (leaf) certificate in the PEM chain,
/// then verifies the signature using the `sigstore` crate's `CosignVerificationKey`.
/// The Rekor log ID is recorded but not verified online.
fn verify_signature_with_certificate(
    payload: &[u8],
    signature_b64: &str,
    certificate_chain: &str,
    rekor_log_id: &str,
) -> Result<(), VerificationError> {
    // Extract the leaf certificate's public key from the PEM chain
    let cert_der = pem_to_der(certificate_chain).ok_or_else(|| {
        VerificationError::InvalidSignature("invalid PEM certificate chain".to_owned())
    })?;

    let cert = Certificate::from_der(&cert_der).map_err(|e| {
        VerificationError::InvalidSignature(format!("failed to parse X.509 certificate: {e}"))
    })?;

    // Extract the SubjectPublicKeyInfo DER bytes
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| VerificationError::InvalidSignature(format!("failed to encode SPKI: {e}")))?;

    // Build a CosignVerificationKey from the SPKI DER (auto-detects algorithm)
    let verification_key = CosignVerificationKey::try_from_der(&spki_der).map_err(|e| {
        VerificationError::InvalidSignature(format!("unsupported key type in certificate: {e}"))
    })?;

    // Verify the signature
    verification_key
        .verify_signature(Signature::Base64Encoded(signature_b64.as_bytes()), payload)
        .map_err(|e| {
            VerificationError::InvalidSignature(format!(
                "sigstore signature verification failed: {e}"
            ))
        })?;

    // Log Rekor transparency log ID (not verified online)
    if !rekor_log_id.is_empty() {
        tracing::info!(
            rekor_log_id,
            "Rekor log entry recorded (not verified online)"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use gleisner_introdus::signer::{der_to_pem, encode_p256_spki};

    fn generate_test_keypair() -> (EcdsaKeyPair, String) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keygen");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("parse key");
        let pub_pem = der_to_pem(
            &encode_p256_spki(key_pair.public_key().as_ref()),
            "PUBLIC KEY",
        );
        (key_pair, pub_pem)
    }

    fn sign_payload(key_pair: &EcdsaKeyPair, payload: &[u8]) -> String {
        let rng = SystemRandom::new();
        let sig = key_pair.sign(&rng, payload).expect("sign");
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (key_pair, pub_pem) = generate_test_keypair();
        let payload = b"hello world";
        let sig_b64 = sign_payload(&key_pair, payload);

        let material = VerificationMaterial::LocalKey {
            public_key: pub_pem,
        };
        verify_signature(payload, &sig_b64, &material).expect("should verify");
    }

    #[test]
    fn wrong_key_fails() {
        let (key_pair, _) = generate_test_keypair();
        let (_, other_pub_pem) = generate_test_keypair();
        let payload = b"hello world";
        let sig_b64 = sign_payload(&key_pair, payload);

        let result = verify_signature_with_key(payload, &sig_b64, &other_pub_pem);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let (key_pair, pub_pem) = generate_test_keypair();
        let payload = b"hello world";
        let sig_b64 = sign_payload(&key_pair, payload);

        let result = verify_signature_with_key(b"tampered", &sig_b64, &pub_pem);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let (key_pair, pub_pem) = generate_test_keypair();
        let payload = b"hello world";
        let mut sig_b64 = sign_payload(&key_pair, payload);

        // Tamper with the base64 signature
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        bytes[0] ^= 0xFF;
        sig_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let result = verify_signature_with_key(payload, &sig_b64, &pub_pem);
        assert!(result.is_err());
    }

    #[test]
    fn sigstore_invalid_certificate_fails() {
        let material = VerificationMaterial::Sigstore {
            certificate_chain: "not-a-valid-cert".to_owned(),
            rekor_log_id: String::new(),
        };
        let result = verify_signature(b"payload", "c2ln", &material);
        assert!(
            result.is_err(),
            "invalid certificate should fail verification"
        );
    }

    #[test]
    fn sigstore_empty_certificate_fails() {
        let material = VerificationMaterial::Sigstore {
            certificate_chain: String::new(),
            rekor_log_id: String::new(),
        };
        let result = verify_signature(b"payload", "c2ln", &material);
        assert!(
            result.is_err(),
            "empty certificate chain should fail verification"
        );
    }

    #[test]
    fn empty_signature_rejected_early() {
        let (_, pub_pem) = generate_test_keypair();
        let result = verify_signature_with_key(b"payload", "", &pub_pem);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("empty signature"),
            "should report empty signature, got: {err_msg}"
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Any payload signed with a key can be verified with the same key.
            #[test]
            fn sign_verify_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
                let (key_pair, pub_pem) = generate_test_keypair();
                let sig_b64 = sign_payload(&key_pair, &payload);
                let result = verify_signature_with_key(&payload, &sig_b64, &pub_pem);
                prop_assert!(result.is_ok(), "valid signature should verify: {:?}", result.err());
            }

            /// Tampered payloads always fail verification.
            #[test]
            fn tampered_payload_always_fails(
                payload in prop::collection::vec(any::<u8>(), 1..1024),
                flip_idx in any::<prop::sample::Index>(),
            ) {
                let (key_pair, pub_pem) = generate_test_keypair();
                let sig_b64 = sign_payload(&key_pair, &payload);

                // Tamper with one byte
                let mut tampered = payload;
                let idx = flip_idx.index(tampered.len());
                tampered[idx] ^= 0xFF;

                // Tampered payload must not verify (unless we flipped to same value,
                // which can't happen with XOR 0xFF on a byte)
                let result = verify_signature_with_key(&tampered, &sig_b64, &pub_pem);
                prop_assert!(result.is_err(), "tampered payload should fail verification");
            }
        }
    }
}
