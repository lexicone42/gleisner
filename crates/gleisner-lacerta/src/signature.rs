//! ECDSA P-256 signature verification.
//!
//! Verifies attestation bundle signatures using `aws-lc-rs`.

use aws_lc_rs::signature::{self, ECDSA_P256_SHA256_ASN1};
use base64::Engine;
use gleisner_introdus::bundle::VerificationMaterial;
use gleisner_introdus::signer::pem_to_der;

use crate::error::VerificationError;

/// The fixed size of the SPKI ASN.1 header for P-256 keys.
const P256_SPKI_HEADER_LEN: usize = 26;

/// Verify a signature over `payload` using the given verification material.
///
/// Currently only supports `LocalKey` material (ECDSA P-256).
/// Sigstore material will return `UnsupportedMaterial`.
pub fn verify_signature(
    payload: &[u8],
    signature_b64: &str,
    material: &VerificationMaterial,
) -> Result<(), VerificationError> {
    match material {
        VerificationMaterial::LocalKey { public_key } => {
            verify_signature_with_key(payload, signature_b64, public_key)
        }
        VerificationMaterial::Sigstore { .. } => Err(VerificationError::UnsupportedMaterial(
            "sigstore verification not yet implemented".to_owned(),
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
    fn sigstore_material_unsupported() {
        let material = VerificationMaterial::Sigstore {
            certificate_chain: String::new(),
            rekor_log_id: String::new(),
        };
        let result = verify_signature(b"payload", "sig", &material);
        assert!(matches!(
            result,
            Err(VerificationError::UnsupportedMaterial(_))
        ));
    }
}
