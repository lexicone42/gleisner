//! Verification and policy enforcement for Gleisner attestation bundles.
//!
//! `gleisner-lacerta` verifies cryptographic signatures, checks digest
//! integrity, and evaluates policies against attestation records.
//!
//! The verification pipeline has three phases:
//! 1. **Signature** — ECDSA P-256 over the canonical JSON payload
//! 2. **Digests** — SHA-256 of subjects and audit logs
//! 3. **Policy** — configurable rules (built-in JSON or WASM/OPA stub)

pub mod diff;
pub mod digest;
pub mod error;
pub mod inspect;
pub mod policy;
pub mod policy_wasm;
pub mod signature;
pub mod verify;

// Re-export primary types for convenience.
pub use error::VerificationError;
pub use verify::{VerificationOutcome, VerificationReport, Verifier, VerifyConfig};
