//! Verification and policy enforcement for Gleisner attestation bundles.
//!
//! `gleisner-lacerta` verifies cryptographic signatures, checks digest
//! integrity, and evaluates OPA/Rego policies (via Wasmtime) against
//! attestation records.

pub mod error;
