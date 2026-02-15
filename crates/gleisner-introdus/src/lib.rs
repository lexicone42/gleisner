//! Attestation and cryptographic provenance for Claude Code sessions.
//!
//! `gleisner-introdus` records session events, builds in-toto v1 attestation
//! statements with SLSA v1.0-compatible provenance predicates, and signs
//! them via Sigstore or local keys.

pub mod bundle;
pub mod chain;
pub mod claude_code;
pub mod error;
pub mod metadata;
pub mod provenance;
pub mod recorder;
pub mod signer;
pub mod statement;
pub mod vcs;
