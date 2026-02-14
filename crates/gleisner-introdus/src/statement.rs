//! in-toto v1 attestation statement builder.
//!
//! See: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>

use serde::Serialize;

use crate::provenance::GleisnerProvenance;

/// An in-toto v1 attestation statement.
#[derive(Debug, Serialize)]
pub struct InTotoStatement {
    /// Always [`InTotoStatement::TYPE`].
    #[serde(rename = "_type")]
    pub statement_type: &'static str,
    /// Output artifacts of the build.
    pub subject: Vec<Subject>,
    /// Always [`InTotoStatement::PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: &'static str,
    /// The Gleisner provenance predicate.
    pub predicate: GleisnerProvenance,
}

impl InTotoStatement {
    /// The canonical statement type URI.
    pub const TYPE: &str = "https://in-toto.io/Statement/v1";
    /// The Gleisner provenance predicate type URI.
    pub const PREDICATE_TYPE: &str = "https://gleisner.dev/provenance/v1";
}

/// A subject (output artifact) of the build.
#[derive(Debug, Serialize)]
pub struct Subject {
    /// Artifact name or path.
    pub name: String,
    /// Content digests.
    pub digest: DigestSet,
}

/// A set of digest algorithms and their hex-encoded values.
#[derive(Debug, Clone, Serialize)]
pub struct DigestSet {
    /// SHA-256 hex digest.
    pub sha256: String,
}
