//! Error types for the Nickel package evaluator.

use std::path::PathBuf;

/// Errors that can occur during package evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    /// A package file could not be read.
    #[error("failed to read package at {path}: {source}")]
    PackageRead {
        /// Path to the package file.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Nickel evaluation failed.
    #[error("nickel evaluation failed for {package}: {message}")]
    NickelEval {
        /// Package name.
        package: String,
        /// Error message from Nickel.
        message: String,
    },

    /// Import substitution failed.
    #[error("import substitution failed for {package}: {message}")]
    ImportSubstitution {
        /// Package name.
        package: String,
        /// Error detail.
        message: String,
    },

    /// A dependency cycle was detected without a `replace_on_cycle` fallback.
    #[error("unresolvable dependency cycle involving: {}", packages.join(", "))]
    UnresolvableCycle {
        /// Packages involved in the cycle.
        packages: Vec<String>,
    },

    /// The content store failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// JSON serialization/deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The dependency graph has no valid topological ordering (unexpected).
    #[error("dependency graph is not a DAG")]
    NotADag,
}

/// Errors specific to the content-addressed store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// I/O error reading or writing store entries.
    #[error("store I/O error at {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A store entry's hash did not match its content.
    #[error("integrity check failed for {hash}: expected content hash does not match")]
    IntegrityMismatch {
        /// The expected hash.
        hash: String,
    },
}
