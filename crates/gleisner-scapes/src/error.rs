//! Error types for the audit logging subsystem.

/// Errors from the Scapes audit subsystem.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Failed to write an audit event to the log file.
    #[error("failed to write audit event: {0}")]
    WriteError(#[from] std::io::Error),

    /// Failed to serialize an audit event.
    #[error("failed to serialize audit event: {0}")]
    SerializeError(#[from] serde_json::Error),
}
