//! Audit event types and JSONL writer.
//!
//! Defines the vocabulary of observable actions within a sandboxed
//! Claude Code session. Every event is timestamped, sequenced, and
//! tagged with whether it was allowed or denied by policy.
//!
//! Events are serialized as newline-delimited JSON (JSONL) for
//! machine consumption and forensic analysis.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::AuditError;

/// A single auditable action observed during a sandboxed session.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Monotonically increasing sequence number within a session.
    pub sequence: u64,
    /// What happened.
    pub event: EventKind,
    /// Whether the sandbox policy allowed or denied this action.
    pub result: EventResult,
}

/// The kind of action observed.
///
/// Uses adjacently-tagged serde representation so each JSON line
/// self-describes its event type for easy `jq` filtering.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "detail")]
pub enum EventKind {
    /// A file was read. Includes content digest.
    FileRead {
        /// Path to the file that was read.
        path: PathBuf,
        /// SHA-256 hex digest of the file content.
        sha256: String,
    },

    /// A file was written. Includes before/after digests.
    FileWrite {
        /// Path to the file that was written.
        path: PathBuf,
        /// SHA-256 of the file before writing (`None` if newly created).
        sha256_before: Option<String>,
        /// SHA-256 of the file after writing.
        sha256_after: String,
    },

    /// A file was deleted.
    FileDelete {
        /// Path to the deleted file.
        path: PathBuf,
        /// SHA-256 of the file before deletion.
        sha256_before: String,
    },

    /// A process was spawned.
    ProcessExec {
        /// The command that was executed.
        command: String,
        /// Command arguments.
        args: Vec<String>,
        /// Working directory at time of execution.
        cwd: PathBuf,
    },

    /// A process exited.
    ProcessExit {
        /// The command that exited.
        command: String,
        /// Process exit code.
        exit_code: i32,
    },

    /// An outbound network connection was attempted.
    NetworkConnect {
        /// Target host or IP.
        target: String,
        /// Target port.
        port: u16,
    },

    /// A DNS query was made.
    NetworkDns {
        /// The DNS query name.
        query: String,
        /// Resolved addresses.
        results: Vec<String>,
    },

    /// An environment variable was read.
    /// **Never logs the actual value** — only its digest.
    EnvRead {
        /// Environment variable name.
        key: String,
        /// SHA-256 hex digest of the value.
        value_sha256: String,
    },
}

/// Whether the action was allowed or denied by the sandbox policy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventResult {
    /// The action was permitted by policy.
    Allowed,
    /// The action was blocked by policy.
    Denied {
        /// Why the action was denied.
        reason: String,
    },
}

/// Writes audit events as newline-delimited JSON (JSONL) to a file.
///
/// Each call to [`write_event`] appends exactly one JSON line followed
/// by a newline character. The writer flushes after every event to
/// ensure crash-consistent audit trails.
pub struct JsonlWriter<W: Write> {
    writer: W,
}

impl<W: Write> JsonlWriter<W> {
    /// Create a new JSONL writer wrapping the given output.
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Serialize and append a single audit event as one JSON line.
    ///
    /// Flushes after writing to ensure durability.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if serialization or I/O fails.
    pub fn write_event(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

/// Create a [`JsonlWriter`] backed by a file at the given path.
///
/// Creates the file if it doesn't exist, appends if it does.
///
/// # Errors
///
/// Returns [`AuditError`] if the file cannot be opened or created.
pub fn open_audit_log(
    path: &Path,
) -> Result<JsonlWriter<std::io::BufWriter<std::fs::File>>, AuditError> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    Ok(JsonlWriter::new(std::io::BufWriter::new(file)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes_as_tagged_json() {
        let event = AuditEvent {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
            sequence: 1,
            event: EventKind::FileRead {
                path: PathBuf::from("/project/src/main.rs"),
                sha256: "abc123".to_owned(),
            },
            result: EventResult::Allowed,
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        assert!(json.contains(r#""type":"FileRead"#));
        assert!(json.contains(r#""sha256":"abc123"#));
        assert!(json.contains(r#""result":"allowed"#));
    }

    #[test]
    fn jsonl_writer_appends_newlines() {
        let mut buf = Vec::new();
        let mut writer = JsonlWriter::new(&mut buf);

        let event = AuditEvent {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
            sequence: 0,
            event: EventKind::ProcessExec {
                command: "cargo".to_owned(),
                args: vec!["build".to_owned()],
                cwd: PathBuf::from("/project"),
            },
            result: EventResult::Allowed,
        };

        writer.write_event(&event).expect("write should succeed");
        writer.write_event(&event).expect("write should succeed");

        let output = String::from_utf8(buf).expect("valid UTF-8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "should have exactly 2 JSONL lines");

        // Each line should be valid JSON
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("each line should be valid JSON");
        }
    }

    #[test]
    fn denied_event_includes_reason() {
        let event = AuditEvent {
            timestamp: Utc::now(),
            sequence: 42,
            event: EventKind::NetworkConnect {
                target: "evil.example.com".to_owned(),
                port: 443,
            },
            result: EventResult::Denied {
                reason: "domain not in allowlist".to_owned(),
            },
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        assert!(json.contains(r#""denied"#));
        assert!(json.contains("domain not in allowlist"));
    }

    #[test]
    fn env_read_never_contains_raw_value() {
        let event = AuditEvent {
            timestamp: Utc::now(),
            sequence: 5,
            event: EventKind::EnvRead {
                key: "ANTHROPIC_API_KEY".to_owned(),
                value_sha256: "deadbeef".to_owned(),
            },
            result: EventResult::Allowed,
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        // The JSON should contain the key name and hash, but no field for the raw value
        assert!(json.contains("ANTHROPIC_API_KEY"));
        assert!(json.contains("value_sha256"));
        assert!(!json.contains("sk-ant-")); // No API key prefix
    }
}
