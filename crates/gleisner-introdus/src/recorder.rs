//! Session recorder that consumes audit events and builds attestation data.
//!
//! The recorder listens on the broadcast channel from `gleisner-scapes`,
//! classifies events into materials (inputs) and subjects (outputs),
//! and on finalization produces a [`RecorderOutput`] ready for
//! assembly into an in-toto statement.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use gleisner_scapes::audit::{AuditEvent, EventKind};

use crate::provenance::Material;
use crate::statement::{DigestSet, Subject};

/// Output produced by the session recorder after the event channel closes.
#[derive(Debug)]
pub struct RecorderOutput {
    /// Input artifacts — files read during the session.
    pub materials: Vec<Material>,
    /// Output artifacts — files written during the session.
    pub subjects: Vec<Subject>,
    /// Total number of events processed.
    pub event_count: u64,
    /// SHA-256 hex digest of the JSONL audit log file.
    pub audit_log_digest: String,
    /// When the recording started.
    pub start_time: DateTime<Utc>,
    /// When the recording finished.
    pub finish_time: DateTime<Utc>,
}

/// Drain audit events from the broadcast receiver, classify them,
/// and produce a [`RecorderOutput`] once the channel closes.
///
/// The `audit_log_path` is hashed after the channel closes to include
/// the audit log's integrity digest in the attestation.
pub async fn run(
    mut rx: broadcast::Receiver<AuditEvent>,
    audit_log_path: PathBuf,
) -> RecorderOutput {
    let start_time = Utc::now();

    // Materials: keyed by path, first digest wins (initial state of inputs)
    let mut materials_map: HashMap<PathBuf, String> = HashMap::new();
    // Subjects: keyed by path, last digest wins (final state of outputs)
    let mut subjects_map: HashMap<PathBuf, String> = HashMap::new();
    let mut event_count: u64 = 0;

    loop {
        match rx.recv().await {
            Ok(event) => {
                event_count += 1;
                classify_event(&event.event, &mut materials_map, &mut subjects_map);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    skipped = n,
                    "recorder lagged — some events were not classified"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("event channel closed — recorder finalizing");
                break;
            }
        }
    }

    let finish_time = Utc::now();

    // Hash the completed audit log file
    let audit_log_digest = hash_file(&audit_log_path).unwrap_or_default();

    let materials = materials_map
        .into_iter()
        .map(|(path, sha256)| Material {
            uri: format!("file://{}", path.display()),
            digest: DigestSet { sha256 },
        })
        .collect();

    let subjects = subjects_map
        .into_iter()
        .map(|(path, sha256)| Subject {
            name: path.display().to_string(),
            digest: DigestSet { sha256 },
        })
        .collect();

    RecorderOutput {
        materials,
        subjects,
        event_count,
        audit_log_digest,
        start_time,
        finish_time,
    }
}

/// Classify a single event into materials and/or subjects.
fn classify_event(
    kind: &EventKind,
    materials: &mut HashMap<PathBuf, String>,
    subjects: &mut HashMap<PathBuf, String>,
) {
    match kind {
        EventKind::FileRead { path, sha256 } => {
            // First digest wins for materials (initial state)
            materials
                .entry(path.clone())
                .or_insert_with(|| sha256.clone());
        }
        EventKind::FileWrite {
            path, sha256_after, ..
        } => {
            // Last digest wins for subjects (final state)
            subjects.insert(path.clone(), sha256_after.clone());
        }
        EventKind::FileDelete { .. }
        | EventKind::ProcessExec { .. }
        | EventKind::ProcessExit { .. }
        | EventKind::NetworkConnect { .. }
        | EventKind::NetworkDns { .. }
        | EventKind::EnvRead { .. } => {
            // Counted by event_count, no material/subject tracking
        }
    }
}

/// Hash a file with SHA-256 and return the hex digest.
fn hash_file(path: &PathBuf) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&content);
    Some(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gleisner_scapes::audit::{AuditEvent, EventResult};
    use gleisner_scapes::stream::EventBus;

    fn make_event(kind: EventKind) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            sequence: 0,
            event: kind,
            result: EventResult::Allowed,
        }
    }

    #[tokio::test]
    async fn recorder_classifies_file_events() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        // Publish events
        bus.publish(make_event(EventKind::FileRead {
            path: PathBuf::from("/project/src/main.rs"),
            sha256: "aaa".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/output.rs"),
            sha256_before: None,
            sha256_after: "bbb".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileDelete {
            path: PathBuf::from("/project/tmp.txt"),
            sha256_before: "ccc".to_owned(),
        }));

        // Drop bus to close channel
        drop(bus);

        let output = run(rx, log_path).await;

        assert_eq!(output.event_count, 3);
        assert_eq!(output.materials.len(), 1, "one file read → one material");
        assert_eq!(output.subjects.len(), 1, "one file write → one subject");
    }

    #[tokio::test]
    async fn recorder_deduplicates_materials_first_wins() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        // Same file read twice with different digests
        bus.publish(make_event(EventKind::FileRead {
            path: PathBuf::from("/project/src/lib.rs"),
            sha256: "first".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileRead {
            path: PathBuf::from("/project/src/lib.rs"),
            sha256: "second".to_owned(),
        }));

        drop(bus);

        let output = run(rx, log_path).await;

        assert_eq!(output.materials.len(), 1);
        assert_eq!(
            output.materials[0].digest.sha256, "first",
            "first digest should win for materials"
        );
    }

    #[tokio::test]
    async fn recorder_deduplicates_subjects_last_wins() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        // Same file written twice
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/out.txt"),
            sha256_before: None,
            sha256_after: "first".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/out.txt"),
            sha256_before: Some("first".to_owned()),
            sha256_after: "final".to_owned(),
        }));

        drop(bus);

        let output = run(rx, log_path).await;

        assert_eq!(output.subjects.len(), 1);
        assert_eq!(
            output.subjects[0].digest.sha256, "final",
            "last digest should win for subjects"
        );
    }

    #[tokio::test]
    async fn recorder_zero_events() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        drop(bus);

        let output = run(rx, log_path).await;

        assert_eq!(output.event_count, 0);
        assert!(output.materials.is_empty());
        assert!(output.subjects.is_empty());
    }
}
