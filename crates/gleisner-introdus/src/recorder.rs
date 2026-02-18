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

use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};

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
    /// Number of events that were denied by sandbox policy.
    pub denial_count: u64,
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
pub async fn run(mut rx: broadcast::Receiver<AuditEvent>) -> RecorderOutput {
    let start_time = Utc::now();

    // Materials: keyed by path, first digest wins (initial state of inputs)
    let mut materials_map: HashMap<PathBuf, String> = HashMap::new();
    // Subjects: keyed by path, last digest wins (final state of outputs)
    let mut subjects_map: HashMap<PathBuf, String> = HashMap::new();
    let mut event_count: u64 = 0;
    let mut denial_count: u64 = 0;

    loop {
        match rx.recv().await {
            Ok(event) => {
                event_count += 1;
                if matches!(event.result, EventResult::Denied { .. }) {
                    denial_count += 1;
                }
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

    let materials = materials_map
        .into_iter()
        .map(|(path, sha256)| Material {
            uri: format!("file://{}", path.display()),
            digest: DigestSet { sha256 },
        })
        .collect();

    // Deduplicate atomic-write temp files: if `foo.rs.tmp.X.Y` exists
    // as a subject AND `foo.rs` also exists with the same digest, drop
    // the temp entry. This is safe because we require *both* the base
    // file to exist as a subject AND the digests to match — an attacker
    // can't hide writes by naming files with `.tmp.` in the name.
    let atomic_temps: Vec<PathBuf> = subjects_map
        .keys()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(base_end) = name.find(".tmp.") {
                let base_name = &name[..base_end];
                let base_path = p.with_file_name(base_name);
                // If the base file exists as a subject, the temp file is
                // definitionally an atomic-write artifact — drop it.
                // The base file's final digest is the meaningful output.
                subjects_map.contains_key(&base_path)
            } else {
                false
            }
        })
        .cloned()
        .collect();
    for tmp_path in &atomic_temps {
        subjects_map.remove(tmp_path);
    }

    // Drop ephemeral sandbox artifacts: files that no longer exist on disk
    // AND have no usable digest. These are files that only existed inside
    // the sandbox's private mount namespace (e.g., cargo build artifacts
    // in bwrap's tmpfs target dirs). We keep deleted files that had a real
    // digest — those represent meaningful deletions during the session.
    let ephemeral: Vec<PathBuf> = subjects_map
        .iter()
        .filter(|(path, digest)| !path.exists() && digest.as_str() == "unavailable")
        .map(|(path, _)| path.clone())
        .collect();
    for path in &ephemeral {
        debug!(path = %path.display(), "dropping ephemeral sandbox artifact from subjects");
        subjects_map.remove(path);
    }

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
        denial_count,
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
pub fn hash_file(path: &PathBuf) -> Option<String> {
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

        let output = run(rx).await;

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

        let output = run(rx).await;

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

        let output = run(rx).await;

        assert_eq!(output.subjects.len(), 1);
        assert_eq!(
            output.subjects[0].digest.sha256, "final",
            "last digest should win for subjects"
        );
    }

    #[tokio::test]
    async fn recorder_deduplicates_atomic_write_temp_files() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        // Simulate Claude Code's atomic write pattern:
        // writes to main.rs.tmp.2.1771347619103 then renames to main.rs
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs.tmp.2.1771347619103"),
            sha256_before: None,
            sha256_after: "abc123".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs"),
            sha256_before: Some("old".to_owned()),
            sha256_after: "abc123".to_owned(),
        }));

        drop(bus);
        let output = run(rx).await;

        assert_eq!(
            output.subjects.len(),
            1,
            "temp file should be deduplicated when base file has same digest"
        );
        assert_eq!(output.subjects[0].name, "/project/src/main.rs");
    }

    #[tokio::test]
    async fn recorder_deduplicates_temp_file_with_different_digest() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        // Temp file with different digest (intermediate edit) — still an
        // atomic-write artifact when the base file exists as a subject.
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs.tmp.2.999"),
            sha256_before: None,
            sha256_after: "intermediate_hash".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs"),
            sha256_before: None,
            sha256_after: "final_hash".to_owned(),
        }));

        drop(bus);
        let output = run(rx).await;

        assert_eq!(
            output.subjects.len(),
            1,
            "temp file should be dropped when base file exists"
        );
        assert_eq!(output.subjects[0].name, "/project/src/main.rs");
    }

    #[tokio::test]
    async fn recorder_keeps_temp_file_without_base() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        // Temp file with NO corresponding base file — must not be dropped
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/orphan.rs.tmp.2.999"),
            sha256_before: None,
            sha256_after: "abc123".to_owned(),
        }));

        drop(bus);
        let output = run(rx).await;

        assert_eq!(
            output.subjects.len(),
            1,
            "orphan temp file must be preserved as subject"
        );
    }

    #[tokio::test]
    async fn recorder_deduplicates_multiple_temp_files() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        // Two edits to the same file produce two temp files with different
        // intermediate digests — both should be dropped
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs.tmp.2.111"),
            sha256_before: None,
            sha256_after: "first_intermediate".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs.tmp.2.222"),
            sha256_before: None,
            sha256_after: "unavailable".to_owned(),
        }));
        bus.publish(make_event(EventKind::FileWrite {
            path: PathBuf::from("/project/src/main.rs"),
            sha256_before: None,
            sha256_after: "final_hash".to_owned(),
        }));

        drop(bus);
        let output = run(rx).await;

        assert_eq!(
            output.subjects.len(),
            1,
            "all temp files should be dropped when base exists"
        );
        assert_eq!(output.subjects[0].name, "/project/src/main.rs");
    }

    #[tokio::test]
    async fn recorder_zero_events() {
        let bus = EventBus::new();
        let rx = bus.subscribe();

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("audit.jsonl");
        std::fs::write(&log_path, "").expect("create log");

        drop(bus);

        let output = run(rx).await;

        assert_eq!(output.event_count, 0);
        assert!(output.materials.is_empty());
        assert!(output.subjects.is_empty());
    }
}
