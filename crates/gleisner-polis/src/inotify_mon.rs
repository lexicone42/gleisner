//! Filesystem monitor using inotify (via the `notify` crate).
//!
//! Uses recursive inotify watches to detect file writes, creates, and
//! deletes within the project directory. Requires no special capabilities.
//!
//! Also provides **before/after snapshot reconciliation**: hash every
//! file before the session starts, then diff after the session ends.
//! Any changes the real-time watcher missed are synthesized as events.
//! Combined with inotify, this provides stronger completeness guarantees
//! than mount-scoped monitors that rely solely on real-time events.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use chrono::Utc;
use notify::{EventKind as NotifyEventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};
use gleisner_scapes::stream::EventPublisher;

use crate::error::SandboxError;
use crate::monitor::{FsMonitorConfig, should_ignore};

/// Run the filesystem monitor using inotify until cancelled.
///
/// Creates a recursive watcher on the configured mount path and
/// publishes [`AuditEvent`]s for file writes, creates, and deletes.
///
/// Requires no special capabilities — works as any unprivileged user.
///
/// # Errors
///
/// Returns [`SandboxError::MonitorError`] if the watcher cannot be
/// created or the initial watch cannot be registered.
pub async fn run_fs_monitor(
    config: FsMonitorConfig,
    publisher: EventPublisher,
    cancel: CancellationToken,
) -> Result<(), SandboxError> {
    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(tx, notify::Config::default())
        .map_err(|e| SandboxError::MonitorError(format!("inotify watcher creation failed: {e}")))?;

    watcher
        .watch(&config.mount_path, RecursiveMode::Recursive)
        .map_err(|e| {
            SandboxError::MonitorError(format!(
                "inotify watch on {} failed: {e}",
                config.mount_path.display()
            ))
        })?;

    debug!(
        mount_path = %config.mount_path.display(),
        ignore_patterns = ?config.ignore_patterns,
        "inotify filesystem monitor started"
    );

    let ignore_patterns = config.ignore_patterns;

    // Run the blocking event loop in a dedicated thread.
    // The watcher must be moved into the thread to keep it alive.
    tokio::task::spawn_blocking(move || {
        monitor_loop(rx, &publisher, &cancel, &ignore_patterns);
        // Dropping `watcher` here stops the inotify watches.
        drop(watcher);
    })
    .await
    .map_err(|e| SandboxError::MonitorError(format!("inotify monitor task panicked: {e}")))?;

    Ok(())
}

/// The blocking event read loop.
fn monitor_loop(
    rx: mpsc::Receiver<Result<notify::Event, notify::Error>>,
    publisher: &EventPublisher,
    cancel: &CancellationToken,
    ignore_patterns: &[String],
) {
    loop {
        if cancel.is_cancelled() {
            debug!("inotify filesystem monitor cancelled");
            break;
        }

        // Use recv_timeout so we can check cancellation periodically.
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                process_event(&event, publisher, ignore_patterns);
            }
            Ok(Err(e)) => {
                warn!(error = %e, "inotify watch error");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No events — loop back to check cancellation.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                debug!("inotify watcher channel closed");
                break;
            }
        }
    }
}

/// Process a single notify event: filter, hash, publish.
fn process_event(event: &notify::Event, publisher: &EventPublisher, ignore_patterns: &[String]) {
    for path in &event.paths {
        if should_ignore(path, ignore_patterns) {
            trace!(path = %path.display(), "ignoring monitored path");
            continue;
        }

        match &event.kind {
            // File content was written and closed — this is our primary signal.
            NotifyEventKind::Access(notify::event::AccessKind::Close(
                notify::event::AccessMode::Write,
            )) => {
                publish_file_write(path, publisher);
            }

            // File was created — hash the new content.
            NotifyEventKind::Create(notify::event::CreateKind::File) => {
                publish_file_write(path, publisher);
            }

            // Content modification without close — debounce: log but don't
            // publish, since we'll capture the final state on close.
            NotifyEventKind::Modify(notify::event::ModifyKind::Data(_)) => {
                trace!(path = %path.display(), "file modified (awaiting close)");
            }

            // File was removed.
            NotifyEventKind::Remove(notify::event::RemoveKind::File) => {
                // We can't hash a deleted file, but record the event.
                let audit = AuditEvent {
                    timestamp: Utc::now(),
                    sequence: 0,
                    event: EventKind::FileDelete {
                        path: path.clone(),
                        sha256_before: "unavailable".to_owned(),
                    },
                    result: EventResult::Allowed,
                };
                publisher.publish(audit);
            }

            _ => {
                trace!(kind = ?event.kind, path = %path.display(), "unhandled event kind");
            }
        }
    }
}

/// Hash a file and publish a `FileWrite` event.
fn publish_file_write(path: &Path, publisher: &EventPublisher) {
    let sha256 = hash_file_at_path(path);
    let audit = AuditEvent {
        timestamp: Utc::now(),
        sequence: 0,
        event: EventKind::FileWrite {
            path: path.to_path_buf(),
            sha256_before: None,
            sha256_after: sha256,
        },
        result: EventResult::Allowed,
    };
    publisher.publish(audit);
}

// ── Before/after snapshot reconciliation ─────────────────────────────

/// A snapshot of file hashes in a directory tree.
///
/// Used for before/after comparison to detect any file changes that
/// the real-time inotify monitor might have missed.
pub type FileSnapshot = HashMap<PathBuf, String>;

/// Walk a directory tree and hash every file, respecting ignore patterns.
///
/// Returns a map from canonical file path to SHA-256 hex digest.
/// Symlinks are followed. Files that can't be read produce "unavailable".
pub fn snapshot_directory(root: &Path, ignore_patterns: &[String]) -> FileSnapshot {
    let mut snapshot = HashMap::new();
    walk_and_hash(root, root, ignore_patterns, &mut snapshot);
    snapshot
}

/// Recursive directory walker.
fn walk_and_hash(
    current: &Path,
    root: &Path,
    ignore_patterns: &[String],
    snapshot: &mut FileSnapshot,
) {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(e) => {
            trace!(path = %current.display(), error = %e, "cannot read directory");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if should_ignore(&path, ignore_patterns) {
            continue;
        }

        if path.is_dir() {
            walk_and_hash(&path, root, ignore_patterns, snapshot);
        } else if path.is_file() {
            let hash = hash_file_at_path(&path);
            snapshot.insert(path, hash);
        }
    }
}

/// Compare before and after snapshots, publishing events for changes
/// that the real-time monitor might have missed.
///
/// This is the reconciliation step: any file that changed between
/// snapshots but wasn't seen by inotify gets a synthetic event.
/// The `seen_paths` set contains paths already reported by the monitor.
pub fn reconcile_snapshots(
    before: &FileSnapshot,
    after: &FileSnapshot,
    seen_paths: &std::collections::HashSet<PathBuf>,
    publisher: &EventPublisher,
) -> ReconciliationStats {
    let mut stats = ReconciliationStats::default();

    // Files that were modified or created.
    for (path, after_hash) in after {
        if seen_paths.contains(path) {
            continue; // Already reported by real-time monitor.
        }

        match before.get(path) {
            Some(before_hash) if before_hash != after_hash => {
                // Modified but not seen by inotify.
                let audit = AuditEvent {
                    timestamp: Utc::now(),
                    sequence: 0,
                    event: EventKind::FileWrite {
                        path: path.clone(),
                        sha256_before: Some(before_hash.clone()),
                        sha256_after: after_hash.clone(),
                    },
                    result: EventResult::Allowed,
                };
                publisher.publish(audit);
                stats.missed_writes += 1;
            }
            None => {
                // New file not seen by inotify.
                let audit = AuditEvent {
                    timestamp: Utc::now(),
                    sequence: 0,
                    event: EventKind::FileWrite {
                        path: path.clone(),
                        sha256_before: None,
                        sha256_after: after_hash.clone(),
                    },
                    result: EventResult::Allowed,
                };
                publisher.publish(audit);
                stats.missed_creates += 1;
            }
            _ => {} // Hash unchanged or already seen.
        }
    }

    // Files that were deleted but not seen by inotify.
    for (path, before_hash) in before {
        if !after.contains_key(path) && !seen_paths.contains(path) {
            let audit = AuditEvent {
                timestamp: Utc::now(),
                sequence: 0,
                event: EventKind::FileDelete {
                    path: path.clone(),
                    sha256_before: before_hash.clone(),
                },
                result: EventResult::Allowed,
            };
            publisher.publish(audit);
            stats.missed_deletes += 1;
        }
    }

    if stats.total_missed() > 0 {
        warn!(
            missed_writes = stats.missed_writes,
            missed_creates = stats.missed_creates,
            missed_deletes = stats.missed_deletes,
            "snapshot reconciliation found events missed by real-time monitor"
        );
    } else {
        debug!("snapshot reconciliation: no missed events");
    }

    stats
}

/// Statistics from snapshot reconciliation.
#[derive(Debug, Default)]
pub struct ReconciliationStats {
    /// Files modified but not detected by inotify.
    pub missed_writes: usize,
    /// Files created but not detected by inotify.
    pub missed_creates: usize,
    /// Files deleted but not detected by inotify.
    pub missed_deletes: usize,
}

impl ReconciliationStats {
    /// Total missed events.
    pub const fn total_missed(&self) -> usize {
        self.missed_writes + self.missed_creates + self.missed_deletes
    }
}

// ── Hashing ──────────────────────────────────────────────────────────

/// Hash a file at a given path. Returns hex-encoded SHA-256.
fn hash_file_at_path(path: &Path) -> String {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            trace!(path = %path.display(), error = %e, "cannot open file for hashing");
            return String::from("unavailable");
        }
    };

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => {
                trace!(error = %e, "read error during hashing");
                return String::from("unavailable");
            }
        }
    }

    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_file_at_path_works_on_self() {
        let path = Path::new("/proc/self/exe");
        let hash = hash_file_at_path(path);
        assert_ne!(hash, "unavailable");
        assert_eq!(hash.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn hash_file_at_path_returns_unavailable_for_missing() {
        let hash = hash_file_at_path(Path::new("/nonexistent/file"));
        assert_eq!(hash, "unavailable");
    }

    #[test]
    fn snapshot_directory_captures_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = tmp.path().join("a.txt");
        let b = tmp.path().join("sub");
        std::fs::write(&a, "hello").expect("write a");
        std::fs::create_dir(&b).expect("mkdir sub");
        std::fs::write(b.join("b.txt"), "world").expect("write b");

        let snap = snapshot_directory(tmp.path(), &[]);
        assert_eq!(snap.len(), 2);
        assert!(snap.contains_key(&a));
        assert!(snap.contains_key(&b.join("b.txt")));

        // Hashes should be valid SHA-256 hex.
        for hash in snap.values() {
            assert_eq!(hash.len(), 64);
        }
    }

    #[test]
    fn snapshot_respects_ignore_patterns() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("keep.txt"), "keep").expect("write");
        let ignored = tmp.path().join("target");
        std::fs::create_dir(&ignored).expect("mkdir");
        std::fs::write(ignored.join("ignored.txt"), "ignore").expect("write");

        let snap = snapshot_directory(tmp.path(), &["target".to_owned()]);
        assert_eq!(snap.len(), 1);
        assert!(snap.contains_key(&tmp.path().join("keep.txt")));
    }

    #[test]
    fn reconcile_detects_missed_write() {
        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();

        let path = PathBuf::from("/project/changed.txt");
        let mut before = HashMap::new();
        before.insert(path.clone(), "aaa".to_owned());
        let mut after = HashMap::new();
        after.insert(path.clone(), "bbb".to_owned());

        let seen = std::collections::HashSet::new();
        let stats = reconcile_snapshots(&before, &after, &seen, &publisher);

        assert_eq!(stats.missed_writes, 1);
        assert_eq!(stats.missed_creates, 0);
        assert_eq!(stats.missed_deletes, 0);

        let event = rx.try_recv().expect("should receive event");
        match &event.event {
            EventKind::FileWrite {
                sha256_before,
                sha256_after,
                ..
            } => {
                assert_eq!(sha256_before.as_deref(), Some("aaa"));
                assert_eq!(sha256_after, "bbb");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_detects_missed_create() {
        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();

        let before = HashMap::new();
        let mut after = HashMap::new();
        after.insert(PathBuf::from("/project/new.txt"), "ccc".to_owned());

        let seen = std::collections::HashSet::new();
        let stats = reconcile_snapshots(&before, &after, &seen, &publisher);

        assert_eq!(stats.missed_creates, 1);

        let event = rx.try_recv().expect("should receive event");
        match &event.event {
            EventKind::FileWrite { sha256_before, .. } => {
                assert!(sha256_before.is_none());
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_detects_missed_delete() {
        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();

        let mut before = HashMap::new();
        before.insert(PathBuf::from("/project/gone.txt"), "ddd".to_owned());
        let after = HashMap::new();

        let seen = std::collections::HashSet::new();
        let stats = reconcile_snapshots(&before, &after, &seen, &publisher);

        assert_eq!(stats.missed_deletes, 1);

        let event = rx.try_recv().expect("should receive event");
        match &event.event {
            EventKind::FileDelete { sha256_before, .. } => {
                assert_eq!(sha256_before, "ddd");
            }
            other => panic!("expected FileDelete, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_skips_already_seen_paths() {
        let bus = gleisner_scapes::stream::EventBus::new();
        let publisher = bus.publisher();

        let path = PathBuf::from("/project/seen.txt");
        let mut before = HashMap::new();
        before.insert(path.clone(), "aaa".to_owned());
        let mut after = HashMap::new();
        after.insert(path.clone(), "bbb".to_owned());

        let mut seen = std::collections::HashSet::new();
        seen.insert(path);

        let stats = reconcile_snapshots(&before, &after, &seen, &publisher);
        assert_eq!(stats.total_missed(), 0);
    }

    #[tokio::test]
    async fn inotify_detects_file_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_file = tmp.path().join("test.txt");

        let config = FsMonitorConfig {
            mount_path: tmp.path().to_path_buf(),
            ignore_patterns: vec![],
        };

        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Start the monitor.
        let monitor =
            tokio::spawn(async move { run_fs_monitor(config, publisher, cancel_clone).await });

        // Give the watcher time to set up.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Write a file.
        std::fs::write(&test_file, "hello inotify").expect("write");

        // Give inotify time to deliver the event.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        cancel.cancel();
        let _ = monitor.await;

        // We should have received at least one FileWrite event.
        let mut found_write = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(&event.event, EventKind::FileWrite { path, .. } if path == &test_file) {
                found_write = true;
                break;
            }
        }
        assert!(found_write, "should have detected the file write");
    }
}
