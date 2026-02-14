//! Filesystem monitor using Linux fanotify.
//!
//! Watches a mount point for file open, modify, and close-write events,
//! resolves paths via `/proc/self/fd/{fd}`, hashes file contents, and
//! publishes [`AuditEvent`]s to the event bus.
//!
//! Requires `CAP_SYS_ADMIN` (or root) to initialize fanotify.

use std::io::Read as _;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use chrono::Utc;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};
use gleisner_scapes::stream::EventPublisher;

use crate::error::SandboxError;
use crate::monitor::{FsMonitorConfig, should_ignore};

/// Run the filesystem monitor until cancelled.
///
/// Initializes fanotify, marks the configured mount path, and reads
/// events in a blocking loop (via `spawn_blocking`). Each relevant
/// event is published as an [`AuditEvent`].
///
/// # Errors
///
/// Returns [`SandboxError::MonitorError`] if fanotify initialization
/// or marking fails.
pub async fn run_fs_monitor(
    config: FsMonitorConfig,
    publisher: EventPublisher,
    cancel: CancellationToken,
) -> Result<(), SandboxError> {
    let fan = Fanotify::init(
        InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE,
    )
    .map_err(|e| SandboxError::MonitorError(format!("fanotify init failed: {e}")))?;

    fan.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
        MaskFlags::FAN_OPEN | MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_MODIFY,
        None,
        Some(&config.mount_path),
    )
    .map_err(|e| {
        SandboxError::MonitorError(format!(
            "fanotify mark on {} failed: {e}",
            config.mount_path.display()
        ))
    })?;

    debug!(
        mount_path = %config.mount_path.display(),
        ignore_patterns = ?config.ignore_patterns,
        "filesystem monitor started"
    );

    let ignore_patterns = config.ignore_patterns;

    tokio::task::spawn_blocking(move || {
        monitor_loop(&fan, &publisher, &cancel, &ignore_patterns);
    })
    .await
    .map_err(|e| SandboxError::MonitorError(format!("monitor task panicked: {e}")))?;

    Ok(())
}

/// The blocking event read loop.
fn monitor_loop(
    fan: &Fanotify,
    publisher: &EventPublisher,
    cancel: &CancellationToken,
    ignore_patterns: &[String],
) {
    loop {
        if cancel.is_cancelled() {
            debug!("filesystem monitor cancelled");
            break;
        }

        match fan.read_events() {
            Ok(events) => {
                for event in &events {
                    process_event(event, publisher, ignore_patterns);
                }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // Non-blocking mode: no events available
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                warn!(error = %e, "fanotify read error");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// Process a single fanotify event: resolve path, hash, publish.
fn process_event(
    event: &nix::sys::fanotify::FanotifyEvent,
    publisher: &EventPublisher,
    ignore_patterns: &[String],
) {
    let Some(fd) = event.fd() else {
        return;
    };

    // Resolve the file path from the fd via /proc/self/fd/
    let fd_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let Ok(resolved) = std::fs::read_link(&fd_path) else {
        trace!(fd = fd.as_raw_fd(), "could not resolve fd path");
        return;
    };

    if should_ignore(&resolved, ignore_patterns) {
        trace!(path = %resolved.display(), "ignoring monitored path");
        return;
    }

    let mask = event.mask();

    if mask.contains(MaskFlags::FAN_CLOSE_WRITE) {
        // File was written and closed — hash the final content
        let sha256 = hash_file_at_path(&resolved);
        let audit = AuditEvent {
            timestamp: Utc::now(),
            sequence: 0,
            event: EventKind::FileWrite {
                path: resolved,
                sha256_before: None,
                sha256_after: sha256,
            },
            result: EventResult::Allowed,
        };
        publisher.publish(audit);
    } else if mask.contains(MaskFlags::FAN_OPEN) {
        // File was opened for reading — hash via the fd
        let sha256 = hash_file_via_fd(fd.as_raw_fd());
        let audit = AuditEvent {
            timestamp: Utc::now(),
            sequence: 0,
            event: EventKind::FileRead {
                path: resolved,
                sha256,
            },
            result: EventResult::Allowed,
        };
        publisher.publish(audit);
    } else if mask.contains(MaskFlags::FAN_MODIFY) {
        // Modify events are frequent and noisy; just trace-log them
        trace!(path = %resolved.display(), "file modified (not publishing)");
    }
}

/// Hash a file by reading it via an already-open fd.
fn hash_file_via_fd(raw_fd: i32) -> String {
    // Read through /proc/self/fd/N to avoid consuming the original fd
    let fd_path = format!("/proc/self/fd/{raw_fd}");
    hash_file_at_path(&PathBuf::from(fd_path))
}

/// Hash a file at a given path. Returns hex-encoded SHA-256.
fn hash_file_at_path(path: &std::path::Path) -> String {
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
        // Use an absolute path that definitely exists
        let path = std::path::Path::new("/proc/self/exe");
        let hash = hash_file_at_path(path);
        assert_ne!(hash, "unavailable");
        assert_eq!(hash.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn hash_file_at_path_returns_unavailable_for_missing() {
        let hash = hash_file_at_path(std::path::Path::new("/nonexistent/file"));
        assert_eq!(hash, "unavailable");
    }

    #[tokio::test]
    async fn fanotify_init_requires_capability() {
        let config = FsMonitorConfig {
            mount_path: PathBuf::from("/tmp"),
            ignore_patterns: vec![],
        };
        let publisher = {
            let bus = gleisner_scapes::stream::EventBus::new();
            bus.publisher()
        };
        let cancel = CancellationToken::new();
        cancel.cancel(); // Cancel immediately so it doesn't block

        let result = run_fs_monitor(config, publisher, cancel).await;

        // Without CAP_SYS_ADMIN, fanotify_init fails with EPERM.
        // If running as root / with capabilities, it may succeed — that's fine.
        // We just verify the function doesn't panic.
        let _ = result;
    }
}
