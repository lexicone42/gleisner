//! Async broadcast channel for event streaming.
//!
//! Provides a multi-consumer broadcast channel that distributes
//! audit events to the JSONL writer, session recorder, and optional
//! TUI viewer simultaneously.
//!
//! Built on [`tokio::sync::broadcast`] — each consumer gets an
//! independent receiver and processes events at its own pace.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::audit::{AuditEvent, JsonlWriter};
use crate::error::AuditError;

/// Default broadcast channel capacity.
///
/// 4096 events buffered should be more than enough for any session.
/// If a slow consumer falls behind, it will receive a `Lagged` error
/// and skip to the most recent event.
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

/// An event bus that distributes [`AuditEvent`]s to multiple consumers.
pub struct EventBus {
    sender: broadcast::Sender<AuditEvent>,
    sequence: Arc<AtomicU64>,
}

impl EventBus {
    /// Create a new event bus with the default channel capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new event bus with a custom channel capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe to the event stream.
    ///
    /// Returns a receiver that will get all events published after
    /// this call. Multiple receivers can be active simultaneously.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.sender.subscribe()
    }

    /// Create a cloneable publisher handle for use in background tasks.
    ///
    /// The publisher shares the same sequence counter and broadcast
    /// channel as this bus. Multiple publishers can coexist.
    #[must_use]
    pub fn publisher(&self) -> EventPublisher {
        EventPublisher {
            sender: self.sender.clone(),
            sequence: Arc::clone(&self.sequence),
        }
    }

    /// Publish an event to all subscribers.
    ///
    /// Automatically assigns the next sequence number. Returns the
    /// number of active receivers that received the event.
    pub fn publish(&self, mut event: AuditEvent) -> usize {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        event.sequence = seq;

        self.sender.send(event).map_or(0, |count| {
            debug!(sequence = seq, receivers = count, "event published");
            count
        })
    }

    /// Returns the number of events published so far.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }
}

/// A cloneable handle for publishing events to an [`EventBus`].
///
/// Created via [`EventBus::publisher`]. Safe to send into
/// `spawn_blocking` or other background tasks.
#[derive(Clone)]
pub struct EventPublisher {
    sender: broadcast::Sender<AuditEvent>,
    sequence: Arc<AtomicU64>,
}

impl EventPublisher {
    /// Publish an event to all subscribers.
    ///
    /// Automatically assigns the next sequence number. Returns the
    /// number of active receivers that received the event.
    pub fn publish(&self, mut event: AuditEvent) -> usize {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        event.sequence = seq;

        self.sender.send(event).map_or(0, |count| {
            debug!(sequence = seq, receivers = count, "event published");
            count
        })
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a background task that writes all events from a receiver
/// to a JSONL audit log file.
///
/// Returns a [`tokio::task::JoinHandle`] that resolves when the
/// receiver channel is closed (all senders dropped).
///
/// # Errors
///
/// Returns [`AuditError`] if the audit log file cannot be opened.
pub fn spawn_jsonl_writer(
    rx: broadcast::Receiver<AuditEvent>,
    log_path: &Path,
) -> Result<tokio::task::JoinHandle<()>, AuditError> {
    let mut writer = crate::audit::open_audit_log(log_path)?;

    let handle = tokio::spawn(async move {
        drain_to_writer(rx, &mut writer).await;
    });

    Ok(handle)
}

/// Drain events from a receiver into a JSONL writer until the channel closes.
async fn drain_to_writer<W: std::io::Write>(
    mut rx: broadcast::Receiver<AuditEvent>,
    writer: &mut JsonlWriter<W>,
) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Err(e) = writer.write_event(&event) {
                    warn!(error = %e, "failed to write audit event — continuing");
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    skipped = n,
                    "audit log consumer lagged — events were dropped"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("event channel closed — audit log writer shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{EventKind, EventResult};
    use chrono::Utc;
    use std::path::PathBuf;

    fn test_event(kind: EventKind) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            sequence: 0, // Will be overwritten by EventBus
            event: kind,
            result: EventResult::Allowed,
        }
    }

    #[test]
    fn event_bus_assigns_monotonic_sequences() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let event = test_event(EventKind::FileRead {
            path: PathBuf::from("/test"),
            sha256: "abc".to_owned(),
        });

        bus.publish(event.clone());
        bus.publish(event.clone());
        bus.publish(event);

        assert_eq!(bus.event_count(), 3);

        // Sequences should be 0, 1, 2
        let e0 = rx.try_recv().expect("should receive event 0");
        let e1 = rx.try_recv().expect("should receive event 1");
        let e2 = rx.try_recv().expect("should receive event 2");

        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
    }

    #[test]
    fn publish_with_no_receivers_returns_zero() {
        let bus = EventBus::new();
        // No subscribe() call — no receivers

        let count = bus.publish(test_event(EventKind::FileRead {
            path: PathBuf::from("/test"),
            sha256: "abc".to_owned(),
        }));

        assert_eq!(count, 0);
    }

    #[test]
    fn event_publisher_shares_sequence_with_bus() {
        let bus = EventBus::new();
        let publisher = bus.publisher();
        let mut rx = bus.subscribe();

        let event = test_event(EventKind::FileRead {
            path: PathBuf::from("/test"),
            sha256: "abc".to_owned(),
        });

        // Publish via bus, then via publisher — sequences should be contiguous
        bus.publish(event.clone());
        publisher.publish(event.clone());
        bus.publish(event);

        assert_eq!(bus.event_count(), 3);

        let e0 = rx.try_recv().expect("should receive event 0");
        let e1 = rx.try_recv().expect("should receive event 1");
        let e2 = rx.try_recv().expect("should receive event 2");

        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
    }

    #[test]
    fn cloned_publishers_share_sequence() {
        let bus = EventBus::new();
        let pub1 = bus.publisher();
        let pub2 = pub1.clone();
        let mut rx = bus.subscribe();

        let event = test_event(EventKind::FileRead {
            path: PathBuf::from("/test"),
            sha256: "abc".to_owned(),
        });

        pub1.publish(event.clone());
        pub2.publish(event);

        let e0 = rx.try_recv().expect("should receive event 0");
        let e1 = rx.try_recv().expect("should receive event 1");

        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
    }
}
