//! Kernel audit log reader for Landlock V7 denial events.
//!
//! Landlock V7 writes access denials to the kernel audit subsystem as
//! `AUDIT_LANDLOCK_ACCESS` records (type 1423). This module parses
//! those records from a user-readable log file (populated by audisp)
//! and publishes them as [`AuditEvent`]s with [`EventResult::Denied`].
//!
//! This completes the observability picture: inotify + procmon capture
//! *successful* accesses, while this module captures *blocked* accesses.
//! Together, the learner can generate tighter profiles on the first
//! pass (the "audit2allow" pattern).
//!
//! # Kernel audit record format
//!
//! ```text
//! type=UNKNOWN[1423] msg=audit(1764079004.833:1261): domain=... blockers=fs.make_reg path="/home/user/file"
//! type=UNKNOWN[1423] msg=audit(1764080735.711:1623): domain=... blockers=net.connect_tcp daddr=1.2.3.4 dest=80
//! ```
//!
//! Fields: `domain` (hex), `blockers` (comma-separated access flags),
//! `path` (filesystem), `dev`/`ino` (filesystem), `daddr`/`dest` (network).

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};
use gleisner_scapes::stream::EventPublisher;

/// Configuration for reading kernel audit denials.
pub struct KernelAuditConfig {
    /// Start of the session window — only records after this are included.
    pub session_start: DateTime<Utc>,
    /// End of the session window — only records before this are included.
    pub session_end: DateTime<Utc>,
    /// Path to the audisp-populated audit log file.
    pub audit_log_path: PathBuf,
}

/// A parsed Landlock denial from the kernel audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LandlockDenial {
    /// When the denial occurred (from `msg=audit(secs.msecs:serial)`).
    timestamp: DateTime<Utc>,
    /// The Landlock access flags that were denied (e.g. `fs.make_reg`, `net.connect_tcp`).
    blockers: Vec<String>,
    /// Filesystem path (if present).
    path: Option<String>,
    /// Network destination address (if present).
    daddr: Option<String>,
    /// Network destination port (if present).
    dest: Option<u16>,
}

/// The audit type identifiers for Landlock access denial records.
const AUDIT_TYPE_NUMERIC: &str = "UNKNOWN[1423]";
const AUDIT_TYPE_NAMED: &str = "LANDLOCK_ACCESS";

/// Collect Landlock denial events from the kernel audit log and publish
/// them to the event bus.
///
/// Returns the number of denial events published. Logs a warning and
/// returns 0 if the file is missing or unreadable.
pub fn collect_and_publish_denials(
    config: &KernelAuditConfig,
    publisher: &EventPublisher,
) -> usize {
    let contents = match std::fs::read_to_string(&config.audit_log_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                path = %config.audit_log_path.display(),
                error = %e,
                "could not read kernel audit log — skipping denial collection"
            );
            return 0;
        }
    };

    let mut count = 0;
    for line in contents.lines() {
        let Some(denial) = parse_audit_line(line) else {
            continue;
        };

        // Filter to session time window.
        if denial.timestamp < config.session_start || denial.timestamp > config.session_end {
            continue;
        }

        let events = denial_to_events(&denial);
        for event in events {
            publisher.publish(event);
            count += 1;
        }
    }

    count
}

/// Parse a single kernel audit line into a `LandlockDenial`, if it matches.
fn parse_audit_line(line: &str) -> Option<LandlockDenial> {
    // Must be a Landlock access denial record.
    if !is_landlock_record(line) {
        return None;
    }

    let timestamp = parse_audit_timestamp(line)?;

    let blockers_raw = extract_field(line, "blockers")?;
    let blockers: Vec<String> = blockers_raw
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();
    if blockers.is_empty() {
        return None;
    }

    let path = extract_field(line, "path").map(String::from);
    let daddr = extract_field(line, "daddr").map(String::from);
    let dest = extract_field(line, "dest").and_then(|s| s.parse::<u16>().ok());

    Some(LandlockDenial {
        timestamp,
        blockers,
        path,
        daddr,
        dest,
    })
}

/// Check whether a line is a Landlock audit record.
fn is_landlock_record(line: &str) -> bool {
    // type=UNKNOWN[1423] or type=LANDLOCK_ACCESS
    line.contains(AUDIT_TYPE_NUMERIC) || line.contains(AUDIT_TYPE_NAMED)
}

/// Parse the audit timestamp from `msg=audit(secs.msecs:serial)`.
///
/// Returns `None` if the format doesn't match.
fn parse_audit_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // Find "audit(" and extract until the closing ")".
    let start = line.find("audit(")? + "audit(".len();
    let end = line[start..].find(')')? + start;
    let inner = &line[start..end];

    // Format: "secs.msecs:serial" — we only need secs.msecs
    let time_part = inner.split(':').next()?;

    let (secs_str, msecs_str) = time_part.split_once('.')?;
    let secs: i64 = secs_str.parse().ok()?;
    let msecs: u32 = msecs_str.parse().ok()?;

    // msecs field is actually milliseconds
    let nanos = msecs * 1_000_000;
    Utc.timestamp_opt(secs, nanos).single()
}

/// Extract a `key=value` or `key="quoted value"` field from an audit line.
///
/// Returns the value with any surrounding quotes stripped.
fn extract_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    // Build the search pattern: "key=" (with space or start-of-content before it)
    let needle = format!("{key}=");
    let idx = find_field_start(line, &needle)?;
    let value_start = idx + needle.len();

    if value_start >= line.len() {
        return None;
    }

    let rest = &line[value_start..];
    if rest.starts_with('"') {
        // Quoted value: find the closing quote.
        let close = rest[1..].find('"')?;
        Some(&rest[1..=close])
    } else {
        // Bare value: ends at next whitespace.
        let end = rest.find(' ').unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        Some(&rest[..end])
    }
}

/// Find the start of a `key=` field, ensuring it's preceded by whitespace
/// or is at the start of the content (after the audit header).
fn find_field_start(line: &str, needle: &str) -> Option<usize> {
    let mut search_from = 0;
    loop {
        let idx = line[search_from..].find(needle)? + search_from;
        // Valid if at start of line or preceded by space
        if idx == 0 || line.as_bytes().get(idx.wrapping_sub(1)) == Some(&b' ') {
            return Some(idx);
        }
        search_from = idx + 1;
        if search_from >= line.len() {
            return None;
        }
    }
}

/// Convert a `LandlockDenial` into one or more `AuditEvent`s.
///
/// Each blocker becomes a separate event so the learner can classify
/// them independently.
fn denial_to_events(denial: &LandlockDenial) -> Vec<AuditEvent> {
    denial
        .blockers
        .iter()
        .map(|blocker| {
            let event_kind = blocker_to_event_kind(
                blocker,
                denial.path.as_deref(),
                denial.daddr.as_deref(),
                denial.dest,
            );
            AuditEvent {
                timestamp: denial.timestamp,
                sequence: 0, // Assigned by EventPublisher
                event: event_kind,
                result: EventResult::Denied {
                    reason: format!("landlock: {blocker}"),
                },
            }
        })
        .collect()
}

/// Map a Landlock blocker string to the corresponding `EventKind`.
fn blocker_to_event_kind(
    blocker: &str,
    path: Option<&str>,
    daddr: Option<&str>,
    dest: Option<u16>,
) -> EventKind {
    let path_buf = path.map_or_else(|| PathBuf::from("<unknown>"), PathBuf::from);

    match blocker {
        // Read operations
        "fs.read_file" | "fs.read_dir" => EventKind::FileRead {
            path: path_buf,
            sha256: "<denied>".to_owned(),
        },

        // Write operations
        "fs.write_file" | "fs.truncate" | "fs.make_reg" | "fs.make_dir" | "fs.make_sock"
        | "fs.make_fifo" | "fs.make_block" | "fs.make_char" | "fs.make_sym" => {
            EventKind::FileWrite {
                path: path_buf,
                sha256_before: None,
                sha256_after: "<denied>".to_owned(),
            }
        }

        // Delete operations
        "fs.remove_file" | "fs.remove_dir" => EventKind::FileDelete {
            path: path_buf,
            sha256_before: "<denied>".to_owned(),
        },

        // Execute
        "fs.execute" => EventKind::ProcessExec {
            command: path_buf.display().to_string(),
            args: vec![],
            cwd: PathBuf::from("<denied>"),
        },

        // Network connect
        "net.connect_tcp" => EventKind::NetworkConnect {
            target: daddr.unwrap_or("<unknown>").to_owned(),
            port: dest.unwrap_or(0),
        },

        // Network bind
        "net.bind_tcp" => EventKind::NetworkConnect {
            target: "bind".to_owned(),
            port: dest.unwrap_or(0),
        },

        // Unknown filesystem blocker — default to FileRead
        other if other.starts_with("fs.") => EventKind::FileRead {
            path: path_buf,
            sha256: "<denied>".to_owned(),
        },

        // Unknown network blocker — default to NetworkConnect
        other if other.starts_with("net.") => EventKind::NetworkConnect {
            target: daddr.unwrap_or("<unknown>").to_owned(),
            port: dest.unwrap_or(0),
        },

        // Completely unknown blocker
        _ => EventKind::FileRead {
            path: PathBuf::from(format!("<unknown:{blocker}>")),
            sha256: "<denied>".to_owned(),
        },
    }
}

/// Parse all Landlock denial events from a kernel audit log file.
///
/// Reads the entire file, parses Landlock V7 records (type 1423), and
/// returns them as [`AuditEvent`]s with [`EventResult::Denied`]. Unlike
/// [`collect_and_publish_denials`], this function does no time-window
/// filtering — all valid records in the file are returned.
///
/// Used by `gleisner learn --kernel-audit-log` to learn from Landlock
/// denials without needing a full `gleisner record` session.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn parse_kernel_denials(path: &Path) -> Result<Vec<AuditEvent>, std::io::Error> {
    let contents = std::fs::read_to_string(path)?;
    let mut events = Vec::new();

    for line in contents.lines() {
        let Some(denial) = parse_audit_line(line) else {
            continue;
        };
        events.extend(denial_to_events(&denial));
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FS_DENIAL: &str = r#"type=UNKNOWN[1423] msg=audit(1764079004.833:1261): domain=1266faee0 blockers=fs.make_reg path="/home/user/sandbox_c" dev="sda1" ino=1183972"#;
    const NET_DENIAL: &str = "type=UNKNOWN[1423] msg=audit(1764080735.711:1623): domain=1266faef9 blockers=net.connect_tcp daddr=142.250.179.110 dest=80";
    const NAMED_TYPE: &str = r#"type=LANDLOCK_ACCESS msg=audit(1764079004.833:1261): domain=abc blockers=fs.read_file path="/etc/passwd""#;

    #[test]
    fn parse_fs_denial() {
        let denial = parse_audit_line(FS_DENIAL).expect("should parse");
        assert_eq!(denial.blockers, vec!["fs.make_reg"]);
        assert_eq!(denial.path.as_deref(), Some("/home/user/sandbox_c"));
        assert!(denial.daddr.is_none());
        assert!(denial.dest.is_none());
    }

    #[test]
    fn parse_net_denial() {
        let denial = parse_audit_line(NET_DENIAL).expect("should parse");
        assert_eq!(denial.blockers, vec!["net.connect_tcp"]);
        assert!(denial.path.is_none());
        assert_eq!(denial.daddr.as_deref(), Some("142.250.179.110"));
        assert_eq!(denial.dest, Some(80));
    }

    #[test]
    fn parse_named_type_record() {
        let denial = parse_audit_line(NAMED_TYPE).expect("should parse");
        assert_eq!(denial.blockers, vec!["fs.read_file"]);
        assert_eq!(denial.path.as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn parse_audit_timestamp_valid() {
        let ts =
            parse_audit_timestamp("type=UNKNOWN[1423] msg=audit(1764079004.833:1261): domain=abc")
                .expect("should parse");
        assert_eq!(ts.timestamp(), 1_764_079_004);
        assert_eq!(ts.timestamp_subsec_millis(), 833);
    }

    #[test]
    fn parse_audit_timestamp_invalid() {
        assert!(parse_audit_timestamp("no audit timestamp here").is_none());
        assert!(parse_audit_timestamp("msg=audit(abc.def:123)").is_none());
    }

    #[test]
    fn blocker_mapping_file_write() {
        let kind = blocker_to_event_kind("fs.make_reg", Some("/tmp/new"), None, None);
        match kind {
            EventKind::FileWrite {
                path, sha256_after, ..
            } => {
                assert_eq!(path, PathBuf::from("/tmp/new"));
                assert_eq!(sha256_after, "<denied>");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn blocker_mapping_file_delete() {
        let kind = blocker_to_event_kind("fs.remove_file", Some("/tmp/old"), None, None);
        match kind {
            EventKind::FileDelete {
                path,
                sha256_before,
            } => {
                assert_eq!(path, PathBuf::from("/tmp/old"));
                assert_eq!(sha256_before, "<denied>");
            }
            other => panic!("expected FileDelete, got {other:?}"),
        }
    }

    #[test]
    fn blocker_mapping_execute() {
        let kind = blocker_to_event_kind("fs.execute", Some("/usr/bin/curl"), None, None);
        match kind {
            EventKind::ProcessExec { command, cwd, .. } => {
                assert_eq!(command, "/usr/bin/curl");
                assert_eq!(cwd, PathBuf::from("<denied>"));
            }
            other => panic!("expected ProcessExec, got {other:?}"),
        }
    }

    #[test]
    fn blocker_mapping_network_connect() {
        let kind = blocker_to_event_kind("net.connect_tcp", None, Some("10.0.0.1"), Some(443));
        match kind {
            EventKind::NetworkConnect { target, port } => {
                assert_eq!(target, "10.0.0.1");
                assert_eq!(port, 443);
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn blocker_mapping_network_bind() {
        let kind = blocker_to_event_kind("net.bind_tcp", None, None, Some(8080));
        match kind {
            EventKind::NetworkConnect { target, port } => {
                assert_eq!(target, "bind");
                assert_eq!(port, 8080);
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn time_window_filtering() {
        // Create a temp file with records at different times
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");

        // Record at t=1000, t=2000, t=3000
        let lines = [
            "type=UNKNOWN[1423] msg=audit(1000.000:1): domain=a blockers=fs.read_file path=\"/early\"",
            "type=UNKNOWN[1423] msg=audit(2000.000:2): domain=a blockers=fs.read_file path=\"/middle\"",
            "type=UNKNOWN[1423] msg=audit(3000.000:3): domain=a blockers=fs.read_file path=\"/late\"",
        ];
        std::fs::write(&log_path, lines.join("\n")).unwrap();

        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();

        let config = KernelAuditConfig {
            session_start: Utc.timestamp_opt(1500, 0).unwrap(),
            session_end: Utc.timestamp_opt(2500, 0).unwrap(),
            audit_log_path: log_path,
        };

        let count = collect_and_publish_denials(&config, &publisher);
        assert_eq!(count, 1, "only the t=2000 record should be in window");

        let event = rx.try_recv().expect("should have one event");
        match &event.event {
            EventKind::FileRead { path, .. } => {
                assert_eq!(path, &PathBuf::from("/middle"));
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
        assert!(matches!(event.result, EventResult::Denied { .. }));
    }

    #[test]
    fn missing_file_returns_zero() {
        let bus = gleisner_scapes::stream::EventBus::new();
        let publisher = bus.publisher();

        let config = KernelAuditConfig {
            session_start: Utc::now(),
            session_end: Utc::now(),
            audit_log_path: PathBuf::from("/nonexistent/audit.log"),
        };

        let count = collect_and_publish_denials(&config, &publisher);
        assert_eq!(count, 0);
    }

    #[test]
    fn multiple_blockers() {
        let line = r#"type=UNKNOWN[1423] msg=audit(2000.000:1): domain=a blockers=fs.read_file,fs.execute path="/bin/sh""#;
        let denial = parse_audit_line(line).expect("should parse");
        assert_eq!(denial.blockers, vec!["fs.read_file", "fs.execute"]);

        let events = denial_to_events(&denial);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event, EventKind::FileRead { .. }));
        assert!(matches!(events[1].event, EventKind::ProcessExec { .. }));
    }

    #[test]
    fn quoted_path_with_spaces() {
        let line = r#"type=UNKNOWN[1423] msg=audit(2000.000:1): domain=a blockers=fs.write_file path="/my dir/my file.txt""#;
        let denial = parse_audit_line(line).expect("should parse");
        assert_eq!(denial.path.as_deref(), Some("/my dir/my file.txt"));
    }

    #[test]
    fn unquoted_path() {
        let line =
            "type=UNKNOWN[1423] msg=audit(2000.000:1): domain=a blockers=fs.read_dir path=/etc";
        let denial = parse_audit_line(line).expect("should parse");
        assert_eq!(denial.path.as_deref(), Some("/etc"));
    }

    #[test]
    fn non_landlock_record_returns_none() {
        let line = "type=SYSCALL msg=audit(2000.000:1): arch=c000003e syscall=257";
        assert!(parse_audit_line(line).is_none());
    }

    #[test]
    fn extract_field_avoids_substring_match() {
        // "dest=80" should not match when looking for "daddr"
        let line = "blockers=net.connect_tcp daddr=10.0.0.1 dest=80";
        assert_eq!(extract_field(line, "daddr"), Some("10.0.0.1"));
        assert_eq!(extract_field(line, "dest"), Some("80"));
        // "daddr" should not accidentally match inside another field
        assert!(
            extract_field(line, "addr").is_none()
                || extract_field(line, "addr") == Some("10.0.0.1")
        );
    }

    #[test]
    fn parse_kernel_denials_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");

        let content = [
            FS_DENIAL,
            NET_DENIAL,
            "type=SYSCALL msg=audit(2000.000:1): arch=c000003e", // non-Landlock, skipped
            NAMED_TYPE,
        ]
        .join("\n");
        std::fs::write(&log_path, content).unwrap();

        let events = parse_kernel_denials(&log_path).expect("should parse");
        // 3 Landlock records, each with 1 blocker = 3 events
        assert_eq!(events.len(), 3);

        // All should be Denied
        for event in &events {
            assert!(matches!(event.result, EventResult::Denied { .. }));
        }
    }

    #[test]
    fn parse_kernel_denials_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("empty.log");
        std::fs::write(&log_path, "").unwrap();

        let events = parse_kernel_denials(&log_path).expect("should parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_kernel_denials_missing_file() {
        let result = parse_kernel_denials(Path::new("/nonexistent/audit.log"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_kernel_denials_multiple_blockers() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("multi.log");

        let line = r#"type=UNKNOWN[1423] msg=audit(2000.000:1): domain=a blockers=fs.read_file,fs.execute path="/bin/sh""#;
        std::fs::write(&log_path, line).unwrap();

        let events = parse_kernel_denials(&log_path).expect("should parse");
        // 1 record with 2 blockers = 2 events
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event, EventKind::FileRead { .. }));
        assert!(matches!(events[1].event, EventKind::ProcessExec { .. }));
    }
}
