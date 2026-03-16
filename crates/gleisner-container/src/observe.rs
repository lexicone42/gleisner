//! Audit log → [`ObservedCapabilities`] bridge.
//!
//! Reads a gleisner JSONL audit log and extracts what the sandboxed process
//! actually used at runtime, closing the feedback loop with
//! [`TaskSandbox::narrow()`](crate::task::TaskSandbox::narrow).
//!
//! ```ignore
//! use gleisner_container::observe::observe_from_audit_log;
//! use gleisner_container::task::{TaskSandbox, ObservedCapabilities};
//!
//! let observed = observe_from_audit_log(".gleisner/audit-20260316.jsonl")?;
//! let report = task.narrow(&observed);
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use gleisner_scapes::audit::{EventKind, open_audit_log_reader};

use crate::task::ObservedCapabilities;

/// Read a JSONL audit log and extract observed runtime capabilities.
///
/// Scans all events in the log and classifies them:
/// - `FileRead` / `FileWrite` → read/write paths
/// - `ProcessExec` → executed tool (basename of command)
/// - `NetworkConnect` → contacted domain (from target)
/// - `NetworkDns` → contacted domain (from query)
///
/// # Errors
///
/// Returns an error if the audit log file cannot be opened or parsed.
pub fn observe_from_audit_log(
    path: impl AsRef<Path>,
) -> Result<ObservedCapabilities, crate::error::ContainerError> {
    let mut reader = open_audit_log_reader(path.as_ref())
        .map_err(|e| crate::error::ContainerError::Config(format!("open audit log: {e}")))?;

    let mut read_paths = BTreeSet::new();
    let mut write_paths = BTreeSet::new();
    let mut contacted_domains = BTreeSet::new();
    let mut executed_tools = BTreeSet::new();

    while let Ok(Some(event)) = reader.next_event() {
        match event.event {
            EventKind::FileRead { ref path, .. } => {
                // Normalize to parent directory (we track dir-level access)
                if let Some(parent) = path.parent() {
                    read_paths.insert(parent.to_path_buf());
                }
            }
            EventKind::FileWrite { ref path, .. } => {
                if let Some(parent) = path.parent() {
                    write_paths.insert(parent.to_path_buf());
                }
            }
            EventKind::FileDelete { ref path, .. } => {
                if let Some(parent) = path.parent() {
                    write_paths.insert(parent.to_path_buf());
                }
            }
            EventKind::ProcessExec { ref command, .. } => {
                // Extract basename of the command
                let basename = Path::new(command)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(command);
                executed_tools.insert(basename.to_owned());
            }
            EventKind::NetworkConnect { ref target, .. } => {
                contacted_domains.insert(target.clone());
            }
            EventKind::NetworkDns { ref query, .. } => {
                contacted_domains.insert(query.clone());
            }
            EventKind::EnvRead { .. }
            | EventKind::ProcessExit { .. }
            | EventKind::Syscall { .. } => {}
        }
    }

    Ok(ObservedCapabilities {
        read_paths,
        write_paths,
        contacted_domains,
        executed_tools,
    })
}

/// Read multiple audit log files (e.g., from glob) and merge observations.
pub fn observe_from_audit_logs(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Result<ObservedCapabilities, crate::error::ContainerError> {
    let mut combined = ObservedCapabilities::default();
    for path in paths {
        let obs = observe_from_audit_log(path)?;
        combined.read_paths.extend(obs.read_paths);
        combined.write_paths.extend(obs.write_paths);
        combined.contacted_domains.extend(obs.contacted_domains);
        combined.executed_tools.extend(obs.executed_tools);
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use chrono::Utc;
    use gleisner_scapes::audit::{AuditEvent, EventResult, JsonlWriter};

    fn make_event(event: EventKind, result: EventResult) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            sequence: 0,
            event,
            result,
        }
    }

    fn write_test_log(events: &[AuditEvent]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = JsonlWriter::new(&mut buf);
        for event in events {
            writer.write_event(event).expect("write event");
        }
        buf
    }

    #[test]
    fn observe_classifies_events() {
        let events = vec![
            make_event(
                EventKind::FileRead {
                    path: PathBuf::from("/workspace/src/main.rs"),
                    sha256: "abc".to_owned(),
                },
                EventResult::Allowed,
            ),
            make_event(
                EventKind::FileWrite {
                    path: PathBuf::from("/workspace/target/debug/app"),
                    sha256_before: None,
                    sha256_after: "def".to_owned(),
                },
                EventResult::Allowed,
            ),
            make_event(
                EventKind::ProcessExec {
                    command: "/usr/bin/cargo".to_owned(),
                    args: vec!["build".to_owned()],
                    cwd: PathBuf::from("/workspace"),
                },
                EventResult::Allowed,
            ),
            make_event(
                EventKind::NetworkConnect {
                    target: "crates.io".to_owned(),
                    port: 443,
                },
                EventResult::Allowed,
            ),
            make_event(
                EventKind::NetworkDns {
                    query: "api.anthropic.com".to_owned(),
                    results: vec!["1.2.3.4".to_owned()],
                },
                EventResult::Allowed,
            ),
        ];

        let buf = write_test_log(&events);

        // Write to temp file for the reader
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &buf).unwrap();

        let observed = observe_from_audit_log(tmp.path()).unwrap();

        assert!(
            observed
                .read_paths
                .contains(&PathBuf::from("/workspace/src"))
        );
        assert!(
            observed
                .write_paths
                .contains(&PathBuf::from("/workspace/target/debug"))
        );
        assert!(observed.executed_tools.contains("cargo"));
        assert!(observed.contacted_domains.contains("crates.io"));
        assert!(observed.contacted_domains.contains("api.anthropic.com"));
    }

    #[test]
    fn observe_extracts_tool_basename() {
        let events = vec![make_event(
            EventKind::ProcessExec {
                command: "/home/user/.cargo/bin/cargo-clippy".to_owned(),
                args: vec![],
                cwd: PathBuf::from("/workspace"),
            },
            EventResult::Allowed,
        )];

        let buf = write_test_log(&events);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &buf).unwrap();

        let observed = observe_from_audit_log(tmp.path()).unwrap();
        assert!(
            observed.executed_tools.contains("cargo-clippy"),
            "should extract basename, got: {:?}",
            observed.executed_tools
        );
    }
}
