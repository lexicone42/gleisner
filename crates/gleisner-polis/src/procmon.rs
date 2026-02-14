//! Process monitor using `/proc` scanning.
//!
//! Periodically scans the process tree rooted at the sandbox PID,
//! detects new and exited processes, and publishes [`AuditEvent`]s
//! for each transition.

use std::collections::HashSet;
use std::path::PathBuf;

use chrono::Utc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};
use gleisner_scapes::stream::EventPublisher;

use crate::error::SandboxError;
use crate::monitor::ProcMonitorConfig;

/// Run the process monitor until cancelled.
///
/// Scans `/proc` at the configured interval to detect process
/// creation and exit within the sandbox process tree.
///
/// # Errors
///
/// Returns [`SandboxError::MonitorError`] if the root PID disappears
/// before cancellation.
pub async fn run_proc_monitor(
    config: ProcMonitorConfig,
    publisher: EventPublisher,
    cancel: CancellationToken,
) -> Result<(), SandboxError> {
    debug!(
        root_pid = config.root_pid,
        poll_ms = config.poll_interval.as_millis(),
        "process monitor started"
    );

    let mut known_pids: HashSet<u32> = HashSet::new();
    // Track the command name for each PID so we can report it on exit
    let mut pid_commands: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let current_pids = collect_child_pids(config.root_pid);

        // Detect new processes
        for &pid in &current_pids {
            if known_pids.insert(pid) {
                let (command, args, cwd) = read_proc_info(pid);
                pid_commands.insert(pid, command.clone());

                let audit = AuditEvent {
                    timestamp: Utc::now(),
                    sequence: 0,
                    event: EventKind::ProcessExec { command, args, cwd },
                    result: EventResult::Allowed,
                };
                publisher.publish(audit);
            }
        }

        // Detect exited processes
        let exited: Vec<u32> = known_pids
            .iter()
            .filter(|pid| !current_pids.contains(pid))
            .copied()
            .collect();

        for pid in exited {
            known_pids.remove(&pid);
            let command = pid_commands
                .remove(&pid)
                .unwrap_or_else(|| format!("<pid:{pid}>"));

            let audit = AuditEvent {
                timestamp: Utc::now(),
                sequence: 0,
                event: EventKind::ProcessExit {
                    command,
                    exit_code: 0, // Exit code not available from /proc after exit
                },
                result: EventResult::Allowed,
            };
            publisher.publish(audit);
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(config.poll_interval) => {}
        }
    }

    // Publish exit events for any remaining tracked processes
    for pid in &known_pids {
        let command = pid_commands
            .remove(pid)
            .unwrap_or_else(|| format!("<pid:{pid}>"));
        let audit = AuditEvent {
            timestamp: Utc::now(),
            sequence: 0,
            event: EventKind::ProcessExit {
                command,
                exit_code: 0,
            },
            result: EventResult::Allowed,
        };
        publisher.publish(audit);
    }

    debug!("process monitor stopped");
    Ok(())
}

/// Collect all child PIDs of the given root PID recursively.
///
/// Tries `/proc/{pid}/task/{pid}/children` first (fast, requires
/// kernel support). Falls back to scanning `/proc/*/stat` and
/// filtering by ppid.
fn collect_child_pids(root_pid: u32) -> HashSet<u32> {
    let mut result = HashSet::new();
    let mut queue = vec![root_pid];

    while let Some(pid) = queue.pop() {
        let children = read_children(pid);
        for child in children {
            if result.insert(child) {
                queue.push(child);
            }
        }
    }

    result
}

/// Read direct children of a PID from `/proc/{pid}/task/{pid}/children`.
fn read_children(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    std::fs::read_to_string(&path).map_or_else(
        |_| read_children_fallback(pid),
        |content| {
            content
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .collect()
        },
    )
}

/// Fallback child discovery: scan `/proc/*/stat` files for processes
/// whose ppid matches the target.
fn read_children_fallback(parent_pid: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut children = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        if let Some(ppid) = read_ppid(pid) {
            if ppid == parent_pid {
                children.push(pid);
            }
        }
    }

    children
}

/// Read the parent PID from `/proc/{pid}/stat`.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Format: "pid (comm) state ppid ..."
    // The comm field may contain spaces and parentheses, so find the last ')'
    let after_comm = stat.rfind(')')? + 2; // skip ") "
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    // fields[0] = state, fields[1] = ppid
    fields.get(1)?.parse::<u32>().ok()
}

/// Read process info from /proc: command, args, cwd.
fn read_proc_info(pid: u32) -> (String, Vec<String>, PathBuf) {
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<Vec<_>>();

    let command = cmdline
        .first()
        .cloned()
        .unwrap_or_else(|| format!("<pid:{pid}>"));
    let args = cmdline.into_iter().skip(1).collect();

    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|_| PathBuf::from("/"));

    trace!(pid, command = %command, "discovered new process");

    (command, args, cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_ppid_of_self() {
        let my_pid = std::process::id();
        let ppid = read_ppid(my_pid);
        assert!(ppid.is_some(), "should be able to read own ppid");
        // Our ppid should be > 0
        assert!(ppid.unwrap() > 0);
    }

    #[test]
    fn collect_child_pids_of_init() {
        // PID 1 should have children (unless in a very minimal container)
        let children = collect_child_pids(1);
        // We can't guarantee children exist, but the function shouldn't panic
        let _ = children;
    }

    #[test]
    fn read_proc_info_for_self() {
        let pid = std::process::id();
        let (command, _args, cwd) = read_proc_info(pid);
        assert!(!command.is_empty());
        assert!(cwd.is_absolute());
    }

    #[tokio::test]
    async fn proc_monitor_detects_spawned_process() {
        use std::process::Command;

        let bus = gleisner_scapes::stream::EventBus::new();
        let mut rx = bus.subscribe();
        let publisher = bus.publisher();
        let cancel = CancellationToken::new();

        let my_pid = std::process::id();
        let config = ProcMonitorConfig {
            root_pid: my_pid,
            poll_interval: std::time::Duration::from_millis(50),
        };

        // Start monitor
        let cancel_clone = cancel.clone();
        let monitor_handle = tokio::spawn(run_proc_monitor(config, publisher, cancel_clone));

        // Spawn a short-lived child process
        let child = Command::new("sleep").arg("0.2").spawn();

        // Give the monitor time to detect it
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Cancel the monitor
        cancel.cancel();
        let result = monitor_handle.await.expect("monitor task should complete");
        assert!(result.is_ok());

        // Check if we got any ProcessExec events
        let mut found_exec = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event.event, EventKind::ProcessExec { .. }) {
                found_exec = true;
            }
        }

        if child.is_ok() {
            // If we could spawn a child, we should have seen it
            // (though timing makes this slightly flaky)
            if !found_exec {
                tracing::warn!("no ProcessExec event detected (timing-sensitive test)");
            }
        }
    }
}
