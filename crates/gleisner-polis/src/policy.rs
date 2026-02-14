//! Command, path, and network allowlists.
//!
//! Provides runtime policy checking against the profile's allowlists
//! and denylists. These functions **classify** events for the audit
//! trail (allowed vs. denied) — actual enforcement is handled by
//! bwrap's namespace isolation.

use std::path::Path;

use gleisner_scapes::audit::EventResult;

use crate::profile::{PolicyDefault, Profile};

/// The type of file access being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessType {
    /// File was opened for reading.
    Read,
    /// File was written or created.
    Write,
    /// File was deleted.
    Delete,
}

/// Evaluate whether a file access should be allowed by the profile.
///
/// Checks the path against the profile's filesystem policy:
/// - Paths under `deny` are always denied.
/// - Paths under `readonly_bind` deny writes/deletes.
/// - Paths under `readwrite_bind` allow all access.
pub fn evaluate_file_access(
    path: &Path,
    access_type: FileAccessType,
    profile: &Profile,
) -> EventResult {
    let fs = &profile.filesystem;

    // Check deny list first
    for denied in &fs.deny {
        if path.starts_with(denied) {
            return EventResult::Denied {
                reason: format!(
                    "path {} is under denied prefix {}",
                    path.display(),
                    denied.display()
                ),
            };
        }
    }

    // Writes/deletes to readonly paths are denied
    if matches!(access_type, FileAccessType::Write | FileAccessType::Delete) {
        for ro in &fs.readonly_bind {
            if path.starts_with(ro) {
                return EventResult::Denied {
                    reason: format!("{access_type:?} to read-only path {}", path.display()),
                };
            }
        }
    }

    EventResult::Allowed
}

/// Evaluate whether a process execution should be allowed.
///
/// If the profile has a non-empty command allowlist, the command
/// must match one of the allowed entries. An empty allowlist
/// permits all commands (but they are still logged).
pub fn evaluate_process_exec(command: &str, profile: &Profile) -> EventResult {
    let allowlist = &profile.process.command_allowlist;

    if allowlist.is_empty() {
        return EventResult::Allowed;
    }

    // Check if the command basename matches any allowlisted entry
    let basename = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    let allowed = allowlist.iter().any(|entry| {
        let entry_base = Path::new(entry.as_str())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(entry);
        entry_base == basename || entry == command
    });

    if allowed {
        EventResult::Allowed
    } else {
        EventResult::Denied {
            reason: format!("command `{command}` not in allowlist"),
        }
    }
}

/// Evaluate whether a network connection should be allowed.
///
/// Checks the target host and port against the profile's network policy.
pub fn evaluate_network(target: &str, port: u16, profile: &Profile) -> EventResult {
    let net = &profile.network;

    match net.default {
        PolicyDefault::Allow => {
            // In allow-by-default mode, everything is permitted
            EventResult::Allowed
        }
        PolicyDefault::Deny => {
            // Check domain allowlist
            let domain_allowed = net.allow_domains.iter().any(|d| d == target);
            let port_allowed = net.allow_ports.contains(&port);

            if domain_allowed && port_allowed {
                EventResult::Allowed
            } else if domain_allowed {
                EventResult::Denied {
                    reason: format!("port {port} not in allowed ports for {target}"),
                }
            } else {
                EventResult::Denied {
                    reason: format!("domain `{target}` not in allowlist"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{FilesystemPolicy, NetworkPolicy, ProcessPolicy, ResourceLimits};
    use std::path::PathBuf;

    fn test_profile() -> Profile {
        Profile {
            name: "test".to_owned(),
            description: "test profile".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                readwrite_bind: vec![PathBuf::from("/project")],
                deny: vec![PathBuf::from("/home/user/.ssh")],
                tmpfs: vec![],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![
                    "cargo".to_owned(),
                    "rustc".to_owned(),
                    "/usr/bin/git".to_owned(),
                ],
                seccomp_profile: None,
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
        }
    }

    #[test]
    fn file_access_denied_path() {
        let profile = test_profile();
        let result = evaluate_file_access(
            Path::new("/home/user/.ssh/id_rsa"),
            FileAccessType::Read,
            &profile,
        );
        assert!(matches!(result, EventResult::Denied { .. }));
    }

    #[test]
    fn file_access_readonly_write_denied() {
        let profile = test_profile();
        let result = evaluate_file_access(
            Path::new("/usr/lib/libc.so"),
            FileAccessType::Write,
            &profile,
        );
        assert!(matches!(result, EventResult::Denied { .. }));
    }

    #[test]
    fn file_access_readonly_read_allowed() {
        let profile = test_profile();
        let result = evaluate_file_access(
            Path::new("/usr/lib/libc.so"),
            FileAccessType::Read,
            &profile,
        );
        assert!(matches!(result, EventResult::Allowed));
    }

    #[test]
    fn process_exec_allowed_command() {
        let profile = test_profile();
        assert!(matches!(
            evaluate_process_exec("cargo", &profile),
            EventResult::Allowed
        ));
    }

    #[test]
    fn process_exec_allowed_full_path() {
        let profile = test_profile();
        assert!(matches!(
            evaluate_process_exec("/usr/bin/git", &profile),
            EventResult::Allowed
        ));
    }

    #[test]
    fn process_exec_denied_command() {
        let profile = test_profile();
        let result = evaluate_process_exec("curl", &profile);
        assert!(matches!(result, EventResult::Denied { .. }));
    }

    #[test]
    fn process_exec_empty_allowlist_allows_all() {
        let mut profile = test_profile();
        profile.process.command_allowlist.clear();
        assert!(matches!(
            evaluate_process_exec("anything", &profile),
            EventResult::Allowed
        ));
    }

    #[test]
    fn network_allowed_domain_and_port() {
        let profile = test_profile();
        let result = evaluate_network("api.anthropic.com", 443, &profile);
        assert!(matches!(result, EventResult::Allowed));
    }

    #[test]
    fn network_denied_domain() {
        let profile = test_profile();
        let result = evaluate_network("evil.example.com", 443, &profile);
        assert!(matches!(result, EventResult::Denied { .. }));
    }

    #[test]
    fn network_denied_port() {
        let profile = test_profile();
        let result = evaluate_network("api.anthropic.com", 80, &profile);
        assert!(matches!(result, EventResult::Denied { .. }));
    }

    #[test]
    fn network_allow_default_permits_all() {
        let mut profile = test_profile();
        profile.network.default = PolicyDefault::Allow;
        let result = evaluate_network("anything.example.com", 12345, &profile);
        assert!(matches!(result, EventResult::Allowed));
    }
}
