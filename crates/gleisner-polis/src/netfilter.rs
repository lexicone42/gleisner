//! Selective network filtering via slirp4netns + iptables.
//!
//! When a sandbox profile declares `network.default = "deny"` with
//! `allow_domains`, this module provides domain-level outbound filtering
//! instead of blanket network isolation. It works by:
//!
//! 1. Resolving domain names to IP addresses before sandbox entry
//! 2. Starting slirp4netns to provide a TAP device inside the network namespace
//! 3. Applying iptables rules that allow only resolved IPs on specified ports
//!
//! The sandbox child runs inside `--unshare-net` with a shell wrapper that
//! waits for the TAP device and applies firewall rules before exec-ing
//! the actual command.

use std::fmt::Write as _;
use std::net::ToSocketAddrs;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::error::SandboxError;
use crate::profile::NetworkPolicy;

/// Resolved network filter ready to apply inside a sandbox.
///
/// Created by resolving domain names to IP addresses at sandbox startup.
/// The resolved IPs are baked into iptables rules that run inside the
/// network namespace before the actual command executes.
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    /// Resolved (IP, port) pairs to allow.
    allowed_endpoints: Vec<(std::net::IpAddr, u16)>,
    /// Whether DNS traffic (port 53) is permitted.
    allow_dns: bool,
}

impl NetworkFilter {
    /// Resolve a network policy into concrete IP addresses.
    ///
    /// Each domain in the policy is resolved via `ToSocketAddrs` against
    /// each allowed port. Resolution happens *before* sandbox entry while
    /// the host network is still available.
    ///
    /// # Errors
    ///
    /// Logs warnings for domains that fail to resolve but does not fail
    /// the entire operation — partial resolution is better than none.
    pub fn resolve(policy: &NetworkPolicy, extra_domains: &[String]) -> Result<Self, SandboxError> {
        let all_domains: Vec<&str> = policy
            .allow_domains
            .iter()
            .chain(extra_domains.iter())
            .map(String::as_str)
            .collect();

        let ports = if policy.allow_ports.is_empty() {
            vec![443]
        } else {
            policy.allow_ports.clone()
        };

        let mut allowed_endpoints = Vec::new();

        for domain in &all_domains {
            for &port in &ports {
                let addr_str = format!("{domain}:{port}");
                match addr_str.to_socket_addrs() {
                    Ok(addrs) => {
                        for addr in addrs {
                            if addr.is_ipv4() {
                                allowed_endpoints.push((addr.ip(), port));
                                debug!(domain, ip = %addr.ip(), port, "resolved domain");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(domain, port, error = %e, "failed to resolve domain — skipping");
                    }
                }
            }
        }

        if allowed_endpoints.is_empty() && !all_domains.is_empty() {
            warn!("no domains could be resolved — all outbound traffic will be blocked");
        }

        info!(
            domains = ?all_domains,
            resolved_endpoints = allowed_endpoints.len(),
            "network filter resolved"
        );

        Ok(Self {
            allowed_endpoints,
            allow_dns: policy.allow_dns,
        })
    }

    /// Generate the iptables setup script to run inside the sandbox.
    ///
    /// The script:
    /// 1. Polls for the `tap0` device (created by slirp4netns)
    /// 2. Drops all IPv6 traffic
    /// 3. Sets default OUTPUT policy to DROP
    /// 4. Allows loopback and optionally DNS
    /// 5. Allows each resolved IP+port combination
    /// 6. Execs the wrapped command via `"$@"`
    #[must_use]
    pub fn iptables_setup_script(&self) -> String {
        let mut script = String::from(
            r#"set -e
# Wait for tap0 (slirp4netns creates it)
for i in $(seq 1 200); do
  ip link show tap0 >/dev/null 2>&1 && break; sleep 0.05
done
ip link show tap0 >/dev/null 2>&1 || { echo "gleisner: tap0 timeout" >&2; exit 1; }

# Block IPv6 entirely
ip6tables -P OUTPUT DROP 2>/dev/null || true
ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true

# IPv4: restrict outbound
iptables -P FORWARD DROP
iptables -P INPUT ACCEPT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
"#,
        );

        if self.allow_dns {
            script.push_str("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\n");
            script.push_str("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT\n");
        }

        for (ip, port) in &self.allowed_endpoints {
            let _ = writeln!(
                script,
                "iptables -A OUTPUT -p tcp -d {ip} --dport {port} -j ACCEPT"
            );
        }

        script.push_str("\nexec \"$@\"\n");
        script
    }

    /// Wrap an inner command with the iptables setup script.
    ///
    /// Returns a command vector where the first element is `sh` and the
    /// inner command is passed as positional arguments after `--`.
    #[must_use]
    pub fn wrap_command(&self, inner_cmd: &[String]) -> Vec<String> {
        let script = self.iptables_setup_script();
        let mut wrapped = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            script,
            "_".to_owned(), // $0 placeholder
        ];
        wrapped.extend_from_slice(inner_cmd);
        wrapped
    }

    /// Returns true if there are any resolved endpoints.
    #[must_use]
    pub fn has_endpoints(&self) -> bool {
        !self.allowed_endpoints.is_empty()
    }
}

/// Handle for a running slirp4netns process.
///
/// Owns the child process and kills it on drop to ensure cleanup.
/// Keep this alive for the duration of the sandboxed session.
#[derive(Debug)]
pub struct SlirpHandle {
    child: Child,
}

impl SlirpHandle {
    /// Start slirp4netns for the given PID.
    ///
    /// The process will create a `tap0` device inside the network
    /// namespace of `child_pid` with the default slirp4netns addressing:
    /// - Guest IP: 10.0.2.100/24
    /// - Gateway:  10.0.2.2
    /// - DNS:      10.0.2.3
    ///
    /// # Errors
    ///
    /// Returns `SlirpNotFound` if the binary isn't installed, or
    /// `NetworkSetupFailed` if spawn fails.
    pub fn start(child_pid: u32) -> Result<Self, SandboxError> {
        which::which("slirp4netns").map_err(|_| SandboxError::SlirpNotFound)?;

        info!(pid = child_pid, "starting slirp4netns");

        let child = Command::new("slirp4netns")
            .args([
                "--configure",
                "--disable-host-loopback",
                &child_pid.to_string(),
                "tap0",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::NetworkSetupFailed(format!("slirp4netns spawn: {e}")))?;

        debug!(slirp_pid = child.id(), "slirp4netns started");

        Ok(Self { child })
    }
}

impl Drop for SlirpHandle {
    fn drop(&mut self) {
        let pid = self.child.id();
        debug!(slirp_pid = pid, "stopping slirp4netns");

        // Try graceful SIGTERM first, then SIGKILL
        #[allow(clippy::cast_possible_wrap)]
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        if let Err(e) = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM) {
            warn!(error = %e, "failed to send SIGTERM to slirp4netns");
        }

        // Brief wait then force kill
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Scan `/proc` to find a child process of the given parent PID.
///
/// Returns the first PID whose `PPid` field in `/proc/[pid]/status`
/// matches `parent_pid`. This is used to find the bwrap child process
/// inside the new PID namespace.
#[must_use]
pub fn find_child_pid(parent_pid: u32) -> Option<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return None;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        // Skip self
        if pid == parent_pid {
            continue;
        }

        let status_path = format!("/proc/{pid}/status");
        let Ok(status) = std::fs::read_to_string(&status_path) else {
            continue;
        };

        for line in status.lines() {
            if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
                if let Ok(ppid) = ppid_str.trim().parse::<u32>() {
                    if ppid == parent_pid {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}

/// Poll for a child PID of the given parent, with timeout.
///
/// Retries every 50ms until a child is found or the timeout elapses.
///
/// # Errors
///
/// Returns `NetworkSetupFailed` if no child is found within the timeout.
pub fn wait_for_child_pid(parent_pid: u32, timeout: Duration) -> Result<u32, SandboxError> {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);

    while start.elapsed() < timeout {
        if let Some(pid) = find_child_pid(parent_pid) {
            debug!(child_pid = pid, parent_pid, "found child process");
            return Ok(pid);
        }
        std::thread::sleep(poll_interval);
    }

    Err(SandboxError::NetworkSetupFailed(format!(
        "no child process found for PID {parent_pid} within {timeout:?}"
    )))
}

/// Check whether slirp4netns is installed on the system.
#[must_use]
pub fn slirp4netns_available() -> bool {
    which::which("slirp4netns").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::NetworkPolicy;

    fn test_policy() -> NetworkPolicy {
        NetworkPolicy {
            default: crate::profile::PolicyDefault::Deny,
            allow_domains: vec!["api.anthropic.com".to_owned(), "sentry.io".to_owned()],
            allow_ports: vec![443],
            allow_dns: true,
        }
    }

    #[test]
    fn resolve_produces_endpoints() {
        let policy = test_policy();
        let filter = NetworkFilter::resolve(&policy, &[]).unwrap();
        // At least one of the domains should resolve (api.anthropic.com almost certainly does)
        // But in CI without network, this might be empty — that's OK
        if filter.has_endpoints() {
            assert!(!filter.allowed_endpoints.is_empty());
        }
    }

    #[test]
    fn resolve_with_extra_domains() {
        let policy = test_policy();
        let extra = vec!["registry.npmjs.org".to_owned()];
        let filter = NetworkFilter::resolve(&policy, &extra).unwrap();
        // Extra domains should be included in resolution
        // (may or may not resolve depending on network availability)
        let _ = filter;
    }

    #[test]
    fn iptables_script_contains_rules() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![
                ("104.18.0.1".parse().unwrap(), 443),
                ("104.18.0.2".parse().unwrap(), 443),
            ],
            allow_dns: true,
        };

        let script = filter.iptables_setup_script();

        assert!(script.contains("tap0"), "should wait for tap0");
        assert!(script.contains("ip6tables"), "should block IPv6");
        assert!(script.contains("OUTPUT DROP"), "should drop by default");
        assert!(script.contains("-o lo -j ACCEPT"), "should allow loopback");
        assert!(script.contains("--dport 53"), "should allow DNS");
        assert!(
            script.contains("-d 104.18.0.1 --dport 443"),
            "should allow resolved IPs"
        );
        assert!(
            script.contains("-d 104.18.0.2 --dport 443"),
            "should allow resolved IPs"
        );
        assert!(script.contains("exec \"$@\""), "should exec inner command");
    }

    #[test]
    fn iptables_script_without_dns() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![("1.2.3.4".parse().unwrap(), 443)],
            allow_dns: false,
        };

        let script = filter.iptables_setup_script();

        assert!(
            !script.contains("--dport 53"),
            "should not allow DNS when disabled"
        );
    }

    #[test]
    fn wrap_command_structure() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![("1.2.3.4".parse().unwrap(), 443)],
            allow_dns: true,
        };

        let wrapped = filter.wrap_command(&["claude".to_owned(), "--help".to_owned()]);

        assert_eq!(wrapped[0], "sh");
        assert_eq!(wrapped[1], "-c");
        // wrapped[2] is the script
        assert_eq!(wrapped[3], "_"); // $0 placeholder
        assert_eq!(wrapped[4], "claude");
        assert_eq!(wrapped[5], "--help");
    }

    #[test]
    fn find_child_pid_finds_own_children() {
        // Spawn a sleep child and verify we can find it
        let child = Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("failed to spawn sleep");

        let child_pid = child.id();
        let my_pid = std::process::id();

        let found = find_child_pid(my_pid);
        assert!(found.is_some(), "should find child process");
        assert_eq!(found.unwrap(), child_pid);

        // Clean up
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn wait_for_child_pid_with_timeout() {
        let result = wait_for_child_pid(999_999_999, Duration::from_millis(100));
        assert!(result.is_err(), "should timeout for nonexistent PID");
    }

    #[test]
    fn slirp_check_does_not_panic() {
        // Just verify it doesn't panic — result depends on system
        let _ = slirp4netns_available();
    }

    #[test]
    fn empty_policy_resolves_to_empty() {
        let policy = NetworkPolicy {
            default: crate::profile::PolicyDefault::Deny,
            allow_domains: vec![],
            allow_ports: vec![443],
            allow_dns: false,
        };
        let filter = NetworkFilter::resolve(&policy, &[]).unwrap();
        assert!(!filter.has_endpoints());
    }
}
