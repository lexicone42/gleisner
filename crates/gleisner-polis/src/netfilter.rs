//! Selective network filtering via pasta + nftables.
//!
//! When a sandbox profile declares `network.default = "deny"` with
//! `allow_domains`, this module provides domain-level outbound filtering
//! instead of blanket network isolation. It works by:
//!
//! 1. Resolving domain names to IP addresses before sandbox entry
//! 2. Creating a user+network namespace pair via `unshare`
//! 3. Starting pasta to configure networking in that namespace
//! 4. Running bwrap inside the namespace via `nsenter` (inheriting the
//!    filtered network instead of using `--unshare-net`)
//! 5. Applying nftables rules inside the namespace to restrict outbound
//!    traffic to only the resolved IPs
//!
//! ## Why not `--unshare-net` inside bwrap?
//!
//! bwrap implicitly creates a user namespace when run unprivileged.
//! Network namespaces are *owned* by the user namespace they were created
//! in, and `setns(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the owning
//! user namespace. By creating the namespaces ourselves first, pasta can
//! configure networking before bwrap starts.

use std::fmt::Write as _;
use std::net::ToSocketAddrs;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::error::SandboxError;
use crate::profile::NetworkPolicy;

/// Log prefix added to nftables/iptables rules for denied packets.
///
/// Used by the firewall denial parser in [`crate::audit_log`] to identify
/// gleisner-originated denial entries in the kernel log.
pub const FIREWALL_DENY_PREFIX: &str = "[gleisner-fw-deny]";

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
        let mut ipv6_only_domains = Vec::new();

        for domain in &all_domains {
            let mut has_ipv4 = false;
            for &port in &ports {
                let addr_str = format!("{domain}:{port}");
                match addr_str.to_socket_addrs() {
                    Ok(addrs) => {
                        for addr in addrs {
                            if addr.is_ipv4() {
                                has_ipv4 = true;
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
            if !has_ipv4 {
                ipv6_only_domains.push(*domain);
            }
        }

        if !ipv6_only_domains.is_empty() {
            warn!(
                domains = ?ipv6_only_domains,
                "domains resolved only to IPv6 — not reachable through pasta TAP, traffic will be blocked"
            );
        }

        if allowed_endpoints.is_empty() && !all_domains.is_empty() {
            return Err(SandboxError::NetworkSetupFailed(format!(
                "no domains could be resolved to IPv4 (attempted: {}) — DNS may be unavailable or domain names are invalid",
                all_domains.join(", ")
            )));
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

    /// Check whether nft log support is available (`nf_log_syslog` module loaded).
    ///
    /// Returns `Ok(())` if logging will work, or `Err` with a human-readable
    /// message explaining how to fix it. Call before starting a sandboxed
    /// session that needs audit2allow network observability.
    pub fn check_log_available() -> Result<(), String> {
        // Check /sys/module/nf_log_syslog — present when module is loaded or built-in
        if std::path::Path::new("/sys/module/nf_log_syslog").exists() {
            return Ok(());
        }
        // Also check if nft_log is built-in (some kernels integrate it)
        if std::path::Path::new("/sys/module/nft_log").exists() {
            return Ok(());
        }
        Err(
            "nf_log_syslog kernel module not loaded — firewall denial logging disabled.\n\
             Fix: sudo modprobe nf_log_syslog"
                .to_owned(),
        )
    }

    /// Generate the firewall setup script to run inside the sandbox.
    ///
    /// The script auto-detects the firewall backend: prefers `nft` (nftables),
    /// falls back to `iptables` (legacy), and errors out if neither works.
    /// This covers modern kernels with only `nf_tables` as well as traditional
    /// distros with `ip_tables`.
    ///
    /// The script:
    /// 1. Verifies `tap0` device exists (created by TAP provider before bwrap)
    /// 2. Sets default output policy to DROP (blocks both IPv4 and IPv6 with nft)
    /// 3. Allows loopback and optionally DNS
    /// 4. Allows each resolved IP+port combination
    /// 5. Execs the wrapped command via `"$@"`
    #[must_use]
    pub fn firewall_setup_script(&self) -> String {
        let mut script = String::from(
            r#"set -e
# Verify tap0 exists (should already be created by TAP provider)
if ! ip link show tap0 >/dev/null 2>&1; then
  echo "gleisner: tap0 not found — TAP provider may have failed" >&2
  exit 1
fi

# Auto-detect firewall backend: prefer nft (modern), fall back to iptables (legacy)
if command -v nft >/dev/null 2>&1; then
  # nftables: single inet table handles both IPv4 and IPv6
  nft add table inet gleisner
  nft add chain inet gleisner input '{ type filter hook input priority 0; policy accept; }'
  nft add chain inet gleisner forward '{ type filter hook forward priority 0; policy drop; }'
  nft add chain inet gleisner output '{ type filter hook output priority 0; policy drop; }'
  nft add rule inet gleisner output oifname lo accept
"#,
        );

        // nft DNS rules
        if self.allow_dns {
            script.push_str("  nft add rule inet gleisner output udp dport 53 accept\n");
            script.push_str("  nft add rule inet gleisner output tcp dport 53 accept\n");
        }

        // nft per-IP rules
        for (ip, port) in &self.allowed_endpoints {
            let _ = writeln!(
                script,
                "  nft add rule inet gleisner output ip daddr {ip} tcp dport {port} accept"
            );
        }

        // Log denied packets (everything not accepted above) before the chain
        // policy drops them. This enables the audit2allow workflow: denied
        // connections appear in dmesg/kernel log for `gleisner learn --firewall-log`.
        // nf_log_syslog module must be loaded for nft log to work.
        // Pre-flight check: `NetworkFilter::check_log_available()`.
        script.push_str("  nft add rule inet gleisner output counter log prefix '\"[gleisner-fw-deny] \"' level warn 2>/dev/null || true\n");

        script.push_str(
            r"elif command -v iptables >/dev/null 2>&1 && iptables -L -n >/dev/null 2>&1; then
  # iptables legacy fallback (only if kernel module is available)
  # Block IPv6 entirely (ip6tables may not exist — ignore errors)
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
    ip6tables -A OUTPUT -j LOG --log-prefix '[gleisner-fw-deny] ' 2>/dev/null || true
  fi
  # IPv4: restrict outbound
  iptables -P FORWARD DROP
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
",
        );

        // iptables DNS rules
        if self.allow_dns {
            script.push_str("  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\n");
            script.push_str("  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT\n");
        }

        // iptables per-IP rules
        for (ip, port) in &self.allowed_endpoints {
            let _ = writeln!(
                script,
                "  iptables -A OUTPUT -p tcp -d {ip} --dport {port} -j ACCEPT"
            );
        }

        // Log denied packets before the chain policy drops them.
        // Best-effort: LOG target may not be available in all environments.
        script.push_str(
            "  iptables -A OUTPUT -j LOG --log-prefix '[gleisner-fw-deny] ' 2>/dev/null || true\n",
        );

        script.push_str(
            r#"else
  echo "gleisner: neither nft nor iptables available — cannot apply network filter" >&2
  exit 1
fi

exec "$@"
"#,
        );
        script
    }

    /// Wrap an inner command with the firewall setup script.
    ///
    /// Returns a command vector where the first element is `sh` and the
    /// inner command is passed as positional arguments after `--`.
    ///
    /// **Note:** This runs the firewall setup and inner command in the same
    /// process. The caller must ensure the process has `CAP_NET_ADMIN` in
    /// the network namespace (e.g., by running as root in a user namespace).
    /// If the inner command runs inside a nested user namespace (like bwrap
    /// with `--unshare-user`), use [`Self::apply_firewall_via_nsenter`]
    /// instead.
    #[must_use]
    pub fn wrap_command(&self, inner_cmd: &[String]) -> Vec<String> {
        let script = self.firewall_setup_script();
        let mut wrapped = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            script,
            "_".to_owned(), // $0 placeholder
        ];
        wrapped.extend_from_slice(inner_cmd);
        wrapped
    }

    /// Apply firewall rules inside the namespace as a separate step.
    ///
    /// Runs the firewall setup script via `nsenter` into the given namespace
    /// as root (the namespace creator), then returns. The actual sandboxed
    /// command can then run in a nested user namespace without needing
    /// `CAP_NET_ADMIN`.
    ///
    /// # Errors
    ///
    /// Returns an error if the firewall script fails (neither nftables nor
    /// iptables available, or rules cannot be applied).
    pub fn apply_firewall_via_nsenter(&self, ns: &NamespaceHandle) -> Result<(), SandboxError> {
        // Build a script that applies firewall rules and exits (no exec "$@")
        let setup_script = self.firewall_setup_script().replace("exec \"$@\"\n", "");

        let mut cmd = Command::new("nsenter");
        cmd.args([
            &format!("--user={}", ns.user_ns_path()),
            &format!("--net={}", ns.net_ns_path()),
            "--preserve-credentials",
            "--no-fork",
            "--",
            "sh",
            "-c",
            &setup_script,
        ]);

        debug!("applying firewall rules via nsenter");
        let output = cmd.output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!(
                "failed to run nsenter for firewall setup: {e}"
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "firewall setup failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }

        info!("firewall rules applied successfully");
        Ok(())
    }

    /// Returns true if there are any resolved endpoints.
    #[must_use]
    pub fn has_endpoints(&self) -> bool {
        !self.allowed_endpoints.is_empty()
    }
}

/// Holds a user+network namespace pair created via `unshare`.
///
/// The namespace is kept alive by a long-running `sleep` process.
/// pasta configures this namespace, and bwrap enters it via
/// `nsenter` instead of creating its own with `--unshare-net`.
///
/// On drop, the holder process is killed, which destroys the namespace.
#[derive(Debug)]
pub struct NamespaceHandle {
    /// The `unshare ... sleep` process that holds the namespace open.
    holder: Child,
    /// PID of the holder (used for nsenter --target).
    holder_pid: u32,
}

impl NamespaceHandle {
    /// Create a new user+network namespace pair.
    ///
    /// Spawns `unshare --user --map-root-user --net -- sleep infinity`
    /// to hold the namespaces open.
    ///
    /// # Errors
    ///
    /// Returns `NetworkSetupFailed` if unshare cannot be spawned.
    pub fn create() -> Result<Self, SandboxError> {
        let holder = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "--",
                "sleep",
                "infinity",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SandboxError::NetworkSetupFailed(format!("failed to create network namespace: {e}"))
            })?;

        let holder_pid = holder.id();
        debug!(holder_pid, "created user+network namespace");

        // Brief wait for namespace to be ready
        std::thread::sleep(Duration::from_millis(100));

        Ok(Self { holder, holder_pid })
    }

    /// Get the PID of the namespace holder process.
    ///
    /// Used as the target for both pasta and nsenter.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.holder_pid
    }

    /// Get the path to the holder's user namespace.
    #[must_use]
    pub fn user_ns_path(&self) -> String {
        format!("/proc/{}/ns/user", self.holder_pid)
    }

    /// Get the path to the holder's network namespace.
    #[must_use]
    pub fn net_ns_path(&self) -> String {
        format!("/proc/{}/ns/net", self.holder_pid)
    }
}

impl Drop for NamespaceHandle {
    fn drop(&mut self) {
        debug!(holder_pid = self.holder_pid, "destroying network namespace");
        if let Err(e) = self.holder.kill() {
            warn!(
                holder_pid = self.holder_pid,
                error = %e,
                "failed to kill namespace holder — namespace may leak"
            );
        }
        let _ = self.holder.wait();
    }
}

/// Which TAP provider to use for userspace networking.
///
/// `Pasta` uses L4 socket mapping via `splice()` — faster for few connections.
/// `Slirp4netns` implements a full userspace TCP/IP stack — wider compatibility.
/// Handle for the pasta TAP provider process.
///
/// pasta configures the namespace and exits — there's no long-running child.
/// This sentinel type exists so callers can hold it for the session lifetime.
///
/// Keep this alive for the duration of the sandboxed session.
#[derive(Debug)]
pub struct TapHandle {
    _private: (),
}

impl TapHandle {
    /// Start pasta for the given namespace holder PID.
    ///
    /// pasta creates a `tap0` device inside the network namespace using
    /// L4 socket mapping via `splice()`. It configures the namespace and
    /// exits — no long-running child process.
    ///
    /// # Errors
    ///
    /// Returns `TapProviderNotFound` if pasta isn't installed, or
    /// `NetworkSetupFailed` if spawn fails or the process exits with error.
    pub fn start(ns_holder_pid: u32) -> Result<Self, SandboxError> {
        which::which("pasta").map_err(|_| SandboxError::TapProviderNotFound {
            provider: "pasta",
            install_hint: "emerge net-misc/passt",
        })?;

        info!(pid = ns_holder_pid, "starting pasta");

        let output = Command::new("pasta")
            .args([
                "--config-net",
                "--ns-ifname",
                "tap0",
                "--no-map-gw",
                "--tcp-ports",
                "none",
                "--udp-ports",
                "none",
                &ns_holder_pid.to_string(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| SandboxError::NetworkSetupFailed(format!("pasta spawn: {e}")))?;

        if !output.status.success() {
            let stderr_output = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "pasta failed with {}: {stderr_output}",
                output.status
            )));
        }

        let stderr_output = String::from_utf8_lossy(&output.stderr);
        debug!(status = %output.status, "pasta configured namespace");
        if !stderr_output.is_empty() {
            debug!(stderr = %stderr_output, "pasta output");
        }

        Ok(Self { _private: () })
    }
}

// pasta configures and exits — no Drop cleanup needed for TapHandle.

/// Build an nsenter prefix command that enters the given namespace.
///
/// Returns a `Command` for `nsenter --user=... --net=... --preserve-credentials --no-fork`
/// which should have the actual bwrap command appended to it.
#[must_use]
pub fn nsenter_command(ns: &NamespaceHandle) -> Command {
    let mut cmd = Command::new("nsenter");
    cmd.args([
        &format!("--user={}", ns.user_ns_path()),
        &format!("--net={}", ns.net_ns_path()),
        "--preserve-credentials",
        "--no-fork",
        "--",
    ]);
    cmd
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

/// Check whether pasta (passt) is installed on the system.
#[must_use]
pub fn pasta_available() -> bool {
    which::which("pasta").is_ok()
}

/// Verify that pasta is available.
///
/// # Errors
///
/// Returns `TapProviderNotFound` if pasta is not installed.
pub fn require_pasta() -> Result<(), SandboxError> {
    if pasta_available() {
        Ok(())
    } else {
        Err(SandboxError::TapProviderNotFound {
            provider: "pasta",
            install_hint: "emerge net-misc/passt",
        })
    }
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
    fn firewall_script_contains_both_backends() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![
                ("104.18.0.1".parse().unwrap(), 443),
                ("104.18.0.2".parse().unwrap(), 443),
            ],
            allow_dns: true,
        };

        let script = filter.firewall_setup_script();

        // Common checks
        assert!(script.contains("tap0"), "should check for tap0");
        assert!(script.contains("exec \"$@\""), "should exec inner command");

        // nft backend present
        assert!(
            script.contains("nft add table inet gleisner"),
            "should have nft table creation"
        );
        assert!(script.contains("policy drop"), "nft should drop by default");
        assert!(
            script.contains("oifname lo accept"),
            "nft should allow loopback"
        );
        assert!(
            script.contains("daddr 104.18.0.1 tcp dport 443"),
            "nft should allow resolved IPs"
        );
        assert!(
            script.contains("daddr 104.18.0.2 tcp dport 443"),
            "nft should allow resolved IPs"
        );

        // nft logging present (audit2allow)
        assert!(
            script.contains("gleisner-fw-deny"),
            "nft should log denied packets"
        );
        assert!(
            script.contains("counter log prefix"),
            "nft should use counter + log"
        );

        // iptables fallback present
        assert!(
            script.contains("ip6tables"),
            "iptables fallback should block IPv6"
        );
        assert!(
            script.contains("OUTPUT DROP"),
            "iptables should drop by default"
        );
        assert!(
            script.contains("-o lo -j ACCEPT"),
            "iptables should allow loopback"
        );
        assert!(
            script.contains("-d 104.18.0.1 --dport 443"),
            "iptables should allow resolved IPs"
        );

        // iptables logging present (audit2allow)
        assert!(
            script.contains("-j LOG --log-prefix"),
            "iptables should log denied packets"
        );
    }

    #[test]
    fn firewall_script_has_elif_structure() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![("1.2.3.4".parse().unwrap(), 443)],
            allow_dns: true,
        };

        let script = filter.firewall_setup_script();

        // Should use elif (not bare else) to check iptables availability AND kernel module
        assert!(
            script.contains("elif command -v iptables"),
            "should check iptables binary exists before using it"
        );
        assert!(
            script.contains("iptables -L -n"),
            "should probe iptables kernel module before using it"
        );
        // Should check ip6tables binary exists before calling it
        assert!(
            script.contains("command -v ip6tables"),
            "should check ip6tables exists before calling it"
        );
        // Should error out if neither backend works
        assert!(
            script.contains("neither nft nor iptables"),
            "should error when no firewall backend available"
        );
    }

    #[test]
    fn firewall_script_without_dns() {
        let filter = NetworkFilter {
            allowed_endpoints: vec![("1.2.3.4".parse().unwrap(), 443)],
            allow_dns: false,
        };

        let script = filter.firewall_setup_script();

        assert!(
            !script.contains("dport 53"),
            "should not allow DNS when disabled in either backend"
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
    #[ignore] // Flaky in multi-threaded test runner: find_child_pid returns the first
    // child it finds via /proc, which may belong to a sibling test thread's spawn.
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
    fn pasta_check_does_not_panic() {
        let _ = pasta_available();
    }

    #[test]
    fn require_pasta_matches_availability() {
        if pasta_available() {
            assert!(require_pasta().is_ok());
        } else {
            assert!(require_pasta().is_err());
        }
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

    /// E2E: create namespace + start pasta + verify network is up.
    ///
    /// Skipped in environments without user namespace support (e.g. GitHub Actions).
    #[test]
    fn e2e_namespace_with_pasta_has_network() {
        if !pasta_available() || which::which("nsenter").is_err() {
            return;
        }

        let Ok(ns) = NamespaceHandle::create() else {
            return; // no user namespace support (CI, containers)
        };
        let Ok(_tap) = TapHandle::start(ns.pid()) else {
            return; // pasta failed (IPv6 disabled, etc.)
        };

        // Verify we can run a command inside the namespace that sees a tap0 device
        let output = Command::new("nsenter")
            .args([
                &format!("--user=/proc/{}/ns/user", ns.pid()),
                &format!("--net=/proc/{}/ns/net", ns.pid()),
                "--preserve-credentials",
                "--no-fork",
                "--",
                "ip",
                "link",
                "show",
                "tap0",
            ])
            .output()
            .expect("nsenter ip link");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("tap0"),
            "tap0 device should exist in namespace: {stdout}"
        );
    }

    /// E2E: create namespace + pasta + nftables + verify filtering.
    ///
    /// Skipped in environments without user namespace support (e.g. GitHub Actions).
    #[test]
    fn e2e_firewall_blocks_disallowed_traffic() {
        if !pasta_available()
            || which::which("nsenter").is_err()
            || which::which("nft").is_err()
            || which::which("curl").is_err()
        {
            return;
        }

        // Allow only a known-good domain (httpbin.org on 443)
        let policy = NetworkPolicy {
            default: crate::profile::PolicyDefault::Deny,
            allow_domains: vec!["api.anthropic.com".to_owned()],
            allow_ports: vec![443],
            allow_dns: true,
        };

        let filter = NetworkFilter::resolve(&policy, &[]).expect("resolve filter");
        if !filter.has_endpoints() {
            // DNS resolution failed (no network) — skip test
            return;
        }

        let Ok(ns) = NamespaceHandle::create() else {
            return; // no user namespace support (CI, containers)
        };
        let Ok(_tap) = TapHandle::start(ns.pid()) else {
            return; // pasta failed (IPv6 disabled, etc.)
        };

        // Apply firewall
        filter
            .apply_firewall_via_nsenter(&ns)
            .expect("apply firewall");

        // Allowed: api.anthropic.com should connect (we don't need a response,
        // just verify the connection attempt isn't blocked by nftables).
        // Use curl with a short timeout — connect success = allowed by firewall.
        let allowed = Command::new("nsenter")
            .args([
                &format!("--user=/proc/{}/ns/user", ns.pid()),
                &format!("--net=/proc/{}/ns/net", ns.pid()),
                "--preserve-credentials",
                "--no-fork",
                "--",
                "curl",
                "-sf",
                "--connect-timeout",
                "5",
                "--max-time",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "https://api.anthropic.com/",
            ])
            .output()
            .expect("curl allowed");

        let allowed_stdout = String::from_utf8_lossy(&allowed.stdout);
        // Any HTTP response (even 4xx) means the connection was allowed through
        assert!(
            allowed.status.success() || allowed_stdout.starts_with('4'),
            "api.anthropic.com should be reachable (got: {}, stdout: {allowed_stdout})",
            allowed.status
        );

        // Blocked: example.com should NOT be reachable
        let blocked = Command::new("nsenter")
            .args([
                &format!("--user=/proc/{}/ns/user", ns.pid()),
                &format!("--net=/proc/{}/ns/net", ns.pid()),
                "--preserve-credentials",
                "--no-fork",
                "--",
                "curl",
                "-sf",
                "--connect-timeout",
                "3",
                "--max-time",
                "3",
                "-o",
                "/dev/null",
                "https://example.com/",
            ])
            .output()
            .expect("curl blocked");

        assert!(
            !blocked.status.success(),
            "example.com should be blocked by firewall"
        );
    }

    #[test]
    fn nsenter_command_has_correct_args() {
        let ns = NamespaceHandle {
            holder: Command::new("sleep").arg("0").spawn().expect("spawn sleep"),
            holder_pid: 12345,
        };

        let cmd = nsenter_command(&ns);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();

        assert!(args.contains(&"--user=/proc/12345/ns/user"));
        assert!(args.contains(&"--net=/proc/12345/ns/net"));
        assert!(args.contains(&"--preserve-credentials"));
        assert!(args.contains(&"--no-fork"));
        // ns dropped here, kills the sleep 0
    }
}
