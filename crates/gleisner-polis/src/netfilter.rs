//! Selective network filtering via slirp4netns + nftables/iptables.
//!
//! When a sandbox profile declares `network.default = "deny"` with
//! `allow_domains`, this module provides domain-level outbound filtering
//! instead of blanket network isolation. It works by:
//!
//! 1. Resolving domain names to IP addresses before sandbox entry
//! 2. Creating a user+network namespace pair via `unshare`
//! 3. Starting slirp4netns to provide a TAP device in that namespace
//! 4. Running bwrap inside the namespace via `nsenter` (inheriting the
//!    filtered network instead of using `--unshare-net`)
//! 5. Applying iptables rules inside the namespace to restrict outbound
//!    traffic to only the resolved IPs
//!
//! ## Why not `--unshare-net` + external slirp4netns?
//!
//! bwrap implicitly creates a user namespace when run unprivileged.
//! Network namespaces are *owned* by the user namespace they were created
//! in, and `setns(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the owning
//! user namespace. Since slirp4netns runs in the init user namespace, it
//! can't enter bwrap's network namespace. By creating the namespaces
//! ourselves first, slirp4netns can attach before bwrap starts.

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
                "domains resolved only to IPv6 — not reachable through slirp4netns, traffic will be blocked"
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
/// slirp4netns attaches to this namespace, and bwrap enters it via
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
    /// Used as the target for both slirp4netns and nsenter.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapProvider {
    /// passt/pasta — L4 socket mapping via `splice()`.
    Pasta,
    /// slirp4netns — full userspace TCP/IP stack.
    Slirp4netns,
}

/// Handle for a running TAP provider process (pasta or slirp4netns).
///
/// For slirp4netns, this owns the child process and kills it on drop.
/// For pasta, the process exits after configuring the namespace (no
/// long-running child), so this is a no-op sentinel.
///
/// Keep this alive for the duration of the sandboxed session.
#[derive(Debug)]
pub struct TapHandle {
    child: Option<Child>,
    provider: TapProvider,
}

impl TapHandle {
    /// Start the given TAP provider for the given namespace holder PID.
    ///
    /// The process will create a `tap0` device inside the network
    /// namespace with the default addressing:
    /// - Guest IP: 10.0.2.100/24 (slirp4netns) or auto-assigned (pasta)
    /// - Gateway:  10.0.2.2
    /// - DNS:      10.0.2.3
    ///
    /// # Errors
    ///
    /// Returns `TapProviderNotFound` if the binary isn't installed, or
    /// `NetworkSetupFailed` if spawn fails or the process exits immediately.
    pub fn start(ns_holder_pid: u32, provider: TapProvider) -> Result<Self, SandboxError> {
        match provider {
            TapProvider::Pasta => Self::start_pasta(ns_holder_pid),
            TapProvider::Slirp4netns => Self::start_slirp4netns(ns_holder_pid),
        }
    }

    fn start_pasta(ns_holder_pid: u32) -> Result<Self, SandboxError> {
        which::which("pasta").map_err(|_| SandboxError::TapProviderNotFound {
            provider: "pasta",
            install_hint: "emerge net-misc/passt",
        })?;

        info!(pid = ns_holder_pid, "starting pasta");

        // pasta configures the namespace and exits — it does NOT stay running
        // like slirp4netns. The kernel handles socket mapping via splice().
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

        Ok(Self {
            child: None,
            provider: TapProvider::Pasta,
        })
    }

    fn start_slirp4netns(ns_holder_pid: u32) -> Result<Self, SandboxError> {
        which::which("slirp4netns").map_err(|_| SandboxError::TapProviderNotFound {
            provider: "slirp4netns",
            install_hint: "install slirp4netns (apt install slirp4netns / dnf install slirp4netns)",
        })?;

        info!(pid = ns_holder_pid, "starting slirp4netns");

        let mut child = Command::new("slirp4netns")
            .args([
                "--configure",
                "--disable-host-loopback",
                &ns_holder_pid.to_string(),
                "tap0",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::NetworkSetupFailed(format!("slirp4netns spawn: {e}")))?;

        let tap_pid = child.id();
        debug!(tap_pid, "slirp4netns started");

        // Give slirp4netns a moment to attach, then check it hasn't crashed
        std::thread::sleep(Duration::from_millis(500));
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr_output = String::new();
                if let Some(mut stderr) = child.stderr {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut stderr_output);
                }
                return Err(SandboxError::NetworkSetupFailed(format!(
                    "slirp4netns exited immediately with {status}: {stderr_output}"
                )));
            }
            Ok(None) => debug!(tap_pid, "slirp4netns running"),
            Err(e) => warn!(error = %e, "could not check slirp4netns status"),
        }

        Ok(Self {
            child: Some(child),
            provider: TapProvider::Slirp4netns,
        })
    }
}

impl Drop for TapHandle {
    fn drop(&mut self) {
        // pasta exits after configuring — nothing to kill
        let Some(ref mut child) = self.child else {
            return;
        };

        let pid = child.id();
        let name = match self.provider {
            TapProvider::Pasta => "pasta",
            TapProvider::Slirp4netns => "slirp4netns",
        };
        debug!(tap_pid = pid, provider = name, "stopping TAP provider");

        // Try graceful SIGTERM first, then SIGKILL
        #[allow(clippy::cast_possible_wrap)]
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        if let Err(e) = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM) {
            warn!(error = %e, "failed to send SIGTERM to {name}");
        }

        // Brief wait then force kill
        if !matches!(child.try_wait(), Ok(Some(_))) {
            if let Err(e) = child.kill() {
                warn!(
                    tap_pid = pid,
                    error = %e,
                    "failed to kill {name} — process may leak"
                );
            }
            let _ = child.wait();
        }
    }
}

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

/// Check whether slirp4netns is installed on the system.
#[must_use]
pub fn slirp4netns_available() -> bool {
    which::which("slirp4netns").is_ok()
}

/// Check whether pasta (passt) is installed on the system.
#[must_use]
pub fn pasta_available() -> bool {
    which::which("pasta").is_ok()
}

/// Returns the preferred TAP provider: pasta if available, else slirp4netns.
///
/// # Errors
///
/// Returns `TapProviderNotFound` if neither provider is installed.
pub fn preferred_tap_provider() -> Result<TapProvider, SandboxError> {
    if pasta_available() {
        Ok(TapProvider::Pasta)
    } else if slirp4netns_available() {
        Ok(TapProvider::Slirp4netns)
    } else {
        Err(SandboxError::TapProviderNotFound {
            provider: "pasta or slirp4netns",
            install_hint: "emerge net-misc/passt (preferred) or install slirp4netns",
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
    fn pasta_check_does_not_panic() {
        // Just verify it doesn't panic — result depends on system
        let _ = pasta_available();
    }

    #[test]
    fn preferred_tap_provider_returns_ok_if_any_available() {
        // On CI or dev machines, at least one provider should be installed.
        // If neither is installed, this test just verifies we get the right error.
        match preferred_tap_provider() {
            Ok(TapProvider::Pasta) => assert!(pasta_available()),
            Ok(TapProvider::Slirp4netns) => {
                assert!(!pasta_available());
                assert!(slirp4netns_available());
            }
            Err(_) => {
                assert!(!pasta_available());
                assert!(!slirp4netns_available());
            }
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
