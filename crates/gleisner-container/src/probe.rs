//! Sandbox capability probing — detect what the kernel supports.
//!
//! Before creating a sandbox, probe the system to understand what
//! isolation layers are available. This enables graceful degradation
//! instead of hard failures on systems without full kernel support.
//!
//! ```no_run
//! use gleisner_container::probe::SandboxCapabilities;
//!
//! let caps = SandboxCapabilities::probe();
//! println!("{caps}");
//! // Kernel: 6.19.8-gentoo
//! // User namespaces: supported
//! // Landlock: V7 (ABI 7)
//! // Seccomp: supported
//! // Pasta: available at /usr/bin/pasta
//! ```

use std::fmt;
use std::path::PathBuf;

/// Detected sandbox capabilities of the current system.
#[derive(Debug, Clone)]
pub struct SandboxCapabilities {
    /// Kernel version string.
    pub kernel_version: String,
    /// Whether user namespaces are supported.
    pub user_namespaces: bool,
    /// Landlock ABI version (0 = not supported).
    pub landlock_abi: u32,
    /// Whether seccomp-BPF is available.
    pub seccomp: bool,
    /// Path to the pasta binary (None = not found).
    pub pasta_path: Option<PathBuf>,
    /// Path to the nft binary (None = not found).
    pub nft_path: Option<PathBuf>,
    /// Whether cgroup v2 is mounted and writable.
    pub cgroups_v2: bool,
    /// Path to gleisner-sandbox-init (None = not found).
    pub sandbox_init_path: Option<PathBuf>,
    /// Issues that will prevent full sandbox operation.
    pub blockers: Vec<String>,
    /// Non-blocking warnings (degraded features).
    pub warnings: Vec<String>,
}

impl SandboxCapabilities {
    /// Probe the current system for sandbox capabilities.
    pub fn probe() -> Self {
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();

        // Kernel version
        let kernel_version = std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|v| v.split_whitespace().nth(2).map(String::from))
            .unwrap_or_else(|| "unknown".to_owned());

        // User namespaces
        let user_namespaces = std::process::Command::new("unshare")
            .args(["--user", "true"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !user_namespaces {
            blockers.push("user namespaces not supported (required for sandbox)".to_owned());
        }

        // Landlock ABI version
        let landlock_abi = detect_landlock_abi();
        if landlock_abi == 0 {
            warnings.push("Landlock not available — filesystem access control disabled".to_owned());
        } else if landlock_abi < 7 {
            warnings.push(format!(
                "Landlock ABI {landlock_abi} (V7 recommended for full audit support)"
            ));
        }

        // Seccomp
        let seccomp = std::path::Path::new("/proc/sys/kernel/seccomp").exists()
            || std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .contains("Seccomp:");
        if !seccomp {
            warnings.push("seccomp not detected — syscall filtering unavailable".to_owned());
        }

        // Pasta
        let pasta_path = which::which("pasta").ok().or_else(|| {
            which::which("passt").ok() // alternative name
        });
        if pasta_path.is_none() {
            warnings.push("pasta/passt not found — network isolation unavailable".to_owned());
        }

        // nft
        let nft_path = which::which("nft").ok();
        if nft_path.is_none() && pasta_path.is_some() {
            warnings.push("nft not found — domain-level network filtering unavailable".to_owned());
        }

        // Cgroups v2
        let cgroups_v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        if !cgroups_v2 {
            warnings
                .push("cgroup v2 not mounted — resource limits via cgroups unavailable".to_owned());
        }

        // Sandbox init
        let sandbox_init_path = which::which("gleisner-sandbox-init").ok().or_else(|| {
            // Check sibling of current exe
            std::env::current_exe().ok().and_then(|exe| {
                let sibling = exe.with_file_name("gleisner-sandbox-init");
                sibling.is_file().then_some(sibling)
            })
        });
        if sandbox_init_path.is_none() {
            blockers.push(
                "gleisner-sandbox-init not found — build with: cargo build -p gleisner-sandbox-init"
                    .to_owned(),
            );
        }

        Self {
            kernel_version,
            user_namespaces,
            landlock_abi,
            seccomp,
            pasta_path,
            nft_path,
            cgroups_v2,
            sandbox_init_path,
            blockers,
            warnings,
        }
    }

    /// Whether the system can run sandboxes at all.
    pub fn can_sandbox(&self) -> bool {
        self.blockers.is_empty()
    }

    /// Whether the system supports the full security stack.
    pub fn full_security(&self) -> bool {
        self.can_sandbox()
            && self.landlock_abi >= 7
            && self.seccomp
            && self.pasta_path.is_some()
            && self.nft_path.is_some()
    }

    /// Summary string suitable for logging at startup.
    pub fn summary(&self) -> String {
        let status = if self.full_security() {
            "full security"
        } else if self.can_sandbox() {
            "degraded (see warnings)"
        } else {
            "CANNOT SANDBOX (see blockers)"
        };

        let mut parts = vec![format!("kernel={}, status={status}", self.kernel_version)];
        if self.landlock_abi > 0 {
            parts.push(format!("landlock=V{}", self.landlock_abi));
        }
        if self.seccomp {
            parts.push("seccomp=yes".to_owned());
        }
        if self.pasta_path.is_some() {
            parts.push("pasta=yes".to_owned());
        }
        parts.join(", ")
    }
}

impl fmt::Display for SandboxCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Kernel: {}", self.kernel_version)?;
        writeln!(
            f,
            "User namespaces: {}",
            if self.user_namespaces {
                "supported"
            } else {
                "NOT SUPPORTED"
            }
        )?;
        writeln!(
            f,
            "Landlock: {}",
            if self.landlock_abi > 0 {
                format!("V{} (ABI {})", self.landlock_abi, self.landlock_abi)
            } else {
                "not available".to_owned()
            }
        )?;
        writeln!(
            f,
            "Seccomp: {}",
            if self.seccomp {
                "supported"
            } else {
                "not detected"
            }
        )?;
        writeln!(
            f,
            "Pasta: {}",
            self.pasta_path
                .as_ref()
                .map_or("not found".to_owned(), |p| format!(
                    "available at {}",
                    p.display()
                ))
        )?;
        writeln!(
            f,
            "Cgroups v2: {}",
            if self.cgroups_v2 {
                "available"
            } else {
                "not mounted"
            }
        )?;

        if !self.blockers.is_empty() {
            writeln!(f, "\nBlockers:")?;
            for b in &self.blockers {
                writeln!(f, "  ✗ {b}")?;
            }
        }
        if !self.warnings.is_empty() {
            writeln!(f, "\nWarnings:")?;
            for w in &self.warnings {
                writeln!(f, "  ⚠ {w}")?;
            }
        }

        Ok(())
    }
}

/// Detect the Landlock ABI version via the kernel interface.
fn detect_landlock_abi() -> u32 {
    // Try sysfs first
    if let Ok(content) = std::fs::read_to_string("/sys/kernel/security/landlock/abi_version")
        && let Ok(v) = content.trim().parse()
    {
        return v;
    }
    // Check if Landlock is in the LSM stack (doesn't tell us version)
    if let Ok(lsm) = std::fs::read_to_string("/sys/kernel/security/lsm")
        && lsm.contains("landlock")
    {
        // Landlock is present but we can't determine version via sysfs.
        // The actual ABI is probed at sandbox creation time via
        // landlock_create_ruleset(LANDLOCK_CREATE_RULESET_VERSION).
        // Return 1 as a conservative minimum.
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_something() {
        let caps = SandboxCapabilities::probe();
        // Should at least detect the kernel version
        assert!(
            !caps.kernel_version.is_empty(),
            "should detect kernel version"
        );
        eprintln!("{caps}");
        eprintln!("Summary: {}", caps.summary());
    }

    #[test]
    fn display_is_readable() {
        let caps = SandboxCapabilities::probe();
        let text = caps.to_string();
        assert!(text.contains("Kernel:"), "should have kernel line: {text}");
        assert!(
            text.contains("Landlock:"),
            "should have landlock line: {text}"
        );
    }
}
