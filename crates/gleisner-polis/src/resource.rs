//! cgroup v2 resource limit enforcement.
//!
//! Applies memory, CPU, PID, and I/O limits to the sandboxed
//! process via the cgroup v2 unified hierarchy.
//!
//! Discovers a writable cgroup base automatically:
//! 1. OpenRC/elogind: `/sys/fs/cgroup/openrc.user.{username}/`
//! 2. systemd: `/sys/fs/cgroup/user.slice/user-{uid}.slice/`
//! 3. Direct root: `/sys/fs/cgroup/` (requires root or delegation)
//!
//! Creates `gleisner-{uuid}/` under the first writable base and
//! removes it on drop.

use std::path::PathBuf;

use tracing::{debug, info, warn};

use crate::error::SandboxError;
use crate::profile::ResourceLimits;

/// The root of the cgroup v2 unified hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// A scoped cgroup that applies resource limits and cleans up on drop.
pub struct CgroupScope {
    cgroup_path: PathBuf,
}

impl CgroupScope {
    /// Create a new cgroup scope with the given resource limits.
    ///
    /// Discovers a writable cgroup base path automatically, then creates
    /// `gleisner-{uuid}/` under it and writes the appropriate control files.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::CgroupError`] if no writable cgroup base
    /// can be found or the cgroup cannot be configured.
    pub fn create(limits: &ResourceLimits) -> Result<Self, SandboxError> {
        let base = discover_cgroup_base()?;
        let id = simple_id();
        let cgroup_path = base.join(format!("gleisner-{id}"));

        std::fs::create_dir_all(&cgroup_path).map_err(|source| SandboxError::CgroupError {
            operation: format!("create directory {}", cgroup_path.display()),
            source,
        })?;

        debug!(cgroup = %cgroup_path.display(), "created cgroup directory");

        let scope = Self { cgroup_path };
        scope.write_limits(limits)?;

        Ok(scope)
    }

    /// Add a process to this cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::CgroupError`] if the PID cannot be written
    /// to `cgroup.procs`.
    pub fn add_pid(&self, pid: u32) -> Result<(), SandboxError> {
        let procs_path = self.cgroup_path.join("cgroup.procs");
        std::fs::write(&procs_path, pid.to_string()).map_err(|source| {
            SandboxError::CgroupError {
                operation: format!("add pid {pid} to {}", procs_path.display()),
                source,
            }
        })?;
        debug!(pid, cgroup = %self.cgroup_path.display(), "added process to cgroup");
        Ok(())
    }

    fn write_limits(&self, limits: &ResourceLimits) -> Result<(), SandboxError> {
        // memory.max: bytes
        if limits.max_memory_mb == 0 {
            warn!("max_memory_mb is 0 — skipping memory limit (no limit applied)");
        } else {
            let memory_bytes = limits.max_memory_mb * 1024 * 1024;
            self.write_control("memory.max", &memory_bytes.to_string())?;
        }

        // cpu.max: "quota period" where period is 100000us
        if limits.max_cpu_percent == 0 {
            warn!("max_cpu_percent is 0 — skipping CPU limit (no limit applied)");
        } else {
            let quota = u64::from(limits.max_cpu_percent) * 1000;
            self.write_control("cpu.max", &format!("{quota} 100000"))?;
        }

        // pids.max
        if limits.max_pids == 0 {
            warn!("max_pids is 0 — skipping PID limit (no limit applied)");
        } else {
            self.write_control("pids.max", &limits.max_pids.to_string())?;
        }

        // RLIMIT_NOFILE: enforced by BwrapSandbox::apply_rlimits() after spawn,
        // not via cgroup. Logged here for completeness.
        if limits.max_file_descriptors > 0 {
            debug!(
                max_fd = limits.max_file_descriptors,
                "file descriptor limit will be applied via prlimit after spawn"
            );
        }

        // Disk write limits are enforced via RLIMIT_FSIZE (per-file max size)
        // in apply_rlimits(). Cgroup io.max would provide total I/O throttling
        // but requires a major:minor block device identifier.
        if limits.max_disk_write_mb > 0 {
            debug!(
                max_disk_write_mb = limits.max_disk_write_mb,
                "disk write limit will be enforced via RLIMIT_FSIZE after spawn"
            );
        }

        debug!(
            memory_mb = limits.max_memory_mb,
            cpu_percent = limits.max_cpu_percent,
            max_pids = limits.max_pids,
            max_fd = limits.max_file_descriptors,
            max_disk_write_mb = limits.max_disk_write_mb,
            "configured cgroup resource limits"
        );

        Ok(())
    }

    /// Write a value to a cgroup control file.
    fn write_control(&self, filename: &str, value: &str) -> Result<(), SandboxError> {
        let path = self.cgroup_path.join(filename);
        std::fs::write(&path, value).map_err(|source| SandboxError::CgroupError {
            operation: format!("write {value} to {}", path.display()),
            source,
        })
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        // Move all processes out first (to parent cgroup) then remove dir
        let procs_path = self.cgroup_path.join("cgroup.procs");
        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            let parent_procs = self.cgroup_path.parent().map_or_else(
                || PathBuf::from("/sys/fs/cgroup/cgroup.procs"),
                |p| p.join("cgroup.procs"),
            );

            for pid in content.lines().filter(|l| !l.is_empty()) {
                if let Err(e) = std::fs::write(&parent_procs, pid) {
                    warn!(pid, error = %e, "failed to move process out of cgroup");
                }
            }
        }

        if let Err(e) = std::fs::remove_dir(&self.cgroup_path) {
            warn!(
                cgroup = %self.cgroup_path.display(),
                error = %e,
                "failed to remove cgroup directory"
            );
        } else {
            debug!(cgroup = %self.cgroup_path.display(), "removed cgroup directory");
        }
    }
}

/// Discover a writable cgroup v2 base directory.
///
/// Probes (in order):
/// 1. **Gleisner-dedicated**: `/sys/fs/cgroup/gleisner.{username}/`
///    (not managed by elogind, survives session changes)
/// 2. **OpenRC/elogind**: `/sys/fs/cgroup/openrc.user.{username}/`
///    (may be reset by elogind on session events)
/// 3. **systemd user slice**: `/sys/fs/cgroup/user.slice/user-{uid}.slice/`
/// 4. **Direct root**: `/sys/fs/cgroup/`
///
/// Returns the first path that exists and is writable by the current user.
fn discover_cgroup_base() -> Result<PathBuf, SandboxError> {
    let uid = nix::unistd::getuid();

    // Resolve username for cgroup path construction
    let username = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name);

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(ref name) = username {
        // 1. Gleisner-dedicated: not managed by elogind, stable across sessions
        candidates.push(PathBuf::from(CGROUP_ROOT).join(format!("gleisner.{name}")));

        // 2. OpenRC/elogind: may be reset by elogind on session events
        candidates.push(PathBuf::from(CGROUP_ROOT).join(format!("openrc.user.{name}")));
    }

    // 3. systemd user slice: /sys/fs/cgroup/user.slice/user-{uid}.slice/
    candidates.push(
        PathBuf::from(CGROUP_ROOT)
            .join("user.slice")
            .join(format!("user-{uid}.slice")),
    );

    // 4. Direct root (works if running as root or cgroup is delegated)
    candidates.push(PathBuf::from(CGROUP_ROOT));

    for candidate in &candidates {
        if candidate.is_dir() && is_writable(candidate) {
            info!(base = %candidate.display(), "discovered writable cgroup base");
            return Ok(candidate.clone());
        }
        debug!(path = %candidate.display(), "cgroup base candidate not writable — skipping");
    }

    Err(SandboxError::CgroupError {
        operation: "discover writable cgroup base".to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "no writable cgroup base found (tried: {}). \
                 Hint: run `sudo sh /tmp/gleisner-cgroup-fix.sh` \
                 to set up cgroup delegation",
                candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    })
}

/// Check if a path is writable by attempting to create and remove a probe directory.
fn is_writable(path: &std::path::Path) -> bool {
    let probe = path.join(".gleisner-probe");
    if std::fs::create_dir(&probe).is_ok() {
        let _ = std::fs::remove_dir(&probe);
        true
    } else {
        false
    }
}

/// Generate a short unique-ish identifier (timestamp + random suffix).
fn simple_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let rand: u32 = (ts as u32) ^ std::process::id();
    format!("{ts:x}-{rand:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits() -> ResourceLimits {
        ResourceLimits {
            max_memory_mb: 4096,
            max_cpu_percent: 100,
            max_pids: 256,
            max_file_descriptors: 1024,
            max_disk_write_mb: 10240,
        }
    }

    #[test]
    fn cgroup_scope_create_requires_privilege() {
        let limits = test_limits();
        let result = CgroupScope::create(&limits);

        // This will fail without root/cgroup permissions, which is expected
        if std::fs::metadata(CGROUP_ROOT).is_err() {
            assert!(result.is_err(), "should fail without cgroup filesystem");
        }
        // If /sys/fs/cgroup exists but isn't writable, also expect failure
        // If it somehow works (running as root), that's fine too
    }

    #[test]
    fn simple_id_is_nonempty() {
        let id = simple_id();
        assert!(!id.is_empty());
        assert!(id.contains('-'));
    }
}
