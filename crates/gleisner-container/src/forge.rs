//! Forge integration — auto-configure sandboxes from minimal.dev package compositions.
//!
//! When the `forge` feature is enabled, [`Sandbox`] can be configured directly
//! from a [`BridgeReport`] produced by the forge pipeline. This bridges package
//! metadata (what a package *needs*) into sandbox configuration (what to *allow*).

use std::path::{Path, PathBuf};

use gleisner_forge::bridge::BridgeReport;

use crate::builder::Sandbox;
use crate::error::ContainerError;
use crate::types::{NetworkMode, SeccompPreset};

/// A forge composition that can configure a [`Sandbox`].
///
/// Wraps a [`BridgeReport`] and project directory to provide a high-level
/// interface for creating sandboxes from package metadata.
pub struct ForgeComposition {
    report: BridgeReport,
    project_dir: PathBuf,
}

impl ForgeComposition {
    /// Create from a bridge report and project directory.
    pub fn new(report: BridgeReport, project_dir: impl Into<PathBuf>) -> Self {
        Self {
            report,
            project_dir: project_dir.into(),
        }
    }

    /// Configure a [`Sandbox`] from this forge composition.
    ///
    /// This applies:
    /// - Filesystem mounts (readonly + readwrite) from package declarations
    /// - Network policy (dns, internet, domain allowlist) from package `needs`
    /// - State directory provisioning from `env_state_wiring` declarations
    /// - Environment variables from harness detection
    ///
    /// The resulting sandbox is ready to run a process in the composed
    /// environment. The caller can further customize it before spawning.
    pub fn configure(&self, sandbox: &mut Sandbox) -> Result<(), ContainerError> {
        // Filesystem: readonly binds from package declarations
        for path in &self.report.filesystem.readonly_bind {
            sandbox.mount_readonly(path, path);
        }

        // Filesystem: readwrite binds
        for path in &self.report.filesystem.readwrite_bind {
            sandbox.mount_readwrite(path, path);
        }

        // State directories: provision and mount
        let state_root = self.project_dir.join(".gleisner/state");
        for wiring in &self.report.state_wirings {
            let state_dir = state_root.join(&wiring.prefix);
            std::fs::create_dir_all(&state_dir).map_err(|e| {
                ContainerError::Forge(format!(
                    "failed to create state dir for ${}: {e}",
                    wiring.env_var
                ))
            })?;
            sandbox.mount_readwrite(&state_dir, &state_dir);
            sandbox.env(&wiring.env_var, state_dir.display().to_string());
        }

        // Network: compose from package needs
        let network = if self.report.network.allow_internet {
            NetworkMode::Host
        } else if self.report.network.allow_dns || !self.report.network.allow_domains.is_empty() {
            NetworkMode::Isolated {
                allow_domains: self.report.network.allow_domains.clone(),
                allow_dns: self.report.network.allow_dns,
            }
        } else {
            NetworkMode::None
        };
        sandbox.network(network);

        // Environment variables from harness/bridge
        for (key, value) in &self.report.env.vars {
            sandbox.env(key, value);
        }

        // Seccomp: use Nodejs preset by default for Claude Code workloads
        sandbox.seccomp(SeccompPreset::Nodejs);

        Ok(())
    }

    /// Convenience: create a fully configured sandbox from this composition.
    pub fn sandbox(&self) -> Result<Sandbox, ContainerError> {
        let mut sb = Sandbox::new();
        // Standard namespaces for forge workloads
        sb.namespace(crate::types::Namespace::Pid)
            .namespace(crate::types::Namespace::Time)
            .namespace(crate::types::Namespace::Ipc)
            .work_dir(&self.project_dir);

        // Mount the project directory read-write
        sb.mount_readwrite(&self.project_dir, &self.project_dir);

        self.configure(&mut sb)?;
        Ok(sb)
    }

    /// The forge bridge report.
    pub fn report(&self) -> &BridgeReport {
        &self.report
    }

    /// The project directory.
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }
}
