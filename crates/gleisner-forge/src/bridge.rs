//! Bridge from [`ComposedEnvironment`] to sandbox-compatible policy types.
//!
//! Converts forge's merged package declarations into filesystem and network
//! policy that gleisner-polis can enforce. This module intentionally avoids
//! depending on gleisner-polis directly — it produces plain data types that
//! the CLI/TUI wiring layer converts into `SandboxSpec` fields.

use std::path::{Path, PathBuf};

use crate::compose::{ComposedEnvironment, StateWiring};

/// Filesystem policy derived from package declarations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ForgeFilesystemPolicy {
    /// Directories to mount read-only.
    pub readonly_bind: Vec<PathBuf>,
    /// Directories to mount read-write.
    pub readwrite_bind: Vec<PathBuf>,
}

/// Network policy derived from package `needs` declarations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ForgeNetworkPolicy {
    /// Whether any package needs DNS resolution.
    pub allow_dns: bool,
    /// Whether any package needs full internet access.
    pub allow_internet: bool,
}

/// Validation warnings and errors from environment composition.
#[derive(Debug, Clone)]
pub struct BridgeReport {
    /// Filesystem policy for the sandbox.
    pub filesystem: ForgeFilesystemPolicy,
    /// Network policy for the sandbox.
    pub network: ForgeNetworkPolicy,
    /// State wirings: env var → prefix mappings for persistent cache directories.
    pub state_wirings: Vec<StateWiring>,
    /// Credential paths that packages declared (informational — NOT mounted).
    pub credential_paths: Vec<String>,
    /// Warnings from the composition (conflicts, degraded binds, etc.).
    pub warnings: Vec<String>,
}

/// Convert a `ComposedEnvironment` into sandbox-ready policy.
///
/// # Credential handling
///
/// Paths with `class == "Credential"` are **not** added to filesystem binds.
/// They are collected in `BridgeReport::credential_paths` for informational
/// purposes. The caller decides whether to expose them (e.g., via an
/// `--allow-credentials` flag).
///
/// # File mappings
///
/// Since sandbox bind-mounts operate at directory granularity, individual
/// file mappings are resolved to their parent directory. A warning is emitted
/// when this happens.
pub fn compose_to_policy(env: &ComposedEnvironment) -> BridgeReport {
    let mut fs = ForgeFilesystemPolicy::default();
    let mut credential_paths = Vec::new();
    let mut warnings = env.warnings.clone();

    // Process directory mappings
    for dir in &env.dir_mappings {
        let path = expand_tilde(&dir.path);

        if dir.class == "Credential" {
            credential_paths.push(dir.path.clone());
            continue;
        }

        add_bind_path(&mut fs, &path, dir.read_only);
    }

    // Process file mappings — degrade to parent directory
    for file in &env.file_mappings {
        let path = expand_tilde(&file.path);

        if file.class == "Credential" {
            credential_paths.push(file.path.clone());
            continue;
        }

        if let Some(parent) = path.parent().filter(|p| *p != Path::new("")) {
            warnings.push(format!(
                "file mapping '{}' degraded to parent directory '{}'",
                file.path,
                parent.display(),
            ));
            add_bind_path(&mut fs, &parent.to_path_buf(), file.read_only);
        } else {
            warnings.push(format!(
                "file mapping '{}' has no parent directory — skipped",
                file.path,
            ));
        }
    }

    let network = ForgeNetworkPolicy {
        allow_dns: env.needs.dns,
        allow_internet: env.needs.internet,
    };

    BridgeReport {
        filesystem: fs,
        network,
        state_wirings: env.state_wirings.clone(),
        credential_paths,
        warnings,
    }
}

/// Add a path to the appropriate bind list, avoiding duplicates and
/// resolving read-only vs read-write conflicts (RW wins).
fn add_bind_path(fs: &mut ForgeFilesystemPolicy, path: &PathBuf, read_only: bool) {
    // Check if already in RW list — if so, RW already wins
    if fs.readwrite_bind.contains(path) {
        return;
    }

    if read_only {
        // Check if already in RO list
        if !fs.readonly_bind.contains(path) {
            fs.readonly_bind.push(path.clone());
        }
    } else {
        // Remove from RO if present (upgrading to RW)
        fs.readonly_bind.retain(|p| p != path);
        fs.readwrite_bind.push(path.clone());
    }
}

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{ComposedEnvironment, DirMapping, FileMapping, MergedNeeds};

    fn env_with_dirs(dirs: Vec<DirMapping>) -> ComposedEnvironment {
        ComposedEnvironment {
            dir_mappings: dirs,
            file_mappings: Vec::new(),
            state_wirings: Vec::new(),
            needs: MergedNeeds::default(),
            packages: vec!["test".to_string()],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn credential_paths_excluded_from_binds() {
        let env = env_with_dirs(vec![
            DirMapping {
                read_only: false,
                path: "~/.config/app".to_string(),
                class: "State".to_string(),
            },
            DirMapping {
                read_only: true,
                path: "~/.ssh".to_string(),
                class: "Credential".to_string(),
            },
        ]);

        let report = compose_to_policy(&env);

        // State dir should be in RW binds
        assert_eq!(report.filesystem.readwrite_bind.len(), 1);
        // Credential dir should NOT be in any bind list
        assert!(report.filesystem.readonly_bind.is_empty());
        // But should be noted
        assert_eq!(report.credential_paths, vec!["~/.ssh"]);
    }

    #[test]
    fn file_mapping_degrades_to_parent() {
        let env = ComposedEnvironment {
            dir_mappings: Vec::new(),
            file_mappings: vec![FileMapping {
                read_only: true,
                path: "~/.claude.json".to_string(),
                class: "State".to_string(),
            }],
            state_wirings: Vec::new(),
            needs: MergedNeeds::default(),
            packages: vec!["test".to_string()],
            warnings: Vec::new(),
        };

        let report = compose_to_policy(&env);

        // Parent (~/) should be added as RO bind
        assert_eq!(report.filesystem.readonly_bind.len(), 1);
        // Warning about degradation
        assert!(report.warnings.iter().any(|w| w.contains("degraded")));
    }

    #[test]
    fn needs_map_to_network_policy() {
        let env = ComposedEnvironment {
            dir_mappings: Vec::new(),
            file_mappings: Vec::new(),
            state_wirings: Vec::new(),
            needs: MergedNeeds {
                dns: true,
                internet: false,
            },
            packages: vec!["test".to_string()],
            warnings: Vec::new(),
        };

        let report = compose_to_policy(&env);

        assert!(report.network.allow_dns);
        assert!(!report.network.allow_internet);
    }

    #[test]
    fn rw_wins_over_ro_conflict() {
        let _env = env_with_dirs(vec![
            DirMapping {
                read_only: true,
                path: "/data".to_string(),
                class: "State".to_string(),
            },
            DirMapping {
                read_only: false,
                path: "/data".to_string(),
                class: "State".to_string(),
            },
        ]);

        // Manually merge since ComposedEnvironment dedup happens in merge_package
        let mut composed = ComposedEnvironment::new();
        let j1 = serde_json::json!({
            "attrs": {"env_dir_mappings": [{"read_only": true, "path": "/data", "class": "State"}]}
        });
        let j2 = serde_json::json!({
            "attrs": {"env_dir_mappings": [{"read_only": false, "path": "/data", "class": "State"}]}
        });
        composed.merge_package("a", &j1);
        composed.merge_package("b", &j2);

        let report = compose_to_policy(&composed);

        // Should be in RW, not RO
        assert!(report.filesystem.readonly_bind.is_empty());
        assert_eq!(report.filesystem.readwrite_bind.len(), 1);
    }
}
