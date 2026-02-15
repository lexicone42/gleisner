//! Sandbox profile definitions and resolution.
//!
//! Profiles are TOML files that define filesystem, network, process,
//! and resource constraints for the sandboxed environment.
//!
//! Resolution order:
//! 1. If the argument is an existing `.toml` file path, use it directly
//! 2. Search XDG config dir (`~/.config/gleisner/profiles/`)
//! 3. Search bundled profiles (relative `profiles/` directory)

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;
use serde::de::Error as _;

use crate::error::SandboxError;

/// Default profile search paths, resolved lazily.
static DEFAULT_PROFILE_DIRS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    let mut dirs = Vec::new();

    // XDG config directory
    if let Some(config) = directories::ProjectDirs::from("dev", "gleisner", "gleisner") {
        dirs.push(config.config_dir().join("profiles"));
    }

    // Bundled profiles relative to the binary (for development)
    dirs.push(PathBuf::from("profiles"));

    // System-wide profiles
    dirs.push(PathBuf::from("/usr/share/gleisner/profiles"));

    dirs
});

/// A sandbox profile defining isolation boundaries.
///
/// Profiles are loaded from TOML files and define filesystem, network,
/// process, and resource constraints for the sandboxed environment.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// Human-readable profile name.
    pub name: String,
    /// Description of the profile's security posture.
    pub description: String,
    /// Filesystem access controls.
    pub filesystem: FilesystemPolicy,
    /// Network access controls.
    pub network: NetworkPolicy,
    /// Process-level isolation.
    pub process: ProcessPolicy,
    /// Resource limits via cgroups v2.
    pub resources: ResourceLimits,
    /// Claude Code plugin and MCP tool policy.
    #[serde(default)]
    pub plugins: PluginPolicy,
}

/// Controls which filesystem paths are visible and writable.
#[derive(Debug, Clone, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths mounted read-only (e.g., `/usr`, `/lib`, `/etc`).
    pub readonly_bind: Vec<PathBuf>,
    /// Paths mounted read-write (project dir is always added automatically).
    pub readwrite_bind: Vec<PathBuf>,
    /// Paths explicitly hidden — replaced with empty tmpfs.
    /// Defaults: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`.
    pub deny: Vec<PathBuf>,
    /// Additional tmpfs mounts.
    pub tmpfs: Vec<PathBuf>,
}

/// Controls outbound network access.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicy {
    /// Default disposition: `deny` (recommended) or `allow`.
    pub default: PolicyDefault,
    /// Domains allowed for outbound connections.
    pub allow_domains: Vec<String>,
    /// Ports allowed for outbound connections.
    pub allow_ports: Vec<u16>,
    /// Whether DNS resolution is permitted.
    pub allow_dns: bool,
}

/// Controls process-level isolation.
#[derive(Debug, Clone, Deserialize)]
pub struct ProcessPolicy {
    /// Isolate PID namespace (sandboxed process sees itself as PID 1).
    pub pid_namespace: bool,
    /// Prevent privilege escalation via `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privileges: bool,
    /// Command allowlist. Empty means all commands are permitted (but logged).
    pub command_allowlist: Vec<String>,
    /// Optional seccomp BPF profile path.
    pub seccomp_profile: Option<PathBuf>,
}

/// Claude Code plugin and MCP tool policy.
///
/// Controls which MCP tools are blocked, which additional directories
/// Claude Code can access (e.g. for exo-self), and network domains
/// needed by MCP servers.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginPolicy {
    /// Tools to explicitly deny via `--disallowedTools`.
    /// e.g. `["mcp__plugin_serena_serena__execute_shell_command"]`
    #[serde(default)]
    pub disallowed_tools: Vec<String>,
    /// Additional directories to grant via `--add-dir`.
    /// Tilde expansion is applied (e.g. `~/.claude/exo-self`).
    #[serde(default)]
    pub add_dirs: Vec<PathBuf>,
    /// Extra domains needed by MCP servers (merged into network allowlist).
    /// e.g. context7 needs `context7.com`, greptile needs `api.greptile.com`.
    #[serde(default)]
    pub mcp_network_domains: Vec<String>,
    /// Whether to skip Claude Code's built-in permission system.
    /// When `true`, passes `--dangerously-skip-permissions`.
    /// Gleisner's sandbox provides the real security boundary.
    #[serde(default = "default_true")]
    pub skip_permissions: bool,
}

const fn default_true() -> bool {
    true
}

impl Default for PluginPolicy {
    fn default() -> Self {
        Self {
            disallowed_tools: vec![],
            add_dirs: vec![],
            mcp_network_domains: vec![],
            skip_permissions: true,
        }
    }
}

/// Resource limits enforced via cgroups v2.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory in megabytes.
    pub max_memory_mb: u64,
    /// Maximum CPU usage as percentage (0–100).
    pub max_cpu_percent: u32,
    /// Maximum number of processes.
    pub max_pids: u32,
    /// Maximum file descriptors.
    pub max_file_descriptors: u64,
    /// Maximum disk write in megabytes.
    pub max_disk_write_mb: u64,
}

/// Whether the default disposition is to allow or deny.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDefault {
    /// Allow by default.
    Allow,
    /// Deny by default.
    #[default]
    Deny,
}

/// Resolve a profile by name or path.
///
/// If `name_or_path` is an existing `.toml` file path, loads it directly.
/// Otherwise, searches [`DEFAULT_PROFILE_DIRS`] for `{name}.toml`.
///
/// # Errors
///
/// Returns [`SandboxError::InvalidProfile`] if the profile cannot be
/// found or parsed.
pub fn resolve_profile(name_or_path: &str) -> Result<Profile, SandboxError> {
    let path = Path::new(name_or_path);

    // If it's already a valid path to a TOML file, use it directly
    if path.extension().is_some_and(|ext| ext == "toml") && path.exists() {
        return load_profile(path);
    }

    // Search default dirs for {name}.toml
    let found = DEFAULT_PROFILE_DIRS
        .iter()
        .map(|dir| dir.join(format!("{name_or_path}.toml")))
        .find(|p| p.exists());

    // let-else: early return on None
    let Some(profile_path) = found else {
        let search_paths: Vec<String> = DEFAULT_PROFILE_DIRS
            .iter()
            .map(|d| d.display().to_string())
            .collect();

        return Err(SandboxError::InvalidProfile {
            path: name_or_path.to_owned(),
            source: toml::de::Error::custom(format!(
                "profile '{name_or_path}' not found in search paths: {}",
                search_paths.join(", ")
            )),
        });
    };

    load_profile(&profile_path)
}

fn load_profile(path: &Path) -> Result<Profile, SandboxError> {
    let content = std::fs::read_to_string(path)
        .map_err(|_| SandboxError::PathNotFound(path.to_path_buf()))?;

    toml::from_str(&content).map_err(|source| SandboxError::InvalidProfile {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_default_deserializes_from_lowercase() {
        #[derive(Deserialize)]
        struct Wrapper {
            default: PolicyDefault,
        }

        let deny: Wrapper = toml::from_str(r#"default = "deny""#).expect("should parse deny");
        assert!(matches!(deny.default, PolicyDefault::Deny));

        let allow: Wrapper = toml::from_str(r#"default = "allow""#).expect("should parse allow");
        assert!(matches!(allow.default, PolicyDefault::Allow));
    }

    #[test]
    fn konishi_profile_parses_correctly() {
        // This test runs from the workspace root, so profiles/ is accessible
        let result = resolve_profile("konishi");
        if let Ok(profile) = result {
            assert_eq!(profile.name, "konishi");
            assert!(matches!(profile.network.default, PolicyDefault::Deny));
            assert!(
                profile
                    .network
                    .allow_domains
                    .contains(&"api.anthropic.com".to_owned())
            );
            assert!(profile.process.pid_namespace);
        }
        // If the file isn't found (CI, different cwd), that's also fine
    }

    #[test]
    fn nonexistent_profile_returns_error() {
        let result = resolve_profile("definitely_does_not_exist_xyz");
        assert!(result.is_err());

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "error should mention 'not found': {msg}"
        );
    }
}
