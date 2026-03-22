//! SLSA v1.0-compatible provenance with Gleisner/Claude Code extensions.
//!
//! See: <https://slsa.dev/spec/v1.0/provenance>

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::statement::DigestSet;

/// SLSA v1.0-compatible provenance with Gleisner/Claude Code extensions.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GleisnerProvenance {
    /// Always [`GleisnerProvenance::BUILD_TYPE`].
    pub build_type: &'static str,
    /// Identifies the build system.
    pub builder: Builder,
    /// What triggered the build.
    pub invocation: Invocation,
    /// Timing and completeness metadata.
    pub metadata: BuildMetadata,
    /// Input materials (files read, dependencies).
    pub materials: Vec<Material>,

    /// SHA-256 digest of the full JSONL audit log.
    #[serde(rename = "gleisner:auditLogDigest")]
    pub audit_log_digest: String,

    /// Summary of the sandbox configuration used.
    #[serde(rename = "gleisner:sandboxProfile")]
    pub sandbox_profile: SandboxProfileSummary,

    /// Number of Landlock denial events observed during the session.
    #[serde(rename = "gleisner:denialCount")]
    pub denial_count: u64,

    /// Digest of the parent attestation's payload, linking sessions into a chain.
    #[serde(rename = "gleisner:chain", skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainMetadata>,
}

impl GleisnerProvenance {
    /// The Gleisner build type URI for Claude Code sessions.
    pub const BUILD_TYPE: &str = "https://gleisner.dev/claude-code/v1";
    /// The Gleisner build type URI for generic sandboxed builds.
    pub const BUILD_TYPE_GENERIC: &str = "https://gleisner.dev/build/v1";
}

/// Identifies the build system.
#[derive(Debug, Serialize)]
pub struct Builder {
    /// Builder identifier (e.g., `"gleisner-cli/0.1.0"`).
    pub id: String,
}

/// What triggered the build and in what environment.
#[derive(Debug, Serialize)]
pub struct Invocation {
    /// Invocation parameters.
    pub parameters: serde_json::Value,
    /// Build environment metadata.
    pub environment: BuildEnvironment,
}

/// Build environment metadata captured during a sandboxed run.
///
/// Tool-agnostic: works for Claude Code sessions, package builds,
/// CI steps, or any sandboxed process. Tool-specific fields (model,
/// API base URL, etc.) are optional and only populated when relevant.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildEnvironment {
    /// The primary tool or build system (e.g. `"claude-code"`, `"cargo"`, `"pnpm"`).
    pub tool: String,
    /// Tool version string (e.g. `"2.1.76 (Claude Code)"`, `"1.93.0"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    /// Whether the session ran inside a sandbox.
    pub sandboxed: bool,
    /// Name of the sandbox profile used.
    pub profile: String,
    /// Landlock enforcement level (e.g. `"FullyEnforced"`, `"BestEffort"`, `"Disabled"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landlock_enforcement: Option<String>,
    /// Seccomp-BPF preset applied (e.g. `"Nodejs"`, `"Custom"`, `"Disabled"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp_preset: Option<String>,
    /// Namespace isolation types active in the sandbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// AI model used (Claude Code sessions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// SHA-256 of the CLAUDE.md file, if present (Claude Code only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_md_hash: Option<String>,
    /// API base URL (Claude Code only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
}

/// Backwards-compatible alias.
pub type ClaudeCodeEnvironment = BuildEnvironment;

impl BuildEnvironment {
    /// Create a `BuildEnvironment` for a Claude Code session.
    pub fn claude_code(
        version: Option<String>,
        model: Option<String>,
        claude_md_hash: Option<String>,
        api_base_url: Option<String>,
        profile: String,
    ) -> Self {
        Self {
            tool: "claude-code".to_owned(),
            tool_version: version,
            sandboxed: true,
            profile,
            landlock_enforcement: None,
            seccomp_preset: None,
            namespaces: None,
            model,
            claude_md_hash,
            api_base_url,
        }
    }

    /// Create a `BuildEnvironment` for a generic build tool (cargo, pnpm, etc.).
    pub fn build_tool(tool: impl Into<String>, version: Option<String>, profile: String) -> Self {
        Self {
            tool: tool.into(),
            tool_version: version,
            sandboxed: true,
            profile,
            landlock_enforcement: None,
            seccomp_preset: None,
            namespaces: None,
            model: None,
            claude_md_hash: None,
            api_base_url: None,
        }
    }

    /// Create a `BuildEnvironment` from a minimal.toml task definition.
    ///
    /// The tool name comes from the task's exec command or the harness.
    pub fn from_minimal_task(
        tool: impl Into<String>,
        version: Option<String>,
        profile: String,
        sandboxed: bool,
    ) -> Self {
        Self {
            tool: tool.into(),
            tool_version: version,
            sandboxed,
            profile,
            landlock_enforcement: None,
            seccomp_preset: None,
            namespaces: None,
            model: None,
            claude_md_hash: None,
            api_base_url: None,
        }
    }

    /// Set the sandbox enforcement details.
    pub fn with_enforcement(
        mut self,
        landlock: impl Into<String>,
        seccomp: impl Into<String>,
        namespaces: Vec<String>,
    ) -> Self {
        self.landlock_enforcement = Some(landlock.into());
        self.seccomp_preset = Some(seccomp.into());
        self.namespaces = Some(namespaces);
        self
    }
}

/// Timing and completeness metadata.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMetadata {
    /// When the build started.
    pub build_started_on: DateTime<Utc>,
    /// When the build finished.
    pub build_finished_on: DateTime<Utc>,
    /// Which categories of information are captured.
    pub completeness: Completeness,
}

/// Which categories of information are captured.
#[derive(Debug, Serialize)]
pub struct Completeness {
    /// Whether invocation parameters are fully captured.
    pub parameters: bool,
    /// Whether the environment is fully captured.
    pub environment: bool,
    /// Whether all materials are captured.
    pub materials: bool,
}

/// A material (input) to the build.
#[derive(Debug, Serialize)]
pub struct Material {
    /// URI identifying the material.
    pub uri: String,
    /// Content digests.
    pub digest: DigestSet,
}

/// Summary of sandbox config for attestation records.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxProfileSummary {
    /// Profile name.
    pub name: String,
    /// SHA-256 of the profile TOML file.
    pub profile_digest: String,
    /// Network policy summary (e.g., "deny" or "allow").
    pub network_policy: String,
    /// Number of denied filesystem paths.
    pub filesystem_deny_count: usize,
}

/// Chain metadata linking this attestation to its predecessor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainMetadata {
    /// SHA-256 of the parent attestation bundle's `payload` field.
    pub parent_digest: String,
    /// Path to the parent attestation bundle (for discovery).
    pub parent_path: String,
}
