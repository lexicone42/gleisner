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
    /// The Gleisner build type URI.
    pub const BUILD_TYPE: &str = "https://gleisner.dev/claude-code/v1";
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
    /// Claude Code environment metadata.
    pub environment: ClaudeCodeEnvironment,
}

/// Claude Code session metadata captured during the sandboxed run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeCodeEnvironment {
    /// Always `"claude-code"`.
    pub tool: &'static str,
    /// Claude Code CLI version.
    pub claude_code_version: Option<String>,
    /// Model used by the session.
    pub model: Option<String>,
    /// SHA-256 of the CLAUDE.md file, if present.
    pub claude_md_hash: Option<String>,
    /// SHA-256 of the initial conversation context.
    pub context_hash: Option<String>,
    /// Whether the session ran inside a Gleisner sandbox.
    pub sandboxed: bool,
    /// Name of the sandbox profile used.
    pub profile: String,
    /// Anthropic API base URL used.
    pub api_base_url: String,
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
