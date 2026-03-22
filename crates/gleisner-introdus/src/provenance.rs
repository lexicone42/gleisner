//! SLSA v1.0-compatible provenance for sandboxed builds.
//!
//! Supports Claude Code sessions, package builds, CI steps, and any
//! sandboxed process. Tool-specific metadata is optional; the core
//! provenance format works for any build system.
//!
//! SLSA levels:
//! - L1-L2: Base [`GleisnerProvenance`] with signed provenance
//! - L3: [`ExtendedProvenance`] with [`HermeticMaterials`] (requires sandbox cooperation)
//! - L4: [`ExtendedProvenance`] + [`ReproducibilityAttestation`] (requires rebuild verification)
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
#[derive(Debug, Clone, Serialize)]
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

// ── Gap-closing extensions for SLSA L3+ ─────────────────────

/// Hermetic material declaration — a sealed, complete list of build inputs.
///
/// When a sandbox can guarantee that ONLY these materials were accessible
/// during the build (no network, no unmounted paths), the attestation can
/// set `completeness.materials = true`.
///
/// This is the bridge between minimal.dev's sandbox (which controls inputs)
/// and gleisner's attestation (which signs the claim).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HermeticMaterials {
    /// Complete list of inputs with content digests.
    pub materials: Vec<Material>,
    /// How hermiticity was enforced.
    pub enforcement: HermeticEnforcement,
    /// Whether the sandbox guarantees no other inputs were accessible.
    pub sealed: bool,
}

/// How hermetic enforcement was achieved.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HermeticEnforcement {
    /// Sandbox-provided: the sandbox declares the complete input set
    /// and enforces it via namespaces + Landlock.
    SandboxDeclared,
    /// Observed: file-access monitoring captured all reads and no
    /// undeclared reads occurred (weaker — race conditions possible).
    Observed,
    /// Self-reported: the build tool reported its inputs (weakest —
    /// trusts the build tool).
    SelfReported,
}

/// Reproducibility claim — asserts that rebuilding from the same inputs
/// produces the same outputs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReproducibilityAttestation {
    /// The spec hash (content-addressed build recipe).
    pub spec_hash: String,
    /// SHA-256 of the build outputs.
    pub output_digest: String,
    /// Number of independent rebuilds that produced the same digest.
    pub rebuild_count: u32,
    /// Whether all rebuilds matched.
    pub reproducible: bool,
    /// Timestamp of the verification.
    pub verified_at: DateTime<Utc>,
}

/// Per-step attestation for multi-step build pipelines.
///
/// Each step (eval, build, test, deploy) gets its own attestation that
/// references the prior step's attestation via `depends_on`. This enables
/// fine-grained supply chain auditing: "the test step consumed the build
/// step's outputs and produced a pass/fail result."
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildStep {
    /// Step name (e.g., "eval", "build", "test", "deploy").
    pub name: String,
    /// Index in the pipeline (0-based).
    pub index: u32,
    /// Total steps in the pipeline.
    pub total_steps: u32,
    /// SHA-256 of the prior step's attestation payload (if not the first step).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<String>,
    /// What this step consumed (subset of the pipeline's materials).
    pub step_materials: Vec<Material>,
    /// What this step produced.
    pub step_subjects: Vec<Material>,
}

/// Extended provenance for builds with hermetic materials and/or
/// reproducibility claims. Wraps [`GleisnerProvenance`] with additional fields.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedProvenance {
    /// The base SLSA provenance.
    #[serde(flatten)]
    pub base: GleisnerProvenance,

    /// Hermetic materials declaration (if the sandbox can guarantee completeness).
    #[serde(
        rename = "gleisner:hermeticMaterials",
        skip_serializing_if = "Option::is_none"
    )]
    pub hermetic_materials: Option<HermeticMaterials>,

    /// Reproducibility attestation (if rebuild verification was performed).
    #[serde(
        rename = "gleisner:reproducibility",
        skip_serializing_if = "Option::is_none"
    )]
    pub reproducibility: Option<ReproducibilityAttestation>,

    /// Build step metadata (for multi-step pipelines).
    #[serde(rename = "gleisner:buildStep", skip_serializing_if = "Option::is_none")]
    pub build_step: Option<BuildStep>,

    /// Per-package attestation references (for composed environments).
    /// Each entry maps a package name to the digest of its individual attestation.
    #[serde(
        rename = "gleisner:packageAttestations",
        skip_serializing_if = "Option::is_none"
    )]
    pub package_attestations: Option<Vec<PackageAttestationRef>>,
}

/// Reference to an individual package's attestation within a composed environment.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageAttestationRef {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: Option<String>,
    /// SHA-256 of the package's individual attestation payload.
    pub attestation_digest: String,
    /// Whether the package was individually verified (vs trusted from cache).
    pub individually_verified: bool,
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
