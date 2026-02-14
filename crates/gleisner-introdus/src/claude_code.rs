//! Claude Code configuration and version detection.
//!
//! Detects the Claude Code binary, reads its config, and captures
//! contextual metadata for attestation records. Never captures
//! secrets — only hashes and boolean presence flags.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Claude Code configuration, read from `~/.claude/config.json`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeCodeConfig {
    /// Configured model name.
    pub model: Option<String>,
    /// Custom API base URL.
    pub api_base_url: Option<String>,
}

/// Detected Claude Code runtime context for attestation metadata.
pub struct ClaudeCodeContext {
    /// Claude Code CLI version string.
    pub version: Option<String>,
    /// Parsed config from `~/.claude/config.json`.
    pub config: Option<ClaudeCodeConfig>,
    /// SHA-256 hash of the project's CLAUDE.md, if present.
    pub claude_md_hash: Option<String>,
    /// Whether `ANTHROPIC_API_KEY` is set (never the value itself).
    pub api_key_present: bool,
    /// Model override from `ANTHROPIC_MODEL` env var.
    pub model_override: Option<String>,
}

impl ClaudeCodeContext {
    /// Capture Claude Code context from the current environment.
    ///
    /// Reads config files and environment variables. Never captures
    /// secrets — only hashes and boolean presence flags.
    pub fn capture(project_dir: &Path) -> Self {
        let version = detect_version();
        let config = load_config();
        let claude_md_hash = hash_file_if_exists(&project_dir.join("CLAUDE.md"));
        let api_key_present = std::env::var_os("ANTHROPIC_API_KEY").is_some();
        let model_override = std::env::var("ANTHROPIC_MODEL").ok();

        Self {
            version,
            config,
            claude_md_hash,
            api_key_present,
            model_override,
        }
    }

    /// The effective model: env override > config > default.
    #[must_use]
    pub fn effective_model(&self) -> Option<&str> {
        self.model_override
            .as_deref()
            .or_else(|| self.config.as_ref().and_then(|c| c.model.as_deref()))
    }
}

fn detect_version() -> Option<String> {
    std::process::Command::new("claude")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
}

fn load_config() -> Option<ClaudeCodeConfig> {
    let home = std::env::var_os("HOME")?;
    let config_path = PathBuf::from(home).join(".claude/config.json");
    let content = std::fs::read_to_string(config_path).ok()?;
    serde_json::from_str(&content).ok()
}

fn hash_file_if_exists(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let content = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&content);
    Some(hex::encode(hash))
}
