//! Portable utilities — path expansion, binary resolution, command building.
//!
//! These functions use no Linux-specific APIs and are available on all
//! platforms. Extracted from `bwrap.rs` and `session.rs` to support
//! cfg-gating the Linux-only sandbox modules.

use std::path::{Path, PathBuf};

/// Expand `~` to the user's home directory.
///
/// Only expands a leading `~` — embedded tildes are left alone.
/// Tries `$HOME` first, falls back to system passwd lookup via
/// `directories::BaseDirs`. Logs a warning and returns the path
/// unchanged only if both methods fail.
#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.display().to_string();
    if path_str.starts_with('~') {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()));
        let Some(home) = home else {
            tracing::warn!(
                path = %path_str,
                "$HOME is not set and passwd lookup failed — tilde path will not be expanded"
            );
            return path.to_path_buf();
        };
        home.join(path.strip_prefix("~").unwrap_or(path))
    } else {
        path.to_path_buf()
    }
}

/// Resolve the `claude` binary path.
///
/// Checks common installation locations when `claude` isn't on PATH:
/// 1. `~/.npm-global/bin/claude` (npm global with custom prefix)
/// 2. `~/.local/bin/claude` (pipx, local installs)
/// 3. `~/.claude/local/bin/claude` (Claude's own installer)
///
/// Falls back to `"claude"` (relies on PATH) if none found.
#[must_use]
pub fn resolve_claude_bin() -> String {
    if let Ok(home) = std::env::var("HOME") {
        let candidates = [
            format!("{home}/.npm-global/bin/claude"),
            format!("{home}/.local/bin/claude"),
            format!("{home}/.claude/local/bin/claude"),
        ];
        for candidate in &candidates {
            if Path::new(candidate).is_file() {
                return candidate.clone();
            }
        }
    }
    "claude".into()
}

/// Build the standard Claude CLI inner command.
///
/// Constructs `[claude_bin, --dangerously-skip-permissions (if enabled),
/// --disallowedTools (if any), ...extra_args]` — the common pattern
/// used by `wrap` and `record`.
#[must_use]
pub fn build_claude_inner_command(
    claude_bin: &str,
    profile: &crate::Profile,
    extra_args: &[String],
) -> Vec<String> {
    let mut cmd = vec![claude_bin.to_owned()];

    if profile.plugins.skip_permissions {
        cmd.push("--dangerously-skip-permissions".into());
    }
    if !profile.plugins.disallowed_tools.is_empty() {
        cmd.push("--disallowedTools".into());
        cmd.push(profile.plugins.disallowed_tools.join(","));
    }

    cmd.extend(extra_args.iter().cloned());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_substitutes_home() {
        if std::env::var_os("HOME").is_some() {
            let expanded = expand_tilde(Path::new("~/.ssh"));
            assert!(!expanded.starts_with("~"), "tilde should be expanded");
            assert!(
                expanded.ends_with(".ssh"),
                "path suffix should be preserved"
            );
        }
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths_alone() {
        let path = Path::new("/usr/bin");
        let expanded = expand_tilde(path);
        assert_eq!(expanded, PathBuf::from("/usr/bin"));
    }
}
