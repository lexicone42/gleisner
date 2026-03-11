//! Portable utilities — path expansion, binary resolution, command building.
//!
//! These functions use no Linux-specific APIs and are available on all
//! platforms. Extracted from `sandbox.rs` and `session.rs` to support
//! cfg-gating the Linux-only sandbox modules.

use std::path::{Path, PathBuf};

/// Resolve the user's home directory.
///
/// Uses a consistent two-step strategy everywhere:
/// 1. `$HOME` environment variable
/// 2. `directories::BaseDirs` (passwd/NSS lookup)
///
/// Returns `None` only if both methods fail (extremely rare).
#[must_use]
pub fn resolve_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()))
}

/// Expand `~` to the user's home directory.
///
/// Only expands a leading `~` — embedded tildes are left alone.
/// Uses [`resolve_home_dir`] for consistent resolution everywhere.
/// Logs a warning and returns the path unchanged only if both
/// `$HOME` and passwd lookup fail.
#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.display().to_string();
    if path_str.starts_with('~') {
        let Some(home) = resolve_home_dir() else {
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
    fn resolve_home_dir_returns_some() {
        // Should work on any system with either $HOME or a passwd entry.
        let home = resolve_home_dir();
        assert!(
            home.is_some(),
            "resolve_home_dir should find a home directory"
        );
        let home = home.unwrap();
        assert!(home.is_absolute(), "home dir should be absolute");
    }

    // ── Property-based tests ──────────────────────────────────────

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// expand_tilde never panics on arbitrary paths.
            #[test]
            fn expand_tilde_never_panics(s in ".*") {
                let _ = expand_tilde(Path::new(&s));
            }

            /// Absolute paths are returned unchanged by expand_tilde.
            #[test]
            fn absolute_paths_unchanged(
                path in "/[a-zA-Z0-9._-]{1,10}(/[a-zA-Z0-9._-]{1,10}){0,5}"
            ) {
                let result = expand_tilde(Path::new(&path));
                prop_assert_eq!(result, PathBuf::from(&path));
            }

            /// Tilde paths produce absolute results (when HOME is set).
            #[test]
            fn tilde_paths_become_absolute(
                suffix in "[a-zA-Z0-9_-]{1,10}(/[a-zA-Z0-9_-]{1,10}){0,3}"
            ) {
                if std::env::var_os("HOME").is_some() {
                    let path = format!("~/{suffix}");
                    let result = expand_tilde(Path::new(&path));
                    prop_assert!(
                        result.is_absolute(),
                        "expanded path should be absolute: {}",
                        result.display()
                    );
                    // The last component of the suffix should appear in the result
                    let last = Path::new(&suffix).file_name().unwrap().to_string_lossy();
                    prop_assert!(
                        result.to_string_lossy().contains(last.as_ref()),
                        "last component '{}' should be in result '{}'",
                        last,
                        result.display()
                    );
                }
            }

            /// expand_tilde is idempotent: expanding twice gives same result.
            #[test]
            fn expand_tilde_is_idempotent(
                path in prop_oneof![
                    "/[a-z]{1,10}(/[a-z]{1,10}){0,3}",
                    "~/[a-z]{1,10}(/[a-z]{1,10}){0,3}",
                ]
            ) {
                let once = expand_tilde(Path::new(&path));
                let twice = expand_tilde(&once);
                prop_assert_eq!(once, twice);
            }

            /// resolve_home_dir always returns an absolute path (when it returns Some).
            #[test]
            fn resolve_home_dir_is_absolute(_dummy in 0..1u8) {
                if let Some(home) = resolve_home_dir() {
                    prop_assert!(home.is_absolute());
                }
            }
        }
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths_alone() {
        let path = Path::new("/usr/bin");
        let expanded = expand_tilde(path);
        assert_eq!(expanded, PathBuf::from("/usr/bin"));
    }
}
