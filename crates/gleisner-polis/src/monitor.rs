//! Shared types and utilities for event monitors.
//!
//! Provides configuration structs for the filesystem (fanotify) and
//! process (/proc) monitors, plus glob-matching helpers.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Configuration for the filesystem monitor (fanotify).
pub struct FsMonitorConfig {
    /// Path to watch (e.g., the project directory mount).
    pub mount_path: PathBuf,
    /// Glob patterns for paths to ignore (e.g., `target/`, `.git/`).
    pub ignore_patterns: Vec<String>,
}

/// Configuration for the process monitor (/proc scanner).
pub struct ProcMonitorConfig {
    /// PID of the root sandboxed process (the bwrap child).
    pub root_pid: u32,
    /// How often to scan /proc for new/exited processes.
    pub poll_interval: Duration,
}

impl ProcMonitorConfig {
    /// Default polling interval: 250ms.
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);
}

/// Check whether a path should be ignored based on glob patterns.
///
/// Patterns are matched against each component of the path.
/// A pattern like `target/` matches any path containing a `target` directory.
/// A pattern like `*.log` matches any file ending in `.log`.
pub fn should_ignore(path: &Path, patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    for pattern in patterns {
        let pat = pattern.trim_end_matches('/');
        // Component match: any path segment equals the pattern
        if path
            .components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| matches_glob(s, pat)))
        {
            return true;
        }
        // Full path suffix match
        if matches_glob(&path_str, pat) {
            return true;
        }
    }
    false
}

/// Simple glob matching supporting `*` and `?` wildcards.
fn matches_glob(text: &str, pattern: &str) -> bool {
    let t = text.as_bytes();
    let p = pattern.as_bytes();

    let mut text_idx = 0;
    let mut pat_idx = 0;
    let mut last_star: Option<usize> = None;
    let mut match_after_star = 0;

    while text_idx < t.len() {
        if pat_idx < p.len() && (p[pat_idx] == b'?' || p[pat_idx] == t[text_idx]) {
            text_idx += 1;
            pat_idx += 1;
        } else if pat_idx < p.len() && p[pat_idx] == b'*' {
            last_star = Some(pat_idx);
            match_after_star = text_idx;
            pat_idx += 1;
        } else if let Some(star) = last_star {
            pat_idx = star + 1;
            match_after_star += 1;
            text_idx = match_after_star;
        } else {
            return false;
        }
    }

    // Consume trailing stars
    while pat_idx < p.len() && p[pat_idx] == b'*' {
        pat_idx += 1;
    }

    pat_idx == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_ignore_target_dir() {
        let patterns = vec!["target".to_owned(), ".git".to_owned()];
        assert!(should_ignore(
            Path::new("/project/target/debug/main"),
            &patterns
        ));
        assert!(should_ignore(
            Path::new("/project/.git/objects/abc"),
            &patterns
        ));
        assert!(!should_ignore(Path::new("/project/src/main.rs"), &patterns));
    }

    #[test]
    fn should_ignore_glob_extension() {
        let patterns = vec!["*.log".to_owned()];
        assert!(should_ignore(Path::new("/project/build.log"), &patterns));
        assert!(!should_ignore(Path::new("/project/main.rs"), &patterns));
    }

    #[test]
    fn should_ignore_node_modules() {
        let patterns = vec!["node_modules".to_owned()];
        assert!(should_ignore(
            Path::new("/project/node_modules/lodash/index.js"),
            &patterns
        ));
        assert!(!should_ignore(Path::new("/project/src/app.ts"), &patterns));
    }

    #[test]
    fn should_ignore_trailing_slash_pattern() {
        let patterns = vec!["target/".to_owned()];
        assert!(should_ignore(
            Path::new("/project/target/release/bin"),
            &patterns
        ));
    }

    #[test]
    fn empty_patterns_ignores_nothing() {
        assert!(!should_ignore(Path::new("/any/path"), &[]));
    }

    #[test]
    fn matches_glob_basic() {
        assert!(matches_glob("hello", "hello"));
        assert!(matches_glob("hello", "*"));
        assert!(matches_glob("hello.rs", "*.rs"));
        assert!(matches_glob("test", "t?st"));
        assert!(!matches_glob("hello", "world"));
        assert!(!matches_glob("hello.rs", "*.py"));
    }
}
