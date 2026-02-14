//! Build environment metadata helpers for attestation provenance.
//!
//! Captures runtime context about the Gleisner CLI itself — version,
//! builder identity, and hostname — for inclusion in SLSA provenance
//! predicates.

/// The version of the `gleisner-introdus` crate (compile-time constant).
///
/// Used as the canonical Gleisner version in attestation records.
#[must_use]
pub const fn gleisner_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A SLSA builder identifier for this Gleisner CLI instance.
///
/// Format: `gleisner-cli/{version}`.
#[must_use]
pub fn builder_id() -> String {
    format!("gleisner-cli/{}", gleisner_version())
}

/// Attempt to capture the machine hostname.
///
/// Returns `None` if the hostname cannot be determined. Uses the
/// `gethostname` syscall via the `nix` crate, falling back to the
/// `HOSTNAME` environment variable.
#[must_use]
pub fn capture_hostname() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .and_then(|name: std::ffi::OsString| name.into_string().ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gleisner_version_is_non_empty() {
        let v = gleisner_version();
        assert!(!v.is_empty(), "version should not be empty");
    }

    #[test]
    fn builder_id_starts_with_prefix() {
        let id = builder_id();
        assert!(
            id.starts_with("gleisner-cli/"),
            "builder_id should start with 'gleisner-cli/': got {id}"
        );
    }

    #[test]
    fn capture_hostname_returns_something() {
        // On most systems this should return Some; in very unusual
        // environments it might not, so we just verify it doesn't panic.
        let _ = capture_hostname();
    }
}
