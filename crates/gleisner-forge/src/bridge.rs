//! Bridge from [`ComposedEnvironment`] to sandbox-compatible policy types.
//!
//! Converts forge's merged package declarations into filesystem and network
//! policy that gleisner-polis can enforce. This module intentionally avoids
//! depending on gleisner-polis directly — it produces plain data types that
//! the CLI/TUI wiring layer converts into `SandboxSpec` fields.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::compose::{ComposedEnvironment, SourceDomain, StateWiring};

/// Filesystem policy derived from package declarations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ForgeFilesystemPolicy {
    /// Directories to mount read-only.
    pub readonly_bind: Vec<PathBuf>,
    /// Directories to mount read-write.
    pub readwrite_bind: Vec<PathBuf>,
}

/// Network policy derived from package `needs` and source declarations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ForgeNetworkPolicy {
    /// Whether any package needs DNS resolution.
    pub allow_dns: bool,
    /// Whether any package needs full internet access.
    pub allow_internet: bool,
    /// Domains required by package source declarations.
    ///
    /// Derived from `build_deps` URLs — these are the exact domains the build
    /// needs to download source tarballs from. When merged into a sandbox
    /// profile, these extend (not replace) the profile's existing allowlist.
    pub allow_domains: Vec<String>,
}

/// Environment variables to set inside the sandbox.
///
/// These come from harness `build_env_vars` and state wiring template
/// expansion (e.g., `{cargo-cache-home}` → resolved state dir path).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ForgeEnvPolicy {
    /// Key-value pairs to set as environment variables.
    pub vars: Vec<(String, String)>,
}

/// Per-domain provenance: which packages use this domain and why.
///
/// This answers supply chain questions like "if storage.googleapis.com is
/// compromised, which packages are affected?" and "which package introduced
/// this new domain?"
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainProvenance {
    /// The domain name.
    pub domain: String,
    /// Packages that download sources from this domain.
    pub packages: Vec<String>,
    /// Number of source URLs pointing at this domain.
    pub url_count: usize,
    /// Example source URLs (up to 3, for display).
    pub example_urls: Vec<String>,
}

/// Validation warnings and errors from environment composition.
#[derive(Debug, Clone)]
pub struct BridgeReport {
    /// Filesystem policy for the sandbox.
    pub filesystem: ForgeFilesystemPolicy,
    /// Network policy for the sandbox.
    pub network: ForgeNetworkPolicy,
    /// Environment variables for the sandbox.
    pub env: ForgeEnvPolicy,
    /// State wirings: env var → prefix mappings for persistent cache directories.
    pub state_wirings: Vec<StateWiring>,
    /// Per-domain provenance attribution: which packages use which domains.
    ///
    /// Sorted by package count descending (highest blast radius first).
    pub domain_provenance: Vec<DomainProvenance>,
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

    // Build per-domain provenance and derive the unique domain allowlist
    let (allow_domains, domain_provenance) = build_domain_provenance(&env.source_domains);

    // If any source domains were found, DNS is implicitly required
    let needs_dns = env.needs.dns || !allow_domains.is_empty();

    let network = ForgeNetworkPolicy {
        allow_dns: needs_dns,
        allow_internet: env.needs.internet,
        allow_domains,
    };

    BridgeReport {
        filesystem: fs,
        network,
        env: ForgeEnvPolicy::default(),
        state_wirings: env.state_wirings.clone(),
        domain_provenance,
        credential_paths,
        warnings,
    }
}

/// Build per-domain provenance attribution from all source domain records.
///
/// Returns `(unique_domains_sorted, provenance_by_blast_radius)`.
fn build_domain_provenance(
    source_domains: &[SourceDomain],
) -> (Vec<String>, Vec<DomainProvenance>) {
    // Group by domain
    let mut by_domain: BTreeMap<&str, Vec<&SourceDomain>> = BTreeMap::new();
    for sd in source_domains {
        by_domain.entry(&sd.domain).or_default().push(sd);
    }

    let allow_domains: Vec<String> = by_domain.keys().map(ToString::to_string).collect();

    let mut provenance: Vec<DomainProvenance> = by_domain
        .into_iter()
        .map(|(domain, entries)| {
            // Unique packages for this domain
            let mut packages: Vec<String> = entries.iter().map(|e| e.package.clone()).collect();
            packages.sort();
            packages.dedup();

            let url_count = entries.len();
            let example_urls: Vec<String> = entries
                .iter()
                .map(|e| e.source_url.clone())
                .take(3)
                .collect();

            DomainProvenance {
                domain: domain.to_string(),
                packages,
                url_count,
                example_urls,
            }
        })
        .collect();

    // Sort by blast radius: most packages first
    provenance.sort_by(|a, b| b.packages.len().cmp(&a.packages.len()));

    (allow_domains, provenance)
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
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home);
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
            source_domains: Vec::new(),
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
            source_domains: Vec::new(),
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
            source_domains: Vec::new(),
            packages: vec!["test".to_string()],
            warnings: Vec::new(),
        };

        let report = compose_to_policy(&env);

        assert!(report.network.allow_dns);
        assert!(!report.network.allow_internet);
        assert!(report.network.allow_domains.is_empty());
    }

    #[test]
    fn source_domains_become_allow_domains() {
        use crate::compose::SourceDomain;

        let env = ComposedEnvironment {
            dir_mappings: Vec::new(),
            file_mappings: Vec::new(),
            state_wirings: Vec::new(),
            needs: MergedNeeds::default(), // no explicit dns/internet
            source_domains: vec![
                SourceDomain {
                    domain: "github.com".to_string(),
                    package: "zlib".to_string(),
                    source_url: "https://github.com/madler/zlib/archive/v1.3.1.tar.gz".to_string(),
                },
                SourceDomain {
                    domain: "storage.googleapis.com".to_string(),
                    package: "curl".to_string(),
                    source_url: "gs://minimal-staging-archives/curl-8.tar.gz".to_string(),
                },
            ],
            packages: vec!["zlib".to_string(), "curl".to_string()],
            warnings: Vec::new(),
        };

        let report = compose_to_policy(&env);

        // Source domains should appear in allow_domains
        assert_eq!(report.network.allow_domains.len(), 2);
        assert!(
            report
                .network
                .allow_domains
                .contains(&"github.com".to_string())
        );
        assert!(
            report
                .network
                .allow_domains
                .contains(&"storage.googleapis.com".to_string())
        );
        // DNS should be implicitly enabled (source domains need resolution)
        assert!(report.network.allow_dns);
        // allow_internet should still be false (not declared in needs)
        assert!(!report.network.allow_internet);
    }

    #[test]
    fn domain_provenance_tracks_blast_radius() {
        use crate::compose::SourceDomain;

        let env = ComposedEnvironment {
            dir_mappings: Vec::new(),
            file_mappings: Vec::new(),
            state_wirings: Vec::new(),
            needs: MergedNeeds::default(),
            source_domains: vec![
                SourceDomain {
                    domain: "github.com".to_string(),
                    package: "zlib".to_string(),
                    source_url: "https://github.com/madler/zlib/v1.3.1.tar.gz".to_string(),
                },
                SourceDomain {
                    domain: "github.com".to_string(),
                    package: "curl".to_string(),
                    source_url: "https://github.com/curl/curl/curl-8.tar.gz".to_string(),
                },
                SourceDomain {
                    domain: "github.com".to_string(),
                    package: "openssh".to_string(),
                    source_url: "https://github.com/openssh/openssh-portable/v10.tar.gz"
                        .to_string(),
                },
                SourceDomain {
                    domain: "storage.googleapis.com".to_string(),
                    package: "gcc".to_string(),
                    source_url: "gs://minimal-staging/gcc-14.tar.gz".to_string(),
                },
            ],
            packages: vec![
                "zlib".to_string(),
                "curl".to_string(),
                "openssh".to_string(),
                "gcc".to_string(),
            ],
            warnings: Vec::new(),
        };

        let report = compose_to_policy(&env);

        // 2 unique domains
        assert_eq!(report.network.allow_domains.len(), 2);

        // Provenance sorted by blast radius: github.com (3 pkgs) > GCS (1 pkg)
        assert_eq!(report.domain_provenance.len(), 2);
        assert_eq!(report.domain_provenance[0].domain, "github.com");
        assert_eq!(report.domain_provenance[0].packages.len(), 3);
        assert_eq!(report.domain_provenance[0].url_count, 3);
        assert_eq!(
            report.domain_provenance[0].packages,
            vec!["curl", "openssh", "zlib"]
        );

        assert_eq!(report.domain_provenance[1].domain, "storage.googleapis.com");
        assert_eq!(report.domain_provenance[1].packages.len(), 1);
        assert_eq!(report.domain_provenance[1].packages, vec!["gcc"]);

        // Example URLs capped at 3
        assert_eq!(report.domain_provenance[0].example_urls.len(), 3);
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
