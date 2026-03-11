//! Environment composition — merging `Attrs` and `Needs` across packages.
//!
//! After evaluating all packages in a set, their `attrs` and `needs` fields
//! are merged to produce a unified environment specification. This drives
//! the sandbox policy: filesystem binds from `env_dir_mappings`, network
//! access from `Needs`, etc.

/// A directory mapping extracted from a package's `attrs.env_dir_mappings`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DirMapping {
    /// Whether the directory is read-only.
    pub read_only: bool,
    /// The mount path.
    pub path: String,
    /// The class: `Credential` or `State`.
    pub class: String,
}

/// A file mapping extracted from a package's `attrs.env_file_mappings`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileMapping {
    /// Whether the file is read-only.
    pub read_only: bool,
    /// The mount path.
    pub path: String,
    /// The class: `Credential` or `State`.
    pub class: String,
}

/// A state wiring extracted from a package's `attrs.env_state_wiring`.
///
/// Tells the sandbox runtime to create a persistent state directory at
/// `$STATE_ROOT/<prefix>/` and set `env_var` to point at it. This is how
/// packages like `rust` (`CARGO_HOME`), `go` (`GOCACHE`), and `uv`
/// (`UV_CACHE_DIR`) communicate their cache directory needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StateWiring {
    /// Environment variable to set (e.g., `CARGO_HOME`).
    pub env_var: String,
    /// Directory prefix within the state root (e.g., `cargo`).
    pub prefix: String,
    /// Which package declared this wiring.
    pub package: String,
}

/// A domain required by a package's source declarations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SourceDomain {
    /// The domain name (e.g., `github.com`).
    pub domain: String,
    /// Which package declared this source.
    pub package: String,
    /// The full URL this was extracted from.
    pub source_url: String,
}

/// Abstract needs declared by packages.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MergedNeeds {
    /// Whether any package needs DNS.
    pub dns: bool,
    /// Whether any package needs internet.
    pub internet: bool,
}

/// The composed environment from merging all packages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComposedEnvironment {
    /// All directory mappings (deduplicated, conflicts resolved).
    pub dir_mappings: Vec<DirMapping>,
    /// All file mappings (deduplicated, conflicts resolved).
    pub file_mappings: Vec<FileMapping>,
    /// State directory wirings (env var → prefix pairs).
    pub state_wirings: Vec<StateWiring>,
    /// Merged abstract needs (logical OR).
    pub needs: MergedNeeds,
    /// Domains required by package source declarations.
    ///
    /// Extracted from `build_deps` entries with `url` fields. Contains ALL
    /// occurrences (not deduplicated) — each entry records which package
    /// declared a source from that domain. The bridge layer aggregates these
    /// into a unique domain allowlist and provenance attribution.
    pub source_domains: Vec<SourceDomain>,
    /// Packages that contributed to this environment.
    pub packages: Vec<String>,
    /// Conflict warnings (e.g., same path with different `read_only` flags).
    pub warnings: Vec<String>,
}

impl ComposedEnvironment {
    /// Create a new empty composed environment.
    pub fn new() -> Self {
        Self {
            dir_mappings: Vec::new(),
            file_mappings: Vec::new(),
            state_wirings: Vec::new(),
            needs: MergedNeeds::default(),
            source_domains: Vec::new(),
            packages: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Merge a package's evaluated JSON into this environment.
    ///
    /// Extracts `attrs.env_dir_mappings`, `attrs.env_file_mappings`, and
    /// `needs` from the JSON and merges them with set-union semantics.
    pub fn merge_package(&mut self, name: &str, json: &serde_json::Value) {
        self.packages.push(name.to_string());

        // Extract attrs.env_dir_mappings
        if let Some(dirs) = json
            .get("attrs")
            .and_then(|a| a.get("env_dir_mappings"))
            .and_then(|d| d.as_array())
        {
            for entry in dirs {
                if let Some(mapping) = parse_dir_mapping(entry) {
                    self.add_dir_mapping(name, mapping);
                }
            }
        }

        // Extract attrs.env_file_mappings
        if let Some(files) = json
            .get("attrs")
            .and_then(|a| a.get("env_file_mappings"))
            .and_then(|f| f.as_array())
        {
            for entry in files {
                if let Some(mapping) = parse_file_mapping(entry) {
                    self.add_file_mapping(name, mapping);
                }
            }
        }

        // Extract attrs.env_state_wiring (single object or array)
        if let Some(wiring) = json.get("attrs").and_then(|a| a.get("env_state_wiring")) {
            match wiring {
                serde_json::Value::Array(entries) => {
                    for entry in entries {
                        if let Some(sw) = parse_state_wiring(entry, name) {
                            self.add_state_wiring(name, sw);
                        }
                    }
                }
                serde_json::Value::Object(_) => {
                    if let Some(sw) = parse_state_wiring(wiring, name) {
                        self.add_state_wiring(name, sw);
                    }
                }
                _ => {}
            }
        }

        // Extract needs (presence-based flags)
        if let Some(needs) = json.get("needs") {
            if needs.get("dns").is_some() {
                self.needs.dns = true;
            }
            if needs.get("internet").is_some() {
                self.needs.internet = true;
            }
        }

        // Extract domains from source URLs in build_deps.
        // All occurrences are kept — the bridge aggregates into a unique
        // domain list and per-domain provenance attribution.
        if let Some(deps) = json.get("build_deps").and_then(|d| d.as_array()) {
            for dep in deps {
                if let Some(url) = dep.get("url").and_then(|u| u.as_str()) {
                    if let Some(domain) = extract_domain(url) {
                        self.source_domains.push(SourceDomain {
                            domain,
                            package: name.to_string(),
                            source_url: url.to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Add a directory mapping, resolving conflicts.
    fn add_dir_mapping(&mut self, package: &str, new: DirMapping) {
        // Check for existing mapping at same path
        if let Some(existing) = self.dir_mappings.iter_mut().find(|m| m.path == new.path) {
            if existing.read_only != new.read_only {
                // Conflict: more permissive (rw) wins
                self.warnings.push(format!(
                    "dir mapping conflict at '{}': {} wants {}, {} wants {} — using rw",
                    new.path,
                    package,
                    if new.read_only { "ro" } else { "rw" },
                    "(earlier)",
                    if existing.read_only { "ro" } else { "rw" },
                ));
                existing.read_only = false;
            }
            if existing.class != new.class {
                self.warnings.push(format!(
                    "dir mapping class conflict at '{}': '{}' vs '{}' from {package}",
                    new.path, existing.class, new.class,
                ));
            }
        } else {
            self.dir_mappings.push(new);
        }
    }

    /// Add a state wiring, warning on env var conflicts.
    fn add_state_wiring(&mut self, package: &str, new: StateWiring) {
        if let Some(existing) = self.state_wirings.iter().find(|w| w.env_var == new.env_var) {
            if existing.prefix != new.prefix {
                self.warnings.push(format!(
                    "state wiring conflict for ${}: {} wants prefix '{}', {} wants '{}' — keeping first",
                    new.env_var, existing.package, existing.prefix, package, new.prefix,
                ));
            }
            // Same env_var already wired — skip duplicate
            return;
        }
        self.state_wirings.push(new);
    }

    /// Add a file mapping, resolving conflicts.
    fn add_file_mapping(&mut self, package: &str, new: FileMapping) {
        if let Some(existing) = self.file_mappings.iter_mut().find(|m| m.path == new.path) {
            if existing.read_only != new.read_only {
                self.warnings.push(format!(
                    "file mapping conflict at '{}': {package} — using rw",
                    new.path,
                ));
                existing.read_only = false;
            }
            if existing.class != new.class {
                self.warnings.push(format!(
                    "file mapping class conflict at '{}': '{}' vs '{}' from {package}",
                    new.path, existing.class, new.class,
                ));
            }
        } else {
            self.file_mappings.push(new);
        }
    }
}

impl Default for ComposedEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_dir_mapping(value: &serde_json::Value) -> Option<DirMapping> {
    Some(DirMapping {
        read_only: value.get("read_only")?.as_bool()?,
        path: value.get("path")?.as_str()?.to_string(),
        class: format_class(value.get("class")?),
    })
}

fn parse_state_wiring(value: &serde_json::Value, package: &str) -> Option<StateWiring> {
    Some(StateWiring {
        env_var: value.get("env_var")?.as_str()?.to_string(),
        prefix: value.get("prefix")?.as_str()?.to_string(),
        package: package.to_string(),
    })
}

fn parse_file_mapping(value: &serde_json::Value) -> Option<FileMapping> {
    Some(FileMapping {
        read_only: value.get("read_only")?.as_bool()?,
        path: value.get("path")?.as_str()?.to_string(),
        class: format_class(value.get("class")?),
    })
}

/// Extract the domain from a URL string.
///
/// Handles `https://`, `http://`, and `gs://` (Google Cloud Storage) schemes.
/// Returns `None` for non-URL strings (e.g., bare filenames).
fn extract_domain(url: &str) -> Option<String> {
    // Handle standard URLs
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        return rest.split('/').next().map(|h| {
            // Strip port if present
            h.split(':').next().unwrap_or(h).to_string()
        });
    }
    // gs:// URLs don't correspond to a network domain (accessed via API)
    if url.starts_with("gs://") {
        return Some("storage.googleapis.com".to_string());
    }
    None
}

/// Nickel enum tags serialize as `"Credential"` or `{"Credential": {}}` depending
/// on format. Handle both.
fn format_class(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => map
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string()),
        _ => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_json(attrs_json: &str, needs_json: &str) -> serde_json::Value {
        serde_json::from_str(&format!(
            r#"{{"name": "test", "attrs": {attrs_json}, "needs": {needs_json}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn merge_dir_mappings_dedup() {
        let mut env = ComposedEnvironment::new();
        let json = pkg_json(
            r#"{"env_dir_mappings": [
                {"read_only": false, "path": "~/.config", "class": "State"},
                {"read_only": true, "path": "/usr", "class": "State"}
            ]}"#,
            "{}",
        );
        env.merge_package("pkg1", &json);
        assert_eq!(env.dir_mappings.len(), 2);

        // Same path from another package — no duplicate
        let json2 = pkg_json(
            r#"{"env_dir_mappings": [
                {"read_only": false, "path": "~/.config", "class": "State"}
            ]}"#,
            "{}",
        );
        env.merge_package("pkg2", &json2);
        assert_eq!(env.dir_mappings.len(), 2);
    }

    #[test]
    fn merge_read_only_conflict_picks_rw() {
        let mut env = ComposedEnvironment::new();
        let j1 = pkg_json(
            r#"{"env_dir_mappings": [{"read_only": true, "path": "/data", "class": "State"}]}"#,
            "{}",
        );
        let j2 = pkg_json(
            r#"{"env_dir_mappings": [{"read_only": false, "path": "/data", "class": "State"}]}"#,
            "{}",
        );
        env.merge_package("a", &j1);
        env.merge_package("b", &j2);

        assert!(!env.dir_mappings[0].read_only);
        assert!(!env.warnings.is_empty());
    }

    #[test]
    fn merge_needs_logical_or() {
        let mut env = ComposedEnvironment::new();
        let j1 = pkg_json("{}", r#"{"dns": {}}"#);
        let j2 = pkg_json("{}", r#"{"internet": {}}"#);

        env.merge_package("a", &j1);
        assert!(env.needs.dns);
        assert!(!env.needs.internet);

        env.merge_package("b", &j2);
        assert!(env.needs.dns);
        assert!(env.needs.internet);
    }

    #[test]
    fn state_wiring_single_object() {
        let mut env = ComposedEnvironment::new();
        let json = pkg_json(
            r#"{"env_state_wiring": {"env_var": "CARGO_HOME", "prefix": "cargo"}}"#,
            "{}",
        );
        env.merge_package("rust", &json);

        assert_eq!(env.state_wirings.len(), 1);
        assert_eq!(env.state_wirings[0].env_var, "CARGO_HOME");
        assert_eq!(env.state_wirings[0].prefix, "cargo");
        assert_eq!(env.state_wirings[0].package, "rust");
    }

    #[test]
    fn state_wiring_array() {
        let mut env = ComposedEnvironment::new();
        let json = pkg_json(
            r#"{"env_state_wiring": [
                {"env_var": "GOCACHE", "prefix": "gocache"},
                {"env_var": "GOPATH", "prefix": "gopath"}
            ]}"#,
            "{}",
        );
        env.merge_package("go", &json);

        assert_eq!(env.state_wirings.len(), 2);
        assert_eq!(env.state_wirings[0].env_var, "GOCACHE");
        assert_eq!(env.state_wirings[1].env_var, "GOPATH");
    }

    #[test]
    fn state_wiring_dedup_same_env_var() {
        let mut env = ComposedEnvironment::new();
        let j1 = pkg_json(
            r#"{"env_state_wiring": {"env_var": "CARGO_HOME", "prefix": "cargo"}}"#,
            "{}",
        );
        let j2 = pkg_json(
            r#"{"env_state_wiring": {"env_var": "CARGO_HOME", "prefix": "cargo"}}"#,
            "{}",
        );
        env.merge_package("rust", &j1);
        env.merge_package("rust-src", &j2);

        // Should dedup — same env_var, same prefix
        assert_eq!(env.state_wirings.len(), 1);
        assert!(env.warnings.is_empty());
    }

    #[test]
    fn state_wiring_conflict_warns() {
        let mut env = ComposedEnvironment::new();
        let j1 = pkg_json(
            r#"{"env_state_wiring": {"env_var": "CARGO_HOME", "prefix": "cargo"}}"#,
            "{}",
        );
        let j2 = pkg_json(
            r#"{"env_state_wiring": {"env_var": "CARGO_HOME", "prefix": "cargo2"}}"#,
            "{}",
        );
        env.merge_package("rust", &j1);
        env.merge_package("rust-alt", &j2);

        // First one wins, but warning emitted
        assert_eq!(env.state_wirings.len(), 1);
        assert_eq!(env.state_wirings[0].prefix, "cargo");
        assert!(env.warnings.iter().any(|w| w.contains("CARGO_HOME")));
    }

    #[test]
    fn source_domains_extracted_from_build_deps() {
        let mut env = ComposedEnvironment::new();
        let json = serde_json::json!({
            "name": "curl",
            "attrs": {},
            "needs": {"dns": {}},
            "build_deps": [
                {"file": "build.sh"},
                {
                    "url": "https://github.com/curl/curl/releases/download/curl-8_11_0/curl-8.11.0.tar.gz",
                    "sha256": "abc123",
                },
                {
                    "url": "https://storage.googleapis.com/minimal-os/patches/curl-fix.patch",
                    "sha256": "def456",
                },
            ],
        });
        env.merge_package("curl", &json);

        assert_eq!(env.source_domains.len(), 2);
        assert_eq!(env.source_domains[0].domain, "github.com");
        assert_eq!(env.source_domains[0].package, "curl");
        assert_eq!(env.source_domains[1].domain, "storage.googleapis.com");
    }

    #[test]
    fn source_domains_all_occurrences_kept() {
        let mut env = ComposedEnvironment::new();
        let j1 = serde_json::json!({
            "name": "zlib",
            "attrs": {},
            "needs": {},
            "build_deps": [{"url": "https://github.com/madler/zlib/archive/v1.3.1.tar.gz", "sha256": "a"}],
        });
        let j2 = serde_json::json!({
            "name": "curl",
            "attrs": {},
            "needs": {},
            "build_deps": [{"url": "https://github.com/curl/curl/archive/curl-8.tar.gz", "sha256": "b"}],
        });
        env.merge_package("zlib", &j1);
        env.merge_package("curl", &j2);

        // Both occurrences of github.com are kept (bridge handles dedup)
        assert_eq!(env.source_domains.len(), 2);
        assert_eq!(env.source_domains[0].package, "zlib");
        assert_eq!(env.source_domains[1].package, "curl");
        assert!(env.source_domains.iter().all(|d| d.domain == "github.com"));
    }

    #[test]
    fn source_domains_gs_url_maps_to_storage_api() {
        let mut env = ComposedEnvironment::new();
        let json = serde_json::json!({
            "name": "openssh",
            "attrs": {},
            "needs": {},
            "build_deps": [{"url": "gs://minimal-staging-archives/openssh-10.2p1.tar.gz", "sha256": "c"}],
        });
        env.merge_package("openssh", &json);

        assert_eq!(env.source_domains.len(), 1);
        assert_eq!(env.source_domains[0].domain, "storage.googleapis.com");
    }

    // ── Property-based tests ──────────────────────────────────────

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// extract_domain never panics on arbitrary strings.
            #[test]
            fn extract_domain_never_panics(s in ".*") {
                let _ = extract_domain(&s);
            }

            /// https:// URLs always produce a domain (non-empty host).
            #[test]
            fn https_urls_always_have_domain(
                host in "[a-z][a-z0-9.-]{0,30}",
                path in "[a-z0-9/._-]{0,30}"
            ) {
                let url = format!("https://{host}/{path}");
                let domain = extract_domain(&url);
                prop_assert!(domain.is_some(), "https URL should always have domain");
                prop_assert!(!domain.as_ref().unwrap().is_empty());
                // Domain should not contain port numbers
                prop_assert!(!domain.unwrap().contains(':'));
            }

            /// gs:// URLs always map to storage.googleapis.com.
            #[test]
            fn gs_urls_map_to_gcs(
                bucket in "[a-z][a-z0-9-]{0,20}",
                object in "[a-z0-9/._-]{1,30}"
            ) {
                let url = format!("gs://{bucket}/{object}");
                prop_assert_eq!(
                    extract_domain(&url),
                    Some("storage.googleapis.com".to_string())
                );
            }

            /// merge_package never panics on arbitrary JSON.
            #[test]
            fn merge_package_never_panics(
                name in "[a-z][a-z0-9-]{0,15}",
                json_str in "\\{[a-z0-9 :,\"{}\\[\\]]*\\}"
            ) {
                let mut env = ComposedEnvironment::new();
                // Try to parse the string as JSON; if it fails, use a default
                let json = serde_json::from_str(&json_str)
                    .unwrap_or(serde_json::json!({"name": name.clone()}));
                env.merge_package(&name, &json);
                // At minimum the package name is recorded
                prop_assert!(env.packages.contains(&name));
            }

            /// Merging the same package twice is idempotent for dir mappings.
            #[test]
            fn merge_idempotent_for_dir_mappings(
                path in "/[a-z]{1,10}(/[a-z]{1,10}){0,3}",
                read_only in any::<bool>()
            ) {
                let json = serde_json::json!({
                    "name": "test",
                    "attrs": {
                        "env_dir_mappings": [
                            {"read_only": read_only, "path": path, "class": "State"}
                        ]
                    },
                    "needs": {}
                });

                let mut env = ComposedEnvironment::new();
                env.merge_package("a", &json);
                let count_after_first = env.dir_mappings.len();

                env.merge_package("b", &json);
                // Same path should be deduped, not added again
                prop_assert_eq!(env.dir_mappings.len(), count_after_first);
            }

            /// needs.dns and needs.internet are monotonic (once true, stays true).
            #[test]
            fn needs_are_monotonic(
                dns1 in any::<bool>(),
                internet1 in any::<bool>(),
                dns2 in any::<bool>(),
                internet2 in any::<bool>()
            ) {
                let mut env = ComposedEnvironment::new();
                let j1 = serde_json::json!({
                    "name": "a",
                    "attrs": {},
                    "needs": {
                        "dns": if dns1 { serde_json::json!({}) } else { serde_json::Value::Null },
                        "internet": if internet1 { serde_json::json!({}) } else { serde_json::Value::Null },
                    }
                });
                let j2 = serde_json::json!({
                    "name": "b",
                    "attrs": {},
                    "needs": {
                        "dns": if dns2 { serde_json::json!({}) } else { serde_json::Value::Null },
                        "internet": if internet2 { serde_json::json!({}) } else { serde_json::Value::Null },
                    }
                });

                env.merge_package("a", &j1);
                let dns_after_first = env.needs.dns;
                let internet_after_first = env.needs.internet;

                env.merge_package("b", &j2);
                // Monotonic: once true, can't go back to false
                if dns_after_first {
                    prop_assert!(env.needs.dns);
                }
                if internet_after_first {
                    prop_assert!(env.needs.internet);
                }
            }
        }
    }

    #[test]
    fn extract_domain_handles_edge_cases() {
        assert_eq!(
            extract_domain("https://example.com/file.tar.gz"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://example.com:8080/file.tar.gz"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://mirror.example.org/pkg.deb"),
            Some("mirror.example.org".to_string())
        );
        assert_eq!(
            extract_domain("gs://bucket-name/object"),
            Some("storage.googleapis.com".to_string())
        );
        assert_eq!(extract_domain("build.sh"), None);
        assert_eq!(extract_domain("./local/file.patch"), None);
    }
}
