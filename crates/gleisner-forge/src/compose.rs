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
    /// Merged abstract needs (logical OR).
    pub needs: MergedNeeds,
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
            needs: MergedNeeds::default(),
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

        // Extract needs (presence-based flags)
        if let Some(needs) = json.get("needs") {
            if needs.get("dns").is_some() {
                self.needs.dns = true;
            }
            if needs.get("internet").is_some() {
                self.needs.internet = true;
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

fn parse_file_mapping(value: &serde_json::Value) -> Option<FileMapping> {
    Some(FileMapping {
        read_only: value.get("read_only")?.as_bool()?,
        path: value.get("path")?.as_str()?.to_string(),
        class: format_class(value.get("class")?),
    })
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
}
