//! Harness loading, evaluation, and project matching.
//!
//! Harnesses are build-system detectors used by [minimal.dev](https://minimal.dev)
//! to automatically configure environments. Each harness declares:
//!
//! - **`build_packages`** — packages needed for the build (e.g., `gcc`, `rust`)
//! - **`build_env_vars`** — environment variables to set (e.g., `CC=gcc`)
//! - **`matches_project_if_any`** — file-existence rules to detect project type
//!
//! The forge evaluates harness Nickel files, matches them against a project
//! directory, and injects their requirements into the composed environment.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::compose::StateWiring;
use crate::error::ForgeError;
use crate::eval::EvalContext;

/// A loaded and parsed harness specification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarnessSpec {
    /// Harness name (e.g., `rust`, `cmake`, `npm`).
    pub name: String,
    /// Packages required to build (e.g., `["gcc", "rust", "binutils"]`).
    pub build_packages: Vec<String>,
    /// Packages required at runtime (e.g., `["node"]`).
    pub runtime_packages: Vec<String>,
    /// Environment variables to set (e.g., `CC=gcc`).
    /// Values may contain template variables like `{cargo-cache-home}`.
    pub build_env_vars: HashMap<String, String>,
    /// Build command (if specified as a single string).
    pub build_cmd: Option<String>,
    /// File-existence matchers: the harness matches if ANY entry matches.
    pub matchers: Vec<HarnessMatcher>,
    /// Priority for harness selection when multiple harnesses match.
    /// Higher values win. Default is 0.
    pub priority: i64,
}

/// A single matcher entry from `matches_project_if_any`.
///
/// A matcher matches a project if ALL of its `file_regexes` files exist
/// in the project directory. The glob pattern is currently ignored (treated
/// as a simple existence check).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarnessMatcher {
    /// Map of filename → glob pattern. The file must exist for the matcher to match.
    pub file_regexes: HashMap<String, String>,
    /// Conditional build packages: package name → array of predicate entries.
    /// These require `file_predicates` evaluation (deferred — logged as warnings).
    pub build_package_if_any: HashMap<String, serde_json::Value>,
    /// Conditional runtime packages: package name → array of predicate entries.
    pub runtime_package_if_any: HashMap<String, serde_json::Value>,
}

/// Result of matching a harness against a project.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarnessMatch {
    /// The matched harness.
    pub harness: HarnessSpec,
    /// Expanded environment variables (template vars resolved).
    pub env_vars: Vec<(String, String)>,
}

/// Load all harnesses from a directory.
///
/// Each subdirectory should contain a `harness.ncl` file. Harnesses that
/// fail to evaluate are logged as warnings and skipped.
pub fn load_harnesses(
    harnesses_dir: &Path,
    ctx: &EvalContext,
) -> Result<Vec<HarnessSpec>, ForgeError> {
    let entries = std::fs::read_dir(harnesses_dir).map_err(|e| ForgeError::NickelEval {
        package: "<harnesses>".to_string(),
        message: format!("failed to read {}: {e}", harnesses_dir.display()),
    })?;

    let mut harnesses = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("failed to read harness entry: {e}");
                continue;
            }
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let harness_file = path.join("harness.ncl");
        if !harness_file.exists() {
            continue;
        }

        match eval_harness(&harness_file, ctx) {
            Ok(spec) => {
                tracing::debug!(
                    harness = %spec.name,
                    build_packages = spec.build_packages.len(),
                    matchers = spec.matchers.len(),
                    "loaded harness"
                );
                harnesses.push(spec);
            }
            Err(e) => {
                tracing::warn!(
                    path = %harness_file.display(),
                    error = %e,
                    "failed to load harness — skipping"
                );
            }
        }
    }

    tracing::info!(count = harnesses.len(), "harnesses loaded");
    Ok(harnesses)
}

/// Evaluate a single harness.ncl and parse its output into a `HarnessSpec`.
fn eval_harness(path: &Path, ctx: &EvalContext) -> Result<HarnessSpec, ForgeError> {
    let json = crate::eval::eval_file(path, ctx)?;
    parse_harness_json(&json, path)
}

/// Parse evaluated harness JSON into a `HarnessSpec`.
fn parse_harness_json(json: &serde_json::Value, path: &Path) -> Result<HarnessSpec, ForgeError> {
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ForgeError::NickelEval {
            package: format!("{}", path.display()),
            message: "harness missing 'name' field".to_string(),
        })?
        .to_string();

    let build_packages = json
        .get("build_packages")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let runtime_packages = json
        .get("runtime_packages")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let build_env_vars = json
        .get("build_env_vars")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let build_cmd = json
        .get("build_cmd")
        .and_then(|v| v.as_str())
        .map(String::from);

    let matchers = json
        .get("matches_project_if_any")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_matcher).collect())
        .unwrap_or_default();

    let priority = json
        .get("matches_project_priority")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);

    Ok(HarnessSpec {
        name,
        build_packages,
        runtime_packages,
        build_env_vars,
        build_cmd,
        matchers,
        priority,
    })
}

/// Parse a single matcher entry from `matches_project_if_any`.
fn parse_matcher(value: &serde_json::Value) -> Option<HarnessMatcher> {
    let obj = value.as_object()?;

    let file_regexes = obj
        .get("file_regexes")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let build_package_if_any = obj
        .get("build_package_if_any")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    let runtime_package_if_any = obj
        .get("runtime_package_if_any")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    Some(HarnessMatcher {
        file_regexes,
        build_package_if_any,
        runtime_package_if_any,
    })
}

/// Match harnesses against a project directory.
///
/// Returns the highest-priority harness whose `matches_project_if_any`
/// entries have at least one matcher where ALL `file_regexes` files exist
/// in the project. When priorities are equal, the first match wins
/// (directory listing order).
pub fn match_harness<'a>(
    harnesses: &'a [HarnessSpec],
    project_dir: &Path,
) -> Option<&'a HarnessSpec> {
    let mut best: Option<&HarnessSpec> = None;

    for harness in harnesses {
        if harness_matches(harness, project_dir)
            && (best.is_none() || harness.priority > best.unwrap().priority)
        {
            best = Some(harness);
        }
    }

    if let Some(h) = best {
        tracing::info!(
            harness = %h.name,
            priority = h.priority,
            "harness matched project"
        );
    }

    best
}

/// Check if a harness matches a project directory.
fn harness_matches(harness: &HarnessSpec, project_dir: &Path) -> bool {
    // A harness with no matchers never matches
    if harness.matchers.is_empty() {
        return false;
    }

    // ANY matcher must match (OR logic across matchers)
    harness
        .matchers
        .iter()
        .any(|m| matcher_matches(m, project_dir))
}

/// Check if a single matcher matches a project directory.
///
/// ALL `file_regexes` files must exist (AND logic within a matcher).
fn matcher_matches(matcher: &HarnessMatcher, project_dir: &Path) -> bool {
    if matcher.file_regexes.is_empty() {
        return false;
    }

    matcher.file_regexes.keys().all(|filename| {
        let path = project_dir.join(filename);
        path.exists()
    })
}

/// Expand template variables in a harness's `build_env_vars`.
///
/// Currently supports:
/// - `{<prefix>-cache-home}` → resolved state wiring directory path
///
/// For example, the Rust harness uses `{cargo-cache-home}` which resolves
/// to the state directory provisioned for `CARGO_HOME`.
pub fn expand_env_vars(
    harness: &HarnessSpec,
    state_wirings: &[StateWiring],
    state_root: &Path,
) -> Vec<(String, String)> {
    harness
        .build_env_vars
        .iter()
        .map(|(key, value)| {
            let expanded = expand_template(value, state_wirings, state_root);
            (key.clone(), expanded)
        })
        .collect()
}

/// Expand `{prefix-cache-home}` template variables in a string.
fn expand_template(template: &str, state_wirings: &[StateWiring], state_root: &Path) -> String {
    let mut result = template.to_string();

    for wiring in state_wirings {
        let placeholder = format!("{{{}-cache-home}}", wiring.prefix);
        if result.contains(&placeholder) {
            let resolved = state_root.join(&wiring.prefix);
            result = result.replace(&placeholder, &resolved.to_string_lossy());
        }
    }

    result
}

/// Collect additional packages from conditional matchers that matched.
///
/// When a harness matches a project, its conditional `build_package_if_any`
/// and `runtime_package_if_any` entries are checked. Since `file_predicates`
/// evaluation is deferred, this returns only the package names that were
/// declared (for informational purposes) without checking predicates.
pub fn collect_conditional_packages(harness: &HarnessSpec, project_dir: &Path) -> Vec<String> {
    let packages = Vec::new();

    for matcher in &harness.matchers {
        if !matcher_matches(matcher, project_dir) {
            continue;
        }

        // Log conditional packages (we can't evaluate predicates yet)
        for pkg in matcher.build_package_if_any.keys() {
            tracing::debug!(
                package = %pkg,
                harness = %harness.name,
                "conditional build package declared (predicate evaluation deferred)"
            );
        }
        for pkg in matcher.runtime_package_if_any.keys() {
            tracing::debug!(
                package = %pkg,
                harness = %harness.name,
                "conditional runtime package declared (predicate evaluation deferred)"
            );
        }
    }

    packages
}

/// Resolve a full harness match: expand env vars and collect metadata.
pub fn resolve_match(
    harness: &HarnessSpec,
    state_wirings: &[StateWiring],
    state_root: &Path,
) -> HarnessMatch {
    let env_vars = expand_env_vars(harness, state_wirings, state_root);

    HarnessMatch {
        harness: harness.clone(),
        env_vars,
    }
}

/// Return all harness directories found inside a path.
///
/// Checks both `harnesses/` subdirectory and the path directly.
pub fn find_harnesses_dir(base: &Path) -> Option<PathBuf> {
    let sub = base.join("harnesses");
    if sub.is_dir() {
        return Some(sub);
    }
    // Check if base itself contains harness.ncl subdirs
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            if entry.path().join("harness.ncl").exists() {
                return Some(base.to_path_buf());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parse_rust_harness_json() {
        let json = serde_json::json!({
            "ty": "Harness",
            "name": "rust",
            "build_packages": ["gcc", "rust", "binutils"],
            "build_env_vars": {
                "CC": "gcc",
                "CARGO_BUILD_BUILD_DIR": "{cargo-cache-home}/build"
            },
            "build_cmd": "cargo build --release",
            "matches_project_if_any": [
                {
                    "file_regexes": { "Cargo.toml": "*" },
                    "build_package_if_any": {
                        "protobuf": [{ "file_predicates": { "Cargo.toml": ".workspace.dependencies.\"prost-build\"" } }]
                    }
                }
            ]
        });

        let spec = parse_harness_json(&json, Path::new("test")).unwrap();
        assert_eq!(spec.name, "rust");
        assert_eq!(spec.build_packages, vec!["gcc", "rust", "binutils"]);
        assert_eq!(spec.build_env_vars.get("CC").unwrap(), "gcc");
        assert_eq!(spec.build_cmd.as_deref(), Some("cargo build --release"));
        assert_eq!(spec.matchers.len(), 1);
        assert!(spec.matchers[0].file_regexes.contains_key("Cargo.toml"));
        assert!(
            spec.matchers[0]
                .build_package_if_any
                .contains_key("protobuf")
        );
    }

    #[test]
    fn matcher_checks_file_existence() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();

        let matcher = HarnessMatcher {
            file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
            build_package_if_any: HashMap::new(),
            runtime_package_if_any: HashMap::new(),
        };

        assert!(matcher_matches(&matcher, tmp.path()));

        // Non-existent file
        let matcher2 = HarnessMatcher {
            file_regexes: HashMap::from([("go.mod".to_string(), "*".to_string())]),
            build_package_if_any: HashMap::new(),
            runtime_package_if_any: HashMap::new(),
        };

        assert!(!matcher_matches(&matcher2, tmp.path()));
    }

    #[test]
    fn matcher_requires_all_files() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("go.mod"), "module test").unwrap();
        // go.sum does NOT exist

        let matcher = HarnessMatcher {
            file_regexes: HashMap::from([
                ("go.mod".to_string(), "*".to_string()),
                ("go.sum".to_string(), "*".to_string()),
            ]),
            build_package_if_any: HashMap::new(),
            runtime_package_if_any: HashMap::new(),
        };

        assert!(!matcher_matches(&matcher, tmp.path()));

        // Now create go.sum
        fs::write(tmp.path().join("go.sum"), "").unwrap();
        assert!(matcher_matches(&matcher, tmp.path()));
    }

    #[test]
    fn harness_matches_any_matcher() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();

        let harness = HarnessSpec {
            name: "test".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![
                HarnessMatcher {
                    file_regexes: HashMap::from([("go.mod".to_string(), "*".to_string())]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                },
                HarnessMatcher {
                    file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                },
            ],
        };

        assert!(harness_matches(&harness, tmp.path()));
    }

    #[test]
    fn no_matchers_never_matches() {
        let tmp = TempDir::new().unwrap();

        let harness = HarnessSpec {
            name: "shell".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![],
        };

        assert!(!harness_matches(&harness, tmp.path()));
    }

    #[test]
    fn template_expansion() {
        let state_root = Path::new("/project/.gleisner/state");
        let wirings = vec![StateWiring {
            env_var: "CARGO_HOME".to_string(),
            prefix: "cargo".to_string(),
            package: "rust".to_string(),
        }];

        let result = expand_template("{cargo-cache-home}/build", &wirings, state_root);
        assert_eq!(result, "/project/.gleisner/state/cargo/build");
    }

    #[test]
    fn template_expansion_no_match() {
        let state_root = Path::new("/project/.gleisner/state");
        let wirings = vec![];

        let result = expand_template("plain-value", &wirings, state_root);
        assert_eq!(result, "plain-value");
    }

    #[test]
    fn expand_env_vars_full() {
        let state_root = Path::new("/project/.gleisner/state");
        let wirings = vec![StateWiring {
            env_var: "CARGO_HOME".to_string(),
            prefix: "cargo".to_string(),
            package: "rust".to_string(),
        }];

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::from([
                ("CC".to_string(), "gcc".to_string()),
                (
                    "CARGO_BUILD_BUILD_DIR".to_string(),
                    "{cargo-cache-home}/build".to_string(),
                ),
            ]),
            build_cmd: None,
            priority: 0,
            matchers: vec![],
        };

        let vars = expand_env_vars(&harness, &wirings, state_root);

        let cc = vars.iter().find(|(k, _)| k == "CC").unwrap();
        assert_eq!(cc.1, "gcc");

        let build_dir = vars
            .iter()
            .find(|(k, _)| k == "CARGO_BUILD_BUILD_DIR")
            .unwrap();
        assert_eq!(build_dir.1, "/project/.gleisner/state/cargo/build");
    }

    #[test]
    fn match_harness_selects_first() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();
        fs::write(tmp.path().join("Makefile"), "all:").unwrap();

        let harnesses = vec![
            HarnessSpec {
                name: "rust".to_string(),
                build_packages: vec!["rust".to_string()],
                runtime_packages: vec![],
                build_env_vars: HashMap::new(),
                build_cmd: None,
                priority: 0,
                matchers: vec![HarnessMatcher {
                    file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                }],
            },
            HarnessSpec {
                name: "make".to_string(),
                build_packages: vec!["make".to_string()],
                runtime_packages: vec![],
                build_env_vars: HashMap::new(),
                build_cmd: None,
                priority: 0,
                matchers: vec![HarnessMatcher {
                    file_regexes: HashMap::from([("Makefile".to_string(), "*".to_string())]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                }],
            },
        ];

        let matched = match_harness(&harnesses, tmp.path());
        // Same priority — first match wins
        assert_eq!(matched.unwrap().name, "rust");
    }

    #[test]
    fn priority_wins_over_order() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("package-lock.json"), "{}").unwrap();
        fs::write(tmp.path().join("pnpm-lock.yaml"), "").unwrap();
        fs::write(tmp.path().join("pnpm-workspace.yaml"), "").unwrap();

        let harnesses = vec![
            HarnessSpec {
                name: "npm".to_string(),
                build_packages: vec!["base".to_string()],
                runtime_packages: vec![],
                build_env_vars: HashMap::new(),
                build_cmd: None,
                priority: 0,
                matchers: vec![HarnessMatcher {
                    file_regexes: HashMap::from([(
                        "package-lock.json".to_string(),
                        "*".to_string(),
                    )]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                }],
            },
            HarnessSpec {
                name: "pnpm".to_string(),
                build_packages: vec!["pnpm".to_string()],
                runtime_packages: vec![],
                build_env_vars: HashMap::new(),
                build_cmd: None,
                priority: 10,
                matchers: vec![HarnessMatcher {
                    file_regexes: HashMap::from([
                        ("pnpm-lock.yaml".to_string(), "*".to_string()),
                        ("pnpm-workspace.yaml".to_string(), "*".to_string()),
                    ]),
                    build_package_if_any: HashMap::new(),
                    runtime_package_if_any: HashMap::new(),
                }],
            },
        ];

        let matched = match_harness(&harnesses, tmp.path());
        // pnpm should win due to higher priority, even though npm is listed first
        assert_eq!(matched.unwrap().name, "pnpm");
    }

    #[test]
    fn find_harnesses_dir_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let harnesses = tmp.path().join("harnesses");
        fs::create_dir(&harnesses).unwrap();

        assert_eq!(find_harnesses_dir(tmp.path()), Some(harnesses));
    }
}
