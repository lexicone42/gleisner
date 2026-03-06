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
            && best.as_ref().is_none_or(|b| harness.priority > b.priority)
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
/// and `runtime_package_if_any` entries are checked against file contents.
///
/// Each conditional entry maps a package name to an array of predicate sets.
/// A package is included if ANY predicate set matches (OR across entries).
/// Within a predicate set, `file_predicates` maps filename → expression.
/// ALL file predicates in a set must match (AND within a set).
///
/// Supported expression syntax (subset of jq):
/// - `.path.to.key` — check if the key exists
/// - `.path.to.key."quoted-key"` — dotted path with quoted segments
/// - `.path | contains("value")` — check if array contains a string
///
/// Complex expressions (boolean `and`, `not`, chained pipes) are logged
/// as warnings and treated as non-matching.
pub fn collect_conditional_packages(harness: &HarnessSpec, project_dir: &Path) -> Vec<String> {
    let mut packages = Vec::new();

    for matcher in &harness.matchers {
        if !matcher_matches(matcher, project_dir) {
            continue;
        }

        // Evaluate conditional build packages
        for (pkg, predicates) in &matcher.build_package_if_any {
            if evaluate_conditional(pkg, predicates, project_dir, &harness.name)
                && !packages.contains(pkg)
            {
                packages.push(pkg.clone());
                tracing::info!(
                    package = %pkg,
                    harness = %harness.name,
                    "conditional build package matched"
                );
            }
        }

        // Evaluate conditional runtime packages
        for (pkg, predicates) in &matcher.runtime_package_if_any {
            if evaluate_conditional(pkg, predicates, project_dir, &harness.name)
                && !packages.contains(pkg)
            {
                packages.push(pkg.clone());
                tracing::info!(
                    package = %pkg,
                    harness = %harness.name,
                    "conditional runtime package matched"
                );
            }
        }
    }

    packages
}

/// Evaluate a conditional package entry.
///
/// `predicates` is a JSON array of predicate sets. The package matches
/// if ANY set matches (OR logic across array entries).
fn evaluate_conditional(
    pkg: &str,
    predicates: &serde_json::Value,
    project_dir: &Path,
    harness_name: &str,
) -> bool {
    let Some(arr) = predicates.as_array() else {
        tracing::warn!(
            package = %pkg,
            harness = %harness_name,
            "conditional predicates is not an array — skipping"
        );
        return false;
    };

    // ANY predicate set must match (OR)
    arr.iter().any(|pred_set| {
        let Some(obj) = pred_set.as_object() else {
            return false;
        };
        let Some(file_preds) = obj.get("file_predicates").and_then(|v| v.as_object()) else {
            return false;
        };

        // ALL file predicates must match (AND)
        file_preds.iter().all(|(filename, expr)| {
            let Some(expr_str) = expr.as_str() else {
                return false;
            };
            evaluate_file_predicate(filename, expr_str, project_dir, pkg, harness_name)
        })
    })
}

/// Evaluate a single file predicate: parse the file, apply the expression.
fn evaluate_file_predicate(
    filename: &str,
    expr: &str,
    project_dir: &Path,
    pkg: &str,
    harness_name: &str,
) -> bool {
    let file_path = project_dir.join(filename);

    // Read and parse the file
    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => return false, // File doesn't exist → predicate fails
    };

    // Parse based on file extension
    let parsed = if filename.ends_with(".toml") {
        match toml::from_str::<serde_json::Value>(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(file = %filename, error = %e, "failed to parse TOML");
                return false;
            }
        }
    } else if filename.ends_with(".json") {
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(file = %filename, error = %e, "failed to parse JSON");
                return false;
            }
        }
    } else {
        tracing::debug!(
            file = %filename,
            "unsupported file type for predicate evaluation (expected .toml or .json)"
        );
        return false;
    };

    // Evaluate the expression against parsed content
    match eval_jq_expr(&parsed, expr) {
        Some(true) => true,
        Some(false) => false,
        None => {
            tracing::debug!(
                package = %pkg,
                harness = %harness_name,
                file = %filename,
                expr = %expr,
                "predicate expression not supported — treating as non-matching"
            );
            false
        }
    }
}

/// Evaluate a subset of jq-style expressions against a JSON value.
///
/// Returns:
/// - `Some(true)` — expression matched
/// - `Some(false)` — expression evaluated but didn't match
/// - `None` — expression syntax not supported
///
/// Supported expressions:
/// - `.path.to.key` — returns true if key exists (not null)
/// - `.path.to."quoted-key"` — dotted path with quoted segments
/// - `.path.to.key | contains("value")` — check if value/array contains string
fn eval_jq_expr(value: &serde_json::Value, expr: &str) -> Option<bool> {
    let expr = expr.trim();

    // Reject complex top-level boolean expressions we can't handle.
    // But allow " or " inside any() — that's just value enumeration.
    let top_level_expr = if let Some(pipe_pos) = expr.find('|') {
        &expr[..pipe_pos]
    } else {
        expr
    };
    if top_level_expr.contains(" and ") || top_level_expr.contains(" or ") || expr.contains("| not")
    {
        return None;
    }

    // Split on pipe for `.path | contains("val")`
    if let Some((path_part, filter_part)) = expr.split_once('|') {
        let path_part = path_part.trim();
        let filter_part = filter_part.trim();

        let navigated = match navigate_path(value, path_part) {
            Some(v) => v,
            None => return Some(false), // Path doesn't exist
        };

        // contains("value")
        if let Some(inner) = filter_part
            .strip_prefix("contains(\"")
            .and_then(|s| s.strip_suffix("\")"))
        {
            return Some(json_contains(navigated, inner));
        }

        // any(. == "value" or . == "other")
        if filter_part.starts_with("any(") {
            // Parse `any(. == "a" or . == "b" or . == "c")`
            let inner = filter_part
                .strip_prefix("any(")
                .and_then(|s| s.strip_suffix(')'));
            if let Some(inner) = inner {
                let values: Vec<&str> = inner
                    .split(" or ")
                    .filter_map(|part| {
                        part.trim()
                            .strip_prefix(". == \"")
                            .and_then(|s| s.strip_suffix('"'))
                    })
                    .collect();
                if !values.is_empty() {
                    let arr = navigated.as_array();
                    return Some(arr.is_some_and(|a| {
                        a.iter()
                            .any(|elem| values.iter().any(|v| elem.as_str() == Some(v)))
                    }));
                }
            }
            return None;
        }

        return None; // Unsupported filter
    }

    // Simple path navigation — check if key exists
    match navigate_path(value, expr) {
        Some(v) => Some(!v.is_null()),
        None => Some(false), // Path doesn't exist
    }
}

/// Navigate a dotted path like `.workspace.dependencies."prost-build"`.
fn navigate_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let path = path.trim().strip_prefix('.')?;

    let mut current = value;
    let mut remaining = path;

    while !remaining.is_empty() {
        let (key, rest) = if remaining.starts_with('"') {
            // Quoted key: ."some-key".rest
            let end = remaining[1..].find('"')?;
            let key = &remaining[1..=end];
            let rest = remaining[end + 2..].strip_prefix('.').unwrap_or("");
            (key, rest)
        } else {
            // Unquoted key
            match remaining.find('.') {
                Some(dot) => (&remaining[..dot], &remaining[dot + 1..]),
                None => (remaining, ""),
            }
        };

        current = current.get(key)?;
        remaining = rest;
    }

    Some(current)
}

/// Check if a JSON value contains a string.
///
/// For arrays: checks if any element equals the string.
/// For strings: checks if the string contains the substring.
/// For objects: checks if any key equals the string.
fn json_contains(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(needle)),
        serde_json::Value::String(s) => s.contains(needle),
        serde_json::Value::Object(obj) => obj.contains_key(needle),
        _ => false,
    }
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

    // ── jq expression evaluator tests ────────────────────────────

    #[test]
    fn jq_simple_path_exists() {
        let value = serde_json::json!({
            "workspace": {
                "dependencies": {
                    "serde": { "version": "1.0" }
                }
            }
        });

        assert_eq!(
            eval_jq_expr(&value, ".workspace.dependencies.serde"),
            Some(true)
        );
        assert_eq!(
            eval_jq_expr(&value, ".workspace.dependencies.tokio"),
            Some(false)
        );
    }

    #[test]
    fn jq_quoted_key() {
        let value = serde_json::json!({
            "workspace": {
                "dependencies": {
                    "prost-build": { "version": "0.12" }
                }
            }
        });

        assert_eq!(
            eval_jq_expr(&value, r#".workspace.dependencies."prost-build""#),
            Some(true)
        );
        assert_eq!(
            eval_jq_expr(&value, r#".workspace.dependencies."non-existent""#),
            Some(false)
        );
    }

    #[test]
    fn jq_contains_in_array() {
        let value = serde_json::json!({
            "workspace": {
                "dependencies": {
                    "reqwest": {
                        "features": ["native-tls", "json", "gzip"]
                    }
                }
            }
        });

        assert_eq!(
            eval_jq_expr(
                &value,
                r#".workspace.dependencies.reqwest.features | contains("native-tls")"#
            ),
            Some(true)
        );
        assert_eq!(
            eval_jq_expr(
                &value,
                r#".workspace.dependencies.reqwest.features | contains("rustls")"#
            ),
            Some(false)
        );
    }

    #[test]
    fn jq_any_in_array() {
        let value = serde_json::json!({
            "workspace": {
                "dependencies": {
                    "flate2": {
                        "features": ["zlib", "miniz_oxide"]
                    }
                }
            }
        });

        assert_eq!(
            eval_jq_expr(
                &value,
                r#".workspace.dependencies.flate2.features | any(. == "zlib" or . == "zlib-default" or . == "cloudflare_zlib")"#
            ),
            Some(true)
        );
        assert_eq!(
            eval_jq_expr(
                &value,
                r#".workspace.dependencies.flate2.features | any(. == "brotli" or . == "lz4")"#
            ),
            Some(false)
        );
    }

    #[test]
    fn jq_complex_expressions_return_none() {
        let value = serde_json::json!({"a": 1});

        // Boolean and/or/not are not supported
        assert_eq!(
            eval_jq_expr(
                &value,
                ".deps.rustls and (.deps.rustls.features | contains(\"ring\") | not)"
            ),
            None
        );
    }

    #[test]
    fn navigate_path_basic() {
        let value = serde_json::json!({"a": {"b": {"c": 42}}});
        assert_eq!(
            navigate_path(&value, ".a.b.c"),
            Some(&serde_json::json!(42))
        );
        assert_eq!(navigate_path(&value, ".a.b.d"), None);
        assert_eq!(navigate_path(&value, ".x"), None);
    }

    #[test]
    fn navigate_path_quoted() {
        let value = serde_json::json!({"deps": {"my-crate": {"version": "1.0"}}});
        assert_eq!(
            navigate_path(&value, r#".deps."my-crate".version"#),
            Some(&serde_json::json!("1.0"))
        );
    }

    // ── Conditional package evaluation tests ─────────────────────

    #[test]
    fn conditional_package_matches_simple_key() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.dependencies]
prost-build = { version = "0.12" }
serde = "1.0"
"#,
        )
        .unwrap();

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec!["gcc".to_string(), "rust".to_string()],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![HarnessMatcher {
                file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                build_package_if_any: HashMap::from([(
                    "protobuf".to_string(),
                    serde_json::json!([{
                        "file_predicates": {
                            "Cargo.toml": ".workspace.dependencies.\"prost-build\""
                        }
                    }]),
                )]),
                runtime_package_if_any: HashMap::new(),
            }],
        };

        let packages = collect_conditional_packages(&harness, tmp.path());
        assert!(
            packages.contains(&"protobuf".to_string()),
            "protobuf should be included when prost-build is in Cargo.toml deps, got: {packages:?}"
        );
    }

    #[test]
    fn conditional_package_no_match_when_dep_absent() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.dependencies]
serde = "1.0"
tokio = "1.0"
"#,
        )
        .unwrap();

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![HarnessMatcher {
                file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                build_package_if_any: HashMap::from([(
                    "protobuf".to_string(),
                    serde_json::json!([{
                        "file_predicates": {
                            "Cargo.toml": ".workspace.dependencies.\"prost-build\""
                        }
                    }]),
                )]),
                runtime_package_if_any: HashMap::new(),
            }],
        };

        let packages = collect_conditional_packages(&harness, tmp.path());
        assert!(
            packages.is_empty(),
            "no conditional packages when deps don't match, got: {packages:?}"
        );
    }

    #[test]
    fn conditional_package_contains_check() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.dependencies.reqwest]
version = "0.12"
features = ["native-tls", "json"]
"#,
        )
        .unwrap();

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![HarnessMatcher {
                file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                build_package_if_any: HashMap::new(),
                runtime_package_if_any: HashMap::from([(
                    "openssl".to_string(),
                    serde_json::json!([{
                        "file_predicates": {
                            "Cargo.toml": ".workspace.dependencies.reqwest.features | contains(\"native-tls\")"
                        }
                    }]),
                )]),
            }],
        };

        let packages = collect_conditional_packages(&harness, tmp.path());
        assert!(
            packages.contains(&"openssl".to_string()),
            "openssl should be included when reqwest has native-tls feature, got: {packages:?}"
        );
    }

    #[test]
    fn conditional_or_across_predicate_sets() {
        let tmp = TempDir::new().unwrap();
        // Has openssl-sys but NOT native-tls feature on reqwest
        fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.dependencies]
openssl-sys = "0.9"
[workspace.dependencies.reqwest]
version = "0.12"
features = ["rustls-tls"]
"#,
        )
        .unwrap();

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![HarnessMatcher {
                file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                build_package_if_any: HashMap::new(),
                runtime_package_if_any: HashMap::from([(
                    "openssl".to_string(),
                    serde_json::json!([
                        { "file_predicates": { "Cargo.toml": ".workspace.dependencies.reqwest.features | contains(\"native-tls\")" } },
                        { "file_predicates": { "Cargo.toml": ".workspace.dependencies.\"openssl-sys\"" } }
                    ]),
                )]),
            }],
        };

        let packages = collect_conditional_packages(&harness, tmp.path());
        assert!(
            packages.contains(&"openssl".to_string()),
            "openssl should match via second predicate (openssl-sys), got: {packages:?}"
        );
    }

    #[test]
    fn conditional_skips_unmatched_matchers() {
        let tmp = TempDir::new().unwrap();
        // No Cargo.toml — matcher won't match, so conditionals shouldn't run
        fs::write(tmp.path().join("go.mod"), "module test").unwrap();

        let harness = HarnessSpec {
            name: "rust".to_string(),
            build_packages: vec![],
            runtime_packages: vec![],
            build_env_vars: HashMap::new(),
            build_cmd: None,
            priority: 0,
            matchers: vec![HarnessMatcher {
                file_regexes: HashMap::from([("Cargo.toml".to_string(), "*".to_string())]),
                build_package_if_any: HashMap::from([(
                    "protobuf".to_string(),
                    serde_json::json!([{"file_predicates": {"Cargo.toml": ".workspace.dependencies.\"prost-build\""}}]),
                )]),
                runtime_package_if_any: HashMap::new(),
            }],
        };

        let packages = collect_conditional_packages(&harness, tmp.path());
        assert!(
            packages.is_empty(),
            "no conditionals when matcher doesn't match"
        );
    }
}
