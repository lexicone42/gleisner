//! Single-package Nickel evaluation with shared stdlib and virtual import injection.
//!
//! Evaluates one package's `build.ncl` at a time, replacing imports to
//! already-evaluated dependencies with their pre-computed results.
//!
//! # Architecture
//!
//! ```text
//! EvalContext (shared, created once)
//! ├── base CacheHub (stdlib loaded, import paths configured)
//! ├── stdlib stubs (minimal.ncl, config.ncl — lightweight contract replacements)
//! └── package stubs (all packages → trivial records, prevent cascading loads)
//!
//! Per-package:
//! 1. clone_for_package() — shallow clone of base CacheHub
//! 2. Inject dep results as Nickel-syntax virtual files
//! 3. Re-inject self-stub (breaks circular self-imports)
//! 4. prepare_eval_only → eval_full_for_export
//! ```
//!
//! The Nickel stdlib is loaded once into a `CacheHub` and cloned for
//! each package evaluation via `clone_for_eval()`. This avoids the
//! ~4GB per-package cost of reloading the stdlib from scratch.
//!
//! For shared imports like `minimal.ncl`, we inject a lightweight stub
//! that preserves record shapes and defaults but replaces expensive
//! `std.contract.custom` validators with `Dyn`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nickel_lang_core::cache::{CacheHub, InputFormat, SourcePath, normalize_path};
use nickel_lang_core::error::NullReporter;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::eval::{VirtualMachine, VmContext};
use nickel_lang_core::serialize::{self, ExportFormat};

use crate::error::ForgeError;
use crate::store::{Store, StoreRef};

/// Result of evaluating a single package.
#[derive(Debug)]
pub struct EvalResult {
    /// The fully evaluated JSON output.
    pub json: serde_json::Value,
    /// The content-addressed store reference.
    pub store_ref: StoreRef,
}

/// Shared evaluation context with Nickel stdlib and virtual import stubs.
///
/// Created once, then `clone_for_package()` for each package evaluation.
pub struct EvalContext {
    /// Base `CacheHub` with stdlib loaded and import paths configured.
    base_cache: CacheHub,
    /// Normalized (path, content) pairs for stdlib-level stubs.
    stdlib_stubs: Vec<(PathBuf, String)>,
    /// Pre-computed (`normalized_path`, `stub_content`) for every package.
    package_stubs: Vec<(PathBuf, String)>,
}

impl EvalContext {
    /// Create a new evaluation context, loading the Nickel stdlib.
    pub fn new(import_paths: &[&Path]) -> Result<Self, ForgeError> {
        let mut cache = CacheHub::new();

        if !import_paths.is_empty() {
            cache
                .sources
                .add_import_paths(import_paths.iter().map(|p| p.to_path_buf()));
        }

        cache.load_stdlib().map_err(|e| ForgeError::NickelEval {
            package: "<stdlib>".to_string(),
            message: format!("failed to load Nickel stdlib: {e:?}"),
        })?;

        let mut stdlib_stubs = Vec::new();

        for import_path in import_paths {
            let minimal_path = import_path.join("minimal.ncl");
            if minimal_path.exists() {
                let norm = normalize_path(&minimal_path).map_err(|e| ForgeError::NickelEval {
                    package: "<stub>".to_string(),
                    message: format!("failed to normalize {}: {e}", minimal_path.display()),
                })?;
                stdlib_stubs.push((norm, MINIMAL_NCL_STUB.to_string()));
            }

            let config_path = import_path.join("config.ncl");
            if config_path.exists() {
                let norm = normalize_path(&config_path).map_err(|e| ForgeError::NickelEval {
                    package: "<stub>".to_string(),
                    message: format!("failed to normalize {}: {e}", config_path.display()),
                })?;
                stdlib_stubs.push((norm, CONFIG_NCL_STUB.to_string()));
            }
        }

        Ok(Self {
            base_cache: cache,
            stdlib_stubs,
            package_stubs: Vec::new(),
        })
    }

    /// Pre-register all packages in the directory as stub virtual imports.
    pub fn register_packages_dir(&mut self, pkgs_dir: &Path) -> Result<(), ForgeError> {
        let entries = std::fs::read_dir(pkgs_dir).map_err(|e| ForgeError::NickelEval {
            package: "<packages>".to_string(),
            message: format!("failed to read {}: {e}", pkgs_dir.display()),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| ForgeError::NickelEval {
                package: "<packages>".to_string(),
                message: format!("failed to read dir entry: {e}"),
            })?;

            if !entry.path().is_dir() {
                continue;
            }

            let build_file = entry.path().join("build.ncl");
            if !build_file.exists() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            let norm = normalize_path(&build_file).map_err(|e| ForgeError::NickelEval {
                package: "<packages>".to_string(),
                message: format!("failed to normalize {}: {e}", build_file.display()),
            })?;

            let stub = format!(r#"{{ name = "{name}", _stub = true, ty = 'Builder }}"#);
            self.package_stubs.push((norm, stub));
        }

        Ok(())
    }

    /// Clone the base cache and inject all stubs for a single package.
    fn clone_for_package(&self) -> CacheHub {
        let mut cache = self.base_cache.clone_for_eval();

        for (path, content) in &self.stdlib_stubs {
            cache.sources.add_string(
                SourcePath::Path(path.clone(), InputFormat::Nickel),
                content.clone(),
            );
        }

        for (path, content) in &self.package_stubs {
            cache.sources.add_string(
                SourcePath::Path(path.clone(), InputFormat::Nickel),
                content.clone(),
            );
        }

        cache
    }
}

/// Evaluate a single package's `build.ncl`, substituting dependencies.
pub fn eval_package(
    build_file: &Path,
    dep_results: &HashMap<String, serde_json::Value>,
    store: &Store,
    ctx: &EvalContext,
) -> Result<EvalResult, ForgeError> {
    let package_name = build_file.parent().and_then(|p| p.file_name()).map_or_else(
        || "unknown".to_string(),
        |n| n.to_string_lossy().to_string(),
    );

    let mut cache = ctx.clone_for_package();

    let main_id = cache
        .sources
        .add_file(build_file.as_os_str(), InputFormat::Nickel)
        .map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("failed to load {}: {e}", build_file.display()),
        })?;

    let pkgs_dir = build_file.parent().and_then(|p| p.parent());

    if let Some(pkgs_dir) = pkgs_dir {
        // Re-inject self-import stub to break circular imports.
        // add_file above overwrote the package's own stub entry (same
        // normalized path), so self-imports would recurse infinitely.
        let self_path = normalize_path(build_file).map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("failed to normalize self path: {e}"),
        })?;
        let self_stub = format!(r#"{{ name = "{package_name}", _stub = true, ty = 'Builder }}"#);
        cache
            .sources
            .add_string(SourcePath::Path(self_path, InputFormat::Nickel), self_stub);

        // Inject pre-evaluated dep results (overriding package stubs)
        for (dep_name, json) in dep_results {
            let dep_path =
                normalize_path(pkgs_dir.join(dep_name).join("build.ncl")).map_err(|e| {
                    ForgeError::NickelEval {
                        package: package_name.clone(),
                        message: format!("failed to normalize dep path for {dep_name}: {e}"),
                    }
                })?;

            let flat = flatten_for_injection(json);
            let nickel_content = json_to_nickel(&flat);
            cache.sources.add_string(
                SourcePath::Path(dep_path, InputFormat::Nickel),
                nickel_content,
            );
        }
    }

    // Build VM context with the prepared cache. Skip typechecking
    // (prepare_eval_only) because pre-evaluated deps are already type-safe.
    let mut vm_ctx: VmContext<CacheHub, CacheImpl> =
        VmContext::new(cache, std::io::sink(), NullReporter {});

    let prepared = vm_ctx
        .prepare_eval_only(main_id)
        .map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("{e:?}"),
        })?;

    let mut vm = VirtualMachine::new(&mut vm_ctx);
    let result = vm
        .eval_full_for_export(prepared)
        .map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("{e:?}"),
        })?;

    let json_str =
        serialize::to_string(ExportFormat::Json, &result).map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("serialization failed: {e:?}"),
        })?;

    let json: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("JSON parse of Nickel output failed: {e}"),
        })?;

    let store_ref = store.put(&json)?;
    Ok(EvalResult { json, store_ref })
}

/// Strip transitive dep trees from a result before injection.
///
/// Package results recursively embed their full dep trees in `build_deps`
/// and `runtime_deps`. A single gcc result is 136 MB because it nests
/// all transitive deps. Downstream packages only need the top-level
/// record (name, ty, outputs, attrs, etc.) — not the full dep chains.
///
/// This replaces `build_deps` and `runtime_deps` arrays with flattened
/// versions: each entry that has a `name` field is replaced with a
/// `{ name, ty, _stub = true }` stub. Non-package entries (Source,
/// Local, etc.) are kept as-is.
pub fn flatten_for_injection(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if k == "build_deps" || k == "runtime_deps" {
                    // Flatten: keep non-package entries, stub package entries
                    if let serde_json::Value::Array(arr) = v {
                        let flat: Vec<serde_json::Value> = arr
                            .iter()
                            .map(|entry| {
                                if let Some(obj) = entry.as_object() {
                                    if obj.contains_key("build_deps") || obj.contains_key("_stub") {
                                        // Package entry → stub it
                                        let name = obj
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("unknown");
                                        serde_json::json!({
                                            "name": name,
                                            "ty": "Builder",
                                            "_stub": true
                                        })
                                    } else {
                                        // Non-package entry (Source, Local, etc.) → keep as-is
                                        entry.clone()
                                    }
                                } else {
                                    entry.clone()
                                }
                            })
                            .collect();
                        out.insert(k.clone(), serde_json::Value::Array(flat));
                    } else {
                        out.insert(k.clone(), v.clone());
                    }
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Convert a JSON value to a Nickel record literal string.
fn json_to_nickel(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            let escaped = s
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            format!("\"{escaped}\"")
        }
        serde_json::Value::Array(arr) => {
            let elements: Vec<String> = arr.iter().map(json_to_nickel).collect();
            format!("[{}]", elements.join(", "))
        }
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let fields: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let key = if k.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        k.clone()
                    } else {
                        format!("\"{k}\"")
                    };
                    format!("  {key} = {}", json_to_nickel(v))
                })
                .collect();
            format!("{{\n{},\n}}", fields.join(",\n"))
        }
    }
}

/// Lightweight stub for `minimal.ncl`.
const MINIMAL_NCL_STUB: &str = r"
{
    BuildSpec = {
        ty = 'Builder,
        name,
        build_deps,
        runtime_deps | optional,
        needs | optional,
        attrs | optional,
        cmd | optional,
        cmds | optional,
        build_args | optional,
        __magic_buildspec_id | optional,
        prebuilt | optional,
        target | optional,
        replace_on_cycle | optional,
        outputs = {},
        tests | optional,
        ..
    },
    build = fun spec => spec,
    Output = Dyn,
    OutputLib = { ty = 'OutputLib, glob, allow_data | optional, .. },
    OutputBin = { ty = 'OutputBin, glob, .. },
    OutputData = { ty = 'OutputData, glob, allow_executable | optional, .. },
    RuntimeDep = Dyn,
    Input = Dyn,
    HostPath = { ty = 'Path, path, .. },
    Source = {
        ty = 'Source, file | optional, url | optional, sha256 | optional,
        extract | optional, strip_prefix | optional, ..
    },
    Local = { ty = 'Local, file, .. },
    Subset = { ty = 'Subset, from, outputs, .. },
    subsetOf = fun s__ o__ => { from = s__, outputs = o__, ty = 'Subset },
    Attrs = Dyn,
    Needs = Dyn,
    Profile = {
        ty = 'Profile, name, from_profile | optional, packages | optional,
        env_vars | optional, patch | optional, patches | optional, ..
    },
    profile = fun spec => spec,
    Layer = { ty = 'Layer, builds, profiles, harnesses, .. },
    layer = fun spec => spec,
    UpstreamPkg = { ty = 'Upstream, name, .. },
    upstream = fun n => { name = n, ty = 'Upstream },
    Test = {
        ty = 'Test, class, test_deps | optional, cmd | optional, cmds | optional, ..
    },
    standaloneTest = fun c__ => { class = 'Standalone, cmd = c__, ty = 'Test },
    buildTest = fun c__ => { class = 'Build, cmd = c__, ty = 'Test },
    HarnessMatcherEntry = { file_regexes | optional, .. },
    Harness = {
        ty = 'Harness, name, build_packages | optional, runtime_packages | optional,
        build_env_vars | optional, build_cmd | optional, build_cmds_cmd | optional,
        project_matchers | optional, ..
    },
    harness = fun spec => spec,
    Target = { os, arch, .. },
}
";

/// Lightweight stub for `config.ncl`.
const CONFIG_NCL_STUB: &str = r"
{
    target = {
        os = 'Linux,
        arch = 'Amd64,
    },
}
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_to_nickel_primitives() {
        assert_eq!(json_to_nickel(&serde_json::json!(null)), "null");
        assert_eq!(json_to_nickel(&serde_json::json!(true)), "true");
        assert_eq!(json_to_nickel(&serde_json::json!(42)), "42");
        assert_eq!(json_to_nickel(&serde_json::json!("hello")), "\"hello\"");
    }

    #[test]
    fn json_to_nickel_record() {
        let json = serde_json::json!({"name": "test", "value": 42});
        let nickel = json_to_nickel(&json);
        assert!(nickel.contains("name = \"test\""));
        assert!(nickel.contains("value = 42"));
    }

    #[test]
    fn json_to_nickel_escapes_strings() {
        let json = serde_json::json!("line1\nline2");
        assert_eq!(json_to_nickel(&json), "\"line1\\nline2\"");
    }

    #[test]
    fn eval_simple_nickel_file() {
        let dir = tempfile::tempdir().unwrap();
        let build_file = dir.path().join("build.ncl");
        std::fs::write(
            &build_file,
            r#"{ name = "hello", version = "1.0", value = 42 }"#,
        )
        .unwrap();

        let store = Store::new(dir.path().join("store")).unwrap();
        let ctx = EvalContext::new(&[]).unwrap();

        let result = eval_package(&build_file, &HashMap::new(), &store, &ctx).unwrap();

        assert_eq!(result.json["name"], "hello");
        assert_eq!(result.json["version"], "1.0");
        assert_eq!(result.json["value"], 42);
    }

    #[test]
    fn eval_with_import_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let pkgs = dir.path().join("pkgs");

        std::fs::create_dir_all(pkgs.join("dep")).unwrap();
        std::fs::write(
            pkgs.join("dep/build.ncl"),
            r#"{ name = "dep", value = 100 }"#,
        )
        .unwrap();

        std::fs::create_dir_all(pkgs.join("main")).unwrap();
        std::fs::write(
            pkgs.join("main/build.ncl"),
            r#"let dep = import "../dep/build.ncl" in
            { name = "main", dep_value = dep.value }"#,
        )
        .unwrap();

        let store = Store::new(dir.path().join("store")).unwrap();
        let ctx = EvalContext::new(&[]).unwrap();

        let mut dep_results = HashMap::new();
        dep_results.insert(
            "dep".to_string(),
            serde_json::json!({"name": "dep", "value": 100}),
        );

        let result =
            eval_package(&pkgs.join("main/build.ncl"), &dep_results, &store, &ctx).unwrap();

        assert_eq!(result.json["name"], "main");
        assert_eq!(result.json["dep_value"], 100);
    }

    #[test]
    fn eval_shared_context_multiple_packages() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = EvalContext::new(&[]).unwrap();
        let store = Store::new(dir.path().join("store")).unwrap();

        let file_a = dir.path().join("a.ncl");
        std::fs::write(&file_a, r#"{ name = "a", value = 1 }"#).unwrap();

        let file_b = dir.path().join("b.ncl");
        std::fs::write(&file_b, r#"{ name = "b", value = 2 }"#).unwrap();

        let result_a = eval_package(&file_a, &HashMap::new(), &store, &ctx).unwrap();
        let result_b = eval_package(&file_b, &HashMap::new(), &store, &ctx).unwrap();

        assert_eq!(result_a.json["name"], "a");
        assert_eq!(result_b.json["name"], "b");
        assert_ne!(result_a.store_ref.hash, result_b.store_ref.hash);
    }
}
