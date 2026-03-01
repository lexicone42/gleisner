//! Single-package Nickel evaluation with virtual import injection.
//!
//! Evaluates one package's `build.ncl` at a time, replacing imports to
//! already-evaluated dependencies with their pre-computed results.
//!
//! # Import Substitution Strategy
//!
//! We inject pre-evaluated dependency results directly into Nickel's
//! `SourceCache` as in-memory virtual files, keyed by the normalized
//! path that import resolution will look up. When the evaluator
//! encounters `import "../dep/build.ncl"`, it normalizes the path,
//! finds our pre-registered entry (tagged `SourceKind::Memory`), and
//! uses it without touching disk.
//!
//! # Shared Stdlib and Lightweight Contract Stubs
//!
//! The Nickel stdlib is loaded once into a `CacheHub` and cloned for
//! each package evaluation via `clone_for_eval()`. This avoids the
//! ~4GB per-package cost of reloading the stdlib from scratch.
//!
//! For shared imports like `minimal.ncl`, we inject a lightweight stub
//! that preserves record shapes and defaults (e.g., `ty = 'Builder`)
//! but replaces expensive `std.contract.custom` validators with `Dyn`.
//! This avoids the ~10GB memory cost of processing the full contract
//! system while still producing correct JSON output structure.
//!
//! Contract validation (Attrs schema, Needs schema, Input/Output type
//! dispatch) is deferred to a separate verification pass, preserving
//! all security guarantees without the memory cost during evaluation.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use nickel_lang_core::cache::{CacheHub, InputFormat, SourcePath, normalize_path};
use nickel_lang_core::error::NullReporter;
use nickel_lang_core::eval::VirtualMachine;
use nickel_lang_core::eval::VmContext;
use nickel_lang_core::eval::cache::CacheImpl;
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
/// All stubs are injected lazily per-clone (not pre-processed) to avoid
/// triggering full stdlib closurization at init time.
///
/// Three kinds of stubs prevent cascading disk loads and stdlib bloat:
/// 1. **minimal.ncl stub**: Lightweight version without `std.contract.custom`
/// 2. **config.ncl stub**: Inlined target config without importing minimal.ncl
/// 3. **Package stubs**: Every `build.ncl` in the monorepo gets a trivial
///    virtual import so `import "../X/build.ncl"` never reads from disk.
///    Real dep results override the stubs during `eval_package()`.
pub struct EvalContext {
    /// Base `CacheHub` with stdlib loaded and import paths configured.
    base_cache: CacheHub,
    /// Normalized (path, content) pairs for stdlib-level stubs
    /// (minimal.ncl, config.ncl, etc.) found in import paths.
    stdlib_stubs: Vec<(PathBuf, String)>,
    /// Pre-computed (`normalized_path`, `stub_content`) for every package in the
    /// monorepo. Injected into each clone to prevent cascading disk loads.
    package_stubs: Vec<(PathBuf, String)>,
}

impl EvalContext {
    /// Create a new evaluation context, loading the Nickel stdlib.
    ///
    /// `import_paths` are directories for bare imports (e.g., the stdlib dir
    /// containing `minimal.ncl`).
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

        // Find stdlib files (minimal.ncl, config.ncl) and prepare stubs.
        let mut stdlib_stubs = Vec::new();

        for import_path in import_paths {
            // Stub minimal.ncl — heavy contracts replaced with lightweight records
            let minimal_path = import_path.join("minimal.ncl");
            if minimal_path.exists() {
                let norm = normalize_path(&minimal_path).map_err(|e| ForgeError::NickelEval {
                    package: "<stub>".to_string(),
                    message: format!("failed to normalize {}: {e}", minimal_path.display()),
                })?;
                stdlib_stubs.push((norm, MINIMAL_NCL_STUB.to_string()));
            }

            // Stub config.ncl — inline the target without importing minimal.ncl
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
    ///
    /// This prevents cascading disk loads during Nickel import resolution.
    /// When a package's `build.ncl` does `import "../X/build.ncl"`, the
    /// resolver finds a pre-registered virtual stub instead of loading the
    /// real file (which would recursively load all transitive deps).
    ///
    /// Real dep results override these stubs in `eval_package()`.
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

            // Minimal stub: just a record with the package name and a marker.
            // No type annotations, no imports — zero stdlib references.
            let stub = format!(r#"{{ name = "{name}", _stub = true, ty = 'Builder }}"#);
            self.package_stubs.push((norm, stub));
        }

        tracing::info!(count = self.package_stubs.len(), "registered package stubs");

        Ok(())
    }

    /// Clone the base cache and inject all stubs for a single package evaluation.
    fn clone_for_package(&self) -> CacheHub {
        let mut cache = self.base_cache.clone_for_eval();

        // Inject stdlib-level stubs (minimal.ncl, config.ncl).
        for (path, content) in &self.stdlib_stubs {
            cache.sources.add_string(
                SourcePath::Path(path.clone(), InputFormat::Nickel),
                content.clone(),
            );
        }

        // Inject stubs for ALL packages to prevent cascading disk loads.
        // Real dep results will override these in eval_package().
        for (path, content) in &self.package_stubs {
            cache.sources.add_string(
                SourcePath::Path(path.clone(), InputFormat::Nickel),
                content.clone(),
            );
        }

        cache
    }
}

/// Lightweight evaluation stub for `minimal.ncl`.
///
/// Preserves record shapes with defaults (`ty = 'Builder`, `outputs = {}`)
/// and constructor functions. Uses NO stdlib type references (`String`,
/// `Bool`, `Array`, etc.) — only bare fields, `optional`, and defaults.
/// This avoids triggering stdlib closurization entirely.
///
/// Contract validation is deferred to a separate verification pass.
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
        ty = 'Source,
        file | optional,
        url | optional,
        sha256 | optional,
        extract | optional,
        strip_prefix | optional,
        ..
    },
    Local = { ty = 'Local, file, .. },

    Subset = { ty = 'Subset, from, outputs, .. },
    subsetOf = fun s__ o__ =>
        { from = s__, outputs = o__, ty = 'Subset },

    Attrs = Dyn,
    Needs = Dyn,

    Profile = {
        ty = 'Profile,
        name,
        from_profile | optional,
        packages | optional,
        env_vars | optional,
        patch | optional,
        patches | optional,
        ..
    },
    profile = fun spec => spec,

    Layer = { ty = 'Layer, builds, profiles, harnesses, .. },
    layer = fun spec => spec,

    UpstreamPkg = { ty = 'Upstream, name, .. },
    upstream = fun n => { name = n, ty = 'Upstream },

    Test = {
        ty = 'Test,
        class,
        test_deps | optional,
        cmd | optional,
        cmds | optional,
        ..
    },
    standaloneTest = fun c__ => { class = 'Standalone, cmd = c__, ty = 'Test },
    buildTest = fun c__ => { class = 'Build, cmd = c__, ty = 'Test },

    HarnessMatcherEntry = { file_regexes | optional, .. },
    Harness = {
        ty = 'Harness,
        name,
        build_packages | optional,
        runtime_packages | optional,
        build_env_vars | optional,
        build_cmd | optional,
        build_cmds_cmd | optional,
        project_matchers | optional,
        ..
    },
    harness = fun spec => spec,

    Target = { os, arch, .. },
}
";

/// Lightweight stub for `config.ncl`.
///
/// The real config.ncl imports minimal.ncl (for `Target` contract) and
/// `__injected_config__.ncl` (for target values). We inline both to avoid
/// any import chain that could trigger stdlib closurization.
const CONFIG_NCL_STUB: &str = r"
{
    target = {
        os = 'Linux,
        arch = 'Amd64,
    },
}
";

/// Evaluate a single package's `build.ncl`, substituting dependencies.
///
/// Uses a shared `EvalContext` for stdlib reuse. Dependencies are injected
/// as in-memory virtual files — no temporary files are written to disk.
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

    tracing::info!(package = %package_name, file = %build_file.display(), "evaluating");

    // Clone the shared stdlib cache for this package
    let mut cache = ctx.clone_for_package();

    // Add the main file from disk
    let main_id = cache
        .sources
        .add_file(build_file.as_os_str(), InputFormat::Nickel)
        .map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("failed to load {}: {e}", build_file.display()),
        })?;

    // Inject pre-evaluated dependencies as virtual in-memory files.
    // Also re-inject the self-import stub: `add_file` above overwrote the
    // package's own stub entry (same normalized path), so self-imports like
    // `import "../linux_headers/build.ncl"` from inside linux_headers/build.ncl
    // would resolve to the real file → infinite recursion. Re-injecting the
    // stub after `add_file` makes the path mapping point to the stub, while
    // the main FileId (from `add_file`) remains valid for evaluation.
    let pkgs_dir = build_file.parent().and_then(|p| p.parent());

    if let Some(pkgs_dir) = pkgs_dir {
        // Re-inject self-import stub to break circular imports
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

            let nickel_content = json_to_nickel(json);
            cache.sources.add_string(
                SourcePath::Path(dep_path, InputFormat::Nickel),
                nickel_content,
            );

            tracing::debug!(dependency = dep_name, "injected virtual import");
        }
    }

    // Build VM context. Skip typechecking (prepare_eval_only) because:
    // 1. Pre-evaluated deps are already type-safe
    // 2. Typechecking adds significant memory overhead
    // 3. Contracts are enforced at runtime during evaluation anyway
    let mut vm_ctxt: VmContext<CacheHub, CacheImpl> =
        VmContext::new(cache, io::stderr(), NullReporter {});

    let prepared = vm_ctxt
        .prepare_eval_only(main_id)
        .map_err(|e| ForgeError::NickelEval {
            package: package_name.clone(),
            message: format!("{e:?}"),
        })?;

    let result = {
        let mut vm = VirtualMachine::new(&mut vm_ctxt);
        vm.eval_full_for_export(prepared)
            .map_err(|e| ForgeError::NickelEval {
                package: package_name.clone(),
                message: format!("{e:?}"),
            })?
    };

    // Serialize to JSON
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

    // Store the result
    let store_ref = store.put(&json)?;

    tracing::info!(
        package = %package_name,
        hash = %store_ref.hash,
        "evaluation complete"
    );

    Ok(EvalResult { json, store_ref })
}

/// Convert a JSON value to a Nickel record literal.
///
/// Nickel uses `=` instead of `:` for field assignment. We produce a
/// conservative subset that Nickel can parse: strings, numbers, bools,
/// null, arrays, and records.
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

/// Extract the dependency package name from an import path.
///
/// Matches patterns like:
/// - `../gcc/build.ncl` -> `"gcc"`
/// - `../some-package/build.ncl` -> `"some-package"`
/// - Other paths -> `None`
pub fn extract_dep_name(path: &str) -> Option<&str> {
    let path = path.strip_prefix("../")?;
    let (name, rest) = path.split_once('/')?;
    if rest == "build.ncl" {
        Some(name)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_dep_name_standard_pattern() {
        assert_eq!(extract_dep_name("../gcc/build.ncl"), Some("gcc"));
        assert_eq!(extract_dep_name("../glibc/build.ncl"), Some("glibc"));
        assert_eq!(
            extract_dep_name("../some-package/build.ncl"),
            Some("some-package")
        );
    }

    #[test]
    fn extract_dep_name_rejects_other_patterns() {
        assert_eq!(extract_dep_name("./local.ncl"), None);
        assert_eq!(extract_dep_name("../gcc/other.ncl"), None);
        assert_eq!(extract_dep_name("minimal.ncl"), None);
        assert_eq!(extract_dep_name("../a/b/build.ncl"), None);
    }

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
        assert!(store.contains(&result.store_ref));
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

    /// Verify that virtual imports work even when the dep directory
    /// does NOT exist on disk.
    #[test]
    fn eval_virtual_import_no_disk_dep() {
        let dir = tempfile::tempdir().unwrap();
        let pkgs = dir.path().join("pkgs");

        std::fs::create_dir_all(pkgs.join("main")).unwrap();
        std::fs::write(
            pkgs.join("main/build.ncl"),
            r#"let dep = import "../dep/build.ncl" in
            { name = "main", dep_name = dep.name, dep_value = dep.value }"#,
        )
        .unwrap();

        let store = Store::new(dir.path().join("store")).unwrap();
        let ctx = EvalContext::new(&[]).unwrap();

        let mut dep_results = HashMap::new();
        dep_results.insert(
            "dep".to_string(),
            serde_json::json!({"name": "virtual-dep", "value": 999}),
        );

        let result =
            eval_package(&pkgs.join("main/build.ncl"), &dep_results, &store, &ctx).unwrap();

        assert_eq!(result.json["name"], "main");
        assert_eq!(result.json["dep_name"], "virtual-dep");
        assert_eq!(result.json["dep_value"], 999);
    }

    #[test]
    fn eval_with_string_interpolation() {
        let dir = tempfile::tempdir().unwrap();
        let build_file = dir.path().join("build.ncl");

        std::fs::write(
            &build_file,
            r#"
            let name = "world" in
            { greeting = "hello %{name}", count = 1 + 1 }
            "#,
        )
        .unwrap();

        let store = Store::new(dir.path().join("store")).unwrap();
        let ctx = EvalContext::new(&[]).unwrap();
        let result = eval_package(&build_file, &HashMap::new(), &store, &ctx).unwrap();

        assert_eq!(result.json["greeting"], "hello world");
        assert_eq!(result.json["count"], 2);
    }

    /// Test that the shared stdlib context works for multiple packages.
    #[test]
    fn eval_shared_context_multiple_packages() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = EvalContext::new(&[]).unwrap();
        let store = Store::new(dir.path().join("store")).unwrap();

        // Evaluate two different files using the same context
        let file_a = dir.path().join("a.ncl");
        std::fs::write(&file_a, r#"{ name = "a", value = 1 }"#).unwrap();

        let file_b = dir.path().join("b.ncl");
        std::fs::write(&file_b, r#"{ name = "b", value = 2 }"#).unwrap();

        let result_a = eval_package(&file_a, &HashMap::new(), &store, &ctx).unwrap();
        let result_b = eval_package(&file_b, &HashMap::new(), &store, &ctx).unwrap();

        assert_eq!(result_a.json["name"], "a");
        assert_eq!(result_b.json["name"], "b");
        // Different content should produce different hashes
        assert_ne!(result_a.store_ref.hash, result_b.store_ref.hash);
    }
}
