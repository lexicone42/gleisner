//! High-level orchestration: DAG → eval → store → compose in one call.
//!
//! Wraps the individual pipeline stages into a convenient `evaluate_packages`
//! function suitable for CLI and TUI integration.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::compose::ComposedEnvironment;
use crate::dag::PackageGraph;
use crate::error::ForgeError;
use crate::eval::{EvalContext, eval_package, project_for_injection};
use crate::store::Store;

/// Result of a full evaluation run.
#[derive(Debug)]
pub struct ForgeOutput {
    /// The composed environment (merged attrs + needs across all packages).
    pub environment: ComposedEnvironment,
    /// Number of packages successfully evaluated.
    pub evaluated: usize,
    /// Number of packages that failed evaluation.
    pub failed: usize,
    /// Names of packages that failed.
    pub failed_packages: Vec<String>,
    /// Wall-clock time for the full evaluation.
    pub elapsed: std::time::Duration,
    /// Path to the content-addressed store.
    pub store_dir: PathBuf,
    /// Per-package evaluation results (for metadata extraction/attestation).
    ///
    /// Keys are package names, values are the full evaluated JSON.
    /// Only includes successfully evaluated packages.
    pub package_results: HashMap<String, serde_json::Value>,
}

/// Configuration for a forge evaluation run.
#[derive(Debug)]
pub struct ForgeConfig {
    /// Path to the packages directory (containing `<pkg>/build.ncl` subdirs).
    pub pkgs_dir: PathBuf,
    /// Path to the Nickel stdlib directory (containing `minimal.ncl`, `config.ncl`).
    pub stdlib_dir: PathBuf,
    /// Directory for the content-addressed store. Defaults to `<project>/.gleisner/forge-store`.
    pub store_dir: PathBuf,
    /// If set, only evaluate these packages (and their transitive deps).
    pub filter: Vec<String>,
}

/// Evaluate a set of Nickel packages and compose their environment.
///
/// This is the main entry point for forge integration. It:
/// 1. Builds the dependency graph from the packages directory
/// 2. Creates a shared `EvalContext` (loads Nickel stdlib once)
/// 3. Evaluates packages in topological order
/// 4. Stores results in a content-addressed store
/// 5. Merges all `attrs` and `needs` into a `ComposedEnvironment`
///
/// # Errors
///
/// Returns `ForgeError` if the DAG cannot be built, the stdlib fails
/// to load, or a critical evaluation error occurs. Individual package
/// failures are collected in `ForgeOutput::failed_packages` rather
/// than aborting the run.
pub fn evaluate_packages(config: &ForgeConfig) -> Result<ForgeOutput, ForgeError> {
    let t_start = Instant::now();

    // Resolve packages/ subdirectory if present
    let pkgs_dir = {
        let sub = config.pkgs_dir.join("packages");
        if sub.is_dir() {
            tracing::debug!("auto-detected packages/ subdirectory");
            sub
        } else {
            config.pkgs_dir.clone()
        }
    };

    // 1. Build DAG
    let graph = PackageGraph::from_directory(&pkgs_dir)?;
    let order = graph.topological_order()?;
    tracing::info!(packages = order.len(), "dependency graph built");

    // 2. Create eval context (loads stdlib once)
    let mut ctx = EvalContext::new(&[config.stdlib_dir.as_path()])?;
    ctx.register_packages_dir(&pkgs_dir)?;

    // 3. Create store
    let store = Store::new(&config.store_dir)?;

    // 4. Evaluate in topological order
    let mut json_cache: HashMap<String, serde_json::Value> = HashMap::new();
    let mut package_results: HashMap<String, serde_json::Value> = HashMap::new();
    let mut composed = ComposedEnvironment::new();
    let mut evaluated = 0usize;
    let mut failed = 0usize;
    let mut failed_packages = Vec::new();

    // Filter to requested packages if specified
    let order_filtered: Vec<_> = if config.filter.is_empty() {
        order.iter().collect()
    } else {
        order
            .iter()
            .filter(|n| config.filter.contains(&n.name))
            .collect()
    };

    for (i, node) in order_filtered.iter().enumerate() {
        let deps = graph.dependencies_of(&node.name);
        let dep_results: HashMap<String, serde_json::Value> = deps
            .iter()
            .filter_map(|dep_name| {
                json_cache
                    .get(*dep_name)
                    .map(|json| ((*dep_name).to_string(), json.clone()))
            })
            .collect();

        match eval_package(&node.build_file, &dep_results, &store, &ctx) {
            Ok(result) => {
                tracing::debug!(
                    package = %node.name,
                    index = i + 1,
                    total = order_filtered.len(),
                    hash = %&result.store_ref.hash[..12],
                    "package evaluated"
                );
                composed.merge_package(&node.name, &result.json);
                package_results.insert(node.name.clone(), result.json.clone());
                json_cache.insert(
                    node.name.clone(),
                    project_for_injection(&result.json, &result.store_ref),
                );
                evaluated += 1;
            }
            Err(e) => {
                tracing::warn!(
                    package = %node.name,
                    error = %e,
                    "package evaluation failed"
                );
                // Insert error stub so dependents can still evaluate
                json_cache.insert(
                    node.name.clone(),
                    serde_json::json!({"name": node.name, "_error": true}),
                );
                failed_packages.push(node.name.clone());
                failed += 1;
            }
        }
    }

    let elapsed = t_start.elapsed();
    tracing::info!(
        evaluated,
        failed,
        elapsed_secs = elapsed.as_secs_f64(),
        "forge evaluation complete"
    );

    Ok(ForgeOutput {
        environment: composed,
        evaluated,
        failed,
        failed_packages,
        elapsed,
        store_dir: config.store_dir.clone(),
        package_results,
    })
}
