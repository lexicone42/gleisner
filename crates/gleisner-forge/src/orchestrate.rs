//! Top-level orchestration: evaluate all packages incrementally.
//!
//! Ties together the DAG extraction, per-package evaluation, content store,
//! and environment composition into a single pipeline.

use crate::compose::ComposedEnvironment;
use crate::dag::PackageGraph;
use crate::error::ForgeError;
use crate::eval::{self, EvalContext};
use crate::store::{Store, StoreRef};
use std::collections::HashMap;

/// Configuration for the forge orchestrator.
#[derive(Debug, Clone)]
pub struct ForgeConfig {
    /// Path to the packages directory (contains `<name>/build.ncl` entries).
    pub pkgs_dir: std::path::PathBuf,
    /// Path to the content-addressed store.
    pub store_dir: std::path::PathBuf,
    /// Optional: only evaluate these packages (and their transitive deps).
    pub targets: Option<Vec<String>>,
    /// Additional directories for bare import resolution (e.g., stdlib path).
    pub import_paths: Vec<std::path::PathBuf>,
}

/// Result of a full forge run.
#[derive(Debug)]
pub struct ForgeOutput {
    /// Per-package evaluation results.
    pub results: HashMap<String, StoreRef>,
    /// The composed environment from all evaluated packages.
    pub environment: ComposedEnvironment,
    /// Total number of packages evaluated.
    pub evaluated_count: usize,
    /// Number of packages that were cache hits (already in store).
    pub cache_hits: usize,
}

/// Run the full forge pipeline: DAG -> eval -> store -> compose.
pub fn run(config: &ForgeConfig) -> Result<ForgeOutput, ForgeError> {
    tracing::info!(
        pkgs_dir = %config.pkgs_dir.display(),
        store_dir = %config.store_dir.display(),
        "starting forge run"
    );

    // 1. Build dependency graph
    let graph = PackageGraph::from_directory(&config.pkgs_dir)?;
    tracing::info!(packages = graph.len(), "dependency graph built");

    // 2. Topological sort
    let order = graph.topological_order()?;
    tracing::info!(
        order = ?order.iter().map(|n| &n.name).collect::<Vec<_>>(),
        "evaluation order determined"
    );

    // 3. Initialize store and shared eval context (loads stdlib once)
    let store = Store::new(&config.store_dir)?;
    let import_paths: Vec<&std::path::Path> = config
        .import_paths
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect();
    let ctx = EvalContext::new(&import_paths)?;

    // 4. Evaluate packages in order
    let mut results: HashMap<String, StoreRef> = HashMap::new();
    let mut json_cache: HashMap<String, serde_json::Value> = HashMap::new();
    let mut environment = ComposedEnvironment::new();
    let cache_hits = 0usize;

    for node in &order {
        // Skip if not in targets (when targets are specified)
        if let Some(ref targets) = config.targets {
            if !targets.contains(&node.name) {
                // Still need to evaluate if it's a transitive dep of a target
                // For now, evaluate everything in topo order
                // TODO: filter to only transitive deps of targets
            }
        }

        // Collect pre-evaluated dependency results
        let deps = graph.dependencies_of(&node.name);
        let dep_results: HashMap<String, serde_json::Value> = deps
            .iter()
            .filter_map(|dep_name| {
                json_cache
                    .get(*dep_name)
                    .map(|json| ((*dep_name).to_string(), json.clone()))
            })
            .collect();

        // Evaluate the package using shared context
        let eval_result = eval::eval_package(&node.build_file, &dep_results, &store, &ctx)?;

        // Merge into composed environment
        environment.merge_package(&node.name, &eval_result.json);

        // Cache for downstream dependents
        results.insert(node.name.clone(), eval_result.store_ref);
        json_cache.insert(node.name.clone(), eval_result.json);
    }

    let evaluated_count = results.len();

    tracing::info!(
        evaluated = evaluated_count,
        cache_hits = cache_hits,
        warnings = environment.warnings.len(),
        "forge run complete"
    );

    Ok(ForgeOutput {
        results,
        environment,
        evaluated_count,
        cache_hits,
    })
}
