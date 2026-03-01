//! Integration test: evaluate the real minimal-pkgs tree.
//!
//! Usage: cargo run -p gleisner-forge --example `eval_minimal` -- /path/to/minimal-pkgs /path/to/minimal-std

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gleisner_forge::dag::PackageGraph;
use gleisner_forge::eval::EvalContext;
use gleisner_forge::store::Store;

/// Read current process RSS from /proc/self/statm (Linux only).
fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0.0, |pages| pages as f64 * 4096.0 / 1_048_576.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <minimal-pkgs-dir> <minimal-std-dir>", args[0]);
        std::process::exit(1);
    }

    let mut pkgs_dir = PathBuf::from(&args[1]);
    let stdlib_dir = PathBuf::from(&args[2]);

    // Auto-detect: if the given dir has a packages/ subdirectory, use that
    let packages_subdir = pkgs_dir.join("packages");
    if packages_subdir.is_dir() {
        eprintln!("auto-detected packages/ subdirectory");
        pkgs_dir = packages_subdir;
    }

    eprintln!("=== gleisner-forge: minimal-pkgs evaluation ===");
    eprintln!("packages dir: {}", pkgs_dir.display());
    eprintln!("stdlib dir:   {}", stdlib_dir.display());

    // Build dependency graph
    let t0 = Instant::now();
    let graph = PackageGraph::from_directory(&pkgs_dir).unwrap();
    eprintln!("DAG: {} packages, built in {:?}", graph.len(), t0.elapsed());

    // Topological sort
    let order = graph.topological_order().unwrap();
    eprintln!("topo order: {} packages", order.len());
    eprintln!(
        "first 10: {:?}",
        order.iter().take(10).map(|n| &n.name).collect::<Vec<_>>()
    );

    // Initialize store
    let store_dir = std::env::temp_dir().join("forge-minimal-store");
    let store = Store::new(&store_dir).unwrap();
    eprintln!("store: {}", store_dir.display());

    // Load Nickel stdlib and register package stubs
    eprintln!("loading Nickel stdlib...");
    let t_stdlib = Instant::now();
    let import_paths: Vec<&Path> = vec![stdlib_dir.as_path()];
    let mut ctx = EvalContext::new(&import_paths).unwrap();
    eprintln!(
        "stdlib loaded in {:?}  (RSS: {:.0} MB)",
        t_stdlib.elapsed(),
        rss_mb()
    );

    // Pre-register all packages as stub virtual imports.
    // This prevents cascading disk loads during import resolution:
    // without stubs, `import "../X/build.ncl"` loads the real file,
    // which imports ITS deps, which import THEIR deps — loading all
    // 226 packages into memory at once.
    eprintln!("registering package stubs...");
    ctx.register_packages_dir(&pkgs_dir).unwrap();
    eprintln!("package stubs registered  (RSS: {:.0} MB)", rss_mb());

    // Evaluate in topological order
    let mut json_cache: HashMap<String, serde_json::Value> = HashMap::new();
    let mut evaluated = 0usize;
    let mut failed = 0usize;
    let mut peak_rss: f64 = 0.0;
    let t_total = Instant::now();

    // Test single package for error diagnostics
    let target_pkg = std::env::var("FORGE_PKG").ok();
    let order_filtered: Vec<_> = if let Some(ref pkg) = target_pkg {
        eprintln!("targeting single package: {pkg}");
        order.iter().filter(|n| n.name == *pkg).collect()
    } else {
        order.iter().collect()
    };

    for node in &order_filtered {
        // Collect pre-evaluated deps
        let deps = graph.dependencies_of(&node.name);
        let dep_results: HashMap<String, serde_json::Value> = deps
            .iter()
            .filter_map(|dep_name| {
                json_cache
                    .get(*dep_name)
                    .map(|json| ((*dep_name).to_string(), json.clone()))
            })
            .collect();

        let t_pkg = Instant::now();
        match gleisner_forge::eval::eval_package(&node.build_file, &dep_results, &store, &ctx) {
            Ok(result) => {
                let elapsed = t_pkg.elapsed();
                let fields = result.json.as_object().map_or(0, serde_json::Map::len);
                let rss = rss_mb();
                if rss > peak_rss {
                    peak_rss = rss;
                }
                eprintln!(
                    "  OK  {:30} {:>8.1?}  ({} fields, hash {})  RSS: {:.0} MB",
                    node.name,
                    elapsed,
                    fields,
                    &result.store_ref.hash[..12],
                    rss,
                );
                json_cache.insert(node.name.clone(), result.json);
                evaluated += 1;
            }
            Err(e) => {
                let elapsed = t_pkg.elapsed();
                let msg = format!("{e}");
                let truncated: String = msg.chars().take(300).collect();
                let rss = rss_mb();
                if rss > peak_rss {
                    peak_rss = rss;
                }
                eprintln!(
                    "  ERR {:30} {:>8.1?}  {}  RSS: {:.0} MB",
                    node.name, elapsed, truncated, rss,
                );
                // Insert a stub so downstream packages can still attempt
                json_cache.insert(
                    node.name.clone(),
                    serde_json::json!({"name": node.name, "_error": true}),
                );
                failed += 1;
            }
        }
    }

    eprintln!("\n=== Summary ===");
    eprintln!("total:     {}", order.len());
    eprintln!("evaluated: {evaluated}");
    eprintln!("failed:    {failed}");
    eprintln!("time:      {:?}", t_total.elapsed());
    eprintln!("peak RSS:  {peak_rss:.0} MB");
    eprintln!("final RSS: {:.0} MB", rss_mb());
}
