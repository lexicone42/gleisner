//! Dependency graph extraction and topological ordering.
//!
//! Scans Nickel package files for `import` statements using regex,
//! builds a directed acyclic graph, and produces a topological ordering
//! for incremental evaluation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use regex::Regex;

use crate::error::ForgeError;

/// Matches `import "../<name>/build.ncl"` dependency declarations.
static IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"import\s+"\.\./([\w.+-]+)/build\.ncl""#).expect("valid regex"));

/// Matches the `replace_on_cycle` marker in package files.
static CYCLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"replace_on_cycle\b").expect("valid regex"));

/// Matches `prebuilt = true` in package files.
static PREBUILT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"prebuilt\s*=\s*true").expect("valid regex"));

/// A node in the package dependency graph.
#[derive(Debug, Clone)]
pub struct PackageNode {
    /// Package name (directory name, e.g. "gcc", "glibc").
    pub name: String,
    /// Path to the package's `build.ncl` file.
    pub build_file: PathBuf,
    /// Whether this package has a `replace_on_cycle` + `prebuilt` fallback.
    pub has_cycle_fallback: bool,
}

/// The extracted dependency graph with topological ordering.
#[derive(Debug)]
pub struct PackageGraph {
    graph: DiGraph<PackageNode, ()>,
    name_to_index: HashMap<String, NodeIndex>,
}

impl PackageGraph {
    /// Scan a package repository directory and build the dependency graph.
    ///
    /// Expects the directory structure: `<pkgs_dir>/<name>/build.ncl`
    /// where each `build.ncl` imports dependencies via `import "../<dep>/build.ncl"`.
    pub fn from_directory(pkgs_dir: &Path) -> Result<Self, ForgeError> {
        let mut graph = DiGraph::new();
        let mut name_to_index: HashMap<String, NodeIndex> = HashMap::new();

        // First pass: discover all packages
        let entries = std::fs::read_dir(pkgs_dir).map_err(|source| ForgeError::PackageRead {
            path: pkgs_dir.to_path_buf(),
            source,
        })?;

        for entry in entries {
            let entry = entry.map_err(|source| ForgeError::PackageRead {
                path: pkgs_dir.to_path_buf(),
                source,
            })?;
            let build_file = entry.path().join("build.ncl");
            if !build_file.exists() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();

            let content =
                std::fs::read_to_string(&build_file).map_err(|source| ForgeError::PackageRead {
                    path: build_file.clone(),
                    source,
                })?;

            let has_cycle_fallback = CYCLE_RE.is_match(&content) && PREBUILT_RE.is_match(&content);

            let idx = graph.add_node(PackageNode {
                name: name.clone(),
                build_file,
                has_cycle_fallback,
            });
            name_to_index.insert(name, idx);
        }

        // Second pass: extract edges (dependency → dependent)
        let indices: Vec<(String, NodeIndex)> =
            name_to_index.iter().map(|(k, v)| (k.clone(), *v)).collect();

        for (name, idx) in &indices {
            let node = &graph[*idx];
            let content = std::fs::read_to_string(&node.build_file).map_err(|source| {
                ForgeError::PackageRead {
                    path: node.build_file.clone(),
                    source,
                }
            })?;

            for cap in IMPORT_RE.captures_iter(&content) {
                let dep_name = &cap[1];
                if let Some(&dep_idx) = name_to_index.get(dep_name) {
                    // Edge: dep → this package (dep must be evaluated first)
                    graph.add_edge(dep_idx, *idx, ());
                } else {
                    tracing::warn!(
                        package = %name,
                        dependency = %dep_name,
                        "import references unknown package — skipping edge"
                    );
                }
            }
        }

        Ok(Self {
            graph,
            name_to_index,
        })
    }

    /// Return packages in topological order (dependencies before dependents).
    ///
    /// Self-edges (a package importing itself, common with `replace_on_cycle`)
    /// are always removed. If cycles remain, edges *into* packages with
    /// `has_cycle_fallback` are removed until the graph is acyclic.
    ///
    /// ## Cycle-breaking semantics
    ///
    /// Only packages with `has_cycle_fallback` act as circuit breakers. A package
    /// has this flag when it declares both `replace_on_cycle` and a `prebuilt`
    /// fallback in its Nickel definition.
    ///
    /// For a cycle A -> B -> C -> A, if only A has a fallback, all of A's
    /// *incoming* edges are removed (here: C -> A), which breaks the cycle.
    /// The other packages in the cycle (B, C) are then free to be sorted
    /// normally because the cycle no longer exists.
    ///
    /// If a cycle has *no* packages with fallbacks, or if removing fallback
    /// edges is insufficient to break all cycles (e.g., B -> C -> B where
    /// neither has a fallback), the final `toposort` will fail with
    /// [`ForgeError::NotADag`].
    pub fn topological_order(&self) -> Result<Vec<&PackageNode>, ForgeError> {
        // Clone the graph so we can mutate edges for cycle-breaking
        let mut work = self.graph.clone();

        // Remove self-edges (e.g., bash imports ../bash/build.ncl for replace_on_cycle)
        let self_edges: Vec<_> = work
            .edge_indices()
            .filter(|&e| work.edge_endpoints(e).is_some_and(|(src, dst)| src == dst))
            .collect();
        for e in self_edges.into_iter().rev() {
            work.remove_edge(e);
        }

        // Try toposort; if it fails, break cycles at fallback-enabled packages.
        // Only packages with has_cycle_fallback (i.e., replace_on_cycle + prebuilt)
        // can serve as circuit breakers. Their incoming edges are severed so that
        // dependents use the prebuilt fallback instead of the freshly-built output.
        if toposort(&work, None).is_err() {
            let fallback_nodes: Vec<NodeIndex> = work
                .node_indices()
                .filter(|&idx| work[idx].has_cycle_fallback)
                .collect();

            for idx in &fallback_nodes {
                let incoming: Vec<_> = work
                    .neighbors_directed(*idx, petgraph::Direction::Incoming)
                    .collect();
                for src in incoming {
                    if let Some(e) = work.find_edge(src, *idx) {
                        work.remove_edge(e);
                    }
                }
            }
        }

        // If cycles remain after removing fallback edges, the graph is not a DAG.
        // This happens when a sub-cycle has no fallback-enabled packages.
        let sorted = toposort(&work, None).map_err(|_| ForgeError::NotADag)?;
        Ok(sorted.iter().map(|idx| &self.graph[*idx]).collect())
    }

    /// Get a package node by name.
    pub fn get(&self, name: &str) -> Option<&PackageNode> {
        self.name_to_index.get(name).map(|idx| &self.graph[*idx])
    }

    /// Return the names of direct dependencies of a package.
    pub fn dependencies_of(&self, name: &str) -> Vec<&str> {
        let Some(&idx) = self.name_to_index.get(name) else {
            return Vec::new();
        };

        self.graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .map(|dep_idx| self.graph[dep_idx].name.as_str())
            .collect()
    }

    /// Return the total number of packages.
    pub fn len(&self) -> usize {
        self.graph.node_count()
    }

    /// Return whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.graph.node_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_repo(dir: &Path, packages: &[(&str, &str)]) {
        for (name, content) in packages {
            let pkg_dir = dir.join(name);
            std::fs::create_dir_all(&pkg_dir).unwrap();
            std::fs::write(pkg_dir.join("build.ncl"), content).unwrap();
        }
    }

    #[test]
    fn linear_dependency_chain() {
        let dir = tempfile::tempdir().unwrap();
        make_test_repo(
            dir.path(),
            &[
                ("a", r#"{ name = "a", build_deps = [] }"#),
                (
                    "b",
                    r#"let a = import "../a/build.ncl" in { name = "b", build_deps = [a] }"#,
                ),
                (
                    "c",
                    r#"let b = import "../b/build.ncl" in { name = "c", build_deps = [b] }"#,
                ),
            ],
        );

        let graph = PackageGraph::from_directory(dir.path()).unwrap();
        assert_eq!(graph.len(), 3);

        let order = graph.topological_order().unwrap();
        let names: Vec<&str> = order.iter().map(|n| n.name.as_str()).collect();

        // a must come before b, b before c
        let pos_a = names.iter().position(|&n| n == "a").unwrap();
        let pos_b = names.iter().position(|&n| n == "b").unwrap();
        let pos_c = names.iter().position(|&n| n == "c").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn diamond_dependency() {
        let dir = tempfile::tempdir().unwrap();
        make_test_repo(
            dir.path(),
            &[
                ("base", r#"{ name = "base" }"#),
                (
                    "left",
                    r#"let b = import "../base/build.ncl" in { name = "left" }"#,
                ),
                (
                    "right",
                    r#"let b = import "../base/build.ncl" in { name = "right" }"#,
                ),
                (
                    "top",
                    r#"let l = import "../left/build.ncl" in
                     let r = import "../right/build.ncl" in
                     { name = "top" }"#,
                ),
            ],
        );

        let graph = PackageGraph::from_directory(dir.path()).unwrap();
        let order = graph.topological_order().unwrap();
        let names: Vec<&str> = order.iter().map(|n| n.name.as_str()).collect();

        // base must come before left and right, both before top
        let pos_base = names.iter().position(|&n| n == "base").unwrap();
        let pos_top = names.iter().position(|&n| n == "top").unwrap();
        assert!(pos_base < pos_top);
    }

    #[test]
    fn detects_cycle_fallback() {
        let dir = tempfile::tempdir().unwrap();
        make_test_repo(
            dir.path(),
            &[(
                "bootstrap",
                r#"{
                    name = "bootstrap",
                    replace_on_cycle = { prebuilt = true },
                }"#,
            )],
        );

        let graph = PackageGraph::from_directory(dir.path()).unwrap();
        let node = graph.get("bootstrap").unwrap();
        assert!(node.has_cycle_fallback);
    }

    #[test]
    fn dependencies_of_returns_correct_deps() {
        let dir = tempfile::tempdir().unwrap();
        make_test_repo(
            dir.path(),
            &[
                ("x", r#"{ name = "x" }"#),
                ("y", r#"{ name = "y" }"#),
                (
                    "z",
                    r#"let x = import "../x/build.ncl" in
                     let y = import "../y/build.ncl" in
                     { name = "z" }"#,
                ),
            ],
        );

        let graph = PackageGraph::from_directory(dir.path()).unwrap();
        let mut deps = graph.dependencies_of("z");
        deps.sort_unstable();
        assert_eq!(deps, vec!["x", "y"]);
    }
}
