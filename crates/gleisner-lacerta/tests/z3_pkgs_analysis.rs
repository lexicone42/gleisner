//! Z3 composition analysis against the real gominimal/pkgs repo (276 packages).
//!
//! Requires:
//! - `gominimal/pkgs` at /datar/workspace/pkgs
//! - `gominimal/std` at /datar/workspace/minimal-std
//! - `lattice` feature enabled

#![cfg(feature = "lattice")]

use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};
use gleisner_lacerta::composition_analysis::{
    CompositionInput, PackageCapabilities, analyze, find_minimum_zero_excess_groups,
    find_optimal_partition, find_optimal_partition_with_timeout,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn pkgs_available() -> bool {
    PathBuf::from("/datar/workspace/pkgs/packages").is_dir()
        && PathBuf::from("/datar/workspace/minimal-std").is_dir()
}

fn build_composition_input() -> CompositionInput {
    let config = ForgeConfig {
        pkgs_dir: PathBuf::from("/datar/workspace/pkgs/packages"),
        stdlib_dir: PathBuf::from("/datar/workspace/minimal-std"),
        store_dir: PathBuf::from("/tmp/gleisner-z3-test-store"),
        filter: vec![],
    };

    let output = evaluate_packages(&config).expect("evaluate packages");
    eprintln!(
        "Evaluated {} packages ({} failed)",
        output.evaluated, output.failed
    );

    let mut pkg_map: std::collections::HashMap<String, PackageCapabilities> =
        std::collections::HashMap::new();

    // Extract per-package source domains from the composed environment
    for sd in &output.environment.source_domains {
        let entry = pkg_map
            .entry(sd.package.clone())
            .or_insert_with(|| PackageCapabilities {
                name: sd.package.clone(),
                needs_dns: false,
                needs_internet: false,
                source_domains: BTreeSet::new(),
            });
        entry.source_domains.insert(sd.domain.clone());
    }

    // Extract per-package needs from the eval results
    for (name, result) in &output.package_results {
        if let Some(needs) = result.get("needs") {
            let entry = pkg_map
                .entry(name.clone())
                .or_insert_with(|| PackageCapabilities {
                    name: name.clone(),
                    needs_dns: false,
                    needs_internet: false,
                    source_domains: BTreeSet::new(),
                });
            if let Some(dns) = needs.get("dns") {
                entry.needs_dns = dns.is_object() || dns.as_bool().unwrap_or(false);
            }
            if let Some(internet) = needs.get("internet") {
                entry.needs_internet = internet.is_object() || internet.as_bool().unwrap_or(false);
            }
        }
    }

    // Include packages with no source domains or needs
    for name in &output.environment.packages {
        pkg_map
            .entry(name.clone())
            .or_insert_with(|| PackageCapabilities {
                name: name.clone(),
                needs_dns: false,
                needs_internet: false,
                source_domains: BTreeSet::new(),
            });
    }

    let packages: Vec<_> = pkg_map.into_values().collect();
    eprintln!("{} packages in composition input", packages.len());
    CompositionInput { packages }
}

#[test]
fn z3_composition_analysis_276_packages() {
    if !pkgs_available() {
        eprintln!("skipping: gominimal/pkgs not available");
        return;
    }

    let input = build_composition_input();
    let analysis = analyze(&input);

    eprintln!(
        "\n=== Z3 Composition Analysis: {} packages ===",
        analysis.total_packages
    );
    eprintln!(
        "Composed grant: dns={}, internet={}",
        analysis.composed_grant.dns, analysis.composed_grant.internet
    );
    eprintln!(
        "Unique domains in composed grant: {}",
        analysis.composed_grant.domains.len()
    );
    eprintln!("Total excess: {} capability-units", analysis.total_excess);
    eprintln!("Capability classes: {}", analysis.capability_classes);

    eprintln!("\n--- Top 10 over-privileged packages ---");
    let mut sorted: Vec<_> = analysis
        .package_excess
        .iter()
        .filter(|e| e.excess_count > 0)
        .collect();
    sorted.sort_by(|a, b| b.excess_count.cmp(&a.excess_count));
    for e in sorted.iter().take(10) {
        eprintln!(
            "  {}: {} excess (dns={} internet={} domains={})",
            e.name,
            e.excess_count,
            e.excess_dns,
            e.excess_internet,
            e.excess_domains.len()
        );
    }

    assert!(
        analysis.total_packages >= 270,
        "should analyze most packages"
    );
    assert!(
        analysis.capability_classes > 1,
        "should have multiple capability classes"
    );

    // Z3 optimal partitioning (120s timeout per K value)
    eprintln!("\n--- Z3 Optimal Partitioning (120s timeout per K) ---");
    for k in [1, 2, 3, 5] {
        let timeout = std::time::Duration::from_secs(120);
        if let Some(result) = find_optimal_partition_with_timeout(&input, k, timeout) {
            eprintln!(
                "  K={}: {} groups, {} excess, zero_excess={}",
                k, result.group_count, result.total_excess, result.zero_excess
            );
            if k <= 3 {
                for g in &result.groups {
                    eprintln!(
                        "    Group {}: {} pkgs | dns={} internet={} domains={}",
                        g.id,
                        g.packages.len(),
                        g.effective_dns,
                        g.effective_internet,
                        g.effective_domains.len()
                    );
                }
            }
        } else {
            eprintln!("  K={k}: INFEASIBLE");
        }
    }

    // Minimum zero-excess partition (K = |classes|, always fast)
    eprintln!("\n--- Minimum Zero-Excess Partition ---");
    let min_result = find_minimum_zero_excess_groups(&input);
    eprintln!(
        "  {} groups needed for zero excess (verified by Z3)",
        min_result.group_count
    );
    for g in &min_result.groups {
        eprintln!(
            "    Group {}: {} pkgs | dns={} internet={} domains={:?}",
            g.id,
            g.packages.len(),
            g.effective_dns,
            g.effective_internet,
            g.effective_domains
        );
    }

    assert!(
        min_result.zero_excess,
        "minimum partition should achieve zero excess"
    );
}
