// Standalone script to run composition analysis on real forge output.
// Run with: cargo run --release --features lattice --example analyze_composition

use gleisner_lacerta::composition_analysis::*;
use std::fs;

fn main() {
    let json =
        fs::read_to_string("/tmp/composition-input.json").expect("read composition-input.json");
    let input: CompositionInput = serde_json::from_str(&json).expect("parse composition input");

    println!(
        "=== Composition Analysis: {} packages ===\n",
        input.packages.len()
    );

    // Phase 1: Excess analysis
    let analysis = analyze(&input);

    println!("Composed grant:");
    println!("  DNS: {}", analysis.composed_grant.dns);
    println!("  Internet: {}", analysis.composed_grant.internet);
    println!(
        "  Domains: {} unique",
        analysis.composed_grant.domains.len()
    );
    println!("\nTotal excess: {} capability-units", analysis.total_excess);
    println!("Capability classes: {}", analysis.capability_classes);

    println!("\n--- Capability classes ---");
    for (i, cls) in analysis.classes.iter().enumerate() {
        println!(
            "  Class {}: {} packages | dns={} internet={} domains={}",
            i,
            cls.packages.len(),
            cls.needs_dns,
            cls.needs_internet,
            cls.domains.len()
        );
        if cls.packages.len() <= 5 {
            for p in &cls.packages {
                println!("    - {p}");
            }
        } else {
            for p in cls.packages.iter().take(3) {
                println!("    - {p}");
            }
            println!("    ... and {} more", cls.packages.len() - 3);
        }
    }

    // Phase 2: Worst excess packages
    let mut sorted_excess: Vec<_> = analysis
        .package_excess
        .iter()
        .filter(|e| e.excess_count > 0)
        .collect();
    sorted_excess.sort_by(|a, b| b.excess_count.cmp(&a.excess_count));

    println!("\n--- Top 10 most over-privileged packages ---");
    for e in sorted_excess.iter().take(10) {
        println!(
            "  {}: {} excess (dns={} internet={} domains={})",
            e.name,
            e.excess_count,
            e.excess_dns,
            e.excess_internet,
            e.excess_domains.len()
        );
    }

    // Phase 3: Z3 partitioning
    println!("\n--- Z3 optimal partitioning ---");
    for k in [1, 2, 3, 5] {
        print!("  K={k}: ");
        if let Some(result) = find_optimal_partition(&input, k) {
            println!(
                "{} groups, {} excess, zero_excess={}",
                result.group_count, result.total_excess, result.zero_excess
            );
            if k <= 3 {
                for g in &result.groups {
                    println!(
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
            println!("INFEASIBLE");
        }
    }

    println!("\n--- Minimum zero-excess partition ---");
    let min_result = find_minimum_zero_excess_groups(&input);
    println!(
        "  {} groups needed for zero excess (verified by Z3)",
        min_result.group_count
    );
    for g in &min_result.groups {
        println!(
            "    Group {}: {} pkgs | dns={} internet={} domains={:?}",
            g.id,
            g.packages.len(),
            g.effective_dns,
            g.effective_internet,
            g.effective_domains
        );
    }
}
