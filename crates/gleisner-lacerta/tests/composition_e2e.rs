//! End-to-end tests for composed environment security analysis.
//!
//! These tests exercise the full pipeline:
//! 1. Build a realistic package composition (modeled on minimal.dev's 226 packages)
//! 2. Compute excess capabilities per-package
//! 3. Run Z3 optimal partitioning at various K values
//! 4. Verify partitions are correct and monotonically improve
//! 5. Find minimum zero-excess group count

#[cfg(feature = "lattice")]
mod composition_e2e {
    use gleisner_lacerta::composition_analysis::{
        CompositionInput, PackageCapabilities, analyze, compute_capability_classes,
        find_minimum_zero_excess_groups, find_optimal_partition,
    };

    fn pkg(name: &str, dns: bool, internet: bool, domains: &[&str]) -> PackageCapabilities {
        PackageCapabilities {
            name: name.to_string(),
            needs_dns: dns,
            needs_internet: internet,
            source_domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// Build a realistic package set modeled on minimal.dev:
    /// - ~180 packages download from github.com (dns only, no internet)
    /// - ~20 packages download from storage.googleapis.com (GCS tarballs)
    /// - ~15 packages download from both github.com and GCS
    /// - ~5 packages download from unique mirrors (gnu.org, kernel.org, etc.)
    /// - ~3 packages need full internet (node, python-pip, rust-cargo)
    /// - ~3 packages have no network needs at all (patches, config)
    fn realistic_package_set() -> CompositionInput {
        let mut packages = Vec::new();

        // 180 github-only packages
        for i in 0..180 {
            packages.push(pkg(&format!("gh-{i}"), false, false, &["github.com"]));
        }

        // 20 GCS-only packages
        for i in 0..20 {
            packages.push(pkg(
                &format!("gcs-{i}"),
                false,
                false,
                &["storage.googleapis.com"],
            ));
        }

        // 15 packages needing both github + GCS
        for i in 0..15 {
            packages.push(pkg(
                &format!("dual-{i}"),
                false,
                false,
                &["github.com", "storage.googleapis.com"],
            ));
        }

        // 5 packages with unique mirrors
        packages.push(pkg("gcc", false, false, &["ftp.gnu.org", "github.com"]));
        packages.push(pkg(
            "linux",
            false,
            false,
            &["cdn.kernel.org", "github.com"],
        ));
        packages.push(pkg("perl", false, false, &["cpan.org"]));
        packages.push(pkg("ruby", false, false, &["cache.ruby-lang.org"]));
        packages.push(pkg("lua", false, false, &["www.lua.org"]));

        // 3 packages needing full internet
        packages.push(pkg(
            "node",
            true,
            true,
            &["registry.npmjs.org", "github.com"],
        ));
        packages.push(pkg("python-pip", true, true, &["pypi.org", "github.com"]));
        packages.push(pkg("rust-cargo", true, true, &["crates.io", "github.com"]));

        // 3 packages with no network needs
        packages.push(pkg("config", false, false, &[]));
        packages.push(pkg("patches", false, false, &[]));
        packages.push(pkg("scripts", false, false, &[]));

        CompositionInput { packages }
    }

    /// Full pipeline: analyze flat composition, verify expected excess pattern.
    #[test]
    fn e2e_flat_composition_excess_analysis() {
        let input = realistic_package_set();
        let analysis = analyze(&input);

        assert_eq!(analysis.total_packages, 226);
        assert!(analysis.composed_grant.dns, "composed env should grant DNS");
        assert!(
            analysis.composed_grant.internet,
            "composed env should grant internet"
        );
        assert!(
            analysis.composed_grant.domains.len() >= 10,
            "should have at least 10 unique domains, got {}",
            analysis.composed_grant.domains.len()
        );

        // 223 of 226 packages get excess internet (only 3 declared it)
        let internet_excess_count = analysis
            .package_excess
            .iter()
            .filter(|e| e.excess_internet)
            .count();
        assert_eq!(internet_excess_count, 223);

        // The 3 no-network packages get excess on EVERY capability
        for name in &["config", "patches", "scripts"] {
            let excess = analysis
                .package_excess
                .iter()
                .find(|e| e.name == *name)
                .unwrap();
            assert!(excess.excess_dns, "{name} should have excess dns");
            assert!(excess.excess_internet, "{name} should have excess internet");
            assert!(
                !excess.excess_domains.is_empty(),
                "{name} should have excess domains"
            );
        }

        // Total excess should be substantial
        assert!(
            analysis.total_excess > 1000,
            "total excess should be >1000, got {}",
            analysis.total_excess
        );
    }

    /// Verify capability classes match the expected number.
    #[test]
    fn e2e_capability_class_count() {
        let input = realistic_package_set();
        let classes = compute_capability_classes(&input);

        // Expected classes:
        // 1. github-only (180 packages)
        // 2. GCS-only (20 packages)
        // 3. github+GCS (15 packages)
        // 4-8. unique mirrors (gcc, linux, perl, ruby, lua - each unique)
        // 9-11. internet packages (node, pip, cargo - each has different domains)
        // 12. no-network (3 packages: config, patches, scripts)
        // Total: ~12 classes
        assert!(
            classes.len() >= 10,
            "should have at least 10 capability classes, got {}",
            classes.len()
        );

        // The largest class should be the github-only group
        let largest = classes.iter().max_by_key(|c| c.packages.len()).unwrap();
        assert_eq!(
            largest.packages.len(),
            180,
            "largest class should have 180 packages"
        );
        assert!(largest.domains.contains("github.com"));
        assert!(!largest.needs_internet);
    }

    /// K=2 should dramatically reduce excess by isolating internet packages.
    #[test]
    fn e2e_partition_k2_isolates_internet() {
        let input = realistic_package_set();
        let analysis = analyze(&input);
        let k2 = find_optimal_partition(&input, 2).unwrap();

        // K=2 should reduce excess vs K=1
        assert!(
            k2.total_excess < analysis.total_excess,
            "k=2 ({}) should beat k=1 ({})",
            k2.total_excess,
            analysis.total_excess
        );

        // Find the group with internet packages
        let internet_group = k2
            .groups
            .iter()
            .find(|g| g.effective_internet)
            .expect("one group should have internet");

        // Internet packages should be in this group
        assert!(
            internet_group
                .packages
                .iter()
                .any(|p| p == "node" || p == "python-pip" || p == "rust-cargo")
        );

        // The non-internet group should NOT have internet
        for g in &k2.groups {
            if !g.effective_internet {
                for pkg_name in &g.packages {
                    let pkg = input.packages.iter().find(|p| &p.name == pkg_name).unwrap();
                    assert!(
                        !pkg.needs_internet,
                        "{pkg_name} needs internet but is in non-internet group"
                    );
                }
            }
        }
    }

    /// Monotonicity: more groups should mean less or equal excess.
    #[test]
    fn e2e_partition_monotonicity() {
        let input = realistic_package_set();
        let mut prev_excess = usize::MAX;

        for k in 1..=5 {
            let result = find_optimal_partition(&input, k).unwrap();
            assert!(
                result.total_excess <= prev_excess,
                "k={k} excess ({}) should be <= k={} excess ({prev_excess})",
                result.total_excess,
                k - 1
            );
            prev_excess = result.total_excess;
        }
    }

    /// Find minimum zero-excess partition for the full 226-package set.
    #[test]
    fn e2e_minimum_zero_excess_partition() {
        let input = realistic_package_set();
        let classes = compute_capability_classes(&input);
        let result = find_minimum_zero_excess_groups(&input);

        assert!(
            result.zero_excess,
            "should achieve zero excess, got {}",
            result.total_excess
        );
        assert_eq!(
            result.group_count,
            classes.len(),
            "minimum groups should equal number of capability classes"
        );

        // Verify every package is assigned
        let total_assigned: usize = result.groups.iter().map(|g| g.packages.len()).sum();
        assert_eq!(total_assigned, 226);

        // Verify zero excess: each package's capabilities == its group's capabilities
        for group in &result.groups {
            for pkg_name in &group.packages {
                let pkg = input.packages.iter().find(|p| &p.name == pkg_name).unwrap();
                let pkg_effective_dns = pkg.needs_dns || !pkg.source_domains.is_empty();
                assert_eq!(
                    group.effective_dns, pkg_effective_dns,
                    "{pkg_name}: group dns should match package dns"
                );
                assert_eq!(
                    group.effective_internet, pkg.needs_internet,
                    "{pkg_name}: group internet should match package internet"
                );
                assert_eq!(
                    group.effective_domains, pkg.source_domains,
                    "{pkg_name}: group domains should match package domains"
                );
            }
        }
    }

    /// Serialization roundtrip: analysis results survive JSON serialization.
    #[test]
    fn e2e_analysis_serialization_roundtrip() {
        let input = realistic_package_set();
        let analysis = analyze(&input);

        let json = serde_json::to_string_pretty(&analysis).unwrap();
        let roundtripped: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped["total_packages"], 226);
        assert_eq!(
            roundtripped["capability_classes"],
            analysis.capability_classes
        );
        assert_eq!(roundtripped["total_excess"], analysis.total_excess);

        // Verify package_excess array has correct length
        assert_eq!(
            roundtripped["package_excess"].as_array().unwrap().len(),
            226
        );
    }
}
