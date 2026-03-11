//! Composed environment security analysis via Z3 SMT solver.
//!
//! When packages are composed into a single sandbox, each package gets the
//! **union** of all packages' capabilities — even capabilities it never
//! declared. This module answers three questions:
//!
//! 1. **Excess report**: which packages get capabilities they didn't ask for?
//! 2. **Capability classes**: how many distinct capability profiles exist?
//! 3. **Optimal partitioning**: given K sandbox groups, what assignment
//!    minimizes capability excess? (Z3 optimization)
//!
//! # Encoding
//!
//! Each package has a capability vector: `(needs_dns, needs_internet, {domains})`.
//! The composed environment grants the component-wise OR across all packages.
//! For partitioning, each package gets an Int variable `group_i ∈ [0, K)`.
//! Group capabilities are the union of members'. Z3's `Optimize` solver with
//! soft constraints finds assignments that minimize total excess.

use std::collections::{BTreeMap, BTreeSet};

use z3::ast::Int;
use z3::{Optimize, SatResult};

// ── Input types ──────────────────────────────────────────────

/// Per-package capability declaration, as extracted from Nickel evaluation.
///
/// Forge constructs these from `ComposedEnvironment` data — each package's
/// `needs` flags and source domain URLs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageCapabilities {
    /// Package name.
    pub name: String,
    /// Whether this package declared `needs = { dns }`.
    pub needs_dns: bool,
    /// Whether this package declared `needs = { internet }`.
    pub needs_internet: bool,
    /// Domains this package's sources download from (from `build_deps` URLs).
    pub source_domains: BTreeSet<String>,
}

/// Input for composed environment analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompositionInput {
    /// Per-package capability declarations.
    pub packages: Vec<PackageCapabilities>,
}

// ── Output types ─────────────────────────────────────────────

/// Complete analysis of a composed environment's capability grants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompositionAnalysis {
    /// Total packages analyzed.
    pub total_packages: usize,
    /// Per-package excess report.
    pub package_excess: Vec<PackageExcess>,
    /// Total excess capability units across all packages.
    /// (1 unit = 1 capability granted but not declared, per package.)
    pub total_excess: usize,
    /// Number of distinct capability classes (packages with identical vectors).
    pub capability_classes: usize,
    /// Class details.
    pub classes: Vec<CapabilityClass>,
    /// Effective composed grant (union of all packages).
    pub composed_grant: ComposedGrant,
}

/// Excess capabilities granted to a single package by the composition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageExcess {
    /// Package name.
    pub name: String,
    /// Granted DNS but didn't declare it.
    pub excess_dns: bool,
    /// Granted internet but didn't declare it.
    pub excess_internet: bool,
    /// Domains granted but not needed by this package.
    pub excess_domains: Vec<String>,
    /// Total excess capability count.
    pub excess_count: usize,
}

/// A group of packages with identical capability vectors.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilityClass {
    /// Whether packages in this class need DNS.
    pub needs_dns: bool,
    /// Whether packages in this class need internet.
    pub needs_internet: bool,
    /// Source domains required by packages in this class.
    pub domains: BTreeSet<String>,
    /// Packages in this class.
    pub packages: Vec<String>,
}

/// The effective capability grant of the composed environment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComposedGrant {
    /// Whether DNS is granted (any package needs DNS or has source domains).
    pub dns: bool,
    /// Whether full internet is granted (any package needs internet).
    pub internet: bool,
    /// All unique domains in the domain allowlist.
    pub domains: BTreeSet<String>,
}

/// Result of Z3 optimal partitioning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartitionResult {
    /// Number of groups used.
    pub group_count: usize,
    /// Per-group details.
    pub groups: Vec<PartitionGroup>,
    /// Total excess across all packages after partitioning.
    pub total_excess: usize,
    /// Whether partitioning achieved zero excess.
    pub zero_excess: bool,
}

/// A single sandbox partition group.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartitionGroup {
    /// Group index.
    pub id: usize,
    /// Packages assigned to this group.
    pub packages: Vec<String>,
    /// Effective DNS grant for this group.
    pub effective_dns: bool,
    /// Effective internet grant for this group.
    pub effective_internet: bool,
    /// Effective domain allowlist for this group.
    pub effective_domains: BTreeSet<String>,
}

// ── Analysis (no Z3) ─────────────────────────────────────────

/// Compute the composed grant: component-wise OR across all packages.
pub fn compute_composed_grant(input: &CompositionInput) -> ComposedGrant {
    let mut dns = false;
    let mut internet = false;
    let mut domains = BTreeSet::new();
    for pkg in &input.packages {
        dns |= pkg.needs_dns;
        internet |= pkg.needs_internet;
        domains.extend(pkg.source_domains.iter().cloned());
    }
    // Source domains imply DNS (same as bridge.rs logic)
    if !domains.is_empty() {
        dns = true;
    }
    ComposedGrant {
        dns,
        internet,
        domains,
    }
}

/// Compute per-package excess when all packages share one sandbox.
pub fn compute_excess(input: &CompositionInput) -> (Vec<PackageExcess>, ComposedGrant) {
    let grant = compute_composed_grant(input);
    let excess = input
        .packages
        .iter()
        .map(|pkg| {
            let excess_dns = grant.dns && !pkg.needs_dns && pkg.source_domains.is_empty();
            let excess_internet = grant.internet && !pkg.needs_internet;
            let excess_domains: Vec<String> = grant
                .domains
                .difference(&pkg.source_domains)
                .cloned()
                .collect();
            let excess_count =
                usize::from(excess_dns) + usize::from(excess_internet) + excess_domains.len();
            PackageExcess {
                name: pkg.name.clone(),
                excess_dns,
                excess_internet,
                excess_domains,
                excess_count,
            }
        })
        .collect();
    (excess, grant)
}

/// Group packages into capability classes (identical capability vectors).
pub fn compute_capability_classes(input: &CompositionInput) -> Vec<CapabilityClass> {
    let mut classes: BTreeMap<(bool, bool, BTreeSet<String>), Vec<String>> = BTreeMap::new();
    for pkg in &input.packages {
        let key = (
            pkg.needs_dns || !pkg.source_domains.is_empty(), // effective dns
            pkg.needs_internet,
            pkg.source_domains.clone(),
        );
        classes.entry(key).or_default().push(pkg.name.clone());
    }
    classes
        .into_iter()
        .map(|((dns, internet, domains), packages)| CapabilityClass {
            needs_dns: dns,
            needs_internet: internet,
            domains,
            packages,
        })
        .collect()
}

/// Full analysis without Z3 partitioning.
pub fn analyze(input: &CompositionInput) -> CompositionAnalysis {
    let (package_excess, composed_grant) = compute_excess(input);
    let total_excess: usize = package_excess.iter().map(|e| e.excess_count).sum();
    let classes = compute_capability_classes(input);
    CompositionAnalysis {
        total_packages: input.packages.len(),
        package_excess,
        total_excess,
        capability_classes: classes.len(),
        classes,
        composed_grant,
    }
}

// ── Z3 optimal partitioning ──────────────────────────────────

/// Find the optimal partition of packages into `k` groups that minimizes
/// total capability excess.
///
/// Operates on **capability classes**, not individual packages. Packages
/// with identical capability vectors always share a group in the optimal
/// solution, so this reduces the problem from O(N) to O(C) variables
/// where C is the number of distinct capability profiles (typically ~10-15
/// for a 226-package composition).
///
/// Uses Z3's `Optimize` solver with weighted soft constraints. Each excess
/// capability unit is weighted by the class size (number of affected packages).
///
/// # Returns
///
/// `None` if the problem is infeasible (shouldn't happen — any assignment
/// is valid, just with varying excess).
///
/// # Panics
///
/// Panics if Z3 returns SAT but fails to produce a model.
#[expect(
    clippy::cast_possible_wrap,
    reason = "package counts and domain indices don't approach i64::MAX"
)]
pub fn find_optimal_partition(input: &CompositionInput, k: usize) -> Option<PartitionResult> {
    if input.packages.is_empty() || k == 0 {
        return Some(PartitionResult {
            group_count: 0,
            groups: vec![],
            total_excess: 0,
            zero_excess: true,
        });
    }

    let classes = compute_capability_classes(input);
    let c = classes.len();

    // Collect all unique capabilities (domains + dns + internet).
    let all_domains: Vec<String> = {
        let mut set = BTreeSet::new();
        for cls in &classes {
            set.extend(cls.domains.iter().cloned());
        }
        set.into_iter().collect()
    };

    let opt = Optimize::new();

    // One Int variable per capability class (not per package).
    let class_vars: Vec<Int> = (0..c).map(|i| Int::new_const(format!("cls_{i}"))).collect();

    // Domain: class_i in [0, k)
    let zero = Int::from_i64(0);
    let k_val = Int::from_i64(k as i64);
    for cv in &class_vars {
        opt.assert(&cv.ge(&zero));
        opt.assert(&cv.lt(&k_val));
    }

    // Symmetry breaking: first class goes to group 0.
    if !classes.is_empty() {
        opt.assert(&class_vars[0].eq(Int::from_i64(0)));
    }

    // For each pair of classes (ci, cj) where cj has a capability that ci
    // doesn't, add a weighted soft constraint: prefer they're in different
    // groups. Weight = |ci| (number of packages that get excess).
    for (i, cls_i) in classes.iter().enumerate() {
        let weight = cls_i.packages.len() as u32;

        for (j, cls_j) in classes.iter().enumerate() {
            if i == j {
                continue;
            }

            let same_group = class_vars[i].eq(&class_vars[j]);

            // DNS excess: ci doesn't have dns, cj does
            if !cls_i.needs_dns && cls_j.needs_dns {
                opt.assert_soft(&same_group.not(), weight, None);
            }

            // Internet excess: ci doesn't have internet, cj does
            if !cls_i.needs_internet && cls_j.needs_internet {
                opt.assert_soft(&same_group.not(), weight, None);
            }

            // Domain excess: for each domain in cj but not in ci
            let excess_domain_count = cls_j.domains.difference(&cls_i.domains).count();
            if excess_domain_count > 0 {
                // Weight = |ci| * number of excess domains
                #[expect(clippy::cast_possible_truncation, reason = "domain counts are tiny")]
                let domain_weight = weight * excess_domain_count as u32;
                opt.assert_soft(&same_group.not(), domain_weight, None);
            }
        }
    }

    match opt.check(&[]) {
        SatResult::Sat | SatResult::Unknown => {
            let model = opt.get_model().expect("Optimize result must have a model");
            extract_partition_from_classes(&model, &class_vars, &classes, k, &all_domains)
        }
        SatResult::Unsat => None,
    }
}

/// Extract partition assignment from a Z3 model (class-level).
#[expect(
    clippy::cast_sign_loss,
    reason = "group indices are non-negative by construction"
)]
fn extract_partition_from_classes(
    model: &z3::Model,
    class_vars: &[Int],
    classes: &[CapabilityClass],
    k: usize,
    all_domains: &[String],
) -> Option<PartitionResult> {
    let class_assignments: Vec<usize> = class_vars
        .iter()
        .map(|cv| model.eval(cv, true).and_then(|v| v.as_i64()).unwrap_or(0) as usize)
        .collect();

    // Build groups from class assignments.
    let mut groups: Vec<PartitionGroup> = (0..k)
        .map(|id| PartitionGroup {
            id,
            packages: vec![],
            effective_dns: false,
            effective_internet: false,
            effective_domains: BTreeSet::new(),
        })
        .collect();

    for (ci, &g) in class_assignments.iter().enumerate() {
        if g >= k {
            continue;
        }
        let cls = &classes[ci];
        groups[g].packages.extend(cls.packages.iter().cloned());
        groups[g].effective_dns |= cls.needs_dns;
        groups[g].effective_internet |= cls.needs_internet;
        groups[g]
            .effective_domains
            .extend(cls.domains.iter().cloned());
    }

    // Remove empty groups.
    groups.retain(|g| !g.packages.is_empty());

    // Compute total excess after partitioning.
    let mut total_excess = 0;
    for (ci, &g) in class_assignments.iter().enumerate() {
        if g >= k {
            continue;
        }
        let cls = &classes[ci];
        let group = groups.iter().find(|grp| grp.id == g).unwrap();
        let pkg_count = cls.packages.len();

        if group.effective_dns && !cls.needs_dns {
            total_excess += pkg_count;
        }
        if group.effective_internet && !cls.needs_internet {
            total_excess += pkg_count;
        }
        for domain in all_domains {
            if group.effective_domains.contains(domain) && !cls.domains.contains(domain) {
                total_excess += pkg_count;
            }
        }
    }

    Some(PartitionResult {
        group_count: groups.len(),
        groups,
        total_excess,
        zero_excess: total_excess == 0,
    })
}

/// Find the minimum number of groups needed for zero excess.
///
/// The minimum K for zero excess is always `|classes|`: packages with different
/// capability vectors in the same group necessarily produce excess (the group
/// grants the union, which exceeds at least one member's declaration).
///
/// This function computes the partition at K = `|classes|` via Z3 and then
/// searches downward to verify no smaller K achieves zero excess. In practice
/// it returns immediately since K = `|classes|` is both necessary and sufficient.
pub fn find_minimum_zero_excess_groups(input: &CompositionInput) -> PartitionResult {
    let classes = compute_capability_classes(input);
    let max_k = classes.len();

    if max_k == 0 {
        return PartitionResult {
            group_count: 0,
            groups: vec![],
            total_excess: 0,
            zero_excess: true,
        };
    }

    // K = |classes| is guaranteed to achieve zero excess. Verify via Z3
    // and return the concrete assignment.
    let result =
        find_optimal_partition(input, max_k).expect("partition with k=|classes| must succeed");

    if !result.zero_excess {
        // Shouldn't happen — defensive fallback.
        return result;
    }

    // Try K-1 downward to see if any merges preserve zero excess.
    // Stop as soon as we can't achieve it.
    let mut best = result;
    for k in (1..max_k).rev() {
        if let Some(r) = find_optimal_partition(input, k) {
            if r.zero_excess {
                best = r;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    best
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, dns: bool, internet: bool, domains: &[&str]) -> PackageCapabilities {
        PackageCapabilities {
            name: name.to_string(),
            needs_dns: dns,
            needs_internet: internet,
            source_domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    // ── Excess analysis ──────────────────────────────────────

    #[test]
    fn single_package_has_no_excess() {
        let input = CompositionInput {
            packages: vec![pkg("zlib", true, false, &["github.com"])],
        };
        let (excess, _) = compute_excess(&input);
        assert_eq!(excess[0].excess_count, 0);
    }

    #[test]
    fn identical_packages_have_no_excess() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", true, false, &["github.com"]),
                pkg("curl", true, false, &["github.com"]),
            ],
        };
        let (excess, _) = compute_excess(&input);
        assert!(excess.iter().all(|e| e.excess_count == 0));
    }

    #[test]
    fn internet_excess_when_one_package_needs_internet() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", true, false, &["github.com"]),
                pkg("npm", true, true, &["registry.npmjs.org"]),
            ],
        };
        let (excess, grant) = compute_excess(&input);
        assert!(grant.internet);
        // zlib gets excess internet
        assert!(excess[0].excess_internet);
        assert!(!excess[1].excess_internet);
    }

    #[test]
    fn domain_excess_for_unrelated_packages() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("gcc", false, false, &["storage.googleapis.com"]),
            ],
        };
        let (excess, _) = compute_excess(&input);
        assert_eq!(excess[0].excess_domains, vec!["storage.googleapis.com"]);
        assert_eq!(excess[1].excess_domains, vec!["github.com"]);
    }

    #[test]
    fn total_excess_computation() {
        let input = CompositionInput {
            packages: vec![
                pkg("a", true, false, &["x.com"]),
                pkg("b", false, true, &["y.com"]),
            ],
        };
        let analysis = analyze(&input);
        // a: excess internet + excess domain y.com = 2
        // b: has source_domains so effective_dns=true, no excess dns
        //    excess_domains: x.com = 1
        // total = 3
        assert_eq!(analysis.total_excess, 3);
    }

    // ── Capability classes ───────────────────────────────────

    #[test]
    fn identical_packages_form_one_class() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", true, false, &["github.com"]),
                pkg("curl", true, false, &["github.com"]),
                pkg("openssl", true, false, &["github.com"]),
            ],
        };
        let classes = compute_capability_classes(&input);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].packages.len(), 3);
    }

    #[test]
    fn different_capabilities_form_separate_classes() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("npm", false, true, &["registry.npmjs.org"]),
                pkg("curl", false, false, &["github.com"]),
            ],
        };
        let classes = compute_capability_classes(&input);
        assert_eq!(classes.len(), 2);
    }

    // ── Z3 partitioning ──────────────────────────────────────

    #[test]
    fn partition_single_group_has_same_excess_as_composed() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("npm", false, true, &["registry.npmjs.org"]),
            ],
        };
        let analysis = analyze(&input);
        let partition = find_optimal_partition(&input, 1).unwrap();
        assert_eq!(partition.total_excess, analysis.total_excess);
    }

    #[test]
    fn partition_into_classes_achieves_zero_excess() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("curl", false, false, &["github.com"]),
                pkg("npm", false, true, &["registry.npmjs.org"]),
            ],
        };
        let classes = compute_capability_classes(&input);
        let partition = find_optimal_partition(&input, classes.len()).unwrap();
        assert!(
            partition.zero_excess,
            "partitioning into {} groups should achieve zero excess, got excess={}",
            classes.len(),
            partition.total_excess
        );
    }

    #[test]
    fn optimal_partition_reduces_excess() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("curl", false, false, &["github.com"]),
                pkg("npm", false, true, &["registry.npmjs.org"]),
                pkg("pip", false, true, &["pypi.org"]),
            ],
        };
        let k1 = find_optimal_partition(&input, 1).unwrap();
        let k2 = find_optimal_partition(&input, 2).unwrap();
        assert!(
            k2.total_excess <= k1.total_excess,
            "k=2 ({}) should be <= k=1 ({})",
            k2.total_excess,
            k1.total_excess
        );
    }

    #[test]
    fn minimum_zero_excess_groups() {
        let input = CompositionInput {
            packages: vec![
                pkg("zlib", false, false, &["github.com"]),
                pkg("curl", false, false, &["github.com"]),
                pkg("npm", false, true, &["registry.npmjs.org"]),
                pkg("pip", false, true, &["pypi.org"]),
            ],
        };
        let result = find_minimum_zero_excess_groups(&input);
        assert!(result.zero_excess);
        let classes = compute_capability_classes(&input);
        assert!(
            result.group_count <= classes.len(),
            "should need at most {} groups, got {}",
            classes.len(),
            result.group_count
        );
    }

    #[test]
    fn empty_input_handled() {
        let input = CompositionInput { packages: vec![] };
        let analysis = analyze(&input);
        assert_eq!(analysis.total_excess, 0);
        assert_eq!(analysis.capability_classes, 0);

        let partition = find_optimal_partition(&input, 0).unwrap();
        assert!(partition.zero_excess);
    }

    // ── Realistic scenario ───────────────────────────────────

    #[test]
    fn realistic_package_mix() {
        // Simulate a realistic mix: most packages download from github,
        // a few need GCS, one needs full internet.
        let github_only: Vec<PackageCapabilities> = (0..10)
            .map(|i| pkg(&format!("lib{i}"), false, false, &["github.com"]))
            .collect();

        let gcs_pkgs = vec![
            pkg("gcc", false, false, &["storage.googleapis.com"]),
            pkg("binutils", false, false, &["storage.googleapis.com"]),
        ];

        let internet_pkg = vec![pkg(
            "node",
            true,
            true,
            &["registry.npmjs.org", "github.com"],
        )];

        let mut all = github_only;
        all.extend(gcs_pkgs);
        all.extend(internet_pkg);

        let input = CompositionInput { packages: all };

        // Analyze flat composition
        let analysis = analyze(&input);
        assert!(
            analysis.total_excess > 0,
            "heterogeneous mix should have excess"
        );

        // The internet package forces internet on everyone in a single sandbox
        let internet_excess = analysis
            .package_excess
            .iter()
            .filter(|e| e.excess_internet)
            .count();
        assert_eq!(internet_excess, 12, "12 of 13 packages get excess internet");

        // K=2 should dramatically reduce excess by isolating the internet package
        let k2 = find_optimal_partition(&input, 2).unwrap();
        assert!(
            k2.total_excess < analysis.total_excess,
            "k=2 ({}) should beat k=1 ({})",
            k2.total_excess,
            analysis.total_excess
        );

        // Verify the internet package is isolated
        let node_group = k2
            .groups
            .iter()
            .find(|g| g.packages.contains(&"node".to_string()));
        assert!(node_group.is_some());
        assert!(node_group.unwrap().effective_internet);

        // The non-internet group should NOT have internet
        let other_groups: Vec<_> = k2
            .groups
            .iter()
            .filter(|g| !g.packages.contains(&"node".to_string()))
            .collect();
        for g in &other_groups {
            assert!(
                !g.effective_internet,
                "group {} should not have internet but does: {:?}",
                g.id, g.packages
            );
        }
    }

    #[test]
    fn partition_correctness_cross_validation() {
        // Verify that the partition's reported effective capabilities
        // are the actual union of its members' capabilities.
        let input = CompositionInput {
            packages: vec![
                pkg("a", true, false, &["x.com", "y.com"]),
                pkg("b", false, true, &["y.com", "z.com"]),
                pkg("c", true, true, &["x.com"]),
            ],
        };

        let result = find_optimal_partition(&input, 2).unwrap();

        for group in &result.groups {
            let mut expected_dns = false;
            let mut expected_internet = false;
            let mut expected_domains = BTreeSet::new();
            for pkg_name in &group.packages {
                let pkg = input.packages.iter().find(|p| &p.name == pkg_name).unwrap();
                expected_dns |= pkg.needs_dns || !pkg.source_domains.is_empty();
                expected_internet |= pkg.needs_internet;
                expected_domains.extend(pkg.source_domains.iter().cloned());
            }
            assert_eq!(
                group.effective_dns, expected_dns,
                "group {} dns mismatch",
                group.id
            );
            assert_eq!(
                group.effective_internet, expected_internet,
                "group {} internet mismatch",
                group.id
            );
            assert_eq!(
                group.effective_domains, expected_domains,
                "group {} domains mismatch",
                group.id
            );
        }
    }
}
