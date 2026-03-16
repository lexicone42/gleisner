//! Property-based tests for gleisner-container.
//!
//! These verify invariants that must hold for ALL possible inputs,
//! not just the specific cases covered by unit tests.

use std::collections::BTreeSet;
use std::path::PathBuf;

use gleisner_container::task::{ObservedCapabilities, TaskSandbox};
use proptest::prelude::*;

/// Known tool names that trigger special behavior in build/explain/prompt.
const KNOWN_TOOLS: &[&str] = &[
    "claude", "node", "npm", "npx", "git", "cargo", "rustc", "pip", "uv", "uvx", "sh",
];

/// Strategy for generating a TaskSandbox with random configuration.
fn arb_task_sandbox() -> impl Strategy<Value = TaskSandbox> {
    let tools = prop::collection::vec(prop::sample::select(KNOWN_TOOLS), 0..5);
    let domains = prop::collection::vec("[a-z][a-z0-9.]{0,15}", 0..4);
    let read_paths = prop::collection::vec("/[a-z]{1,6}(/[a-z]{1,6}){0,2}", 0..3);
    let internet = any::<bool>();
    let home = any::<bool>();

    (tools, domains, read_paths, internet, home).prop_map(
        |(tools, domains, read_paths, internet, home)| {
            let mut t = TaskSandbox::new("/workspace/proptest");
            t = t.needs_tools(tools.iter().map(|s| (*s).to_owned()));
            if !domains.is_empty() {
                t = t.needs_network(domains);
            }
            if !read_paths.is_empty() {
                t = t.needs_read(read_paths.iter().map(PathBuf::from));
            }
            if internet {
                t = t.needs_internet();
            }
            if home {
                t = t.with_home();
            }
            t
        },
    )
}

/// Strategy for generating ObservedCapabilities.
fn arb_observed(task: &TaskSandbox) -> ObservedCapabilities {
    // Randomly include subsets of declared capabilities
    let mut obs = ObservedCapabilities::default();
    for tool in task.tools() {
        obs.executed_tools.insert(tool.clone());
    }
    for domain in task.domains() {
        obs.contacted_domains.insert(domain.clone());
    }
    obs
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // ── Property 1: build() always produces Landlock-enabled sandbox ───

    #[test]
    fn task_build_always_enables_landlock(task in arb_task_sandbox()) {
        let sb = task.build().expect("build should succeed");
        prop_assert!(
            sb.is_landlock_enabled(),
            "TaskSandbox::build() must always enable Landlock"
        );
    }

    // ── Property 3: merge is a superset of both inputs ────────────────

    #[test]
    fn merge_is_superset(
        a in arb_task_sandbox(),
        b in arb_task_sandbox(),
    ) {
        let a_tools: BTreeSet<String> = a.tools().iter().cloned().collect();
        let a_domains: BTreeSet<String> = a.domains().iter().cloned().collect();
        let b_tools: BTreeSet<String> = b.tools().iter().cloned().collect();
        let b_domains: BTreeSet<String> = b.domains().iter().cloned().collect();

        let combined = a.merge(b);
        let c_tools: BTreeSet<String> = combined.tools().iter().cloned().collect();
        let c_domains: BTreeSet<String> = combined.domains().iter().cloned().collect();

        // Superset of both inputs
        prop_assert!(
            a_tools.is_subset(&c_tools),
            "merge must be superset of a's tools: a={a_tools:?} combined={c_tools:?}"
        );
        prop_assert!(
            b_tools.is_subset(&c_tools),
            "merge must be superset of b's tools: b={b_tools:?} combined={c_tools:?}"
        );
        prop_assert!(
            a_domains.is_subset(&c_domains),
            "merge must be superset of a's domains"
        );
        prop_assert!(
            b_domains.is_subset(&c_domains),
            "merge must be superset of b's domains"
        );
    }

    // ── Property 5: merge never reduces tool count ────────────────────

    #[test]
    fn merge_monotone_unique_tools(
        a in arb_task_sandbox(),
        b in arb_task_sandbox(),
    ) {
        // Compare unique tool counts (merge deduplicates)
        let a_unique: BTreeSet<_> = a.tools().iter().cloned().collect();
        let b_unique: BTreeSet<_> = b.tools().iter().cloned().collect();
        let max_unique = a_unique.len().max(b_unique.len());
        let combined = a.merge(b);
        let c_unique: BTreeSet<_> = combined.tools().iter().cloned().collect();
        prop_assert!(
            c_unique.len() >= max_unique,
            "merge must not reduce unique tool count: max={max_unique} combined={}",
            c_unique.len()
        );
    }

    // ── Property 6: explain() always has >= 3 security grants ─────────

    #[test]
    fn explain_has_security_grants(task in arb_task_sandbox()) {
        let explanation = task.explain();
        let security_count = explanation.grants.iter()
            .filter(|g| g.category == "security")
            .count();
        prop_assert!(
            security_count >= 3,
            "explain must have >= 3 security grants, got {security_count}"
        );
    }

    // ── Property 7: adding tools never reduces explain grants ─────────

    #[test]
    fn explain_monotone_in_tools(
        task in arb_task_sandbox(),
        new_tool in prop::sample::select(KNOWN_TOOLS),
    ) {
        let baseline = task.explain().grants.len();
        let with_tool = task.needs_tools([new_tool.to_string()]);
        let extended = with_tool.explain().grants.len();
        prop_assert!(
            extended >= baseline,
            "adding tool '{new_tool}' reduced grants: {baseline} -> {extended}"
        );
    }

    // ── Property 9: system prompt never leaks implementation details ──

    #[test]
    fn prompt_never_leaks_internals(task in arb_task_sandbox()) {
        let prompt = task.system_prompt_fragment();
        let forbidden = [
            "Landlock:", "seccomp", "gleisner-sandbox-init",
            "CLONE_NEW", "pivot_root", ".gleisner-inject",
            "namespace:", "SandboxSpec",
        ];
        for word in &forbidden {
            prop_assert!(
                !prompt.contains(word),
                "prompt leaked internal detail '{word}': {prompt}"
            );
        }
    }

    // ── Property 12: narrow suggested_config is intersection subset ───

    #[test]
    fn narrow_suggested_is_subset(task in arb_task_sandbox()) {
        let observed = arb_observed(&task);
        let report = task.narrow(&observed);

        // Suggested tools must be subset of BOTH declared and observed
        for tool in report.suggested_config.tools() {
            prop_assert!(
                task.tools().contains(tool),
                "suggested tool '{tool}' not in original declaration"
            );
            prop_assert!(
                observed.executed_tools.contains(tool),
                "suggested tool '{tool}' not in observed set"
            );
        }

        // Suggested domains must be subset of BOTH declared and observed
        for domain in report.suggested_config.domains() {
            prop_assert!(
                task.domains().contains(domain),
                "suggested domain '{domain}' not in original declaration"
            );
            prop_assert!(
                observed.contacted_domains.contains(domain),
                "suggested domain '{domain}' not in observed set"
            );
        }
    }

    // ── Property 11: narrow with full observation → no unused tools/domains ─

    #[test]
    fn narrow_full_observation_no_unused_tools_or_domains(task in arb_task_sandbox()) {
        let observed = arb_observed(&task);
        let report = task.narrow(&observed);
        // Tools and domains should all be "used" since we copy them to observed.
        // read_paths may appear unused since we don't expose them via a getter —
        // that's a known limitation, not a bug.
        let tool_unused = report.unused.iter().any(|u| u.starts_with("tools:"));
        let domain_unused = report.unused.iter().any(|u| u.starts_with("domains:"));
        prop_assert!(
            !tool_unused,
            "full observation should have no unused tools: {:?}",
            report.unused
        );
        prop_assert!(
            !domain_unused,
            "full observation should have no unused domains: {:?}",
            report.unused
        );
    }

    // ── Property 14: prompt mentions all declared domains ─────────────

    #[test]
    fn prompt_mentions_all_declared_domains(task in arb_task_sandbox()) {
        let prompt = task.system_prompt_fragment();
        // Only check when not needs_internet (which uses "Unrestricted")
        if !prompt.contains("Unrestricted") {
            for domain in task.domains() {
                prop_assert!(
                    prompt.contains(domain.as_str()),
                    "prompt missing declared domain '{domain}': {prompt}"
                );
            }
        }
    }
}
