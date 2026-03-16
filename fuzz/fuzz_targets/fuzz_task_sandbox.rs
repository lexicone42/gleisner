//! Fuzz the TaskSandbox builder with arbitrary inputs.
//!
//! Goals:
//! - build() must never panic for any input combination
//! - explain() must never panic
//! - narrow() must never panic
//! - merge() must never panic
//! - system_prompt_fragment() must never contain sandbox internals

#![no_main]
use libfuzzer_sys::fuzz_target;

use gleisner_container::task::{ObservedCapabilities, TaskSandbox};

fuzz_target!(|data: &[u8]| {
    // Split the fuzz input into fields
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let parts: Vec<&str> = s.split('\n').collect();
    if parts.len() < 3 {
        return;
    }

    // Part 0: project dir
    let project_dir = parts[0];
    if project_dir.is_empty() || project_dir.len() > 200 {
        return;
    }

    // Part 1: tools (comma-separated)
    let tools: Vec<&str> = parts[1].split(',').filter(|t| !t.is_empty()).collect();

    // Part 2: domains (comma-separated)
    let domains: Vec<&str> = parts[2].split(',').filter(|d| !d.is_empty()).collect();

    // Build a task — must not panic
    let mut task = TaskSandbox::new(project_dir);
    if !tools.is_empty() {
        task = task.needs_tools(tools.iter().map(|s| s.to_string()));
    }
    if !domains.is_empty() {
        task = task.needs_network(domains.iter().map(|s| s.to_string()));
    }

    // Optional: needs_internet
    if parts.len() > 3 && parts[3] == "internet" {
        task = task.needs_internet();
    }

    // explain() must not panic
    let _explanation = task.explain();

    // explain_verbose() must not panic
    let _verbose = task.explain_verbose();

    // system_prompt_fragment() must not panic and must not leak internals
    let prompt = task.system_prompt_fragment();
    assert!(
        !prompt.contains("gleisner-sandbox-init"),
        "prompt leaked sandbox-init binary"
    );
    assert!(!prompt.contains("SandboxSpec"), "prompt leaked SandboxSpec");

    // build() must not panic (may return Err, that's fine)
    let _sb = task.build();

    // merge with self must not panic
    let task2 = TaskSandbox::new(project_dir);
    let _merged = task.merge(task2);

    // narrow() must not panic
    let mut obs = ObservedCapabilities::default();
    for tool in &tools {
        obs.executed_tools.insert(tool.to_string());
    }
    let task_for_narrow = TaskSandbox::new(project_dir);
    let _report = task_for_narrow.narrow(&obs);
});
