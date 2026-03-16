//! Fuzz the system prompt generator with adversarial inputs.
//!
//! Goals:
//! - system_prompt_fragment() must never panic
//! - Must never contain sandbox implementation details
//! - Must handle arbitrary Unicode, control characters, very long strings
//! - explain().to_system_prompt() must never panic

#![no_main]
use libfuzzer_sys::fuzz_target;

use gleisner_container::task::TaskSandbox;

/// Strings that indicate implementation detail leaks when they appear
/// in CONTEXT (not just as tool names). We check these appear only
/// within the "Available tools:" line if they're user-provided tool names.
const FORBIDDEN_CONTEXTS: &[&str] = &[
    "SandboxSpec",
    "pivot_root",
    "CLONE_NEW",
    ".gleisner-inject",
    "seccomp-bpf",
    "Landlock:",
];

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Use the fuzz input as tool names, domain names, and paths
    let parts: Vec<&str> = s.split('\0').collect();

    let mut task = TaskSandbox::new("/workspace/fuzz");

    // Add arbitrary strings as tools (validation should reject bad ones)
    for part in parts.iter().take(5) {
        if !part.is_empty() && part.len() < 100 {
            task = task.needs_tools([part.to_string()]);
        }
    }

    // Add arbitrary strings as domains
    for part in parts.iter().skip(5).take(3) {
        if !part.is_empty() && part.len() < 100 {
            task = task.needs_network([part.to_string()]);
        }
    }

    // system_prompt_fragment() must not panic
    let prompt = task.system_prompt_fragment();

    // Security invariant: no implementation details in non-tool-name context
    // Tool names are user-controlled and may contain anything — that's fine.
    // We check that forbidden strings don't appear OUTSIDE the "Available tools:" line.
    let non_tools_section: String = prompt
        .lines()
        .filter(|l| !l.starts_with("Available tools:"))
        .collect::<Vec<_>>()
        .join("\n");
    for word in FORBIDDEN_CONTEXTS {
        assert!(
            !non_tools_section.contains(word),
            "system prompt leaked forbidden context '{word}' outside tools line"
        );
    }

    // explain() must not panic
    let explanation = task.explain();

    // to_system_prompt() must not panic
    let _prompt2 = explanation.to_system_prompt();

    // explain_verbose() must not panic
    let _verbose = task.explain_verbose();

    // write_context_file in a temp dir must not panic
    // (skip this — it does I/O which is slow for fuzzing)
});
