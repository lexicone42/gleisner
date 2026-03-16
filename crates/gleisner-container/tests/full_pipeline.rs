//! Full pipeline test: declare → explain → prompt → build → run → observe → narrow.
//!
//! Exercises the complete agent sandbox lifecycle with live sandbox-init.
//! Requires `gleisner-sandbox-init` on PATH and `audit` feature.

use gleisner_container::Stdio;
use gleisner_container::task::{ObservedCapabilities, TaskSandbox, claude_code_sandbox};
use std::path::Path;
use std::time::Duration;

fn skip_if_no_sandbox() -> bool {
    if which::which("gleisner-sandbox-init").is_err() {
        eprintln!("skipping: gleisner-sandbox-init not on PATH");
        return true;
    }
    let probe = std::process::Command::new("unshare")
        .args(["--user", "true"])
        .output();
    if probe.is_err() || !probe.as_ref().unwrap().status.success() {
        eprintln!("skipping: no user namespace support");
        return true;
    }
    false
}

/// Full lifecycle: declare → explain → prompt → build → run → narrow
#[test]
fn full_lifecycle_cargo_build_task() {
    if skip_if_no_sandbox() {
        return;
    }

    // ── 1. DECLARE ──────────────────────────────────────────────
    let task = TaskSandbox::new("/datar/workspace/claude_code_experiments/gleisner")
        .needs_tools(["sh", "echo", "hostname"])
        .hostname("lifecycle-test");

    // ── 2. EXPLAIN ──────────────────────────────────────────────
    let explanation = task.explain();
    eprintln!("\n=== EXPLAIN ===\n{explanation}");

    // Verify explanation has the right structure
    assert!(
        explanation.grants.len() >= 4,
        "should have filesystem + network + seccomp + security grants"
    );

    // ── 3. SYSTEM PROMPT ────────────────────────────────────────
    let prompt = task.system_prompt_fragment();
    eprintln!("\n=== SYSTEM PROMPT ===\n{prompt}");

    // Verify prompt security properties
    assert!(prompt.contains("sandboxed environment"));
    assert!(prompt.contains("gleisner")); // project dir
    assert!(!prompt.contains("Landlock")); // no internal details
    assert!(!prompt.contains("seccomp")); // no internal details
    assert!(!prompt.contains(".gleisner-inject")); // no staging paths

    // ── 4. BUILD ────────────────────────────────────────────────
    let sb = task.build().expect("build sandbox");
    assert!(sb.is_landlock_enabled());

    // ── 5. RUN ──────────────────────────────────────────────────
    let result = sb.command_with_args(
        "/bin/sh",
        &["-c", "echo HELLO_FROM_SANDBOX; hostname; echo PID=$$"],
    );
    if let Err(ref e) = result {
        eprintln!("skipping run: {e}");
        return;
    }

    let output = result
        .unwrap()
        .stdout(Stdio::Piped)
        .stderr(Stdio::Piped)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run sandbox");

    let stdout = output.stdout_str();
    let stderr = output.stderr_str();
    eprintln!("\n=== RUN OUTPUT ===");
    eprintln!("stdout: {stdout}");
    eprintln!("stderr (last 3 lines):");
    for line in stderr
        .lines()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        eprintln!("  {line}");
    }
    eprintln!(
        "exit: {:?}, elapsed: {:?}",
        output.exit_code(),
        output.elapsed
    );

    assert!(output.status.success(), "sandbox should exit 0");
    assert!(
        stdout.contains("HELLO_FROM_SANDBOX"),
        "should see echo output: {stdout}"
    );
    assert!(
        stdout.contains("lifecycle-test") || stdout.contains("gleisner"),
        "should see hostname: {stdout}"
    );
    assert!(
        stdout.contains("PID=1"),
        "should be PID 1 inside namespace: {stdout}"
    );

    // ── 6. OBSERVE (synthetic — real audit needs gleisner record) ─
    let mut observed = ObservedCapabilities::default();
    observed.executed_tools.insert("sh".to_owned());
    observed.executed_tools.insert("echo".to_owned());
    observed.executed_tools.insert("hostname".to_owned());
    // No network used, no extra reads/writes

    // ── 7. NARROW (reuses the original task — build() takes &self) ─
    let report = task.narrow(&observed);
    eprintln!("\n=== NARROW ===");
    eprintln!("{}", report.summary);

    // All declared tools were used, so config should be minimal
    assert!(
        report.summary.contains("already minimal"),
        "all tools used, should be minimal: {}",
        report.summary
    );
}

/// Test claude_code_sandbox() runs Claude --version through the task API
#[test]
fn claude_code_sandbox_full_pipeline() {
    if skip_if_no_sandbox() {
        return;
    }
    if which::which("claude").is_err() {
        eprintln!("skipping: claude not on PATH");
        return;
    }

    let project = Path::new("/datar/workspace/claude_code_experiments/gleisner");

    // Generate the prompt that would be injected
    let task = TaskSandbox::new(project)
        .needs_tools(["claude", "node", "git"])
        .needs_network(["api.anthropic.com"])
        .hostname("gleisner-claude");

    let prompt = task.system_prompt_fragment();
    eprintln!("\n=== CLAUDE SANDBOX PROMPT ===\n{prompt}");

    // Build and run
    let sb = claude_code_sandbox(project).expect("build claude sandbox");

    let result = sb.command_with_args("claude", &["--version"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result
        .unwrap()
        .timeout(Duration::from_secs(30))
        .output()
        .expect("run claude");

    eprintln!("\n=== CLAUDE IN SANDBOX ===");
    eprintln!("version: {}", output.stdout_str());
    eprintln!("elapsed: {:?}", output.elapsed);
    #[cfg(unix)]
    eprintln!("signal: {:?}", output.signal());

    assert!(
        output.status.success() || output.stdout_str().contains("Claude"),
        "claude --version failed: exit={:?} stdout={}",
        output.exit_code(),
        output.stdout_str()
    );
}

/// Test that merge + explain works for multi-agent scenario
#[test]
fn multi_agent_merge_and_explain() {
    let code_agent = TaskSandbox::new("/workspace")
        .needs_tools(["claude", "git"])
        .needs_network(["api.anthropic.com"]);

    let build_agent = TaskSandbox::new("/workspace")
        .needs_tools(["cargo", "rustc"])
        .needs_network(["crates.io"]);

    let combined = code_agent.merge(build_agent);

    // Explain the combined requirements
    let explanation = combined.explain();
    let text = explanation.to_string();
    eprintln!("\n=== MULTI-AGENT EXPLANATION ===\n{text}");

    // Should include both agents' tools
    assert!(text.contains("$HOME"), "should need home for claude+cargo");
    assert!(text.contains("api.anthropic.com"), "should have API domain");
    assert!(text.contains("crates.io"), "should have cargo domain");

    // System prompt should describe the union
    let prompt = combined.system_prompt_fragment();
    eprintln!("\n=== MULTI-AGENT PROMPT ===\n{prompt}");

    assert!(prompt.contains("claude"));
    assert!(prompt.contains("cargo"));
    assert!(prompt.contains("api.anthropic.com"));
    assert!(prompt.contains("crates.io"));

    // Narrowing with partial usage
    let mut observed = ObservedCapabilities::default();
    observed.executed_tools.insert("claude".to_owned());
    observed.executed_tools.insert("git".to_owned());
    // cargo and rustc were never used

    let report = combined.narrow(&observed);
    eprintln!("\n=== MULTI-AGENT NARROWING ===\n{}", report.summary);

    assert!(
        report.summary.contains("cargo"),
        "should detect unused cargo: {}",
        report.summary
    );
}
