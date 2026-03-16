//! Integration test: write a realistic audit log, observe it, narrow a task.
//!
//! This exercises the full feedback loop with actual JSONL I/O:
//! TaskSandbox → explain → (simulate run with audit log) → observe → narrow
//!
//! Requires `audit` feature.

#![cfg(feature = "audit")]

use std::path::PathBuf;

use chrono::Utc;
use gleisner_container::observe::{observe_from_audit_log, observe_from_audit_logs};
use gleisner_container::task::TaskSandbox;
use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult, JsonlWriter};

fn make_event(kind: EventKind, result: EventResult) -> AuditEvent {
    AuditEvent {
        timestamp: Utc::now(),
        sequence: 0,
        event: kind,
        result,
    }
}

/// Write a realistic audit log simulating a Claude Code session that:
/// - Reads project files (Cargo.toml, src/main.rs)
/// - Runs cargo build
/// - Writes to target/
/// - Connects to crates.io for deps
/// - Reads .gitconfig from home
fn write_realistic_session(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create audit log");
    let mut writer = JsonlWriter::new(file);

    let events = vec![
        // Claude reads project files
        make_event(
            EventKind::FileRead {
                path: PathBuf::from("/workspace/project/Cargo.toml"),
                sha256: "abc123".to_owned(),
            },
            EventResult::Allowed,
        ),
        make_event(
            EventKind::FileRead {
                path: PathBuf::from("/workspace/project/src/main.rs"),
                sha256: "def456".to_owned(),
            },
            EventResult::Allowed,
        ),
        // Claude reads git config
        make_event(
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.gitconfig"),
                sha256: "git789".to_owned(),
            },
            EventResult::Allowed,
        ),
        // Claude runs cargo build
        make_event(
            EventKind::ProcessExec {
                command: "/home/user/.cargo/bin/cargo".to_owned(),
                args: vec!["build".to_owned(), "--release".to_owned()],
                cwd: PathBuf::from("/workspace/project"),
            },
            EventResult::Allowed,
        ),
        // cargo spawns rustc
        make_event(
            EventKind::ProcessExec {
                command: "/home/user/.rustup/toolchains/stable/bin/rustc".to_owned(),
                args: vec!["--edition=2024".to_owned(), "src/main.rs".to_owned()],
                cwd: PathBuf::from("/workspace/project"),
            },
            EventResult::Allowed,
        ),
        // cargo downloads from crates.io
        make_event(
            EventKind::NetworkDns {
                query: "crates.io".to_owned(),
                results: vec!["108.138.64.100".to_owned()],
            },
            EventResult::Allowed,
        ),
        make_event(
            EventKind::NetworkConnect {
                target: "crates.io".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ),
        make_event(
            EventKind::NetworkConnect {
                target: "static.crates.io".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ),
        // Build produces output
        make_event(
            EventKind::FileWrite {
                path: PathBuf::from("/workspace/project/target/release/myapp"),
                sha256_before: None,
                sha256_after: "binary_hash".to_owned(),
            },
            EventResult::Allowed,
        ),
        // Env var read (API key check — only digest logged)
        make_event(
            EventKind::EnvRead {
                key: "ANTHROPIC_API_KEY".to_owned(),
                value_sha256: "key_digest".to_owned(),
            },
            EventResult::Allowed,
        ),
        // Process exit
        make_event(
            EventKind::ProcessExit {
                command: "cargo".to_owned(),
                exit_code: 0,
            },
            EventResult::Allowed,
        ),
    ];

    for event in &events {
        writer.write_event(event).expect("write event");
    }
}

#[test]
fn observe_realistic_session() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp");
    write_realistic_session(tmp.path());

    let observed = observe_from_audit_log(tmp.path()).expect("observe");

    // File reads: /workspace/project (Cargo.toml, src/main.rs) + /home/user (.gitconfig)
    assert!(
        observed
            .read_paths
            .contains(&PathBuf::from("/workspace/project")),
        "should observe project dir reads: {:?}",
        observed.read_paths
    );
    assert!(
        observed
            .read_paths
            .contains(&PathBuf::from("/workspace/project/src")),
        "should observe src dir reads: {:?}",
        observed.read_paths
    );
    assert!(
        observed.read_paths.contains(&PathBuf::from("/home/user")),
        "should observe home dir reads: {:?}",
        observed.read_paths
    );

    // File writes: target/release/
    assert!(
        observed
            .write_paths
            .contains(&PathBuf::from("/workspace/project/target/release")),
        "should observe target writes: {:?}",
        observed.write_paths
    );

    // Tools: cargo, rustc
    assert!(
        observed.executed_tools.contains("cargo"),
        "should see cargo"
    );
    assert!(
        observed.executed_tools.contains("rustc"),
        "should see rustc"
    );

    // Network: crates.io, static.crates.io
    assert!(
        observed.contacted_domains.contains("crates.io"),
        "should see crates.io: {:?}",
        observed.contacted_domains
    );
    assert!(
        observed.contacted_domains.contains("static.crates.io"),
        "should see static.crates.io: {:?}",
        observed.contacted_domains
    );
}

#[test]
fn observe_then_narrow_finds_unused() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp");
    write_realistic_session(tmp.path());

    let observed = observe_from_audit_log(tmp.path()).expect("observe");

    // Declare a task with MORE capabilities than the session used
    let task = TaskSandbox::new("/workspace/project")
        .needs_tools(["cargo", "rustc", "git", "npm"]) // git + npm unused
        .needs_network(["crates.io", "registry.npmjs.org", "api.anthropic.com"]); // npm registry + api unused

    let report = task.narrow(&observed);

    eprintln!("Narrowing report: {}", report.summary);

    // git and npm were never used
    assert!(
        report.summary.contains("git"),
        "should detect unused git: {}",
        report.summary
    );
    assert!(
        report.summary.contains("npm"),
        "should detect unused npm: {}",
        report.summary
    );

    // api.anthropic.com and registry.npmjs.org were never contacted
    assert!(
        report.summary.contains("api.anthropic.com"),
        "should detect unused API domain: {}",
        report.summary
    );
    assert!(
        report.summary.contains("registry.npmjs.org"),
        "should detect unused npm registry: {}",
        report.summary
    );

    // Suggested config should keep only cargo, rustc, crates.io
    let suggested_tools = report.suggested_config.tools();
    let suggested_domains = report.suggested_config.domains();
    assert!(suggested_tools.contains(&"cargo".to_owned()));
    assert!(suggested_tools.contains(&"rustc".to_owned()));
    assert!(!suggested_tools.contains(&"npm".to_owned()));
    assert!(suggested_domains.contains(&"crates.io".to_owned()));
    assert!(!suggested_domains.contains(&"api.anthropic.com".to_owned()));
}

#[test]
fn observe_multiple_logs_merges() {
    let tmp1 = tempfile::NamedTempFile::new().expect("create temp1");
    let tmp2 = tempfile::NamedTempFile::new().expect("create temp2");

    // Log 1: cargo build session
    {
        let file = std::fs::File::create(tmp1.path()).unwrap();
        let mut w = JsonlWriter::new(file);
        w.write_event(&make_event(
            EventKind::ProcessExec {
                command: "cargo".to_owned(),
                args: vec!["build".to_owned()],
                cwd: PathBuf::from("/workspace"),
            },
            EventResult::Allowed,
        ))
        .unwrap();
    }

    // Log 2: git session
    {
        let file = std::fs::File::create(tmp2.path()).unwrap();
        let mut w = JsonlWriter::new(file);
        w.write_event(&make_event(
            EventKind::ProcessExec {
                command: "git".to_owned(),
                args: vec!["commit".to_owned()],
                cwd: PathBuf::from("/workspace"),
            },
            EventResult::Allowed,
        ))
        .unwrap();
    }

    let observed = observe_from_audit_logs([tmp1.path(), tmp2.path()]).expect("observe multiple");

    assert!(
        observed.executed_tools.contains("cargo"),
        "should merge cargo"
    );
    assert!(observed.executed_tools.contains("git"), "should merge git");
}
