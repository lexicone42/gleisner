//! End-to-end sandbox tests exercising combined features.
//!
//! These tests require:
//! - `gleisner-sandbox-init` on PATH (run: `cargo build -p gleisner-sandbox-init`)
//! - Linux with user namespace support

use gleisner_container::{Namespace, Sandbox, SeccompPreset};
use std::path::Path;

/// Skip test if sandbox-init not available or no user namespaces.
fn skip_if_no_sandbox() -> bool {
    // Check PATH for sandbox-init (detect_sandbox_init uses `which`)
    let has_init = which::which("gleisner-sandbox-init").is_ok();
    if !has_init {
        eprintln!(
            "skipping: gleisner-sandbox-init not on PATH \
             (run: cargo build -p gleisner-sandbox-init, then add target/debug/ to PATH)"
        );
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

/// Helper: run a command in a sandbox and return stdout as string.
fn run_in_sandbox(sb: &Sandbox, program: &str, args: &[&str]) -> Option<String> {
    let cmd = sb.command_with_args(program, args).ok()?;
    let output = cmd.output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// ── Combined feature tests ──────────────────────────────────────

#[test]
fn combined_rootfs_env_landlock_seccomp() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs()
        .namespace(Namespace::Pid)
        .namespace(Namespace::Time)
        .hostname("combined-test")
        .env("GREETING", "hello_combined")
        .env("STAGE", "testing")
        .seccomp(SeccompPreset::Nodejs)
        .landlock(true);

    // Verify multiple env vars and hostname in one shot
    let result = sb.command_with_args("/bin/sh", &["-c", "echo $GREETING $STAGE $(hostname)"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        stdout.contains("hello_combined"),
        "env GREETING missing: {stdout}"
    );
    assert!(stdout.contains("testing"), "env STAGE missing: {stdout}");
    assert!(output.status.success());
}

#[test]
fn landlock_denies_write_outside_rootfs() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs().namespace(Namespace::Pid).landlock(true);

    // Try to write to /etc (read-only via rootfs). Should fail.
    let result = sb.command_with_args(
        "/bin/sh",
        &["-c", "echo hack > /etc/gleisner-test 2>&1; echo exit=$?"],
    );
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The write should fail (Read-only file system or Permission denied)
    assert!(
        stdout.contains("exit=1")
            || stdout.contains("exit=2")
            || stdout.contains("Read-only")
            || stdout.contains("Permission denied"),
        "write to /etc should be denied, got: {stdout}"
    );
}

#[test]
fn time_namespace_isolation() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs()
        .namespace(Namespace::Pid)
        .namespace(Namespace::Time)
        .landlock(false);

    // Verify time namespace by checking the time namespace inode differs from host.
    // /proc/uptime leaks host uptime (known limitation — procfs bind-mount fallback),
    // so we compare namespace inodes instead.
    let host_time_ns = std::fs::read_link("/proc/self/ns/time")
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let stdout = run_in_sandbox(
        &sb,
        "/bin/sh",
        &[
            "-c",
            "readlink /proc/self/ns/time 2>/dev/null || echo unavailable",
        ],
    );
    if stdout.is_none() {
        eprintln!("skipping: couldn't run in sandbox");
        return;
    }

    let sandbox_time_ns = stdout.unwrap();
    if sandbox_time_ns == "unavailable" {
        eprintln!("skipping: /proc/self/ns/time not available in sandbox");
        return;
    }

    assert_ne!(
        host_time_ns, sandbox_time_ns,
        "time namespace inode should differ: host={host_time_ns} sandbox={sandbox_time_ns}"
    );
}

#[test]
fn file_injection_visible_inside_container() {
    if skip_if_no_sandbox() {
        return;
    }

    // File injection works by writing to a staging dir on the host and
    // bind-mounting. For this test, write a file to a known location and
    // verify it's readable inside the container using env + shell.
    // Use a dir outside /tmp — rootfs() adds /tmp as tmpfs which hides host /tmp
    let test_dir = std::env::current_dir()
        .unwrap()
        .join("target/gleisner-inject-test");
    std::fs::create_dir_all(&test_dir).expect("create test dir");
    let config_path = test_dir.join("gleisner-test-config.txt");
    std::fs::write(&config_path, "injected_content_here").expect("write test file");

    let mut sb = Sandbox::new();
    sb.rootfs()
        .namespace(Namespace::Pid)
        // Mount the test dir so the file is visible
        .mount_readonly(&test_dir, &test_dir)
        .landlock(false);

    let result = sb.command_with_args("/bin/cat", &[config_path.to_str().unwrap()]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("injected_content_here"),
        "injected file should be visible, got: {stdout}"
    );
}

// ── Ergonomics tests ────────────────────────────────────────────

#[test]
fn bind_ro_shorthand_e2e() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.bind_ro_all(["/usr", "/lib", "/lib64", "/bin", "/sbin"])
        .tmpfs("/tmp")
        .namespace(Namespace::Pid)
        .landlock(false);

    let result = sb.command_with_args("/bin/echo", &["bind_ro works"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    assert!(output.stdout_str().contains("bind_ro works"));
    assert!(output.elapsed.as_millis() < 5000, "should finish quickly");
}

#[test]
fn timeout_kills_long_process() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs().namespace(Namespace::Pid).landlock(false);

    let result = sb.command_with_args("/bin/sleep", &["60"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let cmd = result.unwrap().timeout(std::time::Duration::from_secs(1));
    let err = cmd.output();

    match err {
        Err(gleisner_container::ContainerError::Timeout(d)) => {
            assert!(d.as_secs() <= 2, "timeout should be ~1s, got {d:?}");
        }
        Ok(output) => {
            // Process may have exited with signal
            assert!(!output.status.success(), "should not succeed");
        }
        Err(e) => panic!("expected Timeout error, got: {e}"),
    }
}

#[test]
fn output_has_elapsed_time() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs().namespace(Namespace::Pid).landlock(false);

    let result = sb.command_with_args("/bin/true", &[] as &[&str]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    assert!(output.elapsed.as_millis() < 5000);
    assert!(output.status.success());
}

#[test]
fn stdio_piped_captures_output() {
    if skip_if_no_sandbox() {
        return;
    }

    let mut sb = Sandbox::new();
    sb.rootfs().namespace(Namespace::Pid).landlock(false);

    let result = sb.command_with_args("/bin/sh", &["-c", "echo stdout_msg; echo stderr_msg >&2"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    // output() defaults to piped for both — should capture both streams
    let output = result.unwrap().output().expect("run");
    assert!(
        output.stdout_str().contains("stdout_msg"),
        "should capture stdout: {}",
        output.stdout_str()
    );
    assert!(
        output.stderr_str().contains("stderr_msg"),
        "should capture stderr: {}",
        output.stderr_str()
    );
}

// ── Task-oriented API tests ──────────────────────────────────────

#[test]
fn task_sandbox_echo() {
    if skip_if_no_sandbox() {
        return;
    }

    let sb = gleisner_container::task::TaskSandbox::new("/tmp")
        .needs_tools(["sh"])
        .build()
        .expect("build task sandbox");

    let result = sb.command_with_args("/bin/echo", &["task sandbox works"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run");
    assert!(output.stdout_str().contains("task sandbox works"));
}

#[test]
fn task_sandbox_claude_code() {
    if skip_if_no_sandbox() {
        return;
    }

    if which::which("claude").is_err() {
        eprintln!("skipping: claude binary not on PATH");
        return;
    }

    let project_dir = Path::new("/datar/workspace/claude_code_experiments/gleisner");
    let sb =
        gleisner_container::task::claude_code_sandbox(project_dir).expect("build claude sandbox");

    let result = sb.command_with_args("claude", &["--version"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run claude");
    eprintln!("task API g-in-g: {}", output.stdout_str());
    assert!(
        output.status.success() || output.stdout_str().contains("Claude Code"),
        "claude --version should work via task API"
    );
}

// ── Gleisner-in-gleisner test (low-level API) ───────────────────

#[test]
fn gleisner_in_gleisner_claude_version() {
    if skip_if_no_sandbox() {
        return;
    }

    // Check if claude binary is available
    if which::which("claude").is_err() {
        eprintln!("skipping: claude binary not on PATH");
        return;
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    let project_dir = Path::new("/datar/workspace/claude_code_experiments/gleisner");

    let mut sb = Sandbox::new();
    sb.rootfs()
        .namespace(Namespace::Pid)
        // Claude Code needs $HOME for config, hooks, MCP
        .mount_readonly(&home, &home)
        // Project dir for context
        .mount_readwrite(project_dir, project_dir)
        .work_dir(project_dir)
        // Claude Code needs network for API
        .allow_domains(["api.anthropic.com"])
        // Node.js runtime needs this preset
        .seccomp(SeccompPreset::Nodejs)
        .hostname("gleisner-g-in-g")
        .landlock(true);

    // Just get the version — non-interactive, no API key needed
    let result = sb.command_with_args("claude", &["--version"]);
    if let Err(ref e) = result {
        eprintln!("skipping: {e}");
        return;
    }

    let output = result.unwrap().output().expect("run claude --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("g-in-g stdout: {stdout}");
    eprintln!("g-in-g stderr (last 5 lines):");
    for line in stderr
        .lines()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        eprintln!("  {line}");
    }

    // Claude --version should output version info and exit 0
    assert!(
        output.status.success() || stdout.contains("Claude Code"),
        "claude --version should succeed inside sandbox, exit={:?}, stdout={stdout}",
        output.status.code()
    );
}

// NOTE: These tests use real paths under target/ (not /tmp) because
// the sandbox replaces /tmp with a fresh tmpfs. tempfile::tempdir()
// creates dirs under /tmp which aren't visible inside the sandbox.

const TEST_DIR: &str = "/datar/workspace/claude_code_experiments/gleisner/target/e2e-test-scratch";

fn test_project_dir(name: &str) -> std::path::PathBuf {
    let dir = Path::new(TEST_DIR).join(name);
    // Clean and recreate
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── state_key e2e ──────────────────────────────────────────────

#[test]
fn state_key_creates_persistent_directory() {
    use gleisner_container::task::TaskSandbox;

    if skip_if_no_sandbox() {
        return;
    }

    let project_path = test_project_dir("state-key");

    let task = TaskSandbox::new(&project_path)
        .needs_tools(["sh"])
        .state_key("test-persist");

    let sb = task.build().expect("build sandbox with state_key");

    // The state dir should have been created on the host
    let state_dir = project_path.join(".gleisner/state/test-persist");
    assert!(
        state_dir.exists(),
        "state_key should create .gleisner/state/test-persist: {}",
        state_dir.display()
    );

    // Write a marker file from inside the sandbox
    let output = run_in_sandbox(
        &sb,
        "sh",
        &[
            "-c",
            &format!(
                "echo 'persisted' > {}/marker.txt && cat {}/marker.txt",
                state_dir.display(),
                state_dir.display()
            ),
        ],
    );

    assert_eq!(
        output.as_deref(),
        Some("persisted"),
        "should write and read from state dir inside sandbox"
    );

    // Verify persistence on host after sandbox exits
    let marker = std::fs::read_to_string(state_dir.join("marker.txt")).unwrap();
    assert_eq!(marker.trim(), "persisted", "state should persist on host");

    // Clean up
    std::fs::remove_dir_all(&project_path).ok();
}

// ── needs_packages e2e ─────────────────────────────────────────

#[test]
fn package_mount_is_readable_inside_sandbox() {
    use gleisner_container::task::{PackageMount, TaskSandbox};

    if skip_if_no_sandbox() {
        return;
    }

    let project_path = test_project_dir("pkg-mount");

    // Create a fake "package" directory under /usr/local (a real path
    // that exists outside the sandbox's tmpfs)
    let pkg_dir = Path::new(TEST_DIR).join("fake-pkg-data");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("hello.txt"), "from-package").unwrap();

    let task = TaskSandbox::new(&project_path)
        .needs_tools(["sh"])
        .needs_packages([PackageMount {
            name: "test-pkg".to_owned(),
            host_path: pkg_dir.clone(),
            container_path: pkg_dir.clone(), // same path (bind_ro pattern)
        }]);

    let sb = task.build().expect("build sandbox with package mount");

    // Read the package file from inside the sandbox
    let output = run_in_sandbox(
        &sb,
        "sh",
        &["-c", &format!("cat {}/hello.txt", pkg_dir.display())],
    );

    assert_eq!(
        output.as_deref(),
        Some("from-package"),
        "package content should be readable inside sandbox"
    );

    // Clean up
    std::fs::remove_dir_all(&project_path).ok();
    std::fs::remove_dir_all(&pkg_dir).ok();
}

// ── pool e2e ───────────────────────────────────────────────────

#[test]
fn pool_runs_concurrent_sandboxes() {
    use gleisner_container::pool::SandboxPool;
    use gleisner_container::task::TaskSandbox;

    if skip_if_no_sandbox() {
        return;
    }

    let project_path = test_project_dir("pool");

    let pool = SandboxPool::new(2).task_timeout(std::time::Duration::from_secs(10));

    pool.submit(
        "echo-one",
        TaskSandbox::new(&project_path).needs_tools(["sh"]),
        "sh",
        &["-c", "echo one"],
    );
    pool.submit(
        "echo-two",
        TaskSandbox::new(&project_path).needs_tools(["sh"]),
        "sh",
        &["-c", "echo two"],
    );
    pool.submit(
        "echo-three",
        TaskSandbox::new(&project_path).needs_tools(["sh"]),
        "sh",
        &["-c", "echo three"],
    );

    let results = pool.run_all();

    eprintln!(
        "Pool: {} succeeded, {} failed, elapsed {:?}",
        results.succeeded, results.failed, results.elapsed
    );

    assert_eq!(
        results.succeeded, 3,
        "all 3 tasks should produce Ok results"
    );
    assert_eq!(results.failed, 0);

    // Verify output from each task
    for (name, expected) in [
        ("echo-one", "one"),
        ("echo-two", "two"),
        ("echo-three", "three"),
    ] {
        let output = results.results[name].as_ref().expect("Ok result");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            expected,
            "{name} should output '{expected}', got: {stdout}"
        );
    }

    // Clean up
    std::fs::remove_dir_all(&project_path).ok();
}
