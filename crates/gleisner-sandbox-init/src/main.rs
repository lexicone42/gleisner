//! Landlock init wrapper — runs inside a bwrap sandbox.
//!
//! This binary is the first process spawned by bwrap. It:
//! 1. Reads a `LandlockPolicy` from a JSON file (argv[1])
//! 2. Applies Landlock restrictions (`BestEffort` — no error on unsupported kernels)
//! 3. Replaces itself with the inner command (argv after `--`)
//!
//! ```text
//! Usage: gleisner-sandbox-init <policy.json> -- <command> [args...]
//! ```
//!
//! The binary is a trampoline: it exists solely to apply Landlock
//! restrictions, then replaces itself via `CommandExt` process replacement.

#[cfg(target_os = "linux")]
fn main() {
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;

    use gleisner_polis::LandlockPolicy;

    let args: Vec<String> = std::env::args().collect();

    // Parse: <policy.json> -- <command> [args...]
    let (policy_path, inner_args) = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("gleisner-sandbox-init: {msg}");
            eprintln!("Usage: gleisner-sandbox-init <policy.json> -- <command> [args...]");
            std::process::exit(2);
        }
    };

    // Read and deserialize the policy
    let policy_json = match std::fs::read_to_string(&policy_path) {
        Ok(json) => json,
        Err(e) => {
            eprintln!(
                "gleisner-sandbox-init: failed to read policy {}: {e}",
                policy_path.display()
            );
            std::process::exit(2);
        }
    };

    let policy: LandlockPolicy = match serde_json::from_str(&policy_json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gleisner-sandbox-init: failed to parse policy JSON: {e}");
            std::process::exit(2);
        }
    };

    // Apply Landlock (BestEffort — require: false)
    match gleisner_polis::apply_landlock(
        &policy.filesystem,
        &policy.network,
        &policy.project_dir,
        &policy.extra_rw_paths,
        false, // BestEffort
    ) {
        Ok(status) => {
            eprintln!(
                "gleisner-sandbox-init: landlock {:?} (network={}, scope={}, audit={})",
                status.enforcement,
                status.network_enforced,
                status.scope_enforced,
                status.audit_log_enabled
            );
            if !status.skipped_paths.is_empty() {
                eprintln!(
                    "gleisner-sandbox-init: skipped {} nonexistent paths",
                    status.skipped_paths.len()
                );
            }
        }
        Err(e) => {
            eprintln!("gleisner-sandbox-init: landlock failed (continuing): {e}");
        }
    }

    // Replace this process with the inner command.
    // CommandExt::exec() replaces the current process image — if it returns, it failed.
    let program = &inner_args[0];
    let err = Command::new(program).args(&inner_args[1..]).exec();
    eprintln!("gleisner-sandbox-init: failed to run {program}: {err}");
    std::process::exit(127);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("gleisner-sandbox-init is only supported on Linux");
    std::process::exit(1);
}

/// Parse argv into `(policy_path, inner_command_args)`.
fn parse_args(args: &[String]) -> Result<(std::path::PathBuf, Vec<String>), String> {
    // args[0] is the binary name
    if args.len() < 2 {
        return Err("missing policy path".to_owned());
    }

    let policy_path = std::path::PathBuf::from(&args[1]);

    // Find "--" separator
    let separator_pos = args[2..]
        .iter()
        .position(|a| a == "--")
        .map(|i| i + 2)
        .ok_or_else(|| "missing '--' separator before command".to_owned())?;

    let inner_args: Vec<String> = args[separator_pos + 1..].to_vec();
    if inner_args.is_empty() {
        return Err("missing command after '--'".to_owned());
    }

    Ok((policy_path, inner_args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_basic() {
        let args = vec![
            "gleisner-sandbox-init".to_owned(),
            "/tmp/policy.json".to_owned(),
            "--".to_owned(),
            "echo".to_owned(),
            "hello".to_owned(),
        ];
        let (policy, inner) = parse_args(&args).unwrap();
        assert_eq!(policy, std::path::PathBuf::from("/tmp/policy.json"));
        assert_eq!(inner, vec!["echo", "hello"]);
    }

    #[test]
    fn parse_args_missing_separator() {
        let args = vec![
            "gleisner-sandbox-init".to_owned(),
            "/tmp/policy.json".to_owned(),
            "echo".to_owned(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_missing_command() {
        let args = vec![
            "gleisner-sandbox-init".to_owned(),
            "/tmp/policy.json".to_owned(),
            "--".to_owned(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_missing_policy() {
        let args = vec!["gleisner-sandbox-init".to_owned()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn policy_json_roundtrip() {
        use gleisner_polis::LandlockPolicy;
        use gleisner_polis::profile::{FilesystemPolicy, NetworkPolicy, PolicyDefault};

        let policy = LandlockPolicy {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![
                    std::path::PathBuf::from("/usr"),
                    std::path::PathBuf::from("/lib"),
                ],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![std::path::PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            project_dir: std::path::PathBuf::from("/home/user/project"),
            extra_rw_paths: vec![std::path::PathBuf::from("/home/user/.cargo")],
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: LandlockPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.project_dir, policy.project_dir);
        assert_eq!(parsed.filesystem.readonly_bind.len(), 2);
        assert_eq!(parsed.network.allow_ports, vec![443]);
        assert_eq!(parsed.extra_rw_paths.len(), 1);
    }
}
