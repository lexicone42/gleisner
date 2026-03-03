//! Direct sandbox runtime — creates a Linux container and exec's the inner command.
//!
//! This binary handles all container setup directly via syscalls.
//! It reads a [`SandboxSpec`] from a JSON file (argv[1]) and:
//!
//! 1. Creates user + mount + (optionally PID) namespaces via `unshare(2)`
//! 2. Maps the real UID/GID inside the user namespace
//! 3. Sets up bind mounts (4-phase ordering) with `pivot_root`
//! 4. Applies Landlock restrictions (if enabled)
//! 5. Replaces itself with the inner command via `exec`
//!
//! ```text
//! Usage: gleisner-sandbox-init <spec.json>
//! ```
//!
//! The parent process (`gleisner-polis` `DirectSandbox`) serializes the
//! spec to a tempfile and passes its path as the sole argument.

#[cfg(target_os = "linux")]
mod runtime;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("gleisner-sandbox-init: expected exactly one argument (spec.json path)");
        eprintln!("Usage: gleisner-sandbox-init <spec.json>");
        std::process::exit(2);
    }

    let spec_path = &args[1];
    let spec_json = match std::fs::read_to_string(spec_path) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("gleisner-sandbox-init: failed to read spec {spec_path}: {e}");
            std::process::exit(2);
        }
    };

    let spec: gleisner_polis::SandboxSpec = match serde_json::from_str(&spec_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gleisner-sandbox-init: failed to parse spec JSON: {e}");
            std::process::exit(2);
        }
    };

    if let Err(e) = runtime::run(spec) {
        eprintln!("gleisner-sandbox-init: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("gleisner-sandbox-init is only supported on Linux");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    #[test]
    fn spec_json_roundtrip() {
        use gleisner_polis::SandboxSpec;
        use gleisner_polis::profile::{
            FilesystemPolicy, NetworkPolicy, PolicyDefault, ProcessPolicy,
        };
        use std::path::PathBuf;

        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
            },
            project_dir: PathBuf::from("/home/user/project"),
            extra_rw_paths: vec![PathBuf::from("/home/user/.cargo")],
            work_dir: PathBuf::from("/home/user/project"),
            inner_command: vec!["echo".to_owned(), "hello".to_owned()],
            enable_landlock: true,
            use_external_netns: false,
            uid: 1000,
            gid: 1000,
            resource_limits: None,
        };

        let json = serde_json::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.project_dir, spec.project_dir);
        assert_eq!(parsed.inner_command, vec!["echo", "hello"]);
        assert_eq!(parsed.uid, 1000);
        assert!(parsed.enable_landlock);
    }
}
