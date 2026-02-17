//! Landlock LSM access control — filesystem, network, and IPC isolation.
//!
//! Applies a Landlock ruleset to the current thread (and all future
//! children via `fork`/`exec`) based on the sandbox profile's policies.
//! This provides defense-in-depth on top of the bubblewrap namespace
//! isolation.
//!
//! # ABI version
//!
//! We target [`ABI::V7`] (Linux 6.15+) using a fork of the `landlock`
//! crate with V7 support (<https://github.com/lexicone42/rust-landlock>).
//! The `BestEffort` compatibility level means this degrades gracefully on
//! older kernels — flags unsupported by the running kernel are silently
//! dropped rather than causing errors.
//!
//! ## Feature summary by ABI version
//!
//! | ABI | Kernel | Feature |
//! |-----|--------|---------|
//! | V1  | 5.13   | Filesystem access control |
//! | V2  | 5.19   | `Refer` (cross-directory rename/link) |
//! | V3  | 6.2    | `Truncate` |
//! | V4  | 6.7    | `AccessNet` — TCP bind/connect port filtering |
//! | V5  | 6.10   | `IoctlDev` — device ioctl control |
//! | V6  | 6.12   | `Scope` — IPC isolation (abstract UNIX sockets, signals) |
//! | V7  | 6.15   | Audit logging flags on `restrict_self()` |

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope, path_beneath_rules,
};
use tracing::{debug, info, warn};

use crate::bwrap::expand_tilde;
use crate::error::SandboxError;
use crate::profile::{FilesystemPolicy, NetworkPolicy, PolicyDefault};

/// Target ABI version — V7 adds audit logging flags (Linux 6.15+).
const TARGET_ABI: ABI = ABI::V7;

/// How strictly Landlock was enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockEnforcement {
    /// All requested access controls are active.
    FullyEnforced,
    /// Some access controls are active; the kernel supports Landlock
    /// but not all requested flags.
    PartiallyEnforced,
    /// The kernel does not support Landlock at all.
    NotEnforced,
    /// Landlock was explicitly disabled via `--no-landlock`.
    Skipped,
}

/// Result of applying Landlock restrictions.
#[derive(Debug)]
pub struct LandlockStatus {
    /// How strictly the ruleset was enforced.
    pub enforcement: LandlockEnforcement,
    /// Paths from the profile that were skipped (nonexistent, inaccessible).
    pub skipped_paths: Vec<PathBuf>,
    /// Whether V4 network port filtering was requested and applied.
    pub network_enforced: bool,
    /// Whether V6 IPC scope isolation was requested and applied.
    pub scope_enforced: bool,
    /// Whether V7 audit logging flags were applied to `restrict_self()`.
    pub audit_log_enabled: bool,
}

/// Serializable policy for the sandbox-init binary.
///
/// The parent orchestrator writes this to a tempfile as JSON, bind-mounts
/// it into the bwrap sandbox, and the `gleisner-sandbox-init` binary reads
/// it to apply Landlock restrictions before exec-ing the inner command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LandlockPolicy {
    /// Filesystem access rules (readonly binds, readwrite binds, deny paths, tmpfs).
    pub filesystem: FilesystemPolicy,
    /// Network access rules (default deny/allow, allowed domains/ports).
    pub network: NetworkPolicy,
    /// Project directory — always gets read-write access.
    pub project_dir: PathBuf,
    /// Additional paths from `--allow-path` CLI flags.
    pub extra_rw_paths: Vec<PathBuf>,
}

/// Apply Landlock restrictions based on the sandbox profile.
///
/// Restricts the calling thread (and all descendants) to only the paths
/// and ports declared in the profile, plus orchestration paths needed
/// by the parent process (cgroup management, signing keys, etc.).
///
/// # Layers
///
/// 1. **Filesystem** (V1-V5): path-based access control including
///    `IoctlDev` on V5+ kernels (automatic via `AccessFs::from_all`).
/// 2. **Network** (V4): TCP port allowlist when the profile's network
///    default is `Deny`. Only `ConnectTcp` rules are created — the
///    sandboxed process should never bind server sockets.
/// 3. **IPC scope** (V6): unconditional isolation from abstract UNIX
///    sockets and signal delivery outside the sandbox.
/// 4. **Audit logging** (V7): enables kernel audit log entries for
///    Landlock denials on new executables and subdomains.
///
/// # Arguments
///
/// * `filesystem` — The profile's filesystem policy (bind mounts, deny list, tmpfs).
/// * `network` — The profile's network policy (default disposition, allowed ports).
/// * `project_dir` — The project directory (always gets read-write access).
/// * `extra_rw_paths` — Additional paths from `--allow-path` CLI flags.
/// * `require` — If `true`, returns an error when Landlock is unsupported.
///   If `false`, returns `Ok(NotEnforced)` on unsupported kernels.
///
/// # Errors
///
/// Returns [`SandboxError::LandlockError`] if ruleset construction fails,
/// or [`SandboxError::LandlockUnsupported`] if `require` is true and the
/// kernel lacks Landlock support.
pub fn apply_landlock(
    filesystem: &FilesystemPolicy,
    network: &NetworkPolicy,
    project_dir: &Path,
    extra_rw_paths: &[PathBuf],
    require: bool,
) -> Result<LandlockStatus, SandboxError> {
    // Check for deny-path conflicts: Landlock cannot create exceptions
    // within subtrees — a parent rule always wins.
    check_deny_conflicts(filesystem);

    let compat_level = if require {
        CompatLevel::HardRequirement
    } else {
        CompatLevel::BestEffort
    };

    let enforce_network = matches!(network.default, PolicyDefault::Deny);

    // --- Phase 1: Declare handled access types ---
    let mut ruleset_builder = Ruleset::default()
        .set_compatibility(compat_level)
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| map_ruleset_error(&e, require))?;

    // V4: Declare network access handling only when network policy is deny-default.
    // When allow-default, we don't restrict TCP at all.
    if enforce_network {
        ruleset_builder = ruleset_builder
            .handle_access(AccessNet::from_all(TARGET_ABI))
            .map_err(|e| map_ruleset_error(&e, require))?;
    }

    // V6: IPC scope isolation — always applied (unconditionally good for sandboxing).
    // Prevents the sandboxed process from connecting to abstract UNIX sockets
    // or sending signals to processes outside the sandbox.
    ruleset_builder = ruleset_builder
        .scope(Scope::from_all(TARGET_ABI))
        .map_err(|e| map_ruleset_error(&e, require))?;

    let ruleset = ruleset_builder
        .create()
        .map_err(|e| map_ruleset_error(&e, require))?;

    // --- Phase 2: Add rules (exceptions to deny-all) ---

    let mut skipped_paths = Vec::new();
    let ruleset = add_filesystem_rules(
        ruleset,
        filesystem,
        project_dir,
        extra_rw_paths,
        require,
        &mut skipped_paths,
    )?;

    // V4: Network port rules (only when deny-default)
    let ruleset = if enforce_network {
        add_network_rules(ruleset, network, require)?
    } else {
        ruleset
    };

    // --- Phase 3: V7 audit logging + restrict this thread ---
    // Enable audit logging for Landlock denials:
    //   - log_new_exec_on: log denials for newly exec'd processes
    //   - log_subdomains_off: don't log denials from nested Landlock domains
    //     (reduces noise — only the outermost sandbox's denials are interesting)
    let status = ruleset
        .set_log_new_exec_on(true)
        .set_log_subdomains_off(true)
        .restrict_self()
        .map_err(|e| map_ruleset_error(&e, require))?;

    let enforcement = match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("landlock fully enforced (ABI V7: filesystem + network + scope + audit)");
            LandlockEnforcement::FullyEnforced
        }
        RulesetStatus::PartiallyEnforced => {
            info!("landlock partially enforced (kernel supports subset of requested V7 flags)");
            LandlockEnforcement::PartiallyEnforced
        }
        RulesetStatus::NotEnforced => {
            warn!("landlock not enforced — kernel may not support landlock");
            LandlockEnforcement::NotEnforced
        }
    };

    if !skipped_paths.is_empty() {
        debug!(
            skipped = ?skipped_paths,
            "landlock skipped nonexistent/inaccessible paths"
        );
    }

    // Report what was actually applied (FullyEnforced means all layers active)
    let fully = enforcement == LandlockEnforcement::FullyEnforced;

    Ok(LandlockStatus {
        enforcement,
        skipped_paths,
        network_enforced: enforce_network && fully,
        scope_enforced: fully,
        audit_log_enabled: fully,
    })
}

/// Apply filesystem path rules: profile binds, project dir, extra CLI paths,
/// and orchestration paths needed by the parent process.
#[allow(clippy::similar_names)]
fn add_filesystem_rules(
    ruleset: landlock::RulesetCreated,
    filesystem: &FilesystemPolicy,
    project_dir: &Path,
    extra_rw_paths: &[PathBuf],
    require: bool,
    skipped_paths: &mut Vec<PathBuf>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    let read_access = AccessFs::from_read(TARGET_ABI);
    let full_access = AccessFs::from_all(TARGET_ABI);

    // Profile-declared paths
    let ro_paths: Vec<&Path> = filesystem
        .readonly_bind
        .iter()
        .map(PathBuf::as_path)
        .collect();
    let rw_paths: Vec<&Path> = filesystem
        .readwrite_bind
        .iter()
        .map(PathBuf::as_path)
        .collect();
    let tmpfs_paths: Vec<&Path> = filesystem.tmpfs.iter().map(PathBuf::as_path).collect();

    // Orchestration paths (parent process needs)
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let gleisner_config = home.as_ref().map(|h| h.join(".config/gleisner"));
    let claude_config = home.as_ref().map(|h| h.join(".claude"));

    let mut orch_ro: Vec<PathBuf> = Vec::new();
    if let Some(ref cc) = claude_config {
        orch_ro.push(cc.clone());
    }

    // /dev: write for /dev/null, /dev/tty (Stdio redirections)
    // /proc: write for /proc/<pid>/uid_map (user namespace setup)
    // /sys/fs/cgroup: write for resource limit management
    let mut orch_rw: Vec<PathBuf> = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/dev"),
        PathBuf::from("/sys/fs/cgroup"),
    ];
    if let Some(ref gc) = gleisner_config {
        orch_rw.push(gc.clone());
    }

    // Apply all rules
    let ruleset = add_rules_tracking_skips(ruleset, &ro_paths, read_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let ruleset = add_rules_tracking_skips(ruleset, &rw_paths, full_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let ruleset = add_rules_tracking_skips(ruleset, &tmpfs_paths, full_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let ruleset = add_rules_tracking_skips(ruleset, &[project_dir], full_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let extra_refs: Vec<&Path> = extra_rw_paths.iter().map(PathBuf::as_path).collect();
    let ruleset = add_rules_tracking_skips(ruleset, &extra_refs, full_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let orch_ro_refs: Vec<&Path> = orch_ro.iter().map(PathBuf::as_path).collect();
    let ruleset = add_rules_tracking_skips(ruleset, &orch_ro_refs, read_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    let orch_rw_refs: Vec<&Path> = orch_rw.iter().map(PathBuf::as_path).collect();
    let ruleset = add_rules_tracking_skips(ruleset, &orch_rw_refs, full_access, skipped_paths)
        .map_err(|e| map_ruleset_error(&e, require))?;

    Ok(ruleset)
}

/// Add V4 TCP port rules based on the network policy.
///
/// Creates `ConnectTcp` rules for each allowed port. No `BindTcp` rules
/// are created — sandboxed processes should never bind server sockets.
fn add_network_rules(
    ruleset: landlock::RulesetCreated,
    network: &NetworkPolicy,
    require: bool,
) -> Result<landlock::RulesetCreated, SandboxError> {
    let connect = AccessNet::ConnectTcp;

    // Collect all port rules
    let mut port_rules: Vec<NetPort> = network
        .allow_ports
        .iter()
        .map(|&port| NetPort::new(port, connect))
        .collect();

    // DNS uses TCP for large responses and zone transfers (port 53)
    if network.allow_dns && !network.allow_ports.contains(&53) {
        port_rules.push(NetPort::new(53, connect));
    }

    if port_rules.is_empty() {
        debug!("landlock network: deny-default with no port exceptions");
        return Ok(ruleset);
    }

    debug!(
        ports = ?network.allow_ports,
        dns = network.allow_dns,
        "landlock network: allowing ConnectTcp on {} ports",
        port_rules.len()
    );

    // add_rules expects an iterator of Result<NetPort, E>
    let rules_iter = port_rules.into_iter().map(Ok::<_, RulesetError>);
    ruleset
        .add_rules(rules_iter)
        .map_err(|e| map_ruleset_error(&e, require))
}

/// Add `path_beneath_rules` for the given paths, collecting any that were
/// skipped (nonexistent, inaccessible) into `skipped`.
///
/// Uses the landlock crate's `path_beneath_rules()` helper which auto-adjusts
/// flags for files vs directories and silently skips inaccessible paths
/// under `BestEffort` compatibility.
fn add_rules_tracking_skips(
    ruleset: landlock::RulesetCreated,
    paths: &[&Path],
    access: BitFlags<AccessFs>,
    skipped: &mut Vec<PathBuf>,
) -> Result<landlock::RulesetCreated, RulesetError> {
    // Pre-check existence for skip tracking — path_beneath_rules handles
    // nonexistent paths gracefully (yields Err items that add_rules skips
    // with BestEffort), but we want to log which paths were skipped.
    for path in paths {
        if !path.exists() {
            debug!(path = %path.display(), "skipping nonexistent path for landlock");
            skipped.push(path.to_path_buf());
        }
    }

    // path_beneath_rules opens each path as an fd, auto-adjusts flags for
    // files vs directories, and yields Err for inaccessible paths.
    let paths_owned: Vec<PathBuf> = paths.iter().map(|p| p.to_path_buf()).collect();
    ruleset.add_rules(path_beneath_rules(paths_owned, access))
}

/// Warn about deny paths that overlap with bind-mounted paths.
///
/// Landlock cannot create exceptions within subtrees — if `/home` has
/// read-write access, you cannot deny `/home/.ssh` via Landlock alone.
/// (Bubblewrap's tmpfs overlay handles this instead.)
fn check_deny_conflicts(filesystem: &FilesystemPolicy) {
    let all_allowed: Vec<PathBuf> = filesystem
        .readonly_bind
        .iter()
        .chain(filesystem.readwrite_bind.iter())
        .map(|p| expand_tilde(p))
        .collect();

    for deny_path in &filesystem.deny {
        let expanded = expand_tilde(deny_path);
        for allowed in &all_allowed {
            if expanded.starts_with(allowed) {
                warn!(
                    deny = %expanded.display(),
                    parent_allow = %allowed.display(),
                    "deny path is under an allowed path — landlock cannot enforce this denial \
                     (bubblewrap tmpfs overlay handles it instead)"
                );
            }
        }
    }
}

/// Convert a [`RulesetError`] to a [`SandboxError`], choosing between
/// `LandlockUnsupported` and `LandlockError` based on context.
fn map_ruleset_error(err: &RulesetError, require: bool) -> SandboxError {
    let msg = err.to_string();
    if require {
        // When requiring Landlock, a compat error means unsupported kernel
        if msg.contains("compat") || msg.contains("Incompatible") {
            let kernel = kernel_version().unwrap_or_else(|| "unknown".to_owned());
            SandboxError::LandlockUnsupported(kernel)
        } else {
            SandboxError::LandlockError(msg)
        }
    } else {
        SandboxError::LandlockError(msg)
    }
}

/// Read the kernel version from `/proc/version` (first token after "Linux version").
fn kernel_version() -> Option<String> {
    let content = std::fs::read_to_string("/proc/version").ok()?;
    content.split_whitespace().nth(2).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_access_excludes_write_flags() {
        let read = AccessFs::from_read(TARGET_ABI);
        let all = AccessFs::from_all(TARGET_ABI);

        // Read flags should be a strict subset of all flags
        assert!(
            read != all,
            "read-only access should differ from full access"
        );

        // Verify write-specific flags are NOT in read access
        assert!(
            !read.contains(AccessFs::WriteFile),
            "read access should not include WriteFile"
        );
        assert!(
            !read.contains(AccessFs::MakeDir),
            "read access should not include MakeDir"
        );

        // from_read() includes Execute (reading a file to execute it is read-like)
        assert!(
            read.contains(AccessFs::Execute),
            "read access should include Execute"
        );
    }

    #[test]
    fn readwrite_access_includes_all_flags() {
        let all = AccessFs::from_all(TARGET_ABI);

        // Full access should include both read and write operations
        assert!(
            all.contains(AccessFs::ReadFile),
            "full access should include ReadFile"
        );
        assert!(
            all.contains(AccessFs::WriteFile),
            "full access should include WriteFile"
        );
        assert!(
            all.contains(AccessFs::Execute),
            "full access should include Execute"
        );
        assert!(
            all.contains(AccessFs::ReadDir),
            "full access should include ReadDir"
        );
    }

    /// V4: Verify `AccessNet::from_all` contains both bind and connect flags.
    #[test]
    fn v4_network_access_flags() {
        let net = AccessNet::from_all(TARGET_ABI);
        assert!(
            net.contains(AccessNet::BindTcp),
            "V4+ should include BindTcp"
        );
        assert!(
            net.contains(AccessNet::ConnectTcp),
            "V4+ should include ConnectTcp"
        );
    }

    /// V5: Verify `AccessFs::from_all(V6)` includes `IoctlDev` but V3 does not.
    #[test]
    fn v5_ioctl_dev_included() {
        let v6_all = AccessFs::from_all(ABI::V6);
        let v3_all = AccessFs::from_all(ABI::V3);

        assert!(
            v6_all.contains(AccessFs::IoctlDev),
            "V6 from_all should include IoctlDev (added in V5)"
        );
        assert!(
            !v3_all.contains(AccessFs::IoctlDev),
            "V3 from_all should NOT include IoctlDev"
        );
    }

    /// V6: Verify `Scope::from_all` contains both IPC isolation flags.
    #[test]
    fn v6_scope_flags() {
        let scope = Scope::from_all(TARGET_ABI);
        assert!(
            scope.contains(Scope::AbstractUnixSocket),
            "V6 should include AbstractUnixSocket scope"
        );
        assert!(
            scope.contains(Scope::Signal),
            "V6 should include Signal scope"
        );
    }

    /// V7: Verify TARGET_ABI is V7 and that V7 access sets are supersets of V6.
    #[test]
    fn v7_target_abi() {
        assert_eq!(TARGET_ABI, ABI::V7, "TARGET_ABI should be V7");

        // V7 doesn't add new access types — it adds audit logging flags.
        // Verify that V7 access sets are identical to V6 (no regressions).
        assert_eq!(
            AccessFs::from_all(ABI::V7),
            AccessFs::from_all(ABI::V6),
            "V7 filesystem access should match V6"
        );
        assert_eq!(
            AccessNet::from_all(ABI::V7),
            AccessNet::from_all(ABI::V6),
            "V7 network access should match V6"
        );
        assert_eq!(
            Scope::from_all(ABI::V7),
            Scope::from_all(ABI::V6),
            "V7 scope should match V6"
        );
    }

    #[test]
    fn deny_conflict_detection() {
        // This test verifies the logic, not the warning output.
        // A deny path under a bind path is a conflict.
        let fs = FilesystemPolicy {
            readonly_bind: vec![PathBuf::from("/home")],
            readwrite_bind: vec![],
            deny: vec![PathBuf::from("/home/.ssh")],
            tmpfs: vec![],
        };

        // The function only emits warnings; verify it doesn't panic
        check_deny_conflicts(&fs);
    }

    #[test]
    fn deny_no_false_conflict() {
        // Deny path NOT under any allowed path — should not warn
        let fs = FilesystemPolicy {
            readonly_bind: vec![PathBuf::from("/usr")],
            readwrite_bind: vec![],
            deny: vec![PathBuf::from("/home/.ssh")],
            tmpfs: vec![],
        };

        check_deny_conflicts(&fs);
    }

    #[test]
    fn kernel_version_returns_something() {
        // On any Linux system, /proc/version should exist
        if Path::new("/proc/version").exists() {
            let version = kernel_version();
            assert!(version.is_some(), "should parse kernel version");
            let v = version.unwrap();
            assert!(!v.is_empty(), "kernel version should not be empty");
        }
    }

    /// Integration test: apply Landlock with filesystem + scope and verify enforcement.
    /// Requires a Landlock-capable kernel (LSM enabled at boot).
    #[test]
    fn apply_landlock_enforced() {
        let fs = FilesystemPolicy {
            readonly_bind: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            readwrite_bind: vec![],
            deny: vec![],
            tmpfs: vec![PathBuf::from("/tmp")],
        };

        let net = NetworkPolicy {
            default: PolicyDefault::Allow,
            allow_domains: vec![],
            allow_ports: vec![],
            allow_dns: true,
        };

        let result = apply_landlock(&fs, &net, Path::new("/tmp/test-project"), &[], false);

        match result {
            Ok(status) => {
                assert_ne!(
                    status.enforcement,
                    LandlockEnforcement::Skipped,
                    "should not be skipped when called"
                );
                // Network not enforced when default is Allow
                assert!(
                    !status.network_enforced,
                    "network should not be enforced with allow-default"
                );
                println!("enforcement: {:?}", status.enforcement);
            }
            Err(e) => {
                // On kernels without Landlock, this is expected
                println!("landlock not available: {e}");
            }
        }
    }

    /// Integration test: apply Landlock with deny-default network policy.
    #[test]
    fn apply_landlock_with_network() {
        let fs = FilesystemPolicy {
            readonly_bind: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            readwrite_bind: vec![],
            deny: vec![],
            tmpfs: vec![PathBuf::from("/tmp")],
        };

        let net = NetworkPolicy {
            default: PolicyDefault::Deny,
            allow_domains: vec!["api.anthropic.com".to_owned()],
            allow_ports: vec![443],
            allow_dns: true,
        };

        let result = apply_landlock(&fs, &net, Path::new("/tmp/test-project"), &[], false);

        match result {
            Ok(status) => {
                assert_ne!(
                    status.enforcement,
                    LandlockEnforcement::Skipped,
                    "should not be skipped when called"
                );
                if status.enforcement == LandlockEnforcement::FullyEnforced {
                    assert!(
                        status.network_enforced,
                        "network should be enforced with deny-default on V4+ kernel"
                    );
                    assert!(
                        status.scope_enforced,
                        "scope should be enforced on V6+ kernel"
                    );
                }
                println!(
                    "enforcement: {:?}, network: {}, scope: {}, audit: {}",
                    status.enforcement,
                    status.network_enforced,
                    status.scope_enforced,
                    status.audit_log_enabled
                );
            }
            Err(e) => {
                println!("landlock not available: {e}");
            }
        }
    }
}
