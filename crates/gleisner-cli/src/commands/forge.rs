//! `gleisner forge` — evaluate Nickel packages and compose sandbox environments.
//!
//! Evaluates a [minimal.dev](https://minimal.dev) package set, merges their
//! `attrs` and `needs` into a composed environment, then optionally runs
//! Claude Code inside a sandbox derived from those declarations.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};

/// Evaluate Nickel packages and compose a sandbox environment.
///
/// Reads `build.ncl` package declarations from a minimal.dev package tree,
/// evaluates them in dependency order, and composes their filesystem/network
/// requirements into a unified environment specification.
#[derive(Args)]
pub struct ForgeArgs {
    /// Path to the packages directory (containing `<pkg>/build.ncl` subdirs).
    #[arg(long)]
    pub pkgs_dir: PathBuf,

    /// Path to the Nickel stdlib directory (containing `minimal.ncl`, etc.).
    #[arg(long)]
    pub stdlib_dir: PathBuf,

    /// Directory for the content-addressed evaluation store.
    #[arg(long, default_value = ".gleisner/forge-store")]
    pub store_dir: PathBuf,

    /// Only evaluate these packages (comma-separated).
    /// If omitted, evaluates all packages in the tree.
    #[arg(long, value_delimiter = ',')]
    pub packages: Vec<String>,

    /// Sandbox profile to validate the composed environment against.
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Write the composed environment JSON to this path.
    #[arg(short, long, default_value = ".gleisner/composed-env.json")]
    pub output: PathBuf,

    /// Evaluate and compose only — print the policy as JSON to stdout.
    /// Does not write files or launch a sandbox. Suitable for programmatic
    /// consumption by a management Claude reasoning about permissions.
    #[arg(long)]
    pub dry_run: bool,

    /// Verify proof artifacts for packages declaring `verified_properties`.
    /// Requires a Lean 4 binary (auto-detected or via --lean-bin).
    #[arg(long)]
    pub verify: bool,

    /// Path to the Lean 4 binary for proof verification.
    /// If not specified, auto-detected from PATH or ~/.elan/bin/.
    #[arg(long)]
    pub lean_bin: Option<PathBuf>,

    /// Fail the pipeline if any proof verification fails (used with --verify).
    #[arg(long)]
    pub strict_verify: bool,

    /// Also run Claude Code inside a sandbox derived from the composed environment.
    #[arg(long)]
    pub run: bool,

    /// Claude Code binary path (used with --run).
    #[arg(long, default_value = "claude")]
    pub claude_bin: String,

    /// Project directory (defaults to current directory).
    #[arg(short = 'd', long)]
    pub project_dir: Option<PathBuf>,

    /// Additional arguments to pass to Claude Code (used with --run).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub claude_args: Vec<String>,
}

/// Execute the `forge` command.
#[cfg(target_os = "linux")]
#[allow(clippy::unused_async)]
pub async fn execute(args: ForgeArgs) -> Result<()> {
    use gleisner_forge::attest::extract_attestation_with_results;
    use gleisner_forge::bridge::compose_to_policy;
    use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};

    let project_dir = match &args.project_dir {
        Some(d) => d.clone(),
        None => std::env::current_dir().map_err(|e| {
            eyre!("--project-dir not specified and current directory is inaccessible: {e}")
        })?,
    };

    // Resolve store dir relative to project
    let store_dir = if args.store_dir.is_relative() {
        project_dir.join(&args.store_dir)
    } else {
        args.store_dir.clone()
    };

    // Resolve output path relative to project
    let output_path = if args.output.is_relative() {
        project_dir.join(&args.output)
    } else {
        args.output.clone()
    };

    tracing::info!(
        pkgs_dir = %args.pkgs_dir.display(),
        stdlib_dir = %args.stdlib_dir.display(),
        store_dir = %store_dir.display(),
        "starting forge evaluation"
    );

    // 1. Evaluate packages
    let config = ForgeConfig {
        pkgs_dir: args.pkgs_dir.clone(),
        stdlib_dir: args.stdlib_dir.clone(),
        store_dir,
        filter: args.packages.clone(),
    };

    let output = evaluate_packages(&config)?;

    eprintln!(
        "forge: {}/{} packages evaluated in {:.1}s",
        output.evaluated,
        output.evaluated + output.failed,
        output.elapsed.as_secs_f64(),
    );

    if !output.failed_packages.is_empty() {
        eprintln!(
            "forge: failed packages: {}",
            output.failed_packages.join(", ")
        );
    }

    // 1b. Verify proof artifacts (optional)
    #[allow(unused_assignments)]
    let mut verification_results = vec![];
    if args.verify {
        use gleisner_forge::attest::extract_package_metadata;
        use gleisner_forge::verify::{VerifyConfig, detect_lean, verify_packages};

        let lean_bin = args.lean_bin.clone().or_else(detect_lean);
        if lean_bin.is_none() {
            eprintln!(
                "forge: --verify requested but no Lean binary found (install elan or pass --lean-bin)"
            );
            if args.strict_verify {
                return Err(eyre!(
                    "strict verify mode: Lean binary required but not found"
                ));
            }
        }

        let proof_cache_dir = config
            .store_dir
            .parent()
            .unwrap_or(&config.store_dir)
            .join("proof-cache");
        let verify_config = VerifyConfig {
            lean_bin,
            lake_bin: gleisner_forge::verify::detect_lake(),
            strict: args.strict_verify,
            timeout_secs: 300,
            proof_cache_dir,
        };

        let metadata: Vec<_> = output
            .package_results
            .iter()
            .map(|(name, json)| extract_package_metadata(name, json))
            .collect();

        let with_proofs: Vec<_> = metadata
            .iter()
            .filter(|m| !m.verified_properties.is_empty())
            .collect();

        if with_proofs.is_empty() {
            eprintln!("forge: no packages declare verified_properties, skipping verification");
        } else {
            eprintln!(
                "forge: verifying {} packages with proof artifacts",
                with_proofs.len()
            );
            verification_results = verify_packages(&metadata, &verify_config);

            for vr in &verification_results {
                let verified = vr.verified_count();
                let failed = vr.failed_count();
                let total = vr.results.len();
                eprintln!(
                    "forge: {} — {}/{} verified, {} failed",
                    vr.package_name, verified, total, failed
                );

                if failed > 0 && args.strict_verify {
                    return Err(eyre!(
                        "strict verify: package '{}' has {} failed proof(s)",
                        vr.package_name,
                        failed
                    ));
                }
            }
        }
    }

    // 2. Convert to sandbox policy
    let report = compose_to_policy(&output.environment);

    if !report.credential_paths.is_empty() {
        eprintln!(
            "forge: {} credential paths noted (not mounted): {}",
            report.credential_paths.len(),
            report.credential_paths.join(", "),
        );
    }

    for warning in &report.warnings {
        tracing::warn!("{warning}");
    }

    eprintln!(
        "forge: composed {} RO + {} RW dirs, dns={}, internet={}",
        report.filesystem.readonly_bind.len(),
        report.filesystem.readwrite_bind.len(),
        report.network.allow_dns,
        report.network.allow_internet,
    );

    // 3. Validate against profile if requested
    if let Some(profile_name) = &args.profile {
        let profile = gleisner_polis::resolve_profile(profile_name)?;
        validate_against_profile(&report, &profile)?;
        eprintln!("forge: validated against profile '{profile_name}'");
    }

    // 4. Compose the full output
    let composed_json = serde_json::json!({
        "environment": output.environment,
        "policy": {
            "filesystem": report.filesystem,
            "network": report.network,
        },
        "credential_paths": report.credential_paths,
        "warnings": report.warnings,
        "stats": {
            "evaluated": output.evaluated,
            "failed": output.failed,
            "failed_packages": output.failed_packages,
            "elapsed_secs": output.elapsed.as_secs_f64(),
        },
    });

    let mut attestation =
        extract_attestation_with_results(&output, &composed_json, &output.package_results);

    // Apply verification results to attestation metadata
    if !verification_results.is_empty() {
        gleisner_forge::verify::apply_verification_results(
            &mut attestation.package_metadata,
            &verification_results,
        );
        // Recompute verification summary with updated results
        attestation.verification =
            gleisner_forge::attest::compute_verification_summary(&attestation.package_metadata);
    }

    let full_json = serde_json::json!({
        "forge": composed_json,
        "attestation": attestation,
    });

    // --dry-run: print JSON to stdout and exit (no files written, no sandbox)
    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&full_json)?);
        return Ok(());
    }

    // 5. Write composed environment + bridge report
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, serde_json::to_string_pretty(&full_json)?)?;
    eprintln!(
        "forge: wrote {} ({} materials, {} subjects, {} packages with metadata)",
        output_path.display(),
        attestation.materials.len(),
        attestation.subjects.len(),
        attestation.package_metadata.len(),
    );

    // 6. Optionally run Claude Code in the composed sandbox
    if args.run {
        let manifest_path = output_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("session-manifest.json");
        run_in_composed_sandbox(args, &report, &project_dir, &full_json, &manifest_path)?;
    }

    Ok(())
}

/// Validate that the composed environment doesn't conflict with a profile's deny list.
#[cfg(target_os = "linux")]
fn validate_against_profile(
    report: &gleisner_forge::bridge::BridgeReport,
    profile: &gleisner_polis::Profile,
) -> Result<()> {
    let all_binds = report
        .filesystem
        .readonly_bind
        .iter()
        .chain(&report.filesystem.readwrite_bind);

    for bind_path in all_binds {
        for denied in &profile.filesystem.deny {
            let denied_expanded = gleisner_polis::expand_tilde(denied);
            if bind_path.starts_with(&denied_expanded) {
                return Err(eyre!(
                    "composed bind '{}' conflicts with profile deny '{}'",
                    bind_path.display(),
                    denied.display(),
                ));
            }
        }
    }

    Ok(())
}

/// Run Claude Code inside a sandbox derived from the composed environment.
///
/// After the inner process exits, writes a session manifest to `manifest_path`
/// capturing the sandbox configuration, exit status, timing, and a digest of
/// the forge output. This manifest is the trust signal a management Claude
/// uses to verify what happened.
#[cfg(target_os = "linux")]
#[expect(clippy::needless_pass_by_value, reason = "args is consumed by fields")]
fn run_in_composed_sandbox(
    args: ForgeArgs,
    report: &gleisner_forge::bridge::BridgeReport,
    project_dir: &std::path::Path,
    forge_output: &serde_json::Value,
    manifest_path: &std::path::Path,
) -> Result<()> {
    // Start with the requested base profile, or default to konishi
    let base_name = args.profile.as_deref().unwrap_or("konishi");
    let mut profile = gleisner_polis::resolve_profile(base_name)?;

    // Merge forge filesystem policy into profile
    for path in &report.filesystem.readonly_bind {
        if !profile.filesystem.readonly_bind.contains(path) {
            profile.filesystem.readonly_bind.push(path.clone());
        }
    }
    for path in &report.filesystem.readwrite_bind {
        if !profile.filesystem.readwrite_bind.contains(path) {
            profile.filesystem.readwrite_bind.push(path.clone());
        }
    }

    // Merge network policy
    if report.network.allow_dns {
        profile.network.allow_dns = true;
    }
    if report.network.allow_internet {
        profile.network.default = gleisner_polis::profile::PolicyDefault::Allow;
    }

    let inner_command =
        gleisner_polis::build_claude_inner_command(&args.claude_bin, &profile, &args.claude_args);

    let config = gleisner_polis::SandboxSessionConfig {
        profile,
        project_dir: project_dir.to_path_buf(),
        extra_allow_network: Vec::new(),
        extra_allow_paths: Vec::new(),
        no_landlock: false,
        no_cgroups: false,
    };

    let mut prepared = gleisner_polis::prepare_sandbox(config, &inner_command)?;

    prepared.command.env_remove("CLAUDECODE");
    prepared.command.stdin(std::process::Stdio::inherit());
    prepared.command.stdout(std::process::Stdio::inherit());
    prepared.command.stderr(std::process::Stdio::inherit());

    let mut child = prepared
        .command
        .spawn()
        .map_err(|e| eyre!("failed to spawn sandboxed process: {e}"))?;

    let child_pid = child.id();
    #[expect(clippy::cast_possible_wrap, reason = "PID fits in i32")]
    if let Err(e) = prepared.apply_rlimits(nix::unistd::Pid::from_raw(child_pid as i32)) {
        tracing::warn!(error = %e, "failed to apply rlimits");
    }

    let session_start = std::time::Instant::now();
    let session_start_utc = chrono::Utc::now();

    let status = child
        .wait()
        .map_err(|e| eyre!("failed to wait on sandboxed process: {e}"))?;

    drop(prepared);

    let session_duration = session_start.elapsed();
    let exit_code = status.code().unwrap_or(1);

    // Write session manifest — the trust signal for management Claudes
    let forge_digest = {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_string(forge_output).unwrap_or_default();
        hex::encode(Sha256::digest(bytes.as_bytes()))
    };

    let manifest = serde_json::json!({
        "schema": "gleisner.dev/session-manifest/v1",
        "session": {
            "started_at": session_start_utc.to_rfc3339(),
            "duration_secs": session_duration.as_secs_f64(),
            "exit_code": exit_code,
        },
        "sandbox": {
            "profile": args.profile.as_deref().unwrap_or("konishi"),
            "filesystem": {
                "readonly_bind_count": report.filesystem.readonly_bind.len(),
                "readwrite_bind_count": report.filesystem.readwrite_bind.len(),
            },
            "network": {
                "allow_dns": report.network.allow_dns,
                "allow_internet": report.network.allow_internet,
            },
            "credential_paths_excluded": report.credential_paths.len(),
        },
        "forge": {
            "output_digest": forge_digest,
            "packages": args.packages,
        },
        "warnings": report.warnings,
    });

    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    eprintln!(
        "forge: session manifest written to {}",
        manifest_path.display()
    );

    std::process::exit(exit_code);
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)]
pub async fn execute(_args: ForgeArgs) -> Result<()> {
    color_eyre::eyre::bail!("gleisner forge requires Linux")
}
