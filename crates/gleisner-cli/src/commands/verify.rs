//! The `gleisner verify` subcommand.
//!
//! Verifies an attestation bundle's signature, digests, and policies.

use std::path::PathBuf;
use std::process;

use clap::Args;
use color_eyre::eyre::Result;
use gleisner_lacerta::verify::{VerificationOutcome, Verifier, VerifyConfig};

/// Arguments for `gleisner verify`.
#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the attestation bundle JSON file.
    pub bundle: PathBuf,

    /// Override the public key with a PEM file.
    #[arg(long, value_name = "PATH")]
    pub public_key: Option<PathBuf>,

    /// Policy file (JSON or .wasm) to evaluate.
    #[arg(long, value_name = "PATH")]
    pub policy: Option<Vec<PathBuf>>,

    /// Path to the audit log for digest verification.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Re-hash subjects and verify digests against files on disk.
    #[arg(long)]
    pub check_files: bool,

    /// Base directory for resolving subject file paths.
    #[arg(long, value_name = "PATH")]
    pub base_dir: Option<PathBuf>,

    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Execute the verify command.
pub fn execute(args: VerifyArgs) -> Result<()> {
    let mut policies: Vec<Box<dyn gleisner_lacerta::policy::PolicyEngine>> = Vec::new();

    if let Some(policy_paths) = &args.policy {
        for path in policy_paths {
            let policy = gleisner_lacerta::verify::load_policy(path)?;
            policies.push(policy);
        }
    }

    let check_files_base = if args.check_files {
        Some(args.base_dir.clone().unwrap_or_else(|| PathBuf::from(".")))
    } else {
        args.base_dir.clone()
    };

    let config = VerifyConfig {
        public_key_override: args.public_key,
        audit_log_path: args.audit_log,
        check_files_base,
        policies,
    };

    let verifier = Verifier::new(config);
    let report = verifier.verify_file(&args.bundle)?;

    if args.json {
        let json_report = serde_json::json!({
            "passed": report.passed,
            "outcomes": report.outcomes.iter().map(|o| {
                serde_json::json!({
                    "status": match o {
                        VerificationOutcome::Pass(_) => "pass",
                        VerificationOutcome::Fail(_) => "fail",
                        VerificationOutcome::Skip(_) => "skip",
                    },
                    "message": o.message(),
                })
            }).collect::<Vec<_>>(),
            "policy_results": report.policy_results,
        });
        println!("{}", serde_json::to_string_pretty(&json_report)?);
    } else {
        for outcome in &report.outcomes {
            let (icon, msg) = match outcome {
                VerificationOutcome::Pass(m) => ("PASS", m.as_str()),
                VerificationOutcome::Fail(m) => ("FAIL", m.as_str()),
                VerificationOutcome::Skip(m) => ("SKIP", m.as_str()),
            };
            println!("[{icon}] {msg}");
        }

        println!();
        if report.passed {
            println!("Verification PASSED");
        } else {
            println!("Verification FAILED");
        }
    }

    if !report.passed {
        process::exit(1);
    }

    Ok(())
}
