//! Hermetic sandbox for Claude Code — the trusted execution environment.
//!
//! `gleisner-polis` provides sandbox profile definitions, profile resolution,
//! and the bubblewrap/Landlock backend that creates isolated execution
//! environments for Claude Code sessions.
//!
//! # Platform support
//!
//! The sandbox backend (bwrap, Landlock, namespaces, nftables, cgroups) is
//! Linux-only. Profile resolution, the learner, filesystem monitoring, and
//! portable utilities compile on all platforms.

// ── Portable (always compiled) ──────────────────────────────────────
pub mod error;
pub mod fs_monitor;
pub mod learner;
pub mod monitor;
pub mod policy;
pub mod profile;
mod util;

// ── Linux-only ──────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub mod audit_log;
#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
pub mod netfilter;
#[cfg(target_os = "linux")]
pub mod procmon;
#[cfg(target_os = "linux")]
pub mod resource;
#[cfg(target_os = "linux")]
pub mod session;

// ── Portable re-exports ─────────────────────────────────────────────
pub use learner::{
    LearnerConfig, LearningSummary, ProfileLearner, format_profile_toml, format_summary,
};
pub use monitor::{FsMonitorConfig, ProcMonitorConfig};
pub use policy::{FileAccessType, LandlockPolicy};
pub use profile::{Profile, resolve_profile};
pub use util::{build_claude_inner_command, expand_tilde, resolve_claude_bin};

// ── Linux-only re-exports ───────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use audit_log::{
    KernelAuditConfig, capture_firewall_denials_from_dmesg, collect_and_publish_denials,
    denial_to_events, parse_audit_line, parse_firewall_denial_line, parse_firewall_denials,
    parse_firewall_denials_from_str, parse_kernel_denials,
};
#[cfg(target_os = "linux")]
pub use bwrap::BwrapSandbox;
#[cfg(target_os = "linux")]
pub use landlock::{LandlockEnforcement, LandlockStatus, apply_landlock};
#[cfg(target_os = "linux")]
pub use netfilter::{FIREWALL_DENY_PREFIX, NamespaceHandle, NetworkFilter, TapHandle};
#[cfg(target_os = "linux")]
pub use resource::CgroupScope;
#[cfg(target_os = "linux")]
pub use session::{PreparedSandbox, SandboxSessionConfig, detect_sandbox_init, prepare_sandbox};
