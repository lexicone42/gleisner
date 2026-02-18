//! Hermetic sandbox for Claude Code — the trusted execution environment.
//!
//! `gleisner-polis` provides sandbox profile definitions, profile resolution,
//! and the bubblewrap/Landlock backend that creates isolated execution
//! environments for Claude Code sessions.

pub mod audit_log;
mod bwrap;
pub mod error;
pub mod inotify_mon;
mod landlock;
pub mod learner;
pub mod monitor;
mod namespace;
pub mod netfilter;
pub mod policy;
pub mod procmon;
pub mod profile;
pub mod resource;
pub mod session;

pub use audit_log::{KernelAuditConfig, collect_and_publish_denials};
pub use bwrap::{BwrapSandbox, expand_tilde};
pub use landlock::{LandlockEnforcement, LandlockPolicy, LandlockStatus, apply_landlock};
pub use learner::{
    LearnerConfig, LearningSummary, ProfileLearner, format_profile_toml, format_summary,
};
pub use monitor::{FsMonitorConfig, ProcMonitorConfig};
pub use netfilter::{NamespaceHandle, NetworkFilter, SlirpHandle};
pub use policy::FileAccessType;
pub use profile::{Profile, resolve_profile};
pub use resource::CgroupScope;
pub use session::{
    PreparedSandbox, SandboxSessionConfig, build_claude_inner_command, detect_sandbox_init,
    prepare_sandbox, resolve_claude_bin,
};
