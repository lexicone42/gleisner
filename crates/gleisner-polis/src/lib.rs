//! Hermetic sandbox for Claude Code — the trusted execution environment.
//!
//! `gleisner-polis` provides sandbox profile definitions, profile resolution,
//! and the bubblewrap/Landlock backend that creates isolated execution
//! environments for Claude Code sessions.

mod bwrap;
pub mod error;
pub mod fanotify;
pub mod monitor;
mod namespace;
pub mod netfilter;
pub mod policy;
pub mod procmon;
pub mod profile;
pub mod resource;

pub use bwrap::BwrapSandbox;
pub use monitor::{FsMonitorConfig, ProcMonitorConfig};
pub use netfilter::{NamespaceHandle, NetworkFilter, SlirpHandle};
pub use policy::FileAccessType;
pub use profile::{Profile, resolve_profile};
pub use resource::CgroupScope;
