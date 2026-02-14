//! Hermetic sandbox for Claude Code — the trusted execution environment.
//!
//! `gleisner-polis` provides sandbox profile definitions, profile resolution,
//! and the bubblewrap/Landlock backend that creates isolated execution
//! environments for Claude Code sessions.

mod bwrap;
pub mod error;
mod namespace;
mod policy;
pub mod profile;
mod resource;

pub use bwrap::BwrapSandbox;
pub use profile::{Profile, resolve_profile};
