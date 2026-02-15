//! Gleisner TUI — a security-aware AI coding REPL.
//!
//! This crate provides a Ratatui-based terminal interface that consumes
//! Claude CLI's `stream-json` output, with gleisner's security model
//! (sandbox, attestation, policy) built around the subprocess.
//!
//! # Architecture (Phase A)
//!
//! ```text
//! User ──→ gleisner-tui (ratatui)
//!               │
//!               ├── Spawns: claude -p --output-format stream-json (in bwrap)
//!               ├── Parses: NDJSON event stream
//!               ├── Renders: conversation + security dashboard
//!               └── Records: tool calls for attestation
//! ```

pub mod app;
pub mod claude;
pub mod stream;
pub mod ui;
