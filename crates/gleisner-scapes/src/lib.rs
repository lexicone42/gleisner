//! Audit logging and observability for Gleisner sandboxed sessions.
//!
//! `gleisner-scapes` provides the event types, JSONL audit log writer,
//! and async broadcast channel that all other Gleisner crates use to
//! observe and record actions within a sandboxed Claude Code session.

pub mod audit;
pub mod error;
pub mod stream;
