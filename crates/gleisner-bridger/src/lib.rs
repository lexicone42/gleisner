//! SBOM generation and dependency trust analysis for Claude Code projects.
//!
//! `gleisner-bridger` scans lockfiles, cross-references with registries
//! and vulnerability databases, and produces `CycloneDX` 1.5 SBOMs with
//! trust annotations indicating whether dependencies were introduced
//! by Claude Code or pre-existing.

pub mod error;
