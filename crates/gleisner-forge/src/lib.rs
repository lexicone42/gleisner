//! Incremental Nickel package evaluator with content-addressed store.
//!
//! `gleisner-forge` evaluates [minimal.dev](https://minimal.dev) package
//! declarations one at a time in dependency order, substituting already-evaluated
//! dependencies as virtual imports.
//!
//! Results are stored in a content-addressed store keyed by
//! `sha256(canonical_json(result))`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐    ┌─────────┐
//! │  DAG    │───>│  Eval    │───>│  Store    │───>│  Compose    │───>│ Bridge  │
//! │ extract │    │ package  │    │ result    │    │ environment │    │ policy  │
//! └─────────┘    └──────────┘    └───────────┘    └─────────────┘    └─────────┘
//!     regex        Nickel         sha256(JSON)     merge attrs/       →sandbox
//!     scan         virtual        content-         needs across       →attest
//!                  imports        addressed        packages
//! ```
//!
//! # Quick start
//!
//! ```no_run
//! use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};
//! use std::path::PathBuf;
//!
//! let config = ForgeConfig {
//!     pkgs_dir: PathBuf::from("/path/to/minimal-pkgs"),
//!     stdlib_dir: PathBuf::from("/path/to/minimal-std"),
//!     store_dir: PathBuf::from(".gleisner/forge-store"),
//!     filter: vec![],
//! };
//! let output = evaluate_packages(&config).unwrap();
//! println!("{} packages, {} dirs", output.evaluated, output.environment.dir_mappings.len());
//! ```

pub mod attest;
pub mod bridge;
pub mod compose;
pub mod dag;
pub mod error;
pub mod eval;
pub mod orchestrate;
pub mod store;
