//! Incremental Nickel package evaluator with content-addressed store.
//!
//! `gleisner-forge` evaluates [minimal.dev](https://minimal.dev) package
//! declarations one at a time in dependency order, substituting already-evaluated
//! dependencies as flat JSON via Nickel's `custom_transform` API. Results are
//! stored in a content-addressed store keyed by `sha256(canonical_json(result))`.
//!
//! The composed environment (merged `Attrs` and `Needs` across packages) maps
//! directly to gleisner's `FilesystemPolicy` and `NetworkPolicy` for sandbox
//! configuration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐
//! │  DAG    │───>│  Eval    │───>│  Store    │───>│  Compose    │
//! │ extract │    │ package  │    │ result    │    │ environment │
//! └─────────┘    └──────────┘    └───────────┘    └─────────────┘
//!     regex        Nickel         sha256(JSON)     merge attrs/
//!     scan         custom_        content-         needs across
//!                  transform      addressed        packages
//! ```

pub mod compose;
pub mod dag;
pub mod error;
pub mod eval;
pub mod orchestrate;
pub mod store;
