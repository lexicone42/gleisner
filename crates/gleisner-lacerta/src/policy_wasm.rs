//! OPA/WASM policy engine stub.
//!
//! This module provides the structure for evaluating OPA policies compiled
//! to WASM, but the actual evaluation is not yet implemented. The OPA ABI
//! for WASM is complex (memory management, JSON serialization protocol)
//! and the built-in policy engine covers immediate needs.

use std::path::Path;

use wasmtime::{Engine, Module};

use crate::error::VerificationError;
use crate::policy::{PolicyEngine, PolicyInput, PolicyResult};

/// A WASM-based policy engine for OPA/Rego policies.
pub struct WasmPolicy {
    #[expect(dead_code, reason = "will be used when OPA ABI is implemented")]
    engine: Engine,
    #[expect(dead_code, reason = "will be used when OPA ABI is implemented")]
    module: Module,
}

impl WasmPolicy {
    /// Load a WASM policy from a file path.
    pub fn from_file(path: &Path) -> Result<Self, VerificationError> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path).map_err(|e| {
            VerificationError::PolicyError(format!("failed to load WASM module: {e}"))
        })?;
        Ok(Self { engine, module })
    }

    /// Load a WASM policy from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerificationError> {
        let engine = Engine::default();
        let module = Module::new(&engine, bytes).map_err(|e| {
            VerificationError::PolicyError(format!("failed to compile WASM module: {e}"))
        })?;
        Ok(Self { engine, module })
    }
}

impl PolicyEngine for WasmPolicy {
    fn evaluate(&self, _input: &PolicyInput) -> Result<Vec<PolicyResult>, VerificationError> {
        Err(VerificationError::PolicyError(
            "WASM/OPA policy evaluation is not yet implemented".to_owned(),
        ))
    }
}
