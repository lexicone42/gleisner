//! Content-addressed store for evaluated Nickel packages.
//!
//! Each evaluated package is serialized to canonical JSON, hashed with SHA-256,
//! and stored at `<store_root>/<hash>/result.json`. This mirrors Nix's store
//! layout but uses pure content addressing without the name component.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::StoreError;

/// A content-addressed store for evaluated package results.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// A reference to a stored evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StoreRef {
    /// The SHA-256 hash of the canonical JSON content.
    pub hash: String,
}

impl Store {
    /// Create a new store rooted at the given directory.
    ///
    /// The directory is created if it does not exist.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|source| StoreError::Io {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    /// Compute the content hash for a JSON value without storing it.
    pub fn content_hash(json: &serde_json::Value) -> String {
        let canonical = canonical_json(json);
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Store an evaluated result, returning a reference to it.
    ///
    /// If a result with the same hash already exists, this is a no-op.
    pub fn put(&self, json: &serde_json::Value) -> Result<StoreRef, StoreError> {
        let hash = Self::content_hash(json);
        let entry_dir = self.root.join(&hash);
        let result_path = entry_dir.join("result.json");

        if result_path.exists() {
            tracing::debug!(hash = %hash, "store hit — already exists");
            return Ok(StoreRef { hash });
        }

        std::fs::create_dir_all(&entry_dir).map_err(|source| StoreError::Io {
            path: entry_dir.clone(),
            source,
        })?;

        let canonical = canonical_json(json);
        std::fs::write(&result_path, &canonical).map_err(|source| StoreError::Io {
            path: result_path,
            source,
        })?;

        tracing::info!(hash = %hash, "stored evaluation result");
        Ok(StoreRef { hash })
    }

    /// Retrieve a stored result by its hash.
    pub fn get(&self, store_ref: &StoreRef) -> Result<serde_json::Value, StoreError> {
        let result_path = self.root.join(&store_ref.hash).join("result.json");
        let content = std::fs::read_to_string(&result_path).map_err(|source| StoreError::Io {
            path: result_path,
            source,
        })?;
        serde_json::from_str(&content).map_err(|e| StoreError::Io {
            path: self.root.join(&store_ref.hash),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })
    }

    /// Check whether a result exists in the store.
    pub fn contains(&self, store_ref: &StoreRef) -> bool {
        self.root.join(&store_ref.hash).join("result.json").exists()
    }

    /// Return the filesystem path to a stored result.
    pub fn path_of(&self, store_ref: &StoreRef) -> PathBuf {
        self.root.join(&store_ref.hash).join("result.json")
    }

    /// Return the store root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Produce canonical JSON: sorted keys, no trailing whitespace, compact.
fn canonical_json(value: &serde_json::Value) -> String {
    // serde_json with sorted keys via recursive sorting
    let sorted = sort_json_keys(value);
    serde_json::to_string(&sorted).expect("canonical JSON serialization cannot fail")
}

/// Recursively sort all object keys in a JSON value.
fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys() {
        let json: serde_json::Value =
            serde_json::from_str(r#"{"z": 1, "a": 2, "m": {"b": 3, "a": 4}}"#).unwrap();
        let canonical = canonical_json(&json);
        assert_eq!(canonical, r#"{"a":2,"m":{"a":4,"b":3},"z":1}"#);
    }

    #[test]
    fn content_hash_is_deterministic() {
        let json: serde_json::Value = serde_json::from_str(r#"{"name": "test"}"#).unwrap();
        let h1 = Store::content_hash(&json);
        let h2 = Store::content_hash(&json);
        assert_eq!(h1, h2);
    }

    #[test]
    fn store_put_and_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("store")).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(r#"{"name": "hello", "version": "1.0"}"#).unwrap();

        let store_ref = store.put(&json).unwrap();
        assert!(store.contains(&store_ref));

        let retrieved = store.get(&store_ref).unwrap();
        assert_eq!(Store::content_hash(&json), Store::content_hash(&retrieved));
    }

    #[test]
    fn store_put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("store")).unwrap();
        let json: serde_json::Value = serde_json::from_str(r#"{"x": 42}"#).unwrap();

        let ref1 = store.put(&json).unwrap();
        let ref2 = store.put(&json).unwrap();
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn different_key_order_same_hash() {
        let j1: serde_json::Value = serde_json::from_str(r#"{"a": 1, "b": 2}"#).unwrap();
        let j2: serde_json::Value = serde_json::from_str(r#"{"b": 2, "a": 1}"#).unwrap();
        assert_eq!(Store::content_hash(&j1), Store::content_hash(&j2));
    }
}
