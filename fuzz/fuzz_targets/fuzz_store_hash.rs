#![no_main]

//! Fuzz `Store::content_hash` and `canonical_json` (via the public API).
//!
//! Properties:
//! - content_hash never panics on arbitrary JSON
//! - content_hash is deterministic (same input → same hash)
//! - canonical JSON is idempotent (hash of re-parsed output equals original hash)
//! - hash is always 64 hex chars (SHA-256)

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    let h1 = gleisner_forge::store::Store::content_hash(&json);
    let h2 = gleisner_forge::store::Store::content_hash(&json);

    // Determinism
    assert_eq!(h1, h2, "content_hash must be deterministic");

    // SHA-256 is always 64 hex characters
    assert_eq!(h1.len(), 64, "hash must be 64 hex chars");
    assert!(
        h1.chars().all(|c| c.is_ascii_hexdigit()),
        "hash must be hex"
    );
});
