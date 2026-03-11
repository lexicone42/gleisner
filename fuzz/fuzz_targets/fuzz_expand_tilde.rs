#![no_main]

//! Fuzz `expand_tilde` with arbitrary byte sequences interpreted as paths.
//!
//! Properties:
//! - Never panics on any input
//! - Absolute paths pass through unchanged
//! - Result is idempotent (expanding twice equals expanding once)

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let path = Path::new(s);
    let expanded = gleisner_polis::expand_tilde(path);

    // Absolute paths must pass through unchanged
    if path.is_absolute() {
        assert_eq!(
            expanded.as_path(),
            path,
            "absolute paths must be unchanged"
        );
    }

    // Idempotence: expanding the result again must not change it
    let double_expanded = gleisner_polis::expand_tilde(&expanded);
    assert_eq!(
        expanded, double_expanded,
        "expand_tilde must be idempotent"
    );
});
