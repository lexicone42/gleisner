#![no_main]

//! Fuzz `ComposedEnvironment::merge_package` with arbitrary JSON.
//!
//! Exercises all internal parsers: `parse_dir_mapping`, `parse_file_mapping`,
//! `parse_state_wiring`, `extract_domain`, and the conflict resolution logic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse the fuzz input as a JSON value
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    let mut env = gleisner_forge::compose::ComposedEnvironment::new();

    // Merge twice to exercise conflict resolution paths
    env.merge_package("fuzz-pkg-a", &json);
    env.merge_package("fuzz-pkg-b", &json);

    // Basic invariants that must hold for any input
    assert!(env.packages.len() == 2);
    assert!(env.packages[0] == "fuzz-pkg-a");
    assert!(env.packages[1] == "fuzz-pkg-b");

    // Needs are monotonic (logical OR): merging same data twice can't reduce them
    let needs_snapshot = (env.needs.dns, env.needs.internet);
    env.merge_package("fuzz-pkg-c", &json);
    assert!(
        env.needs.dns >= needs_snapshot.0 && env.needs.internet >= needs_snapshot.1,
        "needs must be monotonically non-decreasing"
    );
});
