#![no_main]

//! Fuzz the JSONL audit event reader with arbitrary bytes.
//!
//! The reader must handle malformed input gracefully — returning errors,
//! never panicking, and never producing events from garbage input.

use libfuzzer_sys::fuzz_target;
use std::io::BufReader;

fuzz_target!(|data: &[u8]| {
    let reader = BufReader::new(data);
    let mut jsonl_reader = gleisner_scapes::audit::JsonlReader::new(reader);

    // Drain all events — must not panic regardless of input
    loop {
        match jsonl_reader.next_event() {
            Ok(Some(event)) => {
                // If it successfully deserialized, re-serialize must not panic
                let serialized = serde_json::to_string(&event);
                assert!(serialized.is_ok(), "valid event must re-serialize");

                // EnvRead must never leak raw values — only value_sha256
                if let gleisner_scapes::audit::EventKind::EnvRead { .. } = &event.event {
                    let json_str = serialized.unwrap();
                    // The field is called "value_sha256", not "value"
                    // Check no bare "value" key at the detail level
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(detail) = parsed.get("event").and_then(|e| e.get("detail")) {
                            assert!(
                                detail.get("value").is_none(),
                                "EnvRead must not have raw 'value' field"
                            );
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => break, // Parse errors are expected for fuzz input
        }
    }
});
