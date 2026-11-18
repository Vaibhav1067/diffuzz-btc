//! Arbitrary protocol lines into the Rust adapters' line handlers: they must answer every line
//! with valid JSON and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let _ = diffuzz_adapter_core::handle_line(line);
    let _ = diffuzz_adapter_core::handle_aux_line(line);
    let out = diffuzz_adapter_rust_bitcoin::handle_line(line);
    assert!(
        serde_json::from_str::<serde_json::Value>(&out).is_ok(),
        "invalid JSON: {out}"
    );
});
