#![no_main]

use libfuzzer_sys::fuzz_target;
use vitnet_attribution::{model::Evidence, parse_shape, validate_evidence};

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 64 * 1024 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = parse_shape(text);
    }
    if let Ok(evidence) = serde_json::from_slice::<Evidence>(bytes) {
        let _ = validate_evidence(&evidence);
    }
});
