#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vitnet_dgml::{StatsOptions, analyze_stats};

fuzz_target!(|data: &[u8]| {
    let _ = analyze_stats(
        Cursor::new(data),
        StatsOptions {
            top: 8,
            memory_limit: 1024 * 1024,
            input_bytes: data.len() as u64,
        },
    );
});
