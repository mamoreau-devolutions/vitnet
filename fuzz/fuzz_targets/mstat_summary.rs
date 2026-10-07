#![no_main]

use libfuzzer_sys::fuzz_target;
use vitnet_mstat::summarize;

fuzz_target!(|data: &[u8]| {
    let _ = summarize(data, 1024 * 1024);
});
