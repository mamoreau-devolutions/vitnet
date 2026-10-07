#![no_main]

use libfuzzer_sys::fuzz_target;
use vitnet_metadata::decode_metadata_prefix;

fuzz_target!(|data: &[u8]| {
    let _ = decode_metadata_prefix(data, false);
    let _ = decode_metadata_prefix(data, true);
});
