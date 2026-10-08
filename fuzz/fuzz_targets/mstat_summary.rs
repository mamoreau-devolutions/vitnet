#![no_main]

use libfuzzer_sys::fuzz_target;
use vitnet_mstat::{CohortRule, InsightsOptions, insights, summarize};

fuzz_target!(|data: &[u8]| {
    let _ = summarize(data, 1024 * 1024);
    if data.len() <= 1024 * 1024 {
        let _ = insights(
            data,
            1024 * 1024,
            &InsightsOptions {
                top: 2,
                contains: None,
                rules: vec![
                    CohortRule {
                        name: "literal".into(),
                        contains: vec!["M".into(), "\u{03bb}".into()],
                        stream: None,
                    },
                    CohortRule {
                        name: "shaped".into(),
                        contains: vec!["<".into()],
                        stream: Some("Methods".into()),
                    },
                ],
            },
        );
    }
});
