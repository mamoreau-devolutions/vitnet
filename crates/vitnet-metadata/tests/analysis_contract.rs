use proptest::prelude::*;
use vitnet_metadata::{
    Aggregate, AnalysisOptions, LimitStatus, MetadataRecord, RawRecord, analyze, analyze_stream,
    compare, metadata_records_from_raw, preview_bytes, top_n,
};

fn record(
    offset: u64,
    kind: &[u8],
    name: &[u8],
    assembly: Option<&[u8]>,
    namespace: Option<&[u8]>,
    type_name: Option<&[u8]>,
    is_string: bool,
) -> MetadataRecord {
    MetadataRecord {
        logical_offset: offset,
        kind: kind.to_vec(),
        name: name.to_vec(),
        assembly: assembly.map(<[u8]>::to_vec),
        namespace: namespace.map(<[u8]>::to_vec),
        type_name: type_name.map(<[u8]>::to_vec),
        is_string,
    }
}

fn fixture() -> Vec<MetadataRecord> {
    vec![
        record(0, b"Assembly", b"A", Some(b"A"), None, None, false),
        record(10, b"Namespace", b"N", Some(b"A"), Some(b"N"), None, false),
        record(20, b"Type", b"T", Some(b"A"), Some(b"N"), Some(b"T"), false),
        record(40, b"Blob", b"raw", None, None, None, false),
        record(
            55,
            b"ConstantStringValue",
            b"hello",
            Some(b"A"),
            Some(b"N"),
            Some(b"T"),
            true,
        ),
        record(60, b"Type", b"U", Some(b"B"), Some(b"M"), Some(b"U"), false),
    ]
}

#[test]
#[allow(clippy::too_many_lines)]
fn analysis_reports_every_aggregate_strings_unowned_and_lower_bound_semantics() {
    let analysis = analyze(
        &fixture(),
        &AnalysisOptions {
            top: 10,
            preview_bytes: 256,
            assembly_filter: None,
        },
    );

    assert_eq!(analysis.total_lower_bound, 60);
    assert!(analysis.total_is_lower_bound);
    assert!(!analysis.final_record_size_known);
    assert_eq!(analysis.record_count, 6);
    assert_eq!(
        analysis.by_kind,
        vec![
            Aggregate {
                name: "Type".into(),
                bytes: 20,
                records: 2
            },
            Aggregate {
                name: "Blob".into(),
                bytes: 15,
                records: 1
            },
            Aggregate {
                name: "Assembly".into(),
                bytes: 10,
                records: 1
            },
            Aggregate {
                name: "Namespace".into(),
                bytes: 10,
                records: 1
            },
            Aggregate {
                name: "ConstantStringValue".into(),
                bytes: 5,
                records: 1
            },
        ]
    );
    assert_eq!(
        analysis.by_assembly,
        vec![
            Aggregate {
                name: "A".into(),
                bytes: 45,
                records: 4
            },
            Aggregate {
                name: "B".into(),
                bytes: 0,
                records: 1
            },
        ]
    );
    assert_eq!(
        analysis.by_namespace,
        vec![
            Aggregate {
                name: "N".into(),
                bytes: 35,
                records: 3
            },
            Aggregate {
                name: "M".into(),
                bytes: 0,
                records: 1
            },
        ]
    );
    assert_eq!(
        analysis.by_type,
        vec![
            Aggregate {
                name: "T".into(),
                bytes: 25,
                records: 2
            },
            Aggregate {
                name: "U".into(),
                bytes: 0,
                records: 1
            },
        ]
    );
    assert_eq!(analysis.largest_strings[0].preview.text, "hello");
    assert_eq!(analysis.largest_strings[0].bytes, 5);
    assert_eq!(
        analysis.unowned,
        vec![
            Aggregate {
                name: "Blob".into(),
                bytes: 15,
                records: 1
            },
            Aggregate {
                name: "Assembly".into(),
                bytes: 10,
                records: 1
            },
            Aggregate {
                name: "Namespace".into(),
                bytes: 10,
                records: 1
            },
        ]
    );
    assert!(matches!(
        analysis.limit_status,
        LimitStatus::AtOrBelowHeadroomUnknown {
            observed_lower_bound: 60,
            ..
        }
    ));
}

#[test]
fn assembly_filter_keeps_original_record_sizes_without_bridging_excluded_records() {
    let analysis = analyze(
        &fixture(),
        &AnalysisOptions {
            assembly_filter: Some(b"A".to_vec()),
            top: 10,
            preview_bytes: 20,
        },
    );
    assert_eq!(analysis.record_count, 4);
    assert_eq!(analysis.total_lower_bound, 45);
    assert_eq!(
        analysis.by_assembly,
        vec![Aggregate {
            name: "A".into(),
            bytes: 45,
            records: 4,
        }]
    );
    assert!(analysis.by_kind.iter().all(|value| value.name != "Blob"));
}

#[test]
fn unicode_preview_is_byte_bounded_scalar_safe_and_preserves_raw_length() {
    let preview = preview_bytes("éclair".as_bytes(), 3);
    assert_eq!(preview.text, "éc");
    assert_eq!(preview.text.len(), 3);
    assert_eq!(preview.original_bytes, 7);
    assert!(preview.truncated);

    let invalid = preview_bytes(b"a\xffb", 4);
    assert_eq!(invalid.text, "a\u{fffd}");
    assert_eq!(invalid.text.len(), 4);
    assert_eq!(invalid.original_bytes, 3);
    assert!(invalid.truncated);

    let zero = preview_bytes(b"value", 0);
    assert_eq!(zero.text, "");
    assert_eq!(zero.original_bytes, 5);
    assert!(zero.truncated);

    let empty = preview_bytes(b"", 0);
    assert_eq!(empty.text, "");
    assert_eq!(empty.original_bytes, 0);
    assert!(!empty.truncated);
}

#[test]
fn deterministic_top_n_uses_descending_bytes_then_ordinal_name() {
    let input = vec![
        Aggregate {
            name: "zeta".into(),
            bytes: 9,
            records: 1,
        },
        Aggregate {
            name: "Alpha".into(),
            bytes: 9,
            records: 2,
        },
        Aggregate {
            name: "alpha".into(),
            bytes: 10,
            records: 3,
        },
    ];
    let expected = vec![
        Aggregate {
            name: "alpha".into(),
            bytes: 10,
            records: 3,
        },
        Aggregate {
            name: "Alpha".into(),
            bytes: 9,
            records: 2,
        },
    ];
    for _ in 0..10 {
        assert_eq!(top_n(input.clone(), 2), expected);
    }
    assert!(top_n(input, 0).is_empty());
}

#[test]
fn metadata_limit_reports_unknown_headroom_at_limit_and_overage_above_it() {
    let at = analyze(
        &[record(
            (1 << 25) - 1,
            b"Type",
            b"T",
            None,
            None,
            Some(b"T"),
            false,
        )],
        &AnalysisOptions::default(),
    );
    assert!(matches!(
        at.limit_status,
        LimitStatus::AtOrBelowHeadroomUnknown {
            observed_lower_bound: 33_554_431,
            ..
        }
    ));

    let over = analyze(
        &[record(
            (1 << 25) + 9,
            b"Type",
            b"T",
            None,
            None,
            Some(b"T"),
            false,
        )],
        &AnalysisOptions::default(),
    );
    assert_eq!(
        over.limit_status,
        LimitStatus::OverByAtLeast {
            limit: 33_554_431,
            observed_lower_bound: 33_554_441,
            bytes: 10,
        }
    );
}

#[test]
fn empty_analysis_has_zero_lower_bound_and_empty_sections() {
    let analysis = analyze(&[], &AnalysisOptions::default());
    assert_eq!(analysis.total_lower_bound, 0);
    assert_eq!(analysis.record_count, 0);
    assert!(analysis.total_is_lower_bound);
    assert!(!analysis.final_record_size_known);
    assert!(analysis.by_kind.is_empty());
    assert!(analysis.by_assembly.is_empty());
    assert!(analysis.by_namespace.is_empty());
    assert!(analysis.by_type.is_empty());
    assert!(analysis.largest_strings.is_empty());
    assert!(analysis.unowned.is_empty());
    assert!(matches!(
        analysis.limit_status,
        LimitStatus::AtOrBelowHeadroomUnknown {
            observed_lower_bound: 0,
            ..
        }
    ));
}

#[test]
fn raw_hierarchy_populates_assembly_namespace_type_and_string_context() {
    let raw = vec![
        raw(0, b"Assembly", b"A", vec![10]),
        raw(10, b"Namespace", b"N", vec![20]),
        raw(20, b"Type", b"T", vec![30]),
        raw(30, b"ConstantStringValue", b"value", vec![]),
    ];
    let records = metadata_records_from_raw(&raw, true).unwrap();
    let string = &records[3];
    assert_eq!(string.assembly.as_deref(), Some(b"A".as_slice()));
    assert_eq!(string.namespace.as_deref(), Some(b"N".as_slice()));
    assert_eq!(string.type_name.as_deref(), Some(b"T".as_slice()));
    assert!(string.is_string);
}

fn raw(handle: u32, kind: &[u8], name: &[u8], children: Vec<u32>) -> RawRecord {
    RawRecord {
        handle,
        kind: kind.to_vec(),
        name: name.to_vec(),
        children,
        byte_range: 0..0,
        logical_record: 0,
        physical_line_start: 0,
        physical_line_end: 0,
    }
}

#[test]
fn streaming_analysis_uses_nearest_owner_and_real_producer_scope_kinds() {
    let input = vec![
        Ok(raw(0, b"ScopeDefinition", b"A", vec![20])),
        Ok(raw(10, b"ScopeDefinition", b"B", vec![20])),
        Ok(raw(20, b"TypeDefinition", b"T", vec![30])),
        Ok(raw(30, b"ConstantStringValue", b"value", vec![])),
    ];
    let analysis = analyze_stream(input, AnalysisOptions::default(), true, 1024 * 1024).unwrap();

    assert_eq!(analysis.observed_lower_bound, 30);
    assert_eq!(analysis.record_count, 4);
    assert!(
        analysis
            .by_assembly
            .iter()
            .any(|entry| { entry.name == "B" && entry.bytes == 20 && entry.records == 3 })
    );
    assert!(
        analysis
            .by_type
            .iter()
            .any(|entry| { entry.name == "B!T" && entry.bytes == 10 && entry.records == 2 })
    );
    assert_eq!(analysis.largest_strings[0].preview.text, "value");
}

#[test]
fn streaming_analysis_enforces_the_retained_state_budget() {
    let mut children = Vec::new();
    for value in 1..200 {
        children.push(value);
    }

    let error = analyze_stream(
        vec![Ok(raw(0, b"ScopeDefinition", b"A", children))],
        AnalysisOptions::default(),
        true,
        1024,
    )
    .unwrap_err();

    assert_eq!(error.diagnostic.code, "resource.memory_limit");
    assert!(
        error
            .diagnostic
            .actual
            .as_deref()
            .unwrap()
            .contains("tracked")
    );
}

#[test]
fn streaming_analysis_reconciles_prefix_bytes_and_uses_whole_input_limit_status() {
    let input = vec![
        Ok(raw(
            0x01ff_fff0,
            b"ScopeDefinition",
            b"A",
            vec![0x01ff_fff8],
        )),
        Ok(raw(0x01ff_fff8, b"ConstantStringValue", b"value", vec![])),
    ];
    let analysis = analyze_stream(
        input,
        AnalysisOptions {
            assembly_filter: Some(b"A".to_vec()),
            ..AnalysisOptions::default()
        },
        true,
        1024 * 1024,
    )
    .unwrap();

    assert_eq!(analysis.observed_lower_bound, 0x01ff_fff8);
    assert_eq!(analysis.selected_lower_bound, 8);
    assert_eq!(
        analysis
            .by_kind
            .iter()
            .map(|entry| entry.bytes)
            .sum::<u64>(),
        8
    );
    assert!(matches!(
        analysis.limit_status,
        LimitStatus::AtOrBelowHeadroomUnknown {
            observed_lower_bound: 0x01ff_fff8,
            ..
        }
    ));

    let unfiltered = analyze_stream(
        vec![
            Ok(raw(10, b"ScopeDefinition", b"A", vec![20])),
            Ok(raw(20, b"ConstantStringValue", b"value", vec![])),
        ],
        AnalysisOptions::default(),
        true,
        1024 * 1024,
    )
    .unwrap();
    assert_eq!(
        unfiltered
            .by_kind
            .iter()
            .map(|entry| entry.bytes)
            .sum::<u64>(),
        unfiltered.observed_lower_bound
    );
    assert!(unfiltered.unowned.iter().any(|entry| {
        entry.name == "(metadata prefix)" && entry.bytes == 10 && entry.records == 0
    }));
}

#[test]
fn streaming_analysis_detects_legacy_layout_and_uses_legacy_limit() {
    let analysis = analyze_stream(
        vec![
            Ok(raw(
                0x38ff_fff0,
                b"ScopeDefinition",
                b"A",
                vec![0x1aff_fff8],
            )),
            Ok(raw(0x1aff_fff8, b"ConstantStringValue", b"value", vec![])),
            Ok(raw(0x3800_0004, b"ScopeDefinition", b"B", vec![])),
        ],
        AnalysisOptions::default(),
        true,
        1024 * 1024,
    )
    .unwrap();

    assert_eq!(analysis.offset_bits, 24);
    assert_eq!(analysis.observed_lower_bound, (1 << 24) + 4);
    assert_eq!(
        analysis.limit_status,
        LimitStatus::OverByAtLeast {
            limit: (1 << 24) - 1,
            observed_lower_bound: (1 << 24) + 4,
            bytes: 5,
        }
    );
}

#[test]
fn streaming_analysis_joins_namespace_segments_without_reprefixing_type_names() {
    let analysis = analyze_stream(
        vec![
            Ok(raw(0, b"ScopeDefinition", b"A", vec![10])),
            Ok(raw(10, b"NamespaceDefinition", b"", vec![20])),
            Ok(raw(20, b"NamespaceDefinition", b"System", vec![30])),
            Ok(raw(30, b"TypeDefinition", b"System.String", vec![40])),
            Ok(raw(40, b"Method", b"M", vec![])),
        ],
        AnalysisOptions::default(),
        true,
        1024 * 1024,
    )
    .unwrap();

    assert!(
        analysis
            .by_namespace
            .iter()
            .any(|entry| entry.name == "System")
    );
    assert!(
        analysis
            .by_type
            .iter()
            .any(|entry| entry.name == "A!System.String")
    );
    assert!(
        analysis
            .by_type
            .iter()
            .all(|entry| !entry.name.contains("System.System"))
    );
}

#[test]
fn comparison_reports_added_removed_changed_and_reconciles_total_delta() {
    let before = vec![
        Aggregate {
            name: "removed".into(),
            bytes: 7,
            records: 1,
        },
        Aggregate {
            name: "changed".into(),
            bytes: 10,
            records: 1,
        },
        Aggregate {
            name: "same".into(),
            bytes: 3,
            records: 1,
        },
    ];
    let after = vec![
        Aggregate {
            name: "added".into(),
            bytes: 11,
            records: 1,
        },
        Aggregate {
            name: "changed".into(),
            bytes: 4,
            records: 1,
        },
        Aggregate {
            name: "same".into(),
            bytes: 3,
            records: 1,
        },
    ];
    let comparison = compare(&before, &after);
    assert_eq!(comparison.total_delta, -2);
    assert_eq!(
        comparison
            .entries
            .iter()
            .map(|entry| entry.delta_bytes)
            .sum::<i128>(),
        comparison.total_delta
    );
    assert!(
        comparison
            .entries
            .iter()
            .any(|entry| entry.name == "added" && entry.delta_bytes == 11)
    );
    assert!(
        comparison
            .entries
            .iter()
            .any(|entry| entry.name == "removed" && entry.delta_bytes == -7)
    );
    assert!(
        comparison
            .entries
            .iter()
            .any(|entry| entry.name == "changed" && entry.delta_bytes == -6)
    );
    assert!(
        comparison
            .entries
            .iter()
            .any(|entry| entry.name == "same" && entry.delta_bytes == 0)
    );
}

proptest! {
    #[test]
    fn comparison_reconciliation_always_balances(
        before in prop::collection::btree_map("[a-z]{1,8}", any::<u64>(), 0..30),
        after in prop::collection::btree_map("[a-z]{1,8}", any::<u64>(), 0..30),
    ) {
        let aggregates = |values: &std::collections::BTreeMap<String, u64>| {
            values.iter().map(|(name, bytes)| Aggregate {
                name: name.clone(),
                bytes: *bytes,
                records: 1,
            }).collect::<Vec<_>>()
        };
        let comparison = compare(&aggregates(&before), &aggregates(&after));
        let expected = after.values().map(|value| i128::from(*value)).sum::<i128>()
            - before.values().map(|value| i128::from(*value)).sum::<i128>();
        prop_assert_eq!(comparison.total_delta, expected);
        prop_assert_eq!(
            comparison.entries.iter().map(|entry| entry.delta_bytes).sum::<i128>(),
            expected
        );
    }

    #[test]
    fn top_n_order_is_deterministic_for_arbitrary_inputs(
        values in prop::collection::btree_map("[ -~]{1,12}", any::<u32>(), 0..100),
        limit in 0_usize..100,
    ) {
        let aggregates = values.into_iter().map(|(name, bytes)| Aggregate {
            name,
            bytes: u64::from(bytes),
            records: 1,
        }).collect::<Vec<_>>();
        let first = top_n(aggregates.clone(), limit);
        let second = top_n(aggregates, limit);
        prop_assert_eq!(&first, &second);
        let sorted = first.windows(2).all(|pair| {
            pair[0].bytes > pair[1].bytes
                || (pair[0].bytes == pair[1].bytes && pair[0].name.as_bytes() <= pair[1].name.as_bytes())
        });
        prop_assert!(sorted);
    }
}
