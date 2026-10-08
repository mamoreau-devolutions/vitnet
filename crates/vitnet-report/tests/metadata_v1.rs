use vitnet_metadata::{AnalysisOptions, MetadataRecord, analyze};
use vitnet_report::{
    InputDescriptor, METADATA_COMPARISON_SCHEMA_V1, METADATA_SCHEMA_V1, MetadataComparisonEnvelope,
    MetadataEnvelope,
};

#[test]
fn metadata_v1_json_has_versioned_shape_and_integer_byte_counts() {
    let records = vec![
        MetadataRecord {
            logical_offset: 0,
            kind: b"Type".to_vec(),
            name: b"T".to_vec(),
            assembly: Some(b"A".to_vec()),
            namespace: Some(b"N".to_vec()),
            type_name: Some(b"T".to_vec()),
            is_string: false,
        },
        MetadataRecord {
            logical_offset: 42,
            kind: b"String".to_vec(),
            name: b"value".to_vec(),
            assembly: Some(b"A".to_vec()),
            namespace: Some(b"N".to_vec()),
            type_name: Some(b"T".to_vec()),
            is_string: true,
        },
    ];
    let envelope = MetadataEnvelope::new(
        "0.1.0",
        InputDescriptor {
            path: Some("sample.csv".into()),
            bytes_read: 123,
        },
        analyze(&records, &AnalysisOptions::default()),
        vec![],
    );
    let json = serde_json::to_value(&envelope).unwrap();

    assert_eq!(METADATA_SCHEMA_V1, "vitnet.metadata.v1");
    assert_eq!(json["schema"], "vitnet.metadata.v1");
    assert_eq!(json["tool_version"], "0.1.0");
    assert_eq!(json["input"]["path"], "sample.csv");
    assert_eq!(json["input"]["bytes_read"], 123);
    assert_eq!(json["summary"]["metadata_lower_bound_bytes"], 42);
    assert!(json["summary"]["metadata_lower_bound_bytes"].is_u64());
    assert_eq!(json["summary"]["record_count"], 2);
    assert_eq!(json["summary"]["total_is_lower_bound"], true);
    assert_eq!(json["summary"]["final_record_size_known"], false);
    assert!(json["sections"]["by_kind"].is_array());
    assert!(json["sections"]["by_assembly"].is_array());
    assert!(json["sections"]["by_namespace"].is_array());
    assert!(json["sections"]["by_type"].is_array());
    assert!(json["sections"]["largest_strings"].is_array());
    assert!(json["sections"]["unowned"].is_array());
    assert_eq!(json["diagnostics"], serde_json::json!([]));
}

#[test]
fn metadata_v1_serialization_is_deterministic() {
    let analysis = analyze(&[], &AnalysisOptions::default());
    let envelope = MetadataEnvelope::new(
        "0.1.0",
        InputDescriptor {
            path: None,
            bytes_read: 0,
        },
        analysis,
        vec![],
    );
    assert_eq!(envelope.to_json().unwrap(), envelope.to_json().unwrap());
}

#[test]
fn comparison_v1_is_versioned_signed_reconciled_and_truncatable() {
    let envelope = |offset, path: &str| {
        MetadataEnvelope::new(
            "0.1.0",
            InputDescriptor {
                path: Some(path.into()),
                bytes_read: offset,
            },
            analyze(
                &[
                    MetadataRecord {
                        logical_offset: 0,
                        kind: b"Type".to_vec(),
                        name: b"T".to_vec(),
                        assembly: Some(b"A".to_vec()),
                        namespace: Some(b"N".to_vec()),
                        type_name: Some(b"T".to_vec()),
                        is_string: false,
                    },
                    MetadataRecord {
                        logical_offset: offset,
                        kind: b"String".to_vec(),
                        name: b"value".to_vec(),
                        assembly: Some(b"A".to_vec()),
                        namespace: Some(b"N".to_vec()),
                        type_name: Some(b"T".to_vec()),
                        is_string: true,
                    },
                ],
                &AnalysisOptions::default(),
            ),
            vec![],
        )
    };
    let before = envelope(10, "before.csv");
    let after = envelope(15, "after.csv");
    let mut comparison = MetadataComparisonEnvelope::new("0.1.0", &before, &after);

    assert_eq!(
        METADATA_COMPARISON_SCHEMA_V1,
        "vitnet.metadata-comparison.v1"
    );
    assert_eq!(comparison.schema, METADATA_COMPARISON_SCHEMA_V1);
    assert_eq!(comparison.summary.delta_bytes, 5);
    assert_eq!(comparison.sections.by_kind.total_delta, 5);
    assert_eq!(comparison.sections.by_assembly.total_delta, 5);
    assert_eq!(comparison.sections.by_namespace.total_delta, 5);
    assert_eq!(comparison.sections.by_type.total_delta, 5);
    assert_eq!(comparison.sections.unowned.total_delta, 0);

    comparison.truncate(0);
    assert_eq!(
        comparison.sections.by_kind.entries,
        [] as [vitnet_metadata::ComparisonEntry; 0]
    );
    assert_eq!(comparison.sections.by_kind.total_delta, 5);
}
