use super::*;
use clap::Parser;
use vitnet_mstat::{
    CohortInsight, GenericFamily, InsightCounts, MethodBreakdown, MethodInsightEntry, ResourceGroup,
};

fn counts(bytes: u64) -> InsightCounts {
    InsightCounts {
        bytes,
        identities: 1,
        records: 1,
    }
}

#[test]
fn accounting_ranks_additive_streams_and_keeps_overlaps_separate() {
    let categories: Vec<_> = [
        ("Methods", 300),
        ("Types", 200),
        ("Blobs", 500),
        ("ManifestResources", 150),
    ]
    .into_iter()
    .map(|(name, bytes)| CategorySummary {
        name: name.into(),
        records: 1,
        items: 0,
        aggregate_size_bytes: bytes,
        encoded_bytes: 1,
    })
    .collect();
    let report = accounting(&categories, 1000);
    assert_eq!(
        report
            .additive_streams
            .iter()
            .map(|row| row.name)
            .collect::<Vec<_>>(),
        ["Blobs", "Methods", "Types"]
    );
    assert_eq!(
        report
            .additive_streams
            .iter()
            .map(|row| row.bytes)
            .sum::<u64>(),
        1000
    );
    assert_eq!(report.overlapping_streams[0].share_basis_points, Some(1500));
    assert_eq!(basis_points(0, 0), None);
    assert_eq!(basis_points(u64::MAX, u64::MAX), Some(10_000));
}

fn methods() -> MethodsInsightReport {
    let entry =
        |name: &str, bytes, body_bytes, gc_info_bytes, exception_info_bytes| MethodInsightEntry {
            identity: name.into(),
            identity_bytes: name.len() as u64,
            truncated: false,
            bytes,
            records: 1,
            body_bytes,
            gc_info_bytes,
            exception_info_bytes,
            accounted_basis_points: 0,
        };
    let total = InsightCounts {
        bytes: 1000,
        identities: 200,
        records: 200,
    };
    let components = MethodBreakdown {
        body_bytes: 800,
        gc_info_bytes: 190,
        exception_info_bytes: 10,
    };
    MethodsInsightReport {
        accounted_denominator_bytes: 2000,
        total,
        matched: total,
        total_components: components.clone(),
        matched_components: components,
        top_components: MethodBreakdown {
            body_bytes: 54,
            gc_info_bytes: 46,
            exception_info_bytes: 10,
        },
        omitted_components: MethodBreakdown {
            body_bytes: 746,
            gc_info_bytes: 144,
            exception_info_bytes: 0,
        },
        top_bytes: 110,
        omitted_bytes: 890,
        entries: vec![
            entry("large", 100, 50, 40, 10),
            entry("small", 10, 4, 6, 0),
            entry("zero", 0, 0, 0, 0),
        ],
        size_bands: vec![vitnet_mstat::MethodSizeBand {
            minimum_bytes: 1,
            maximum_bytes: Some(255),
            total,
            matched: total,
        }],
    }
}

#[test]
fn method_costs_use_global_components_and_rerank_only_visible_ratios() {
    let source = methods();
    let report = method_costs(&source);
    assert_eq!(
        report
            .global_components
            .iter()
            .map(|row| row.share_basis_points)
            .collect::<Vec<_>>(),
        [Some(8000), Some(1900), Some(100)]
    );
    assert_eq!(
        report
            .visible_high_auxiliary_ratio
            .iter()
            .map(|row| row.identity)
            .collect::<Vec<_>>(),
        ["small", "large", "zero"]
    );
    assert_eq!(report.visible_high_auxiliary_ratio[0].auxiliary_bytes, 6);
    assert_eq!(
        report.visible_high_auxiliary_ratio[0].auxiliary_share_basis_points,
        Some(6000)
    );
    assert_eq!(
        report.visible_high_auxiliary_ratio[2].auxiliary_share_basis_points,
        None
    );
    assert!(report.ranking_scope.contains("not a global"));
}

#[test]
fn metadata_attribution_keeps_unowned_and_type_bytes_without_double_counting() {
    let report = metadata_attribution(
        1000,
        &Concentration {
            total_bytes: 600,
            ..Default::default()
        },
        &Concentration {
            total_bytes: 400,
            ..Default::default()
        },
    );
    assert_eq!(report.type_attributed_bytes + report.unowned_bytes, 1000);
    assert_eq!(report.type_attributed_share_basis_points, Some(6000));
    assert_eq!(
        metadata_attribution(0, &Concentration::default(), &Concentration::default())
            .type_attributed_share_basis_points,
        None
    );
}

#[test]
fn list_coverage_marks_omitted_zero_byte_groups_and_exact_remainders() {
    let report = coverage("types", 200, 50, 10, 2);
    assert_eq!(report.omitted_bytes, 150);
    assert_eq!(report.shown_share_basis_points, Some(2500));
    assert!(!report.all_groups_shown);
    let zero = coverage("zero", 0, 0, 3, 1);
    assert_eq!(zero.shown_share_basis_points, None);
    assert!(!zero.all_groups_shown);
    assert!(coverage("empty", 0, 0, 0, 0).all_groups_shown);
}

fn cultures() -> ResourceGroupList<String> {
    ResourceGroupList {
        total: counts(100),
        matched: counts(100),
        total_groups: 3,
        matched_groups: 3,
        top_bytes: 80,
        omitted_bytes: 20,
        groups: [("", 70), ("fr", 10)]
            .into_iter()
            .map(|(key, bytes)| ResourceGroup {
                key: key.into(),
                total: counts(bytes),
                matched: counts(bytes),
                top_bytes: 0,
                omitted_bytes: bytes,
                entries: vec![],
            })
            .collect(),
    }
}

#[test]
fn culture_mix_distinguishes_unknown_neutral_absence_from_complete_zero() {
    let mut source = cultures();
    let report = culture_mix(&source);
    assert_eq!(report.neutral_culture_bytes, Some(70));
    assert_eq!(report.non_neutral_culture_bytes, Some(30));
    assert_eq!(report.omitted_culture_bytes, 20);
    source.groups.remove(0);
    assert_eq!(culture_mix(&source).neutral_culture_bytes, None);
    source.matched_groups = 1;
    source.matched.bytes = 10;
    source.omitted_bytes = 0;
    assert_eq!(culture_mix(&source).neutral_culture_bytes, Some(0));
    assert_eq!(culture_mix(&source).non_neutral_culture_bytes, Some(10));
}

fn cohorts() -> CohortsInsightReport {
    CohortsInsightReport {
        warning: "overlap".into(),
        accounted_denominator_bytes: 200,
        union_accounted: counts(100),
        union_non_accounted: InsightCounts::default(),
        multiply_matched_accounted: counts(100),
        multiply_matched_non_accounted: InsightCounts::default(),
        union_sections: [
            ("Methods", counts(100)),
            ("Types", InsightCounts::default()),
            ("Blobs", InsightCounts::default()),
        ]
        .into_iter()
        .map(|(stream, matched)| vitnet_mstat::CohortStreamCounts {
            stream: stream.into(),
            accounted: true,
            matched,
        })
        .collect(),
        cohorts: ["a", "b", "c"]
            .into_iter()
            .map(|name| CohortInsight {
                name: name.into(),
                accounted: counts(100),
                non_accounted: InsightCounts::default(),
                sections: vec![],
                examples: vec![],
            })
            .collect(),
        intersections: vec![],
    }
}

#[test]
fn cohort_overlap_distinguishes_triple_membership_from_once_counted_overlap() {
    let mut source = cohorts();
    let report = cohort_overlap(&source);
    assert_eq!(report.summed_membership_bytes, 300);
    assert_eq!(report.duplicated_membership_bytes, 200);
    assert_eq!(report.multiply_matched_bytes, 100);
    assert_eq!(
        report.membership_amplification_basis_points.as_deref(),
        Some("30000")
    );
    source.union_accounted.bytes = u64::MAX;
    for cohort in &mut source.cohorts {
        cohort.accounted.bytes = u64::MAX;
    }
    let json = serde_json::to_value(cohort_overlap(&source)).unwrap();
    assert_eq!(
        json["summed_membership_bytes"],
        (u128::from(u64::MAX) * 3).to_string()
    );
}

#[test]
fn rule_gaps_count_zero_byte_hits_and_separate_resource_only_predicates() {
    let mut source = cohorts();
    source.cohorts[0].accounted = counts(0);
    source.cohorts[1].accounted = InsightCounts::default();
    source.cohorts[1].non_accounted = counts(10);
    source.cohorts[2].accounted = InsightCounts::default();
    source.cohorts.push(CohortInsight {
        name: "d".into(),
        accounted: counts(100),
        non_accounted: InsightCounts::default(),
        sections: vec![],
        examples: vec![],
    });
    source.union_accounted = InsightCounts {
        bytes: 100,
        identities: 2,
        records: 2,
    };
    source.union_non_accounted = counts(10);
    source.multiply_matched_accounted = InsightCounts::default();
    let report = rule_gaps(&source);
    assert_eq!(report.unmatched_accounted_bytes, 100);
    assert_eq!(report.covered_share_basis_points, Some(5000));
    assert_eq!(report.zero_hit_rules, ["c"]);
    assert_eq!(report.no_accounted_match_rules, ["b", "c"]);
}

#[test]
fn visible_family_density_uses_exact_fraction_order_and_bounded_previews() {
    let mut source = GenericStreamReport {
        stream: "Types".into(),
        total: counts(230),
        generic_shaped: counts(230),
        non_generic_shaped: InsightCounts::default(),
        matched_generic_shaped: counts(230),
        total_families: 3,
        matched_families: 3,
        top_bytes: 230,
        omitted_bytes: 0,
        families: vec![],
    };
    for (name, bytes, identities) in [("lower", 111, 10), ("higher", 119, 10), ("unknown", 0, 0)] {
        source.families.push(GenericFamily {
            prefix: format!("{name}{}", "x".repeat(300)),
            total: counts(bytes),
            matched: InsightCounts {
                bytes,
                identities,
                records: identities,
            },
            top_bytes: 0,
            omitted_bytes: bytes,
            examples: vec![],
        });
    }
    let report = family_density(&[source]);
    assert!(report[0].family.text.starts_with("higher"));
    assert_eq!(report[0].bytes_per_identity, Some(11));
    assert!(report[1].family.text.starts_with("lower"));
    assert!(report[0].family.truncated);
    assert_eq!(report[0].family.text.len(), 256);
    assert_eq!(report[2].bytes_per_identity, None);
    assert!(report[0].ranking_scope.contains("not a global"));
}

#[test]
fn contributor_followups_are_literal_argv_and_omit_unusable_filter_hints() {
    let input = Path::new("-input file.mstat");
    let action = || FollowUp {
        commands: &["mstat", "methods"],
        input,
        top: 20,
        filter: "contains",
    };
    let row = contributor("-name with spaces", false, 10, 100, action());
    assert_eq!(
        row.follow_up_argv,
        [
            "vitnet",
            "mstat",
            "methods",
            "--top=100",
            "--contains=-name with spaces",
            "--",
            "-input file.mstat"
        ]
    );
    assert_eq!(row.share_basis_points, Some(1000));
    crate::Cli::try_parse_from(&row.follow_up_argv).unwrap();
    for (name, truncated) in [("short", true), ("", false), ("nul\0name", false)] {
        let row = contributor(name, truncated, 0, 0, action());
        assert!(!row.filter_hint_available);
        assert_eq!(row.follow_up_argv.len(), 6);
    }
}

#[test]
fn graph_context_is_empty_without_indexes_and_never_claims_a_join() {
    assert_eq!(graph_context(&[]).len(), 0);
    let graph: vitnet_dgml::DgmlCacheInfo = serde_json::from_value(serde_json::json!({
        "schema":"vitnet.dgml-cache-info.v1", "index_directory":"generic-index", "generation":"g",
        "index_bytes":100, "manifest":{
            "schema":"vitnet.dgml-index.v1","vitnet_version":"test","canonical_input_path":"graph.xml",
            "input_length":10,"input_modified_unix_ns":0,"prefix_suffix_fingerprint":"test",
            "full_content_hash":null,"selected_entry":null,"node_count":3,"edge_count":4,"max_node_id":9,
            "duplicate_node_ids":0,"unresolved_endpoints":1,"features":{"incoming_edges":true,"outgoing_edges":false,"label_fst":false},
            "created_unix_ns":0,"complete":true
        }
    })).unwrap();
    let graphs = [graph];
    let report = graph_context(&graphs);
    assert_eq!(report[0].numeric_slots, 10);
    assert_eq!(
        report[0].declared_slot_share_basis_points.as_deref(),
        Some("3000")
    );
    assert_eq!(report[0].unresolved_endpoints, 1);
    assert!(
        report[0]
            .query_argv
            .iter()
            .any(|arg| arg == "--generation=g")
    );
    assert!(report[0].interpretation.contains("no graph query"));
    assert!(report[0].interpretation.contains("guaranteed symbol join"));
    crate::Cli::try_parse_from(&report[0].query_argv).unwrap();
}

#[allow(clippy::too_many_lines)]
pub(super) fn report_fixture() -> (BloatReport, BloatArgs) {
    let methods = methods();
    let mut cohort_report = cohorts();
    cohort_report.accounted_denominator_bytes = 2000;
    let resources = |key| ResourceGroupList {
        total: InsightCounts::default(),
        matched: InsightCounts::default(),
        total_groups: 0,
        matched_groups: 0,
        top_bytes: 0,
        omitted_bytes: 0,
        groups: key,
    };
    let source = vitnet_mstat::MstatInsights {
        schema: "vitnet.mstat-insights.v1".into(),
        summary: vitnet_mstat::MstatSummary {
            schema: "vitnet.mstat-summary.v1".into(),
            format_version: vitnet_mstat::FormatVersion { major: 2, minor: 2 },
            assembly: "generic".into(),
            input_bytes: 100,
            accounted_size_bytes: 2000,
            mangled_names_bytes: 20,
            categories: [("Methods", 1000), ("Types", 200), ("Blobs", 800)]
                .into_iter()
                .map(|(name, bytes)| CategorySummary {
                    name: name.into(),
                    records: 200,
                    items: 0,
                    aggregate_size_bytes: bytes,
                    encoded_bytes: 1,
                })
                .collect(),
            methods: methods.total_components.clone(),
            frozen_objects: vitnet_mstat::FrozenBreakdown::default(),
            deduplicated_methods: vitnet_mstat::DeduplicationSummary::default(),
            peak_tracked_memory_bytes: 65536,
        },
        metadata_blob_bytes: 0,
        metadata_blob_records: 0,
        methods,
        resources: vitnet_mstat::ResourcesInsightReport {
            accounted: false,
            warning: "overlapping".into(),
            by_assembly: vitnet_mstat::ResourceGroupList {
                total: InsightCounts::default(),
                matched: InsightCounts::default(),
                total_groups: 0,
                matched_groups: 0,
                top_bytes: 0,
                omitted_bytes: 0,
                groups: vec![],
            },
            by_culture: resources(Vec::<ResourceGroup<String>>::new()),
            by_resource_name: resources(Vec::<ResourceGroup<String>>::new()),
        },
        generics: vitnet_mstat::GenericsInsightReport {
            caveat: "literal".into(),
            sections: [("Methods", 1000), ("Types", 200)]
                .into_iter()
                .map(|(name, bytes)| GenericStreamReport {
                    stream: name.into(),
                    total: counts(bytes),
                    generic_shaped: InsightCounts::default(),
                    non_generic_shaped: counts(bytes),
                    matched_generic_shaped: InsightCounts::default(),
                    total_families: 0,
                    matched_families: 0,
                    top_bytes: 0,
                    omitted_bytes: 0,
                    families: vec![],
                })
                .collect(),
        },
        cohorts: cohort_report,
        blobs: vitnet_mstat::BlobInsightReport {
            total: counts(800),
            matched: counts(800),
            omitted_bytes: 800,
            ..vitnet_mstat::BlobInsightReport::default()
        },
    };
    let metadata = vitnet_report::MetadataEnvelope::new(
        "test",
        vitnet_report::InputDescriptor {
            path: Some("input.csv".into()),
            bytes_read: 0,
        },
        vitnet_metadata::analyze(&[], &vitnet_metadata::AnalysisOptions::default()),
        vec![],
    );
    let report = BloatReport {
        schema: "vitnet.bloat.v1",
        metadata,
        mstat: source,
        rules: ["a", "b", "c"]
            .into_iter()
            .map(|name| CohortRule {
                name: name.into(),
                contains: vec!["literal".into()],
                stream: None,
            })
            .collect(),
        graph_generations: vec![],
        reconciliation: Reconciliation {
            metadata_csv_lower_bound_bytes: 0,
            mstat_metadata_blob_bytes: None,
            metadata_blob_records: 0,
            blob_minus_lower_bound_bytes: None,
            caveat: "observed only",
        },
        caveats: ["accounting", "cohorts", "metadata", "graphs"],
    };
    let args = BloatArgs {
        brief: true,
        metadata: "input.csv".into(),
        mstat: "input.mstat".into(),
        rules: None,
        top: 20,
        scan_index: None,
        codegen_index: None,
    };
    (report, args)
}

#[test]
fn brief_preserves_null_reconciliation_inputs_and_all_output_formats() {
    let (report, args) = report_fixture();
    let brief = build(&report, &args).unwrap();
    let json = serde_json::to_value(&brief).unwrap();
    assert_eq!(json["schema"], "vitnet.bloat-brief.v1");
    assert_eq!(
        json["inputs"],
        serde_json::json!(["input.csv", "input.mstat"])
    );
    assert_eq!(
        json["reconciliation"]["mstat_metadata_blob_bytes"],
        serde_json::Value::Null
    );
    assert_eq!(json["rule_gaps"]["unmatched_accounted_bytes"], 1900);
    assert_eq!(json["list_coverage"].as_array().unwrap().len(), 11);
    assert_eq!(
        json["contributor_next_steps"][0]["candidates"][0]["name"]["text"],
        "Methods"
    );
    for group in &brief.contributor_next_steps {
        for row in &group.candidates {
            crate::Cli::try_parse_from(&row.follow_up_argv).unwrap();
        }
    }
    for format in [
        crate::FormatArg::Json,
        crate::FormatArg::Ndjson,
        crate::FormatArg::Table,
    ] {
        let output = super::super::render(format, &brief).unwrap();
        assert!(output.contains("vitnet.bloat-brief.v1"));
        if matches!(format, crate::FormatArg::Ndjson) {
            assert_eq!(output.lines().count(), 1);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap(),
                json
            );
        }
    }
}

#[test]
fn brief_rejects_missing_concentration_instead_of_fabricating_coverage() {
    let (mut report, args) = report_fixture();
    report.metadata.sections.concentration.remove("by_type");
    let Err(error) = build(&report, &args) else {
        panic!("missing concentration accepted")
    };
    assert!(error.to_string().contains("bloat.brief.invariant"));
}

#[test]
fn brief_rejects_inconsistent_overlapping_stream_shares_without_panicking() {
    let (mut report, args) = report_fixture();
    report.mstat.summary.categories.push(CategorySummary {
        name: "ManifestResources".into(),
        records: 1,
        items: 0,
        aggregate_size_bytes: u64::MAX,
        encoded_bytes: 1,
    });
    let Err(error) = build(&report, &args) else {
        panic!("inconsistent stream accepted")
    };
    assert_eq!(error.exit_code(), vitnet_core::ExitCode::MalformedInput);
    assert!(
        error
            .to_string()
            .contains("ManifestResources reported byte count exceeds")
    );
    assert!(error.to_string().contains("bloat.brief.invariant"));
}
