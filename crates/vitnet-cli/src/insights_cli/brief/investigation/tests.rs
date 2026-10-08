use super::super::tests::report_fixture;
use super::*;
use serde_json::{Value, json};
use vitnet_metadata::{Aggregate, Concentration};
use vitnet_mstat::{
    BlobInsightReport, CategorySummary, CohortInsight, CohortIntersection, CohortRule,
    CohortStreamCounts, GenericFamily, MethodBreakdown, ResourceAssemblyKey, ResourceGroup,
    ResourceGroupList,
};

fn counts(bytes: u64, identities: u64, records: u64) -> InsightCounts {
    InsightCounts {
        bytes,
        identities,
        records,
    }
}

fn entry(identity: &str, bytes: u64, records: u64) -> IdentityInsightEntry {
    IdentityInsightEntry {
        identity: identity.into(),
        identity_bytes: identity.len() as u64,
        truncated: false,
        bytes,
        records,
    }
}

fn group<K>(
    key: K,
    matched: InsightCounts,
    entries: Vec<IdentityInsightEntry>,
) -> ResourceGroup<K> {
    let top_bytes = entries.iter().map(|item| item.bytes).sum();
    ResourceGroup {
        key,
        total: matched,
        matched,
        top_bytes,
        omitted_bytes: matched.bytes - top_bytes,
        entries,
    }
}

fn list<K>(groups: Vec<ResourceGroup<K>>) -> ResourceGroupList<K> {
    let matched = groups
        .iter()
        .fold(InsightCounts::default(), |mut sum, row| {
            sum.bytes += row.matched.bytes;
            sum.identities += row.matched.identities;
            sum.records += row.matched.records;
            sum
        });
    ResourceGroupList {
        total: matched,
        matched,
        total_groups: groups.len() as u64,
        matched_groups: groups.len() as u64,
        top_bytes: matched.bytes,
        omitted_bytes: 0,
        groups,
    }
}

fn assembly_group(name: &str, culture: &str, bytes: u64) -> ResourceGroup<ResourceAssemblyKey> {
    group(
        ResourceAssemblyKey {
            name: name.into(),
            culture: culture.into(),
        },
        counts(bytes, 1, 2),
        vec![],
    )
}

fn cohort(name: &str, accounted: InsightCounts) -> CohortInsight {
    CohortInsight {
        name: name.into(),
        accounted,
        non_accounted: InsightCounts::default(),
        sections: vec![],
        examples: vec![],
    }
}

fn pair(left: usize, right: usize, bytes: u64) -> CohortIntersection {
    CohortIntersection {
        left,
        right,
        accounted: counts(bytes, 1, 2),
        non_accounted: InsightCounts::default(),
    }
}

fn rule(name: &str, contains: &[&str], stream: Option<&str>) -> CohortRule {
    CohortRule {
        name: name.into(),
        contains: contains.iter().map(|pattern| (*pattern).into()).collect(),
        stream: stream.map(str::to_owned),
    }
}

const STREAMS: [&str; 7] = [
    "Methods",
    "Types",
    "Blobs",
    "RvaFields",
    "FrozenObjects",
    "ManifestResources",
    "DeduplicatedMethods",
];

fn streams(report: &mut BloatReport, totals: [u64; 7], union: [InsightCounts; 7]) {
    report.mstat.summary.categories = STREAMS
        .into_iter()
        .zip(totals)
        .map(|(name, bytes)| CategorySummary {
            name: name.into(),
            records: 4,
            items: 0,
            aggregate_size_bytes: bytes,
            encoded_bytes: 1,
        })
        .collect();
    report.mstat.summary.accounted_size_bytes = totals[..3].iter().sum();
    report.mstat.cohorts.accounted_denominator_bytes = totals[..3].iter().sum();
    report.mstat.cohorts.union_sections = STREAMS
        .into_iter()
        .zip(union)
        .enumerate()
        .map(|(index, (stream, matched))| CohortStreamCounts {
            stream: stream.into(),
            accounted: index < 3,
            matched,
        })
        .collect();
    let sum = |rows: &[InsightCounts]| {
        rows.iter()
            .fold(InsightCounts::default(), |mut total, row| {
                total.bytes += row.bytes;
                total.identities += row.identities;
                total.records += row.records;
                total
            })
    };
    report.mstat.cohorts.union_accounted = sum(&union[..3]);
    report.mstat.cohorts.union_non_accounted = sum(&union[3..]);
}

fn assert_invariant(error: AppError, message: &str) {
    match error {
        AppError::Unsupported(diagnostic) => {
            assert_eq!(diagnostic.code, "bloat.brief.invariant");
            assert_eq!(diagnostic.message, message);
        }
        other => panic!("expected investigation invariant, got {other:?}"),
    }
}

fn prefixes(rows: &[CoverageTarget]) -> Vec<Option<usize>> {
    rows.iter()
        .map(|row| row.required_displayed_prefix)
        .collect()
}

fn assert_null_field(object: &Value, field: &str) {
    assert_eq!(
        object.get(field),
        Some(&Value::Null),
        "{field} must be present and explicitly unknown"
    );
}

#[test]
fn accounting_limits_uses_exact_dehydration_and_logical_accounting() {
    let (mut report, mut args) = report_fixture();
    args.top = 0;
    report.mstat.blobs.entries = vec![entry("DehydratedData.lookalike", 7, 1)];
    for (evidence, expected) in [
        (InsightCounts::default(), false),
        (counts(0, 1, 2), true),
        (counts(70, 1, 3), true),
    ] {
        report.mstat.blobs.dehydrated_data = evidence;
        let result = accounting_limits(&report);
        assert_eq!(result.dehydration_observed, expected);
        assert_eq!(result.dehydrated_data_bytes, evidence.bytes);
        assert_eq!(result.dehydrated_data_records, evidence.records);
        assert_eq!(result.physical_binary_bytes, None);
        assert!(result.interpretation.contains("not executable file size"));
        assert!(result.interpretation.contains("logical hydration targets"));
        assert!(result.interpretation.contains("do not sum"));
        assert!(result.interpretation.contains("or recommend disabling"));
        assert!(result.interpretation.contains("Absence does not prove"));
        let output = serde_json::to_value(build(&report, &args).unwrap()).unwrap();
        assert_eq!(
            output["accounting_limits"]["dehydration_observed"],
            expected
        );
        assert_null_field(&output["accounting_limits"], "physical_binary_bytes");
    }
}

#[test]
fn blob_buckets_preserve_bounded_identity_and_coverage_evidence() {
    let (mut report, _) = report_fixture();
    let mut first = entry("same bounded preview", 50, 2);
    first.identity_bytes = 301;
    first.truncated = true;
    let mut second = first.clone();
    second.identity_bytes = 302;
    second.records = 1;
    let all = [first, second, entry("zero-tail", 0, 2)];
    report.mstat.blobs.total = counts(500, 5, 9);
    report.mstat.blobs.matched = counts(100, 3, 5);
    for top in 0..=4 {
        report.mstat.blobs.entries = all.iter().take(top).cloned().collect();
        report.mstat.blobs.top_bytes = [0, 50, 100, 100, 100][top];
        report.mstat.blobs.omitted_bytes = 100 - report.mstat.blobs.top_bytes;
        let result = blob_buckets(&report);
        assert_eq!(result.total, counts(500, 5, 9));
        assert_eq!(result.matched, counts(100, 3, 5));
        assert_eq!(result.entries, &all[..top.min(3)]);
        assert_eq!(result.shown_bytes + result.omitted_bytes, 100);
        assert_eq!(
            result.shown_share_basis_points,
            Some([0, 5000, 10_000, 10_000, 10_000][top])
        );
        let output = serde_json::to_value(&result).unwrap();
        if top >= 2 {
            assert_eq!(output["entries"].as_array().unwrap().len(), top.min(3));
            assert_eq!(output["entries"][0]["identity_bytes"], 301);
            assert_eq!(output["entries"][1]["identity_bytes"], 302);
            assert_eq!(output["entries"][0]["truncated"], true);
        }
        assert!(result.interpretation.contains("not package ownership"));
        assert!(result.interpretation.contains("not physical savings"));
    }
    // No byte tail does not prove the zero-byte third identity was displayed.
    report.mstat.blobs.entries.truncate(2);
    assert_eq!(blob_buckets(&report).entries.len(), 2);
    assert_eq!(blob_buckets(&report).matched.identities, 3);
    report.mstat.blobs = BlobInsightReport::default();
    let empty = blob_buckets(&report);
    assert_eq!(empty.total, InsightCounts::default());
    assert_eq!(empty.entries, []);
    assert_eq!(empty.shown_share_basis_points, None);
    report.mstat.blobs.total = counts(7, 1, 2);
    report.mstat.blobs.matched = counts(7, 1, 2);
    report.mstat.blobs.top_bytes = 7;
    report.mstat.blobs.entries = vec![entry("single", 7, 2)];
    assert_eq!(blob_buckets(&report).shown_share_basis_points, Some(10_000));
    assert_eq!(blob_buckets(&report).entries[0].records, 2);
}

#[test]
fn diagnostic_artifact_ratios_keep_units_unknowns_and_wide_values() {
    let (mut report, _) = report_fixture();
    report.mstat.summary.accounted_size_bytes = 777;
    for (names, input, expected) in [
        (200, 100, Some("20000")),
        (0, 100, Some("0")),
        (100, 0, None),
        (0, 0, None),
        (u64::MAX, u64::MAX, Some("10000")),
        (u64::MAX - 1, u64::MAX, Some("9999")),
        (u64::MAX, 1, Some("184467440737095516150000")),
    ] {
        report.mstat.summary.input_bytes = input;
        report.mstat.summary.mangled_names_bytes = names;
        let result = diagnostic_artifacts(&report);
        assert_eq!(result.mstat_input_bytes, input);
        assert_eq!(result.mangled_names_bytes, names);
        assert_eq!(result.names_to_input_basis_points.as_deref(), expected);
        assert_eq!(wide_ratio(names, input).as_deref(), expected);
        let output = serde_json::to_value(&result).unwrap();
        assert_eq!(
            output.get("names_to_input_basis_points"),
            Some(&expected.map_or(Value::Null, |value| json!(value)))
        );
        assert!(
            result
                .interpretation
                .contains("not an additional executable")
        );
        assert!(result.interpretation.contains("not a binary-size share"));
    }
}

fn population(report: &mut BloatReport) {
    report.mstat.methods.size_bands = [
        (0, Some(0), counts(0, 2, 3), counts(0, 1, 2)),
        (1, Some(255), counts(255, 1, 2), counts(255, 1, 2)),
        (256, Some(4095), counts(256, 1, 2), InsightCounts::default()),
        (
            4096,
            Some(65535),
            counts(4096, 1, 1),
            InsightCounts::default(),
        ),
        (65536, None, counts(65536, 1, 1), InsightCounts::default()),
    ]
    .into_iter()
    .map(
        |(minimum_bytes, maximum_bytes, total, matched)| MethodSizeBand {
            minimum_bytes,
            maximum_bytes,
            total,
            matched,
        },
    )
    .collect();
    report.mstat.methods.total = counts(70_143, 6, 9);
    report.mstat.methods.matched = counts(255, 2, 4);
    report.mstat.methods.total_components = MethodBreakdown {
        body_bytes: 70_143,
        gc_info_bytes: 0,
        exception_info_bytes: 0,
    };
    report.mstat.methods.matched_components = MethodBreakdown {
        body_bytes: 255,
        gc_info_bytes: 0,
        exception_info_bytes: 0,
    };
    report.mstat.methods.entries.truncate(1);
    let row = &mut report.mstat.methods.entries[0];
    row.identity = "selected".into();
    row.identity_bytes = 8;
    row.bytes = 255;
    row.body_bytes = 255;
    row.gc_info_bytes = 0;
    row.exception_info_bytes = 0;
    row.records = 2;
    report.mstat.methods.top_bytes = 255;
    report.mstat.methods.omitted_bytes = 0;
    report.mstat.methods.top_components = report.mstat.methods.matched_components.clone();
    report.mstat.methods.omitted_components = MethodBreakdown::default();
    report.mstat.generics.sections[0].total = counts(70_143, 6, 9);
    report.mstat.generics.sections[0].non_generic_shaped = counts(70_143, 6, 9);
    report.mstat.generics.sections[1].total = counts(201, 4, 7);
    report.mstat.generics.sections[1].non_generic_shaped = counts(201, 4, 7);
}

#[test]
fn method_population_uses_full_bands_and_distinguishes_missing_evidence() {
    let (mut report, _) = report_fixture();
    population(&mut report);
    // Types is found by exact stream name, not vector position.
    report.mstat.generics.sections.reverse();
    let original = report.mstat.methods.size_bands.clone();
    for hide in [false, true] {
        if hide {
            report.mstat.methods.entries.clear();
            report.mstat.methods.top_bytes = 0;
            report.mstat.methods.omitted_bytes = 255;
            report.mstat.methods.top_components = MethodBreakdown::default();
            report.mstat.methods.omitted_components =
                report.mstat.methods.matched_components.clone();
        }
        let result = method_population(&report);
        assert_eq!(result.methods.total, counts(70_143, 6, 9));
        assert_eq!(result.methods.bytes_per_identity, Some(11_690));
        assert_eq!(result.methods.bytes_per_record, Some(7793));
        assert_eq!(result.size_bands, original);
        assert_eq!(
            result
                .size_bands
                .iter()
                .map(|band| band.total.bytes)
                .sum::<u64>(),
            70_143
        );
        assert_eq!(
            result
                .size_bands
                .iter()
                .map(|band| band.matched.bytes)
                .sum::<u64>(),
            255
        );
        assert_eq!(
            result
                .size_bands
                .iter()
                .map(|band| (band.minimum_bytes, band.maximum_bytes))
                .collect::<Vec<_>>(),
            [
                (0, Some(0)),
                (1, Some(255)),
                (256, Some(4095)),
                (4096, Some(65535)),
                (65536, None)
            ]
        );
        let types = result.types.unwrap();
        assert_eq!(types.stream, "Types");
        assert_eq!(types.total, counts(201, 4, 7));
        assert_eq!(types.bytes_per_identity, Some(50));
        assert_eq!(types.bytes_per_record, Some(28));
        assert!(result.interpretation.contains("independent of display top"));
        assert!(result.interpretation.contains("not percentiles"));
    }
    // Known empty bands, zero-byte population, and legacy omitted bands are distinct.
    for band in &mut report.mstat.methods.size_bands {
        band.total = InsightCounts::default();
        band.matched = InsightCounts::default();
    }
    report.mstat.methods.total = InsightCounts::default();
    report.mstat.methods.matched = InsightCounts::default();
    let empty = serde_json::to_value(method_population(&report)).unwrap();
    assert_eq!(empty["size_bands"].as_array().unwrap().len(), 5);
    assert_null_field(&empty["methods"], "bytes_per_identity");
    assert_null_field(&empty["methods"], "bytes_per_record");
    report.mstat.methods.total = counts(0, 2, 3);
    report.mstat.methods.matched = counts(0, 2, 3);
    report.mstat.methods.size_bands[0].total = counts(0, 2, 3);
    report.mstat.methods.size_bands[0].matched = counts(0, 2, 3);
    assert_eq!(
        method_population(&report).methods.bytes_per_identity,
        Some(0)
    );
    assert_eq!(method_population(&report).methods.bytes_per_record, Some(0));
    assert_eq!(method_population(&report).size_bands[0].total.records, 3);
    report.mstat.methods.size_bands.clear();
    assert_eq!(method_population(&report).size_bands, []);
    report.mstat.generics.sections.clear();
    assert!(method_population(&report).types.is_none());
}

#[test]
fn resource_culture_assemblies_use_exact_visible_groups_and_completeness() {
    let (mut report, _) = report_fixture();
    report.mstat.resources.by_assembly = list(vec![
        assembly_group("A", "", 30),
        assembly_group("A", "fr", 20),
        assembly_group("A", "FR", 10),
        assembly_group("Literal, Culture=fr", "en", 50),
        assembly_group("B", "fr", 50),
        assembly_group("Zero", "fr", 0),
    ]);
    let expected = ["A", "B", "Literal, Culture=fr", "Zero"];
    for top in 0..=5 {
        let result = resource_cultures(&report, top);
        assert!(result.all_assembly_culture_groups_shown);
        assert_eq!(result.omitted_group_bytes, 0);
        assert_eq!(
            result
                .assemblies
                .iter()
                .map(|row| row.assembly.text.as_str())
                .collect::<Vec<_>>(),
            &expected[..top.min(4)]
        );
        if top > 0 {
            let row = &result.assemblies[0];
            assert_eq!(row.visible_bytes, 60);
            assert_eq!(row.visible_cultures, 3);
            assert_eq!(row.neutral_bytes, Some(30));
            assert_eq!(row.visible_non_neutral_bytes, 30);
        }
        if top >= 2 {
            assert_eq!(result.assemblies[1].neutral_bytes, Some(0));
        }
        assert!(result.interpretation.contains("not global"));
        assert!(result.interpretation.contains("Resources overlap Blobs"));
    }
    let before = serde_json::to_value(resource_cultures(&report, 4)).unwrap();
    report.mstat.resources.by_assembly.groups.reverse();
    assert_eq!(
        serde_json::to_value(resource_cultures(&report, 4)).unwrap(),
        before
    );
    // A hidden zero-byte group still makes the input list incomplete.
    report.mstat.resources.by_assembly.matched_groups += 1;
    report.mstat.resources.by_assembly.total_groups += 1;
    report.mstat.resources.by_assembly.matched.identities += 1;
    report.mstat.resources.by_assembly.total.identities += 1;
    let partial = resource_cultures(&report, 4);
    assert!(!partial.all_assembly_culture_groups_shown);
    assert_eq!(partial.omitted_group_bytes, 0);
    assert_eq!(partial.assemblies[0].neutral_bytes, Some(30));
    assert_eq!(partial.assemblies[1].neutral_bytes, None);
    assert!(
        partial
            .interpretation
            .contains("Hidden neutral culture is unknown")
    );
}

#[test]
fn resource_cultures_distinguish_hidden_neutral_and_empty_zero_evidence() {
    let (mut report, _) = report_fixture();
    report.mstat.resources.by_assembly = list(vec![assembly_group("Only", "fr", 0)]);
    let complete = resource_cultures(&report, 1);
    assert_eq!(complete.assemblies[0].visible_bytes, 0);
    assert_eq!(complete.assemblies[0].visible_cultures, 1);
    assert_eq!(complete.assemblies[0].neutral_bytes, Some(0));
    report.mstat.resources.by_assembly.matched_groups = 2;
    report.mstat.resources.by_assembly.total_groups = 2;
    report.mstat.resources.by_assembly.matched = counts(40, 2, 4);
    report.mstat.resources.by_assembly.total = counts(40, 2, 4);
    report.mstat.resources.by_assembly.omitted_bytes = 40;
    let hidden = resource_cultures(&report, 1);
    assert_eq!(hidden.assemblies[0].neutral_bytes, None);
    assert_eq!(hidden.omitted_group_bytes, 40);
    report.mstat.resources.by_assembly.groups = vec![assembly_group("Only", "", 0)];
    let visible_zero_neutral = resource_cultures(&report, 1);
    assert!(!visible_zero_neutral.all_assembly_culture_groups_shown);
    assert_eq!(visible_zero_neutral.assemblies[0].neutral_bytes, Some(0));
    assert_eq!(visible_zero_neutral.assemblies[0].visible_bytes, 0);
    assert_eq!(
        visible_zero_neutral.assemblies[0].visible_non_neutral_bytes,
        0
    );
    report.mstat.resources.by_assembly = list(vec![]);
    let empty = resource_cultures(&report, 5);
    assert!(empty.assemblies.is_empty());
    assert!(empty.all_assembly_culture_groups_shown);
}

#[test]
fn resource_cultures_group_and_tie_break_on_full_keys_not_preview_collisions() {
    let (mut report, _) = report_fixture();
    let prefix = "x".repeat(256);
    report.mstat.resources.by_assembly = list(vec![
        assembly_group(&format!("{prefix}BB"), "fr", 10),
        assembly_group(&format!("{prefix}A"), "", 10),
    ]);
    let result = resource_cultures(&report, 2);
    assert_eq!(result.assemblies.len(), 2);
    assert_eq!(result.assemblies[0].assembly.text, prefix);
    assert_eq!(result.assemblies[1].assembly.text, prefix);
    assert_eq!(result.assemblies[0].assembly.original_bytes, 257);
    assert_eq!(result.assemblies[1].assembly.original_bytes, 258);
    assert!(
        result.assemblies.iter().all(|row| row.assembly.truncated
            && row.visible_bytes == 10
            && row.visible_cultures == 1)
    );
    assert_eq!(result.assemblies[0].neutral_bytes, Some(10));
    assert_eq!(result.assemblies[1].neutral_bytes, Some(0));
    assert_eq!(result.assemblies[1].visible_non_neutral_bytes, 10);
}

#[test]
fn repeated_resource_names_distinguish_identity_repetition_from_payload_hints() {
    let (mut report, _) = report_fixture();
    for (bytes, examples, expected) in [
        (60, vec![], None),
        (60, vec![entry("AsmA/fr/name", 30, 2)], None),
        (
            60,
            vec![entry("AsmA/fr/name", 30, 2), entry("AsmB/en/name", 30, 1)],
            Some(true),
        ),
        (
            60,
            vec![entry("AsmA/fr/name", 40, 2), entry("AsmB/en/name", 20, 1)],
            Some(false),
        ),
        (
            0,
            vec![entry("AsmA/fr/name", 0, 2), entry("AsmB/en/name", 0, 1)],
            Some(true),
        ),
    ] {
        let visible = examples.len();
        report.mstat.resources.by_resource_name = list(vec![
            group("single identity".into(), counts(100, 1, 3), vec![]),
            group("no identity".into(), InsightCounts::default(), vec![]),
            group("same exact name".into(), counts(bytes, 2, 3), examples),
        ]);
        let result = repeated_names(&report, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource_name.text, "same exact name");
        assert_eq!(result[0].bytes, bytes);
        assert_eq!(result[0].identities, 2);
        assert_eq!(result[0].records, 3);
        assert_eq!(result[0].visible_examples, visible);
        assert_eq!(result[0].visible_equal_lengths, expected);
        assert_eq!(
            serde_json::to_value(&result).unwrap()[0].get("visible_equal_lengths"),
            Some(&expected.map_or(Value::Null, |value| json!(value)))
        );
        assert!(result[0].interpretation.contains("candidate clue"));
        assert!(result[0].interpretation.contains("not content hashes"));
        assert!(
            result[0]
                .interpretation
                .contains("deduplication/savings proof")
        );
        assert!(repeated_names(&report, 0).is_empty());
    }
}

#[test]
fn repeated_names_keep_exact_groups_despite_colliding_bounded_previews() {
    let (mut report, _) = report_fixture();
    let prefix = "x".repeat(256);
    report.mstat.resources.by_resource_name = list(vec![
        group(
            format!("{prefix}A"),
            counts(10, 2, 3),
            vec![entry("one", 5, 1)],
        ),
        group(format!("{prefix}BB"), counts(10, 2, 3), vec![]),
        group("Name".into(), counts(0, 2, 3), vec![]),
        group("name".into(), counts(0, 2, 3), vec![]),
    ]);
    for top in 0..=5 {
        let result = repeated_names(&report, top);
        assert_eq!(result.len(), top.min(4));
        if top >= 2 {
            assert_eq!(result[0].resource_name.text, prefix);
            assert_eq!(result[1].resource_name.text, prefix);
            assert_eq!(result[0].resource_name.original_bytes, 257);
            assert_eq!(result[1].resource_name.original_bytes, 258);
            assert!(result[0].resource_name.truncated);
            assert!(result[1].resource_name.truncated);
            assert_eq!(result[0].visible_equal_lengths, None);
            assert_eq!(result[1].visible_equal_lengths, None);
        }
        if top >= 4 {
            assert_eq!(result[2].resource_name.text, "Name");
            assert_eq!(result[3].resource_name.text, "name");
        }
    }
    report.mstat.resources.by_resource_name = list(vec![]);
    assert!(repeated_names(&report, 2).is_empty());
}

#[test]
fn cohort_redundancy_uses_directional_exact_ratios_and_stable_order() {
    let (mut report, _) = report_fixture();
    report.mstat.cohorts.cohorts = vec![
        cohort("z", counts(100, 2, 3)),
        cohort("a", counts(40, 2, 3)),
        cohort("b", counts(100, 2, 3)),
        cohort("zero", counts(0, 1, 2)),
    ];
    // The same 20 bytes belong to three rules; intersections are not additive.
    report.mstat.cohorts.intersections = vec![
        pair(1, 2, 20),
        pair(0, 2, 20),
        pair(0, 1, 20),
        pair(0, 3, 0),
    ];
    for top in 0..=5 {
        let result = cohort_pairs(&report, top).unwrap();
        assert_eq!(result.len(), top.min(4));
        let expected = [("z", "a"), ("z", "b"), ("a", "b"), ("z", "zero")];
        assert_eq!(
            result
                .iter()
                .map(|row| (row.left, row.right))
                .collect::<Vec<_>>(),
            &expected[..top.min(4)]
        );
        if top > 0 {
            assert_eq!(result[0].intersection_bytes, 20);
            assert_eq!(result[0].left_share_basis_points, Some(2000));
            assert_eq!(result[0].right_share_basis_points, Some(5000));
            assert!(result[0].interpretation.contains("not exclusive ownership"));
            assert!(result[0].interpretation.contains("not additive"));
        }
        if top >= 4 {
            assert_eq!(result[3].intersection_bytes, 0);
            assert_eq!(result[3].left_share_basis_points, Some(0));
            assert_eq!(result[3].right_share_basis_points, None);
        }
    }
    let before = serde_json::to_value(cohort_pairs(&report, 4).unwrap()).unwrap();
    report.mstat.cohorts.intersections.reverse();
    assert_eq!(
        serde_json::to_value(cohort_pairs(&report, 4).unwrap()).unwrap(),
        before
    );
    report.mstat.cohorts.cohorts[0].accounted = counts(0, 1, 2);
    report.mstat.cohorts.intersections = vec![pair(0, 3, 0)];
    let zero = serde_json::to_value(cohort_pairs(&report, 1).unwrap()).unwrap();
    assert_null_field(&zero[0], "left_share_basis_points");
    assert_null_field(&zero[0], "right_share_basis_points");
    report.mstat.cohorts.intersections.clear();
    assert!(cohort_pairs(&report, 10).unwrap().is_empty());
}

#[test]
fn cohort_pairs_use_wide_arithmetic_and_byte_rank_before_rule_index_ties() {
    let (mut report, _) = report_fixture();
    report.mstat.cohorts.cohorts = vec![
        cohort("first", counts(u64::MAX, 3, 4)),
        cohort("second", counts(u64::MAX - 1, 3, 4)),
        cohort("third", counts(u64::MAX, 3, 4)),
    ];
    report.mstat.cohorts.intersections = vec![
        pair(0, 2, u64::MAX - 2),
        pair(1, 2, u64::MAX - 1),
        pair(0, 1, u64::MAX - 1),
    ];
    let result = cohort_pairs(&report, 3).unwrap();
    assert_eq!(
        result
            .iter()
            .map(|row| (row.left, row.right, row.intersection_bytes))
            .collect::<Vec<_>>(),
        [
            ("first", "second", u64::MAX - 1),
            ("second", "third", u64::MAX - 1),
            ("first", "third", u64::MAX - 2)
        ]
    );
    assert_eq!(result[0].left_share_basis_points, Some(9999));
    assert_eq!(result[0].right_share_basis_points, Some(10_000));
    assert_eq!(result[1].left_share_basis_points, Some(10_000));
    assert_eq!(result[1].right_share_basis_points, Some(9999));
    assert_eq!(result[2].left_share_basis_points, Some(9999));
    // Distinct exact fractions both floor to 9999; rounding cannot reorder byte ranks.
    assert_eq!(result[2].right_share_basis_points, Some(9999));
    let expected = serde_json::to_value(result).unwrap();
    report.mstat.cohorts.intersections.reverse();
    assert_eq!(
        serde_json::to_value(cohort_pairs(&report, 3).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn cohort_pairs_reject_invalid_indices_and_either_member_overflow_even_at_top_zero() {
    let (mut report, args) = report_fixture();
    report.mstat.cohorts.cohorts = vec![
        cohort("left", counts(40, 1, 1)),
        cohort("right", counts(100, 1, 1)),
    ];
    for (intersection, message) in [
        (
            pair(2, 1, 0),
            "cohort intersection index is outside the rule list",
        ),
        (
            pair(0, 2, 0),
            "cohort intersection index is outside the rule list",
        ),
        (
            pair(0, 1, 41),
            "cohort intersection exceeds a member's accounted bytes",
        ),
        (
            pair(1, 0, 41),
            "cohort intersection exceeds a member's accounted bytes",
        ),
    ] {
        report.mstat.cohorts.intersections = vec![intersection];
        for top in [0, 1] {
            assert_invariant(cohort_pairs(&report, top).err().unwrap(), message);
        }
        assert_invariant(build(&report, &args).err().unwrap(), message);
        // Validation cannot stop at the displayed prefix.
        report.mstat.cohorts.intersections.insert(0, pair(0, 1, 20));
        assert_invariant(cohort_pairs(&report, 1).err().unwrap(), message);
    }
    report.mstat.cohorts.intersections = vec![pair(0, 1, 40)];
    assert_eq!(
        cohort_pairs(&report, 1).unwrap()[0].left_share_basis_points,
        Some(10_000)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn unmatched_by_stream_subtracts_complete_once_counted_union_evidence() {
    let (mut report, mut args) = report_fixture();
    args.top = 0;
    let totals = [100, 50, 200, 10, 20, 30, 0];
    let partial = [
        counts(40, 2, 4),
        counts(10, 1, 2),
        counts(80, 2, 4),
        counts(10, 1, 1),
        counts(20, 2, 3),
        counts(15, 1, 2),
        counts(0, 2, 4),
    ];
    streams(&mut report, totals, partial);
    // Summed triple memberships would underflow Methods; only the union is subtracted.
    report.mstat.cohorts.cohorts = ["a", "b", "c"]
        .into_iter()
        .map(|name| cohort(name, counts(130, 5, 10)))
        .collect();
    let result = stream_gaps(&report).unwrap();
    assert_eq!(result.len(), 7);
    assert_eq!(
        result
            .iter()
            .map(|row| (
                row.stream,
                row.accounted,
                row.total_bytes,
                row.unmatched_bytes,
                row.covered_share_basis_points
            ))
            .collect::<Vec<_>>(),
        [
            ("Methods", true, 100, 60, Some(4000)),
            ("Types", true, 50, 40, Some(2000)),
            ("Blobs", true, 200, 120, Some(4000)),
            ("RvaFields", false, 10, 0, Some(10_000)),
            ("FrozenObjects", false, 20, 0, Some(10_000)),
            ("ManifestResources", false, 30, 15, Some(5000)),
            ("DeduplicatedMethods", false, 0, 0, None)
        ]
    );
    assert_eq!(
        result
            .iter()
            .map(|row| row.matched_union)
            .collect::<Vec<_>>(),
        partial
    );
    assert_eq!(
        result
            .iter()
            .filter(|row| row.accounted)
            .map(|row| row.unmatched_bytes)
            .sum::<u64>(),
        220
    );
    assert_eq!(report.mstat.cohorts.union_accounted.bytes, 130);
    assert_eq!(report.mstat.cohorts.union_non_accounted.bytes, 45);
    let output = serde_json::to_value(build(&report, &args).unwrap()).unwrap();
    assert_eq!(
        output["unmatched_by_stream"][6]["matched_union"]["identities"],
        2
    );
    assert_eq!(
        output["unmatched_by_stream"][6]["matched_union"]["records"],
        4
    );
    assert_null_field(
        &output["unmatched_by_stream"][6],
        "covered_share_basis_points",
    );
    assert_eq!(output["unmatched_by_stream"][2]["stream"], "Blobs");
    assert!(output["unmatched_by_stream"][2].get("owner").is_none());
    report.rules.clear();
    report.mstat.cohorts.cohorts.clear();
    streams(&mut report, totals, [InsightCounts::default(); 7]);
    let no_rules = stream_gaps(&report).unwrap();
    assert_eq!(
        no_rules
            .iter()
            .map(|row| row.unmatched_bytes)
            .collect::<Vec<_>>(),
        totals
    );
    let full = totals.map(|bytes| counts(bytes, 1, 2));
    streams(&mut report, totals, full);
    assert!(
        stream_gaps(&report)
            .unwrap()
            .iter()
            .all(|row| row.unmatched_bytes == 0)
    );
    streams(&mut report, [0; 7], [InsightCounts::default(); 7]);
    let empty = stream_gaps(&report).unwrap();
    assert_eq!(empty.len(), 7);
    assert!(
        empty
            .iter()
            .all(|row| row.covered_share_basis_points.is_none())
    );
    assert!(
        empty
            .iter()
            .all(|row| row.matched_union == InsightCounts::default())
    );
}

#[test]
fn stream_gaps_validate_missing_duplicate_and_excess_union_rows() {
    let (mut report, args) = report_fixture();
    streams(
        &mut report,
        [100, 0, 0, 0, 0, 0, 0],
        [InsightCounts::default(); 7],
    );
    let original = report.mstat.cohorts.union_sections.clone();
    let missing = "expected exactly one cohort union per summary stream";
    report.mstat.cohorts.union_sections.clear();
    assert_invariant(stream_gaps(&report).err().unwrap(), missing);
    assert_invariant(build(&report, &args).err().unwrap(), missing);
    report.mstat.cohorts.union_sections = original.clone();
    report.mstat.cohorts.union_sections.pop();
    assert_invariant(stream_gaps(&report).err().unwrap(), missing);
    report.mstat.cohorts.union_sections = original.clone();
    report
        .mstat
        .cohorts
        .union_sections
        .push(original[0].clone());
    assert_invariant(stream_gaps(&report).err().unwrap(), missing);
    report.mstat.cohorts.union_sections = original.clone();
    report.mstat.cohorts.union_sections[0].matched = counts(101, 1, 1);
    let excess = "cohort stream union exceeds its full stream bytes";
    assert_invariant(stream_gaps(&report).err().unwrap(), excess);
    assert_invariant(build(&report, &args).err().unwrap(), excess);
    report.mstat.cohorts.union_sections = original;
    report.mstat.cohorts.union_sections[1].matched = counts(1, 1, 1);
    assert_invariant(stream_gaps(&report).err().unwrap(), excess);
    report.mstat.cohorts.union_sections[1].matched = InsightCounts::default();
    report.mstat.cohorts.union_sections[0].matched = counts(100, 1, 2);
    assert_eq!(stream_gaps(&report).unwrap()[0].unmatched_bytes, 0);
}

#[test]
fn stream_gaps_use_full_wide_totals_not_encoded_bytes_or_record_counts() {
    let (mut report, _) = report_fixture();
    streams(
        &mut report,
        [u64::MAX, 0, 0, 0, 0, 0, 0],
        [
            counts(u64::MAX - 1, 2, 4),
            InsightCounts::default(),
            InsightCounts::default(),
            InsightCounts::default(),
            InsightCounts::default(),
            InsightCounts::default(),
            InsightCounts::default(),
        ],
    );
    let rows = stream_gaps(&report).unwrap();
    assert_eq!(rows[0].total_bytes, u64::MAX);
    assert_eq!(rows[0].unmatched_bytes, 1);
    assert_eq!(rows[0].covered_share_basis_points, Some(9999));
    assert_eq!(rows[0].matched_union, counts(u64::MAX - 1, 2, 4));
    assert!(
        rows[1..]
            .iter()
            .all(|row| row.covered_share_basis_points.is_none())
    );
}

#[test]
fn spelling_hints_are_bounded_literal_suggestions_without_rule_mutation() {
    let (mut report, _) = report_fixture();
    report.rules = vec![
        rule(
            "resource-only",
            &[
                "Azure.Core",
                "Azure.Core",
                "Azure_Core",
                "A..B",
                "日.😀",
                "no_dot",
                "nul.\0suffix",
            ],
            Some("ManifestResources"),
        ),
        rule("zero-accounted-hit", &["Hidden.Dot"], Some("Blobs")),
        rule("another", &["A..B"], Some("Methods")),
    ];
    report.mstat.cohorts.cohorts = vec![
        cohort("resource-only", InsightCounts::default()),
        cohort("zero-accounted-hit", counts(0, 1, 2)),
        cohort("another", InsightCounts::default()),
    ];
    report.mstat.cohorts.cohorts[0].non_accounted = counts(10, 1, 2);
    let before_rules = report.rules.clone();
    let before_cohorts = report.mstat.cohorts.clone();
    let expected = [
        ("resource-only", "A..B", "A__B"),
        ("resource-only", "日.😀", "日_😀"),
        ("another", "A..B", "A__B"),
    ];
    for top in 0..=4 {
        let result = spelling_hints(&report, top);
        assert_eq!(
            result
                .iter()
                .map(|hint| (
                    hint.rule.text.as_str(),
                    hint.original_predicate.text.as_str(),
                    hint.candidate_predicate.text.as_str()
                ))
                .collect::<Vec<_>>(),
            &expected[..top.min(3)]
        );
        for hint in result {
            assert!(
                hint.interpretation
                    .contains("explicitly test the candidate")
            );
            assert!(hint.interpretation.contains("no rule was changed"));
            assert!(hint.interpretation.contains("no component absence"));
        }
        assert_eq!(report.rules, before_rules);
        assert_eq!(report.mstat.cohorts, before_cohorts);
    }
}

#[test]
fn spelling_hints_deduplicate_per_rule_and_preserve_case_without_normalizing() {
    let (mut report, _) = report_fixture();
    report.rules = vec![rule(
        "dotted",
        &[
            "Azure.Core",
            "Azure.Core",
            "azure.Core",
            ".Leading.",
            "already_under",
            "",
        ],
        None,
    )];
    report.mstat.cohorts.cohorts = vec![cohort("dotted", InsightCounts::default())];
    let hints = spelling_hints(&report, 20);
    assert_eq!(
        hints
            .iter()
            .map(|hint| hint.candidate_predicate.text.as_str())
            .collect::<Vec<_>>(),
        ["Azure_Core", "azure_Core", "_Leading_"]
    );
    assert_eq!(hints[0].original_predicate.text, "Azure.Core");
    report.rules.clear();
    report.mstat.cohorts.cohorts.clear();
    assert!(spelling_hints(&report, 20).is_empty());
}

#[test]
fn spelling_hint_previews_respect_256_byte_utf8_boundaries_and_reject_nul_patterns() {
    let (mut report, _) = report_fixture();
    for length in [255, 256, 257] {
        let pattern = format!("{}.", "x".repeat(length - 1));
        let name = "n".repeat(length);
        report.rules = vec![rule(&name, &[&pattern, "unsafe.\0tail"], None)];
        report.mstat.cohorts.cohorts = vec![cohort(&name, InsightCounts::default())];
        let hints = spelling_hints(&report, 2);
        assert_eq!(hints.len(), 1);
        let hint = &hints[0];
        for preview in [
            &hint.rule,
            &hint.original_predicate,
            &hint.candidate_predicate,
        ] {
            assert_eq!(preview.text.len(), length.min(256));
            assert_eq!(preview.original_bytes, length as u64);
            assert_eq!(preview.truncated, length > 256);
        }
        assert_eq!(hint.original_predicate.text, pattern[..length.min(256)]);
        let candidate = format!("{}_", "x".repeat(length - 1));
        assert_eq!(hint.candidate_predicate.text, candidate[..length.min(256)]);
    }
    let unicode = format!("{}.😀", "x".repeat(254));
    let nul_name = "rule\0name";
    report.rules = vec![rule(nul_name, &[&unicode], None)];
    report.mstat.cohorts.cohorts = vec![cohort(nul_name, InsightCounts::default())];
    let hints = spelling_hints(&report, 1);
    assert_eq!(
        hints[0].original_predicate.text,
        format!("{}.", "x".repeat(254))
    );
    assert_eq!(
        hints[0].candidate_predicate.text,
        format!("{}_", "x".repeat(254))
    );
    assert_eq!(hints[0].original_predicate.original_bytes, 259);
    assert!(hints[0].original_predicate.truncated);
    assert_eq!(hints[0].rule.text, nul_name);
    let serialized = serde_json::to_string(&hints).unwrap();
    assert!(serialized.contains(r"rule\u0000name"));
    assert!(!serialized.contains('\0'));
}

#[test]
fn coverage_targets_require_exact_full_total_prefix_proof() {
    let full = targets("methods", 100, [50, 30, 10, 5, 5].into_iter());
    assert_eq!(prefixes(&full), [Some(2), Some(3), Some(4)]);
    assert_eq!(
        full.iter()
            .map(|row| row.target_basis_points)
            .collect::<Vec<_>>(),
        [8000, 9000, 9500]
    );
    assert!(
        full.iter()
            .all(|row| row.denominator_bytes == 100 && row.dimension == "methods")
    );
    for (slot, threshold) in [80_u64, 90, 95].into_iter().enumerate() {
        for (first, expected) in [(threshold - 1, 2), (threshold, 1), (threshold + 1, 1)] {
            let result = targets("boundary", 100, [first, 100 - first].into_iter());
            assert_eq!(
                result[slot].required_displayed_prefix,
                Some(expected),
                "threshold={threshold}, first={first}"
            );
        }
    }
    assert_eq!(
        prefixes(&targets("ceiling", 101, [80, 10, 6, 5].into_iter())),
        [Some(2), Some(3), Some(3)]
    );
    let hidden = targets("cut", 100, [50, 29].into_iter());
    assert_eq!(prefixes(&hidden), [None, None, None]);
    assert!(hidden.iter().all(|row| row.denominator_bytes == 100));
    assert!(hidden[0].interpretation.contains("increase top or narrow"));
    assert!(hidden[0].interpretation.contains("Not a count percentile"));
    let partial = targets("cut", 100, [50, 30].into_iter());
    assert_eq!(prefixes(&partial), [Some(2), None, None]);
    assert_eq!(
        prefixes(&targets("cut", 100, [50, 30, 10].into_iter())),
        [Some(2), Some(3), None]
    );
    assert_eq!(
        prefixes(&targets("zero_tail", 100, [100].into_iter())),
        [Some(1); 3]
    );
    for total in [0, 100] {
        let empty = targets("empty", total, std::iter::empty());
        assert_eq!(prefixes(&empty), [None; 3]);
        assert_null_field(
            &serde_json::to_value(empty).unwrap()[0],
            "required_displayed_prefix",
        );
    }
    assert_eq!(prefixes(&targets("zero", 0, [0, 0].into_iter())), [None; 3]);
}

#[test]
fn coverage_targets_use_wide_exact_crossproducts_at_u64_max() {
    let total = u64::MAX;
    let threshold80 = total - total / 5;
    let threshold90 = total - total / 10;
    let threshold95 = total - total / 20;
    let parts = [
        total / 2,
        threshold80 - total / 2,
        threshold90 - threshold80,
        threshold95 - threshold90,
        total - threshold95,
    ];
    assert_eq!(
        parts.iter().map(|bytes| u128::from(*bytes)).sum::<u128>(),
        u128::from(total)
    );
    assert_eq!(
        prefixes(&targets("wide", total, parts.into_iter())),
        [Some(2), Some(3), Some(4)]
    );
    for (slot, percent) in [80_u128, 90, 95].into_iter().enumerate() {
        let exact_ceiling = u64::try_from((u128::from(total) * percent).div_ceil(100)).unwrap();
        for (first, expected) in [
            (exact_ceiling - 1, 2),
            (exact_ceiling, 1),
            (exact_ceiling + 1, 1),
        ] {
            let result = targets("wide_boundary", total, [first, total - first].into_iter());
            assert_eq!(result[slot].required_displayed_prefix, Some(expected));
            assert_eq!(result[slot].denominator_bytes, total);
        }
    }
}

#[test]
fn coverage_targets_bind_each_full_matched_dimension_and_optional_metadata() {
    let (mut report, _) = report_fixture();
    report.mstat.methods.total.bytes = 500;
    report.mstat.methods.matched.bytes = 100;
    report.mstat.methods.entries.truncate(1);
    report.mstat.methods.entries[0].bytes = 80;
    report.mstat.blobs.total = counts(500, 5, 5);
    report.mstat.blobs.matched = counts(100, 2, 2);
    report.mstat.blobs.entries = vec![entry("blob", 90, 1)];
    report.mstat.resources.by_culture = list(vec![group("fr".into(), counts(95, 1, 1), vec![])]);
    report.mstat.resources.by_culture.matched.bytes = 100;
    report.mstat.resources.by_resource_name =
        list(vec![group("name".into(), counts(79, 1, 1), vec![])]);
    report.mstat.resources.by_resource_name.matched.bytes = 100;
    report.mstat.resources.by_assembly = list(vec![assembly_group("Asm", "", 100)]);
    report.metadata.sections.by_type = vec![Aggregate {
        name: "Type".into(),
        bytes: 50,
        records: 1,
    }];
    report.metadata.sections.concentration.insert(
        "by_type".into(),
        Concentration {
            total_bytes: 100,
            reported_bytes: 50,
            omitted_bytes: 50,
            total_groups: 2,
            reported_groups: 1,
            reported_share_basis_points: 5000,
        },
    );
    for (section, bytes) in report.mstat.generics.sections.iter_mut().zip([90, 80]) {
        section.matched_generic_shaped = counts(100, 2, 2);
        section.families = vec![GenericFamily {
            prefix: "Family".into(),
            total: counts(bytes, 1, 1),
            matched: counts(bytes, 1, 1),
            top_bytes: 0,
            omitted_bytes: bytes,
            examples: vec![],
        }];
    }
    let result = coverage_targets(&report);
    assert_eq!(result.len(), 24);
    for (index, (dimension, expected)) in [
        ("methods", [Some(1), None, None]),
        ("blobs", [Some(1), Some(1), None]),
        ("resources.culture", [Some(1); 3]),
        ("resources.name", [None; 3]),
        ("resources.assembly_culture", [Some(1); 3]),
        ("metadata.by_type", [None; 3]),
        ("generic_families.Methods", [Some(1), Some(1), None]),
        ("generic_families.Types", [Some(1), None, None]),
    ]
    .into_iter()
    .enumerate()
    {
        let rows = &result[index * 3..index * 3 + 3];
        assert_eq!(prefixes(rows), expected, "{dimension}");
        assert!(
            rows.iter()
                .all(|row| row.dimension == dimension && row.denominator_bytes == 100)
        );
    }
    report.metadata.sections.concentration.remove("by_type");
    assert_eq!(coverage_targets(&report).len(), 21);
    assert!(
        coverage_targets(&report)
            .iter()
            .all(|row| row.dimension != "metadata.by_type")
    );
    report.mstat.generics.sections.clear();
    assert_eq!(coverage_targets(&report).len(), 15);
}

fn composition_fixture() -> (BloatReport, BloatArgs) {
    let (mut report, mut args) = report_fixture();
    args.top = 1;
    population(&mut report);
    report.mstat.summary.input_bytes = 100;
    report.mstat.summary.mangled_names_bytes = 200;
    report.mstat.summary.methods = report.mstat.methods.total_components.clone();
    report.mstat.methods.accounted_denominator_bytes = 71_144;
    report.mstat.blobs.total = counts(800, 3, 5);
    report.mstat.blobs.matched = counts(800, 3, 5);
    report.mstat.blobs.top_bytes = 700;
    report.mstat.blobs.omitted_bytes = 100;
    report.mstat.blobs.dehydrated_data = counts(0, 1, 2);
    report.mstat.blobs.entries = vec![entry("opaque", 700, 2)];
    let mut assembly = list(vec![assembly_group("Exact, Culture=literal", "fr", 40)]);
    assembly.total = counts(60, 3, 6);
    assembly.matched = counts(60, 3, 6);
    assembly.total_groups = 3;
    assembly.matched_groups = 3;
    assembly.omitted_bytes = 20;
    report.mstat.resources.by_assembly = assembly;
    let mut culture = list(vec![group("fr".into(), counts(40, 1, 2), vec![])]);
    culture.total = counts(60, 3, 6);
    culture.matched = counts(60, 3, 6);
    culture.total_groups = 3;
    culture.matched_groups = 3;
    culture.omitted_bytes = 20;
    report.mstat.resources.by_culture = culture;
    report.mstat.resources.by_resource_name = list(vec![group(
        "Name.Space".into(),
        counts(60, 3, 6),
        vec![entry("Exact, Culture=literal/fr/Name.Space", 40, 2)],
    )]);
    report.rules = vec![
        rule("a", &["selected", "opaque"], None),
        rule("b", &["selected", "opaque"], None),
        rule("c", &["selected", "opaque"], None),
        rule("resource-only", &["Name.Space"], Some("ManifestResources")),
    ];
    report.mstat.cohorts.cohorts = ["a", "b", "c"]
        .into_iter()
        .map(|name| cohort(name, counts(955, 2, 4)))
        .collect();
    let mut resource_rule = cohort("resource-only", InsightCounts::default());
    resource_rule.non_accounted = counts(60, 3, 6);
    report.mstat.cohorts.cohorts.push(resource_rule);
    report.mstat.cohorts.intersections = vec![pair(1, 2, 955), pair(0, 2, 955), pair(0, 1, 955)];
    for intersection in &mut report.mstat.cohorts.intersections {
        intersection.accounted = counts(955, 2, 4);
    }
    streams(
        &mut report,
        [70_143, 201, 800, 0, 0, 60, 0],
        [
            counts(255, 1, 2),
            InsightCounts::default(),
            counts(700, 1, 2),
            InsightCounts::default(),
            InsightCounts::default(),
            counts(60, 3, 6),
            InsightCounts::default(),
        ],
    );
    for (category, records) in report
        .mstat
        .summary
        .categories
        .iter_mut()
        .zip([9, 7, 5, 0, 0, 6, 0])
    {
        category.records = records;
    }
    report.mstat.cohorts.multiply_matched_accounted = counts(955, 2, 4);
    report.mstat.cohorts.multiply_matched_non_accounted = InsightCounts::default();
    report.metadata.sections.by_type = vec![Aggregate {
        name: "Type".into(),
        bytes: 80,
        records: 1,
    }];
    report.metadata.sections.concentration.insert(
        "by_type".into(),
        Concentration {
            total_bytes: 100,
            reported_bytes: 80,
            omitted_bytes: 20,
            total_groups: 2,
            reported_groups: 1,
            reported_share_basis_points: 8000,
        },
    );
    (report, args)
}

#[test]
#[allow(clippy::too_many_lines)]
fn investigation_composition_is_deterministic_bounded_and_non_mutating() {
    let (mut report, args) = composition_fixture();
    let original = serde_json::to_value(&report).unwrap();
    let original_args = format!("{args:?}");
    let first = serde_json::to_value(build(&report, &args).unwrap()).unwrap();
    assert_eq!(
        first,
        serde_json::to_value(build(&report, &args).unwrap()).unwrap()
    );
    assert_eq!(serde_json::to_value(&report).unwrap(), original);
    assert_eq!(format!("{args:?}"), original_args);
    assert_eq!(first["schema"], "vitnet.bloat-investigation.v1");
    assert_eq!(first["accounting_limits"]["dehydration_observed"], true);
    assert_eq!(first["accounting_limits"]["dehydrated_data_bytes"], 0);
    assert_eq!(first["accounting_limits"]["dehydrated_data_records"], 2);
    assert_null_field(&first["accounting_limits"], "physical_binary_bytes");
    assert_eq!(
        first["blob_buckets"]["total"],
        json!({"bytes":800,"identities":3,"records":5})
    );
    assert_eq!(
        first["blob_buckets"]["entries"].as_array().unwrap().len(),
        1
    );
    assert_eq!(first["blob_buckets"]["shown_bytes"], 700);
    assert_eq!(first["blob_buckets"]["omitted_bytes"], 100);
    assert_eq!(first["blob_buckets"]["shown_share_basis_points"], 8750);
    assert_eq!(
        first["diagnostic_artifacts"]["names_to_input_basis_points"],
        "20000"
    );
    assert_eq!(
        first["method_population"]["methods"]["total"]["bytes"],
        70_143
    );
    assert_eq!(
        first["method_population"]["methods"]["total"]["identities"],
        6
    );
    assert_eq!(first["method_population"]["methods"]["total"]["records"], 9);
    assert_eq!(
        first["method_population"]["size_bands"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(first["method_population"]["types"]["total"]["bytes"], 201);
    let cultures = &first["resource_culture_assemblies"];
    assert_eq!(cultures["all_assembly_culture_groups_shown"], false);
    assert_eq!(cultures["omitted_group_bytes"], 20);
    assert_eq!(cultures["assemblies"].as_array().unwrap().len(), 1);
    assert_eq!(
        cultures["assemblies"][0]["assembly"]["text"],
        "Exact, Culture=literal"
    );
    assert_eq!(cultures["assemblies"][0]["visible_bytes"], 40);
    assert_eq!(cultures["assemblies"][0]["visible_non_neutral_bytes"], 40);
    assert_null_field(&cultures["assemblies"][0], "neutral_bytes");
    assert_eq!(first["repeated_resource_names"][0]["identities"], 3);
    assert_eq!(first["repeated_resource_names"][0]["visible_examples"], 1);
    assert_null_field(
        &first["repeated_resource_names"][0],
        "visible_equal_lengths",
    );
    assert_eq!(first["cohort_redundancy"].as_array().unwrap().len(), 1);
    assert_eq!(first["cohort_redundancy"][0]["left"], "a");
    assert_eq!(first["cohort_redundancy"][0]["right"], "b");
    assert_eq!(first["cohort_redundancy"][0]["intersection_bytes"], 955);
    assert_eq!(
        first["cohort_redundancy"][0]["left_share_basis_points"],
        10_000
    );
    assert_eq!(first["unmatched_by_stream"].as_array().unwrap().len(), 7);
    assert_eq!(first["unmatched_by_stream"][0]["unmatched_bytes"], 69_888);
    assert_eq!(first["unmatched_by_stream"][1]["unmatched_bytes"], 201);
    assert_eq!(first["unmatched_by_stream"][2]["unmatched_bytes"], 100);
    assert_eq!(first["unmatched_by_stream"][5]["unmatched_bytes"], 0);
    assert_eq!(first["unmatched_by_stream"][5]["accounted"], false);
    assert_eq!(first["spelling_hints"].as_array().unwrap().len(), 1);
    assert_eq!(first["spelling_hints"][0]["rule"]["text"], "resource-only");
    assert_eq!(
        first["spelling_hints"][0]["original_predicate"]["text"],
        "Name.Space"
    );
    assert_eq!(
        first["spelling_hints"][0]["candidate_predicate"]["text"],
        "Name_Space"
    );
    let targets = first["coverage_targets"].as_array().unwrap();
    let blobs: Vec<_> = targets
        .iter()
        .filter(|row| row["dimension"] == "blobs")
        .collect();
    assert_eq!(blobs.len(), 3);
    assert_eq!(blobs[0]["denominator_bytes"], 800);
    assert_eq!(blobs[0]["required_displayed_prefix"], 1);
    assert_null_field(blobs[1], "required_displayed_prefix");
    assert_null_field(blobs[2], "required_displayed_prefix");
    let resource_targets: Vec<_> = targets
        .iter()
        .filter(|row| row["dimension"] == "resources.culture")
        .collect();
    assert!(
        resource_targets
            .iter()
            .all(|row| row["denominator_bytes"] == 60
                && row.get("required_displayed_prefix") == Some(&Value::Null))
    );
    // Sortable evidence can be reversed without changing output; byte-ranked prefixes cannot.
    report.mstat.cohorts.intersections.reverse();
    report.mstat.cohorts.union_sections.reverse();
    assert_eq!(
        first,
        serde_json::to_value(build(&report, &args).unwrap()).unwrap()
    );
}

#[test]
fn investigation_empty_known_evidence_keeps_zero_denominators_unknown() {
    let (mut report, mut args) = report_fixture();
    args.top = 0;
    population(&mut report);
    let methods = &mut report.mstat.methods;
    methods.total = InsightCounts::default();
    methods.matched = InsightCounts::default();
    methods.entries.clear();
    methods.total_components = MethodBreakdown::default();
    methods.matched_components = MethodBreakdown::default();
    methods.top_components = MethodBreakdown::default();
    methods.omitted_components = MethodBreakdown::default();
    methods.top_bytes = 0;
    methods.omitted_bytes = 0;
    methods.accounted_denominator_bytes = 0;
    for band in &mut methods.size_bands {
        band.total = InsightCounts::default();
        band.matched = InsightCounts::default();
    }
    report.mstat.blobs = BlobInsightReport::default();
    report.mstat.summary.input_bytes = 0;
    report.mstat.summary.mangled_names_bytes = 0;
    report.mstat.summary.methods = MethodBreakdown::default();
    report.mstat.resources.by_assembly = list(vec![]);
    report.mstat.resources.by_culture = list(vec![]);
    report.mstat.resources.by_resource_name = list(vec![]);
    report.rules.clear();
    report.mstat.cohorts.cohorts.clear();
    report.mstat.cohorts.intersections.clear();
    report.mstat.cohorts.multiply_matched_accounted = InsightCounts::default();
    report.mstat.cohorts.multiply_matched_non_accounted = InsightCounts::default();
    for section in &mut report.mstat.generics.sections {
        section.total = InsightCounts::default();
        section.non_generic_shaped = InsightCounts::default();
    }
    streams(&mut report, [0; 7], [InsightCounts::default(); 7]);
    for category in &mut report.mstat.summary.categories {
        category.records = 0;
    }
    let output = serde_json::to_value(build(&report, &args).unwrap()).unwrap();
    assert_eq!(output["accounting_limits"]["dehydration_observed"], false);
    assert_null_field(&output["blob_buckets"], "shown_share_basis_points");
    assert_null_field(
        &output["diagnostic_artifacts"],
        "names_to_input_basis_points",
    );
    assert_eq!(
        output["method_population"]["size_bands"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_null_field(
        &output["method_population"]["methods"],
        "bytes_per_identity",
    );
    assert_null_field(&output["method_population"]["types"], "bytes_per_record");
    assert_eq!(
        output["resource_culture_assemblies"]["all_assembly_culture_groups_shown"],
        true
    );
    assert_eq!(
        output["resource_culture_assemblies"]["assemblies"],
        json!([])
    );
    for field in [
        "repeated_resource_names",
        "cohort_redundancy",
        "spelling_hints",
    ] {
        assert_eq!(output[field], json!([]));
    }
    assert_eq!(output["unmatched_by_stream"].as_array().unwrap().len(), 7);
    assert!(
        output["unmatched_by_stream"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |row| row.get("covered_share_basis_points") == Some(&Value::Null)
                    && row["total_bytes"] == 0
                    && row["matched_union"] == json!({"bytes":0,"identities":0,"records":0})
            )
    );
    let targets = output["coverage_targets"].as_array().unwrap();
    assert!(targets.len() >= 21);
    assert!(targets.iter().all(|row| row["denominator_bytes"] == 0
        && row.get("required_displayed_prefix") == Some(&Value::Null)));
}
