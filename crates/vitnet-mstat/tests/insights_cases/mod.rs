use super::{as_u32, fixture_with, i4, push_u32, token};
use vitnet_mstat::{
    CohortRule, InsightCounts, InsightKind, InsightProjection, InsightsOptions, MstatInsights,
    ResourceGroupList, insights, insights_path, project_insights, summarize, top_entries,
};

const LIMIT: u64 = 16 * 1024 * 1024;

struct Image {
    bodies: [Vec<u8>; 7],
    names: Vec<u8>,
    user_strings: Vec<u8>,
    assemblies: Vec<(&'static str, &'static str)>,
}

impl Image {
    fn new() -> Self {
        Self {
            bodies: std::array::from_fn(|_| Vec::new()),
            names: Vec::new(),
            user_strings: vec![0],
            assemblies: vec![
                ("Example", ""),
                ("Example", "fr-FR"),
                ("Example, Culture=fr-FR", ""),
            ],
        }
    }

    fn name(&mut self, name: &str) -> i32 {
        let offset = i32::try_from(self.names.len()).unwrap();
        compressed(&mut self.names, name.len());
        self.names.extend_from_slice(name.as_bytes());
        offset
    }

    fn user_string(&mut self, text: &str) -> u32 {
        let offset = as_u32(self.user_strings.len());
        let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        compressed(&mut self.user_strings, encoded.len() + 1);
        self.user_strings.extend_from_slice(&encoded);
        self.user_strings.push(1);
        0x7000_0000 | offset
    }

    fn method(&mut self, name: &str, sizes: [i32; 3], metadata_token: u32) {
        let offset = self.name(name);
        token(&mut self.bodies[0], metadata_token);
        for size in sizes {
            i4(&mut self.bodies[0], size);
        }
        i4(&mut self.bodies[0], offset);
    }

    fn sized_name(&mut self, stream: usize, name: &str, size: i32) {
        let offset = self.name(name);
        token(
            &mut self.bodies[stream],
            if stream == 3 {
                0x0400_0001
            } else {
                0x0200_0001
            },
        );
        i4(&mut self.bodies[stream], size);
        i4(&mut self.bodies[stream], offset);
        if stream == 4 {
            i4(&mut self.bodies[stream], 0);
        }
    }

    fn blob(&mut self, name: &str, size: i32) {
        let name = self.user_string(name);
        self.bodies[2].push(0x72);
        push_u32(&mut self.bodies[2], name);
        i4(&mut self.bodies[2], size);
    }

    fn resource(&mut self, assembly: i32, name: &str, size: i32) {
        let name = self.user_string(name);
        i4(&mut self.bodies[5], 0x2300_0000 | assembly);
        self.bodies[5].push(0x72);
        push_u32(&mut self.bodies[5], name);
        i4(&mut self.bodies[5], size);
    }

    fn dedup(&mut self, name: &str) {
        let offset = self.name(name);
        token(&mut self.bodies[6], 0x0600_0001);
        i4(&mut self.bodies[6], 1);
        token(&mut self.bodies[6], 0x0600_0002);
        i4(&mut self.bodies[6], offset);
    }

    fn bytes(self) -> Vec<u8> {
        fixture_with(
            &self.bodies,
            &self.names,
            &self.user_strings,
            &self.assemblies,
        )
        .bytes
    }
}

fn compressed(bytes: &mut Vec<u8>, length: usize) {
    let value = as_u32(length);
    if value < 0x80 {
        bytes.push(u8::try_from(value).unwrap());
    } else if value < 0x4000 {
        bytes.extend_from_slice(&(u16::try_from(value).unwrap() | 0x8000).to_be_bytes());
    } else {
        assert!(value < 0x2000_0000);
        bytes.extend_from_slice(&(value | 0xc000_0000).to_be_bytes());
    }
}

fn representative() -> Vec<u8> {
    let mut image = Image::new();
    image.method("F<T>", [10, 2, 1], 0x0600_0001);
    image.method("F<T>", [4, 1, 2], 0x0600_0002);
    image.method("F<U>", [5, 0, 0], 0x0600_0001);
    image.method("Plain", [3, 1, 0], 0x0600_0001);
    image.method("<generated>", [1, 0, 0], 0x0600_0001);
    image.method("Odd<unclosed", [2, 0, 0], 0x0600_0001);
    image.sized_name(1, "T<X>", 12);
    image.sized_name(1, "T<Y>", 8);
    image.sized_name(1, "PlainType", 4);
    image.sized_name(1, "<anonymous>", 3);
    image.blob("F shared", 11);
    image.blob("日本😀", 7);
    image.sized_name(3, "F field", 2);
    image.sized_name(4, "F<T>", 6);
    image.sized_name(4, "F<T>", 3);
    image.resource(1, "日本😀.resources", 7);
    image.resource(1, "日本😀.resources", 3);
    image.resource(2, "日本😀.resources", 5);
    image.resource(3, "日本😀.resources", 4);
    image.resource(1, "Other.resources", 6);
    image.dedup("F<T>");
    image.bytes()
}

fn options(top: usize, contains: Option<&str>, rules: Vec<CohortRule>) -> InsightsOptions {
    InsightsOptions {
        top,
        contains: contains.map(str::to_owned),
        rules,
    }
}

fn rule(name: &str, patterns: &[&str], stream: Option<&str>) -> CohortRule {
    CohortRule {
        name: name.into(),
        contains: patterns.iter().map(|value| (*value).into()).collect(),
        stream: stream.map(str::to_owned),
    }
}

fn counts(bytes: u64, identities: u64, records: u64) -> InsightCounts {
    InsightCounts {
        bytes,
        identities,
        records,
    }
}

fn reconcile_resources<K>(list: &ResourceGroupList<K>) {
    assert_eq!(list.total, counts(25, 4, 5));
    assert_eq!(list.top_bytes + list.omitted_bytes, list.matched.bytes);
    assert_eq!(
        list.groups
            .iter()
            .map(|group| group.matched.bytes)
            .sum::<u64>(),
        list.top_bytes
    );
    for group in &list.groups {
        assert_eq!(group.top_bytes + group.omitted_bytes, group.matched.bytes);
        assert_eq!(
            group.entries.iter().map(|entry| entry.bytes).sum::<u64>(),
            group.top_bytes
        );
    }
}

#[test]
fn metadata_blob_reconciliation_is_exact_unfiltered_and_coalesced() {
    let mut image = Image::new();
    image.blob("Metadata", 5);
    image.blob("Metadata", 7);
    image.blob("metadata", 9);
    image.blob("MetadataSuffix", 11);
    image.blob("PrefixMetadata", 13);
    image.blob("Metadata\0", 17);
    image.blob(&format!("Metadata{}", "x".repeat(300)), 100);
    image.method("Metadata", [23, 0, 0], 0x0600_0001);
    image.resource(1, "Metadata", 31);
    let bytes = image.bytes();
    for (top, contains) in [(0, Some("absent")), (1, Some("Suffix")), (20, None)] {
        let report = insights(
            &bytes,
            LIMIT,
            &options(top, contains, vec![rule("other", &["absent"], None)]),
        )
        .unwrap();
        assert_eq!(report.metadata_blob_bytes, 12);
        assert_eq!(report.metadata_blob_records, 2);
        assert_eq!(report.summary.accounted_size_bytes, 185);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["metadata_blob_bytes"], 12);
        assert_eq!(json["metadata_blob_records"], 2);
        assert_eq!(report.cohorts.cohorts[0].accounted, counts(0, 0, 0));
    }
}

#[test]
fn focused_top_keeps_complete_summary_and_unselected_checked_validation() {
    let bytes = representative();
    let all = top_entries(&bytes, LIMIT, 3, None, None).unwrap();
    let focused = top_entries(&bytes, LIMIT, 3, None, Some("Methods")).unwrap();
    assert_eq!(focused.accounted_size_bytes, all.accounted_size_bytes);
    assert_eq!(focused.sections, all.sections[..1]);
    assert!(focused.peak_tracked_memory_bytes < all.peak_tracked_memory_bytes);

    let mut opcode = Image::new();
    opcode.method("Method", [1, 0, 0], 0x0600_0001);
    opcode.blob("Blob", 1);
    opcode.bodies[2][0] = 0xff;
    let mut token_fixture = Image::new();
    token_fixture.method("Method", [1, 0, 0], 0x0600_0001);
    token_fixture.sized_name(1, "Type", 1);
    token_fixture.bodies[1][1..5].copy_from_slice(&0_u32.to_le_bytes());
    let mut name_fixture = Image::new();
    name_fixture.method("Method", [1, 0, 0], 0x0600_0001);
    name_fixture.sized_name(1, "Type", 1);
    name_fixture.bodies[1].pop();
    i4(&mut name_fixture.bodies[1], 100_000);
    let mut assembly_fixture = Image::new();
    assembly_fixture.method("Method", [1, 0, 0], 0x0600_0001);
    assembly_fixture.resource(1, "Resource", 1);
    let mut assembly_bytes = assembly_fixture.bytes();
    let assembly_name = assembly_bytes
        .windows(b"Example\0".len())
        .position(|part| part == b"Example\0")
        .unwrap();
    assembly_bytes[assembly_name] = 0xff;
    for (bytes, code) in [
        (opcode.bytes(), "mstat.il.opcode"),
        (token_fixture.bytes(), "mstat.token.kind"),
        (name_fixture.bytes(), "mstat.names.offset"),
        (assembly_bytes, "mstat.strings"),
    ] {
        let focused = top_entries(&bytes, LIMIT, 3, None, Some("Methods")).unwrap_err();
        let all = top_entries(&bytes, LIMIT, 3, None, None).unwrap_err();
        assert_eq!(focused.diagnostic.code, code);
        assert_eq!(focused.diagnostic, all.diagnostic);
        for kind in [
            InsightKind::Methods,
            InsightKind::Resources,
            InsightKind::Generics,
            InsightKind::Cohorts,
        ] {
            let projection =
                project_insights(&bytes, LIMIT, &options(3, None, vec![]), kind).unwrap_err();
            assert_eq!(projection.diagnostic, all.diagnostic);
        }
    }
}

#[test]
fn focused_projections_equal_combined_payloads_with_complete_summaries() {
    let bytes = representative();
    for top in [0, 1, 20] {
        for contains in [None, Some("F"), Some("absent")] {
            let options = options(
                top,
                contains,
                vec![rule("F", &["F"], None), rule("unicode", &["日本😀"], None)],
            );
            let combined = insights(&bytes, LIMIT, &options).unwrap();
            for (kind, expected) in [
                (
                    InsightKind::Methods,
                    InsightProjection::Methods(combined.methods.clone()),
                ),
                (
                    InsightKind::Resources,
                    InsightProjection::Resources(combined.resources.clone()),
                ),
                (
                    InsightKind::Generics,
                    InsightProjection::Generics(combined.generics.clone()),
                ),
                (
                    InsightKind::Cohorts,
                    InsightProjection::Cohorts(combined.cohorts.clone()),
                ),
            ] {
                let mut focused = project_insights(&bytes, LIMIT, &options, kind).unwrap();
                assert_eq!(focused.data, expected);
                assert!(
                    focused.summary.peak_tracked_memory_bytes
                        < combined.summary.peak_tracked_memory_bytes
                );
                focused.summary.peak_tracked_memory_bytes =
                    combined.summary.peak_tracked_memory_bytes;
                assert_eq!(focused.summary, combined.summary);
            }
        }
    }
}

#[test]
fn focused_projections_validate_unused_rules_and_shared_option_limits() {
    let bytes = representative();
    for kind in [
        InsightKind::Methods,
        InsightKind::Resources,
        InsightKind::Generics,
        InsightKind::Cohorts,
    ] {
        for rules in [
            vec![rule("invalid", &[""], None)],
            vec![rule("invalid", &["F"], Some("Unknown"))],
        ] {
            let error =
                project_insights(&bytes, LIMIT, &options(1, None, rules), kind).unwrap_err();
            assert_eq!(error.diagnostic.code, "mstat.insights.rule");
        }
        let error =
            project_insights(&bytes, LIMIT, &options(usize::MAX, None, vec![]), kind).unwrap_err();
        assert_eq!(error.diagnostic.code, "resource.memory_limit");
    }
}

#[test]
fn focused_methods_large_top_stays_within_linear_report_budget() {
    let bytes = representative();
    let reference = insights(&bytes, LIMIT, &options(20, None, vec![])).unwrap();
    let report = project_insights(
        &bytes,
        LIMIT,
        &options(1000, None, vec![]),
        InsightKind::Methods,
    )
    .unwrap();
    assert_eq!(report.data, InsightProjection::Methods(reference.methods));
    assert_eq!(
        report.summary.accounted_size_bytes,
        reference.summary.accounted_size_bytes
    );
    assert!(report.summary.peak_tracked_memory_bytes < 2 * 1024 * 1024);
}

#[test]
fn scoped_cohort_budget_is_linear_while_nested_projections_keep_limits() {
    let bytes = representative();
    let predicates = vec![rule("F", &["F"], None)];
    let reference = insights(&bytes, LIMIT, &options(20, None, predicates.clone())).unwrap();
    let report = project_insights(
        &bytes,
        LIMIT,
        &options(1000, None, predicates),
        InsightKind::Cohorts,
    )
    .unwrap();
    assert_eq!(report.data, InsightProjection::Cohorts(reference.cohorts));
    assert!(report.summary.peak_tracked_memory_bytes < 4 * 1024 * 1024);
    for kind in [InsightKind::Resources, InsightKind::Generics] {
        assert_eq!(
            project_insights(&bytes, LIMIT, &options(1000, None, vec![]), kind)
                .unwrap_err()
                .diagnostic
                .code,
            "resource.memory_limit",
        );
    }
}

#[test]
fn top_heap_matches_full_exact_sort_with_ties_coalescing_and_filters() {
    let mut image = Image::new();
    let prefix = "日".repeat(100);
    let mut expected = Vec::new();
    for index in (0..100).rev() {
        let name = format!("{prefix}{index:03}");
        let bytes = index % 7;
        image.method(&name, [bytes, 0, 0], 0x0600_0001);
        image.method(&name, [1, 0, 0], 0x0600_0002);
        expected.push((name, u64::try_from(bytes + 1).unwrap()));
    }
    expected
        .sort_unstable_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let bytes = image.bytes();
    for contains in [None, Some("09"), Some("absent")] {
        let matching: Vec<_> = expected
            .iter()
            .filter(|(name, _)| contains.is_none_or(|needle| name.contains(needle)))
            .collect();
        for top in [1, 2, 3, 20, 99, 100, 101] {
            let report = top_entries(&bytes, LIMIT, top, contains, Some("Methods")).unwrap();
            let section = &report.sections[0];
            assert_eq!(section.matched_identities, matching.len() as u64);
            assert_eq!(
                section.matched_bytes,
                matching.iter().map(|(_, bytes)| *bytes).sum::<u64>()
            );
            assert_eq!(section.entries.len(), top.min(matching.len()));
            for (entry, (name, bytes)) in section.entries.iter().zip(&matching) {
                assert_eq!(entry.bytes, *bytes);
                assert_eq!(entry.records, 2);
                assert_eq!(entry.identity_bytes, name.len() as u64);
                assert_eq!(entry.identity, "日".repeat(85));
                assert!(entry.truncated);
            }
        }
    }
    assert_eq!(
        top_entries(&bytes, LIMIT, 0, None, Some("Methods"))
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
}

#[test]
fn top_compiled_filters_preserve_resource_prefixes_and_aligned_overlapping_hits() {
    let mut image = Image::new();
    image.method(
        &format!("{}needle", "n".repeat(300)),
        [6, 0, 0],
        0x0600_0001,
    );
    image.blob("\u{4100}\u{100}", 5);
    image.blob("A\u{1f600}", 7);
    image.blob("\u{1}\0", 3);
    image.resource(1, "A\u{1f600}", 11);
    image.resource(1, "\u{4100}\u{100}", 13);
    image.resource(2, "second", 17);
    image.resource(3, "third", 19);
    let bytes = image.bytes();
    for (stream, needle, expected_bytes, expected_identities) in [
        ("Methods", "needle", 6, 1),
        ("Blobs", "A", 7, 1),
        ("Blobs", "\0", 3, 1),
        ("Blobs", "a", 0, 0),
        ("Blobs", "", 15, 3),
        ("ManifestResources", "A", 11, 1),
        ("ManifestResources", "Culture=fr-FR", 36, 2),
        ("ManifestResources", "Example, Culture=fr-FR", 36, 2),
        ("ManifestResources", "", 60, 4),
    ] {
        let report = top_entries(&bytes, LIMIT, 20, Some(needle), Some(stream)).unwrap();
        let section = &report.sections[0];
        assert_eq!(
            section.matched_bytes, expected_bytes,
            "{stream}: {needle:?}"
        );
        assert_eq!(section.matched_identities, expected_identities);
        assert_eq!(section.entries.len() as u64, expected_identities);
        assert_eq!(
            section.entries.iter().map(|entry| entry.bytes).sum::<u64>(),
            expected_bytes
        );
        if stream == "Methods" {
            assert_eq!(section.entries[0].identity, "n".repeat(256));
            assert_eq!(section.entries[0].identity_bytes, 306);
            assert!(section.entries[0].truncated);
        }
    }
}

#[test]
fn top_filters_keep_exact_utf16_identities_and_reject_invalid_surrogates() {
    let mut image = Image::new();
    let prefix = "x".repeat(300);
    image.blob(&format!("{prefix}e\u{301}"), 7);
    image.blob(&format!("{prefix}\u{e9}"), 9);
    let bytes = image.bytes();
    for contains in [None, Some("")] {
        let report = top_entries(&bytes, LIMIT, 20, contains, Some("Blobs")).unwrap();
        let section = &report.sections[0];
        assert_eq!(section.matched_bytes, 16);
        assert_eq!(section.matched_identities, 2);
        assert_eq!(section.entries.len(), 2);
        assert_eq!(section.entries[0].bytes, 9);
        assert_eq!(section.entries[1].bytes, 7);
        for (entry, length) in section.entries.iter().zip([602, 604]) {
            assert_eq!(entry.identity, "x".repeat(256));
            assert_eq!(entry.identity_bytes, length);
            assert_eq!(entry.records, 1);
            assert!(entry.truncated);
        }
    }
    let report = top_entries(&bytes, LIMIT, 20, Some("\u{fffd}"), Some("Blobs")).unwrap();
    assert_eq!(report.sections[0].matched_bytes, 0);
    assert_eq!(report.sections[0].matched_identities, 0);
    assert_eq!(report.sections[0].entries, Vec::new());
    for (needle, expected_bytes) in [("\u{e9}", 9), ("e\u{301}", 7)] {
        let report = top_entries(&bytes, LIMIT, 20, Some(needle), Some("Blobs")).unwrap();
        assert_eq!(report.sections[0].matched_bytes, expected_bytes);
        assert_eq!(report.sections[0].matched_identities, 1);
        assert_eq!(report.sections[0].entries[0].bytes, expected_bytes);
    }
    for raw in [[0x00, 0xd8], [0x00, 0xdc]] {
        let mut invalid = Image::new();
        let offset = as_u32(invalid.user_strings.len());
        compressed(&mut invalid.user_strings, 3);
        invalid.user_strings.extend_from_slice(&raw);
        invalid.user_strings.push(1);
        invalid.bodies[2].push(0x72);
        push_u32(&mut invalid.bodies[2], 0x7000_0000 | offset);
        i4(&mut invalid.bodies[2], 7);
        let bytes = invalid.bytes();
        let expected = summarize(&bytes, LIMIT).unwrap_err().diagnostic;
        assert_eq!(expected.code, "mstat.user_string.utf16");
        for contains in [None, Some(""), Some("absent")] {
            for stream in ["Blobs", "Methods"] {
                let error = top_entries(&bytes, LIMIT, 20, contains, Some(stream)).unwrap_err();
                assert_eq!(error.diagnostic, expected);
            }
        }
    }
}

#[test]
fn metadata_blob_absence_does_not_match_case_substrings_or_truncated_names() {
    let mut image = Image::new();
    for name in [
        "metadata".to_owned(),
        "MetaData".to_owned(),
        "MetadataSuffix".to_owned(),
        "PrefixMetadata".to_owned(),
        format!("Metadata{}", "x".repeat(300)),
    ] {
        image.blob(&name, 1);
    }
    image.method("Metadata", [2, 0, 0], 0x0600_0001);
    image.resource(1, "Metadata", 3);
    let report = insights(&image.bytes(), LIMIT, &options(1, None, vec![])).unwrap();
    assert_eq!(report.metadata_blob_bytes, 0);
    assert_eq!(report.metadata_blob_records, 0);
    assert_eq!(report.summary.accounted_size_bytes, 7);
    let empty = insights(&Image::new().bytes(), LIMIT, &options(0, None, vec![])).unwrap();
    assert_eq!(empty.metadata_blob_bytes, 0);
    assert_eq!(empty.metadata_blob_records, 0);
}

#[test]
fn zero_size_metadata_blob_is_present_even_when_projection_is_empty() {
    let mut image = Image::new();
    image.blob("Metadata", 0);
    image.blob("Metadata", 0);
    let report = insights(&image.bytes(), LIMIT, &options(0, Some("absent"), vec![])).unwrap();
    assert_eq!(report.metadata_blob_bytes, 0);
    assert_eq!(report.metadata_blob_records, 2);
    assert_eq!(report.summary.accounted_size_bytes, 0);
}

#[test]
fn methods_coalesce_opaque_identity_components_and_reconcile_denominator() {
    let bytes = representative();
    let report = insights(&bytes, LIMIT, &options(2, None, vec![])).unwrap();
    assert_eq!(report.summary, {
        let mut summary = summarize(&bytes, LIMIT).unwrap();
        summary.peak_tracked_memory_bytes = report.summary.peak_tracked_memory_bytes;
        summary
    });
    assert_eq!(report.summary.accounted_size_bytes, 77);
    assert_eq!(report.methods.accounted_denominator_bytes, 77);
    assert_eq!(report.methods.total, counts(32, 5, 6));
    assert_eq!(report.methods.matched, report.methods.total);
    assert_eq!(report.methods.total_components.body_bytes, 25);
    assert_eq!(report.methods.total_components.gc_info_bytes, 4);
    assert_eq!(report.methods.total_components.exception_info_bytes, 3);
    let first = &report.methods.entries[0];
    assert_eq!(
        (first.identity.as_str(), first.bytes, first.records),
        ("F<T>", 20, 2)
    );
    assert_eq!(
        (
            first.body_bytes,
            first.gc_info_bytes,
            first.exception_info_bytes
        ),
        (14, 3, 3)
    );
    assert_eq!(first.accounted_basis_points, 2597);
    assert_eq!(report.methods.top_bytes, 25);
    assert_eq!(report.methods.omitted_bytes, 7);
    assert_eq!(report.methods.top_components.body_bytes, 19);
    assert_eq!(report.methods.omitted_components.body_bytes, 6);
    assert_eq!(report.methods.omitted_components.gc_info_bytes, 1);
    assert_eq!(report.methods.omitted_components.exception_info_bytes, 0);
    for entry in &report.methods.entries {
        assert_eq!(
            entry.body_bytes + entry.gc_info_bytes + entry.exception_info_bytes,
            entry.bytes
        );
    }
}

#[test]
fn fused_method_selection_reconciles_filtered_components_at_top_boundaries() {
    let mut image = Image::new();
    image.method("keep B", [2, 3, 1], 0x0600_0001);
    image.method("keep B", [4, 1, 2], 0x0600_0002);
    image.method("keep A", [6, 4, 3], 0x0600_0001);
    image.method("drop", [20, 2, 1], 0x0600_0001);
    image.sized_name(1, "type", 5);
    image.blob("Metadata", 7);
    let bytes = image.bytes();
    for top in [0, 1, 2, 3] {
        let projection = project_insights(
            &bytes,
            LIMIT,
            &options(top, Some("keep"), vec![]),
            InsightKind::Methods,
        )
        .unwrap();
        assert_eq!(projection.summary.accounted_size_bytes, 61);
        let InsightProjection::Methods(report) = projection.data else {
            panic!("method projection")
        };
        assert_eq!(report.accounted_denominator_bytes, 61);
        assert_eq!(report.total, counts(49, 3, 4));
        assert_eq!(report.matched, counts(26, 2, 3));
        assert_eq!(report.total_components.body_bytes, 32);
        assert_eq!(report.total_components.gc_info_bytes, 10);
        assert_eq!(report.total_components.exception_info_bytes, 7);
        assert_eq!(report.matched_components.body_bytes, 12);
        assert_eq!(report.matched_components.gc_info_bytes, 8);
        assert_eq!(report.matched_components.exception_info_bytes, 6);
        let length = top.min(2) as u64;
        assert_eq!(report.entries.len() as u64, length);
        assert_eq!(report.top_bytes, 13 * length);
        assert_eq!(report.omitted_bytes, 26 - 13 * length);
        assert_eq!(report.top_components.body_bytes, 6 * length);
        assert_eq!(report.top_components.gc_info_bytes, 4 * length);
        assert_eq!(report.top_components.exception_info_bytes, 3 * length);
        assert_eq!(report.omitted_components.body_bytes, 12 - 6 * length);
        assert_eq!(report.omitted_components.gc_info_bytes, 8 - 4 * length);
        assert_eq!(
            report.omitted_components.exception_info_bytes,
            6 - 3 * length
        );
        for (entry, (identity, records)) in
            report.entries.iter().zip([("keep A", 1), ("keep B", 2)])
        {
            assert_eq!(entry.identity, identity);
            assert_eq!(entry.records, records);
            assert_eq!(entry.bytes, 13);
            assert_eq!(entry.body_bytes, 6);
            assert_eq!(entry.gc_info_bytes, 4);
            assert_eq!(entry.exception_info_bytes, 3);
            assert_eq!(entry.accounted_basis_points, 2131);
        }
    }
}

#[test]
fn methods_filter_full_unicode_identity_beyond_preview_boundary() {
    let mut image = Image::new();
    let prefix = "日".repeat(100);
    image.method(&format!("{prefix}needle"), [1, 2, 3], 0x0600_0001);
    image.method(&format!("{prefix}other"), [9, 0, 0], 0x0600_0001);
    let report = insights(
        &image.bytes(),
        LIMIT,
        &options(1, Some("needle"), vec![rule("tail", &["needle"], None)]),
    )
    .unwrap();
    assert_eq!(report.methods.total.bytes, 15);
    assert_eq!(report.methods.matched, counts(6, 1, 1));
    assert_eq!(report.methods.matched_components.gc_info_bytes, 2);
    assert_eq!(report.methods.matched_components.exception_info_bytes, 3);
    assert_eq!(report.methods.entries[0].identity, "日".repeat(85));
    assert_eq!(report.methods.entries[0].identity_bytes, 306);
    assert!(report.methods.entries[0].truncated);
    assert_eq!(report.cohorts.cohorts[0].accounted, counts(6, 1, 1));
}

#[test]
fn resources_group_exact_assembly_culture_and_unicode_name_without_collisions() {
    let report = insights(&representative(), LIMIT, &options(10, None, vec![])).unwrap();
    let resources = &report.resources;
    assert!(!resources.accounted);
    assert!(resources.warning.contains("Blobs"));
    reconcile_resources(&resources.by_assembly);
    reconcile_resources(&resources.by_culture);
    reconcile_resources(&resources.by_resource_name);
    assert_eq!(resources.by_assembly.total_groups, 3);
    let groups = &resources.by_assembly.groups;
    assert_eq!(
        (
            groups[0].key.name.as_str(),
            groups[0].key.culture.as_str(),
            groups[0].total.bytes
        ),
        ("Example", "", 16)
    );
    assert_eq!(
        (
            groups[1].key.name.as_str(),
            groups[1].key.culture.as_str(),
            groups[1].total.bytes
        ),
        ("Example", "fr-FR", 5)
    );
    assert_eq!(
        (
            groups[2].key.name.as_str(),
            groups[2].key.culture.as_str(),
            groups[2].total.bytes
        ),
        ("Example, Culture=fr-FR", "", 4)
    );
    assert_eq!(groups[0].entries[0].records, 2);
    assert_eq!(resources.by_culture.total_groups, 2);
    assert_eq!(
        (
            resources.by_culture.groups[0].key.as_str(),
            resources.by_culture.groups[0].total.bytes
        ),
        ("", 20)
    );
    assert_eq!(resources.by_resource_name.total_groups, 2);
    assert_eq!(
        (
            resources.by_resource_name.groups[0].key.as_str(),
            resources.by_resource_name.groups[0].total.bytes
        ),
        ("日本😀.resources", 19)
    );
}

#[test]
fn resource_filters_and_top_views_reconcile_independently() {
    for top in [0, 1, 2, 3, 5] {
        let report = insights(
            &representative(),
            LIMIT,
            &options(top, Some("日本😀"), vec![]),
        )
        .unwrap();
        let resources = &report.resources;
        reconcile_resources(&resources.by_assembly);
        reconcile_resources(&resources.by_culture);
        reconcile_resources(&resources.by_resource_name);
        assert_eq!(resources.by_assembly.matched, counts(19, 3, 4));
        assert_eq!(resources.by_culture.matched, counts(19, 3, 4));
        assert_eq!(resources.by_resource_name.matched, counts(19, 3, 4));
        assert!(resources.by_assembly.groups.len() <= top);
        assert!(resources.by_culture.groups.len() <= top);
        assert!(resources.by_resource_name.groups.len() <= top);
    }
    let report = insights(&representative(), LIMIT, &options(1, Some("fr-FR"), vec![])).unwrap();
    assert_eq!(report.resources.by_assembly.matched, counts(9, 2, 2));
    assert_eq!(report.resources.by_assembly.top_bytes, 5);
    assert_eq!(report.resources.by_assembly.omitted_bytes, 4);
    assert_eq!(report.resources.by_culture.matched_groups, 2);
    let report = insights(
        &representative(),
        LIMIT,
        &options(10, Some("Example, Culture=fr-FR"), vec![]),
    )
    .unwrap();
    assert_eq!(report.resources.by_assembly.matched.bytes, 9);
}

#[test]
fn full_group_labels_remain_distinct_past_display_cap() {
    let mut image = Image::new();
    let prefix = "日".repeat(100);
    for (suffix, size) in [("one", 3), ("two", 2)] {
        image.resource(1, &format!("{prefix}{suffix}"), size);
        image.method(&format!("{prefix}{suffix}<X>"), [size, 0, 0], 0x0600_0001);
    }
    let report = insights(&image.bytes(), LIMIT, &options(2, None, vec![])).unwrap();
    let resources = &report.resources.by_resource_name.groups;
    assert_eq!(resources.len(), 2);
    assert_eq!(resources[0].key, format!("{prefix}one"));
    assert_eq!(resources[1].key, format!("{prefix}two"));
    assert!(resources.iter().all(|group| group.entries[0].truncated));
    let families = &report.generics.sections[0].families;
    assert_eq!(families.len(), 2);
    assert_eq!(families[0].prefix, format!("{prefix}one"));
    assert_eq!(families[1].prefix, format!("{prefix}two"));
}

#[test]
fn cohorts_or_predicates_intersections_and_stream_counts_are_not_additive() {
    let rules = vec![
        rule("all F", &["F", "F<T>"], None),
        rule("method F", &["F<T>", "F<U>"], Some("Methods")),
        rule("unicode", &["日本😀"], None),
        rule("missing", &["not present"], None),
    ];
    let report = insights(&representative(), LIMIT, &options(2, None, rules)).unwrap();
    let cohorts = &report.cohorts;
    assert_eq!(cohorts.accounted_denominator_bytes, 77);
    assert_eq!(cohorts.cohorts[0].accounted, counts(36, 3, 4));
    assert_eq!(cohorts.cohorts[0].non_accounted, counts(20, 5, 6));
    assert_eq!(cohorts.cohorts[0].sections[0].matched, counts(25, 2, 3));
    assert_eq!(cohorts.cohorts[0].sections[4].matched, counts(9, 1, 2));
    assert_eq!(cohorts.cohorts[0].sections[6].matched, counts(0, 1, 1));
    assert_eq!(cohorts.cohorts[1].accounted, counts(25, 2, 3));
    assert_eq!(cohorts.cohorts[1].non_accounted, counts(0, 0, 0));
    assert_eq!(cohorts.cohorts[2].accounted, counts(7, 1, 1));
    assert_eq!(cohorts.cohorts[2].non_accounted, counts(19, 3, 4));
    assert_eq!(cohorts.cohorts[3].accounted, counts(0, 0, 0));
    assert_eq!(cohorts.cohorts[3].examples, Vec::new());
    assert_eq!(cohorts.union_accounted, counts(43, 4, 5));
    assert_eq!(cohorts.union_non_accounted, counts(30, 6, 8));
    assert_eq!(cohorts.multiply_matched_accounted, counts(25, 2, 3));
    assert_eq!(cohorts.multiply_matched_non_accounted, counts(9, 2, 2));
    assert_eq!(cohorts.intersections.len(), 2);
    assert_eq!(
        (
            cohorts.intersections[0].left,
            cohorts.intersections[0].right
        ),
        (0, 1)
    );
    assert_eq!(cohorts.intersections[0].accounted, counts(25, 2, 3));
    assert_eq!(
        (
            cohorts.intersections[1].left,
            cohorts.intersections[1].right
        ),
        (0, 2)
    );
    assert_eq!(cohorts.intersections[1].non_accounted, counts(9, 2, 2));
    assert!(cohorts.warning.contains("never sum"));
    assert_eq!(cohorts.cohorts[0].examples.len(), 2);
    assert_eq!(cohorts.cohorts[0].examples[0].stream, "Methods");
    assert_eq!(cohorts.cohorts[0].examples[0].entry.bytes, 20);
}

#[test]
fn cohort_examples_preserve_stream_and_full_identity_ties_at_top_boundaries() {
    let mut image = Image::new();
    let prefix = "n".repeat(300);
    let first = format!("{prefix}A");
    let second = format!("{prefix}B");
    image.method(&second, [10, 0, 0], 0x0600_0001);
    image.method(&first, [4, 0, 0], 0x0600_0001);
    image.method(&first, [6, 0, 0], 0x0600_0002);
    image.sized_name(1, "n type", 10);
    image.blob("n blob", 10);
    image.dedup("n folded");
    let bytes = image.bytes();
    let expected = [
        ("Methods", "n".repeat(256), 10, 2, 301),
        ("Methods", "n".repeat(256), 10, 1, 301),
        ("Types", "n type".to_owned(), 10, 1, 6),
        ("Blobs", "n blob".to_owned(), 10, 1, 12),
        ("DeduplicatedMethods", "n folded".to_owned(), 0, 1, 8),
    ];
    for top in [0, 1, 2, 3, 4, 5, 6] {
        let report = insights(
            &bytes,
            LIMIT,
            &options(top, None, vec![rule("n", &["n"], None)]),
        )
        .unwrap();
        let cohort = &report.cohorts.cohorts[0];
        assert_eq!(cohort.accounted, counts(40, 4, 5));
        assert_eq!(cohort.non_accounted, counts(0, 1, 1));
        assert_eq!(cohort.examples.len(), top.min(expected.len()));
        for (example, (stream, identity, size, records, identity_bytes)) in
            cohort.examples.iter().zip(&expected)
        {
            assert_eq!(example.stream, *stream);
            assert_eq!(example.entry.identity, *identity);
            assert_eq!(example.entry.bytes, *size);
            assert_eq!(example.entry.records, *records);
            assert_eq!(example.entry.identity_bytes, *identity_bytes);
            assert_eq!(example.entry.truncated, *stream == "Methods");
        }
    }
}

#[test]
fn fused_cohort_examples_intersect_filters_scopes_and_keep_zero_byte_members() {
    let mut image = Image::new();
    image.method("keep A", [10, 0, 0], 0x0600_0001);
    image.method("keep B", [5, 0, 0], 0x0600_0001);
    image.method("drop A", [100, 0, 0], 0x0600_0001);
    image.blob("keep B", 4);
    image.resource(1, "keep A", 2);
    image.dedup("keep A");
    let bytes = image.bytes();
    let expected = [
        ("Methods", "keep A", 10),
        ("Methods", "keep B", 5),
        ("Blobs", "keep B", 4),
        ("ManifestResources", "Example!keep A", 2),
        ("DeduplicatedMethods", "keep A", 0),
    ];
    for top in [0, 1, 10] {
        let report = insights(
            &bytes,
            LIMIT,
            &options(
                top,
                Some("keep"),
                vec![
                    rule("all", &["keep", "keep A"], None),
                    rule("method A", &["A"], Some("Methods")),
                    rule("absent", &["missing"], None),
                ],
            ),
        )
        .unwrap();
        let all = &report.cohorts.cohorts[0];
        assert_eq!(all.accounted, counts(19, 3, 3));
        assert_eq!(all.non_accounted, counts(2, 2, 2));
        assert_eq!(all.examples.len(), top.min(expected.len()));
        for (example, (stream, identity, size)) in all.examples.iter().zip(&expected) {
            assert_eq!(example.stream, *stream);
            assert_eq!(example.entry.identity, *identity);
            assert_eq!(example.entry.bytes, *size);
            assert_eq!(example.entry.records, 1);
        }
        let scoped = &report.cohorts.cohorts[1];
        assert_eq!(scoped.accounted, counts(10, 1, 1));
        assert_eq!(scoped.non_accounted, counts(0, 0, 0));
        assert_eq!(scoped.examples.len(), usize::from(top > 0));
        if top > 0 {
            assert_eq!(scoped.examples[0].stream, "Methods");
            assert_eq!(scoped.examples[0].entry.identity, "keep A");
        }
        assert_eq!(report.cohorts.cohorts[2].examples, Vec::new());
        assert_eq!(report.cohorts.union_accounted, counts(19, 3, 3));
        assert_eq!(report.cohorts.union_non_accounted, counts(2, 2, 2));
        assert_eq!(report.cohorts.intersections.len(), 1);
        assert_eq!(report.cohorts.intersections[0].accounted, counts(10, 1, 1));
        assert_eq!(
            report.cohorts.intersections[0].non_accounted,
            counts(0, 0, 0)
        );
    }
}

#[test]
fn cohort_matching_is_case_sensitive_and_utf16_aligned() {
    let mut image = Image::new();
    image.method("A", [2, 0, 0], 0x0600_0001);
    image.blob("\u{4100}\u{100}", 5);
    image.blob("A😀", 7);
    image.resource(1, "\u{4100}\u{100}", 11);
    image.resource(1, "A😀", 13);
    let rules = vec![
        rule("upper", &["A"], None),
        rule("lower", &["a"], Some("Methods")),
        rule("emoji", &["😀"], None),
    ];
    let report = insights(&image.bytes(), LIMIT, &options(5, None, rules)).unwrap();
    assert_eq!(report.cohorts.cohorts[0].accounted, counts(9, 2, 2));
    assert_eq!(report.cohorts.cohorts[0].non_accounted, counts(13, 1, 1));
    assert_eq!(report.cohorts.cohorts[1].accounted, counts(0, 0, 0));
    assert_eq!(report.cohorts.cohorts[2].accounted, counts(7, 1, 1));
    assert_eq!(report.cohorts.cohorts[2].non_accounted, counts(13, 1, 1));
}

#[test]
fn global_filter_intersects_cohort_rules_on_full_names() {
    let bytes = representative();
    let report = insights(
        &bytes,
        LIMIT,
        &options(1, Some("F<T>"), vec![rule("F", &["F"], None)]),
    )
    .unwrap();
    assert_eq!(report.cohorts.cohorts[0].accounted, counts(20, 1, 2));
    assert_eq!(report.cohorts.cohorts[0].non_accounted, counts(9, 2, 3));
    assert_eq!(report.methods.matched.bytes, 20);
    assert_eq!(
        report.generics.sections[0].matched_generic_shaped,
        counts(20, 1, 2)
    );
    assert_eq!(report.generics.sections[0].families[0].total.bytes, 25);
    assert_eq!(report.generics.sections[0].families[0].matched.bytes, 20);
}

#[test]
fn invalid_cohort_rules_are_typed_errors_but_all_seven_streams_are_valid() {
    let bytes = representative();
    for rules in [
        vec![rule("", &["F"], None)],
        vec![rule("  ", &["F"], None)],
        vec![rule("empty", &[], None)],
        vec![rule("empty", &["F", ""], None)],
        vec![rule("stream", &["F"], Some("methods"))],
        vec![
            rule("duplicate", &["F"], None),
            rule("duplicate", &["T"], None),
        ],
    ] {
        let error = insights(&bytes, LIMIT, &options(1, None, rules)).unwrap_err();
        assert_eq!(error.diagnostic.code, "mstat.insights.rule");
    }
    for stream in [
        "Methods",
        "Types",
        "Blobs",
        "RvaFields",
        "FrozenObjects",
        "ManifestResources",
        "DeduplicatedMethods",
    ] {
        let report = insights(
            &bytes,
            LIMIT,
            &options(
                1,
                None,
                vec![rule(stream, &["F", "T", "日本"], Some(stream))],
            ),
        )
        .unwrap();
        assert_eq!(
            report.cohorts.cohorts[0]
                .sections
                .iter()
                .filter(|section| section.matched.identities > 0)
                .count(),
            1
        );
        assert_eq!(report.cohorts.cohorts[0].examples[0].stream, stream);
    }
}

#[test]
fn insights_caps_rules_names_patterns_top_and_exact_resource_labels() {
    let bytes = representative();
    let too_many = (0..65)
        .map(|index| rule(&format!("r{index}"), &["F"], None))
        .collect();
    let patterns = vec!["F"; 65];
    for option in [
        options(usize::MAX, None, vec![]),
        options(1, None, too_many),
        options(1, None, vec![rule(&"n".repeat(257), &["F"], None)]),
        options(1, None, vec![rule("patterns", &patterns, None)]),
        options(
            1,
            None,
            vec![rule("bytes", &[&"p".repeat(1_048_577)], None)],
        ),
    ] {
        assert_eq!(
            insights(&bytes, LIMIT, &option)
                .unwrap_err()
                .diagnostic
                .code,
            "resource.memory_limit"
        );
    }
    assert_eq!(
        insights(&bytes, 32 * 1024, &options(0, None, vec![]))
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    let mut image = Image::new();
    image.resource(1, &"x".repeat(80_000), 3);
    let bytes = image.bytes();
    assert_eq!(
        insights(&bytes, 96 * 1024, &options(1, None, vec![]))
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    let totals = insights(&bytes, 96 * 1024, &options(0, None, vec![])).unwrap();
    assert_eq!(totals.resources.by_resource_name.total.bytes, 3);
    assert!(totals.summary.peak_tracked_memory_bytes <= 96 * 1024);
}

#[test]
fn cohort_cap_boundaries_and_retained_rule_state_respect_memory() {
    let bytes = representative();
    let names: Vec<String> = (0..64)
        .map(|index| format!("{index:02}{}", "n".repeat(254)))
        .collect();
    let rules = names
        .iter()
        .map(|name| rule(name, &["F"; 64], Some("Methods")))
        .collect();
    let accepted = insights(&bytes, LIMIT, &options(0, None, rules)).unwrap();
    assert_eq!(accepted.cohorts.cohorts.len(), 64);
    assert_eq!(accepted.cohorts.intersections.len(), 64 * 63 / 2);
    assert_eq!(accepted.cohorts.union_accounted, counts(25, 2, 3));
    assert_eq!(
        accepted.cohorts.multiply_matched_accounted,
        counts(25, 2, 3)
    );
    assert!(accepted.summary.peak_tracked_memory_bytes <= LIMIT);

    let pattern = "p".repeat(128);
    let rules = (0..8)
        .map(|index| rule(&format!("r{index}"), &[pattern.as_str(); 64], None))
        .collect();
    let error = insights(&bytes, 256 * 1024, &options(0, None, rules)).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
}

#[test]
fn three_way_cohort_overlap_counts_union_once_and_each_pair_once() {
    let mut image = Image::new();
    image.method("Test", [3, 0, 0], 0x0600_0001);
    image.dedup("Test");
    let rules = vec![
        rule("first", &["T"], None),
        rule("second", &["Te"], None),
        rule("third", &["Test"], None),
    ];
    let report = insights(&image.bytes(), LIMIT, &options(0, None, rules)).unwrap();
    assert_eq!(report.cohorts.union_accounted, counts(3, 1, 1));
    assert_eq!(report.cohorts.multiply_matched_accounted, counts(3, 1, 1));
    assert_eq!(report.cohorts.union_non_accounted, counts(0, 1, 1));
    assert_eq!(
        report.cohorts.multiply_matched_non_accounted,
        counts(0, 1, 1)
    );
    assert_eq!(report.cohorts.intersections.len(), 3);
    for pair in &report.cohorts.intersections {
        assert_eq!(pair.accounted, counts(3, 1, 1));
        assert_eq!(pair.non_accounted, counts(0, 1, 1));
    }
}

#[test]
fn generic_shaped_families_are_literal_prefixes_not_instantiation_claims() {
    let report = insights(&representative(), LIMIT, &options(1, None, vec![])).unwrap();
    let methods = &report.generics.sections[0];
    assert_eq!(methods.stream, "Methods");
    assert_eq!(methods.total, counts(32, 5, 6));
    assert_eq!(methods.generic_shaped, counts(28, 4, 5));
    assert_eq!(methods.non_generic_shaped, counts(4, 1, 1));
    assert_eq!(methods.total_families, 3);
    assert_eq!(methods.families[0].prefix, "F");
    assert_eq!(methods.families[0].total, counts(25, 2, 3));
    assert_eq!(methods.top_bytes, 25);
    assert_eq!(methods.omitted_bytes, 3);
    assert_eq!(methods.families[0].examples.len(), 1);
    assert_eq!(methods.families[0].top_bytes, 20);
    assert_eq!(methods.families[0].omitted_bytes, 5);
    let types = &report.generics.sections[1];
    assert_eq!(types.generic_shaped, counts(23, 3, 3));
    assert_eq!(types.non_generic_shaped, counts(4, 1, 1));
    assert_eq!(types.families[0].prefix, "T");
    assert!(report.generics.caveat.contains("not proof"));
    let full = insights(&representative(), LIMIT, &options(3, None, vec![])).unwrap();
    assert_eq!(full.generics.sections[0].families[1].prefix, "Odd");
    assert_eq!(full.generics.sections[0].families[2].prefix, "");
}

#[test]
fn generic_family_ranges_preserve_exact_prefix_order_counts_and_examples() {
    let mut image = Image::new();
    for (name, size) in [
        ("A!<x>", 9),
        ("A<one>", 5),
        ("A<two>", 4),
        ("A?<x>", 9),
        ("A.<x>", 9),
        ("<anon>", 1),
        ("Plain", 3),
    ] {
        image.method(name, [size, 0, 0], 0x0600_0001);
        image.sized_name(1, name, size);
    }
    let bytes = image.bytes();
    let report = insights(&bytes, LIMIT, &options(4, None, vec![])).unwrap();
    for section in &report.generics.sections {
        assert_eq!(section.total, counts(40, 7, 7));
        assert_eq!(section.generic_shaped, counts(37, 6, 6));
        assert_eq!(section.non_generic_shaped, counts(3, 1, 1));
        assert_eq!(section.total_families, 5);
        assert_eq!(section.top_bytes, 36);
        assert_eq!(section.omitted_bytes, 1);
        assert_eq!(
            section
                .families
                .iter()
                .map(|family| family.prefix.as_str())
                .collect::<Vec<_>>(),
            ["A", "A!", "A.", "A?"]
        );
        let family = &section.families[0];
        assert_eq!(family.total, counts(9, 2, 2));
        assert_eq!(family.examples[0].identity, "A<one>");
        assert_eq!(family.examples[1].identity, "A<two>");
    }
    let filtered = insights(&bytes, LIMIT, &options(1, Some("two"), vec![])).unwrap();
    for section in &filtered.generics.sections {
        assert_eq!(section.matched_generic_shaped, counts(4, 1, 1));
        assert_eq!(section.families[0].total, counts(9, 2, 2));
        assert_eq!(section.families[0].matched, counts(4, 1, 1));
        assert_eq!(section.families[0].examples[0].identity, "A<two>");
    }
}

#[test]
fn empty_streams_and_no_matches_are_valid_zero_reports() {
    let empty = insights(&Image::new().bytes(), LIMIT, &InsightsOptions::default()).unwrap();
    assert_eq!(empty.summary.accounted_size_bytes, 0);
    assert_eq!(empty.methods.total, counts(0, 0, 0));
    assert_eq!(empty.methods.entries, Vec::new());
    assert_eq!(empty.resources.by_assembly.total_groups, 0);
    assert_eq!(empty.resources.by_culture.total_groups, 0);
    assert_eq!(empty.resources.by_resource_name.total_groups, 0);
    assert!(
        empty
            .generics
            .sections
            .iter()
            .all(|section| section.total == counts(0, 0, 0) && section.families.is_empty())
    );
    assert_eq!(empty.cohorts.cohorts, Vec::new());
    let absent = insights(
        &representative(),
        LIMIT,
        &options(2, Some("absent"), vec![rule("no matches", &["F"], None)]),
    )
    .unwrap();
    assert_eq!(absent.methods.total.bytes, 32);
    assert_eq!(absent.methods.matched, counts(0, 0, 0));
    assert_eq!(absent.methods.omitted_bytes, 0);
    assert_eq!(absent.resources.by_resource_name.total.bytes, 25);
    assert_eq!(absent.resources.by_resource_name.matched_groups, 0);
    assert_eq!(absent.generics.sections[0].matched_families, 0);
    assert_eq!(absent.cohorts.cohorts[0].accounted, counts(0, 0, 0));
}

#[test]
fn top_boundaries_preserve_totals_and_deterministic_ties() {
    let mut image = Image::new();
    image.method("B<X>", [1, 0, 0], 0x0600_0001);
    image.method("A<X>", [1, 0, 0], 0x0600_0001);
    let bytes = image.bytes();
    for top in [0, 1, 2, 3] {
        let report = insights(&bytes, LIMIT, &options(top, None, vec![])).unwrap();
        assert_eq!(report.methods.total, counts(2, 2, 2));
        assert_eq!(report.methods.entries.len(), top.min(2));
        assert_eq!(report.methods.top_bytes, u64::try_from(top.min(2)).unwrap());
        assert_eq!(report.methods.omitted_bytes, 2 - report.methods.top_bytes);
        assert_eq!(report.generics.sections[0].families.len(), top.min(2));
        if top > 0 {
            assert_eq!(report.methods.entries[0].identity, "A<X>");
            assert_eq!(report.generics.sections[0].families[0].prefix, "A");
        }
    }
}

#[test]
fn zero_byte_identities_remain_visible_and_have_zero_basis_points() {
    let mut image = Image::new();
    image.method("Zero", [0, 0, 0], 0x0600_0001);
    image.resource(1, "Zero", 0);
    image.dedup("Zero");
    let report = insights(
        &image.bytes(),
        LIMIT,
        &options(1, None, vec![rule("zero", &["Zero"], None)]),
    )
    .unwrap();
    assert_eq!(report.methods.total, counts(0, 1, 1));
    assert_eq!(report.methods.entries.len(), 1);
    assert_eq!(report.methods.entries[0].accounted_basis_points, 0);
    assert_eq!(report.resources.by_resource_name.matched_groups, 1);
    assert_eq!(report.cohorts.cohorts[0].non_accounted, counts(0, 2, 2));
}

#[test]
fn insights_json_is_versioned_deterministic_and_round_trips() {
    assert_eq!(InsightsOptions::default().top, 20);
    let options: InsightsOptions = serde_json::from_str(
        r#"{"top":2,"contains":null,"rules":[{"name":"F","contains":["F"],"stream":null}]}"#,
    )
    .unwrap();
    let bytes = representative();
    let first = insights(&bytes, LIMIT, &options).unwrap();
    let second = insights(&bytes, LIMIT, &options).unwrap();
    assert_eq!(first.schema, "vitnet.mstat-insights.v1");
    let json = serde_json::to_string(&first).unwrap();
    assert_eq!(json, serde_json::to_string(&second).unwrap());
    assert_eq!(first, serde_json::from_str::<MstatInsights>(&json).unwrap());
}

#[test]
fn checked_insights_parser_rejects_corrupt_input_and_attaches_path() {
    let mut fixture = super::fixture();
    fixture.bytes[fixture.methods_code_offset] = 0xff;
    let error = insights(&fixture.bytes, LIMIT, &options(1, None, vec![])).unwrap_err();
    assert_eq!(error.diagnostic.code, "mstat.il.opcode");
    assert_eq!(
        error.diagnostic.byte_offset,
        Some(fixture.methods_code_offset as u64 + 1)
    );
    let path = std::env::temp_dir().join(format!(
        "vitnet-insights-generated-{}.mstat",
        std::process::id()
    ));
    std::fs::write(&path, representative()).unwrap();
    let mapped = insights_path(&path, LIMIT, &options(1, None, vec![])).unwrap();
    assert_eq!(mapped.methods.total.bytes, 32);
    std::fs::write(&path, &fixture.bytes).unwrap();
    let error = insights_path(&path, LIMIT, &options(1, None, vec![])).unwrap_err();
    assert_eq!(error.diagnostic.input_path.as_deref(), Some(path.as_path()));
    std::fs::remove_file(&path).unwrap();
}

fn sum_insight_counts(values: impl IntoIterator<Item = InsightCounts>) -> InsightCounts {
    values.into_iter().fold(counts(0, 0, 0), |sum, value| {
        counts(
            sum.bytes + value.bytes,
            sum.identities + value.identities,
            sum.records + value.records,
        )
    })
}

fn method_band_fixture() -> (Vec<u8>, Vec<(String, InsightCounts)>) {
    let mut image = Image::new();
    let mut expected = Vec::new();
    for size in [
        0, 1, 128, 254, 255, 256, 257, 2048, 4094, 4095, 4096, 4097, 32768, 65534, 65535, 65536,
        65537,
    ] {
        let name = match size {
            256 => format!("{}other", "n".repeat(300)),
            257 => format!("{}needle", "n".repeat(300)),
            _ => format!("band-{size}"),
        };
        image.method(&name, [size, 0, 0], 0x0600_0001);
        expected.push((name, counts(u64::try_from(size).unwrap(), 1, 1)));
    }
    image.method("coalesced", [127, 0, 0], 0x0600_0001);
    image.method("coalesced", [129, 0, 0], 0x0600_0002);
    expected.push(("coalesced".into(), counts(256, 1, 2)));
    image.method("components", [200, 40, 16], 0x0600_0001);
    expected.push(("components".into(), counts(256, 1, 1)));
    (image.bytes(), expected)
}

fn assert_method_bands(
    report: &vitnet_mstat::MethodsInsightReport,
    total: [InsightCounts; 5],
    matched: [InsightCounts; 5],
) {
    let bounds = [
        (0, Some(0)),
        (1, Some(255)),
        (256, Some(4095)),
        (4096, Some(65535)),
        (65536, None),
    ];
    assert_eq!(report.size_bands.len(), 5);
    for (index, band) in report.size_bands.iter().enumerate() {
        assert_eq!(
            (band.minimum_bytes, band.maximum_bytes),
            bounds[index],
            "band {index}"
        );
        assert_eq!(band.total, total[index], "total band {index}");
        assert_eq!(band.matched, matched[index], "matched band {index}");
    }
    assert_eq!(sum_insight_counts(total), report.total);
    assert_eq!(sum_insight_counts(matched), report.matched);
}

#[test]
fn method_size_bands_classify_coalesced_component_totals() {
    let (bytes, _) = method_band_fixture();
    let report = insights(&bytes, LIMIT, &options(20, None, vec![])).unwrap();
    let expected = [
        counts(0, 1, 1),
        counts(638, 4, 4),
        counts(11262, 7, 8),
        counts(172_030, 5, 5),
        counts(131_073, 2, 2),
    ];
    assert_method_bands(&report.methods, expected, expected);
    assert_eq!(report.methods.total, counts(315_003, 19, 20));
    assert_eq!(report.methods.total_components.body_bytes, 314_947);
    assert_eq!(report.methods.total_components.gc_info_bytes, 40);
    assert_eq!(report.methods.total_components.exception_info_bytes, 16);
    assert_eq!(
        report.methods.total.bytes,
        report.summary.accounted_size_bytes
    );
    assert_eq!(report.methods.entries.len(), 19);
    for (name, records, components) in [
        ("coalesced", 2, (256, 0, 0)),
        ("components", 1, (200, 40, 16)),
    ] {
        let entry = report
            .methods
            .entries
            .iter()
            .find(|entry| entry.identity == name)
            .unwrap();
        assert_eq!((entry.bytes, entry.records), (256, records));
        assert_eq!(
            (
                entry.body_bytes,
                entry.gc_info_bytes,
                entry.exception_info_bytes
            ),
            components
        );
    }
    for entry in &report.methods.entries {
        assert_eq!(
            entry.body_bytes + entry.gc_info_bytes + entry.exception_info_bytes,
            entry.bytes
        );
    }

    let mut singleton = Image::new();
    singleton.method("zero", [0, 0, 0], 0x0600_0001);
    let singleton = insights(&singleton.bytes(), LIMIT, &options(1, None, vec![])).unwrap();
    let expected = [
        counts(0, 1, 1),
        counts(0, 0, 0),
        counts(0, 0, 0),
        counts(0, 0, 0),
        counts(0, 0, 0),
    ];
    assert_method_bands(&singleton.methods, expected, expected);
    assert_eq!(singleton.methods.entries[0].identity, "zero");

    let mut wide = Image::new();
    wide.method("wide", [i32::MAX; 3], 0x0600_0001);
    wide.method("wide", [i32::MAX; 3], 0x0600_0002);
    let bytes = wide.bytes();
    for top in [0, 1] {
        let report = insights(&bytes, LIMIT, &options(top, Some("wide"), vec![])).unwrap();
        let expected = [
            counts(0, 0, 0),
            counts(0, 0, 0),
            counts(0, 0, 0),
            counts(0, 0, 0),
            counts(12_884_901_882, 1, 2),
        ];
        assert_method_bands(&report.methods, expected, expected);
        assert_eq!(report.methods.total_components.body_bytes, 4_294_967_294);
        assert_eq!(report.methods.total_components.gc_info_bytes, 4_294_967_294);
        assert_eq!(
            report.methods.total_components.exception_info_bytes,
            4_294_967_294
        );
        assert_eq!(report.summary.accounted_size_bytes, 12_884_901_882);
    }
}

#[test]
fn method_size_bands_reconcile_across_filters_tops_and_projection() {
    let (bytes, identities) = method_band_fixture();
    let total = [
        counts(0, 1, 1),
        counts(638, 4, 4),
        counts(11262, 7, 8),
        counts(172_030, 5, 5),
        counts(131_073, 2, 2),
    ];
    for contains in [
        None,
        Some(""),
        Some("band-4"),
        Some("absent"),
        Some("needle"),
    ] {
        let matching: Vec<_> = identities
            .iter()
            .filter(|(name, _)| contains.is_none_or(|needle| name.contains(needle)))
            .collect();
        let mut matched = [counts(0, 0, 0); 5];
        for (_, value) in &matching {
            let index = [
                (0, 0),
                (1, 255),
                (256, 4095),
                (4096, 65535),
                (65536, u64::MAX),
            ]
            .iter()
            .position(|(min, max)| (*min..=*max).contains(&value.bytes))
            .unwrap();
            matched[index] = sum_insight_counts([matched[index], *value]);
        }
        for top in [0, 1, 19, 20] {
            let option = options(top, contains, vec![]);
            let unchanged = option.clone();
            let report = insights(&bytes, LIMIT, &option).unwrap();
            assert_method_bands(&report.methods, total, matched);
            assert_eq!(report.methods.entries.len(), top.min(matching.len()));
            assert_eq!(
                report.methods.top_bytes + report.methods.omitted_bytes,
                report.methods.matched.bytes
            );
            assert_eq!(
                report.methods.matched_components.body_bytes
                    + report.methods.matched_components.gc_info_bytes
                    + report.methods.matched_components.exception_info_bytes,
                report.methods.matched.bytes
            );
            let projected = project_insights(&bytes, LIMIT, &option, InsightKind::Methods).unwrap();
            assert_eq!(
                projected.data,
                InsightProjection::Methods(report.methods.clone())
            );
            assert_eq!(projected.summary.accounted_size_bytes, 315_003);
            assert_eq!(insights(&bytes, LIMIT, &option).unwrap(), report);
            assert_eq!(option, unchanged);
            if contains == Some("needle") && top > 0 {
                assert_eq!(report.methods.matched, counts(257, 1, 1));
                assert_eq!(report.methods.entries[0].identity, "n".repeat(256));
                assert_eq!(report.methods.entries[0].identity_bytes, 306);
                assert!(report.methods.entries[0].truncated);
            }
        }
    }
    for size in [None, Some(4096)] {
        let mut image = Image::new();
        let mut expected = [counts(0, 0, 0); 5];
        if let Some(size) = size {
            image.method("singleton", [size, 0, 0], 0x0600_0001);
            expected[3] = counts(4096, 1, 1);
        }
        let bytes = image.bytes();
        for top in [0, 1, 2] {
            let report = insights(&bytes, LIMIT, &options(top, Some(""), vec![])).unwrap();
            assert_method_bands(&report.methods, expected, expected);
            assert_eq!(
                report.methods.entries.len(),
                usize::from(size.is_some() && top > 0)
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn blob_report_preserves_full_identity_rank_and_coverage() {
    let long_a = format!("{}tail-A", "q".repeat(300));
    let long_b = format!("{}tail-B", "q".repeat(300));
    // This order is explicit: tied UTF-16LE names begin 00, 3d, 41, 65, 71, 71, e9.
    // The two long names have equal previews but different full suffixes and record counts.
    let expected = vec![
        ("heavy".to_owned(), 30, 1, "heavy".to_owned(), false),
        ("dup".to_owned(), 20, 2, "dup".to_owned(), false),
        ("\u{100}".to_owned(), 10, 1, "\u{100}".to_owned(), false),
        ("😀".to_owned(), 10, 1, "😀".to_owned(), false),
        ("A".to_owned(), 10, 1, "A".to_owned(), false),
        ("e\u{301}".to_owned(), 10, 1, "e\u{301}".to_owned(), false),
        (long_a, 10, 2, "q".repeat(256), true),
        (long_b, 10, 1, "q".repeat(256), true),
        ("é".to_owned(), 10, 1, "é".to_owned(), false),
        ("b".repeat(255), 9, 1, "b".repeat(255), false),
        ("c".repeat(256), 8, 1, "c".repeat(256), false),
        ("d".repeat(257), 7, 1, "d".repeat(256), true),
        (
            format!("{}日", "z".repeat(253)),
            6,
            1,
            format!("{}日", "z".repeat(253)),
            false,
        ),
        (
            format!("{}日", "z".repeat(254)),
            5,
            1,
            "z".repeat(254),
            true,
        ),
        (String::new(), 0, 1, String::new(), false),
        ("zero".to_owned(), 0, 1, "zero".to_owned(), false),
    ];
    let images: Vec<_> = [false, true]
        .into_iter()
        .map(|reverse| {
            let mut image = Image::new();
            let mut input: Vec<_> = expected.iter().collect();
            if reverse {
                input.reverse();
            }
            for (name, size, records, _, _) in input {
                let size = i32::try_from(*size).unwrap();
                if *records == 2 {
                    image.blob(name, size / 2);
                    image.blob(name, size - size / 2);
                } else {
                    image.blob(name, size);
                }
            }
            image.bytes()
        })
        .collect();
    for contains in [
        None,
        Some(""),
        Some("tail-A"),
        Some("A"),
        Some("é"),
        Some("e\u{301}"),
        Some("😀"),
        Some("absent"),
    ] {
        let matching: Vec<_> = expected
            .iter()
            .filter(|(name, _, _, _, _)| contains.is_none_or(|needle| name.contains(needle)))
            .collect();
        let matched = sum_insight_counts(
            matching
                .iter()
                .map(|(_, size, records, _, _)| counts(*size, 1, *records)),
        );
        for top in [0, 1, 16, 17] {
            let option = options(top, contains, vec![]);
            let first = insights(&images[0], LIMIT, &option).unwrap();
            let second = insights(&images[1], LIMIT, &option).unwrap();
            let report = &first.blobs;
            assert_eq!(report, &second.blobs);
            assert_eq!(
                serde_json::to_string(report).unwrap(),
                serde_json::to_string(&second.blobs).unwrap()
            );
            assert_eq!(report.total, counts(155, 16, 18));
            assert_eq!(first.summary.categories[2].aggregate_size_bytes, 155);
            assert_eq!(first.summary.categories[2].records, 18);
            assert_eq!(report.matched, matched);
            assert_eq!(report.dehydrated_data, counts(0, 0, 0));
            assert_eq!(report.entries.len(), top.min(matching.len()));
            let top_bytes = matching
                .iter()
                .take(top)
                .map(|(_, size, _, _, _)| *size)
                .sum::<u64>();
            assert_eq!(report.top_bytes, top_bytes);
            assert_eq!(report.omitted_bytes, matched.bytes - top_bytes);
            assert_eq!(
                report.entries.iter().map(|entry| entry.bytes).sum::<u64>(),
                top_bytes
            );
            for (entry, (name, size, records, preview, truncated)) in
                report.entries.iter().zip(&matching)
            {
                assert_eq!((entry.bytes, entry.records), (*size, *records));
                assert_eq!(&entry.identity, preview);
                assert_eq!(entry.truncated, *truncated);
                assert_eq!(
                    entry.identity_bytes,
                    (name.encode_utf16().count() * 2) as u64
                );
            }
        }
    }
    let limited = insights(&images[0], LIMIT, &options(14, None, vec![])).unwrap();
    assert_eq!(limited.blobs.omitted_bytes, 0);
    assert_eq!(limited.blobs.entries.len(), 14);
    assert_eq!(limited.blobs.matched.identities, 16);
    assert_eq!(
        limited
            .blobs
            .entries
            .iter()
            .map(|entry| entry.records)
            .sum::<u64>(),
        16
    );
    assert_eq!(limited.blobs.matched.records, 18);

    for size in [None, Some(0), Some(7)] {
        let mut image = Image::new();
        if let Some(size) = size {
            image.blob("only😀", size);
        }
        let bytes = image.bytes();
        let expected = size.map_or(counts(0, 0, 0), |size| {
            counts(u64::try_from(size).unwrap(), 1, 1)
        });
        for top in [0, 1, 2] {
            let report = insights(&bytes, LIMIT, &options(top, None, vec![]))
                .unwrap()
                .blobs;
            assert_eq!(report.total, expected);
            assert_eq!(report.matched, expected);
            assert_eq!(report.entries.len(), usize::from(size.is_some() && top > 0));
            assert_eq!(report.top_bytes, if top == 0 { 0 } else { expected.bytes });
            assert_eq!(
                report.omitted_bytes,
                if top == 0 { expected.bytes } else { 0 }
            );
            if !report.entries.is_empty() {
                assert_eq!(report.entries[0].identity, "only😀");
                assert_eq!(report.entries[0].identity_bytes, 12);
                assert!(!report.entries[0].truncated);
                assert_eq!(report.entries[0].records, 1);
            }
        }
    }

    let mut wide = Image::new();
    for _ in 0..3 {
        wide.blob("wide", i32::MAX);
    }
    let bytes = wide.bytes();
    for top in [0, 1] {
        let report = insights(&bytes, LIMIT, &options(top, Some("wide"), vec![])).unwrap();
        assert_eq!(report.blobs.total, counts(6_442_450_941, 1, 3));
        assert_eq!(report.blobs.matched, counts(6_442_450_941, 1, 3));
        assert_eq!(
            report.blobs.top_bytes,
            if top == 0 { 0 } else { 6_442_450_941 }
        );
        assert_eq!(
            report.blobs.omitted_bytes,
            if top == 0 { 6_442_450_941 } else { 0 }
        );
        assert_eq!(
            report.summary.categories[2].aggregate_size_bytes,
            6_442_450_941
        );
    }
}

#[test]
fn dehydrated_data_counts_only_exact_unfiltered_blob_identity() {
    for (sizes, expected) in [
        (vec![], counts(0, 0, 0)),
        (vec![0], counts(0, 1, 1)),
        (vec![0, 0], counts(0, 1, 2)),
        (vec![5, 0, 7], counts(12, 1, 3)),
    ] {
        let mut image = Image::new();
        for size in sizes {
            image.blob("DehydratedData", size);
        }
        for name in [
            "dehydrateddata".to_owned(),
            "Dehydrateddata".to_owned(),
            "PrefixDehydratedData".to_owned(),
            "DehydratedDataSuffix".to_owned(),
            "DehydratedData\0".to_owned(),
            format!("DehydratedData{}", "x".repeat(300)),
            format!("{}DehydratedData", "x".repeat(300)),
        ] {
            image.blob(&name, 1);
        }
        image.blob("Metadata", 5);
        image.blob("Metadata", 0);
        image.method("DehydratedData", [2, 0, 0], 0x0600_0001);
        image.resource(1, "DehydratedData", 3);
        let bytes = image.bytes();
        for top in [0, 1, 20] {
            for contains in [None, Some(""), Some("Metadata"), Some("absent")] {
                let report = insights(&bytes, LIMIT, &options(top, contains, vec![])).unwrap();
                assert_eq!(report.blobs.dehydrated_data, expected);
                assert_eq!(report.metadata_blob_bytes, 5);
                assert_eq!(report.metadata_blob_records, 2);
                assert_eq!(
                    report.blobs.total,
                    counts(
                        12 + expected.bytes,
                        8 + expected.identities,
                        9 + expected.records
                    )
                );
                assert_eq!(report.summary.accounted_size_bytes, 14 + expected.bytes);
                if contains == Some("absent") {
                    assert_eq!(report.blobs.matched, counts(0, 0, 0));
                    assert_eq!(
                        report.blobs.entries,
                        Vec::<vitnet_mstat::IdentityInsightEntry>::new()
                    );
                } else if contains == Some("Metadata") {
                    assert_eq!(report.blobs.matched, counts(5, 1, 2));
                }
                if top == 0 {
                    assert_eq!(
                        report.blobs.entries,
                        Vec::<vitnet_mstat::IdentityInsightEntry>::new()
                    );
                    assert_eq!(report.blobs.top_bytes, 0);
                    assert_eq!(report.blobs.omitted_bytes, report.blobs.matched.bytes);
                }
                let json = serde_json::to_value(&report).unwrap();
                assert_eq!(
                    json["blobs"]["dehydrated_data"],
                    serde_json::json!({
                        "bytes": expected.bytes, "identities": expected.identities, "records": expected.records
                    })
                );
            }
        }
    }
}

fn union_evidence_image(reverse: bool) -> Image {
    let mut image = Image::new();
    let needle = format!("{}needle", "n".repeat(300));
    for stream in 0..7 {
        let mut records = vec![
            (1, "hit triple".to_owned(), 3),
            (1, "hit triple".to_owned(), 7),
            (
                1,
                "hit only".to_owned(),
                i32::try_from(stream + 1).unwrap() + 1,
            ),
        ];
        if stream == 0 {
            records.extend([
                (1, needle.clone(), 1),
                (1, "hit zero".into(), 0),
                (1, "outside".into(), 100),
            ]);
        } else if stream == 2 {
            records.push((1, "hit zero".into(), 0));
        } else if stream == 5 {
            records.extend([
                (1, "hit zero".into(), 0),
                (2, "hit triple".into(), 2),
                (3, "hit triple".into(), 1),
            ]);
        }
        if reverse {
            records.reverse();
        }
        if stream == 6 {
            // One group with three folded entries: summary records=1, items=3.
            token(&mut image.bodies[6], 0x0600_0001);
            i4(&mut image.bodies[6], 3);
            for (_, name, _) in records {
                let offset = image.name(&name);
                token(&mut image.bodies[6], 0x0600_0002);
                i4(&mut image.bodies[6], offset);
            }
            continue;
        }
        for (assembly, name, size) in records {
            match stream {
                0 => image.method(&name, [size, 0, 0], 0x0600_0001),
                1 | 3 | 4 => image.sized_name(stream, &name, size),
                2 => image.blob(&name, size),
                5 => image.resource(assembly, &name, size),
                _ => unreachable!(),
            }
        }
    }
    image
}

fn union_evidence_rules() -> Vec<CohortRule> {
    vec![
        rule("all", &["hit", "needle"], None),
        rule("triple", &["triple"], None),
        rule("triple zero tail", &["triple", "zero", "needle"], None),
    ]
}

fn assert_union_rows(report: &vitnet_mstat::CohortsInsightReport, expected: [InsightCounts; 7]) {
    let names = [
        "Methods",
        "Types",
        "Blobs",
        "RvaFields",
        "FrozenObjects",
        "ManifestResources",
        "DeduplicatedMethods",
    ];
    assert_eq!(report.union_sections.len(), 7);
    for (index, row) in report.union_sections.iter().enumerate() {
        assert_eq!(row.stream, names[index]);
        assert_eq!(row.accounted, index < 3);
        assert_eq!(
            row.matched, expected[index],
            "union stream {}",
            names[index]
        );
    }
    assert_eq!(
        report.union_accounted,
        sum_insight_counts(expected[..3].iter().copied())
    );
    assert_eq!(
        report.union_non_accounted,
        sum_insight_counts(expected[3..].iter().copied())
    );
}

#[test]
fn cohort_union_sections_count_each_stream_identity_once() {
    let expected = [
        counts(13, 4, 5),
        counts(13, 2, 3),
        counts(14, 3, 4),
        counts(15, 2, 3),
        counts(16, 2, 3),
        counts(20, 5, 6),
        counts(0, 2, 3),
    ];
    for top in [0, 1, 20] {
        let option = options(top, None, union_evidence_rules());
        let forward = insights(&union_evidence_image(false).bytes(), LIMIT, &option).unwrap();
        let reverse = insights(&union_evidence_image(true).bytes(), LIMIT, &option).unwrap();
        assert_union_rows(&forward.cohorts, expected);
        assert_eq!(forward.cohorts, reverse.cohorts);
        assert_eq!(
            serde_json::to_string(&forward.cohorts).unwrap(),
            serde_json::to_string(&reverse.cohorts).unwrap()
        );
        assert_eq!(forward.cohorts.union_accounted, counts(40, 9, 12));
        assert_eq!(forward.cohorts.union_non_accounted, counts(51, 11, 15));
        assert_eq!(forward.cohorts.cohorts[0].accounted, counts(40, 9, 12));
        assert_eq!(forward.cohorts.cohorts[0].non_accounted, counts(51, 11, 15));
        assert_eq!(forward.cohorts.cohorts[1].accounted, counts(30, 3, 6));
        assert_eq!(forward.cohorts.cohorts[1].non_accounted, counts(33, 6, 10));
        assert_eq!(forward.cohorts.cohorts[2].accounted, counts(31, 6, 9));
        assert_eq!(forward.cohorts.cohorts[2].non_accounted, counts(33, 7, 11));
        assert_eq!(forward.cohorts.multiply_matched_accounted, counts(31, 6, 9));
        assert_eq!(
            forward.cohorts.multiply_matched_non_accounted,
            counts(33, 7, 11)
        );
        assert_eq!(forward.cohorts.intersections.len(), 3);
        for (pair, (left, right, accounted, non_accounted)) in
            forward.cohorts.intersections.iter().zip([
                (0, 1, counts(30, 3, 6), counts(33, 6, 10)),
                (0, 2, counts(31, 6, 9), counts(33, 7, 11)),
                (1, 2, counts(30, 3, 6), counts(33, 6, 10)),
            ])
        {
            assert_eq!((pair.left, pair.right), (left, right));
            assert_eq!(pair.accounted, accounted);
            assert_eq!(pair.non_accounted, non_accounted);
        }
        assert_eq!(forward.summary.categories[6].records, 1);
        assert_eq!(forward.summary.categories[6].items, 3);
        assert_eq!(
            forward.cohorts.union_sections[6].matched.records,
            forward.summary.categories[6].items
        );
        assert_eq!(forward.summary.accounted_size_bytes, 140);
        assert_eq!(forward.cohorts.cohorts[0].examples.len(), top.min(20));
        if top == 1 {
            let example = &forward.cohorts.cohorts[0].examples[0];
            assert_eq!(example.stream, "Methods");
            assert_eq!(example.entry.identity, "hit triple");
            assert_eq!((example.entry.bytes, example.entry.records), (10, 2));
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn cohort_union_sections_preserve_empty_and_filtered_evidence() {
    let zero = counts(0, 0, 0);
    let all = [
        counts(13, 4, 5),
        counts(13, 2, 3),
        counts(14, 3, 4),
        counts(15, 2, 3),
        counts(16, 2, 3),
        counts(20, 5, 6),
        counts(0, 2, 3),
    ];
    let cases = [
        (None, vec![], [zero; 7]),
        (None, vec![rule("missing", &["absent"], None)], [zero; 7]),
        (Some(""), union_evidence_rules(), all),
        (Some("absent"), union_evidence_rules(), [zero; 7]),
        (
            Some("triple"),
            union_evidence_rules(),
            [
                counts(10, 1, 2),
                counts(10, 1, 2),
                counts(10, 1, 2),
                counts(10, 1, 2),
                counts(10, 1, 2),
                counts(13, 3, 4),
                counts(0, 1, 2),
            ],
        ),
        (
            Some("needle"),
            union_evidence_rules(),
            [counts(1, 1, 1), zero, zero, zero, zero, zero, zero],
        ),
        (
            Some("zero"),
            union_evidence_rules(),
            [
                counts(0, 1, 1),
                zero,
                counts(0, 1, 1),
                zero,
                zero,
                counts(0, 1, 1),
                zero,
            ],
        ),
        (
            None,
            vec![rule("resources", &["hit"], Some("ManifestResources"))],
            [zero, zero, zero, zero, zero, counts(20, 5, 6), zero],
        ),
        (
            None,
            vec![rule("zero method", &["zero"], Some("Methods"))],
            [counts(0, 1, 1), zero, zero, zero, zero, zero, zero],
        ),
        (
            None,
            vec![rule("folded", &["triple"], Some("DeduplicatedMethods"))],
            [zero, zero, zero, zero, zero, zero, counts(0, 1, 2)],
        ),
    ];
    let bytes = union_evidence_image(false).bytes();
    for (contains, rules, expected) in cases {
        for top in [0, 1, 20] {
            let option = options(top, contains, rules.clone());
            let unchanged = option.clone();
            let report = insights(&bytes, LIMIT, &option).unwrap();
            assert_union_rows(&report.cohorts, expected);
            assert_eq!(report.cohorts.accounted_denominator_bytes, 140);
            assert_eq!(option, unchanged);
            if top == 0 {
                assert!(
                    report
                        .cohorts
                        .cohorts
                        .iter()
                        .all(|cohort| cohort.examples.is_empty())
                );
            }
            if contains == Some("needle") && top > 0 {
                let example = &report.cohorts.cohorts[0].examples[0].entry;
                assert_eq!(example.identity, "n".repeat(256));
                assert_eq!(example.identity_bytes, 306);
                assert!(example.truncated);
            }
        }
    }
    for stream in [None, Some(0), Some(6)] {
        let mut image = Image::new();
        let mut expected = [zero; 7];
        if stream == Some(0) {
            image.method("hit zero", [0, 0, 0], 0x0600_0001);
            expected[0] = counts(0, 1, 1);
        } else if stream == Some(6) {
            image.dedup("hit zero");
            expected[6] = counts(0, 1, 1);
        }
        let bytes = image.bytes();
        for top in [0, 1, 2] {
            let report =
                insights(&bytes, LIMIT, &options(top, None, union_evidence_rules())).unwrap();
            assert_union_rows(&report.cohorts, expected);
            assert_eq!(report.summary.accounted_size_bytes, 0);
            assert_eq!(
                report.cohorts.cohorts[0].examples.len(),
                usize::from(stream.is_some() && top > 0)
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn new_insight_evidence_composes_serializes_and_preserves_validation() {
    let mut image = union_evidence_image(false);
    image.blob("Metadata", 5);
    image.blob("Metadata", 0);
    image.blob("DehydratedData", 8);
    image.blob("DehydratedData", 0);
    let bytes = image.bytes();
    let option = options(
        1,
        None,
        vec![rule(
            "all evidence",
            &["hit", "needle", "Metadata", "DehydratedData"],
            None,
        )],
    );
    let report = insights(&bytes, LIMIT, &option).unwrap();
    let zero = counts(0, 0, 0);
    let bands = [counts(0, 1, 1), counts(113, 4, 5), zero, zero, zero];
    assert_method_bands(&report.methods, bands, bands);
    assert_eq!(report.methods.total_components.body_bytes, 113);
    assert_eq!(report.methods.total_components.gc_info_bytes, 0);
    assert_eq!(report.methods.total_components.exception_info_bytes, 0);
    assert_eq!(report.methods.top_bytes, 100);
    assert_eq!(report.methods.omitted_bytes, 13);
    assert_eq!(report.blobs.total, counts(27, 5, 8));
    assert_eq!(report.blobs.matched, counts(27, 5, 8));
    assert_eq!(report.blobs.top_bytes, 10);
    assert_eq!(report.blobs.omitted_bytes, 17);
    assert_eq!(report.blobs.entries[0].identity, "hit triple");
    assert_eq!(report.blobs.entries[0].records, 2);
    assert_eq!(report.blobs.dehydrated_data, counts(8, 1, 2));
    assert_eq!(
        (report.metadata_blob_bytes, report.metadata_blob_records),
        (5, 2)
    );
    assert_eq!(report.summary.accounted_size_bytes, 153);
    assert_eq!(
        report.methods.total.bytes
            + report.summary.categories[1].aggregate_size_bytes
            + report.blobs.total.bytes,
        153
    );
    let union = [
        counts(13, 4, 5),
        counts(13, 2, 3),
        counts(27, 5, 8),
        counts(15, 2, 3),
        counts(16, 2, 3),
        counts(20, 5, 6),
        counts(0, 2, 3),
    ];
    assert_union_rows(&report.cohorts, union);
    assert_eq!(report.cohorts.union_accounted, counts(53, 11, 16));
    assert_eq!(report.cohorts.union_non_accounted, counts(51, 11, 15));
    for total in [
        report.resources.by_assembly.total,
        report.resources.by_culture.total,
        report.resources.by_resource_name.total,
    ] {
        assert_eq!(total, counts(20, 5, 6));
    }
    for (matched, top, omitted, expected_top, expected_omitted) in [
        (
            report.resources.by_assembly.matched,
            report.resources.by_assembly.top_bytes,
            report.resources.by_assembly.omitted_bytes,
            17,
            3,
        ),
        (
            report.resources.by_culture.matched,
            report.resources.by_culture.top_bytes,
            report.resources.by_culture.omitted_bytes,
            18,
            2,
        ),
        (
            report.resources.by_resource_name.matched,
            report.resources.by_resource_name.top_bytes,
            report.resources.by_resource_name.omitted_bytes,
            13,
            7,
        ),
    ] {
        assert_eq!(matched, counts(20, 5, 6));
        assert_eq!((top, omitted), (expected_top, expected_omitted));
        assert_eq!(top + omitted, matched.bytes);
    }
    assert!(!report.resources.accounted);
    let json = serde_json::to_string(&report).unwrap();
    assert_eq!(
        json,
        serde_json::to_string(&insights(&bytes, LIMIT, &option).unwrap()).unwrap()
    );
    assert_eq!(
        serde_json::from_str::<MstatInsights>(&json).unwrap(),
        report
    );
    let mut legacy: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        legacy["methods"]["size_bands"][0],
        serde_json::json!({
            "minimum_bytes": 0, "maximum_bytes": 0,
            "total": {"bytes": 0, "identities": 1, "records": 1},
            "matched": {"bytes": 0, "identities": 1, "records": 1}
        })
    );
    assert_eq!(
        legacy["methods"]["size_bands"][4]["maximum_bytes"],
        serde_json::Value::Null
    );
    assert_eq!(
        legacy["blobs"]["total"],
        serde_json::json!({"bytes": 27, "identities": 5, "records": 8})
    );
    assert_eq!(
        legacy["blobs"]["dehydrated_data"],
        serde_json::json!({"bytes": 8, "identities": 1, "records": 2})
    );
    assert_eq!(
        legacy["cohorts"]["union_sections"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        legacy["cohorts"]["union_sections"][6],
        serde_json::json!({
            "stream": "DeduplicatedMethods", "accounted": false,
            "matched": {"bytes": 0, "identities": 2, "records": 3}
        })
    );
    assert!(
        legacy["methods"]
            .as_object_mut()
            .unwrap()
            .remove("size_bands")
            .is_some()
    );
    assert!(legacy.as_object_mut().unwrap().remove("blobs").is_some());
    assert!(
        legacy["cohorts"]
            .as_object_mut()
            .unwrap()
            .remove("union_sections")
            .is_some()
    );
    let restored: MstatInsights = serde_json::from_value(legacy).unwrap();
    let mut expected_legacy = report.clone();
    expected_legacy.methods.size_bands.clear();
    expected_legacy.blobs = vitnet_mstat::BlobInsightReport::default();
    expected_legacy.cohorts.union_sections.clear();
    assert_eq!(restored, expected_legacy);
    assert_eq!(
        restored.methods.size_bands,
        Vec::<vitnet_mstat::MethodSizeBand>::new()
    );
    assert_eq!(
        restored.cohorts.union_sections,
        Vec::<vitnet_mstat::CohortStreamCounts>::new()
    );
    assert_eq!(restored.blobs.dehydrated_data, counts(0, 0, 0));
    assert_eq!(restored.cohorts.union_accounted, counts(53, 11, 16));

    let mut invalid_images = Vec::new();
    for raw in [[0x00, 0xd8], [0x00, 0xdc]] {
        let mut invalid = Image::new();
        let offset = as_u32(invalid.user_strings.len());
        compressed(&mut invalid.user_strings, 3);
        invalid.user_strings.extend_from_slice(&raw);
        invalid.user_strings.push(1);
        invalid.bodies[2].push(0x72);
        push_u32(&mut invalid.bodies[2], 0x7000_0000 | offset);
        i4(&mut invalid.bodies[2], 0);
        invalid_images.push((invalid.bytes(), "mstat.user_string.utf16"));
    }
    let mut invalid = Image::new();
    invalid.method("hidden", [0, 0, 0], 0x0600_0001);
    invalid.bodies[0][0] = 0xff;
    invalid_images.push((invalid.bytes(), "mstat.il.opcode"));
    for (bytes, code) in invalid_images {
        let expected = summarize(&bytes, LIMIT).unwrap_err().diagnostic;
        assert_eq!(expected.code, code);
        assert!(expected.byte_offset.is_some());
        for top in [0, 1] {
            let error = insights(&bytes, LIMIT, &options(top, Some("absent"), vec![])).unwrap_err();
            assert_eq!(error.diagnostic, expected);
        }
    }
}
