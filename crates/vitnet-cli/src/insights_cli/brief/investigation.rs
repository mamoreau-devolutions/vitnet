use super::{AppError, BloatArgs, BloatReport, basis_points};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use vitnet_metadata::{Preview, preview_bytes};
use vitnet_mstat::{IdentityInsightEntry, InsightCounts, MethodSizeBand};

#[derive(Serialize)]
pub(super) struct Investigation<'a> {
    schema: &'static str,
    accounting_limits: AccountingLimits,
    blob_buckets: BlobBuckets<'a>,
    diagnostic_artifacts: DiagnosticArtifacts,
    method_population: MethodPopulation<'a>,
    resource_culture_assemblies: ResourceCultures,
    repeated_resource_names: Vec<RepeatedName>,
    cohort_redundancy: Vec<CohortPair<'a>>,
    unmatched_by_stream: Vec<StreamGap<'a>>,
    spelling_hints: Vec<SpellingHint>,
    coverage_targets: Vec<CoverageTarget>,
}

#[derive(Serialize)]
struct AccountingLimits {
    dehydration_observed: bool,
    dehydrated_data_bytes: u64,
    dehydrated_data_records: u64,
    physical_binary_bytes: Option<u64>,
    interpretation: &'static str,
}

fn accounting_limits(report: &BloatReport) -> AccountingLimits {
    let observed = report.mstat.blobs.dehydrated_data;
    AccountingLimits {
        dehydration_observed: observed.records != 0,
        dehydrated_data_bytes: observed.bytes,
        dehydrated_data_records: observed.records,
        physical_binary_bytes: None,
        interpretation: "MSTAT reports object accounting, not executable file size. Exact DehydratedData presence signals an encoded representation alongside logical hydration targets; do not sum them as independent physical payloads or recommend disabling dehydration. Absence does not prove a build switch.",
    }
}

#[derive(Serialize)]
struct BlobBuckets<'a> {
    total: InsightCounts,
    matched: InsightCounts,
    shown_bytes: u64,
    omitted_bytes: u64,
    shown_share_basis_points: Option<u64>,
    entries: &'a [IdentityInsightEntry],
    interpretation: &'static str,
}

fn blob_buckets(report: &BloatReport) -> BlobBuckets<'_> {
    let blobs = &report.mstat.blobs;
    BlobBuckets {
        total: blobs.total,
        matched: blobs.matched,
        shown_bytes: blobs.top_bytes,
        omitted_bytes: blobs.omitted_bytes,
        shown_share_basis_points: basis_points(blobs.top_bytes, blobs.matched.bytes),
        entries: &blobs.entries,
        interpretation: "Exact producer bucket identities, not package ownership. Displayed buckets can omit a tail; their reported bytes are not physical savings.",
    }
}

#[derive(Serialize)]
struct DiagnosticArtifacts {
    mstat_input_bytes: u64,
    mangled_names_bytes: u64,
    names_to_input_basis_points: Option<String>,
    interpretation: &'static str,
}

fn diagnostic_artifacts(report: &BloatReport) -> DiagnosticArtifacts {
    let summary = &report.mstat.summary;
    DiagnosticArtifacts {
        mstat_input_bytes: summary.input_bytes,
        mangled_names_bytes: summary.mangled_names_bytes,
        names_to_input_basis_points: wide_ratio(summary.mangled_names_bytes, summary.input_bytes),
        interpretation: "The diagnostic .names payload belongs to the MSTAT file, not an additional executable contribution. This ratio is artifact accounting, not a binary-size share.",
    }
}

fn wide_ratio(bytes: u64, denominator: u64) -> Option<String> {
    (denominator != 0).then(|| (u128::from(bytes) * 10_000 / u128::from(denominator)).to_string())
}

#[derive(Serialize)]
struct Breadth {
    stream: &'static str,
    total: InsightCounts,
    bytes_per_identity: Option<u64>,
    bytes_per_record: Option<u64>,
}

fn breadth(stream: &'static str, total: InsightCounts) -> Breadth {
    Breadth {
        stream,
        total,
        bytes_per_identity: total.bytes.checked_div(total.identities),
        bytes_per_record: total.bytes.checked_div(total.records),
    }
}

#[derive(Serialize)]
struct MethodPopulation<'a> {
    methods: Breadth,
    types: Option<Breadth>,
    size_bands: &'a [MethodSizeBand],
    interpretation: &'static str,
}

fn method_population(report: &BloatReport) -> MethodPopulation<'_> {
    MethodPopulation {
        methods: breadth("Methods", report.mstat.methods.total),
        types: report
            .mstat
            .generics
            .sections
            .iter()
            .find(|section| section.stream == "Types")
            .map(|section| breadth("Types", section.total)),
        size_bands: &report.mstat.methods.size_bands,
        interpretation: "Full coalesced producer identities, not managed methods/types or generic-instantiation counts. Inclusive byte bands and total counts are independent of display top; matched bands reflect the contains filter. Averages are floored, not percentiles.",
    }
}

#[derive(Serialize)]
struct ResourceCultures {
    all_assembly_culture_groups_shown: bool,
    omitted_group_bytes: u64,
    assemblies: Vec<VisibleAssembly>,
    interpretation: &'static str,
}

#[derive(Serialize)]
struct VisibleAssembly {
    assembly: Preview,
    visible_bytes: u64,
    visible_cultures: u64,
    neutral_bytes: Option<u64>,
    visible_non_neutral_bytes: u64,
}

fn resource_cultures(report: &BloatReport, top: usize) -> ResourceCultures {
    let source = &report.mstat.resources.by_assembly;
    let complete = source.groups.len() as u64 == source.matched_groups;
    let mut groups: BTreeMap<&str, VisibleAssembly> = BTreeMap::new();
    for group in &source.groups {
        let row = groups
            .entry(&group.key.name)
            .or_insert_with(|| VisibleAssembly {
                assembly: preview_bytes(group.key.name.as_bytes(), 256),
                visible_bytes: 0,
                visible_cultures: 0,
                neutral_bytes: complete.then_some(0),
                visible_non_neutral_bytes: 0,
            });
        row.visible_bytes += group.matched.bytes;
        row.visible_cultures += 1;
        if group.key.culture.is_empty() {
            row.neutral_bytes = Some(group.matched.bytes);
        } else {
            row.visible_non_neutral_bytes += group.matched.bytes;
        }
    }
    let mut rows: Vec<_> = groups.into_iter().collect();
    rows.sort_by(|left, right| {
        right
            .1
            .visible_bytes
            .cmp(&left.1.visible_bytes)
            .then_with(|| left.0.cmp(right.0))
    });
    rows.truncate(top);
    ResourceCultures {
        all_assembly_culture_groups_shown: complete,
        omitted_group_bytes: source.omitted_bytes,
        assemblies: rows.into_iter().map(|(_, row)| row).collect(),
        interpretation: "Only displayed exact assembly/culture groups are consolidated. Incomplete input lists yield visible totals/ranks, not global assembly totals/ranks. Hidden neutral culture is unknown, not zero. Resources overlap Blobs.",
    }
}

#[derive(Serialize)]
struct RepeatedName {
    resource_name: Preview,
    bytes: u64,
    identities: u64,
    records: u64,
    visible_examples: usize,
    visible_equal_lengths: Option<bool>,
    interpretation: &'static str,
}

fn repeated_names(report: &BloatReport, top: usize) -> Vec<RepeatedName> {
    report.mstat.resources.by_resource_name.groups.iter()
        .filter(|group| group.matched.identities > 1)
        .take(top)
        .map(|group| RepeatedName {
            resource_name: preview_bytes(group.key.as_bytes(), 256),
            bytes: group.matched.bytes,
            identities: group.matched.identities,
            records: group.matched.records,
            visible_examples: group.entries.len(),
            visible_equal_lengths: (group.entries.len() >= 2).then(|| {
                group.entries.iter().all(|entry| entry.bytes == group.entries[0].bytes)
            }),
            interpretation: "Multiple exact resource identities share this name; cultures/assemblies may differ. Equal visible lengths are only a candidate clue, not content hashes or deduplication/savings proof.",
        }).collect()
}

#[derive(Serialize)]
struct CohortPair<'a> {
    left: &'a str,
    right: &'a str,
    intersection_bytes: u64,
    left_share_basis_points: Option<u64>,
    right_share_basis_points: Option<u64>,
    interpretation: &'static str,
}

fn cohort_pairs(report: &BloatReport, top: usize) -> Result<Vec<CohortPair<'_>>, AppError> {
    let source = &report.mstat.cohorts;
    let mut pairs = Vec::with_capacity(source.intersections.len());
    for pair in &source.intersections {
        let (Some(left), Some(right)) = (
            source.cohorts.get(pair.left),
            source.cohorts.get(pair.right),
        ) else {
            return Err(invariant(
                "cohort intersection index is outside the rule list",
            ));
        };
        if pair.accounted.bytes > left.accounted.bytes
            || pair.accounted.bytes > right.accounted.bytes
        {
            return Err(invariant(
                "cohort intersection exceeds a member's accounted bytes",
            ));
        }
        pairs.push((pair.left, pair.right, CohortPair {
            left: &left.name,
            right: &right.name,
            intersection_bytes: pair.accounted.bytes,
            left_share_basis_points: basis_points(pair.accounted.bytes, left.accounted.bytes),
            right_share_basis_points: basis_points(pair.accounted.bytes, right.accounted.bytes),
            interpretation: "Directional shares of overlapping accounted literal matches, not exclusive ownership or removable bytes. Pair intersections are not additive.",
        }));
    }
    pairs.sort_by(|left, right| {
        right
            .2
            .intersection_bytes
            .cmp(&left.2.intersection_bytes)
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });
    pairs.truncate(top);
    Ok(pairs.into_iter().map(|(_, _, row)| row).collect())
}

#[derive(Serialize)]
struct StreamGap<'a> {
    stream: &'a str,
    accounted: bool,
    total_bytes: u64,
    matched_union: InsightCounts,
    unmatched_bytes: u64,
    covered_share_basis_points: Option<u64>,
}

fn stream_gaps(report: &BloatReport) -> Result<Vec<StreamGap<'_>>, AppError> {
    let mut rows = Vec::new();
    for category in &report.mstat.summary.categories {
        let matched: Vec<_> = report
            .mstat
            .cohorts
            .union_sections
            .iter()
            .filter(|section| section.stream == category.name)
            .collect();
        if matched.len() != 1 {
            return Err(invariant(
                "expected exactly one cohort union per summary stream",
            ));
        }
        let matched = matched[0];
        if matched.matched.bytes > category.aggregate_size_bytes {
            return Err(invariant(
                "cohort stream union exceeds its full stream bytes",
            ));
        }
        rows.push(StreamGap {
            stream: &category.name,
            accounted: matched.accounted,
            total_bytes: category.aggregate_size_bytes,
            matched_union: matched.matched,
            unmatched_bytes: category.aggregate_size_bytes - matched.matched.bytes,
            covered_share_basis_points: basis_points(
                matched.matched.bytes,
                category.aggregate_size_bytes,
            ),
        });
    }
    Ok(rows)
}

#[derive(Serialize)]
struct SpellingHint {
    rule: Preview,
    original_predicate: Preview,
    candidate_predicate: Preview,
    interpretation: &'static str,
}

fn spelling_hints(report: &BloatReport, top: usize) -> Vec<SpellingHint> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    if top == 0 {
        return hints;
    }
    for (index, (rule, counts)) in report
        .rules
        .iter()
        .zip(&report.mstat.cohorts.cohorts)
        .enumerate()
    {
        if counts.accounted.identities != 0 {
            continue;
        }
        for pattern in &rule.contains {
            if !pattern.contains('.') || pattern.contains('\0') {
                continue;
            }
            let candidate = pattern.replace('.', "_");
            if rule.contains.contains(&candidate) || !seen.insert((index, candidate.clone())) {
                continue;
            }
            hints.push(SpellingHint {
                rule: preview_bytes(rule.name.as_bytes(), 256),
                original_predicate: preview_bytes(pattern.as_bytes(), 256),
                candidate_predicate: preview_bytes(candidate.as_bytes(), 256),
                interpretation: "Optional literal spelling hypothesis only. Keep original predicates and explicitly test the candidate; no rule was changed, no component absence or demangling is inferred.",
            });
            if hints.len() == top {
                return hints;
            }
        }
    }
    hints
}

#[derive(Serialize)]
struct CoverageTarget {
    dimension: String,
    target_basis_points: u64,
    denominator_bytes: u64,
    required_displayed_prefix: Option<usize>,
    interpretation: &'static str,
}

fn targets(name: &str, total: u64, bytes: impl Iterator<Item = u64>) -> Vec<CoverageTarget> {
    let mut counts = [None; 3];
    let mut cumulative = 0_u128;
    for (index, bytes) in bytes.enumerate() {
        cumulative += u128::from(bytes);
        for (slot, goal) in counts.iter_mut().zip([8000_u64, 9000, 9500]) {
            if total != 0
                && slot.is_none()
                && cumulative * 10_000 >= u128::from(total) * u128::from(goal)
            {
                *slot = Some(index + 1);
            }
        }
    }
    counts.into_iter().zip([8000, 9000, 9500]).map(|(count, target_basis_points)| CoverageTarget {
        dimension: name.into(), target_basis_points, denominator_bytes: total,
        required_displayed_prefix: count,
        interpretation: "Smallest displayed byte-ranked prefix proven to reach the full dimension's byte target. Null means not proven by this list, or zero denominator; increase top or narrow the selection. Not a count percentile or savings estimate.",
    }).collect()
}

fn coverage_targets(report: &BloatReport) -> Vec<CoverageTarget> {
    let mut rows = targets(
        "methods",
        report.mstat.methods.matched.bytes,
        report.mstat.methods.entries.iter().map(|entry| entry.bytes),
    );
    rows.extend(targets(
        "blobs",
        report.mstat.blobs.matched.bytes,
        report.mstat.blobs.entries.iter().map(|entry| entry.bytes),
    ));
    for (name, list) in [
        ("resources.culture", &report.mstat.resources.by_culture),
        ("resources.name", &report.mstat.resources.by_resource_name),
    ] {
        rows.extend(targets(
            name,
            list.matched.bytes,
            list.groups.iter().map(|group| group.matched.bytes),
        ));
    }
    let assemblies = &report.mstat.resources.by_assembly;
    rows.extend(targets(
        "resources.assembly_culture",
        assemblies.matched.bytes,
        assemblies.groups.iter().map(|group| group.matched.bytes),
    ));
    let metadata = &report.metadata.sections;
    if let Some(total) = metadata.concentration.get("by_type") {
        rows.extend(targets(
            "metadata.by_type",
            total.total_bytes,
            metadata.by_type.iter().map(|group| group.bytes),
        ));
    }
    for section in &report.mstat.generics.sections {
        rows.extend(targets(
            &format!("generic_families.{}", section.stream),
            section.matched_generic_shaped.bytes,
            section.families.iter().map(|group| group.matched.bytes),
        ));
    }
    rows
}

fn invariant(message: &str) -> AppError {
    AppError::Unsupported(Box::new(vitnet_core::Diagnostic::malformed(
        "bloat.brief.invariant",
        message,
    )))
}

pub(super) fn build<'a>(
    report: &'a BloatReport,
    args: &BloatArgs,
) -> Result<Investigation<'a>, AppError> {
    Ok(Investigation {
        schema: "vitnet.bloat-investigation.v1",
        accounting_limits: accounting_limits(report),
        blob_buckets: blob_buckets(report),
        diagnostic_artifacts: diagnostic_artifacts(report),
        method_population: method_population(report),
        resource_culture_assemblies: resource_cultures(report, args.top),
        repeated_resource_names: repeated_names(report, args.top),
        cohort_redundancy: cohort_pairs(report, args.top)?,
        unmatched_by_stream: stream_gaps(report)?,
        spelling_hints: spelling_hints(report, args.top),
        coverage_targets: coverage_targets(report),
    })
}

#[cfg(test)]
mod tests;
