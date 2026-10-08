use super::{AppError, BloatArgs, BloatReport, Reconciliation};
use serde::Serialize;
use std::path::Path;
use vitnet_metadata::{Concentration, Preview, preview_bytes};
use vitnet_mstat::{
    CategorySummary, CohortRule, CohortsInsightReport, GenericStreamReport, MethodsInsightReport,
    ResourceGroupList,
};
mod investigation;

#[derive(Serialize)]
pub(super) struct Brief<'a> {
    schema: &'static str,
    inputs: [&'a Path; 2],
    top: usize,
    rules: &'a [CohortRule],
    reconciliation: &'a Reconciliation,
    accounting: Accounting<'a>,
    method_costs: MethodCosts<'a>,
    metadata_attribution: MetadataAttribution,
    list_coverage: Vec<Coverage>,
    culture_mix: CultureMix<'a>,
    cohort_overlap: CohortOverlap,
    rule_gaps: RuleGaps<'a>,
    visible_family_density: Vec<FamilyDensity>,
    contributor_next_steps: Vec<ContributorGroup>,
    graph_context: Vec<GraphContext<'a>>,
    investigation: investigation::Investigation<'a>,
    caveats: [&'static str; 6],
}

#[derive(Serialize)]
struct ByteFraction<'a> {
    name: &'a str,
    bytes: u64,
    denominator_bytes: u64,
    share_basis_points: Option<u64>,
}

fn share(name: &str, bytes: u64, denominator: u64) -> ByteFraction<'_> {
    ByteFraction {
        name,
        bytes,
        denominator_bytes: denominator,
        share_basis_points: basis_points(bytes, denominator),
    }
}

fn basis_points(bytes: u64, denominator: u64) -> Option<u64> {
    (denominator != 0).then(|| {
        u64::try_from(u128::from(bytes) * 10_000 / u128::from(denominator))
            .expect("validated subset share fits u64")
    })
}

#[derive(Serialize)]
struct Accounting<'a> {
    accounted_total_bytes: u64,
    additive_streams: Vec<ByteFraction<'a>>,
    overlapping_streams: Vec<ByteFraction<'a>>,
}

fn accounting(categories: &[CategorySummary], total: u64) -> Accounting<'_> {
    let (mut additive_streams, mut overlapping_streams): (Vec<_>, Vec<_>) = categories
        .iter()
        .map(|category| share(&category.name, category.aggregate_size_bytes, total))
        .partition(|row| matches!(row.name, "Methods" | "Types" | "Blobs"));
    let order = |left: &ByteFraction<'_>, right: &ByteFraction<'_>| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.name.cmp(right.name))
    };
    additive_streams.sort_by(order);
    overlapping_streams.sort_by(order);
    Accounting {
        accounted_total_bytes: total,
        additive_streams,
        overlapping_streams,
    }
}

#[derive(Serialize)]
struct MethodCosts<'a> {
    global_components: Vec<ByteFraction<'static>>,
    visible_high_auxiliary_ratio: Vec<AuxiliaryMethod<'a>>,
    ranking_scope: &'static str,
}

#[derive(Serialize)]
struct AuxiliaryMethod<'a> {
    identity: &'a str,
    identity_truncated: bool,
    total_bytes: u64,
    auxiliary_bytes: u64,
    auxiliary_share_basis_points: Option<u64>,
}

fn method_costs(report: &MethodsInsightReport) -> MethodCosts<'_> {
    let components = &report.total_components;
    let mut methods: Vec<_> = report
        .entries
        .iter()
        .map(|entry| AuxiliaryMethod {
            identity: &entry.identity,
            identity_truncated: entry.truncated,
            total_bytes: entry.bytes,
            auxiliary_bytes: entry.gc_info_bytes + entry.exception_info_bytes,
            auxiliary_share_basis_points: basis_points(
                entry.gc_info_bytes + entry.exception_info_bytes,
                entry.bytes,
            ),
        })
        .collect();
    methods.sort_by(|left, right| {
        ratio_order(
            left.auxiliary_bytes,
            left.total_bytes,
            right.auxiliary_bytes,
            right.total_bytes,
        )
        .then_with(|| left.identity.cmp(right.identity))
    });
    MethodCosts {
        global_components: vec![
            share("body", components.body_bytes, report.total.bytes),
            share("gc_info", components.gc_info_bytes, report.total.bytes),
            share(
                "exception_info",
                components.exception_info_bytes,
                report.total.bytes,
            ),
        ],
        visible_high_auxiliary_ratio: methods,
        ranking_scope: "Only the displayed byte-ranked methods are reranked; not a global auxiliary-cost ranking.",
    }
}

fn ratio_order(left: u64, left_count: u64, right: u64, right_count: u64) -> std::cmp::Ordering {
    match (left_count, right_count) {
        (0, 0) => std::cmp::Ordering::Equal,
        (0, _) => std::cmp::Ordering::Greater,
        (_, 0) => std::cmp::Ordering::Less,
        _ => (u128::from(right) * u128::from(left_count))
            .cmp(&(u128::from(left) * u128::from(right_count))),
    }
}

#[derive(Serialize)]
struct MetadataAttribution {
    selected_lower_bound_bytes: u64,
    type_attributed_bytes: u64,
    unowned_bytes: u64,
    type_attributed_share_basis_points: Option<u64>,
}

fn metadata_attribution(
    total: u64,
    types: &Concentration,
    unowned: &Concentration,
) -> MetadataAttribution {
    MetadataAttribution {
        selected_lower_bound_bytes: total,
        type_attributed_bytes: types.total_bytes,
        unowned_bytes: unowned.total_bytes,
        type_attributed_share_basis_points: basis_points(types.total_bytes, total),
    }
}

#[derive(Serialize)]
struct Coverage {
    dimension: String,
    total_bytes: u64,
    shown_bytes: u64,
    omitted_bytes: u64,
    total_groups: u64,
    shown_groups: u64,
    shown_share_basis_points: Option<u64>,
    all_groups_shown: bool,
}

fn coverage(name: &str, total: u64, shown: u64, groups: u64, displayed: usize) -> Coverage {
    Coverage {
        dimension: name.into(),
        total_bytes: total,
        shown_bytes: shown,
        omitted_bytes: total - shown,
        total_groups: groups,
        shown_groups: displayed as u64,
        shown_share_basis_points: basis_points(shown, total),
        all_groups_shown: displayed as u64 == groups,
    }
}

#[derive(Serialize)]
struct CultureMix<'a> {
    total_resource_bytes: u64,
    neutral_culture_bytes: Option<u64>,
    non_neutral_culture_bytes: Option<u64>,
    displayed_cultures: Vec<ByteFraction<'a>>,
    omitted_culture_bytes: u64,
    interpretation: &'static str,
}

fn culture_mix(report: &ResourceGroupList<String>) -> CultureMix<'_> {
    let neutral = report
        .groups
        .iter()
        .find(|group| group.key.is_empty())
        .map(|group| group.matched.bytes)
        .or_else(|| (report.groups.len() as u64 == report.matched_groups).then_some(0));
    CultureMix {
        total_resource_bytes: report.matched.bytes,
        neutral_culture_bytes: neutral,
        non_neutral_culture_bytes: neutral.map(|bytes| report.matched.bytes - bytes),
        displayed_cultures: report
            .groups
            .iter()
            .map(|group| share(&group.key, group.matched.bytes, report.matched.bytes))
            .collect(),
        omitted_culture_bytes: report.omitted_bytes,
        interpretation: "Culture is the exact AssemblyRef culture; empty means neutral. This does not infer resource-file contents or localization requirements. Resources overlap Blobs.",
    }
}

#[derive(Serialize)]
struct CohortOverlap {
    accounted_union_bytes: u64,
    #[serde(serialize_with = "decimal")]
    summed_membership_bytes: u128,
    #[serde(serialize_with = "decimal")]
    duplicated_membership_bytes: u128,
    multiply_matched_bytes: u64,
    membership_amplification_basis_points: Option<String>,
}

fn decimal<S: serde::Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn validate_stream_shares(summary: &vitnet_mstat::MstatSummary) -> Result<(), AppError> {
    if let Some(category) = summary
        .categories
        .iter()
        .find(|category| category.aggregate_size_bytes > summary.accounted_size_bytes)
    {
        return Err(AppError::Unsupported(Box::new(
            vitnet_core::Diagnostic::malformed(
                "bloat.brief.invariant",
                format!(
                    "{} reported byte count exceeds the accounted total",
                    category.name
                ),
            ),
        )));
    }
    Ok(())
}

fn cohort_overlap(report: &CohortsInsightReport) -> CohortOverlap {
    let sum: u128 = report
        .cohorts
        .iter()
        .map(|cohort| u128::from(cohort.accounted.bytes))
        .sum();
    let union = report.union_accounted.bytes;
    CohortOverlap {
        accounted_union_bytes: union,
        summed_membership_bytes: sum,
        duplicated_membership_bytes: sum - u128::from(union),
        multiply_matched_bytes: report.multiply_matched_accounted.bytes,
        membership_amplification_basis_points: (union != 0)
            .then(|| (sum * 10_000 / u128::from(union)).to_string()),
    }
}

#[derive(Serialize)]
struct RuleGaps<'a> {
    unmatched_accounted_bytes: u64,
    covered_share_basis_points: Option<u64>,
    zero_hit_rules: Vec<&'a str>,
    no_accounted_match_rules: Vec<&'a str>,
    interpretation: &'static str,
}

fn rule_gaps(report: &CohortsInsightReport) -> RuleGaps<'_> {
    RuleGaps {
        unmatched_accounted_bytes: report.accounted_denominator_bytes
            - report.union_accounted.bytes,
        covered_share_basis_points: basis_points(
            report.union_accounted.bytes,
            report.accounted_denominator_bytes,
        ),
        zero_hit_rules: report
            .cohorts
            .iter()
            .filter(|cohort| {
                cohort.accounted.identities == 0 && cohort.non_accounted.identities == 0
            })
            .map(|cohort| cohort.name.as_str())
            .collect(),
        no_accounted_match_rules: report
            .cohorts
            .iter()
            .filter(|cohort| cohort.accounted.identities == 0)
            .map(|cohort| cohort.name.as_str())
            .collect(),
        interpretation: "Unmatched means outside the supplied literal predicates, not unknown ownership. Zero hits are a predicate result, not proof a component is absent.",
    }
}

#[derive(Serialize)]
struct FamilyDensity {
    stream: String,
    family: Preview,
    bytes: u64,
    identities: u64,
    records: u64,
    bytes_per_identity: Option<u64>,
    bytes_per_record: Option<u64>,
    ranking_scope: &'static str,
}

fn family_density(reports: &[GenericStreamReport]) -> Vec<FamilyDensity> {
    reports.iter().flat_map(|report| {
        let mut families: Vec<_> = report.families.iter().collect();
        families.sort_by(|left, right| ratio_order(left.matched.bytes, left.matched.identities, right.matched.bytes, right.matched.identities)
            .then_with(|| left.prefix.cmp(&right.prefix)));
        families.into_iter().map(|family| FamilyDensity {
            stream: report.stream.clone(),
            family: preview_bytes(family.prefix.as_bytes(), 256),
            bytes: family.matched.bytes, identities: family.matched.identities, records: family.matched.records,
            bytes_per_identity: family.matched.bytes.checked_div(family.matched.identities),
            bytes_per_record: family.matched.bytes.checked_div(family.matched.records),
            ranking_scope: "Only displayed byte-ranked literal '<' families; not a global density ranking or instantiation/removal estimate.",
        }).collect::<Vec<_>>()
    }).collect()
}

#[derive(Serialize)]
struct ContributorGroup {
    dimension: &'static str,
    candidates: Vec<Contributor>,
}

#[derive(Serialize)]
struct Contributor {
    name: Preview,
    bytes: u64,
    denominator_bytes: u64,
    share_basis_points: Option<u64>,
    follow_up_argv: Vec<String>,
    filter_hint_available: bool,
}

#[derive(Clone, Copy)]
struct FollowUp<'a> {
    commands: &'a [&'a str],
    input: &'a Path,
    top: usize,
    filter: &'a str,
}

fn contributor(
    name: &str,
    truncated: bool,
    bytes: u64,
    denominator: u64,
    action: FollowUp<'_>,
) -> Contributor {
    let preview = preview_bytes(name.as_bytes(), 256);
    let hint = !truncated && !preview.truncated && !name.is_empty() && !name.contains('\0');
    let mut argv: Vec<_> = std::iter::once("vitnet")
        .chain(action.commands.iter().copied())
        .map(str::to_owned)
        .collect();
    argv.push(format!(
        "--top={}",
        action.top.saturating_mul(5).clamp(1, 10_000)
    ));
    if hint {
        argv.push(format!("--{}={name}", action.filter));
    }
    argv.extend(["--".into(), action.input.to_string_lossy().into_owned()]);
    Contributor {
        name: preview,
        bytes,
        denominator_bytes: denominator,
        share_basis_points: basis_points(bytes, denominator),
        follow_up_argv: argv,
        filter_hint_available: hint,
    }
}

fn stream_contributors(
    categories: &[CategorySummary],
    total: u64,
    args: &BloatArgs,
) -> ContributorGroup {
    let streams = accounting(categories, total);
    ContributorGroup {
        dimension: "accounted_streams",
        candidates: streams
            .additive_streams
            .iter()
            .take(args.top.min(3))
            .map(|row| {
                contributor(
                    row.name,
                    false,
                    row.bytes,
                    row.denominator_bytes,
                    FollowUp {
                        commands: &["mstat", "top"],
                        input: &args.mstat,
                        top: args.top,
                        filter: "stream",
                    },
                )
            })
            .collect(),
    }
}

fn contributors(report: &BloatReport, args: &BloatArgs) -> Vec<ContributorGroup> {
    let limit = args.top.min(3);
    vec![
        stream_contributors(
            &report.mstat.summary.categories,
            report.mstat.summary.accounted_size_bytes,
            args,
        ),
        ContributorGroup {
            dimension: "methods",
            candidates: report
                .mstat
                .methods
                .entries
                .iter()
                .take(limit)
                .map(|entry| {
                    contributor(
                        &entry.identity,
                        entry.truncated,
                        entry.bytes,
                        report.mstat.methods.matched.bytes,
                        FollowUp {
                            commands: &["mstat", "methods"],
                            input: &args.mstat,
                            top: args.top,
                            filter: "contains",
                        },
                    )
                })
                .collect(),
        },
        ContributorGroup {
            dimension: "metadata_types",
            candidates: report
                .metadata
                .sections
                .by_type
                .iter()
                .take(limit)
                .map(|entry| {
                    contributor(
                        &entry.name,
                        false,
                        entry.bytes,
                        report.metadata.summary.selected_lower_bound_bytes,
                        FollowUp {
                            commands: &["metadata"],
                            input: &args.metadata,
                            top: args.top,
                            filter: "type",
                        },
                    )
                })
                .collect(),
        },
        ContributorGroup {
            dimension: "resource_assemblies",
            candidates: report
                .mstat
                .resources
                .by_assembly
                .groups
                .iter()
                .take(limit)
                .map(|group| {
                    contributor(
                        &group.key.name,
                        false,
                        group.matched.bytes,
                        report.mstat.resources.by_assembly.matched.bytes,
                        FollowUp {
                            commands: &["mstat", "resources"],
                            input: &args.mstat,
                            top: args.top,
                            filter: "contains",
                        },
                    )
                })
                .collect(),
        },
    ]
}

#[derive(Serialize)]
struct GraphContext<'a> {
    index_directory: &'a Path,
    generation: &'a str,
    nodes: u64,
    edges: u64,
    #[serde(serialize_with = "decimal")]
    numeric_slots: u128,
    declared_slot_share_basis_points: Option<String>,
    duplicate_node_ids: u64,
    unresolved_endpoints: u64,
    query_argv: Vec<String>,
    interpretation: &'static str,
}

fn graph_context(graphs: &[vitnet_dgml::DgmlCacheInfo]) -> Vec<GraphContext<'_>> {
    graphs.iter().map(|graph| {
        let slots = graph.manifest.max_node_id.map_or(0, |id| u128::from(id) + 1);
        GraphContext {
            index_directory: &graph.index_directory,
            generation: &graph.generation, nodes: graph.manifest.node_count, edges: graph.manifest.edge_count,
            numeric_slots: slots,
            declared_slot_share_basis_points: (slots != 0).then(|| (u128::from(graph.manifest.node_count) * 10_000 / slots).to_string()),
            duplicate_node_ids: graph.manifest.duplicate_node_ids, unresolved_endpoints: graph.manifest.unresolved_endpoints,
            query_argv: vec!["vitnet".into(), "dgml".into(), "search".into(),
                "--count-all".into(), "--rank=incoming".into(), format!("--max-scanned={}", slots.max(1)),
                "--timeout-ms=120000".into(), format!("--generation={}", graph.generation),
                "--".into(), graph.index_directory.to_string_lossy().into_owned(), "<literal>".into()],
            interpretation: "Immutable index provenance only: no graph query was executed, no same-build assertion or guaranteed symbol join. Replace the literal; counts/rank are global only on complete scans.",
        }
    }).collect()
}

pub(super) fn build<'a>(
    report: &'a BloatReport,
    args: &'a BloatArgs,
) -> Result<Brief<'a>, AppError> {
    validate_stream_shares(&report.mstat.summary)?;
    let concentrations = &report.metadata.sections.concentration;
    let require = |name: &str| {
        concentrations.get(name).ok_or_else(|| {
            AppError::Unsupported(Box::new(vitnet_core::Diagnostic::malformed(
                "bloat.brief.invariant",
                format!("missing {name} concentration"),
            )))
        })
    };
    let metadata_attribution = metadata_attribution(
        report.metadata.summary.selected_lower_bound_bytes,
        require("by_type")?,
        require("unowned")?,
    );
    let mut list_coverage: Vec<_> = concentrations
        .iter()
        .map(|(name, value)| {
            coverage(
                &format!("metadata.{name}"),
                value.total_bytes,
                value.reported_bytes,
                value.total_groups as u64,
                value.reported_groups,
            )
        })
        .collect();
    let methods = &report.mstat.methods;
    list_coverage.push(coverage(
        "methods",
        methods.matched.bytes,
        methods.top_bytes,
        methods.matched.identities,
        methods.entries.len(),
    ));
    let resources = &report.mstat.resources;
    for (name, bytes, shown, groups, count) in [
        (
            "resources.assembly",
            resources.by_assembly.matched.bytes,
            resources.by_assembly.top_bytes,
            resources.by_assembly.matched_groups,
            resources.by_assembly.groups.len(),
        ),
        (
            "resources.culture",
            resources.by_culture.matched.bytes,
            resources.by_culture.top_bytes,
            resources.by_culture.matched_groups,
            resources.by_culture.groups.len(),
        ),
        (
            "resources.name",
            resources.by_resource_name.matched.bytes,
            resources.by_resource_name.top_bytes,
            resources.by_resource_name.matched_groups,
            resources.by_resource_name.groups.len(),
        ),
    ] {
        list_coverage.push(coverage(name, bytes, shown, groups, count));
    }
    for section in &report.mstat.generics.sections {
        list_coverage.push(coverage(
            &format!("generic_families.{}", section.stream),
            section.matched_generic_shaped.bytes,
            section.top_bytes,
            section.matched_families,
            section.families.len(),
        ));
    }
    Ok(Brief {
        schema: "vitnet.bloat-brief.v1",
        inputs: [&args.metadata, &args.mstat],
        top: args.top,
        rules: &report.rules,
        reconciliation: &report.reconciliation,
        accounting: accounting(
            &report.mstat.summary.categories,
            report.mstat.summary.accounted_size_bytes,
        ),
        method_costs: method_costs(methods),
        metadata_attribution,
        list_coverage,
        culture_mix: culture_mix(&resources.by_culture),
        cohort_overlap: cohort_overlap(&report.mstat.cohorts),
        rule_gaps: rule_gaps(&report.mstat.cohorts),
        visible_family_density: family_density(&report.mstat.generics.sections),
        contributor_next_steps: contributors(report, args),
        graph_context: graph_context(&report.graph_generations),
        investigation: investigation::build(report, args)?,
        caveats: [
            report.caveats[0],
            report.caveats[1],
            report.caveats[2],
            report.caveats[3],
            "Alternate dimensions and contributor cards overlap. Do not sum them or equate their bytes with reclaimable file size.",
            "Rerankings are limited to displayed source candidates. Follow-up argv uses literal hints, not an exact symbol/graph join; truncated or NUL-containing labels omit the filter.",
        ],
    })
}

#[cfg(test)]
mod tests;
