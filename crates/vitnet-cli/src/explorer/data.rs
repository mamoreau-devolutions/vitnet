use super::{
    DISPLAY_LIMIT, PREVIEW_BYTES, SNAPSHOT_LIMIT, attribution, catalog, diagnostic, io, preview,
    ranking,
};
use crate::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vitnet_attribution::{AttributionIndex, Matcher, SourceMatch, model::Evidence};
use vitnet_dgml::{GraphSession, IndexControl, WhyOptions};
use vitnet_mstat::CoalescedIdentity;

const BUNDLE_SCHEMA: &str = "vitnet.explorer-bundle.v1";
const SNAPSHOT_SCHEMA: &str = "vitnet.explorer-snapshot.v1";
const ROW_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema: String,
    pub generation: String,
    pub attribution_index: PathBuf,
    pub index_blake3: String,
    pub identities_blake3: String,
    pub identity_file_bytes: u64,
    pub identities: u64,
    pub snapshot_blake3: String,
    pub offsets_blake3: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub datasets: BTreeMap<String, catalog::Dataset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranking: Option<ranking::Descriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub ordinal: u64,
    pub stream: String,
    pub accounted: bool,
    pub identity: String,
    pub identity_bytes: usize,
    pub truncated: bool,
    pub identity_lossy: bool,
    pub bytes: u64,
    pub records: u64,
    pub raw_identity_blake3: String,
}

impl Row {
    #[must_use]
    pub fn new(entry: &CoalescedIdentity, ordinal: u64) -> Self {
        let (identity, truncated) = preview(&entry.identity, PREVIEW_BYTES);
        Self {
            ordinal,
            stream: entry.stream.clone(),
            accounted: entry.accounted,
            identity,
            identity_bytes: entry.identity.len(),
            truncated,
            identity_lossy: entry.identity_lossy,
            bytes: entry.bytes,
            records: entry.records,
            raw_identity_blake3: entry.raw_identity_blake3.clone(),
        }
    }
}

fn checked_add(target: &mut u64, bytes: u64) -> Result<(), AppError> {
    *target = target
        .checked_add(bytes)
        .ok_or_else(|| diagnostic("explorer.size", "byte total overflow"))?;
    Ok(())
}

fn check_cancel(control: &IndexControl) -> Result<(), AppError> {
    if control.is_cancelled() {
        Err(diagnostic(
            "resource.cancelled",
            "explorer operation cancelled",
        ))
    } else {
        Ok(())
    }
}

#[derive(Default, Serialize)]
struct Group {
    dimension: String,
    stream: String,
    name: String,
    bytes: u64,
    identities: u64,
    status: String,
}

#[derive(Default, Serialize)]
struct GenericGroup {
    stream: String,
    family: String,
    bytes: u64,
    identities: u64,
    canonical_shared_identities: u64,
}

type Groups = BTreeMap<(String, String, String, String), Group>;

fn add_group(
    groups: &mut Groups,
    dimension: &str,
    stream: &str,
    name: &str,
    status: &str,
    bytes: u64,
    storage: &mut u64,
) -> Result<(), AppError> {
    let group = groups
        .entry((dimension.into(), stream.into(), name.into(), status.into()))
        .or_insert_with(|| {
            *storage = storage.saturating_add(
                (name.len() * 2 + stream.len() * 2 + status.len() * 2 + dimension.len() * 2) as u64
                    + 512,
            );
            Group {
                dimension: dimension.into(),
                stream: stream.into(),
                name: name.into(),
                status: status.into(),
                ..Group::default()
            }
        });
    checked_add(&mut group.bytes, bytes)?;
    checked_add(&mut group.identities, 1)
}

fn visit_error(cause: AppError) -> vitnet_attribution::AttributionError {
    vitnet_attribution::AttributionError {
        diagnostic: match cause {
            AppError::Unsupported(value)
            | AppError::IoDiagnostic(value)
            | AppError::Resource(value) => value,
            other => Box::new(vitnet_core::Diagnostic::malformed(
                "explorer.prepare",
                other.to_string(),
            )),
        },
    }
}

pub(super) fn details(
    matcher: &Matcher<'_>,
    entry: &CoalescedIdentity,
    ordinal: u64,
    mut sources: SourceMatch,
) -> Value {
    let total_sources = sources.sources.len();
    sources.sources.truncate(50);
    for source in &mut sources.sources {
        source.attributes.truncate(40);
        for attribute in &mut source.attributes {
            *attribute = preview(attribute, 1024).0;
        }
    }
    let mut result = json!({
        "row": Row::new(entry, ordinal), "sources": sources,
        "total_sources": total_sources, "omitted_sources": total_sources.saturating_sub(50),
        "caveat": "Owner association uses the complete cached identity or its raw-name hash for captured typed tokens; source declarations and generic argument spelling remain separately tiered candidates. Display labels and attributes may be shortened; this does not prove source/build equality.",
    });
    if !entry.identity_lossy {
        match vitnet_attribution::parse_shape(&entry.identity) {
            Ok(Some(shape)) => {
                let mut argument_sources = Vec::new();
                for argument in shape.arguments.iter().take(20) {
                    let mut candidates = matcher.locate("Types", argument);
                    let total = candidates.sources.len();
                    candidates.sources.truncate(5);
                    for source in &mut candidates.sources {
                        source.attributes.truncate(40);
                    }
                    argument_sources.push(json!({
                        "argument":argument,"candidates":candidates,"total_sources":total,
                        "caveat":"Producer-argument spelling candidates, not proven managed type arguments or caller sites."
                    }));
                }
                result["shape"] = json!({
                    "family":shape.family, "arguments":shape.arguments.iter().take(50).collect::<Vec<_>>(),
                    "argument_count":shape.arguments.len(), "canonical_shared":shape.canonical_shared,
                    "group_boundaries":shape.group_boundaries.iter().take(50).collect::<Vec<_>>(),
                });
                result["argument_sources"] = json!(argument_sources);
            }
            Ok(None) => {}
            Err(error) => {
                result["shape_diagnostic"] =
                    json!({"code":error.diagnostic.code,"message":error.diagnostic.message});
            }
        }
    }
    bound_text(&mut result);
    result
}

fn bound_text(value: &mut Value) {
    match value {
        Value::String(text) => *text = preview(text, 4096).0,
        Value::Array(values) => values.iter_mut().for_each(bound_text),
        Value::Object(values) => values.values_mut().for_each(bound_text),
        _ => {}
    }
}

fn bound_comparison(value: &mut Value) {
    let Some(report) = value.as_object_mut() else {
        return;
    };
    let mut counts = serde_json::Map::new();
    for key in [
        "provenance_changes",
        "package_changes",
        "graph_generation_changes",
        "source_changes",
        "attribution_visible_changes",
        "diagnostics",
    ] {
        if let Some(Value::Array(entries)) = report.get_mut(key) {
            counts.insert(key.into(), json!(entries.len()));
            entries.truncate(DISPLAY_LIMIT);
        }
    }
    report.insert("projection_counts".into(), Value::Object(counts));
}

fn sort_rows(rows: &mut [Row]) {
    rows.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    });
}

fn supplemental(
    index: &mut AttributionIndex,
    paths: &[PathBuf],
    memory: u64,
    catalog: &mut catalog::Writer<'_>,
    relationships: &mut BTreeSet<(String, String, String, String)>,
) -> Result<Vec<Value>, AppError> {
    let mut inventories = Vec::new();
    for (ordinal, path) in paths.iter().enumerate() {
        let mut evidence: Evidence =
            vitnet_attribution::read_json(path, memory / 2).map_err(attribution)?;
        vitnet_attribution::validate_evidence(&evidence).map_err(attribution)?;
        catalog.evidence(&format!("supplemental_{ordinal}_"), &evidence)?;
        assembly_links(&evidence, relationships, memory)?;
        inventories.push(json!({
            "label": evidence.label, "resource_count": evidence.resources.len(),
            "package_count": evidence.packages.len(),
            "caveat": "Supplemental inventory is independent local evidence, not a compiler retention witness or a proven publish-time dependency graph."
        }));
        index.evidence.resources.append(&mut evidence.resources);
        index.evidence.packages.append(&mut evidence.packages);
        index.evidence.generators.append(&mut evidence.generators);
        index.evidence.binaries.append(&mut evidence.binaries);
        index.diagnostics.append(&mut evidence.diagnostics);
    }
    let mut resources = BTreeMap::new();
    for resource in index.evidence.resources.drain(..) {
        let key = (
            resource.assembly.clone(),
            resource.container.clone(),
            resource.name.clone(),
        );
        if let Some(old) = resources.insert(key, resource.clone()) {
            if old.bytes != resource.bytes
                || old.sha256 != resource.sha256
                || old.storage != resource.storage
            {
                return Err(diagnostic(
                    "explorer.inventory.conflict",
                    "conflicting supplemental resource identities",
                ));
            }
        }
    }
    index.evidence.resources = resources.into_values().collect();
    let mut packages = BTreeMap::new();
    for package in index.evidence.packages.drain(..) {
        let key = (
            package.target.clone(),
            package.id.clone(),
            package.version.clone(),
        );
        if let Some(old) = packages.insert(key, package.clone()) {
            if old.dependencies != package.dependencies || old.direct != package.direct {
                return Err(diagnostic(
                    "explorer.inventory.conflict",
                    "conflicting supplemental package identities",
                ));
            }
        }
    }
    index.evidence.packages = packages.into_values().collect();
    let mut binaries = BTreeMap::new();
    for binary in index.evidence.binaries.drain(..) {
        if let Some(old) = binaries.insert(binary.path.clone(), binary.clone()) {
            if serde_json::to_value(old).map_err(AppError::Json)?
                != serde_json::to_value(&binary).map_err(AppError::Json)?
            {
                return Err(diagnostic(
                    "explorer.inventory.conflict",
                    "conflicting physical binary evidence for one path",
                ));
            }
        }
    }
    index.evidence.binaries = binaries.into_values().collect();
    Ok(inventories)
}

fn assembly_links(
    evidence: &Evidence,
    links: &mut BTreeSet<(String, String, String, String)>,
    memory: u64,
) -> Result<(), AppError> {
    let estimate = |key: &(String, String, String, String)| {
        u64::try_from(key.0.len() + key.1.len() + key.2.len() + key.3.len())
            .ok()
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| diagnostic("resource.explorer.relations", "relation storage overflow"))
    };
    let mut stored = links.iter().try_fold(0_u64, |sum, key| {
        sum.checked_add(estimate(key)?)
            .ok_or_else(|| diagnostic("resource.explorer.relations", "relation storage overflow"))
    })?;
    let mut insert = |key| -> Result<(), AppError> {
        if !links.contains(&key) {
            stored = stored.checked_add(estimate(&key)?).ok_or_else(|| {
                diagnostic("resource.explorer.relations", "relation storage overflow")
            })?;
            if stored > memory / 16 {
                return Err(diagnostic(
                    "resource.explorer.relations",
                    "package-origin keys exceed their memory reservation; increase --memory-limit",
                ));
            }
            links.insert(key);
        }
        Ok(())
    };
    for assembly in &evidence.assemblies {
        if let Some(package) = &assembly.package {
            insert((
                assembly.name.clone(),
                package.clone(),
                String::new(),
                "recorded_assembly_package".into(),
            ))?;
        }
    }
    for mapping in &evidence.mappings {
        if mapping.stream == "package" {
            // Assets collector records the role followed by the complete target scope.
            let target = mapping
                .basis
                .strip_prefix("assets_resolved_")
                .and_then(|value| value.split_once(':').map(|(_, target)| target))
                .unwrap_or("");
            insert((
                mapping.assembly.clone(),
                mapping.identity.clone(),
                target.into(),
                mapping.basis.clone(),
            ))?;
        }
    }
    Ok(())
}

fn scopes(
    groups: &Groups,
    families: &BTreeMap<(String, String), GenericGroup>,
    memory: u64,
) -> Result<Vec<Value>, AppError> {
    let mut totals = BTreeMap::<(String, String, String), (u64, u64, BTreeSet<String>)>::new();
    let mut storage = 0_u64;
    for group in groups.values() {
        let key = (
            group.dimension.clone(),
            group.stream.clone(),
            group.name.clone(),
        );
        if !totals.contains_key(&key) {
            storage =
                storage.saturating_add((key.0.len() + key.1.len() + key.2.len()) as u64 * 2 + 512);
        }
        let total = totals.entry(key).or_default();
        checked_add(&mut total.0, group.bytes)?;
        checked_add(&mut total.1, group.identities)?;
        total.2.insert(group.status.clone());
    }
    for family in families.values() {
        storage =
            storage.saturating_add((family.family.len() + family.stream.len()) as u64 * 2 + 512);
        totals.insert(
            (
                "family".into(),
                family.stream.clone(),
                family.family.clone(),
            ),
            (
                family.bytes,
                family.identities,
                BTreeSet::from(["parsed_producer_family".into()]),
            ),
        );
    }
    if storage > memory / 8 {
        return Err(diagnostic(
            "resource.explorer.scopes",
            "scope lookup exceeds reserved memory share",
        ));
    }
    Ok(totals
        .into_iter()
        .map(
            |((dimension, stream, name), (bytes, identities, statuses))| {
                json!({
                    "dimension":dimension,"stream":stream,"name":name,"bytes":bytes,
                    "identities":identities,"statuses":statuses,
                })
            },
        )
        .collect())
}

/// Creates a new immutable browsing bundle by streaming verified input once.
///
/// # Errors
///
/// Rejects corrupt source caches, output collisions, invalid inventories and budgets.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn prepare(
    index_path: &Path,
    output: &Path,
    evidence: &[PathBuf],
    before: Option<&Path>,
    nodes: &[u64],
    graph_kind: &str,
    memory: u64,
    control: &IndexControl,
) -> Result<BundleManifest, AppError> {
    prepare_with_policy(
        index_path, output, evidence, before, nodes, graph_kind, memory, control, None,
    )
}

/// Prepares complete opportunity evidence with an optional declarative local policy.
///
/// # Errors
///
/// Rejects invalid policy, corrupt inputs, collisions, cancellation and memory exhaustion.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn prepare_with_policy(
    index_path: &Path,
    output: &Path,
    evidence: &[PathBuf],
    before: Option<&Path>,
    nodes: &[u64],
    graph_kind: &str,
    memory: u64,
    control: &IndexControl,
    opportunity_policy: Option<&Path>,
) -> Result<BundleManifest, AppError> {
    if output.exists() {
        return Err(diagnostic(
            "explorer.output.exists",
            "bundle already exists; choose a new immutable directory",
        ));
    }
    if nodes.len() > 3 || evidence.len() > 16 || memory < 32 * 1024 * 1024 {
        return Err(diagnostic(
            "resource.explorer.options",
            "prepare needs >=32 MiB, at most three nodes and sixteen supplemental inventories",
        ));
    }
    let source = fs::canonicalize(index_path).map_err(io)?;
    let index_hash = vitnet_attribution::hash_file(&source.join("index.json"))
        .map_err(attribution)?
        .1;
    let mut index = vitnet_attribution::open_index(&source, memory).map_err(attribution)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(io)?;
    let temporary = tempfile::Builder::new()
        .prefix(".vitnet-explorer-")
        .tempdir_in(parent)
        .map_err(io)?;
    let mut catalog = catalog::Writer::new(temporary.path(), memory, control);
    let mut relationships = BTreeSet::new();
    assembly_links(&index.evidence, &mut relationships, memory)?;
    let inventories = supplemental(
        &mut index,
        evidence,
        memory,
        &mut catalog,
        &mut relationships,
    )?;
    catalog.write("assembly_links", relationships.into_iter().map(|(assembly, package, target, basis)| json!({
        "assembly":assembly,"package":package,"target":target,"basis":basis,
        "caveat":"Recorded package origin, not compiler retention, exclusive byte ownership or removable size."
    })))?;
    catalog.evidence("", &index.evidence)?;
    catalog.write(
        "index_header",
        [json!({
            "schema":index.schema, "identities":index.identities,
            "identities_blake3":index.identities_blake3,
        })],
    )?;
    catalog.write("artifacts", &index.artifacts)?;
    catalog.write("mstat_summary", index.mstat.iter())?;
    if let Some(analysis) = &index.metadata {
        catalog.write("metadata_by_kind", &analysis.by_kind)?;
        catalog.write("metadata_by_assembly", &analysis.by_assembly)?;
        catalog.write("metadata_by_namespace", &analysis.by_namespace)?;
        catalog.write("metadata_by_type", &analysis.by_type)?;
        catalog.write("metadata_largest_strings", &analysis.largest_strings)?;
        catalog.write("metadata_unowned", &analysis.unowned)?;
        catalog.write("metadata_summary", [json!({
            "offset_bits":analysis.offset_bits,
            "observed_lower_bound":analysis.observed_lower_bound,
            "total_lower_bound":analysis.total_lower_bound,
            "selected_lower_bound":analysis.selected_lower_bound,
            "total_is_lower_bound":analysis.total_is_lower_bound,
            "final_record_size_known":analysis.final_record_size_known,
            "observed_record_count":analysis.observed_record_count,
            "record_count":analysis.record_count, "limit_status":analysis.limit_status,
            "peak_tracked_bytes":analysis.peak_tracked_bytes, "concentration":analysis.concentration,
        })])?;
    }
    let matcher = Matcher::new(&index.evidence);
    let mut symbols = index
        .symbols
        .as_ref()
        .map(|descriptor| vitnet_attribution::SymbolLookup::open(&source, descriptor, memory))
        .transpose()
        .map_err(attribution)?;
    let policy: Option<vitnet_attribution::OpportunityPolicy> = opportunity_policy
        .map(|path| vitnet_attribution::read_json(path, memory).map_err(attribution))
        .transpose()?;
    let mut opportunities =
        vitnet_attribution::OpportunityCollector::new(&index.evidence, policy.as_ref(), memory / 8)
            .map_err(attribution)?;
    let mut lenses = vitnet_attribution::lenses::Collector::new(&index.evidence, memory / 2)
        .map_err(attribution)?;
    let mut offsets =
        BufWriter::new(File::create(temporary.path().join("offsets.bin")).map_err(io)?);
    let mut count = 0_u64;
    let mut total = 0_u64;
    let mut streams: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut groups = Groups::new();
    let mut families: BTreeMap<(String, String), GenericGroup> = BTreeMap::new();
    let mut aggregate_storage = 0;
    let mut generators: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut top: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    let mut malformed = 0_u64;
    let mut ranking = ranking::Writer::new(temporary.path(), memory, control)?;
    vitnet_attribution::visit_identities_with_offsets(&source, &index, memory, |entry, offset| {
        ranking.push(entry.bytes, count).map_err(visit_error)?;
        let candidates = symbols
            .as_mut()
            .map(|symbols| symbols.get(&entry.stream, &entry.raw_identity_blake3))
            .transpose()?
            .unwrap_or_default();
        let located = matcher.locate_symbols(entry, &candidates)?;
        let ordinal = count;
        process_entry(
            entry,
            offset,
            &mut offsets,
            &located,
            &mut count,
            &mut total,
            &mut streams,
            &mut groups,
            &mut families,
            &mut generators,
            &mut opportunities,
            &mut top,
            &mut malformed,
            &mut aggregate_storage,
            memory,
            control,
        )
        .map_err(visit_error)?;
        lenses.observe(entry, &located, &candidates, ordinal)
    })
    .map_err(attribution)?;
    if let Some(symbols) = &symbols {
        symbols.check().map_err(attribution)?;
    }
    if let Some(analysis) = &index.metadata {
        let mut typed_metadata: BTreeMap<&str, u64> = BTreeMap::new();
        for group in &analysis.by_type {
            lenses
                .metadata(&group.name, group.bytes)
                .map_err(attribution)?;
            if let Some((assembly, _)) = group.name.split_once('!') {
                checked_add(typed_metadata.entry(assembly).or_default(), group.bytes)?;
            }
        }
        let mut owned_metadata = 0;
        for group in &analysis.by_assembly {
            checked_add(&mut owned_metadata, group.bytes)?;
            let remainder = group
                .bytes
                .checked_sub(
                    typed_metadata
                        .get(group.name.as_str())
                        .copied()
                        .unwrap_or(0),
                )
                .ok_or_else(|| {
                    diagnostic(
                        "explorer.metadata.accounting",
                        "type metadata exceeds assembly metadata",
                    )
                })?;
            if remainder > 0 {
                lenses
                    .metadata(&format!("{}!_unresolved_owner", group.name), remainder)
                    .map_err(attribution)?;
            }
        }
        let unowned = analysis
            .selected_lower_bound
            .checked_sub(owned_metadata)
            .ok_or_else(|| {
                diagnostic(
                    "explorer.metadata.accounting",
                    "assembly metadata exceeds selected metadata",
                )
            })?;
        if unowned > 0 {
            lenses
                .metadata("_unowned_metadata!_unresolved_owner", unowned)
                .map_err(attribution)?;
        }
        catalog.write(
            "lens_metadata_strings",
            analysis
                .largest_strings
                .iter()
                .map(|entry| vitnet_attribution::lenses::metadata_string(&json!(entry))),
        )?;
        let mut reported = 0;
        for group in &analysis.by_assembly {
            checked_add(&mut reported, group.bytes)?;
            opportunities
                .observe_metadata_budget(&group.name, group.bytes)
                .map_err(attribution)?;
        }
        let remainder = analysis
            .selected_lower_bound
            .checked_sub(reported)
            .ok_or_else(|| {
                diagnostic(
                    "explorer.metadata.accounting",
                    "captured metadata assembly groups exceed the selected lower bound",
                )
            })?;
        if remainder != 0 {
            opportunities
                .observe_metadata_budget("_unowned_or_omitted_metadata", remainder)
                .map_err(attribution)?;
        }
    }
    let mut opportunity_report = opportunities.finish().map_err(attribution)?;
    let mut lens_report = lenses.finish().map_err(attribution)?;
    if let Some(metadata) = &index.metadata {
        let mut captured_bytes = 0;
        let mut captured_owners = 0_u64;
        for entry in &metadata.largest_strings {
            checked_add(&mut captured_bytes, entry.bytes)?;
            if entry.type_name.is_some() {
                checked_add(&mut captured_owners, 1)?;
            }
        }
        lens_report.coverage["metadata_strings"] = json!({
            "captured_records":metadata.largest_strings.len(),"captured_lower_bound_bytes":captured_bytes,
            "records_with_selected_owner":captured_owners,"truncated_previews":metadata.largest_strings.iter().filter(|entry|entry.preview.truncated).count(),
            "scope":"Upstream largest-string top-N selection; omissions and preview suffixes cannot be recovered. Selected log owners do not establish exclusive runtime footprint.",
            "metadata_concentration":metadata.concentration
        });
    } else {
        lens_report.coverage["metadata_strings"] = json!({"status":"not_captured"});
    }
    catalog.write("lens_feature_owners", &lens_report.owners)?;
    catalog.write("lens_costs", &lens_report.owners)?;
    catalog.write("lens_xaml", &lens_report.xaml)?;
    catalog.write("lens_serializers", &lens_report.serializers)?;
    catalog.write("lens_repetitions", &lens_report.repetitions)?;
    catalog.write("lens_arguments", &lens_report.arguments)?;
    catalog.write("lens_reflection", &lens_report.reflection)?;
    catalog.write("lens_coverage", [&lens_report.coverage])?;
    catalog.write("opportunities", &opportunity_report.opportunities)?;
    catalog.write("budgets", &opportunity_report.budgets)?;
    catalog.write("opportunity_coverage", [json!({
        "schema": opportunity_report.schema,
        "accounted_bytes": opportunity_report.accounted_bytes,
        "streams": opportunity_report.streams,
        "source_declarations": opportunity_report.source_declarations,
        "generated_declarations": opportunity_report.generated_declarations,
        "generator_descriptors": opportunity_report.generator_descriptors,
        "generator_runs": index.evidence.generator_runs.len(),
        "generator_links": index.evidence.generator_links.len(),
        "generator_outputs_captured": index.evidence.generator_runs.iter().map(|run| run.outputs.len()).sum::<usize>(),
        "generator_execution_observed": index.evidence.generator_runs.iter().filter(|run| run.execution_status == "observed").count(),
        "attribute_occurrences": opportunity_report.attribute_occurrences,
        "malformed_shape_identities": opportunity_report.malformed_shape_identities,
        "limitations": opportunity_report.limitations,
        "metadata_dimensions_complete": index.metadata.as_ref().and_then(|m|
            (!m.concentration.is_empty()).then(|| m.concentration.values().all(|c| c.reported_groups == c.total_groups))),
        "metadata_scope": "Captured lower-bound groups. Unowned and upstream-omitted assembly bytes stay in a separate remainder budget.",
        "policy": policy,
    })])?;
    let opportunity_count = opportunity_report.opportunities.len();
    let budget_count = opportunity_report.budgets.len();
    opportunity_report.opportunities.truncate(40);
    opportunity_report.budgets.truncate(40);
    check_cancel(control)?;
    let identity_file_bytes = fs::metadata(source.join("identities.ndjson"))
        .map_err(io)?
        .len();
    offsets
        .write_all(&identity_file_bytes.to_le_bytes())
        .map_err(io)?;
    offsets.flush().map_err(io)?;
    offsets.get_ref().sync_all().map_err(io)?;
    drop(offsets);
    let ranking = ranking.finish(temporary.path())?;
    if index
        .mstat
        .as_ref()
        .is_some_and(|summary| summary.accounted_size_bytes != total)
    {
        return Err(diagnostic(
            "explorer.accounting",
            "complete identity sum differs from recorded MSTAT total",
        ));
    }
    catalog.write("scopes", scopes(&groups, &families, memory)?)?;
    let mut group_values: Vec<_> = groups.into_values().collect();
    let group_count = group_values.len();
    group_values.sort_by(|left, right| {
        right.bytes.cmp(&left.bytes).then_with(|| {
            (&left.dimension, &left.stream, &left.name, &left.status).cmp(&(
                &right.dimension,
                &right.stream,
                &right.name,
                &right.status,
            ))
        })
    });
    catalog.write("groups", &group_values)?;
    let mut displayed_groups = Vec::new();
    let mut displayed_by_scope = BTreeMap::new();
    for group in group_values {
        let value = displayed_by_scope
            .entry((group.dimension.clone(), group.stream.clone()))
            .or_insert(0);
        if *value < DISPLAY_LIMIT {
            displayed_groups.push(group);
            *value += 1;
        }
    }
    let mut family_values: Vec<_> = families.into_values().collect();
    let generic_family_count = family_values.len();
    family_values.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| (&left.stream, &left.family).cmp(&(&right.stream, &right.family)))
    });
    catalog.write("generic_families", &family_values)?;
    family_values.truncate(DISPLAY_LIMIT);
    let mut contributors: Vec<_> = top.into_values().flatten().collect();
    sort_rows(&mut contributors);
    let displayed_bytes = contributors
        .iter()
        .filter(|row| row.accounted)
        .try_fold(0_u64, |sum, row| sum.checked_add(row.bytes))
        .ok_or_else(|| diagnostic("explorer.size", "display byte overflow"))?;
    let mut detail_values = BTreeMap::new();
    let mut reader = File::open(source.join("identities.ndjson")).map_err(io)?;
    let mut positions = File::open(temporary.path().join("offsets.bin")).map_err(io)?;
    for row in &contributors {
        let entry = read_identity(
            &mut reader,
            &mut positions,
            row.ordinal,
            count,
            identity_file_bytes,
            memory,
        )?;
        detail_values.insert(
            row.ordinal.to_string(),
            details(
                &matcher,
                &entry,
                row.ordinal,
                matcher
                    .locate_entry(&entry, symbols.as_mut())
                    .map_err(attribution)?,
            ),
        );
    }
    drop(reader);
    drop(positions);
    let mut resources = index.evidence.resources.clone();
    let resource_count = resources.len();
    let mut asset_bytes = 0;
    let mut container_bytes = 0;
    for resource in &resources {
        checked_add(
            if resource.is_container() {
                &mut container_bytes
            } else {
                &mut asset_bytes
            },
            resource.bytes,
        )?;
    }
    resources.sort_by(|left, right| {
        right.bytes.cmp(&left.bytes).then_with(|| {
            (&left.assembly, &left.container, &left.name).cmp(&(
                &right.assembly,
                &right.container,
                &right.name,
            ))
        })
    });
    catalog.write("resources", &resources)?;
    resources.truncate(200);
    let mut duplicates =
        vitnet_attribution::asset_duplicates(&index.evidence.resources).map_err(attribution)?;
    let duplicate_count = duplicates.len();
    duplicates.sort_by(|left, right| {
        right
            .bytes_each
            .cmp(&left.bytes_each)
            .then_with(|| left.sha256.cmp(&right.sha256))
    });
    catalog.write("duplicate_assets", &duplicates)?;
    duplicates.truncate(DISPLAY_LIMIT);
    for group in &mut duplicates {
        group.instances.truncate(20);
    }
    let mut routes =
        vitnet_attribution::package_routes(&index.evidence, memory / 4).map_err(attribution)?;
    let package_route_count = routes.len();
    catalog.write("package_routes", &routes)?;
    routes.truncate(200);
    let mut emitter_reports: Vec<_> = index.evidence.generators.iter().map(|generator| json!({
        "name":generator.name,"version":generator.version,"generated_files":generator.generated_files.len(),
        "declared_inputs":generator.input_symbols.len(),
        "generated_declarations":index.evidence.sources.iter().filter(|source| source.generated_by.as_deref()==Some(&generator.name)).count(),
        "candidate_accounted_bytes":generators.get(&(generator.name.clone(),"producer_prefix_candidate".into())).copied().unwrap_or(0),
        "asserted_accounted_bytes":generators.get(&(generator.name.clone(),"asserted".into())).copied().unwrap_or(0),
        "evidence":generator,
        "caveat":"Generator associations may overlap and do not measure the build-tool DLL or execution cost."
    })).collect();
    catalog.write("generators", &emitter_reports)?;
    for report in &mut emitter_reports {
        report
            .as_object_mut()
            .ok_or_else(|| diagnostic("explorer.invariant", "generator report is not an object"))?
            .remove("evidence");
    }
    emitter_reports.truncate(DISPLAY_LIMIT);
    let mut graph_values = Vec::new();
    for artifact in index.artifacts.iter().filter(|artifact| {
        artifact.available && matches!(artifact.kind.as_str(), "scan_index" | "codegen_index")
    }) {
        let info = vitnet_dgml::cache_info(&artifact.path).map_err(AppError::Dgml)?;
        if artifact.graph_generation.as_deref() != Some(&info.generation) {
            return Err(diagnostic(
                "explorer.graph.stale",
                "graph generation changed after attribution import",
            ));
        }
        graph_values.push(json!({"kind":artifact.kind,"generation":info.generation,"node_count":info.manifest.node_count,"edge_count":info.manifest.edge_count}));
    }
    let mut witnesses = Vec::new();
    if !nodes.is_empty() {
        let artifacts: Vec<_> = index
            .artifacts
            .iter()
            .filter(|artifact| artifact.available && artifact.kind == graph_kind)
            .collect();
        if artifacts.len() != 1 {
            return Err(diagnostic(
                "explorer.graph.missing",
                "offline witnesses require exactly one imported graph of the selected kind",
            ));
        }
        let mut graph =
            GraphSession::open(&artifacts[0].path, memory / 4).map_err(AppError::Dgml)?;
        graph.set_control(control.clone());
        for node in nodes {
            witnesses.push(
                graph
                    .why(*node, &why_options(&graph.generation))
                    .map_err(AppError::Dgml)?,
            );
        }
    }
    let comparison = before
        .map(|before| {
            vitnet_attribution::compare(before, &source, memory, DISPLAY_LIMIT).map_err(attribution)
        })
        .transpose()?;
    check_cancel(control)?;
    catalog.write("comparison", comparison.iter())?;
    let provenance_count = index.evidence.provenance.len();
    let provenance: BTreeMap<_, _> = index
        .evidence
        .provenance
        .iter()
        .take(DISPLAY_LIMIT)
        .map(|(key, value)| (key.clone(), preview(value, 1024).0))
        .collect();
    let diagnostic_count = index.diagnostics.len();
    catalog.write("diagnostics", &index.diagnostics)?;
    index.diagnostics.truncate(DISPLAY_LIMIT);
    let datasets = catalog.datasets;
    let mut snapshot = json!({
        "schema":SNAPSHOT_SCHEMA,"generation":null,"title":index.evidence.label,
        "datasets":datasets,
        "ranking":ranking,
        "ledger":{
            "accounted_bytes":index.mstat.as_ref().map(|_|total),
            "accounting_basis":"Reported NativeAOT object sizes; not a physical executable sum or savings estimate.",
            "physical_binaries":index.evidence.binaries.iter().map(|binary|json!({
                "path":binary.path,"format":binary.format,"architecture":binary.architecture,"file_bytes":binary.file_bytes,
            })).collect::<Vec<_>>(),
            "physical_total_bytes":if index.evidence.binaries.is_empty(){None}else{
                Some(index.evidence.binaries.iter().try_fold(0_u64, |sum, binary|sum.checked_add(binary.file_bytes))
                    .ok_or_else(||diagnostic("explorer.size","physical inventory overflow"))?)
            },
            "resource_asset_bytes":asset_bytes,"resource_container_bytes":container_bytes,
            "metadata_lower_bound_bytes":index.metadata.as_ref().map(|analysis|analysis.total_lower_bound),
            "resource_basis":"Inventory containers may contain child assets; neither inventory sum is additive to Blobs or proven equal to ResourceData.",
        },
        "accounting":{"total_bytes":index.mstat.as_ref().map(|_|total),"streams":streams.iter().map(|(name,(bytes,identities))|json!({"name":name,"bytes":bytes,"identities":identities})).collect::<Vec<_>>(),
            "methods":index.mstat.as_ref().map(|summary|&summary.methods),
            "metadata_lower_bound_bytes":index.metadata.as_ref().map(|analysis|analysis.total_lower_bound)},
        "groups":displayed_groups,"contributors":contributors,"details":detail_values,
        "generic_families":family_values,"generators":emitter_reports,"resources":resources,
        "opportunities":opportunity_report.opportunities, "budgets":opportunity_report.budgets,
        "lens_coverage":lens_report.coverage,
        "duplicate_assets":duplicates,"package_routes":routes,"provenance":provenance,
        "diagnostics":index.diagnostics,"graphs":graph_values,"witnesses":witnesses,"comparison":comparison,
        "metadata":index.metadata.as_ref().map(|analysis|json!({"by_kind":analysis.by_kind})),
        "coverage":{"identities":count,"contributors_shown":contributors.len(),
            "displayed_accounted_bytes":displayed_bytes,"remaining_accounted_bytes":total.saturating_sub(displayed_bytes),
            "resource_count":resource_count,"resource_asset_bytes":asset_bytes,"resource_container_bytes":container_bytes,
            "generic_family_count":generic_family_count,"group_count":group_count,
            "malformed_generic_identities":malformed,"duplicate_asset_group_count":duplicate_count,
            "package_route_count":package_route_count,"provenance_count":provenance_count,
            "diagnostic_count":diagnostic_count,"supplemental_inventories":inventories},
        "opportunity_coverage": {
            "findings":opportunity_count,"budgets":budget_count,
            "generated_declarations":opportunity_report.generated_declarations,
            "generator_descriptors":opportunity_report.generator_descriptors,
            "generator_runs":index.evidence.generator_runs.len(),
            "generator_links":index.evidence.generator_links.len(),
            "generator_outputs_captured":index.evidence.generator_runs.iter().map(|run| run.outputs.len()).sum::<usize>(),
            "typed_symbol_records":index.symbols.as_ref().map(|symbols| symbols.records),
            "full_dataset":"opportunity_coverage",
            "scope":"Ranked investigations, not predicted savings. Missing generator output/source provenance remains unknown.",
        },
        "limits":{"graph_nodes":200,"graph_edges":500,"page_rows":super::PAGE_LIMIT,"preview_bytes":PREVIEW_BYTES,
            "query_timeout_ms":super::QUERY_TIMEOUT_MS,"max_scanned":super::MAX_SCANNED},
        "caveats":[
            "Methods, Types and Blobs are additive; resources, metadata, generic families and generator associations are overlapping projections, never extra totals.",
            "Assembly groups are evidence-tiered source/name associations; owner groups are opaque producer prefixes, not managed namespace demangling.",
            "All identity aggregates use the complete verified cache. Displayed groups, contributors and inventories are bounded; remaining bytes remain accounted for.",
            "Local inventory routes are not compiler reachability. Selected witnesses and paged incoming edges are not all retention paths or predictions of reclaimed bytes.",
            "Source/build drift and import limitations remain visible. Recorded source anchors do not execute or fetch source files.",
            "Graph/source identities and byte ownership are independent evidence dimensions. Fan-in is never a byte size.",
        ],
    });
    bound_comparison(&mut snapshot["comparison"]);
    bound_text(&mut snapshot);
    let mut fingerprint = blake3::Hasher::new();
    fingerprint.update(b"vitnet.explorer-generation.v1\0");
    fingerprint.update(index_hash.as_bytes());
    fingerprint.update(index.identities_blake3.as_bytes());
    fingerprint.update(&serde_json::to_vec(&snapshot).map_err(AppError::Json)?);
    let generation = fingerprint.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    let snapshot_bytes = serde_json::to_vec(&snapshot).map_err(AppError::Json)?;
    if snapshot_bytes.len() as u64 > SNAPSHOT_LIMIT {
        return Err(diagnostic(
            "resource.explorer.snapshot",
            "bounded snapshot exceeds 8 MiB; reduce evidence dimensions",
        ));
    }
    write_synced(&temporary.path().join("snapshot.json"), &snapshot_bytes)?;
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA.into(),
        generation,
        attribution_index: source,
        index_blake3: index_hash,
        identities_blake3: index.identities_blake3,
        identity_file_bytes,
        identities: count,
        snapshot_blake3: blake3::hash(&snapshot_bytes).to_hex().to_string(),
        offsets_blake3: vitnet_attribution::hash_file(&temporary.path().join("offsets.bin"))
            .map_err(attribution)?
            .1,
        datasets,
        ranking: Some(ranking),
    };
    write_synced(
        &temporary.path().join("bundle.json"),
        &serde_json::to_vec(&manifest).map_err(AppError::Json)?,
    )?;
    check_cancel(control)?;
    fs::rename(temporary.path(), output).map_err(io)?;
    Ok(manifest)
}

#[allow(clippy::too_many_arguments)]
fn process_entry(
    entry: &CoalescedIdentity,
    offset: u64,
    offsets: &mut BufWriter<File>,
    sources: &SourceMatch,
    count: &mut u64,
    total: &mut u64,
    streams: &mut BTreeMap<String, (u64, u64)>,
    groups: &mut Groups,
    families: &mut BTreeMap<(String, String), GenericGroup>,
    generators: &mut BTreeMap<(String, String), u64>,
    opportunities: &mut vitnet_attribution::OpportunityCollector<'_>,
    top: &mut BTreeMap<String, Vec<Row>>,
    malformed: &mut u64,
    aggregate_storage: &mut u64,
    memory: u64,
    control: &IndexControl,
) -> Result<(), AppError> {
    check_cancel(control)?;
    offsets.write_all(&offset.to_le_bytes()).map_err(io)?;
    opportunities
        .observe(entry, sources, *count)
        .map_err(attribution)?;
    if entry.accounted {
        checked_add(total, entry.bytes)?;
        let stream = streams.entry(entry.stream.clone()).or_default();
        checked_add(&mut stream.0, entry.bytes)?;
        checked_add(&mut stream.1, 1)?;
        let assembly = if sources.assemblies.len() == 1 {
            sources.assemblies[0].as_str()
        } else if sources.assemblies.is_empty() {
            "_unmapped"
        } else {
            "_ambiguous"
        };
        add_group(
            groups,
            "assembly",
            &entry.stream,
            assembly,
            &sources.status,
            entry.bytes,
            aggregate_storage,
        )?;
        let owner = entry
            .identity
            .split_once("__")
            .map_or(entry.identity.as_str(), |(owner, _)| owner);
        let owner = owner.split_once('<').map_or(owner, |(family, _)| family);
        add_group(
            groups,
            "owner",
            &entry.stream,
            owner,
            "opaque_producer_family_prefix",
            entry.bytes,
            aggregate_storage,
        )?;
        let emitters: BTreeSet<_> = sources
            .sources
            .iter()
            .filter_map(|source| source.generated_by.as_deref())
            .collect();
        for emitter in emitters {
            checked_add(
                generators
                    .entry((emitter.into(), sources.status.clone()))
                    .or_default(),
                entry.bytes,
            )?;
        }
        let rows = top.entry(entry.stream.clone()).or_default();
        if rows.len() < DISPLAY_LIMIT || rows.last().is_some_and(|last| entry.bytes > last.bytes) {
            rows.push(Row::new(entry, *count));
            sort_rows(rows);
            rows.truncate(DISPLAY_LIMIT);
        }
    }
    if !entry.identity_lossy && matches!(entry.stream.as_str(), "Methods" | "Types") {
        match vitnet_attribution::parse_shape(&entry.identity) {
            Ok(Some(shape)) => {
                let group = families
                    .entry((entry.stream.clone(), shape.family.clone()))
                    .or_insert_with(|| {
                        *aggregate_storage = aggregate_storage.saturating_add(
                            (shape.family.len() * 2 + entry.stream.len() * 2) as u64 + 512,
                        );
                        GenericGroup {
                            stream: entry.stream.clone(),
                            family: shape.family,
                            ..GenericGroup::default()
                        }
                    });
                checked_add(&mut group.bytes, entry.bytes)?;
                checked_add(&mut group.identities, 1)?;
                checked_add(
                    &mut group.canonical_shared_identities,
                    u64::from(shape.canonical_shared),
                )?;
            }
            Ok(None) => {}
            Err(error) if error.diagnostic.code.starts_with("resource.") => {
                return Err(attribution(error));
            }
            Err(_) => checked_add(malformed, 1)?,
        }
    }
    if aggregate_storage.saturating_add(generators.len() as u64 * 4096) > memory / 4 {
        return Err(diagnostic(
            "resource.explorer.aggregates",
            "aggregate cardinality exceeds reserved memory share",
        ));
    }
    checked_add(count, 1)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let mut file = File::create(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)
}

pub(super) fn why_options(generation: &str) -> WhyOptions {
    WhyOptions {
        max_depth: 12,
        max_paths: 3,
        max_visited: 5000,
        max_edges: 25_000,
        timeout_ms: super::QUERY_TIMEOUT_MS,
        preview_bytes: 256,
        generation: Some(generation.into()),
    }
}

pub struct Bundle {
    pub manifest: BundleManifest,
    pub snapshot: Value,
    pub(super) directory: PathBuf,
}

impl Bundle {
    /// Opens a bounded snapshot and validates generation and file shapes.
    ///
    /// # Errors
    ///
    /// Returns explicit stale, corrupt, schema, I/O and resource diagnostics.
    #[allow(clippy::too_many_lines)]
    pub fn open(directory: &Path, memory: u64) -> Result<Self, AppError> {
        let manifest: BundleManifest =
            vitnet_attribution::read_json(&directory.join("bundle.json"), memory)
                .map_err(attribution)?;
        if manifest.schema != BUNDLE_SCHEMA {
            return Err(diagnostic("explorer.schema", "unsupported bundle schema"));
        }
        let snapshot_path = directory.join("snapshot.json");
        if fs::metadata(&snapshot_path).map_err(io)?.len() > SNAPSHOT_LIMIT {
            return Err(diagnostic(
                "resource.explorer.snapshot",
                "snapshot exceeds 8 MiB",
            ));
        }
        let mut snapshot: Value =
            vitnet_attribution::read_json(&snapshot_path, memory).map_err(attribution)?;
        if snapshot["schema"] != SNAPSHOT_SCHEMA || snapshot["generation"] != manifest.generation {
            return Err(diagnostic(
                "explorer.generation",
                "snapshot schema or generation differs from bundle",
            ));
        }
        let expected = manifest
            .identities
            .checked_add(1)
            .and_then(|count| count.checked_mul(8))
            .ok_or_else(|| diagnostic("explorer.offsets", "offset sidecar length overflow"))?;
        if fs::metadata(directory.join("offsets.bin"))
            .map_err(io)?
            .len()
            != expected
        {
            return Err(diagnostic(
                "explorer.offsets",
                "offset sidecar length differs from record count",
            ));
        }
        if fs::metadata(manifest.attribution_index.join("identities.ndjson"))
            .map_err(io)?
            .len()
            != manifest.identity_file_bytes
        {
            return Err(diagnostic(
                "explorer.source.stale",
                "original identity cache length changed",
            ));
        }
        if vitnet_attribution::hash_file(&manifest.attribution_index.join("index.json"))
            .map_err(attribution)?
            .1
            != manifest.index_blake3
        {
            return Err(diagnostic(
                "explorer.source.stale",
                "original attribution index changed",
            ));
        }
        if vitnet_attribution::hash_file(&snapshot_path)
            .map_err(attribution)?
            .1
            != manifest.snapshot_blake3
        {
            return Err(diagnostic(
                "explorer.snapshot.integrity",
                "snapshot hash differs from bundle",
            ));
        }
        let generation = snapshot["generation"].take();
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(b"vitnet.explorer-generation.v1\0");
        fingerprint.update(manifest.index_blake3.as_bytes());
        fingerprint.update(manifest.identities_blake3.as_bytes());
        fingerprint.update(&serde_json::to_vec(&snapshot).map_err(AppError::Json)?);
        snapshot["generation"] = generation;
        if fingerprint.finalize().to_hex().as_str() != manifest.generation {
            return Err(diagnostic(
                "explorer.generation",
                "bundle content differs from its recorded generation",
            ));
        }
        let expected_catalog = serde_json::to_value(&manifest.datasets).map_err(AppError::Json)?;
        if snapshot
            .get("datasets")
            .map_or(!manifest.datasets.is_empty(), |v| v != &expected_catalog)
        {
            return Err(diagnostic(
                "explorer.dataset.integrity",
                "catalog differs from snapshot generation",
            ));
        }
        for (name, descriptor) in &manifest.datasets {
            catalog::Reader::open(directory, name, descriptor)?;
        }
        if let Some(ranking) = &manifest.ranking {
            if snapshot["ranking"] != serde_json::to_value(ranking).map_err(AppError::Json)? {
                return Err(diagnostic(
                    "explorer.ranking.integrity",
                    "ranking differs from snapshot generation",
                ));
            }
            ranking::Reader::open(directory, ranking, manifest.identities)?;
        } else if snapshot.get("ranking").is_some() {
            return Err(diagnostic(
                "explorer.ranking.integrity",
                "ranking manifest is missing",
            ));
        }
        Ok(Self {
            manifest,
            snapshot,
            directory: directory.to_owned(),
        })
    }
}

/// Fully verifies small sidecars and the original streamed identity payload.
///
/// # Errors
///
/// Rejects any changed fingerprint or malformed cached identity.
pub fn verify(directory: &Path, memory: u64) -> Result<(), AppError> {
    let bundle = Bundle::open(directory, memory)?;
    for (path, expected) in [
        (
            directory.join("offsets.bin"),
            &bundle.manifest.offsets_blake3,
        ),
        (
            bundle.manifest.attribution_index.join("identities.ndjson"),
            &bundle.manifest.identities_blake3,
        ),
    ] {
        if vitnet_attribution::hash_file(&path).map_err(attribution)?.1 != *expected {
            return Err(diagnostic(
                "explorer.integrity",
                "sidecar or original identity hash changed",
            ));
        }
    }
    let index = vitnet_attribution::open_index(&bundle.manifest.attribution_index, memory)
        .map_err(attribution)?;
    if let Some(descriptor) = &index.symbols {
        vitnet_attribution::SymbolLookup::open(
            &bundle.manifest.attribution_index,
            descriptor,
            memory,
        )
        .map_err(attribution)?;
    }
    if let Some(descriptor) = &bundle.manifest.ranking {
        let mut ranking = ranking::Reader::open(directory, descriptor, bundle.manifest.identities)?;
        let (mut identities, mut offsets) = open_readers(&bundle)?;
        for position in 0..ranking.records {
            let (bytes, ordinal) = ranking.entry(position)?;
            let row = read_identity(
                &mut identities,
                &mut offsets,
                ordinal,
                bundle.manifest.identities,
                bundle.manifest.identity_file_bytes,
                memory,
            )?;
            if row.bytes != bytes {
                return Err(diagnostic(
                    "explorer.ranking.integrity",
                    "ranked bytes differ from identity",
                ));
            }
        }
    }
    for (name, descriptor) in &bundle.manifest.datasets {
        let mut reader = catalog::Reader::open(directory, name, descriptor)?;
        for ordinal in 0..descriptor.records {
            reader.record(ordinal, memory)?;
        }
    }
    vitnet_attribution::visit_identities(&bundle.manifest.attribution_index, &index, memory, |_| {
        Ok(())
    })
    .map_err(attribution)
}

pub(super) fn read_identity(
    reader: &mut File,
    offsets: &mut File,
    ordinal: u64,
    count: u64,
    total: u64,
    memory: u64,
) -> Result<CoalescedIdentity, AppError> {
    if ordinal >= count {
        return Err(diagnostic(
            "explorer.row",
            "row ordinal is outside this bundle",
        ));
    }
    offsets
        .seek(SeekFrom::Start(ordinal.checked_mul(8).ok_or_else(
            || diagnostic("explorer.offsets", "offset overflow"),
        )?))
        .map_err(io)?;
    let mut pair = [0; 16];
    offsets.read_exact(&mut pair).map_err(io)?;
    let start = u64::from_le_bytes(pair[..8].try_into().unwrap());
    let end = u64::from_le_bytes(pair[8..].try_into().unwrap());
    let limit = (memory / 64).min(ROW_LIMIT);
    if start >= end || end > total || end - start > limit {
        return Err(diagnostic(
            "explorer.offsets",
            "invalid or oversized identity row range",
        ));
    }
    reader.seek(SeekFrom::Start(start)).map_err(io)?;
    let mut bytes = Vec::new();
    reader
        .take(end - start)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| diagnostic("explorer.row.json", error.to_string()))
}

pub(super) fn open_readers(bundle: &Bundle) -> Result<(File, File), AppError> {
    Ok((
        File::open(bundle.manifest.attribution_index.join("identities.ndjson")).map_err(io)?,
        File::open(bundle.directory.join("offsets.bin")).map_err(io)?,
    ))
}
