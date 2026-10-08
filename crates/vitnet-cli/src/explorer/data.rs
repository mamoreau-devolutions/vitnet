use super::{DISPLAY_LIMIT, PREVIEW_BYTES, SNAPSHOT_LIMIT, attribution, diagnostic, io, preview};
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

fn located(matcher: &Matcher<'_>, entry: &CoalescedIdentity) -> SourceMatch {
    if entry.identity_lossy {
        SourceMatch {
            status: "unmapped_lossy_identity".into(),
            basis: "Lossy display decoding cannot establish a source association".into(),
            assemblies: Vec::new(),
            sources: Vec::new(),
        }
    } else {
        matcher.locate(&entry.stream, &entry.identity)
    }
}

pub(super) fn details(matcher: &Matcher<'_>, entry: &CoalescedIdentity, ordinal: u64) -> Value {
    let mut sources = located(matcher, entry);
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
        "caveat": "Source associations use the complete cached identity. Display labels and attributes may be shortened; they are not exact managed-symbol joins.",
    });
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
) -> Result<Vec<Value>, AppError> {
    let mut inventories = Vec::new();
    for path in paths {
        let mut evidence: Evidence =
            vitnet_attribution::read_json(path, memory / 2).map_err(attribution)?;
        vitnet_attribution::validate_evidence(&evidence).map_err(attribution)?;
        inventories.push(json!({
            "label": evidence.label, "resource_count": evidence.resources.len(),
            "package_count": evidence.packages.len(),
            "caveat": "Supplemental inventory is independent local evidence, not a compiler retention witness or a proven publish-time dependency graph."
        }));
        index.evidence.resources.append(&mut evidence.resources);
        index.evidence.packages.append(&mut evidence.packages);
        index.evidence.generators.append(&mut evidence.generators);
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
    Ok(inventories)
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
    let inventories = supplemental(&mut index, evidence, memory)?;
    let matcher = Matcher::new(&index.evidence);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(io)?;
    let temporary = tempfile::Builder::new()
        .prefix(".vitnet-explorer-")
        .tempdir_in(parent)
        .map_err(io)?;
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
    vitnet_attribution::visit_identities_with_offsets(&source, &index, memory, |entry, offset| {
        process_entry(
            entry,
            offset,
            &mut offsets,
            &matcher,
            &mut count,
            &mut total,
            &mut streams,
            &mut groups,
            &mut families,
            &mut generators,
            &mut top,
            &mut malformed,
            &mut aggregate_storage,
            memory,
            control,
        )
        .map_err(|cause| vitnet_attribution::AttributionError {
            diagnostic: match cause {
                AppError::Unsupported(value)
                | AppError::IoDiagnostic(value)
                | AppError::Resource(value) => value,
                other => Box::new(vitnet_core::Diagnostic::malformed(
                    "explorer.prepare",
                    other.to_string(),
                )),
            },
        })
    })
    .map_err(attribution)?;
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
            details(&matcher, &entry, row.ordinal),
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
            if resource.storage == "avalonia_container" {
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
    duplicates.truncate(DISPLAY_LIMIT);
    for group in &mut duplicates {
        group.instances.truncate(20);
    }
    let mut routes =
        vitnet_attribution::package_routes(&index.evidence, memory / 4).map_err(attribution)?;
    let package_route_count = routes.len();
    routes.truncate(200);
    let emitter_reports: Vec<_> = index.evidence.generators.iter().take(DISPLAY_LIMIT).map(|generator| json!({
        "name":generator.name,"version":generator.version,"generated_files":generator.generated_files.len(),
        "declared_inputs":generator.input_symbols.len(),
        "generated_declarations":index.evidence.sources.iter().filter(|source| source.generated_by.as_deref()==Some(&generator.name)).count(),
        "candidate_accounted_bytes":generators.get(&(generator.name.clone(),"producer_prefix_candidate".into())).copied().unwrap_or(0),
        "asserted_accounted_bytes":generators.get(&(generator.name.clone(),"asserted".into())).copied().unwrap_or(0),
        "caveat":"Generator associations may overlap and do not measure the build-tool DLL or execution cost."
    })).collect();
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
    let provenance_count = index.evidence.provenance.len();
    let provenance: BTreeMap<_, _> = index
        .evidence
        .provenance
        .iter()
        .take(DISPLAY_LIMIT)
        .map(|(key, value)| (key.clone(), preview(value, 1024).0))
        .collect();
    let diagnostic_count = index.diagnostics.len();
    index.diagnostics.truncate(DISPLAY_LIMIT);
    let mut snapshot = json!({
        "schema":SNAPSHOT_SCHEMA,"generation":null,"title":index.evidence.label,
        "accounting":{"total_bytes":index.mstat.as_ref().map(|_|total),"streams":streams.iter().map(|(name,(bytes,identities))|json!({"name":name,"bytes":bytes,"identities":identities})).collect::<Vec<_>>(),
            "methods":index.mstat.as_ref().map(|summary|&summary.methods),
            "metadata_lower_bound_bytes":index.metadata.as_ref().map(|analysis|analysis.total_lower_bound)},
        "groups":displayed_groups,"contributors":contributors,"details":detail_values,
        "generic_families":family_values,"generators":emitter_reports,"resources":resources,
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
    matcher: &Matcher<'_>,
    count: &mut u64,
    total: &mut u64,
    streams: &mut BTreeMap<String, (u64, u64)>,
    groups: &mut Groups,
    families: &mut BTreeMap<(String, String), GenericGroup>,
    generators: &mut BTreeMap<(String, String), u64>,
    top: &mut BTreeMap<String, Vec<Row>>,
    malformed: &mut u64,
    aggregate_storage: &mut u64,
    memory: u64,
    control: &IndexControl,
) -> Result<(), AppError> {
    check_cancel(control)?;
    offsets.write_all(&offset.to_le_bytes()).map_err(io)?;
    if entry.accounted {
        checked_add(total, entry.bytes)?;
        let stream = streams.entry(entry.stream.clone()).or_default();
        checked_add(&mut stream.0, entry.bytes)?;
        checked_add(&mut stream.1, 1)?;
        let sources = located(matcher, entry);
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
        let snapshot: Value =
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
