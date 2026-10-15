use crate::{DgmlError, malformed_error, resource_error};
use fs4::FileExt;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System};

mod query;
pub use query::{
    BatchReport, EdgePage, GraphSession, IncomingEdge, IncomingOptions, IncomingReport, SearchMode,
    SearchOptions, SearchRank, SearchReport, WhyOptions, WhyReport,
};

const INDEX_SCHEMA: &str = "vitnet.dgml-index.v1";
const NODE_RECORD_SIZE: u64 = 16;
const EDGE_RECORD_SIZE: usize = 32;
const LABEL_RECORD_SIZE: usize = 24;
const COPY_BUFFER_SIZE: usize = 1024 * 1024;
const MIN_SORT_MEMORY: u64 = 8 * 1024 * 1024;
const MIN_INDEX_MEMORY: u64 = 16 * 1024 * 1024;
const MAX_SORT_MEMORY: u64 = 512 * 1024 * 1024;
const MERGE_FAN_IN: usize = 16;
const LARGE_MERGE_FAN_IN: usize = 128;
const RUN_BUFFER_SIZE: usize = 64 * 1024;
const REQUIRED_FILES: [&str; 7] = [
    "manifest.json",
    "strings.bin",
    "nodes.bin",
    "labels.fst",
    "target-offsets.bin",
    "incoming-edges.bin",
    "reasons.bin",
];

#[derive(Clone, Debug, Default)]
pub struct IndexControl {
    cancelled: Arc<AtomicBool>,
    pub progress: Option<fn(&str, u64)>,
}

impl IndexControl {
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<(), DgmlError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(resource_error(
                "resource.cancelled",
                "DGML index build cancelled",
            ));
        }
        Ok(())
    }

    fn report(&self, phase: &str, records: u64) -> Result<(), DgmlError> {
        self.check()?;
        if let Some(progress) = self.progress {
            progress(phase, records);
        }
        self.check()
    }
}

#[derive(Clone, Debug)]
pub struct IndexOptions {
    pub cache_root: PathBuf,
    pub memory_limit: u64,
    pub selected_entry: Option<String>,
    pub strict_hash: bool,
    pub control: IndexControl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexFeatures {
    pub incoming_edges: bool,
    pub outgoing_edges: bool,
    pub label_fst: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlIndexManifest {
    pub schema: String,
    pub vitnet_version: String,
    pub canonical_input_path: PathBuf,
    pub input_length: u64,
    pub input_modified_unix_ns: u128,
    pub prefix_suffix_fingerprint: String,
    pub full_content_hash: Option<String>,
    pub selected_entry: Option<String>,
    pub node_count: u64,
    pub edge_count: u64,
    pub max_node_id: Option<u64>,
    pub duplicate_node_ids: u64,
    pub unresolved_endpoints: u64,
    pub features: IndexFeatures,
    pub created_unix_ns: u128,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlIndexReport {
    pub schema: String,
    pub index_directory: PathBuf,
    pub generation: String,
    pub manifest: DgmlIndexManifest,
    pub index_bytes: u64,
    pub temporary_bytes: u64,
    pub peak_tracked_memory_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlCacheInfo {
    pub schema: String,
    pub index_directory: PathBuf,
    pub generation: String,
    pub manifest: DgmlIndexManifest,
    pub index_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlCacheVerification {
    pub schema: String,
    pub index_directory: PathBuf,
    pub generation: String,
    pub files_verified: u64,
    pub index_bytes: u64,
    pub valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlCachePruneReport {
    pub schema: String,
    pub index_directory: PathBuf,
    pub current_generation: String,
    pub generations_removed: u64,
    pub temporary_directories_removed: u64,
    pub bytes_removed: u64,
}

#[derive(Serialize, Deserialize)]
struct LockMetadata {
    pid: u32,
    process_start_time: u64,
    created_unix_ns: u128,
}

struct BuildLock {
    _file: File,
}

struct BuildDirectory {
    path: PathBuf,
    published: bool,
}

impl Drop for BuildDirectory {
    fn drop(&mut self) {
        if !self.published {
            if let Err(error) = fs::remove_dir_all(&self.path) {
                eprintln!("dgml.index.cleanup: {}: {error}", self.path.display());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EdgeRecord {
    target: u64,
    source: u64,
    reason_offset: u64,
    reason_len: u32,
    flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LabelRecord {
    node_id: u64,
    label_offset: u64,
    label_len: u32,
    flags: u32,
}

#[derive(Debug, Eq, PartialEq)]
struct OwnedLabel {
    node_id: u64,
    value: Vec<u8>,
}

struct BufferedLabel {
    node_id: u64,
    range: std::ops::Range<usize>,
}

struct MergeTree {
    leaves: usize,
    winners: Vec<Option<usize>>,
}

impl MergeTree {
    fn new<T>(heads: &[Option<T>], compare: impl Fn(&T, &T) -> std::cmp::Ordering) -> Self {
        let leaves = heads.len().max(1).next_power_of_two();
        let mut tree = Self {
            leaves,
            winners: vec![None; leaves * 2],
        };
        for (index, head) in heads.iter().enumerate() {
            tree.winners[leaves + index] = head.as_ref().map(|_| index);
        }
        for node in (1..leaves).rev() {
            tree.refresh(node, heads, &compare);
        }
        tree
    }

    fn first(&self) -> Option<usize> {
        self.winners[1]
    }

    fn update<T>(
        &mut self,
        index: usize,
        heads: &[Option<T>],
        compare: impl Fn(&T, &T) -> std::cmp::Ordering,
    ) {
        let mut node = self.leaves + index;
        self.winners[node] = heads[index].as_ref().map(|_| index);
        while node > 1 {
            node /= 2;
            self.refresh(node, heads, &compare);
        }
    }

    fn refresh<T>(
        &mut self,
        node: usize,
        heads: &[Option<T>],
        compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
    ) {
        self.winners[node] = match (self.winners[node * 2], self.winners[node * 2 + 1]) {
            (Some(left), Some(right)) => {
                let left_head = heads[left].as_ref().expect("populated merge winner");
                let right_head = heads[right].as_ref().expect("populated merge winner");
                if compare(left_head, right_head).is_le() {
                    Some(left)
                } else {
                    Some(right)
                }
            }
            (left, right) => left.or(right),
        };
    }
}

struct ParsedGraph {
    node_count: u64,
    edge_count: u64,
    max_node_id: Option<u64>,
    duplicate_node_ids: u64,
    seen_nodes: Vec<u64>,
    peak_tracked_memory_bytes: u64,
}

struct EventInput<R> {
    input: R,
    remaining: usize,
}

impl<R: BufRead> Read for EventInput<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self.fill_buf()?;
        let length = bytes.len().min(output.len());
        output[..length].copy_from_slice(&bytes[..length]);
        self.consume(length);
        Ok(length)
    }
}

impl<R: BufRead> BufRead for EventInput<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.remaining == 0 {
            return Err(std::io::Error::other(
                "XML event exceeds the index record limit",
            ));
        }
        let bytes = self.input.fill_buf()?;
        Ok(&bytes[..bytes.len().min(self.remaining)])
    }

    fn consume(&mut self, count: usize) {
        self.remaining -= count;
        self.input.consume(count);
    }
}

/// Builds and atomically publishes an immutable DGML index generation.
///
/// # Errors
///
/// Returns typed I/O, malformed-input, resource-limit, ZIP-selection, or
/// concurrent-build diagnostics.
#[allow(clippy::too_many_lines)]
pub fn build_index(input: &Path, options: &IndexOptions) -> Result<DgmlIndexReport, DgmlError> {
    options.control.check()?;
    if options.memory_limit < MIN_INDEX_MEMORY {
        return Err(resource_error(
            "resource.memory_limit",
            format!("DGML indexing needs at least {MIN_INDEX_MEMORY} bytes of memory"),
        ));
    }
    let canonical_input = input.canonicalize().map_err(|error| {
        io_error(
            "dgml.index.input",
            format!("unable to canonicalize {}: {error}", input.display()),
        )
    })?;
    let metadata = canonical_input.metadata().map_err(|error| {
        io_error(
            "dgml.index.input",
            format!("unable to inspect {}: {error}", canonical_input.display()),
        )
    })?;
    let input_length = metadata.len();
    let input_modified_unix_ns = modified_ns(&metadata)?;
    let prefix_suffix_fingerprint = prefix_suffix_fingerprint(&canonical_input)?;
    let full_content_hash = if options.strict_hash {
        Some(hash_file_controlled(&canonical_input, &options.control)?)
    } else {
        None
    };
    let selected_entry = select_zip_entry(&canonical_input, options.selected_entry.as_deref())?;
    let input_key = input_key(
        &canonical_input,
        input_length,
        input_modified_unix_ns,
        selected_entry.as_deref(),
    );
    let index_directory = options.cache_root.join(input_key);
    fs::create_dir_all(index_directory.join("generations")).map_err(|error| {
        io_error(
            "dgml.index.cache",
            format!(
                "unable to create cache directory {}: {error}",
                index_directory.display()
            ),
        )
    })?;
    let _lock = acquire_lock(&index_directory.join("lock"))?;
    options.control.report("ingesting XML", 0)?;
    let generation = format!("{}-{}", unix_ns(), std::process::id());
    let mut build = BuildDirectory {
        path: index_directory
            .join("generations")
            .join(format!(".building-{generation}")),
        published: false,
    };
    fs::create_dir(&build.path).map_err(|error| {
        io_error(
            "dgml.index.generation",
            format!(
                "unable to create generation directory {}: {error}",
                build.path.display()
            ),
        )
    })?;

    let parsed = with_input_reader(&canonical_input, selected_entry.as_deref(), |reader| {
        parse_to_spools(reader, &build.path, options.memory_limit, &options.control)
    })
    .map_err(|mut error| {
        error.diagnostic.input_path = Some(canonical_input.clone());
        error.diagnostic.zip_entry.clone_from(&selected_entry);
        error
    })?;
    let available = options
        .memory_limit
        .saturating_sub((parsed.seen_nodes.capacity() * size_of::<u64>()) as u64);
    if available < MIN_SORT_MEMORY {
        return Err(resource_error(
            "resource.memory_limit",
            "node presence state leaves insufficient sort memory",
        ));
    }
    let sort_memory = (available / 4).clamp(MIN_SORT_MEMORY, MAX_SORT_MEMORY);
    options
        .control
        .report("sorting labels", parsed.node_count)?;
    build_label_fst(&build.path, sort_memory, &options.control)?;
    options
        .control
        .report("sorting incoming edges", parsed.edge_count)?;
    let unresolved_endpoints = build_incoming_edges(
        &build.path,
        &parsed.seen_nodes,
        parsed.max_node_id,
        sort_memory,
        &options.control,
    )?;
    let final_metadata = canonical_input
        .metadata()
        .map_err(|error| io_error("dgml.index.input", error.to_string()))?;
    if final_metadata.len() != input_length
        || modified_ns(&final_metadata)? != input_modified_unix_ns
        || self::prefix_suffix_fingerprint(&canonical_input)? != prefix_suffix_fingerprint
    {
        return Err(malformed_simple(
            "dgml.input.changed",
            "input changed during index construction",
        ));
    }
    if let Some(expected) = &full_content_hash {
        if hash_file_controlled(&canonical_input, &options.control)? != *expected {
            return Err(malformed_simple(
                "dgml.input.changed",
                "input content changed during strict index construction",
            ));
        }
    }

    let manifest = DgmlIndexManifest {
        schema: INDEX_SCHEMA.into(),
        vitnet_version: env!("CARGO_PKG_VERSION").into(),
        canonical_input_path: canonical_input,
        input_length,
        input_modified_unix_ns,
        prefix_suffix_fingerprint,
        full_content_hash,
        selected_entry,
        node_count: parsed.node_count,
        edge_count: parsed.edge_count,
        max_node_id: parsed.max_node_id,
        duplicate_node_ids: parsed.duplicate_node_ids,
        unresolved_endpoints,
        features: IndexFeatures {
            incoming_edges: true,
            outgoing_edges: false,
            label_fst: true,
        },
        created_unix_ns: unix_ns(),
        complete: true,
    };
    write_json_sync(&build.path.join("manifest.json"), &manifest)?;
    options.control.report("checksumming generation", 0)?;
    let checksums = write_checksums(&build.path, &options.control)?;
    write_json_sync(&build.path.join("checksums.json"), &checksums)?;
    sync_generation_files(&build.path)?;
    sync_directory(&build.path)?;
    options.control.report("publishing generation", 0)?;

    let final_generation = index_directory.join("generations").join(&generation);
    fs::rename(&build.path, &final_generation).map_err(|error| {
        io_error(
            "dgml.index.publish",
            format!("unable to publish generation {generation}: {error}"),
        )
    })?;
    build.published = true;
    sync_directory(&index_directory.join("generations"))?;
    publish_current(&index_directory, &generation)?;
    let index_bytes = directory_file_bytes(&final_generation)?;

    Ok(DgmlIndexReport {
        schema: INDEX_SCHEMA.into(),
        index_directory,
        generation,
        manifest,
        index_bytes,
        temporary_bytes: 0,
        peak_tracked_memory_bytes: parsed.peak_tracked_memory_bytes.max(
            sort_memory
                .saturating_add(6 * COPY_BUFFER_SIZE as u64)
                .saturating_add((parsed.seen_nodes.capacity() * size_of::<u64>()) as u64),
        ),
    })
}

/// Reads the currently published generation and its manifest.
///
/// # Errors
///
/// Returns a typed cache diagnostic when `CURRENT` or the manifest is invalid.
pub fn cache_info(index_directory: &Path) -> Result<DgmlCacheInfo, DgmlError> {
    let _lock = acquire_read_lock(&index_directory.join("lock"))?;
    cache_info_unlocked(index_directory)
}

fn cache_info_unlocked(index_directory: &Path) -> Result<DgmlCacheInfo, DgmlError> {
    let (generation, path) = current_generation(index_directory)?;
    let manifest: DgmlIndexManifest = read_json(&path.join("manifest.json"))?;
    validate_manifest(&manifest)?;
    Ok(DgmlCacheInfo {
        schema: "vitnet.dgml-cache-info.v1".into(),
        index_directory: index_directory.to_owned(),
        generation,
        manifest,
        index_bytes: directory_file_bytes(&path)?,
    })
}

/// Recomputes every published generation checksum.
///
/// # Errors
///
/// Returns a typed cache diagnostic for missing, malformed, or mismatched
/// files.
pub fn verify_cache(index_directory: &Path) -> Result<DgmlCacheVerification, DgmlError> {
    let _lock = acquire_read_lock(&index_directory.join("lock"))?;
    let info = cache_info_unlocked(index_directory)?;
    let generation_path = index_directory.join("generations").join(&info.generation);
    let expected: BTreeMap<String, String> = read_json(&generation_path.join("checksums.json"))?;
    if expected.len() != REQUIRED_FILES.len()
        || REQUIRED_FILES
            .iter()
            .any(|name| !expected.contains_key(*name))
    {
        return Err(malformed_simple(
            "dgml.cache.checksum",
            "checksums must cover every required generation file",
        ));
    }
    validate_generation_structure(&generation_path, &info.manifest)?;
    for (name, expected_hash) in &expected {
        if Path::new(name).components().count() != 1 {
            return Err(malformed_simple(
                "dgml.cache.checksum",
                format!("invalid checksum path `{name}`"),
            ));
        }
        let actual = hash_file(&generation_path.join(name))?;
        if actual != *expected_hash {
            let mut diagnostic = vitnet_core::Diagnostic::malformed(
                "dgml.cache.checksum",
                format!("checksum mismatch for `{name}`"),
            );
            diagnostic.expected = Some(expected_hash.clone());
            diagnostic.actual = Some(actual);
            return Err(DgmlError {
                diagnostic: Box::new(diagnostic),
            });
        }
    }
    Ok(DgmlCacheVerification {
        schema: "vitnet.dgml-cache-verification.v1".into(),
        index_directory: index_directory.to_owned(),
        generation: info.generation,
        files_verified: expected.len() as u64,
        index_bytes: info.index_bytes,
        valid: true,
    })
}

fn validate_generation_structure(
    directory: &Path,
    manifest: &DgmlIndexManifest,
) -> Result<(), DgmlError> {
    let slots = manifest
        .max_node_id
        .map_or(Some(0), |id| id.checked_add(1))
        .ok_or_else(|| malformed_simple("dgml.cache.structure", "node range overflow"))?;
    for (name, records, width) in [
        ("nodes.bin", slots, NODE_RECORD_SIZE),
        (
            "target-offsets.bin",
            slots
                .checked_add(1)
                .ok_or_else(|| malformed_simple("dgml.cache.structure", "CSR length overflow"))?,
            8,
        ),
        ("incoming-edges.bin", manifest.edge_count, 24),
    ] {
        let expected = records
            .checked_mul(width)
            .ok_or_else(|| malformed_simple("dgml.cache.structure", "file length overflow"))?;
        if file_length(&directory.join(name))? != expected {
            return Err(malformed_simple(
                "dgml.cache.structure",
                format!("incorrect length for {name}"),
            ));
        }
    }
    let string_length = file_length(&directory.join("strings.bin"))?;
    let reason_length = file_length(&directory.join("reasons.bin"))?;
    validate_fst_container(&directory.join("labels.fst"), manifest.node_count)?;
    let mut nodes = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("nodes.bin"))
            .map_err(|error| io_error("dgml.cache.read", error.to_string()))?,
    );
    let mut present = 0_u64;
    while let Some(record) = read_record::<16, _>(&mut nodes, "dgml.cache.structure")? {
        let offset = u64::from_le_bytes(record[0..8].try_into().expect("fixed range"));
        let length = u32::from_le_bytes(record[8..12].try_into().expect("fixed range"));
        let flags = u32::from_le_bytes(record[12..16].try_into().expect("fixed range"));
        if flags > 1
            || offset
                .checked_add(u64::from(length))
                .is_none_or(|end| end > string_length)
        {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid node record",
            ));
        }
        present += u64::from(flags == 1);
    }
    if present != manifest.node_count {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "node presence count differs from manifest",
        ));
    }
    let mut offsets = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("target-offsets.bin"))
            .map_err(|error| io_error("dgml.cache.read", error.to_string()))?,
    );
    let mut previous = 0_u64;
    let mut count = 0_u64;
    while let Some(record) = read_record::<8, _>(&mut offsets, "dgml.cache.structure")? {
        let value = u64::from_le_bytes(record);
        if value < previous || value > manifest.edge_count || (count == 0 && value != 0) {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid CSR offset sequence",
            ));
        }
        count += 1;
        previous = value;
    }
    if previous != manifest.edge_count {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "CSR sentinel differs from edge count",
        ));
    }
    let mut edges = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("incoming-edges.bin"))
            .map_err(|error| io_error("dgml.cache.read", error.to_string()))?,
    );
    while let Some(record) = read_record::<24, _>(&mut edges, "dgml.cache.structure")? {
        let offset = u64::from_le_bytes(record[8..16].try_into().expect("fixed range"));
        let length = u32::from_le_bytes(record[16..20].try_into().expect("fixed range"));
        if record[20..24] != [0; 4]
            || offset
                .checked_add(u64::from(length))
                .is_none_or(|end| end > reason_length)
        {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid incoming edge record",
            ));
        }
    }
    Ok(())
}

fn file_length(path: &Path) -> Result<u64, DgmlError> {
    path.metadata()
        .map(|value| value.len())
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))
}

fn validate_fst_container(path: &Path, node_count: u64) -> Result<(), DgmlError> {
    let mut file =
        File::open(path).map_err(|error| io_error("dgml.cache.read", error.to_string()))?;
    let length = file
        .metadata()
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))?
        .len();
    if length < 36 {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "truncated label FST",
        ));
    }
    let mut version = [0_u8; 8];
    file.read_exact(&mut version)
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))?;
    file.seek(SeekFrom::End(-20))
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))?;
    let mut footer = [0_u8; 20];
    file.read_exact(&mut footer)
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))?;
    let keys = u64::from_le_bytes(footer[..8].try_into().expect("fixed range"));
    let root = u64::from_le_bytes(footer[8..16].try_into().expect("fixed range"));
    if u64::from_le_bytes(version) != fst::raw::VERSION
        || keys != node_count
        || !(root == 0 && length == 36 || root.checked_add(21) == Some(length))
    {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "invalid label FST version, key count, or root offset",
        ));
    }
    Ok(())
}

/// Removes interrupted builds and non-current immutable generations.
///
/// # Errors
///
/// Returns a typed cache or I/O diagnostic. The current generation is never
/// removed.
pub fn prune_cache(index_directory: &Path) -> Result<DgmlCachePruneReport, DgmlError> {
    let _lock = acquire_lock(&index_directory.join("lock"))?;
    let current = if index_directory.join("CURRENT").exists() {
        current_generation(index_directory)?.0
    } else {
        String::new()
    };
    let generations = index_directory.join("generations");
    let mut generations_removed = 0_u64;
    let mut temporary_directories_removed = 0_u64;
    let mut bytes_removed = 0_u64;
    for entry in fs::read_dir(&generations)
        .map_err(|error| io_error("dgml.cache.prune", error.to_string()))?
    {
        let entry = entry.map_err(|error| io_error("dgml.cache.prune", error.to_string()))?;
        if !entry
            .file_type()
            .map_err(|error| io_error("dgml.cache.prune", error.to_string()))?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == current || (!name.starts_with(".building-") && !valid_generation_name(&name)) {
            continue;
        }
        let path = entry.path();
        bytes_removed = bytes_removed.saturating_add(directory_tree_bytes(&path)?);
        fs::remove_dir_all(&path)
            .map_err(|error| io_error("dgml.cache.prune", error.to_string()))?;
        if name.starts_with(".building-") {
            temporary_directories_removed += 1;
        } else {
            generations_removed += 1;
        }
    }
    Ok(DgmlCachePruneReport {
        schema: "vitnet.dgml-cache-prune.v1".into(),
        index_directory: index_directory.to_owned(),
        current_generation: current,
        generations_removed,
        temporary_directories_removed,
        bytes_removed,
    })
}

#[allow(clippy::too_many_lines)]
fn parse_to_spools<R: Read>(
    input: R,
    directory: &Path,
    memory_limit: u64,
    control: &IndexControl,
) -> Result<ParsedGraph, DgmlError> {
    let event_limit = usize::try_from((memory_limit / 64).min(COPY_BUFFER_SIZE as u64))
        .map_err(|_| resource_error("resource.memory_limit", "XML record budget exceeds usize"))?;
    let mut reader = Reader::from_reader(EventInput {
        input: BufReader::with_capacity(256 * 1024, input),
        remaining: event_limit,
    });
    reader.config_mut().trim_text(false);
    let mut xml_buffer = Vec::with_capacity(256 * 1024);
    let nodes_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(directory.join("nodes.bin"))
        .map_err(|error| io_error("dgml.index.nodes", error.to_string()))?;
    let mut nodes = BufWriter::with_capacity(COPY_BUFFER_SIZE, nodes_file);
    let mut node_file_position = 0_u64;
    let mut strings = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("strings.bin"))
            .map_err(|error| io_error("dgml.index.strings", error.to_string()))?,
    );
    let mut labels = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("labels.tmp"))
            .map_err(|error| io_error("dgml.index.labels", error.to_string()))?,
    );
    let mut edges = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("edges.tmp"))
            .map_err(|error| io_error("dgml.index.edges", error.to_string()))?,
    );
    let mut reasons = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("reasons.bin"))
            .map_err(|error| io_error("dgml.index.reasons", error.to_string()))?,
    );
    let mut reason_ids = HashMap::<Vec<u8>, (u64, u32)>::new();
    let mut seen_nodes = Vec::<u64>::new();
    let mut node_count = 0_u64;
    let mut edge_count = 0_u64;
    let mut duplicate_node_ids = 0_u64;
    let mut max_node_id = None::<u64>;
    let mut string_offset = 0_u64;
    let mut reason_offset = 0_u64;
    let mut peak_tracked = 0_u64;
    let mut in_graph = false;
    let mut graph_closed = false;
    let mut depth = 0_u64;
    let mut reason_memory = 0_u64;

    loop {
        reader.get_mut().remaining = event_limit;
        if (node_count + edge_count) % 65536 == 0 {
            control.check()?;
        }
        match reader.read_event_into(&mut xml_buffer) {
            Ok(event @ (Event::Start(_) | Event::Empty(_))) => {
                let empty = matches!(event, Event::Empty(_));
                let (Event::Start(element) | Event::Empty(element)) = event else {
                    unreachable!()
                };
                if graph_closed || (depth == 0 && element.local_name().as_ref() != "DirectedGraph")
                {
                    return Err(malformed_error(
                        "dgml.root",
                        "content outside DirectedGraph root",
                        reader.buffer_position(),
                    ));
                }
                match element.local_name().as_ref() {
                    "DirectedGraph" => {
                        if in_graph || depth != 0 {
                            return Err(malformed_error(
                                "dgml.root",
                                "DirectedGraph must be the single document root",
                                reader.buffer_position(),
                            ));
                        }
                        in_graph = true;
                        graph_closed = empty;
                    }
                    "Node" if in_graph => {
                        validate_attributes(&reader, &element)?;
                        let id = numeric_attribute(&reader, &element, "Id")?;
                        ensure_seen_capacity(
                            id,
                            &mut seen_nodes,
                            memory_limit,
                            reader.buffer_position(),
                        )?;
                        let label =
                            normalized_attribute(&reader, &element, "Label")?.unwrap_or_default();
                        let word = usize::try_from(id / 64)
                            .map_err(|_| resource_error("dgml.node_id", "node ID exceeds usize"))?;
                        let bit = 1_u64 << (id % 64);
                        if seen_nodes[word] & bit != 0 {
                            duplicate_node_ids = duplicate_node_ids.saturating_add(1);
                        } else {
                            seen_nodes[word] |= bit;
                            node_count = node_count.saturating_add(1);
                            max_node_id = Some(max_node_id.map_or(id, |value| value.max(id)));
                            strings.write_all(&label).map_err(|error| {
                                io_error("dgml.index.strings", error.to_string())
                            })?;
                            let label_len = u32::try_from(label.len()).map_err(|_| {
                                resource_error("dgml.label", "node label exceeds u32")
                            })?;
                            write_label(
                                &mut labels,
                                LabelRecord {
                                    node_id: id,
                                    label_offset: string_offset,
                                    label_len,
                                    flags: 1,
                                },
                            )?;
                            write_node_at(
                                &mut nodes,
                                &mut node_file_position,
                                id,
                                string_offset,
                                label_len,
                                1,
                            )?;
                            string_offset = string_offset
                                .checked_add(label.len() as u64)
                                .ok_or_else(|| {
                                    resource_error("dgml.index.strings", "string offset overflow")
                                })?;
                        }
                    }
                    "Link" if in_graph => {
                        validate_attributes(&reader, &element)?;
                        let source = numeric_attribute(&reader, &element, "Source")?;
                        let target = numeric_attribute(&reader, &element, "Target")?;
                        let (offset, length) = intern_reason(
                            &reader,
                            &element,
                            &mut reason_ids,
                            &mut reasons,
                            &mut reason_offset,
                            &mut reason_memory,
                        )?;
                        write_edge(
                            &mut edges,
                            EdgeRecord {
                                target,
                                source,
                                reason_offset: offset,
                                reason_len: length,
                                flags: 0,
                            },
                        )?;
                        edge_count = edge_count.checked_add(1).ok_or_else(|| {
                            resource_error("dgml.index.edges", "edge count overflow")
                        })?;
                    }
                    _ => {}
                }
                if !empty {
                    depth = depth.checked_add(1).ok_or_else(|| {
                        resource_error("resource.memory_limit", "XML depth overflow")
                    })?;
                }
            }
            Ok(Event::DocType(_) | Event::GeneralRef(_)) => {
                return Err(malformed_error(
                    "dgml.xml.external_entity",
                    "DTD and entity references are not allowed",
                    reader.buffer_position(),
                ));
            }
            Ok(Event::End(element)) => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    malformed_error(
                        "dgml.xml",
                        "unmatched closing element",
                        reader.buffer_position(),
                    )
                })?;
                if element.local_name().as_ref() == "DirectedGraph" {
                    graph_closed = true;
                }
            }
            Ok(Event::Eof) => break,
            Ok(Event::Text(text))
                if depth == 0 && !text.as_ref().bytes().all(|byte| byte.is_ascii_whitespace()) =>
            {
                return Err(malformed_error(
                    "dgml.root",
                    "text outside DirectedGraph root",
                    reader.buffer_position(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                if reader.get_ref().remaining == 0 {
                    return Err(resource_error(
                        "resource.record_limit",
                        format!("XML event exceeds {event_limit} bytes"),
                    ));
                }
                return Err(malformed_error(
                    "dgml.xml",
                    format!("invalid XML: {error}"),
                    reader.buffer_position(),
                ));
            }
        }
        let tracked = (xml_buffer.capacity() as u64)
            .saturating_add((seen_nodes.capacity() * size_of::<u64>()) as u64)
            .saturating_add(reason_memory)
            .saturating_add((COPY_BUFFER_SIZE * 6) as u64);
        peak_tracked = peak_tracked.max(tracked);
        if tracked > memory_limit {
            return Err(resource_limit(
                tracked,
                memory_limit,
                reader.buffer_position(),
            ));
        }
        xml_buffer.clear();
    }
    if !in_graph {
        return Err(malformed_error(
            "dgml.root",
            "missing DirectedGraph root element",
            reader.buffer_position(),
        ));
    }
    if !graph_closed || depth != 0 {
        return Err(malformed_error(
            "dgml.xml",
            "DirectedGraph element is not closed",
            reader.buffer_position(),
        ));
    }
    strings
        .flush()
        .and_then(|()| labels.flush())
        .and_then(|()| edges.flush())
        .and_then(|()| reasons.flush())
        .and_then(|()| nodes.flush())
        .map_err(|error| io_error("dgml.index.flush", error.to_string()))?;
    nodes
        .get_ref()
        .sync_all()
        .map_err(|error| io_error("dgml.index.nodes", error.to_string()))?;
    Ok(ParsedGraph {
        node_count,
        edge_count,
        max_node_id,
        duplicate_node_ids,
        seen_nodes,
        peak_tracked_memory_bytes: peak_tracked,
    })
}

fn build_incoming_edges(
    directory: &Path,
    seen_nodes: &[u64],
    max_node_id: Option<u64>,
    sort_memory: u64,
    control: &IndexControl,
) -> Result<u64, DgmlError> {
    let runs = create_edge_runs(directory, sort_memory, control)?;
    let runs = reduce_runs(directory, runs, false, merge_fan_in(sort_memory), control)?;
    let mut readers = open_edge_runs(&runs)?;
    let mut current = readers
        .iter_mut()
        .map(read_edge)
        .collect::<Result<Vec<_>, _>>()?;
    let mut tree = MergeTree::new(&current, EdgeRecord::cmp);
    let mut incoming = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("incoming-edges.bin"))
            .map_err(|error| io_error("dgml.index.incoming", error.to_string()))?,
    );
    let mut offsets = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("target-offsets.bin"))
            .map_err(|error| io_error("dgml.index.offsets", error.to_string()))?,
    );
    let mut next_target = 0_u64;
    let mut emitted = 0_u64;
    let mut unresolved = 0_u64;
    while let Some(index) = tree.first() {
        if emitted % 65536 == 0 {
            control.check()?;
        }
        let record = current[index].take().expect("selected populated run");
        if !node_exists(seen_nodes, record.source) {
            unresolved = unresolved.saturating_add(1);
        }
        if !node_exists(seen_nodes, record.target) {
            unresolved = unresolved.saturating_add(1);
        }
        if max_node_id.is_none_or(|max| record.target > max) {
            return Err(malformed_simple(
                "dgml.edge.target",
                "link target exceeds the declared node range",
            ));
        }
        while next_target <= record.target {
            write_u64(&mut offsets, emitted)?;
            next_target += 1;
        }
        write_u64(&mut incoming, record.source)?;
        write_u64(&mut incoming, record.reason_offset)?;
        write_u32(&mut incoming, record.reason_len)?;
        write_u32(&mut incoming, record.flags)?;
        emitted = emitted
            .checked_add(1)
            .ok_or_else(|| resource_error("dgml.index.edges", "edge count overflow"))?;
        current[index] = read_edge(&mut readers[index])?;
        tree.update(index, &current, EdgeRecord::cmp);
    }
    let required_offsets = max_node_id.map_or(1, |id| id.saturating_add(2));
    while next_target < required_offsets {
        write_u64(&mut offsets, emitted)?;
        next_target += 1;
    }
    incoming
        .flush()
        .and_then(|()| offsets.flush())
        .map_err(|error| io_error("dgml.index.flush", error.to_string()))?;
    drop(readers);
    for path in runs {
        fs::remove_file(path).map_err(|error| io_error("dgml.index.cleanup", error.to_string()))?;
    }
    fs::remove_file(directory.join("edges.tmp"))
        .map_err(|error| io_error("dgml.index.cleanup", error.to_string()))?;
    Ok(unresolved)
}

fn create_edge_runs(
    directory: &Path,
    sort_memory: u64,
    control: &IndexControl,
) -> Result<Vec<PathBuf>, DgmlError> {
    let mut input = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("edges.tmp"))
            .map_err(|error| io_error("dgml.index.edges", error.to_string()))?,
    );
    let capacity = usize::try_from(sort_memory / EDGE_RECORD_SIZE as u64)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut runs = Vec::new();
    loop {
        control.check()?;
        let mut records = Vec::new();
        records.try_reserve_exact(capacity).map_err(|error| {
            resource_error(
                "resource.memory_limit",
                format!("unable to reserve edge sort buffer: {error}"),
            )
        })?;
        while records.len() < capacity {
            match read_edge(&mut input)? {
                Some(record) => records.push(record),
                None => break,
            }
        }
        if records.is_empty() {
            break;
        }
        records.sort_unstable();
        let path = directory.join(format!("edges-run-{}.bin", runs.len()));
        let mut output = BufWriter::with_capacity(
            COPY_BUFFER_SIZE,
            File::create(&path)
                .map_err(|error| io_error("dgml.index.edge_run", error.to_string()))?,
        );
        for record in records {
            write_edge(&mut output, record)?;
        }
        output
            .flush()
            .map_err(|error| io_error("dgml.index.edge_run", error.to_string()))?;
        runs.push(path);
        check_run_memory(&runs, sort_memory)?;
    }
    Ok(runs)
}

fn build_label_fst(
    directory: &Path,
    sort_memory: u64,
    control: &IndexControl,
) -> Result<(), DgmlError> {
    let runs = create_label_runs(directory, sort_memory, control)?;
    let runs = reduce_runs(directory, runs, true, merge_fan_in(sort_memory), control)?;
    let mut readers = open_label_runs(&runs)?;
    let mut current = readers
        .iter_mut()
        .map(read_owned_label)
        .collect::<Result<Vec<_>, _>>()?;
    let mut tree = MergeTree::new(&current, compare_owned_labels);
    let output = BufWriter::with_capacity(
        COPY_BUFFER_SIZE,
        File::create(directory.join("labels.fst"))
            .map_err(|error| io_error("dgml.index.labels", error.to_string()))?,
    );
    let mut builder = fst::MapBuilder::new(output)
        .map_err(|error| io_error("dgml.index.labels", error.to_string()))?;
    let mut emitted = 0_u64;
    while let Some(index) = tree.first() {
        if emitted % 65536 == 0 {
            control.check()?;
        }
        emitted += 1;
        let record = current[index].as_mut().expect("selected populated run");
        record.value.try_reserve_exact(9).map_err(|error| {
            resource_error(
                "resource.memory_limit",
                format!("unable to grow label key: {error}"),
            )
        })?;
        record.value.push(0);
        record
            .value
            .extend_from_slice(&record.node_id.to_be_bytes());
        builder
            .insert(&record.value, record.node_id)
            .map_err(|error| io_error("dgml.index.labels", error.to_string()))?;
        refill_owned_label(&mut readers[index], &mut current[index])?;
        tree.update(index, &current, compare_owned_labels);
    }
    builder
        .finish()
        .map_err(|error| io_error("dgml.index.labels", error.to_string()))?;
    drop(readers);
    for path in runs {
        fs::remove_file(path).map_err(|error| io_error("dgml.index.cleanup", error.to_string()))?;
    }
    fs::remove_file(directory.join("labels.tmp"))
        .map_err(|error| io_error("dgml.index.cleanup", error.to_string()))?;
    Ok(())
}

fn create_label_runs(
    directory: &Path,
    sort_memory: u64,
    control: &IndexControl,
) -> Result<Vec<PathBuf>, DgmlError> {
    let mut input = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("labels.tmp"))
            .map_err(|error| io_error("dgml.index.labels", error.to_string()))?,
    );
    let mut strings = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(directory.join("strings.bin"))
            .map_err(|error| io_error("dgml.index.strings", error.to_string()))?,
    );
    let chunk_target = (sort_memory / 2).max(MIN_SORT_MEMORY / 2);
    let mut string_position = 0_u64;
    let mut runs = Vec::new();
    let mut exhausted = false;
    let mut pending = None;
    loop {
        control.check()?;
        let (mut records, mut bytes) = label_sort_buffers(chunk_target)?;
        let mut tracked = 0_u64;
        while tracked < chunk_target {
            let next = match pending.take() {
                Some(record) => Some(record),
                None => read_label(&mut input)?,
            };
            if let Some(record) = next {
                let charged = u64::from(record.label_len) + size_of::<BufferedLabel>() as u64;
                if charged > chunk_target {
                    return Err(resource_error(
                        "resource.memory_limit",
                        "label exceeds the sort-run budget",
                    ));
                }
                if tracked + charged > chunk_target {
                    pending = Some(record);
                    break;
                }
                if string_position != record.label_offset {
                    strings
                        .seek(SeekFrom::Start(record.label_offset))
                        .map_err(|error| io_error("dgml.index.strings", error.to_string()))?;
                }
                let start = bytes.len();
                let length = record.label_len as usize;
                bytes.try_reserve(length).map_err(|error| {
                    resource_error(
                        "resource.memory_limit",
                        format!("unable to grow label arena: {error}"),
                    )
                })?;
                records.try_reserve(1).map_err(|error| {
                    resource_error(
                        "resource.memory_limit",
                        format!("unable to grow label records: {error}"),
                    )
                })?;
                bytes.resize(start + length, 0);
                strings
                    .read_exact(&mut bytes[start..])
                    .map_err(|error| io_error("dgml.index.strings", error.to_string()))?;
                string_position = record.label_offset + u64::from(record.label_len);
                tracked += charged;
                records.push(BufferedLabel {
                    node_id: record.node_id,
                    range: start..start + length,
                });
            } else {
                exhausted = true;
                break;
            }
        }
        if records.is_empty() {
            break;
        }
        records.sort_unstable_by(|left, right| {
            bytes[left.range.clone()]
                .cmp(&bytes[right.range.clone()])
                .then_with(|| left.node_id.cmp(&right.node_id))
        });
        let path = directory.join(format!("labels-run-{}.bin", runs.len()));
        let mut output = BufWriter::with_capacity(
            COPY_BUFFER_SIZE,
            File::create(&path)
                .map_err(|error| io_error("dgml.index.label_run", error.to_string()))?,
        );
        for record in records {
            write_label_value(&mut output, record.node_id, &bytes[record.range])?;
        }
        output
            .flush()
            .map_err(|error| io_error("dgml.index.label_run", error.to_string()))?;
        runs.push(path);
        check_run_memory(&runs, sort_memory)?;
        if exhausted {
            break;
        }
    }
    Ok(runs)
}

fn label_sort_buffers(chunk_target: u64) -> Result<(Vec<BufferedLabel>, Vec<u8>), DgmlError> {
    let mut records = Vec::new();
    let mut bytes = Vec::new();
    let capacity = usize::try_from(chunk_target)
        .map_err(|_| resource_error("resource.memory_limit", "label arena exceeds usize"))?;
    bytes.try_reserve_exact(capacity).map_err(|error| {
        resource_error(
            "resource.memory_limit",
            format!("unable to reserve label arena: {error}"),
        )
    })?;
    records
        .try_reserve_exact(capacity / size_of::<BufferedLabel>() + 1)
        .map_err(|error| {
            resource_error(
                "resource.memory_limit",
                format!("unable to reserve label records: {error}"),
            )
        })?;
    Ok((records, bytes))
}

fn check_run_memory(runs: &[PathBuf], sort_memory: u64) -> Result<(), DgmlError> {
    let tracked = runs
        .iter()
        .map(|path| path.as_os_str().len() as u64 * 2 + 32)
        .sum::<u64>();
    if tracked > sort_memory / 8 {
        return Err(resource_error(
            "resource.memory_limit",
            "sort-run catalog exceeds its memory budget",
        ));
    }
    Ok(())
}

fn reduce_runs(
    directory: &Path,
    mut runs: Vec<PathBuf>,
    labels: bool,
    fan_in: usize,
    control: &IndexControl,
) -> Result<Vec<PathBuf>, DgmlError> {
    let mut pass = 0;
    while runs.len() > fan_in {
        let mut merged = Vec::new();
        for (batch, paths) in runs.chunks(fan_in).enumerate() {
            control.check()?;
            let path = directory.join(format!(
                "{}-merge-{pass}-{batch}.bin",
                if labels { "labels" } else { "edges" }
            ));
            let mut output = BufWriter::with_capacity(
                COPY_BUFFER_SIZE,
                File::create(&path)
                    .map_err(|error| io_error("dgml.index.merge", error.to_string()))?,
            );
            let mut readers = open_edge_runs(paths)?;
            let mut emitted = 0_u64;
            if labels {
                let mut heads = readers
                    .iter_mut()
                    .map(read_owned_label)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut tree = MergeTree::new(&heads, compare_owned_labels);
                while let Some(index) = tree.first() {
                    if emitted % 65536 == 0 {
                        control.check()?;
                    }
                    emitted += 1;
                    write_owned_label(
                        &mut output,
                        heads[index].as_ref().expect("populated merge head"),
                    )?;
                    refill_owned_label(&mut readers[index], &mut heads[index])?;
                    tree.update(index, &heads, compare_owned_labels);
                }
            } else {
                let mut heads = readers
                    .iter_mut()
                    .map(read_edge)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut tree = MergeTree::new(&heads, EdgeRecord::cmp);
                while let Some(index) = tree.first() {
                    if emitted % 65536 == 0 {
                        control.check()?;
                    }
                    emitted += 1;
                    write_edge(
                        &mut output,
                        heads[index].take().expect("populated merge head"),
                    )?;
                    heads[index] = read_edge(&mut readers[index])?;
                    tree.update(index, &heads, EdgeRecord::cmp);
                }
            }
            output
                .flush()
                .map_err(|error| io_error("dgml.index.merge", error.to_string()))?;
            drop(readers);
            for input in paths {
                fs::remove_file(input)
                    .map_err(|error| io_error("dgml.index.cleanup", error.to_string()))?;
            }
            merged.push(path);
        }
        runs = merged;
        pass += 1;
    }
    Ok(runs)
}

fn merge_fan_in(sort_memory: u64) -> usize {
    if sort_memory >= 256 * 1024 * 1024 {
        LARGE_MERGE_FAN_IN
    } else {
        MERGE_FAN_IN
    }
}

fn compare_owned_labels(left: &OwnedLabel, right: &OwnedLabel) -> std::cmp::Ordering {
    left.value
        .cmp(&right.value)
        .then_with(|| left.node_id.cmp(&right.node_id))
}

fn normalized_attribute<R: std::io::BufRead>(
    reader: &Reader<R>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<Option<Vec<u8>>, DgmlError> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| {
            malformed_error(
                "dgml.attribute",
                format!("invalid XML attribute: {error}"),
                reader.buffer_position(),
            )
        })?;
        if attribute.key.local_name().as_ref() == name {
            return attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| {
                    malformed_error(
                        "dgml.attribute",
                        format!("invalid escaped attribute: {error}"),
                        reader.buffer_position(),
                    )
                })
                .and_then(|value| {
                    validate_attribute_text(&value, reader.buffer_position())?;
                    Ok(Some(value.into_owned().into_bytes()))
                });
        }
    }
    Ok(None)
}

fn validate_attributes<R: BufRead>(
    reader: &Reader<R>,
    element: &BytesStart<'_>,
) -> Result<(), DgmlError> {
    for attribute in element.attributes().with_checks(true) {
        attribute.map_err(|error| {
            malformed_error(
                "dgml.attribute",
                format!("invalid XML attribute: {error}"),
                reader.buffer_position(),
            )
        })?;
    }
    Ok(())
}

fn numeric_attribute<R: std::io::BufRead>(
    reader: &Reader<R>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<u64, DgmlError> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| {
            malformed_error(
                "dgml.attribute",
                format!("invalid XML attribute: {error}"),
                reader.buffer_position(),
            )
        })?;
        if attribute.key.local_name().as_ref() == name {
            return attribute.value.parse::<u64>().map_err(|_| {
                malformed_error(
                    "dgml.node_id",
                    format!("attribute {} is not a numeric node ID", attribute.value),
                    reader.buffer_position(),
                )
            });
        }
    }
    Err(malformed_error(
        "dgml.attribute",
        format!(
            "{} element is missing required {name} attribute",
            element.local_name().as_ref()
        ),
        reader.buffer_position(),
    ))
}

fn intern_reason<R: std::io::BufRead, W: Write>(
    reader: &Reader<R>,
    element: &BytesStart<'_>,
    reasons: &mut HashMap<Vec<u8>, (u64, u32)>,
    output: &mut W,
    next_offset: &mut u64,
    reason_memory: &mut u64,
) -> Result<(u64, u32), DgmlError> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| {
            malformed_error(
                "dgml.attribute",
                format!("invalid XML attribute: {error}"),
                reader.buffer_position(),
            )
        })?;
        if attribute.key.local_name().as_ref() == "Reason" {
            let reason = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| {
                    malformed_error(
                        "dgml.attribute",
                        format!("invalid escaped attribute: {error}"),
                        reader.buffer_position(),
                    )
                })?;
            validate_attribute_text(&reason, reader.buffer_position())?;
            return intern_reason_bytes(
                reason.as_bytes(),
                reasons,
                output,
                next_offset,
                reason_memory,
            );
        }
    }
    intern_reason_bytes(&[], reasons, output, next_offset, reason_memory)
}

fn validate_attribute_text(value: &str, offset: u64) -> Result<(), DgmlError> {
    if value.chars().any(|character| matches!(character, '\0'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}')) {
        return Err(malformed_error("dgml.attribute", "attribute contains a character forbidden in XML 1.0", offset));
    }
    Ok(())
}

fn intern_reason_bytes<W: Write>(
    reason: &[u8],
    reasons: &mut HashMap<Vec<u8>, (u64, u32)>,
    output: &mut W,
    next_offset: &mut u64,
    reason_memory: &mut u64,
) -> Result<(u64, u32), DgmlError> {
    if let Some(value) = reasons.get(reason) {
        return Ok(*value);
    }
    let length = u32::try_from(reason.len())
        .map_err(|_| resource_error("dgml.reason", "link reason exceeds u32"))?;
    output
        .write_all(reason)
        .map_err(|error| io_error("dgml.index.reasons", error.to_string()))?;
    let value = (*next_offset, length);
    *next_offset = next_offset
        .checked_add(reason.len() as u64)
        .ok_or_else(|| resource_error("dgml.index.reasons", "reason offset overflow"))?;
    reasons.try_reserve(1).map_err(|error| {
        resource_error(
            "resource.memory_limit",
            format!("unable to reserve reason index: {error}"),
        )
    })?;
    reasons.insert(reason.to_vec(), value);
    *reason_memory = reason_memory.saturating_add(reason.len() as u64 + 128);
    Ok(value)
}

fn ensure_seen_capacity(
    id: u64,
    seen: &mut Vec<u64>,
    memory_limit: u64,
    offset: u64,
) -> Result<(), DgmlError> {
    if id >= memory_limit / 8 {
        return Err(resource_error(
            "resource.node_id_range",
            "sparse numeric node ID would exceed the bounded CSR address range",
        ));
    }
    let words = id
        .checked_div(64)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| resource_error("dgml.node_id", "node ID exceeds usize"))?;
    let required = (words as u64)
        .saturating_mul(size_of::<u64>() as u64)
        .saturating_add((COPY_BUFFER_SIZE * 4) as u64);
    if required > memory_limit {
        return Err(resource_limit(required, memory_limit, offset));
    }
    if seen.len() < words {
        seen.resize(words, 0);
    }
    Ok(())
}

fn node_exists(seen: &[u64], id: u64) -> bool {
    usize::try_from(id / 64)
        .ok()
        .and_then(|word| seen.get(word))
        .is_some_and(|value| value & (1_u64 << (id % 64)) != 0)
}

fn write_node_at<W: Write + Seek>(
    file: &mut W,
    file_position: &mut u64,
    id: u64,
    label_offset: u64,
    label_len: u32,
    flags: u32,
) -> Result<(), DgmlError> {
    let offset = id
        .checked_mul(NODE_RECORD_SIZE)
        .ok_or_else(|| resource_error("dgml.index.nodes", "node file offset overflow"))?;
    if *file_position != offset {
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| io_error("dgml.index.nodes", error.to_string()))?;
    }
    let mut bytes = [0_u8; 16];
    bytes[0..8].copy_from_slice(&label_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&label_len.to_le_bytes());
    bytes[12..16].copy_from_slice(&flags.to_le_bytes());
    file.write_all(&bytes)
        .map_err(|error| io_error("dgml.index.nodes", error.to_string()))?;
    *file_position = offset + NODE_RECORD_SIZE;
    Ok(())
}

fn write_edge<W: Write>(writer: &mut W, record: EdgeRecord) -> Result<(), DgmlError> {
    writer
        .write_all(&record.target.to_le_bytes())
        .and_then(|()| writer.write_all(&record.source.to_le_bytes()))
        .and_then(|()| writer.write_all(&record.reason_offset.to_le_bytes()))
        .and_then(|()| writer.write_all(&record.reason_len.to_le_bytes()))
        .and_then(|()| writer.write_all(&record.flags.to_le_bytes()))
        .map_err(|error| io_error("dgml.index.edges", error.to_string()))
}

fn read_edge<R: Read>(reader: &mut R) -> Result<Option<EdgeRecord>, DgmlError> {
    let Some(bytes) = read_record::<EDGE_RECORD_SIZE, _>(reader, "dgml.index.edges")? else {
        return Ok(None);
    };
    Ok(Some(EdgeRecord {
        target: u64::from_le_bytes(bytes[0..8].try_into().expect("fixed range")),
        source: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed range")),
        reason_offset: u64::from_le_bytes(bytes[16..24].try_into().expect("fixed range")),
        reason_len: u32::from_le_bytes(bytes[24..28].try_into().expect("fixed range")),
        flags: u32::from_le_bytes(bytes[28..32].try_into().expect("fixed range")),
    }))
}

fn write_label<W: Write>(writer: &mut W, record: LabelRecord) -> Result<(), DgmlError> {
    writer
        .write_all(&record.node_id.to_le_bytes())
        .and_then(|()| writer.write_all(&record.label_offset.to_le_bytes()))
        .and_then(|()| writer.write_all(&record.label_len.to_le_bytes()))
        .and_then(|()| writer.write_all(&record.flags.to_le_bytes()))
        .map_err(|error| io_error("dgml.index.labels", error.to_string()))
}

fn read_label<R: Read>(reader: &mut R) -> Result<Option<LabelRecord>, DgmlError> {
    let Some(bytes) = read_record::<LABEL_RECORD_SIZE, _>(reader, "dgml.index.labels")? else {
        return Ok(None);
    };
    Ok(Some(LabelRecord {
        node_id: u64::from_le_bytes(bytes[0..8].try_into().expect("fixed range")),
        label_offset: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed range")),
        label_len: u32::from_le_bytes(bytes[16..20].try_into().expect("fixed range")),
        flags: u32::from_le_bytes(bytes[20..24].try_into().expect("fixed range")),
    }))
}

fn write_owned_label<W: Write>(writer: &mut W, record: &OwnedLabel) -> Result<(), DgmlError> {
    write_label_value(writer, record.node_id, &record.value)
}

fn write_label_value<W: Write>(
    writer: &mut W,
    node_id: u64,
    value: &[u8],
) -> Result<(), DgmlError> {
    let length = u32::try_from(value.len())
        .map_err(|_| resource_error("dgml.index.labels", "label exceeds u32"))?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(&node_id.to_le_bytes()))
        .and_then(|()| writer.write_all(value))
        .map_err(|error| io_error("dgml.index.label_run", error.to_string()))
}

fn read_owned_label<R: Read>(reader: &mut R) -> Result<Option<OwnedLabel>, DgmlError> {
    let mut record = None;
    refill_owned_label(reader, &mut record)?;
    Ok(record)
}

fn refill_owned_label<R: Read>(
    reader: &mut R,
    record: &mut Option<OwnedLabel>,
) -> Result<(), DgmlError> {
    let Some(header) = read_record::<12, _>(reader, "dgml.index.label_run")? else {
        *record = None;
        return Ok(());
    };
    let length = u32::from_le_bytes(header[0..4].try_into().expect("fixed range"));
    let node_id = u64::from_le_bytes(header[4..12].try_into().expect("fixed range"));
    let record = record.get_or_insert_with(|| OwnedLabel {
        node_id,
        value: Vec::new(),
    });
    record.node_id = node_id;
    let length = length as usize;
    record
        .value
        .try_reserve_exact(length.saturating_sub(record.value.len()))
        .map_err(|error| {
            resource_error(
                "resource.memory_limit",
                format!("unable to grow merge label: {error}"),
            )
        })?;
    record.value.resize(length, 0);
    reader
        .read_exact(&mut record.value)
        .map_err(|error| io_error("dgml.index.label_run", error.to_string()))?;
    Ok(())
}

fn read_record<const N: usize, R: Read>(
    reader: &mut R,
    code: &str,
) -> Result<Option<[u8; N]>, DgmlError> {
    let mut bytes = [0_u8; N];
    let mut read = 0;
    while read < N {
        match reader.read(&mut bytes[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => {
                return Err(io_error(
                    code,
                    format!("truncated fixed-width record: read {read} of {N} bytes"),
                ));
            }
            Ok(count) => read += count,
            Err(error) => return Err(io_error(code, error.to_string())),
        }
    }
    Ok(Some(bytes))
}

fn open_edge_runs(paths: &[PathBuf]) -> Result<Vec<BufReader<File>>, DgmlError> {
    paths
        .iter()
        .map(|path| {
            File::open(path)
                .map(|file| BufReader::with_capacity(RUN_BUFFER_SIZE, file))
                .map_err(|error| io_error("dgml.index.edge_run", error.to_string()))
        })
        .collect()
}

fn open_label_runs(paths: &[PathBuf]) -> Result<Vec<BufReader<File>>, DgmlError> {
    paths
        .iter()
        .map(|path| {
            File::open(path)
                .map(|file| BufReader::with_capacity(RUN_BUFFER_SIZE, file))
                .map_err(|error| io_error("dgml.index.label_run", error.to_string()))
        })
        .collect()
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> Result<(), DgmlError> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| io_error("dgml.index.write", error.to_string()))
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> Result<(), DgmlError> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| io_error("dgml.index.write", error.to_string()))
}

fn with_input_reader<T>(
    path: &Path,
    selected_entry: Option<&str>,
    operation: impl FnOnce(&mut dyn Read) -> Result<T, DgmlError>,
) -> Result<T, DgmlError> {
    let file = File::open(path)
        .map_err(|error| io_error("dgml.index.input", format!("{}: {error}", path.display())))?;
    if let Some(entry) = selected_entry {
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|error| malformed_simple("dgml.zip", error.to_string()))?;
        let mut member = archive
            .by_name(entry)
            .map_err(|error| malformed_simple("dgml.zip.entry", error.to_string()))?;
        operation(&mut member)
    } else {
        let mut reader = file;
        operation(&mut reader)
    }
}

fn select_zip_entry(path: &Path, requested: Option<&str>) -> Result<Option<String>, DgmlError> {
    let is_zip = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
    if !is_zip {
        if requested.is_some() {
            return Err(malformed_simple(
                "dgml.zip.entry",
                "--entry is valid only for ZIP input",
            ));
        }
        return Ok(None);
    }
    let file = File::open(path)
        .map_err(|error| io_error("dgml.zip", format!("{}: {error}", path.display())))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| malformed_simple("dgml.zip", error.to_string()))?;
    if let Some(requested) = requested {
        archive
            .by_name(requested)
            .map_err(|error| malformed_simple("dgml.zip.entry", error.to_string()))?;
        return Ok(Some(requested.into()));
    }
    let mut candidates = Vec::new();
    for index in 0..archive.len() {
        let member = archive
            .by_index(index)
            .map_err(|error| malformed_simple("dgml.zip", error.to_string()))?;
        let name = member.name();
        let extension_matches = Path::new(name).extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("dgml") || extension.eq_ignore_ascii_case("xml")
        });
        if !member.is_dir() && extension_matches {
            candidates.push(name.to_owned());
        }
    }
    match candidates.as_slice() {
        [entry] => Ok(Some(entry.clone())),
        [] => Err(malformed_simple(
            "dgml.zip.entry",
            "ZIP contains no DGML/XML entry",
        )),
        _ => Err(malformed_simple(
            "dgml.zip.entry",
            "ZIP contains multiple DGML/XML entries; select one with --entry",
        )),
    }
}

fn acquire_lock(path: &Path) -> Result<BuildLock, DgmlError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| io_error("dgml.index.lock", error.to_string()))?;
    FileExt::try_lock(&file).map_err(|error| lock_error(&error, path))?;
    file.set_len(0)
        .map_err(|error| io_error("dgml.index.lock", error.to_string()))?;
    let pid = std::process::id();
    serde_json::to_writer(
        &mut file,
        &LockMetadata {
            pid,
            process_start_time: process_start_time(pid).unwrap_or(0),
            created_unix_ns: unix_ns(),
        },
    )
    .map_err(|error| io_error("dgml.index.lock", error.to_string()))?;
    file.sync_all()
        .map_err(|error| io_error("dgml.index.lock", error.to_string()))?;
    Ok(BuildLock { _file: file })
}

fn acquire_read_lock(path: &Path) -> Result<BuildLock, DgmlError> {
    let file = File::open(path).map_err(|error| io_error("dgml.index.lock", error.to_string()))?;
    FileExt::try_lock_shared(&file).map_err(|error| lock_error(&error, path))?;
    Ok(BuildLock { _file: file })
}

fn lock_error(error: &fs4::TryLockError, path: &Path) -> DgmlError {
    match error {
        fs4::TryLockError::WouldBlock => resource_error(
            "dgml.index.locked",
            format!("cache is in use: {}", path.display()),
        ),
        fs4::TryLockError::Error(error) => io_error("dgml.index.lock", error.to_string()),
    }
}
fn process_start_time(pid: u32) -> Option<u64> {
    let system = System::new_all();
    system
        .process(Pid::from_u32(pid))
        .map(sysinfo::Process::start_time)
}

fn prefix_suffix_fingerprint(path: &Path) -> Result<String, DgmlError> {
    let mut file =
        File::open(path).map_err(|error| io_error("dgml.index.fingerprint", error.to_string()))?;
    let length = file
        .metadata()
        .map_err(|error| io_error("dgml.index.fingerprint", error.to_string()))?
        .len();
    let sample = 64 * 1024_u64;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&length.to_le_bytes());
    copy_hash(
        &mut std::io::Read::by_ref(&mut file).take(sample),
        &mut hasher,
    )?;
    if length > sample {
        file.seek(SeekFrom::Start(length.saturating_sub(sample)))
            .map_err(|error| io_error("dgml.index.fingerprint", error.to_string()))?;
        copy_hash(&mut file.take(sample), &mut hasher)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_file(path: &Path) -> Result<String, DgmlError> {
    hash_file_controlled(path, &IndexControl::default())
}

fn hash_file_controlled(path: &Path, control: &IndexControl) -> Result<String, DgmlError> {
    let mut file = BufReader::with_capacity(
        COPY_BUFFER_SIZE,
        File::open(path).map_err(|error| io_error("dgml.index.hash", error.to_string()))?,
    );
    let mut hasher = blake3::Hasher::new();
    copy_hash_controlled(&mut file, &mut hasher, control)?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn copy_hash(reader: &mut dyn Read, hasher: &mut blake3::Hasher) -> Result<(), DgmlError> {
    copy_hash_controlled(reader, hasher, &IndexControl::default())
}

fn copy_hash_controlled(
    reader: &mut dyn Read,
    hasher: &mut blake3::Hasher,
    control: &IndexControl,
) -> Result<(), DgmlError> {
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        control.check()?;
        let count = reader
            .read(&mut buffer)
            .map_err(|error| io_error("dgml.index.hash", error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(())
}

fn input_key(path: &Path, length: u64, modified: u128, entry: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(&length.to_le_bytes());
    hasher.update(&modified.to_le_bytes());
    if let Some(entry) = entry {
        hasher.update(entry.as_bytes());
    }
    hasher.finalize().to_hex()[..32].to_owned()
}

fn write_checksums(
    directory: &Path,
    control: &IndexControl,
) -> Result<BTreeMap<String, String>, DgmlError> {
    let mut checksums = BTreeMap::new();
    for name in REQUIRED_FILES {
        checksums.insert(
            name.into(),
            hash_file_controlled(&directory.join(name), control)?,
        );
    }
    Ok(checksums)
}

fn current_generation(index_directory: &Path) -> Result<(String, PathBuf), DgmlError> {
    let mut current = String::new();
    File::open(index_directory.join("CURRENT"))
        .and_then(|file| file.take(129).read_to_string(&mut current))
        .map_err(|error| io_error("dgml.cache.current", error.to_string()))?;
    if current.len() > 128 {
        return Err(malformed_simple(
            "dgml.cache.current",
            "CURRENT exceeds 128 bytes",
        ));
    }
    let generation = current.trim();
    if !valid_generation_name(generation) {
        return Err(malformed_simple(
            "dgml.cache.current",
            "CURRENT contains an invalid generation name",
        ));
    }
    let path = index_directory.join("generations").join(generation);
    if !path.is_dir() {
        return Err(malformed_simple(
            "dgml.cache.current",
            format!("published generation `{generation}` does not exist"),
        ));
    }
    Ok((generation.into(), path))
}

fn validate_manifest(manifest: &DgmlIndexManifest) -> Result<(), DgmlError> {
    if manifest.schema != INDEX_SCHEMA {
        let mut diagnostic = vitnet_core::Diagnostic::malformed(
            "dgml.cache.schema",
            "unsupported DGML index schema",
        );
        diagnostic.expected = Some(INDEX_SCHEMA.into());
        diagnostic.actual = Some(manifest.schema.clone());
        return Err(DgmlError {
            diagnostic: Box::new(diagnostic),
        });
    }
    if !manifest.complete {
        return Err(malformed_simple(
            "dgml.cache.incomplete",
            "published DGML index is not marked complete",
        ));
    }
    if !manifest.features.incoming_edges
        || !manifest.features.label_fst
        || manifest.features.outgoing_edges
    {
        return Err(malformed_simple(
            "dgml.cache.features",
            "unsupported index feature combination",
        ));
    }
    let valid_range = match manifest.max_node_id {
        None => manifest.node_count == 0 && manifest.edge_count == 0,
        Some(max) => max
            .checked_add(1)
            .is_some_and(|slots| manifest.node_count > 0 && manifest.node_count <= slots),
    };
    if !valid_range {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "invalid manifest node range/count",
        ));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, DgmlError> {
    let file = File::open(path).map_err(|error| io_error("dgml.cache.read", error.to_string()))?;
    if file
        .metadata()
        .map_err(|error| io_error("dgml.cache.read", error.to_string()))?
        .len()
        > 1024 * 1024
    {
        return Err(resource_error(
            "resource.record_limit",
            "cache JSON exceeds 1 MiB",
        ));
    }
    serde_json::from_reader(BufReader::new(file))
        .map_err(|error| malformed_simple("dgml.cache.json", error.to_string()))
}

fn sync_generation_files(directory: &Path) -> Result<(), DgmlError> {
    for entry in
        fs::read_dir(directory).map_err(|error| io_error("dgml.index.sync", error.to_string()))?
    {
        let entry = entry.map_err(|error| io_error("dgml.index.sync", error.to_string()))?;
        if entry
            .file_type()
            .map_err(|error| io_error("dgml.index.sync", error.to_string()))?
            .is_file()
        {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(entry.path())
                .and_then(|file| file.sync_all())
                .map_err(|error| io_error("dgml.index.sync", error.to_string()))?;
        }
    }
    Ok(())
}

fn publish_current(index_directory: &Path, generation: &str) -> Result<(), DgmlError> {
    let mut temporary = tempfile::NamedTempFile::new_in(index_directory)
        .map_err(|error| io_error("dgml.index.current", error.to_string()))?;
    let current = index_directory.join("CURRENT");
    writeln!(temporary, "{generation}")
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| io_error("dgml.index.current", error.to_string()))?;
    temporary
        .persist(&current)
        .map_err(|error| io_error("dgml.index.current", error.to_string()))?;
    sync_directory(index_directory)?;
    Ok(())
}

#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_directory(path: &Path) -> Result<(), DgmlError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("dgml.index.sync", error.to_string()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn valid_generation_name(value: &str) -> bool {
    value.split_once('-').is_some_and(|(time, pid)| {
        !time.is_empty()
            && !pid.is_empty()
            && time.bytes().all(|byte| byte.is_ascii_digit())
            && pid.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn modified_ns(metadata: &fs::Metadata) -> Result<u128, DgmlError> {
    metadata
        .modified()
        .map_err(|error| io_error("dgml.index.input", error.to_string()))?
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .map_err(|error| io_error("dgml.index.input", error.to_string()))
}
fn write_json_sync(path: &Path, value: &impl Serialize) -> Result<(), DgmlError> {
    let file =
        File::create(path).map_err(|error| io_error("dgml.index.json", error.to_string()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|error| io_error("dgml.index.json", error.to_string()))?;
    writer
        .flush()
        .map_err(|error| io_error("dgml.index.json", error.to_string()))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| io_error("dgml.index.json", error.to_string()))
}

fn directory_file_bytes(path: &Path) -> Result<u64, DgmlError> {
    fs::read_dir(path)
        .map_err(|error| io_error("dgml.index.size", error.to_string()))?
        .try_fold(0_u64, |total, entry| {
            let entry = entry.map_err(|error| io_error("dgml.index.size", error.to_string()))?;
            let length = entry
                .metadata()
                .map_err(|error| io_error("dgml.index.size", error.to_string()))?
                .len();
            total
                .checked_add(length)
                .ok_or_else(|| resource_error("dgml.index.size", "index byte count overflow"))
        })
}

fn directory_tree_bytes(path: &Path) -> Result<u64, DgmlError> {
    fs::read_dir(path)
        .map_err(|error| io_error("dgml.cache.size", error.to_string()))?
        .try_fold(0_u64, |total, entry| {
            let entry = entry.map_err(|error| io_error("dgml.cache.size", error.to_string()))?;
            let metadata = entry
                .metadata()
                .map_err(|error| io_error("dgml.cache.size", error.to_string()))?;
            let length = if metadata.is_dir() {
                directory_tree_bytes(&entry.path())?
            } else {
                metadata.len()
            };
            total
                .checked_add(length)
                .ok_or_else(|| resource_error("dgml.cache.size", "cache byte count overflow"))
        })
}

fn unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos())
}

fn resource_limit(actual: u64, limit: u64, byte_offset: u64) -> DgmlError {
    let mut diagnostic = vitnet_core::Diagnostic::malformed(
        "resource.memory_limit",
        "DGML index state exceeded the configured memory limit",
    );
    diagnostic.byte_offset = Some(byte_offset);
    diagnostic.expected = Some(format!("at most {limit} bytes"));
    diagnostic.actual = Some(format!("{actual} tracked bytes"));
    DgmlError {
        diagnostic: Box::new(diagnostic),
    }
}

fn io_error(code: &str, message: impl Into<String>) -> DgmlError {
    DgmlError {
        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
            format!("io.{code}"),
            message,
        )),
    }
}

fn malformed_simple(code: &str, message: impl Into<String>) -> DgmlError {
    DgmlError {
        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(code, message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tournament_merge_matches_exact_sort_for_empty_singleton_and_uneven_runs() {
        for run_count in [0, 1, 2, 3, 15, MERGE_FAN_IN, LARGE_MERGE_FAN_IN] {
            let mut runs = Vec::new();
            for run in 0..run_count {
                let length = if run_count == 1 { 7 } else { run * 3 % 19 };
                let mut records = (0..length)
                    .map(|item| EdgeRecord {
                        target: (item % 3) as u64,
                        source: (run % 2) as u64,
                        reason_offset: (item % 5) as u64,
                        reason_len: u32::try_from(item % 7).unwrap(),
                        flags: u32::try_from(item % 2).unwrap(),
                    })
                    .collect::<Vec<_>>();
                records.sort_unstable();
                runs.push(records);
            }
            let mut expected = runs.iter().flatten().copied().collect::<Vec<_>>();
            expected.sort_unstable();
            let mut iterators = runs.into_iter().map(Vec::into_iter).collect::<Vec<_>>();
            let mut heads = iterators.iter_mut().map(Iterator::next).collect::<Vec<_>>();
            let mut tree = MergeTree::new(&heads, EdgeRecord::cmp);
            let mut actual = Vec::new();
            while let Some(index) = tree.first() {
                actual.push(heads[index].take().unwrap());
                heads[index] = iterators[index].next();
                tree.update(index, &heads, EdgeRecord::cmp);
            }
            assert_eq!(actual, expected, "run count {run_count}");
        }
    }

    #[test]
    fn merge_fan_in_expands_only_with_a_large_sort_budget() {
        assert_eq!(merge_fan_in(MIN_SORT_MEMORY), MERGE_FAN_IN);
        assert_eq!(merge_fan_in((256 << 20) - 1), MERGE_FAN_IN);
        assert_eq!(merge_fan_in(256 << 20), LARGE_MERGE_FAN_IN);
        assert_eq!(merge_fan_in(MAX_SORT_MEMORY), LARGE_MERGE_FAN_IN);
    }

    #[test]
    fn label_refill_reuses_capacity_and_removes_previous_key_suffix() {
        let first = OwnedLabel {
            node_id: 3,
            value: vec![b'x'; 4096],
        };
        let mut bytes = Vec::new();
        write_owned_label(&mut bytes, &first).unwrap();
        for (node_id, value) in [(2, b"short".to_vec()), (1, Vec::new())] {
            write_owned_label(&mut bytes, &OwnedLabel { node_id, value }).unwrap();
        }
        let mut input = std::io::Cursor::new(bytes);
        let mut record = read_owned_label(&mut input).unwrap();
        let label = record.as_mut().unwrap();
        label.value.try_reserve_exact(9).unwrap();
        label.value.extend_from_slice(&[0; 9]);
        let pointer = label.value.as_ptr();
        let capacity = label.value.capacity();
        refill_owned_label(&mut input, &mut record).unwrap();
        let label = record.as_ref().unwrap();
        assert_eq!(label.node_id, 2);
        assert_eq!(label.value, b"short");
        assert_eq!(label.value.as_ptr(), pointer);
        assert_eq!(label.value.capacity(), capacity);
        refill_owned_label(&mut input, &mut record).unwrap();
        let label = record.as_ref().unwrap();
        assert_eq!(label.node_id, 1);
        assert_eq!(label.value, [] as [u8; 0]);
        assert_eq!(label.value.as_ptr(), pointer);
        refill_owned_label(&mut input, &mut record).unwrap();
        assert!(record.is_none());
    }

    #[test]
    fn packed_label_sort_preserves_long_prefixes_duplicates_and_empty_labels() {
        let directory = tempfile::tempdir().unwrap();
        let values = [
            vec![b'z'; 128 * 1024],
            b"same".to_vec(),
            Vec::new(),
            b"same".to_vec(),
            [vec![b'z'; 128 * 1024], vec![b'a']].concat(),
            b"label\xC3\xA9".to_vec(),
        ];
        let mut labels = File::create(directory.path().join("labels.tmp")).unwrap();
        let mut strings = File::create(directory.path().join("strings.bin")).unwrap();
        let mut offset = 0;
        for (node_id, value) in values.iter().enumerate() {
            strings.write_all(value).unwrap();
            write_label(
                &mut labels,
                LabelRecord {
                    node_id: node_id as u64,
                    label_offset: offset,
                    label_len: u32::try_from(value.len()).unwrap(),
                    flags: 1,
                },
            )
            .unwrap();
            offset += value.len() as u64;
        }
        drop(labels);
        drop(strings);
        build_label_fst(directory.path(), MIN_SORT_MEMORY, &IndexControl::default()).unwrap();
        let map = fst::Map::new(fs::read(directory.path().join("labels.fst")).unwrap()).unwrap();
        assert_eq!(map.len(), values.len());
        for (node_id, value) in values.iter().enumerate() {
            let key = [value.as_slice(), &[0], &(node_id as u64).to_be_bytes()].concat();
            assert_eq!(map.get(key), Some(node_id as u64));
        }
    }

    #[test]
    fn packed_label_runs_enforce_budget_without_losing_pending_records() {
        let directory = tempfile::tempdir().unwrap();
        let mut labels = File::create(directory.path().join("labels.tmp")).unwrap();
        let mut strings = File::create(directory.path().join("strings.bin")).unwrap();
        let mut expected = Vec::new();
        let mut offset = 0;
        for node_id in 0..137_u64 {
            let length = [45_000, 60_000, 210_000, 120_000, 64, 0][(node_id % 6) as usize];
            let value = vec![b'a' + u8::try_from(node_id % 2).unwrap(); length];
            strings.write_all(&value).unwrap();
            write_label(
                &mut labels,
                LabelRecord {
                    node_id,
                    label_offset: offset,
                    label_len: u32::try_from(length).unwrap(),
                    flags: 1,
                },
            )
            .unwrap();
            offset += length as u64;
            expected.push(OwnedLabel { node_id, value });
        }
        drop(labels);
        drop(strings);
        let runs =
            create_label_runs(directory.path(), MIN_SORT_MEMORY, &IndexControl::default()).unwrap();
        assert!(runs.len() > 1);
        let mut actual = Vec::new();
        for path in runs {
            assert!(file_length(&path).unwrap() <= MIN_SORT_MEMORY / 2);
            let mut input = File::open(path).unwrap();
            let start = actual.len();
            while let Some(record) = read_owned_label(&mut input).unwrap() {
                actual.push(record);
            }
            assert!(
                actual[start..]
                    .windows(2)
                    .all(|pair| compare_owned_labels(&pair[0], &pair[1]).is_le())
            );
        }
        expected.sort_unstable_by(compare_owned_labels);
        actual.sort_unstable_by(compare_owned_labels);
        assert_eq!(actual, expected);
    }

    #[test]
    fn bounded_multi_pass_merge_preserves_all_records() {
        for fan_in in [MERGE_FAN_IN, LARGE_MERGE_FAN_IN] {
            assert_bounded_merge(fan_in);
        }
    }

    fn assert_bounded_merge(fan_in: usize) {
        let directory = tempfile::tempdir().unwrap();
        let control = IndexControl::default();
        let mut edge_paths = Vec::new();
        let mut label_paths = Vec::new();
        for run in 0..=(fan_in * 2) {
            let edge_path = directory.path().join(format!("edge-{run}"));
            let label_path = directory.path().join(format!("label-{run}"));
            let mut edges = File::create(&edge_path).unwrap();
            let mut labels = File::create(&label_path).unwrap();
            for target in 0..3 {
                write_edge(
                    &mut edges,
                    EdgeRecord {
                        target,
                        source: run as u64,
                        reason_offset: 0,
                        reason_len: 1,
                        flags: 0,
                    },
                )
                .unwrap();
                write_owned_label(
                    &mut labels,
                    &OwnedLabel {
                        node_id: (target * 100 + run as u64),
                        value: vec![b'a' + u8::try_from(target).unwrap()],
                    },
                )
                .unwrap();
            }
            edge_paths.push(edge_path);
            label_paths.push(label_path);
        }
        let edges = reduce_runs(directory.path(), edge_paths, false, fan_in, &control).unwrap();
        let labels = reduce_runs(directory.path(), label_paths, true, fan_in, &control).unwrap();
        assert!(edges.len() <= fan_in);
        assert!(labels.len() <= fan_in);
        let mut actual_edges = Vec::new();
        for path in edges {
            let mut reader = File::open(path).unwrap();
            let mut previous = None;
            while let Some(record) = read_edge(&mut reader).unwrap() {
                assert!(previous.is_none_or(|value| value <= record));
                previous = Some(record);
                actual_edges.push(record);
            }
        }
        let mut actual_labels = Vec::new();
        for path in labels {
            let mut reader = File::open(path).unwrap();
            let mut previous: Option<OwnedLabel> = None;
            while let Some(record) = read_owned_label(&mut reader).unwrap() {
                assert!(
                    previous
                        .as_ref()
                        .is_none_or(|value| compare_owned_labels(value, &record).is_le())
                );
                previous = Some(OwnedLabel {
                    node_id: record.node_id,
                    value: record.value.clone(),
                });
                actual_labels.push(record);
            }
        }
        actual_edges.sort_unstable();
        actual_labels.sort_unstable_by(compare_owned_labels);
        let expected = (fan_in * 2 + 1) * 3;
        assert_eq!(actual_edges.len(), expected);
        assert_eq!(actual_labels.len(), expected);
        for (edge, label) in actual_edges.iter().zip(&actual_labels) {
            assert_eq!(label.node_id, edge.target * 100 + edge.source);
            assert_eq!(label.value, vec![b'a' + u8::try_from(edge.target).unwrap()]);
        }
    }

    struct PatternReader {
        pattern: Vec<u8>,
        remaining: u64,
        position: usize,
    }

    impl Read for PatternReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = usize::try_from(self.remaining.min(output.len() as u64))
                .expect("bounded by output length");
            let mut written = 0;
            while written < count {
                let length = (count - written).min(self.pattern.len() - self.position);
                output[written..written + length]
                    .copy_from_slice(&self.pattern[self.position..self.position + length]);
                written += length;
                self.position = (self.position + length) % self.pattern.len();
            }
            self.remaining -= count as u64;
            Ok(count)
        }
    }

    #[test]
    #[ignore = "101 GiB logical streaming acceptance benchmark; run explicitly in release mode"]
    fn indexes_101_gib_logical_graph_with_bounded_state() {
        let directory = tempfile::tempdir().unwrap();
        let control = IndexControl::default();
        let pattern = format!(
            "<Link Source=\"0\" Target=\"1\" Reason=\"{}\"/>\n",
            "r".repeat(4096)
        )
        .into_bytes();
        let edge_count = (101_u64 << 30).div_ceil(pattern.len() as u64);
        let logical_bytes = edge_count * pattern.len() as u64;
        let input = std::io::Cursor::new(b"<DirectedGraph><Nodes><Node Id=\"0\" Label=\"root\"/><Node Id=\"1\" Label=\"target\"/></Nodes><Links>")
            .chain(PatternReader { pattern, remaining: logical_bytes, position: 0 })
            .chain(std::io::Cursor::new(b"</Links></DirectedGraph>"));
        let started = std::time::Instant::now();
        let parsed = parse_to_spools(input, directory.path(), 64 << 20, &control).unwrap();
        assert_eq!(parsed.node_count, 2);
        assert_eq!(parsed.edge_count, edge_count);
        assert_eq!(parsed.duplicate_node_ids, 0);
        assert!(parsed.peak_tracked_memory_bytes < 64 << 20);
        build_label_fst(directory.path(), 8 << 20, &control).unwrap();
        let unresolved = build_incoming_edges(
            directory.path(),
            &parsed.seen_nodes,
            parsed.max_node_id,
            8 << 20,
            &control,
        )
        .unwrap();
        assert_eq!(unresolved, 0);
        assert_eq!(
            file_length(&directory.path().join("incoming-edges.bin")).unwrap(),
            edge_count * 24
        );
        assert_eq!(
            file_length(&directory.path().join("reasons.bin")).unwrap(),
            4096
        );
        assert_eq!(
            fs::read(directory.path().join("target-offsets.bin")).unwrap(),
            [0_u64, 0, edge_count]
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>()
        );
        println!(
            "logical_bytes={logical_bytes} edges={edge_count} tracked_parse_bytes={} elapsed_seconds={:.3}",
            parsed.peak_tracked_memory_bytes,
            started.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[ignore = "optional private/local corpus; set VITNET_DGML_INPUT and expected counts"]
    fn validates_optional_local_corpus_with_final_ingestion_guards() {
        let input = std::env::var_os("VITNET_DGML_INPUT").expect("set VITNET_DGML_INPUT");
        let expected_nodes = std::env::var("VITNET_DGML_EXPECTED_NODES")
            .expect("set VITNET_DGML_EXPECTED_NODES")
            .parse::<u64>()
            .unwrap();
        let expected_edges = std::env::var("VITNET_DGML_EXPECTED_EDGES")
            .expect("set VITNET_DGML_EXPECTED_EDGES")
            .parse::<u64>()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let parsed = parse_to_spools(
            File::open(input).unwrap(),
            directory.path(),
            2 << 30,
            &IndexControl::default(),
        )
        .unwrap();
        assert_eq!(parsed.node_count, expected_nodes);
        assert_eq!(parsed.edge_count, expected_edges);
        assert_eq!(parsed.duplicate_node_ids, 0);
        assert_eq!(parsed.max_node_id, expected_nodes.checked_sub(1));
        assert!(parsed.peak_tracked_memory_bytes < 2 << 30);
        println!(
            "nodes={} edges={} tracked_parse_bytes={}",
            parsed.node_count, parsed.edge_count, parsed.peak_tracked_memory_bytes
        );
    }
}
