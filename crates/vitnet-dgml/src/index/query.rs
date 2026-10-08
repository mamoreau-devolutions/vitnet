use super::{
    BuildLock, DgmlError, DgmlIndexManifest, acquire_read_lock, cache_info_unlocked, file_length,
    io_error, malformed_simple, resource_error,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};
mod incoming;
mod why;
pub use incoming::{BatchReport, IncomingEdge, IncomingOptions, IncomingReport};
pub use why::{WhyOptions, WhyReport};

const QUERY_BUFFER: usize = 64 * 1024;
const LABEL_BUFFER: usize = 1024 * 1024;
const TEXT_LIMIT: u64 = 1024 * 1024;
const DEADLINE_CHECK_INTERVAL: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    Id,
    Exact,
    Prefix,
    Contains,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchRank {
    #[default]
    Id,
    Incoming,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchOptions {
    #[serde(default)]
    pub count_all: bool,
    #[serde(default)]
    pub rank: SearchRank,
    pub mode: SearchMode,
    pub ignore_case: bool,
    pub limit: usize,
    pub after_id: Option<u64>,
    pub max_scanned: u64,
    pub timeout_ms: u64,
    pub preview_bytes: usize,
    pub generation: Option<String>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            count_all: false,
            rank: SearchRank::Id,
            mode: SearchMode::Contains,
            ignore_case: false,
            limit: 50,
            after_id: None,
            max_scanned: 5_000_000,
            timeout_ms: 30_000,
            preview_bytes: 256,
            generation: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueryNode {
    pub node_id: u64,
    pub label: String,
    pub label_bytes: u64,
    pub truncated: bool,
    pub incoming_edges: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchReport {
    pub schema: String,
    pub generation: String,
    pub query: String,
    pub entries: Vec<QueryNode>,
    pub scanned_nodes: u64,
    pub next_after_id: Option<u64>,
    pub stop_reason: String,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub matched_nodes: u64,
    #[serde(default)]
    pub matched_incoming_edges: u64,
    #[serde(default)]
    pub omitted_matches: u64,
    #[serde(default)]
    pub rank: SearchRank,
}

/// A locked generation with bounded buffered file handles, never a resident graph.
pub struct GraphSession {
    control: super::IndexControl,
    _lock: BuildLock,
    pub generation: String,
    manifest: DgmlIndexManifest,
    nodes: BufReader<File>,
    strings: BufReader<File>,
    offsets: BufReader<File>,
    edges: BufReader<File>,
    reasons: BufReader<File>,
    string_bytes: u64,
    reason_bytes: u64,
    memory_limit: u64,
    next_node: u64,
    next_string: u64,
    next_offset: Option<u64>,
    next_edge: Option<u64>,
}

impl GraphSession {
    /// Opens an immutable generation and holds its shared lock until dropped.
    ///
    /// # Errors
    ///
    /// Returns explicit cache, lock, I/O or resource diagnostics.
    pub fn open(path: &Path, memory_limit: u64) -> Result<Self, DgmlError> {
        if memory_limit < 16 * TEXT_LIMIT {
            return Err(resource_error(
                "resource.memory_limit",
                "graph queries need at least 16 MiB",
            ));
        }
        let lock = acquire_read_lock(&path.join("lock"))?;
        let info = cache_info_unlocked(path)?;
        let directory = path.join("generations").join(&info.generation);
        let slots = info.manifest.max_node_id.map_or(0, |value| value + 1);
        for (name, count, width) in [
            ("nodes.bin", slots, 16),
            ("target-offsets.bin", slots + 1, 8),
            ("incoming-edges.bin", info.manifest.edge_count, 24),
        ] {
            if file_length(&directory.join(name))?
                != count.checked_mul(width).ok_or_else(|| {
                    malformed_simple("dgml.cache.structure", "sidecar length overflow")
                })?
            {
                return Err(malformed_simple(
                    "dgml.cache.structure",
                    format!("invalid {name} length; run cache verify"),
                ));
            }
        }
        let open = |name: &str| {
            File::open(directory.join(name))
                .map(|file| {
                    BufReader::with_capacity(
                        if matches!(name, "nodes.bin" | "strings.bin") {
                            LABEL_BUFFER
                        } else {
                            QUERY_BUFFER
                        },
                        file,
                    )
                })
                .map_err(|error| io_error("dgml.query", error.to_string()))
        };
        Ok(Self {
            control: super::IndexControl::default(),
            _lock: lock,
            generation: info.generation,
            manifest: info.manifest,
            nodes: open("nodes.bin")?,
            strings: open("strings.bin")?,
            offsets: open("target-offsets.bin")?,
            edges: open("incoming-edges.bin")?,
            reasons: open("reasons.bin")?,
            string_bytes: file_length(&directory.join("strings.bin"))?,
            reason_bytes: file_length(&directory.join("reasons.bin"))?,
            memory_limit,
            next_node: 0,
            next_string: 0,
            next_offset: Some(0),
            next_edge: Some(0),
        })
    }

    /// Replaces the cooperative cancellation signal for subsequent queries.
    pub fn set_control(&mut self, control: super::IndexControl) {
        self.control = control;
    }

    fn check_generation(&self, expected: Option<&str>) -> Result<(), DgmlError> {
        if expected.is_some_and(|value| value != self.generation) {
            return Err(malformed_simple(
                "dgml.query.generation",
                "generation changed; restart pagination",
            ));
        }
        Ok(())
    }

    fn incoming_range(&mut self, id: u64) -> Result<std::ops::Range<u64>, DgmlError> {
        if let Some(delta) = self
            .next_offset
            .take()
            .and_then(|next| i64::try_from((i128::from(id) - i128::from(next)) * 8).ok())
        {
            self.offsets.seek_relative(delta).map_err(query_io)?;
        } else {
            self.offsets
                .seek(SeekFrom::Start(id * 8))
                .map_err(query_io)?;
        }
        let mut bytes = [0; 16];
        self.offsets.read_exact(&mut bytes).map_err(query_io)?;
        self.next_offset = Some(id + 2);
        let start = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let end = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if start > end || end > self.manifest.edge_count {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid queried CSR range",
            ));
        }
        Ok(start..end)
    }

    fn raw_label(&mut self, id: u64) -> Result<Option<Vec<u8>>, DgmlError> {
        let mut bytes = Vec::new();
        Ok(self.read_label(id, &mut bytes)?.then_some(bytes))
    }

    fn read_label(&mut self, id: u64, output: &mut Vec<u8>) -> Result<bool, DgmlError> {
        if self.manifest.max_node_id.is_none_or(|max| id > max) {
            return Ok(false);
        }
        if id != self.next_node {
            self.nodes
                .seek(SeekFrom::Start(id * 16))
                .map_err(query_io)?;
        }
        let mut bytes = [0; 16];
        self.nodes.read_exact(&mut bytes).map_err(query_io)?;
        self.next_node = id + 1;
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[12..].try_into().unwrap());
        if flags == 0 {
            return Ok(false);
        }
        if flags != 1 {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid queried node flags",
            ));
        }
        if offset != self.next_string {
            self.strings
                .seek(SeekFrom::Start(offset))
                .map_err(query_io)?;
        }
        read_text_bytes_into(
            &mut self.strings,
            offset,
            u64::from(length),
            self.string_bytes,
            output,
        )?;
        self.next_string = offset + u64::from(length);
        Ok(true)
    }

    fn node(&mut self, id: u64, preview: usize) -> Result<Option<QueryNode>, DgmlError> {
        let Some(bytes) = self.raw_label(id)? else {
            return Ok(None);
        };
        let range = self.incoming_range(id)?;
        let (label, truncated) = text_preview(&bytes, preview)?;
        Ok(Some(QueryNode {
            node_id: id,
            label,
            label_bytes: bytes.len() as u64,
            truncated,
            incoming_edges: range.end - range.start,
        }))
    }

    /// Searches complete label bytes with keyset pagination and explicit work limits.
    ///
    /// # Errors
    ///
    /// Returns typed diagnostics rather than silently skipping invalid cache records.
    #[allow(clippy::too_many_lines)]
    pub fn search(
        &mut self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<SearchReport, DgmlError> {
        self.check_generation(options.generation.as_deref())?;
        check_projection(options.limit, options.preview_bytes, self.memory_limit)?;
        if query.is_empty()
            || query.len() as u64 > TEXT_LIMIT
            || options.max_scanned == 0
            || options.timeout_ms == 0
        {
            return Err(malformed_simple(
                "dgml.query.options",
                "query and work limits must be nonempty/positive",
            ));
        }
        let started = Instant::now();
        let query_key = if options.ignore_case {
            Cow::Owned(query.to_lowercase())
        } else {
            Cow::Borrowed(query)
        };
        let contains = memchr::memmem::Finder::new(query_key.as_bytes());
        let mut report = SearchReport {
            schema: "vitnet.dgml-search.v1".into(),
            generation: self.generation.clone(),
            query: query.into(),
            entries: Vec::new(),
            scanned_nodes: 0,
            next_after_id: options.after_id,
            stop_reason: "complete".into(),
            elapsed_ms: 0,
            matched_nodes: 0,
            matched_incoming_edges: 0,
            omitted_matches: 0,
            rank: options.rank,
        };
        if self.control.is_cancelled() {
            report.stop_reason = "cancelled".into();
            return Ok(report);
        }
        if options.mode == SearchMode::Id {
            let id = query.parse::<u64>().map_err(|_| {
                malformed_simple("dgml.query.id", "ID search needs an unsigned decimal ID")
            })?;
            if options.after_id.is_none_or(|after| id > after) {
                if let Some(node) = self.node(id, options.preview_bytes)? {
                    report.entries.push(node);
                }
            }
        } else if let Some(max) = self.manifest.max_node_id {
            let mut raw = Vec::new();
            let start = options
                .after_id
                .map_or(Some(0), |value| value.checked_add(1));
            for id in start.into_iter().flat_map(|start| start..=max) {
                if self.control.is_cancelled() {
                    report.stop_reason = "cancelled".into();
                    break;
                }
                if report.scanned_nodes >= options.max_scanned
                    || (report.scanned_nodes % DEADLINE_CHECK_INTERVAL == 0
                        && started.elapsed() >= Duration::from_millis(options.timeout_ms))
                {
                    report.stop_reason = if report.scanned_nodes >= options.max_scanned {
                        "max_scanned"
                    } else {
                        "timeout"
                    }
                    .into();
                    break;
                }
                let present = self.read_label(id, &mut raw)?;
                report.scanned_nodes += 1;
                report.next_after_id = Some(id);
                if present {
                    let text = std::str::from_utf8(&raw)
                        .map_err(|_| malformed_simple("dgml.cache.utf8", "invalid label UTF-8"))?;
                    let key = if options.ignore_case {
                        Cow::Owned(text.to_lowercase())
                    } else {
                        Cow::Borrowed(text)
                    };
                    let matches = match options.mode {
                        SearchMode::Exact => key == query_key,
                        SearchMode::Prefix => key.starts_with(query_key.as_ref()),
                        SearchMode::Contains => contains.find(key.as_bytes()).is_some(),
                        SearchMode::Id => unreachable!(),
                    };
                    if matches {
                        let range = self.incoming_range(id)?;
                        report.matched_nodes += 1;
                        report.matched_incoming_edges += range.end - range.start;
                        let incoming_edges = range.end - range.start;
                        let retain = report.entries.len() < options.limit
                            || (options.rank == SearchRank::Incoming
                                && report
                                    .entries
                                    .last()
                                    .is_some_and(|last| incoming_edges > last.incoming_edges));
                        if retain {
                            let (label, truncated) = text_preview(&raw, options.preview_bytes)?;
                            let node = QueryNode {
                                node_id: id,
                                label,
                                label_bytes: raw.len() as u64,
                                truncated,
                                incoming_edges,
                            };
                            if options.rank == SearchRank::Incoming {
                                if report.entries.len() == options.limit {
                                    report.entries.pop();
                                }
                                let position = report.entries.partition_point(|entry| {
                                    entry.incoming_edges > incoming_edges
                                        || (entry.incoming_edges == incoming_edges
                                            && entry.node_id < id)
                                });
                                report.entries.insert(position, node);
                            } else {
                                report.entries.push(node);
                            }
                        }
                        if !options.count_all
                            && options.rank == SearchRank::Id
                            && report.entries.len() == options.limit
                        {
                            report.stop_reason =
                                if id == max { "complete" } else { "limit" }.into();
                            break;
                        }
                        if options.mode == SearchMode::Id {
                            report.matched_nodes = report.entries.len() as u64;
                            report.matched_incoming_edges =
                                report.entries.iter().map(|node| node.incoming_edges).sum();
                        }
                        report.omitted_matches = report.matched_nodes - report.entries.len() as u64;
                    }
                }
            }
        }
        if report.stop_reason == "complete" {
            report.next_after_id = None;
        }
        report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn query_io(error: std::io::Error) -> DgmlError {
    io_error("dgml.query", error.to_string())
}

fn check_projection(limit: usize, preview: usize, memory: u64) -> Result<(), DgmlError> {
    if limit == 0
        || preview == 0
        || preview as u64 > TEXT_LIMIT
        || (limit as u64).saturating_mul(preview as u64 + 256) > memory / 4
    {
        return Err(resource_error(
            "resource.memory_limit",
            "query projection exceeds its memory budget",
        ));
    }
    Ok(())
}

fn read_text(
    reader: &mut BufReader<File>,
    offset: u64,
    length: u64,
    total: u64,
) -> Result<Vec<u8>, DgmlError> {
    reader.seek(SeekFrom::Start(offset)).map_err(query_io)?;
    read_text_bytes(reader, offset, length, total)
}

fn read_text_bytes(
    reader: &mut BufReader<File>,
    offset: u64,
    length: u64,
    total: u64,
) -> Result<Vec<u8>, DgmlError> {
    let mut bytes = Vec::new();
    read_text_bytes_into(reader, offset, length, total, &mut bytes)?;
    Ok(bytes)
}

fn read_text_bytes_into(
    reader: &mut BufReader<File>,
    offset: u64,
    length: u64,
    total: u64,
    bytes: &mut Vec<u8>,
) -> Result<(), DgmlError> {
    if length > TEXT_LIMIT || offset.checked_add(length).is_none_or(|end| end > total) {
        return Err(malformed_simple(
            "dgml.cache.structure",
            "invalid queried text range",
        ));
    }
    bytes.resize(
        usize::try_from(length)
            .map_err(|_| malformed_simple("dgml.cache.structure", "text exceeds usize"))?,
        0,
    );
    reader.read_exact(bytes).map_err(query_io)?;
    Ok(())
}

fn text_preview(bytes: &[u8], maximum: usize) -> Result<(String, bool), DgmlError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| malformed_simple("dgml.cache.utf8", "invalid queried UTF-8"))?;
    let mut end = value.len().min(maximum);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Ok((value[..end].into(), end < value.len()))
}
