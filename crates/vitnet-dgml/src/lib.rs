//! Bounded-memory `NativeAOT` DGML streaming statistics.

mod index;

pub use index::{
    DgmlCacheInfo, DgmlCachePruneReport, DgmlCacheVerification, DgmlIndexManifest, DgmlIndexReport,
    IndexControl, IndexFeatures, IndexOptions, build_index, cache_info, prune_cache, verify_cache,
};

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io::{BufReader, Read};
use thiserror::Error;
use vitnet_core::Diagnostic;

const DEFAULT_BUFFER_CAPACITY: usize = 256 * 1024;
const BITS_PER_WORD: usize = u64::BITS as usize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FanInEntry {
    pub node_id: u64,
    pub incoming_edges: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InDegreeBucket {
    pub incoming_edges: u32,
    pub nodes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DgmlStats {
    pub schema: String,
    pub input_bytes: u64,
    pub node_count: u64,
    pub edge_count: u64,
    pub max_node_id: Option<u64>,
    pub duplicate_node_ids: u64,
    pub unresolved_endpoints: u64,
    pub reasons: Vec<NamedCount>,
    pub in_degree_distribution: Vec<InDegreeBucket>,
    pub largest_fan_in: Vec<FanInEntry>,
    pub peak_tracked_memory_bytes: u64,
}

#[derive(Debug, Error)]
#[error("{diagnostic}")]
pub struct DgmlError {
    pub diagnostic: Box<Diagnostic>,
}

#[derive(Clone, Copy, Debug)]
pub struct StatsOptions {
    pub top: usize,
    pub memory_limit: u64,
    pub input_bytes: u64,
}

/// Streams a DGML document and computes graph statistics without a DOM.
///
/// # Errors
///
/// Returns a typed malformed-input or resource-limit diagnostic.
#[allow(clippy::too_many_lines)]
pub fn analyze_stats<R: Read>(input: R, options: StatsOptions) -> Result<DgmlStats, DgmlError> {
    let mut reader = Reader::from_reader(BufReader::with_capacity(DEFAULT_BUFFER_CAPACITY, input));
    reader.config_mut().trim_text(false);

    let mut buffer = Vec::with_capacity(DEFAULT_BUFFER_CAPACITY);
    let mut seen_nodes = Vec::<u64>::new();
    let mut fan_in = Vec::<u32>::new();
    let mut reasons = HashMap::<String, u64>::new();
    let mut node_count = 0_u64;
    let mut edge_count = 0_u64;
    let mut duplicate_node_ids = 0_u64;
    let mut unresolved_endpoints = 0_u64;
    let mut max_node_id = None::<u64>;
    let mut peak_tracked = 0_u64;
    let mut in_directed_graph = false;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                let local_name = element.local_name();
                match local_name.as_ref() {
                    "DirectedGraph" => in_directed_graph = true,
                    "Node" if in_directed_graph => {
                        let id = required_numeric_attribute(&reader, &element, "Id")?;
                        ensure_node_capacity(
                            id,
                            &mut seen_nodes,
                            &mut fan_in,
                            options.memory_limit,
                            reader.buffer_position(),
                        )?;
                        let word = usize::try_from(id / BITS_PER_WORD as u64)
                            .map_err(|_| resource_error("dgml.node_id", "node ID exceeds usize"))?;
                        let bit = 1_u64 << (id % BITS_PER_WORD as u64);
                        if seen_nodes[word] & bit != 0 {
                            duplicate_node_ids = duplicate_node_ids.saturating_add(1);
                        } else {
                            seen_nodes[word] |= bit;
                            node_count = node_count.saturating_add(1);
                        }
                        max_node_id = Some(max_node_id.map_or(id, |current| current.max(id)));
                    }
                    "Link" if in_directed_graph => {
                        let source = required_numeric_attribute(&reader, &element, "Source")?;
                        let target = required_numeric_attribute(&reader, &element, "Target")?;
                        edge_count = edge_count.saturating_add(1);
                        if !node_exists(&seen_nodes, source) {
                            unresolved_endpoints = unresolved_endpoints.saturating_add(1);
                        }
                        if !node_exists(&seen_nodes, target) {
                            unresolved_endpoints = unresolved_endpoints.saturating_add(1);
                        }
                        if let Ok(target_index) = usize::try_from(target)
                            && let Some(value) = fan_in.get_mut(target_index)
                        {
                            *value = value.checked_add(1).ok_or_else(|| {
                                malformed_error(
                                    "dgml.fan_in",
                                    "node fan-in exceeds the supported u32 range",
                                    reader.buffer_position(),
                                )
                            })?;
                        }
                        increment_reason(&reader, &element, &mut reasons)?;
                    }
                    _ => {}
                }
            }
            Ok(Event::DocType(_) | Event::GeneralRef(_)) => {
                return Err(malformed_error(
                    "dgml.xml.external_entity",
                    "DTD and entity references are not allowed",
                    reader.buffer_position(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(malformed_error(
                    "dgml.xml",
                    format!("invalid XML: {error}"),
                    reader.buffer_position(),
                ));
            }
        }
        let tracked = tracked_bytes(&buffer, &seen_nodes, &fan_in, &reasons);
        peak_tracked = peak_tracked.max(tracked);
        if tracked > options.memory_limit {
            return Err(resource_limit_error(
                tracked,
                options.memory_limit,
                reader.buffer_position(),
            ));
        }
        buffer.clear();
    }

    if !in_directed_graph {
        return Err(malformed_error(
            "dgml.root",
            "missing DirectedGraph root element",
            reader.buffer_position(),
        ));
    }

    let mut reason_counts = reasons
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect::<Vec<_>>();
    reason_counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });

    Ok(DgmlStats {
        schema: "vitnet.dgml-stats.v1".into(),
        input_bytes: options.input_bytes,
        node_count,
        edge_count,
        max_node_id,
        duplicate_node_ids,
        unresolved_endpoints,
        reasons: reason_counts,
        in_degree_distribution: in_degree_distribution(&fan_in),
        largest_fan_in: top_fan_in(&fan_in, options.top),
        peak_tracked_memory_bytes: peak_tracked,
    })
}

fn ensure_node_capacity(
    id: u64,
    seen_nodes: &mut Vec<u64>,
    fan_in: &mut Vec<u32>,
    memory_limit: u64,
    byte_offset: u64,
) -> Result<(), DgmlError> {
    let entries = id
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| resource_error("dgml.node_id", "node ID exceeds usize"))?;
    let words = entries
        .checked_add(BITS_PER_WORD - 1)
        .map(|value| value / BITS_PER_WORD)
        .ok_or_else(|| resource_error("dgml.node_id", "node bitset size overflowed"))?;
    let required = (entries as u64)
        .saturating_mul(size_of::<u32>() as u64)
        .saturating_add((words as u64).saturating_mul(size_of::<u64>() as u64));
    if required > memory_limit {
        return Err(resource_limit_error(required, memory_limit, byte_offset));
    }
    if fan_in.len() < entries {
        fan_in.resize(entries, 0);
    }
    if seen_nodes.len() < words {
        seen_nodes.resize(words, 0);
    }
    Ok(())
}

fn node_exists(seen_nodes: &[u64], id: u64) -> bool {
    let Ok(word) = usize::try_from(id / BITS_PER_WORD as u64) else {
        return false;
    };
    seen_nodes
        .get(word)
        .is_some_and(|value| value & (1_u64 << (id % BITS_PER_WORD as u64)) != 0)
}

fn required_numeric_attribute<R: std::io::BufRead>(
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
            "{} element is missing required {} attribute",
            element.local_name().as_ref(),
            name
        ),
        reader.buffer_position(),
    ))
}

fn increment_reason<R: std::io::BufRead>(
    reader: &Reader<R>,
    element: &BytesStart<'_>,
    reasons: &mut HashMap<String, u64>,
) -> Result<(), DgmlError> {
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
            if let Some(count) = reasons.get_mut(reason.as_ref()) {
                *count = count.saturating_add(1);
            } else {
                reasons.insert(reason.into_owned(), 1);
            }
            break;
        }
    }
    Ok(())
}

fn in_degree_distribution(values: &[u32]) -> Vec<InDegreeBucket> {
    let mut counts = HashMap::<u32, u64>::new();
    for incoming_edges in values {
        *counts.entry(*incoming_edges).or_default() += 1;
    }
    let mut result = counts
        .into_iter()
        .map(|(incoming_edges, nodes)| InDegreeBucket {
            incoming_edges,
            nodes,
        })
        .collect::<Vec<_>>();
    result.sort_unstable_by_key(|entry| entry.incoming_edges);
    result
}

fn top_fan_in(values: &[u32], limit: usize) -> Vec<FanInEntry> {
    let mut heap = BinaryHeap::<Reverse<(u32, Reverse<u64>)>>::new();
    for (node_id, incoming) in values.iter().copied().enumerate() {
        if incoming == 0 || limit == 0 {
            continue;
        }
        let node_id = node_id as u64;
        heap.push(Reverse((incoming, Reverse(node_id))));
        if heap.len() > limit {
            heap.pop();
        }
    }
    let mut result = heap
        .into_iter()
        .map(|Reverse((incoming_edges, Reverse(node_id)))| FanInEntry {
            node_id,
            incoming_edges,
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        right
            .incoming_edges
            .cmp(&left.incoming_edges)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    result
}

fn tracked_bytes(
    buffer: &Vec<u8>,
    seen_nodes: &Vec<u64>,
    fan_in: &Vec<u32>,
    reasons: &HashMap<String, u64>,
) -> u64 {
    (buffer.capacity() as u64)
        .saturating_add((seen_nodes.capacity() * size_of::<u64>()) as u64)
        .saturating_add((fan_in.capacity() * size_of::<u32>()) as u64)
        .saturating_add(
            reasons
                .keys()
                .map(|key| key.capacity() as u64 + 64)
                .sum::<u64>(),
        )
}

fn malformed_error(code: &str, message: impl Into<String>, byte_offset: u64) -> DgmlError {
    let mut diagnostic = Diagnostic::malformed(code, message);
    diagnostic.byte_offset = Some(byte_offset);
    DgmlError {
        diagnostic: Box::new(diagnostic),
    }
}

fn resource_error(code: &str, message: impl Into<String>) -> DgmlError {
    DgmlError {
        diagnostic: Box::new(Diagnostic::malformed(code, message)),
    }
}

fn resource_limit_error(actual: u64, limit: u64, byte_offset: u64) -> DgmlError {
    let mut diagnostic = Diagnostic::malformed(
        "resource.memory_limit",
        "DGML statistics state exceeded the configured memory limit",
    );
    diagnostic.byte_offset = Some(byte_offset);
    diagnostic.expected = Some(format!("at most {limit} bytes"));
    diagnostic.actual = Some(format!("{actual} tracked bytes"));
    DgmlError {
        diagnostic: Box::new(diagnostic),
    }
}
