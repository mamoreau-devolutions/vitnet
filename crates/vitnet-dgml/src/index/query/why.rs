use super::{
    DgmlError, GraphSession, QueryNode, TEXT_LIMIT, check_projection, malformed_simple, query_io,
    read_text, resource_error, text_preview,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhyOptions {
    pub max_depth: usize,
    pub max_paths: usize,
    pub max_visited: usize,
    pub max_edges: u64,
    pub timeout_ms: u64,
    pub preview_bytes: usize,
    pub generation: Option<String>,
}

impl Default for WhyOptions {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_paths: 3,
            max_visited: 10_000,
            max_edges: 100_000,
            timeout_ms: 5_000,
            preview_bytes: 256,
            generation: None,
        }
    }
}

impl WhyOptions {
    pub(super) fn validate(&self, memory_limit: u64) -> Result<(), DgmlError> {
        let projection = self
            .max_depth
            .checked_add(2)
            .and_then(|depth| depth.checked_mul(self.max_paths))
            .ok_or_else(|| resource_error("resource.memory_limit", "path projection overflow"))?;
        check_projection(
            projection,
            self.preview_bytes.saturating_mul(2),
            memory_limit,
        )?;
        if self.max_depth > 1024
            || self.max_paths == 0
            || self.max_visited == 0
            || self.max_visited as u64 > memory_limit / 512
            || self.max_edges == 0
            || self.timeout_ms == 0
        {
            return Err(resource_error(
                "resource.memory_limit",
                "invalid or oversized traversal limits",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhyPath {
    pub root_kind: String,
    pub nodes: Vec<QueryNode>,
    pub reasons: Vec<String>,
    pub reason_bytes: Vec<u64>,
    pub reasons_truncated: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhyReport {
    pub schema: String,
    pub generation: String,
    pub node: QueryNode,
    pub paths: Vec<WhyPath>,
    pub visited_nodes: usize,
    pub examined_edges: u64,
    pub repeated_nodes: u64,
    pub missing_nodes: u64,
    pub stop_reason: String,
    pub elapsed_ms: u64,
    pub caveat: String,
}

#[derive(Clone, Copy)]
pub(super) struct QueryEdge {
    pub(super) source: u64,
    pub(super) reason_offset: u64,
    pub(super) reason_length: u32,
}

struct Visit {
    id: u64,
    toward: Option<usize>,
    edge: Option<QueryEdge>,
    depth: usize,
}

impl GraphSession {
    pub(super) fn edge(&mut self, record: u64) -> Result<QueryEdge, DgmlError> {
        if let Some(delta) = self
            .next_edge
            .take()
            .and_then(|next| i64::try_from((i128::from(record) - i128::from(next)) * 24).ok())
        {
            self.edges.seek_relative(delta).map_err(query_io)?;
        } else {
            self.edges
                .seek(SeekFrom::Start(record * 24))
                .map_err(query_io)?;
        }
        let mut bytes = [0; 24];
        self.edges.read_exact(&mut bytes).map_err(query_io)?;
        self.next_edge = Some(record + 1);
        let edge = QueryEdge {
            source: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            reason_offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            reason_length: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        };
        if bytes[20..] != [0; 4]
            || edge
                .reason_offset
                .checked_add(u64::from(edge.reason_length))
                .is_none_or(|end| end > self.reason_bytes)
            || u64::from(edge.reason_length) > TEXT_LIMIT
        {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "invalid queried edge",
            ));
        }
        Ok(edge)
    }

    fn path(
        &mut self,
        visits: &[Visit],
        mut index: usize,
        kind: &str,
        preview: usize,
    ) -> Result<WhyPath, DgmlError> {
        let mut path = WhyPath {
            root_kind: kind.into(),
            nodes: Vec::new(),
            reasons: Vec::new(),
            reason_bytes: Vec::new(),
            reasons_truncated: Vec::new(),
        };
        loop {
            let visit = &visits[index];
            path.nodes.push(
                self.node(visit.id, preview)?
                    .ok_or_else(|| malformed_simple("dgml.query.node", "path node disappeared"))?,
            );
            if let Some(edge) = visit.edge {
                let raw = read_text(
                    &mut self.reasons,
                    edge.reason_offset,
                    u64::from(edge.reason_length),
                    self.reason_bytes,
                )?;
                let (reason, truncated) = text_preview(&raw, preview)?;
                path.reasons.push(reason);
                path.reason_bytes.push(u64::from(edge.reason_length));
                path.reasons_truncated.push(truncated);
            }
            if let Some(next) = visit.toward {
                index = next;
            } else {
                break;
            }
        }
        Ok(path)
    }

    /// Finds bounded shortest incoming root witnesses, not every possible path.
    ///
    /// # Errors
    ///
    /// Returns explicit errors for invalid IDs, cache data, or resource options.
    #[allow(clippy::too_many_lines)] // Keep traversal stops and witness selection together.
    pub fn why(&mut self, id: u64, options: &WhyOptions) -> Result<WhyReport, DgmlError> {
        self.check_generation(options.generation.as_deref())?;
        options.validate(self.memory_limit)?;
        let started = Instant::now();
        let node = self.node(id, options.preview_bytes)?.ok_or_else(|| {
            malformed_simple("dgml.query.node", "node ID is absent from this graph")
        })?;
        let mut report = WhyReport {
            schema: "vitnet.dgml-why.v1".into(), generation: self.generation.clone(),
            node, paths: Vec::new(), visited_nodes: 0, examined_edges: 0, repeated_nodes: 0,
            missing_nodes: 0, stop_reason: "complete".into(), elapsed_ms: 0,
            caveat: "Shortest BFS witnesses, not all paths. Empty-reason edges follow NativeAOT's root convention; zero-in-degree terminals are candidates only. Primary/Secondary combined nodes encode conjunctions, not independent sufficient causes. Dependency counts are not byte sizes.".into(),
        };
        let mut visits = vec![Visit {
            id,
            toward: None,
            edge: None,
            depth: 0,
        }];
        let mut seen = HashSet::from([id]);
        let mut queue = VecDeque::from([0]);
        'traversal: while let Some(index) = queue.pop_front() {
            if self.control.is_cancelled() {
                report.stop_reason = "cancelled".into();
                break;
            }
            if started.elapsed() >= Duration::from_millis(options.timeout_ms) {
                report.stop_reason = "timeout".into();
                break;
            }
            let range = self.incoming_range(visits[index].id)?;
            if range.is_empty() {
                report.paths.push(self.path(
                    &visits,
                    index,
                    "zero_in_degree_candidate",
                    options.preview_bytes,
                )?);
                if report.paths.len() == options.max_paths {
                    report.stop_reason = "max_paths".into();
                    break;
                }
                continue;
            }
            if visits[index].depth >= options.max_depth {
                report.stop_reason = "max_depth".into();
                continue;
            }
            for record in range {
                if self.control.is_cancelled() {
                    report.stop_reason = "cancelled".into();
                    break 'traversal;
                }
                if report.examined_edges >= options.max_edges
                    || started.elapsed() >= Duration::from_millis(options.timeout_ms)
                {
                    report.stop_reason = if report.examined_edges >= options.max_edges {
                        "max_edges"
                    } else {
                        "timeout"
                    }
                    .into();
                    break 'traversal;
                }
                let edge = self.edge(record)?;
                report.examined_edges += 1;
                if seen.contains(&edge.source) {
                    report.repeated_nodes += 1;
                    continue;
                }
                if visits.len() == options.max_visited {
                    report.stop_reason = "max_visited".into();
                    break 'traversal;
                }
                if self.raw_label(edge.source)?.is_none() {
                    report.missing_nodes += 1;
                    continue;
                }
                seen.insert(edge.source);
                let next = visits.len();
                visits.push(Visit {
                    id: edge.source,
                    toward: Some(index),
                    edge: Some(edge),
                    depth: visits[index].depth + 1,
                });
                if edge.reason_length == 0 {
                    report.paths.push(self.path(
                        &visits,
                        next,
                        "nativeaot_empty_reason_root",
                        options.preview_bytes,
                    )?);
                    if report.paths.len() == options.max_paths {
                        report.stop_reason = "max_paths".into();
                        break 'traversal;
                    }
                } else {
                    queue.push_back(next);
                }
            }
        }
        report.visited_nodes = visits.len();
        report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }
}
