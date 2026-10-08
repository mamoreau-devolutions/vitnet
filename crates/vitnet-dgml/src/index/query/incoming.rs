use super::{
    DgmlError, GraphSession, QueryNode, WhyOptions, WhyReport, check_projection, malformed_simple,
    read_text, resource_error, text_preview,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingOptions {
    pub limit: usize,
    pub after_edge: Option<u64>,
    pub timeout_ms: u64,
    pub preview_bytes: usize,
    pub generation: Option<String>,
}

impl Default for IncomingOptions {
    fn default() -> Self {
        Self {
            limit: 50,
            after_edge: None,
            timeout_ms: 5000,
            preview_bytes: 256,
            generation: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingEdge {
    pub ordinal: u64,
    pub source_id: u64,
    pub source: Option<QueryNode>,
    pub target_id: u64,
    pub reason: String,
    pub reason_bytes: u64,
    pub reason_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingReport {
    pub schema: String,
    pub generation: String,
    pub node: QueryNode,
    pub total_edges: u64,
    pub edges: Vec<IncomingEdge>,
    pub next_after_edge: Option<u64>,
    pub stop_reason: String,
    pub elapsed_ms: u64,
    pub caveat: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchReport {
    pub schema: String,
    pub generation: String,
    pub requested_nodes: usize,
    pub reports: Vec<WhyReport>,
    pub examined_edges: u64,
    pub visited_nodes: usize,
    pub stop_reason: String,
    pub elapsed_ms: u64,
}

impl GraphSession {
    /// Pages immediate incoming edges, including parallel edges and unresolved sources.
    ///
    /// # Errors
    ///
    /// Returns typed cache, absent-node, generation or resource diagnostics.
    pub fn incoming(
        &mut self,
        id: u64,
        options: &IncomingOptions,
    ) -> Result<IncomingReport, DgmlError> {
        self.check_generation(options.generation.as_deref())?;
        check_projection(
            options.limit,
            options.preview_bytes.saturating_mul(2),
            self.memory_limit,
        )?;
        if options.timeout_ms == 0 {
            return Err(malformed_simple(
                "dgml.query.options",
                "incoming timeout must be positive",
            ));
        }
        let started = Instant::now();
        let node = self.node(id, options.preview_bytes)?.ok_or_else(|| {
            malformed_simple("dgml.query.node", "node ID is absent from this graph")
        })?;
        let range = self.incoming_range(id)?;
        let count = range.end - range.start;
        let mut report = IncomingReport {
            schema: "vitnet.dgml-incoming.v1".into(), generation: self.generation.clone(),
            node, total_edges: count, edges: Vec::new(), next_after_edge: None,
            stop_reason: "complete".into(), elapsed_ms: 0,
            caveat: "Edges point source -> target; parallel edges are preserved. Missing sources are explicit. Primary/Secondary dependencies can be conjunctive. Fan-in is not bytes or removable-size evidence.".into(),
        };
        if self.control.is_cancelled() {
            report.stop_reason = "cancelled".into();
            report.next_after_edge = options.after_edge;
            return Ok(report);
        }
        let start = options
            .after_edge
            .map_or(Some(0), |edge| edge.checked_add(1));
        for ordinal in start.into_iter().flat_map(|start| start..count) {
            if self.control.is_cancelled() {
                report.stop_reason = "cancelled".into();
                break;
            }
            if started.elapsed() >= Duration::from_millis(options.timeout_ms) {
                report.stop_reason = "timeout".into();
                break;
            }
            let edge = self.edge(range.start + ordinal)?;
            let source = self.node(edge.source, options.preview_bytes)?;
            let raw = read_text(
                &mut self.reasons,
                edge.reason_offset,
                u64::from(edge.reason_length),
                self.reason_bytes,
            )?;
            let (reason, reason_truncated) = text_preview(&raw, options.preview_bytes)?;
            report.edges.push(IncomingEdge {
                ordinal,
                source_id: edge.source,
                source,
                target_id: id,
                reason,
                reason_bytes: u64::from(edge.reason_length),
                reason_truncated,
            });
            report.next_after_edge = Some(ordinal);
            if report.edges.len() == options.limit {
                report.stop_reason = if ordinal + 1 == count {
                    "complete"
                } else {
                    "limit"
                }
                .into();
                break;
            }
        }
        if report.stop_reason == "complete" {
            report.next_after_edge = None;
        } else if report.edges.is_empty() {
            report.next_after_edge = options.after_edge;
        }
        report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }

    /// Explains multiple IDs in input order under one generation and shared total work limits.
    ///
    /// # Errors
    ///
    /// Returns typed errors for absent IDs, invalid options or excessive combined projection.
    pub fn batch(&mut self, ids: &[u64], options: &WhyOptions) -> Result<BatchReport, DgmlError> {
        self.check_generation(options.generation.as_deref())?;
        options.validate(self.memory_limit)?;
        if ids.is_empty() || ids.len() > 128 {
            return Err(resource_error(
                "resource.memory_limit",
                "batch needs 1..=128 node IDs",
            ));
        }
        let projection = ids
            .len()
            .checked_mul(options.max_depth + 2)
            .and_then(|size| size.checked_mul(options.max_paths))
            .ok_or_else(|| resource_error("resource.memory_limit", "batch projection overflow"))?;
        check_projection(
            projection,
            options.preview_bytes.saturating_mul(2),
            self.memory_limit,
        )?;
        let started = Instant::now();
        let mut report = BatchReport {
            schema: "vitnet.dgml-batch.v1".into(),
            generation: self.generation.clone(),
            requested_nodes: ids.len(),
            reports: Vec::new(),
            examined_edges: 0,
            visited_nodes: 0,
            stop_reason: "complete".into(),
            elapsed_ms: 0,
        };
        for &id in ids {
            if self.control.is_cancelled() {
                report.stop_reason = "cancelled".into();
                break;
            }
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let stop = if elapsed >= options.timeout_ms {
                Some("timeout")
            } else if report.examined_edges >= options.max_edges {
                Some("max_edges")
            } else if report.visited_nodes >= options.max_visited {
                Some("max_visited")
            } else {
                None
            };
            if let Some(stop) = stop {
                report.stop_reason = stop.into();
                break;
            }
            let mut remaining = options.clone();
            remaining.timeout_ms -= elapsed;
            remaining.max_edges -= report.examined_edges;
            remaining.max_visited -= report.visited_nodes;
            let result = self.why(id, &remaining)?;
            report.examined_edges += result.examined_edges;
            report.visited_nodes += result.visited_nodes;
            report.reports.push(result);
        }
        report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }
}
