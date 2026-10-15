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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgePage {
    pub generation: String,
    pub entries: Vec<IncomingEdge>,
    pub total: u64,
    pub next_after_edge: Option<u64>,
    pub scanned: u64,
    pub stop_reason: String,
}

impl GraphSession {
    /// Reads a complete stored edge by its global cache ordinal, including its reason.
    ///
    /// # Errors
    ///
    /// Rejects absent ordinals, cancellation and corrupt CSR ranges.
    pub fn edge_record(&mut self, ordinal: u64) -> Result<IncomingEdge, DgmlError> {
        self.edge_record_preview(ordinal, 1024 * 1024)
    }

    fn edge_record_preview(
        &mut self,
        ordinal: u64,
        preview: usize,
    ) -> Result<IncomingEdge, DgmlError> {
        if self.control.is_cancelled() {
            return Err(resource_error("resource.cancelled", "edge query cancelled"));
        }
        if ordinal >= self.manifest.edge_count {
            return Err(malformed_simple(
                "dgml.query.cursor",
                "edge ordinal outside this graph",
            ));
        }
        let max = self.manifest.max_node_id.ok_or_else(|| {
            malformed_simple("dgml.cache.structure", "edge cache has no node slots")
        })?;
        let (mut low, mut high) = (0, max + 1);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.incoming_range(middle)?.end <= ordinal {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low > max || !self.incoming_range(low)?.contains(&ordinal) {
            return Err(malformed_simple(
                "dgml.cache.structure",
                "edge is outside CSR ranges",
            ));
        }
        let edge = self.edge(ordinal)?;
        let raw = read_text(
            &mut self.reasons,
            edge.reason_offset,
            u64::from(edge.reason_length),
            self.reason_bytes,
        )?;
        let (reason, reason_truncated) = text_preview(&raw, preview)?;
        Ok(IncomingEdge {
            ordinal,
            source_id: edge.source,
            source: None,
            target_id: low,
            reason,
            reason_bytes: u64::from(edge.reason_length),
            reason_truncated,
        })
    }

    /// Maps a target-local incoming-edge ordinal to the complete stored edge.
    ///
    /// # Errors
    ///
    /// Rejects absent targets, ordinals and corrupt records.
    pub fn incoming_edge_record(
        &mut self,
        id: u64,
        ordinal: u64,
    ) -> Result<IncomingEdge, DgmlError> {
        self.node_record(id)?;
        let range = self.incoming_range(id)?;
        if ordinal >= range.end - range.start {
            return Err(malformed_simple(
                "dgml.query.cursor",
                "incoming edge cursor outside node",
            ));
        }
        self.edge_record(range.start + ordinal)
    }

    /// Enumerates all stored edges in CSR order without retaining the graph.
    ///
    /// # Errors
    ///
    /// Rejects invalid generation, cursors, budgets and corrupt records.
    pub fn browse_edges(&mut self, options: &IncomingOptions) -> Result<EdgePage, DgmlError> {
        self.search_edges("", options, 100_000)
    }

    /// Searches complete reasons and numeric edge IDs in bounded CSR-ordinal batches.
    ///
    /// # Errors
    ///
    /// Rejects invalid generation, cursors, search budgets and corrupt records.
    pub fn search_edges(
        &mut self,
        contains: &str,
        options: &IncomingOptions,
        max_scanned: u64,
    ) -> Result<EdgePage, DgmlError> {
        self.check_generation(options.generation.as_deref())?;
        check_projection(options.limit, options.preview_bytes, self.memory_limit)?;
        if options.timeout_ms == 0
            || max_scanned == 0
            || contains.len() > 1024
            || options
                .after_edge
                .is_some_and(|after| after >= self.manifest.edge_count)
        {
            return Err(malformed_simple(
                "dgml.query.cursor",
                "invalid edge cursor or deadline",
            ));
        }
        let started = Instant::now();
        let mut result = EdgePage {
            generation: self.generation.clone(),
            entries: Vec::new(),
            total: self.manifest.edge_count,
            next_after_edge: options.after_edge,
            scanned: 0,
            stop_reason: "complete".into(),
        };
        for ordinal in options.after_edge.map_or(0, |n| n + 1)..self.manifest.edge_count {
            if self.control.is_cancelled() {
                result.stop_reason = "cancelled".into();
                break;
            }
            if started.elapsed() >= Duration::from_millis(options.timeout_ms) {
                result.stop_reason = "timeout".into();
                break;
            }
            if result.scanned >= max_scanned {
                result.stop_reason = "max_scanned".into();
                break;
            }
            let mut edge = self.edge_record(ordinal)?;
            result.scanned += 1;
            result.next_after_edge = Some(ordinal);
            if !contains.is_empty()
                && !edge.reason.contains(contains)
                && !edge.source_id.to_string().contains(contains)
                && !edge.target_id.to_string().contains(contains)
                && !ordinal.to_string().contains(contains)
            {
                continue;
            }
            let (reason, truncated) = text_preview(edge.reason.as_bytes(), options.preview_bytes)?;
            edge.reason = reason;
            edge.reason_truncated = truncated;
            result.entries.push(edge);
            if result.entries.len() == options.limit {
                if ordinal + 1 < self.manifest.edge_count {
                    result.stop_reason = "limit".into();
                }
                break;
            }
        }
        if result.stop_reason == "complete" {
            result.next_after_edge = None;
        }
        Ok(result)
    }

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
