use crate::{AttributionError, Matcher, SourceMatch, error, open_index};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;
use vitnet_dgml::{GraphSession, IncomingOptions, IncomingReport, WhyOptions, WhyReport};

#[derive(Clone, Debug, Serialize)]
pub struct RetentionAnchor {
    pub node_id: u64,
    pub producer_label: String,
    pub sources: SourceMatch,
    pub possible_mechanisms: Vec<String>,
    pub total_source_candidates: usize,
    pub source_preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnnotatedPath {
    pub root_kind: String,
    pub anchors: Vec<RetentionAnchor>,
    pub collapsed_unmapped_nodes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetentionReport {
    pub schema: String,
    pub witness: WhyReport,
    pub alternative_incoming: IncomingReport,
    pub annotated_paths: Vec<AnnotatedPath>,
    pub incoming_anchors: Vec<RetentionAnchor>,
    pub caveats: Vec<String>,
}

fn anchor(matcher: &Matcher<'_>, id: u64, label: &str, truncated: bool) -> RetentionAnchor {
    let mut sources = if truncated {
        SourceMatch {
            status: "unmapped_truncated_label".into(),
            basis: "A bounded preview cannot establish a complete symbol association".into(),
            assemblies: Vec::new(),
            sources: Vec::new(),
        }
    } else {
        matcher.locate("Methods", label)
    };
    let mut mechanisms = BTreeSet::new();
    for source in &sources.sources {
        for attribute in &source.attributes {
            if attribute.contains("ModuleInitializer") {
                mechanisms.insert("module_initializer");
            }
            if attribute.contains("RegisterService") {
                mechanisms.insert("service_registration_annotation");
            }
            if attribute.contains("JsonSerializable") {
                mechanisms.insert("serialization_root_annotation");
            }
        }
        if source.generated_by.is_some() {
            mechanisms.insert("generated_code");
        }
    }
    let total_source_candidates = sources.sources.len();
    let mut source_preview_truncated = total_source_candidates > 8;
    sources.sources.truncate(8);
    for source in &mut sources.sources {
        source_preview_truncated |= source.attributes.len() > 12;
        source.attributes.truncate(12);
        for attribute in &mut source.attributes {
            if attribute.len() > 256 {
                let mut end = 256;
                while !attribute.is_char_boundary(end) {
                    end -= 1;
                }
                attribute.truncate(end);
                source_preview_truncated = true;
            }
        }
    }
    RetentionAnchor {
        node_id: id,
        producer_label: label.into(),
        sources,
        possible_mechanisms: mechanisms.into_iter().map(str::to_owned).collect(),
        total_source_candidates,
        source_preview_truncated,
    }
}

/// Annotates bounded witnesses while retaining original nodes and dependency reasons.
///
/// # Errors
///
/// Rejects absent evidence, stale graph generations, missing nodes and query limits.
pub fn explain(
    directory: &Path,
    node_id: u64,
    graph_kind: &str,
    memory_limit: u64,
    options: &WhyOptions,
    incoming_limit: usize,
) -> Result<RetentionReport, AttributionError> {
    if !matches!(graph_kind, "scan_index" | "codegen_index") {
        return Err(error(
            "attribution.graph.kind",
            "graph kind must be scan_index or codegen_index",
        ));
    }
    let index = open_index(directory, memory_limit)?;
    let graphs: Vec<_> = index
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == graph_kind && artifact.available)
        .collect();
    if graphs.len() != 1 {
        return Err(error(
            "attribution.graph.missing",
            "one available graph index of the requested kind is required",
        ));
    }
    let artifact = graphs[0];
    let mut graph =
        GraphSession::open(&artifact.path, memory_limit / 2).map_err(|cause| AttributionError {
            diagnostic: cause.diagnostic,
        })?;
    if artifact.graph_generation.as_deref() != Some(&graph.generation)
        || options
            .generation
            .as_ref()
            .is_some_and(|generation| generation != &graph.generation)
    {
        return Err(error(
            "attribution.graph.stale",
            "graph generation differs from imported evidence",
        ));
    }
    let witness = graph
        .why(node_id, options)
        .map_err(|cause| AttributionError {
            diagnostic: cause.diagnostic,
        })?;
    let incoming = graph
        .incoming(
            node_id,
            &IncomingOptions {
                limit: incoming_limit,
                preview_bytes: options.preview_bytes,
                generation: Some(graph.generation.clone()),
                timeout_ms: options.timeout_ms,
                after_edge: None,
            },
        )
        .map_err(|cause| AttributionError {
            diagnostic: cause.diagnostic,
        })?;
    Ok(annotate_retention(&index.evidence, witness, incoming))
}

/// Adds source/annotation candidates without discarding original graph evidence.
#[must_use]
pub fn annotate_retention(
    evidence: &crate::model::Evidence,
    witness: WhyReport,
    incoming: IncomingReport,
) -> RetentionReport {
    let matcher = Matcher::new(evidence);
    let annotated_paths = witness
        .paths
        .iter()
        .map(|path| {
            let mut anchors = Vec::new();
            let mut collapsed = 0;
            for node in &path.nodes {
                let item = anchor(&matcher, node.node_id, &node.label, node.truncated);
                if item.sources.sources.is_empty() {
                    collapsed += 1;
                } else {
                    anchors.push(item);
                }
            }
            AnnotatedPath {
                root_kind: path.root_kind.clone(),
                anchors,
                collapsed_unmapped_nodes: collapsed,
            }
        })
        .collect();
    let incoming_anchors = incoming
        .edges
        .iter()
        .filter_map(|edge| edge.source.as_ref())
        .map(|node| anchor(&matcher, node.node_id, &node.label, node.truncated))
        .collect();
    RetentionReport {
        schema: "vitnet.attribution-retention.v1".into(), witness,
        alternative_incoming: incoming, annotated_paths, incoming_anchors,
        caveats: vec![
            "Compiler reachability is not evidence of runtime execution; lazy factories can still retain code.".into(),
            "Annotations are source/name candidates, not proof that one registration is the sole retainer. Full original paths and reasons are preserved.".into(),
            "Primary/Secondary dependencies may be conjunctive. Paged incoming alternatives and bounded shortest witnesses are not all removal prerequisites.".into(),
            "Witness and incoming queries each expose their own limits and completeness; neither predicts reclaimed bytes.".into(),
            "Source anchors retain at most 8 declaration previews and 12 attributes of 256 bytes per declaration. Preview truncation/counts are explicit; complete declarations remain in captured source catalogs.".into(),
        ],
    }
}
